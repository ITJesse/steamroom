//! A logged-in CM connection for one account.

use super::RplnetConnectOptions;
use super::RplnetCredential;
use super::content::Content;
use super::content::RplnetContentRegion;
use super::content::RplnetInspection;
use super::download::RplnetCancellation;
use super::download::RplnetDownloadObserver;
use super::download::RplnetDownloadRequest;
use super::download::RplnetDownloadResult;
use super::library;
use super::library::RplnetAppVersion;
use super::library::RplnetDepotCandidate;
use super::library::RplnetOwnedGame;
use super::update::RplnetUpdatePlan;
use super::update::RplnetUpdateRequest;
use crate::error::RplnetError;
use crate::error::RplnetSteamFailure;
use prost::Message;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use steamroom::client::IncomingMsg;
use steamroom::client::LoggedIn;
use steamroom::client::Ready;
use steamroom::client::SteamClient;
use steamroom::generated;
use steamroom::messages::EMsg;
use steamroom_client::login::PreparedLoginBuilder;
use tokio::sync::broadcast;
use tracing::debug;
use tracing::info;

/// How long to wait for the license list Steam pushes after logon.
const LICENSE_LIST_TIMEOUT: Duration = Duration::from_secs(15);
/// How long to wait for the account info Steam pushes after logon.
const ACCOUNT_INFO_TIMEOUT: Duration = Duration::from_secs(5);
/// How long to wait for the answer to a persona request.
const PERSONA_TIMEOUT: Duration = Duration::from_secs(8);
/// `EPersonaStateFlag` bits asked for when reading the account's own persona:
/// status, player name, presence (carries the avatar hash), last seen, and
/// rich presence. The same set the spike verified to return the avatar.
const PERSONA_FLAGS: u32 = 1 | 2 | 16 | 64 | 1024 | 4096;
/// `GenerateAccessTokenForApp` renewal type that lets Steam issue a new
/// refresh token when it considers the current one due.
const RENEWAL_ALLOW: i32 = 1;

/// What Steam shows for the account.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RplnetProfile {
    /// Display name; `None` when Steam did not send it in time.
    pub persona_name: Option<String>,
    /// Full-size avatar; `None` when Steam did not send the hash in time or
    /// the account uses no avatar.
    pub avatar_url: Option<String>,
}

/// A logged-in connection. Releasing it closes the connection.
///
/// There is deliberately no log-off: in a live run, a refresh token that had
/// logged on and then sent `CMsgClientLogOff` was refused (AccessDenied) at
/// every later logon. Ending a session by closing the connection keeps the
/// token usable.
#[derive(uniffi::Object)]
pub struct RplnetSteamSession {
    client: SteamClient<LoggedIn>,
    account_name: String,
    refresh_token: Mutex<String>,
    events: Events,
    content: Content,
}

impl RplnetSteamSession {
    pub(crate) fn new(
        client: SteamClient<LoggedIn>,
        account_name: String,
        refresh_token: String,
    ) -> Arc<Self> {
        let events = Events::start(&client);
        info!("logged in to Steam");
        Arc::new(Self {
            client,
            account_name,
            refresh_token: Mutex::new(refresh_token),
            events,
            content: Content::default(),
        })
    }

    pub(super) async fn resume_on(
        ready: SteamClient<Ready>,
        options: RplnetConnectOptions,
        account_name: String,
        refresh_token: String,
    ) -> Result<Arc<Self>, RplnetError> {
        let client = PreparedLoginBuilder::new(ready)
            .device_name(options.device_name)
            .login_id(options.login_id)
            .with_refresh_token(account_name.clone(), refresh_token.clone())
            .login()
            .await?;
        Ok(Self::new(client, account_name, refresh_token))
    }

    fn refresh_token(&self) -> String {
        self.refresh_token
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl RplnetSteamSession {
    /// Log in with a saved refresh token.
    #[uniffi::constructor]
    pub async fn resume(
        options: RplnetConnectOptions,
        account_name: String,
        refresh_token: String,
    ) -> Result<Arc<Self>, RplnetError> {
        let ready = super::cm::connect().await?;
        Self::resume_on(ready, options, account_name, refresh_token).await
    }

    /// SteamID64 of the account.
    pub fn steam_id(&self) -> u64 {
        self.client.steam_id().raw()
    }

    pub fn account_name(&self) -> String {
        self.account_name.clone()
    }

    /// False once the CM has closed the connection; log in again to go on.
    pub fn is_connected(&self) -> bool {
        self.client.is_connected()
    }

    /// The account's display name and avatar, read without setting it
    /// online. Missing parts are `None` rather than an error.
    pub async fn profile(&self) -> Result<RplnetProfile, RplnetError> {
        let me = self.steam_id();
        let persona = self.events.subscribe();
        let request = generated::CMsgClientRequestFriendData {
            persona_state_requested: Some(PERSONA_FLAGS),
            friends: vec![me],
        }
        .encode_to_vec();
        self.client
            .send_msg(
                &self
                    .client
                    .make_msg(EMsg::CLIENT_REQUEST_FRIEND_DATA, &request),
            )
            .await?;

        let account_name = self.events.first(
            self.events.subscribe(),
            EMsg::CLIENT_ACCOUNT_INFO,
            ACCOUNT_INFO_TIMEOUT,
            |msg| {
                generated::CMsgClientAccountInfo::decode(&*msg.body)
                    .ok()?
                    .persona_name
                    .filter(|name| !name.is_empty())
            },
        );
        let own_persona = self.events.first(
            persona,
            EMsg::CLIENT_PERSONA_STATE,
            PERSONA_TIMEOUT,
            |msg| {
                generated::CMsgClientPersonaState::decode(&*msg.body)
                    .ok()?
                    .friends
                    .into_iter()
                    .find(|friend| friend.friendid == Some(me))
            },
        );
        let (account_name, own_persona) = tokio::join!(account_name, own_persona);

        let persona_name = account_name.or_else(|| {
            own_persona
                .as_ref()
                .and_then(|persona| persona.player_name.clone())
                .filter(|name| !name.is_empty())
        });
        let avatar_url = own_persona
            .and_then(|persona| persona.avatar_hash)
            .and_then(|hash| avatar_url(&hash));
        debug!(
            "profile: name {}, avatar {}",
            if persona_name.is_some() {
                "present"
            } else {
                "missing"
            },
            if avatar_url.is_some() {
                "present"
            } else {
                "missing"
            }
        );
        Ok(RplnetProfile {
            persona_name,
            avatar_url,
        })
    }

    /// The games the account owns, with the depots to inspect for each.
    /// `language` is a Steam language code (`english`, `schinese`,
    /// `japanese`, …) for names and store images.
    pub async fn owned_games(&self, language: String) -> Result<Vec<RplnetOwnedGame>, RplnetError> {
        let licenses = self
            .events
            .first(
                self.events.subscribe(),
                EMsg::CLIENT_LICENSE_LIST,
                LICENSE_LIST_TIMEOUT,
                |msg| library::decode_licenses(&msg.body).ok(),
            )
            .await
            .ok_or_else(|| {
                RplnetError::steam(
                    RplnetSteamFailure::InvalidResponse,
                    "Steam sent no license list",
                )
            })?;
        library::owned_games(&self.client, &licenses, &language).await
    }

    /// Read a game's depot manifests (from `owned_games`) to tell whether it
    /// is Ren'Py. With `version_dir`, a Ren'Py game's engine version files
    /// are written under that directory at their depot paths.
    pub async fn inspect(
        &self,
        app_id: u32,
        depots: Vec<RplnetDepotCandidate>,
        version_dir: Option<String>,
    ) -> Result<RplnetInspection, RplnetError> {
        self.content
            .inspect(
                &self.client,
                app_id,
                &depots,
                version_dir.as_deref().map(std::path::Path::new),
            )
            .await
    }

    /// Take content servers from `region` from now on (`None`: let Steam
    /// pick, the default). Inspections and downloads both follow it.
    pub fn set_content_region(&self, region: Option<RplnetContentRegion>) {
        self.content.set_region(region);
    }

    /// Download a Ren'Py game's story files; see
    /// [`RplnetDownloadRequest`]. Fails with `Cancelled` once `cancellation`
    /// fires, and with `RegionUnavailable` when the chosen region has no
    /// content servers.
    pub async fn download(
        &self,
        request: RplnetDownloadRequest,
        observer: Arc<dyn RplnetDownloadObserver>,
        cancellation: Arc<RplnetCancellation>,
    ) -> Result<RplnetDownloadResult, RplnetError> {
        super::download::download(
            &self.content,
            &self.client,
            &request,
            observer,
            &cancellation,
        )
        .await
    }

    /// What Steam lists now for the public branch of each of `app_ids`, for
    /// telling whether imported stories are behind. Apps Steam returns
    /// nothing for are left out.
    pub async fn app_versions(
        &self,
        app_ids: Vec<u32>,
    ) -> Result<Vec<RplnetAppVersion>, RplnetError> {
        library::app_versions(&self.client, &app_ids).await
    }

    /// Fetch the manifest an update goes to and work out what it changes;
    /// see [`RplnetUpdateRequest`]. Fails with `NotRenPy` when the new build
    /// has no Ren'Py game.
    pub async fn plan_update(
        &self,
        request: RplnetUpdateRequest,
    ) -> Result<RplnetUpdatePlan, RplnetError> {
        super::update::plan(&self.content, &self.client, &request).await
    }

    /// Download the files an update changes into its destination; see
    /// [`RplnetUpdateRequest`]. Fails with `Cancelled` once `cancellation`
    /// fires.
    pub async fn update(
        &self,
        request: RplnetUpdateRequest,
        observer: Arc<dyn RplnetDownloadObserver>,
        cancellation: Arc<RplnetCancellation>,
    ) -> Result<RplnetUpdatePlan, RplnetError> {
        super::update::update(
            &self.content,
            &self.client,
            &request,
            observer,
            &cancellation,
        )
        .await
    }

    /// Ask Steam for a new refresh token. Steam only issues one when it
    /// considers the current token due, so `None` is the normal answer for a
    /// recent token; keep using it then.
    pub async fn renew_refresh_token(&self) -> Result<Option<RplnetCredential>, RplnetError> {
        let current = self.refresh_token();
        let request = generated::CAuthenticationAccessTokenGenerateForAppRequest {
            refresh_token: Some(current.clone()),
            steamid: Some(self.steam_id()),
            renewal_type: Some(RENEWAL_ALLOW),
        };
        let response: generated::CAuthenticationAccessTokenGenerateForAppResponse = self
            .client
            .call_service_method(
                "Authentication.GenerateAccessTokenForApp#1",
                &request.encode_to_vec(),
            )
            .await?
            .decode()
            .map_err(steamroom::Error::from)?;
        let Some(renewed) = response
            .refresh_token
            .filter(|token| !token.is_empty() && *token != current)
        else {
            info!("Steam did not renew the refresh token");
            return Ok(None);
        };
        *self.refresh_token.lock().unwrap_or_else(|e| e.into_inner()) = renewed.clone();
        info!("Steam renewed the refresh token");
        Ok(Some(RplnetCredential::new(
            self.steam_id(),
            self.account_name.clone(),
            renewed,
        )))
    }
}

/// `https://avatars.steamstatic.com/<hex>_full.jpg`, or `None` for an empty
/// or all-zero hash (no avatar set).
fn avatar_url(hash: &[u8]) -> Option<String> {
    if hash.iter().all(|byte| *byte == 0) {
        return None;
    }
    let hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    Some(format!("https://avatars.steamstatic.com/{hex}_full.jpg"))
}

/// Fans out the messages Steam pushes on the connection: the latest message
/// of each kind is kept for readers that come late, and every message is
/// offered to current subscribers.
struct Events {
    latest: Arc<Mutex<HashMap<EMsg, IncomingMsg>>>,
    sender: broadcast::Sender<IncomingMsg>,
    pump: tokio::task::JoinHandle<()>,
}

/// Room for messages a slow subscriber has not read yet; older ones are
/// skipped (the latest of each kind stays readable).
const SUBSCRIBER_BUFFER: usize = 256;

impl Events {
    fn start(client: &SteamClient<LoggedIn>) -> Self {
        let latest = Arc::new(Mutex::new(HashMap::new()));
        let (sender, _) = broadcast::channel(SUBSCRIBER_BUFFER);
        let incoming = client.events();
        let pump = tokio::spawn({
            let latest = Arc::clone(&latest);
            let sender = sender.clone();
            async move {
                while let Ok(msg) = incoming.recv().await {
                    latest
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(msg.emsg, msg.clone());
                    let _ = sender.send(msg);
                }
            }
        });
        Self {
            latest,
            sender,
            pump,
        }
    }

    /// Subscribe before sending a request whose answer is wanted, so the
    /// answer cannot slip past.
    fn subscribe(&self) -> broadcast::Receiver<IncomingMsg> {
        self.sender.subscribe()
    }

    /// The first message of kind `emsg` that `pick` accepts: the latest one
    /// already received, else one arriving on `receiver` within `timeout`.
    async fn first<T>(
        &self,
        mut receiver: broadcast::Receiver<IncomingMsg>,
        emsg: EMsg,
        timeout: Duration,
        pick: impl Fn(&IncomingMsg) -> Option<T>,
    ) -> Option<T> {
        let seen = self
            .latest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&emsg)
            .cloned();
        if let Some(found) = seen.as_ref().and_then(&pick) {
            return Some(found);
        }
        let wait = async {
            loop {
                match receiver.recv().await {
                    Ok(msg) if msg.emsg == emsg => {
                        if let Some(found) = pick(&msg) {
                            return Some(found);
                        }
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        };
        tokio::time::timeout(timeout, wait).await.ok().flatten()
    }
}

impl Drop for Events {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avatar_url_is_the_hex_hash() {
        assert_eq!(
            avatar_url(&[0xfe, 0xf4, 0x9e, 0x01]).as_deref(),
            Some("https://avatars.steamstatic.com/fef49e01_full.jpg")
        );
    }

    #[test]
    fn empty_or_zero_hash_is_no_avatar() {
        assert_eq!(avatar_url(&[]), None);
        assert_eq!(avatar_url(&[0; 20]), None);
    }
}
