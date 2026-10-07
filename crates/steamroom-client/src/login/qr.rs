use crate::login::BuilderConfig;
use crate::login::STEAM_CLIENT_PLATFORM_TYPE;
use crate::login::TransportConfig;
use crate::login::error::LoginError;
use crate::login::establish_ready_client;
use crate::login::terminal::ApprovedAuth;

use steamroom::auth::AuthClientId;
use steamroom::auth::AuthTokens;
use steamroom::auth::GuardType;
use steamroom::auth::PollInterval;
use steamroom::client::Ready;
use steamroom::client::SteamClient;
use steamroom::generated::CAuthenticationBeginAuthSessionViaQrRequest;

/// Configured QR login. Call [`begin()`] to start the flow.
///
/// [`begin()`]: QrLogin::begin
pub struct QrLogin {
    pub(crate) config: BuilderConfig,
    pub(crate) transport: TransportConfig,
}

/// QR auth session in progress: the caller renders `challenge_url()` as a QR
/// code (or prints it), then calls `poll()` until the user approves on their
/// Steam mobile app.
///
/// Steam replaces the challenge every so often while the session is pending;
/// the previous URL then stops working and later polls must carry the new
/// client id. [`poll`](QrLoginFlow::poll) follows the replacement and reports
/// it so the caller can redraw the code.
pub struct QrLoginFlow {
    client: SteamClient<Ready>,
    config: BuilderConfig,
    challenge_url: String,
    client_id: AuthClientId,
    request_id: Vec<u8>,
    poll_interval: PollInterval,
    allowed_kinds: Vec<GuardType>,
}

impl QrLogin {
    /// Connect (or accept BYO client) and call `BeginAuthSessionViaQR`.
    pub async fn begin(self) -> Result<QrLoginFlow, LoginError> {
        let client = establish_ready_client(self.transport).await?;

        let device_name = self
            .config
            .device_name
            .clone()
            .unwrap_or_else(|| "steamroom".to_string());
        let req = CAuthenticationBeginAuthSessionViaQrRequest {
            device_friendly_name: Some(device_name),
            platform_type: Some(STEAM_CLIENT_PLATFORM_TYPE),
            ..Default::default()
        };
        let session = client.begin_auth_session_via_qr(req).await?;

        Ok(QrLoginFlow {
            client,
            config: self.config,
            challenge_url: session
                .challenge_url
                .ok_or(LoginError::MissingField("challenge_url"))?,
            client_id: session
                .client_id
                .ok_or(LoginError::MissingField("client_id"))?,
            request_id: session
                .request_id
                .ok_or(LoginError::MissingField("request_id"))?,
            poll_interval: session.poll_interval.unwrap_or(PollInterval::DEFAULT),
            allowed_kinds: session.allowed_confirmations,
        })
    }
}

/// Outcome of one [`QrLoginFlow::poll`].
#[derive(Debug)]
#[non_exhaustive]
pub enum QrPoll {
    /// Not approved yet.
    Pending,
    /// Steam replaced the challenge: show [`QrLoginFlow::challenge_url`]
    /// again, the previous code can no longer be scanned.
    ChallengeChanged,
    /// Approved; pass the tokens to [`QrLoginFlow::into_approved`].
    Approved(AuthTokens),
}

impl QrLoginFlow {
    /// URL to encode as a QR code or print for the user. The caller picks
    /// the renderer (the steamroom CLI uses the `qrcode` crate).
    pub fn challenge_url(&self) -> &str {
        &self.challenge_url
    }

    /// Confirmation kinds Steam reported as acceptable (informational —
    /// always mobile confirmation for QR sessions).
    pub fn allowed_kinds(&self) -> &[GuardType] {
        &self.allowed_kinds
    }

    /// False once the CM has closed this connection. The pending sign-in
    /// lives on Steam's side and outlasts it; go on with
    /// [`continue_on`](Self::continue_on).
    pub fn is_connected(&self) -> bool {
        self.client.is_connected()
    }

    /// Go on over `client`, a new connection that has been through
    /// `connect → encrypt → prepare`. A CM closes a connection that has not
    /// logged on after about a minute, and a mobile app loses its connections
    /// in the background, while the user may take longer than that to
    /// approve.
    pub fn continue_on(&mut self, client: SteamClient<Ready>) {
        self.client = client;
    }

    /// Wait the server's poll interval, then ask `PollAuthSessionStatus` once.
    pub async fn poll(&mut self) -> Result<QrPoll, LoginError> {
        tokio::time::sleep(self.poll_interval.as_duration()).await;
        let status = self
            .client
            .poll_auth_session(self.client_id, &self.request_id)
            .await?;
        if let Some(tokens) = status.tokens {
            return Ok(QrPoll::Approved(tokens));
        }
        if let Some(client_id) = status.new_client_id {
            self.client_id = client_id;
        }
        match status.new_challenge_url {
            Some(url) => {
                self.challenge_url = url;
                Ok(QrPoll::ChallengeChanged)
            }
            None => Ok(QrPoll::Pending),
        }
    }

    /// Wrap the tokens from [`QrPoll::Approved`] for the final logon.
    pub fn into_approved(self, tokens: AuthTokens) -> ApprovedAuth {
        ApprovedAuth {
            client: self.client,
            config: self.config,
            tokens,
        }
    }

    /// Poll until the user scans and approves. Challenge replacements are
    /// followed but not reported, so this only suits a caller that cannot
    /// redraw the code; otherwise drive [`poll`](QrLoginFlow::poll) directly.
    pub async fn wait_for_scan(mut self) -> Result<ApprovedAuth, LoginError> {
        loop {
            if let QrPoll::Approved(tokens) = self.poll().await? {
                return Ok(self.into_approved(tokens));
            }
        }
    }
}
