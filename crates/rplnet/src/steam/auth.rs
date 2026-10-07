//! Signing in to Steam: with the account name and password (plus Steam Guard
//! when the account has it), or with a QR code scanned in the Steam mobile
//! app.
//!
//! The app drives a sign-in step by step: read [`RplnetAuthSession::prompt`],
//! call [`poll`](RplnetAuthSession::poll) until it reports approval (entering
//! a code with [`submit_code`](RplnetAuthSession::submit_code) meanwhile if
//! the prompt offers one), then [`finish`](RplnetAuthSession::finish).

use super::RplnetConnectOptions;
use super::RplnetCredential;
use super::session::RplnetSteamSession;
use crate::error::RplnetAuthFailure;
use crate::error::RplnetError;
use crate::error::RplnetNetworkFailure;
use crate::error::RplnetSteamFailure;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use steamroom::client::Ready;
use steamroom::client::SteamClient;
use steamroom::enums::EResultError;
use steamroom::error::ConnectionError;
use steamroom_client::login::ApprovedAuth;
use steamroom_client::login::AuthTokens;
use steamroom_client::login::ConfirmationChallenge;
use steamroom_client::login::CredentialsLoginFlow;
use steamroom_client::login::GuardType;
use steamroom_client::login::LoginError;
use steamroom_client::login::PreparedLoginBuilder;
use steamroom_client::login::QrLoginFlow;
use steamroom_client::login::QrPoll;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// A Steam Guard code the user can type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RplnetGuardCode {
    /// From the Steam Guard screen of the Steam mobile app.
    Authenticator,
    /// From the email Steam sent to the account's address.
    Email,
}

/// The Steam Guard methods Steam accepts for this sign-in. Any of them
/// completes it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RplnetGuardChallenge {
    /// Steam sent an approval request to the Steam mobile app.
    pub mobile_approval: bool,
    /// Steam sent an email with an approval link.
    pub email_approval: bool,
    /// The code the user can enter instead, if any.
    pub code: Option<RplnetGuardCode>,
}

/// What the sign-in needs from the user next.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RplnetAuthPrompt {
    /// Nothing: Steam approved the sign-in. Call `finish`.
    Approved,
    /// Steam Guard: approve elsewhere or enter a code, while polling.
    SteamGuard { challenge: RplnetGuardChallenge },
    /// Show `url` as a QR code for the Steam mobile app, while polling.
    QrCode { url: String },
}

/// Outcome of one [`RplnetAuthSession::poll`].
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RplnetAuthPoll {
    /// Not approved yet; poll again.
    Pending,
    /// Steam replaced the QR code; show `url` instead, the old code no longer
    /// works.
    QrCodeChanged { url: String },
    /// Approved; call `finish`.
    Approved,
}

/// A signed-in account: the live session and what to keep for next time.
#[derive(uniffi::Record)]
pub struct RplnetSignedIn {
    pub session: Arc<RplnetSteamSession>,
    pub credential: RplnetCredential,
}

enum Flow {
    Credentials(ConfirmationChallenge),
    Qr(QrLoginFlow),
    Approved(ApprovedAuth),
}

impl Flow {
    fn is_connected(&self) -> bool {
        match self {
            Self::Credentials(challenge) => challenge.is_connected(),
            Self::Qr(qr) => qr.is_connected(),
            Self::Approved(approved) => approved.is_connected(),
        }
    }

    fn continue_on(&mut self, client: SteamClient<Ready>) {
        match self {
            Self::Credentials(challenge) => challenge.continue_on(client),
            Self::Qr(qr) => qr.continue_on(client),
            Self::Approved(approved) => approved.continue_on(client),
        }
    }
}

/// Opens a new CM connection for a sign-in whose connection closed.
pub(super) type Connector = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<SteamClient<Ready>, RplnetError>> + Send>>
        + Send
        + Sync,
>;

fn cm_connector() -> Connector {
    Arc::new(|| Box::pin(super::cm::connect()))
}

/// One sign-in attempt. Releasing it (or [`cancel`](Self::cancel)) abandons
/// the attempt and closes its connection.
#[derive(uniffi::Object)]
pub struct RplnetAuthSession {
    /// `None` once `finish` has taken it.
    flow: RwLock<Option<Flow>>,
    /// Issued by a poll that saw the approval, until `finish` uses them.
    tokens: Mutex<Option<AuthTokens>>,
    prompt: Mutex<RplnetAuthPrompt>,
    /// The kind of code `submit_code` sends, when the challenge takes one.
    code_kind: Option<GuardType>,
    connect: Connector,
    cancelled: CancellationToken,
}

impl RplnetAuthSession {
    fn new(
        flow: Flow,
        prompt: RplnetAuthPrompt,
        code_kind: Option<GuardType>,
        connect: Connector,
    ) -> Arc<Self> {
        Arc::new(Self {
            flow: RwLock::new(Some(flow)),
            tokens: Mutex::new(None),
            prompt: Mutex::new(prompt),
            code_kind,
            connect,
            cancelled: CancellationToken::new(),
        })
    }

    /// Move the sign-in to a new connection if the CM closed its own. Steam
    /// keeps the pending sign-in, so it goes on where it was.
    async fn reconnect_if_closed(&self) -> Result<(), RplnetError> {
        if self
            .flow
            .read()
            .await
            .as_ref()
            .is_none_or(Flow::is_connected)
        {
            return Ok(());
        }
        let mut flow = self.flow.write().await;
        let Some(flow) = flow.as_mut().filter(|flow| !flow.is_connected()) else {
            // Finished, or another call reconnected meanwhile.
            return Ok(());
        };
        info!("sign-in connection closed; reconnecting");
        let client = self.unless_cancelled((self.connect)()).await?;
        flow.continue_on(client);
        Ok(())
    }

    fn builder(ready: SteamClient<Ready>, options: RplnetConnectOptions) -> PreparedLoginBuilder {
        PreparedLoginBuilder::new(ready)
            .device_name(options.device_name)
            .login_id(options.login_id)
    }

    /// Run `work` unless or until the attempt is cancelled.
    async fn unless_cancelled<T>(
        &self,
        work: impl Future<Output = Result<T, RplnetError>>,
    ) -> Result<T, RplnetError> {
        tokio::select! {
            biased;
            () = self.cancelled.cancelled() => Err(RplnetError::Cancelled),
            outcome = work => outcome,
        }
    }

    /// One poll over the current connection.
    async fn poll_once(&self) -> Result<RplnetAuthPoll, RplnetError> {
        let is_qr = matches!(self.prompt(), RplnetAuthPrompt::QrCode { .. });
        if is_qr {
            // A QR poll may switch the flow to a new challenge.
            let mut flow = self.flow.write().await;
            let Some(Flow::Qr(qr)) = flow.as_mut() else {
                return Ok(RplnetAuthPoll::Approved);
            };
            let outcome = self
                .unless_cancelled(async { qr.poll().await.map_err(auth_error) })
                .await?;
            return Ok(match outcome {
                QrPoll::Approved(tokens) => self.approve(tokens),
                QrPoll::ChallengeChanged => {
                    let url = qr.challenge_url().to_string();
                    *self.prompt.lock().unwrap_or_else(|e| e.into_inner()) =
                        RplnetAuthPrompt::QrCode { url: url.clone() };
                    info!("Steam replaced the QR code");
                    RplnetAuthPoll::QrCodeChanged { url }
                }
                _ => RplnetAuthPoll::Pending,
            });
        }
        let flow = self.flow.read().await;
        let Some(Flow::Credentials(challenge)) = flow.as_ref() else {
            return Ok(RplnetAuthPoll::Approved);
        };
        let tokens = self
            .unless_cancelled(async { challenge.poll().await.map_err(auth_error) })
            .await?;
        Ok(match tokens {
            Some(tokens) => self.approve(tokens),
            None => RplnetAuthPoll::Pending,
        })
    }

    fn approve(&self, tokens: AuthTokens) -> RplnetAuthPoll {
        *self.tokens.lock().unwrap_or_else(|e| e.into_inner()) = Some(tokens);
        *self.prompt.lock().unwrap_or_else(|e| e.into_inner()) = RplnetAuthPrompt::Approved;
        info!("Steam approved the sign-in");
        RplnetAuthPoll::Approved
    }

    fn is_approved(&self) -> bool {
        matches!(
            *self.prompt.lock().unwrap_or_else(|e| e.into_inner()),
            RplnetAuthPrompt::Approved
        )
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl RplnetAuthSession {
    /// Start signing in with the account name and password.
    #[uniffi::constructor]
    pub async fn with_password(
        options: RplnetConnectOptions,
        account_name: String,
        password: String,
    ) -> Result<Arc<Self>, RplnetError> {
        let connect = cm_connector();
        let ready = connect().await?;
        Self::begin_with_password(ready, connect, options, account_name, password).await
    }

    /// Start signing in with a QR code.
    #[uniffi::constructor]
    pub async fn with_qr_code(options: RplnetConnectOptions) -> Result<Arc<Self>, RplnetError> {
        let connect = cm_connector();
        let ready = connect().await?;
        Self::begin_with_qr_code(ready, connect, options).await
    }

    pub fn prompt(&self) -> RplnetAuthPrompt {
        self.prompt
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Send the Steam Guard code the prompt asks for. A wrong code fails with
    /// `InvalidGuardCode` and can be retried; a right one is picked up by the
    /// next `poll`. Safe to call while a `poll` is running.
    pub async fn submit_code(&self, code: String) -> Result<(), RplnetError> {
        let Some(kind) = self.code_kind else {
            return Err(RplnetError::auth(
                RplnetAuthFailure::UnsupportedConfirmation,
                "this sign-in takes no code",
            ));
        };
        let code = code.trim().to_uppercase();
        self.reconnect_if_closed().await?;
        let flow = self.flow.read().await;
        let Some(Flow::Credentials(challenge)) = flow.as_ref() else {
            return Err(RplnetError::auth(
                RplnetAuthFailure::UnsupportedConfirmation,
                "this sign-in takes no code",
            ));
        };
        self.unless_cancelled(async {
            challenge.submit_code(&code, kind).await.map_err(auth_error)
        })
        .await?;
        info!("Steam accepted the Steam Guard code");
        Ok(())
    }

    /// Wait Steam's poll interval (a few seconds), then ask once whether the
    /// sign-in is approved. A connection the CM closes meanwhile counts as
    /// `Pending`; the next poll reconnects.
    pub async fn poll(&self) -> Result<RplnetAuthPoll, RplnetError> {
        if self.is_approved() {
            return Ok(RplnetAuthPoll::Approved);
        }
        self.reconnect_if_closed().await?;
        match self.poll_once().await {
            Err(RplnetError::Network {
                reason: RplnetNetworkFailure::ConnectionLost,
                detail,
            }) => {
                info!("sign-in connection lost while polling ({detail})");
                Ok(RplnetAuthPoll::Pending)
            }
            outcome => outcome,
        }
    }
    /// Log in to Steam with the approved sign-in.
    pub async fn finish(&self) -> Result<RplnetSignedIn, RplnetError> {
        self.reconnect_if_closed().await?;
        let mut slot = self.flow.write().await;
        let tokens = self.tokens.lock().unwrap_or_else(|e| e.into_inner()).take();
        let approved = match (slot.take(), tokens) {
            (Some(Flow::Approved(approved)), _) => approved,
            (Some(Flow::Credentials(challenge)), Some(tokens)) => challenge.into_approved(tokens),
            (Some(Flow::Qr(qr)), Some(tokens)) => qr.into_approved(tokens),
            (flow, tokens) => {
                *slot = flow;
                *self.tokens.lock().unwrap_or_else(|e| e.into_inner()) = tokens;
                return Err(RplnetError::steam(
                    RplnetSteamFailure::InvalidResponse,
                    "finish() before the sign-in was approved",
                ));
            }
        };
        let issued = approved.tokens();
        let account_name = issued.account_name.clone().ok_or_else(|| {
            RplnetError::steam(
                RplnetSteamFailure::InvalidResponse,
                "approval carries no account name",
            )
        })?;
        let refresh_token = issued.refresh_token.clone();
        let client = self
            .unless_cancelled(async { approved.finish().await.map_err(RplnetError::from) })
            .await?;
        let session = RplnetSteamSession::new(client, account_name.clone(), refresh_token.clone());
        let credential = RplnetCredential::new(session.steam_id(), account_name, refresh_token);
        Ok(RplnetSignedIn {
            session,
            credential,
        })
    }

    /// Abandon the sign-in: a running or later `poll`, `submit_code` or
    /// `finish` fails with `Cancelled`.
    pub fn cancel(&self) {
        self.cancelled.cancel();
    }
}

impl RplnetAuthSession {
    pub(super) async fn begin_with_password(
        ready: SteamClient<Ready>,
        connect: Connector,
        options: RplnetConnectOptions,
        account_name: String,
        password: String,
    ) -> Result<Arc<Self>, RplnetError> {
        let flow = Self::builder(ready, options)
            .with_credentials(account_name, password)
            .begin()
            .await
            .map_err(auth_error)?;
        match flow {
            CredentialsLoginFlow::Approved(approved) => {
                info!("sign-in needs no Steam Guard");
                Ok(Self::new(
                    Flow::Approved(approved),
                    RplnetAuthPrompt::Approved,
                    None,
                    connect,
                ))
            }
            CredentialsLoginFlow::NeedsConfirmation(challenge) => {
                let code_kind = [GuardType::DeviceCode, GuardType::EmailCode]
                    .into_iter()
                    .find(|kind| challenge.code_kinds().contains(kind));
                let guard = RplnetGuardChallenge {
                    mobile_approval: challenge
                        .confirmation_kinds()
                        .contains(&GuardType::DeviceConfirmation),
                    email_approval: challenge
                        .confirmation_kinds()
                        .contains(&GuardType::EmailConfirmation),
                    code: code_kind.map(|kind| match kind {
                        GuardType::DeviceCode => RplnetGuardCode::Authenticator,
                        _ => RplnetGuardCode::Email,
                    }),
                };
                info!("sign-in needs Steam Guard: {guard:?}");
                Ok(Self::new(
                    Flow::Credentials(challenge),
                    RplnetAuthPrompt::SteamGuard { challenge: guard },
                    code_kind,
                    connect,
                ))
            }
            _ => Err(RplnetError::steam(
                RplnetSteamFailure::InvalidResponse,
                "unknown sign-in flow",
            )),
        }
    }

    pub(super) async fn begin_with_qr_code(
        ready: SteamClient<Ready>,
        connect: Connector,
        options: RplnetConnectOptions,
    ) -> Result<Arc<Self>, RplnetError> {
        let flow = Self::builder(ready, options)
            .with_qr()
            .begin()
            .await
            .map_err(auth_error)?;
        let url = flow.challenge_url().to_string();
        info!("QR sign-in started");
        Ok(Self::new(
            Flow::Qr(flow),
            RplnetAuthPrompt::QrCode { url },
            None,
            connect,
        ))
    }
}

/// Errors of the sign-in calls. Steam answers some of them with a bare
/// EResult that means something specific here.
fn auth_error(e: LoginError) -> RplnetError {
    if let LoginError::Transport(steamroom::Error::Connection(
        ConnectionError::ServiceMethodFailed(eresult),
    )) = &e
    {
        let reason = match eresult {
            EResultError::RateLimitExceeded | EResultError::LoginDeniedThrottle => {
                Some(RplnetAuthFailure::RateLimited)
            }
            // The request was denied in the mobile app, or it timed out.
            EResultError::FileNotFound | EResultError::Expired => {
                Some(RplnetAuthFailure::RequestEnded)
            }
            EResultError::InvalidPassword => Some(RplnetAuthFailure::InvalidCredentials),
            _ => None,
        };
        if let Some(reason) = reason {
            return RplnetError::auth(reason, &e);
        }
    }
    e.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_reason(e: RplnetError) -> Option<RplnetAuthFailure> {
        match e {
            RplnetError::Auth { reason, .. } => Some(reason),
            _ => None,
        }
    }

    fn service_failure(eresult: EResultError) -> LoginError {
        LoginError::Transport(ConnectionError::ServiceMethodFailed(eresult).into())
    }

    #[test]
    fn sign_in_eresults_have_specific_reasons() {
        for (eresult, expected) in [
            (
                EResultError::RateLimitExceeded,
                RplnetAuthFailure::RateLimited,
            ),
            (
                EResultError::LoginDeniedThrottle,
                RplnetAuthFailure::RateLimited,
            ),
            (EResultError::FileNotFound, RplnetAuthFailure::RequestEnded),
            (EResultError::Expired, RplnetAuthFailure::RequestEnded),
            (
                EResultError::InvalidPassword,
                RplnetAuthFailure::InvalidCredentials,
            ),
        ] {
            assert_eq!(
                auth_reason(auth_error(service_failure(eresult))),
                Some(expected)
            );
        }
    }

    #[test]
    fn other_errors_keep_the_general_mapping() {
        assert_eq!(
            auth_reason(auth_error(LoginError::InvalidGuardCode)),
            Some(RplnetAuthFailure::InvalidGuardCode)
        );
        assert!(matches!(
            auth_error(service_failure(EResultError::Busy)),
            RplnetError::Steam { .. }
        ));
    }
}
