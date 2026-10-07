//! Sign-in and session flows against a scripted CM.

use super::RplnetConnectOptions;
use super::auth::Connector;
use super::auth::RplnetAuthPoll;
use super::auth::RplnetAuthPrompt;
use super::auth::RplnetAuthSession;
use super::auth::RplnetGuardChallenge;
use super::auth::RplnetGuardCode;
use super::session::RplnetSteamSession;
use crate::error::RplnetAuthFailure;
use crate::error::RplnetError;
use base64::Engine;
use prost::Message;
use std::sync::Arc;
use std::time::Duration;
use steamroom::client::IncomingMsg;
use steamroom::client::Ready;
use steamroom::client::SteamClient;
use steamroom::client::msg::ClientMsg;
use steamroom::generated;
use steamroom::generated::CMsgProtoBufHeader;
use steamroom::messages::EMsg;
use steamroom::transport::memory::MemoryPeer;
use steamroom::transport::memory::MemoryTransport;

const STEAM_ID: u64 = 76561197960287930;
const LOGIN_ID: u32 = 0x1234_5678;
/// A throwaway 1024-bit RSA modulus; nothing is ever decrypted with it.
const RSA_MODULUS: &str = "ADE1AADC0B8F0F9F910CC9B783A87A472823AF2D4098F3EC1DA340209F998D324FCCAB147AF50DBFB09C2D33DFDACC770582DDF8BF8D50DEA9627AD2086C4B73D9F11E2CF0FC6107D882792DAA3AF1E70F0F84529670349977C50A55AA7D3A239A4EB24E1D727E3AC20D191E9CA0E784D1654ACEA1BAF7E03730C8A12E9F1AF3";

fn options() -> RplnetConnectOptions {
    RplnetConnectOptions {
        device_name: "RenPyLinter test".to_string(),
        login_id: LOGIN_ID,
    }
}

/// For flows that must not reconnect.
fn no_reconnect() -> Connector {
    Arc::new(|| Box::pin(async { panic!("unexpected reconnect") }))
}

/// A connector that hands the CM side of each new connection to the test.
fn reconnecting() -> (Connector, tokio::sync::mpsc::UnboundedReceiver<Cm>) {
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    let connect: Connector = Arc::new(move || {
        let sender = sender.clone();
        Box::pin(async move {
            let (ready, cm) = Cm::ready().await;
            if sender.send(cm).is_err() {
                panic!("test gone");
            }
            Ok(ready)
        })
    });
    (connect, receiver)
}

fn refresh_token(exp: i64) -> String {
    let encode = |text: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text);
    format!(
        "{}.{}.signature",
        encode(r#"{"alg":"EdDSA"}"#),
        encode(&format!(r#"{{"sub":"{STEAM_ID}","exp":{exp}}}"#))
    )
}

/// The CM side of a [`MemoryTransport`].
struct Cm {
    peer: MemoryPeer,
}

impl Cm {
    async fn ready() -> (SteamClient<Ready>, Cm) {
        let (transport, peer) = MemoryTransport::pair();
        let mut cm = Cm { peer };
        let (client, _events) = SteamClient::connect_ws(transport).await.unwrap();
        let client = client.prepare().await.unwrap();
        assert_eq!(cm.next().await.emsg, EMsg::CLIENT_HELLO);
        (client, cm)
    }

    async fn next(&mut self) -> IncomingMsg {
        let data = tokio::time::timeout(Duration::from_secs(5), self.peer.recv())
            .await
            .expect("client sent nothing")
            .expect("client transport gone");
        IncomingMsg::parse(&data).unwrap()
    }

    /// The next message, which must call the service method `method`.
    async fn call(&mut self, method: &str) -> IncomingMsg {
        let call = self.next().await;
        assert_eq!(call.header.target_job_name.as_deref(), Some(method));
        call
    }

    fn reply(&self, call: &IncomingMsg, eresult: i32, body: impl Message) {
        let header = CMsgProtoBufHeader {
            jobid_target: call.header.jobid_source,
            eresult: Some(eresult),
            ..Default::default()
        };
        self.send(EMsg::SERVICE_METHOD_RESPONSE, header, body);
    }

    fn send(&self, emsg: EMsg, header: CMsgProtoBufHeader, body: impl Message) {
        let body = body.encode_to_vec();
        self.peer
            .send(
                ClientMsg {
                    emsg,
                    header,
                    body: &body,
                }
                .to_bytes(),
            )
            .unwrap();
    }

    fn push(&self, emsg: EMsg, body: impl Message) {
        self.send(emsg, CMsgProtoBufHeader::default(), body);
    }

    fn approve(&self, call: &IncomingMsg, refresh_token: &str) {
        self.reply(
            call,
            1,
            generated::CAuthenticationPollAuthSessionStatusResponse {
                access_token: Some("access".to_string()),
                refresh_token: Some(refresh_token.to_string()),
                account_name: Some("lanternfox".to_string()),
                ..Default::default()
            },
        );
    }

    /// Answer the `CMsgClientLogon` that follows an approval or a resume.
    async fn accept_logon(&mut self, expected_token: &str) {
        let logon = self.next().await;
        assert_eq!(logon.emsg, EMsg::CLIENT_LOGON);
        let body = generated::CMsgClientLogon::decode(&*logon.body).unwrap();
        assert_eq!(body.account_name.as_deref(), Some("lanternfox"));
        assert_eq!(body.access_token.as_deref(), Some(expected_token));
        assert_eq!(
            body.deprecated_obfustucated_private_ip,
            Some(LOGIN_ID ^ 0xBAAD_F00D)
        );
        self.send(
            EMsg::CLIENT_LOG_ON_RESPONSE,
            CMsgProtoBufHeader {
                steamid: Some(STEAM_ID),
                client_sessionid: Some(7),
                ..Default::default()
            },
            generated::CMsgClientLogonResponse {
                eresult: Some(1),
                ..Default::default()
            },
        );
    }

    /// Run a password sign-in up to the Steam Guard prompt.
    async fn password_challenge(offered: &[i32]) -> (Arc<RplnetAuthSession>, Cm) {
        Self::password_challenge_with(offered, no_reconnect()).await
    }

    async fn password_challenge_with(
        offered: &[i32],
        connect: Connector,
    ) -> (Arc<RplnetAuthSession>, Cm) {
        let (ready, mut cm) = Cm::ready().await;
        let begin = tokio::spawn(RplnetAuthSession::begin_with_password(
            ready,
            connect,
            options(),
            "lanternfox".to_string(),
            "password".to_string(),
        ));
        let call = cm.call("Authentication.GetPasswordRSAPublicKey#1").await;
        cm.reply(
            &call,
            1,
            generated::CAuthenticationGetPasswordRsaPublicKeyResponse {
                publickey_mod: Some(RSA_MODULUS.to_string()),
                publickey_exp: Some("010001".to_string()),
                timestamp: Some(1),
            },
        );
        let call = cm
            .call("Authentication.BeginAuthSessionViaCredentials#1")
            .await;
        let request =
            generated::CAuthenticationBeginAuthSessionViaCredentialsRequest::decode(&*call.body)
                .unwrap();
        assert_eq!(
            request.device_friendly_name.as_deref(),
            Some("RenPyLinter test")
        );
        cm.reply(
            &call,
            1,
            generated::CAuthenticationBeginAuthSessionViaCredentialsResponse {
                client_id: Some(5),
                request_id: Some(vec![1, 2, 3]),
                interval: Some(0.01),
                steamid: Some(STEAM_ID),
                allowed_confirmations: offered
                    .iter()
                    .map(|kind| generated::CAuthenticationAllowedConfirmation {
                        confirmation_type: Some(*kind),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            },
        );
        (begin.await.unwrap().unwrap(), cm)
    }
}

/// `EAuthSessionGuardType` values.
const EMAIL_CODE: i32 = 2;
const DEVICE_CODE: i32 = 3;
const DEVICE_CONFIRMATION: i32 = 4;

fn auth_reason(e: RplnetError) -> RplnetAuthFailure {
    match e {
        RplnetError::Auth { reason, .. } => reason,
        other => panic!("expected an auth error, got {other}"),
    }
}

#[tokio::test]
async fn qr_sign_in_follows_a_replaced_code_and_logs_in() {
    let (ready, mut cm) = Cm::ready().await;
    let begin = tokio::spawn(RplnetAuthSession::begin_with_qr_code(
        ready,
        no_reconnect(),
        options(),
    ));
    let call = cm.call("Authentication.BeginAuthSessionViaQR#1").await;
    cm.reply(
        &call,
        1,
        generated::CAuthenticationBeginAuthSessionViaQrResponse {
            client_id: Some(5),
            request_id: Some(vec![1, 2, 3]),
            challenge_url: Some("https://s.team/q/1/first".to_string()),
            interval: Some(0.01),
            ..Default::default()
        },
    );
    let auth = begin.await.unwrap().unwrap();
    assert_eq!(
        auth.prompt(),
        RplnetAuthPrompt::QrCode {
            url: "https://s.team/q/1/first".to_string()
        }
    );

    let poll = tokio::spawn({
        let auth = Arc::clone(&auth);
        async move { auth.poll().await }
    });
    let call = cm.call("Authentication.PollAuthSessionStatus#1").await;
    cm.reply(
        &call,
        1,
        generated::CAuthenticationPollAuthSessionStatusResponse {
            new_client_id: Some(9),
            new_challenge_url: Some("https://s.team/q/1/second".to_string()),
            ..Default::default()
        },
    );
    let second = RplnetAuthPrompt::QrCode {
        url: "https://s.team/q/1/second".to_string(),
    };
    assert_eq!(
        poll.await.unwrap().unwrap(),
        RplnetAuthPoll::QrCodeChanged {
            url: "https://s.team/q/1/second".to_string()
        }
    );
    assert_eq!(auth.prompt(), second);

    let token = refresh_token(1806192000);
    let poll = tokio::spawn({
        let auth = Arc::clone(&auth);
        async move { auth.poll().await }
    });
    let call = cm.call("Authentication.PollAuthSessionStatus#1").await;
    let request =
        generated::CAuthenticationPollAuthSessionStatusRequest::decode(&*call.body).unwrap();
    assert_eq!(request.client_id, Some(9));
    cm.approve(&call, &token);
    assert_eq!(poll.await.unwrap().unwrap(), RplnetAuthPoll::Approved);
    assert_eq!(auth.prompt(), RplnetAuthPrompt::Approved);

    let finish = tokio::spawn({
        let auth = Arc::clone(&auth);
        async move { auth.finish().await }
    });
    cm.accept_logon(&token).await;
    let signed_in = finish.await.unwrap().unwrap();
    assert_eq!(signed_in.credential.steam_id, STEAM_ID);
    assert_eq!(signed_in.credential.account_name, "lanternfox");
    assert_eq!(signed_in.credential.refresh_token, token);
    assert_eq!(signed_in.credential.expires_at, Some(1806192000));
    assert_eq!(signed_in.session.steam_id(), STEAM_ID);
}

#[tokio::test]
async fn password_sign_in_takes_an_authenticator_code() {
    let (auth, mut cm) = Cm::password_challenge(&[DEVICE_CONFIRMATION, DEVICE_CODE]).await;
    assert_eq!(
        auth.prompt(),
        RplnetAuthPrompt::SteamGuard {
            challenge: RplnetGuardChallenge {
                mobile_approval: true,
                email_approval: false,
                code: Some(RplnetGuardCode::Authenticator),
            }
        }
    );

    // A wrong code can be retried.
    let submit = tokio::spawn({
        let auth = Arc::clone(&auth);
        async move { auth.submit_code("wrong".to_string()).await }
    });
    let call = cm
        .call("Authentication.UpdateAuthSessionWithSteamGuardCode#1")
        .await;
    cm.reply(
        &call,
        88,
        generated::CAuthenticationUpdateAuthSessionWithSteamGuardCodeResponse::default(),
    );
    assert_eq!(
        auth_reason(submit.await.unwrap().unwrap_err()),
        RplnetAuthFailure::InvalidGuardCode
    );

    let submit = tokio::spawn({
        let auth = Arc::clone(&auth);
        async move { auth.submit_code(" r7kq2 ".to_string()).await }
    });
    let call = cm
        .call("Authentication.UpdateAuthSessionWithSteamGuardCode#1")
        .await;
    let request =
        generated::CAuthenticationUpdateAuthSessionWithSteamGuardCodeRequest::decode(&*call.body)
            .unwrap();
    assert_eq!(request.code.as_deref(), Some("R7KQ2"));
    assert_eq!(request.code_type, Some(DEVICE_CODE));
    assert_eq!(request.steamid, Some(STEAM_ID));
    cm.reply(
        &call,
        1,
        generated::CAuthenticationUpdateAuthSessionWithSteamGuardCodeResponse::default(),
    );
    submit.await.unwrap().unwrap();

    let poll = tokio::spawn({
        let auth = Arc::clone(&auth);
        async move { auth.poll().await }
    });
    let call = cm.call("Authentication.PollAuthSessionStatus#1").await;
    cm.approve(&call, &refresh_token(1));
    assert_eq!(poll.await.unwrap().unwrap(), RplnetAuthPoll::Approved);
}

#[tokio::test]
async fn email_code_challenge_is_reported() {
    let (auth, _cm) = Cm::password_challenge(&[EMAIL_CODE]).await;
    assert_eq!(
        auth.prompt(),
        RplnetAuthPrompt::SteamGuard {
            challenge: RplnetGuardChallenge {
                mobile_approval: false,
                email_approval: false,
                code: Some(RplnetGuardCode::Email),
            }
        }
    );
}

#[tokio::test]
async fn approval_only_challenge_takes_no_code() {
    let (auth, _cm) = Cm::password_challenge(&[DEVICE_CONFIRMATION]).await;
    assert_eq!(
        auth_reason(auth.submit_code("ABCDE".to_string()).await.unwrap_err()),
        RplnetAuthFailure::UnsupportedConfirmation
    );
}

#[tokio::test]
async fn a_denied_request_ends_the_sign_in() {
    let (auth, mut cm) = Cm::password_challenge(&[DEVICE_CONFIRMATION]).await;
    let poll = tokio::spawn({
        let auth = Arc::clone(&auth);
        async move { auth.poll().await }
    });
    let call = cm.call("Authentication.PollAuthSessionStatus#1").await;
    // FileNotFound: the session is gone.
    cm.reply(
        &call,
        9,
        generated::CAuthenticationPollAuthSessionStatusResponse::default(),
    );
    assert_eq!(
        auth_reason(poll.await.unwrap().unwrap_err()),
        RplnetAuthFailure::RequestEnded
    );
}

#[tokio::test]
async fn cancel_stops_a_running_poll() {
    let (auth, mut cm) = Cm::password_challenge(&[DEVICE_CONFIRMATION]).await;
    let poll = tokio::spawn({
        let auth = Arc::clone(&auth);
        async move { auth.poll().await }
    });
    // Leave the poll unanswered.
    cm.call("Authentication.PollAuthSessionStatus#1").await;
    auth.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(5), poll)
        .await
        .expect("poll did not stop")
        .unwrap();
    assert!(matches!(outcome, Err(RplnetError::Cancelled)));
    assert!(matches!(auth.poll().await, Err(RplnetError::Cancelled)));
}

#[tokio::test]
async fn finish_before_approval_keeps_the_sign_in() {
    let (auth, mut cm) = Cm::password_challenge(&[DEVICE_CONFIRMATION]).await;
    assert!(auth.finish().await.is_err());

    let poll = tokio::spawn({
        let auth = Arc::clone(&auth);
        async move { auth.poll().await }
    });
    let call = cm.call("Authentication.PollAuthSessionStatus#1").await;
    cm.approve(&call, &refresh_token(1));
    assert_eq!(poll.await.unwrap().unwrap(), RplnetAuthPoll::Approved);
}

async fn resumed_session() -> (Arc<RplnetSteamSession>, Cm, String) {
    let (ready, mut cm) = Cm::ready().await;
    let token = refresh_token(1806192000);
    let resume = tokio::spawn(RplnetSteamSession::resume_on(
        ready,
        options(),
        "lanternfox".to_string(),
        token.clone(),
    ));
    cm.accept_logon(&token).await;
    (resume.await.unwrap().unwrap(), cm, token)
}

#[tokio::test]
async fn profile_reads_the_name_and_avatar() {
    let (session, mut cm, _) = resumed_session().await;
    cm.push(
        EMsg::CLIENT_ACCOUNT_INFO,
        generated::CMsgClientAccountInfo {
            persona_name: Some("LanternFox".to_string()),
            ..Default::default()
        },
    );
    let profile = tokio::spawn({
        let session = Arc::clone(&session);
        async move { session.profile().await }
    });
    let request = cm.next().await;
    assert_eq!(request.emsg, EMsg::CLIENT_REQUEST_FRIEND_DATA);
    let body = generated::CMsgClientRequestFriendData::decode(&*request.body).unwrap();
    assert_eq!(body.friends, vec![STEAM_ID]);
    cm.push(
        EMsg::CLIENT_PERSONA_STATE,
        generated::CMsgClientPersonaState {
            friends: vec![
                generated::c_msg_client_persona_state::Friend {
                    friendid: Some(STEAM_ID + 1),
                    avatar_hash: Some(vec![0xaa; 20]),
                    ..Default::default()
                },
                generated::c_msg_client_persona_state::Friend {
                    friendid: Some(STEAM_ID),
                    avatar_hash: Some(vec![0xfe, 0xf4]),
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
    );
    let profile = profile.await.unwrap().unwrap();
    assert_eq!(profile.persona_name.as_deref(), Some("LanternFox"));
    assert_eq!(
        profile.avatar_url.as_deref(),
        Some("https://avatars.steamstatic.com/fef4_full.jpg")
    );
}

#[tokio::test]
async fn renewal_replaces_the_token_only_when_steam_issues_one() {
    let (session, mut cm, token) = resumed_session().await;

    let renew = tokio::spawn({
        let session = Arc::clone(&session);
        async move { session.renew_refresh_token().await }
    });
    let call = cm.call("Authentication.GenerateAccessTokenForApp#1").await;
    let request =
        generated::CAuthenticationAccessTokenGenerateForAppRequest::decode(&*call.body).unwrap();
    assert_eq!(request.refresh_token.as_deref(), Some(token.as_str()));
    assert_eq!(request.steamid, Some(STEAM_ID));
    assert_eq!(request.renewal_type, Some(1));
    cm.reply(
        &call,
        1,
        generated::CAuthenticationAccessTokenGenerateForAppResponse {
            access_token: Some("access".to_string()),
            ..Default::default()
        },
    );
    assert!(renew.await.unwrap().unwrap().is_none());

    let renewed = refresh_token(1900000000);
    let renew = tokio::spawn({
        let session = Arc::clone(&session);
        async move { session.renew_refresh_token().await }
    });
    let call = cm.call("Authentication.GenerateAccessTokenForApp#1").await;
    cm.reply(
        &call,
        1,
        generated::CAuthenticationAccessTokenGenerateForAppResponse {
            access_token: Some("access".to_string()),
            refresh_token: Some(renewed.clone()),
        },
    );
    let credential = renew.await.unwrap().unwrap().unwrap();
    assert_eq!(credential.refresh_token, renewed);
    assert_eq!(credential.expires_at, Some(1900000000));

    // The next renewal sends the new token.
    let renew = tokio::spawn({
        let session = Arc::clone(&session);
        async move { session.renew_refresh_token().await }
    });
    let call = cm.call("Authentication.GenerateAccessTokenForApp#1").await;
    let request =
        generated::CAuthenticationAccessTokenGenerateForAppRequest::decode(&*call.body).unwrap();
    assert_eq!(request.refresh_token.as_deref(), Some(renewed.as_str()));
    cm.reply(
        &call,
        1,
        generated::CAuthenticationAccessTokenGenerateForAppResponse::default(),
    );
    assert!(renew.await.unwrap().unwrap().is_none());
}

#[tokio::test]
async fn polling_reconnects_after_the_cm_closes_the_connection() {
    let (connect, mut reconnected) = reconnecting();
    let (auth, mut cm) = Cm::password_challenge_with(&[DEVICE_CONFIRMATION], connect).await;
    cm.peer.close();

    let polling = tokio::spawn({
        let auth = Arc::clone(&auth);
        async move {
            loop {
                match auth.poll().await {
                    Ok(RplnetAuthPoll::Pending) => {}
                    other => return other,
                }
            }
        }
    });
    let mut cm = tokio::time::timeout(Duration::from_secs(5), reconnected.recv())
        .await
        .expect("no reconnect")
        .unwrap();
    let call = cm.call("Authentication.PollAuthSessionStatus#1").await;
    let request =
        generated::CAuthenticationPollAuthSessionStatusRequest::decode(&*call.body).unwrap();
    assert_eq!(request.client_id, Some(5));
    assert_eq!(request.request_id.as_deref(), Some(&[1u8, 2, 3][..]));
    let token = refresh_token(1);
    cm.approve(&call, &token);
    assert_eq!(polling.await.unwrap().unwrap(), RplnetAuthPoll::Approved);

    // The logon goes over the new connection too.
    let finish = tokio::spawn({
        let auth = Arc::clone(&auth);
        async move { auth.finish().await }
    });
    cm.accept_logon(&token).await;
    assert_eq!(finish.await.unwrap().unwrap().session.steam_id(), STEAM_ID);
}
