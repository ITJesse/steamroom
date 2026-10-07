//! `ConfirmationChallenge::submit_code` and `wait_for_tokens` share one CM
//! connection. Each must get its own response even when they run at the same
//! time; a reader that consumed whichever response came first used to leave the
//! other call waiting forever.

use prost::Message;
use std::time::Duration;
use steamroom::client::IncomingMsg;
use steamroom::client::SteamClient;
use steamroom::client::msg::ClientMsg;
use steamroom::generated;
use steamroom::generated::CMsgProtoBufHeader;
use steamroom::messages::EMsg;
use steamroom::transport::memory::MemoryPeer;
use steamroom::transport::memory::MemoryTransport;
use steamroom_client::login::CredentialsLoginFlow;
use steamroom_client::login::GuardType;
use steamroom_client::login::PreparedLoginBuilder;

/// A throwaway 1024-bit RSA modulus; the test never decrypts the password.
const RSA_MODULUS: &str = "ADE1AADC0B8F0F9F910CC9B783A87A472823AF2D4098F3EC1DA340209F998D324FCCAB147AF50DBFB09C2D33DFDACC770582DDF8BF8D50DEA9627AD2086C4B73D9F11E2CF0FC6107D882792DAA3AF1E70F0F84529670349977C50A55AA7D3A239A4EB24E1D727E3AC20D191E9CA0E784D1654ACEA1BAF7E03730C8A12E9F1AF3";

async fn next_call(peer: &mut MemoryPeer) -> IncomingMsg {
    let data = tokio::time::timeout(Duration::from_secs(5), peer.recv())
        .await
        .expect("client sent nothing")
        .expect("client transport gone");
    IncomingMsg::parse(&data).unwrap()
}

fn reply(peer: &MemoryPeer, call: &IncomingMsg, body: Vec<u8>) {
    let header = CMsgProtoBufHeader {
        jobid_target: call.header.jobid_source,
        eresult: Some(1),
        ..Default::default()
    };
    peer.send(
        ClientMsg {
            emsg: EMsg::SERVICE_METHOD_RESPONSE,
            header,
            body: &body,
        }
        .to_bytes(),
    )
    .unwrap();
}

fn method(call: &IncomingMsg) -> &str {
    call.header.target_job_name.as_deref().unwrap()
}

#[tokio::test]
async fn code_submission_and_polling_do_not_steal_each_others_responses() {
    let (transport, mut peer) = MemoryTransport::pair();
    let (client, _events) = SteamClient::connect_ws(transport).await.unwrap();
    let client = client.prepare().await.unwrap();
    assert_eq!(next_call(&mut peer).await.emsg, EMsg::CLIENT_HELLO);

    let begin = tokio::spawn(
        PreparedLoginBuilder::new(client)
            .with_credentials("account", "password")
            .begin(),
    );

    let call = next_call(&mut peer).await;
    assert_eq!(method(&call), "Authentication.GetPasswordRSAPublicKey#1");
    reply(
        &peer,
        &call,
        generated::CAuthenticationGetPasswordRsaPublicKeyResponse {
            publickey_mod: Some(RSA_MODULUS.to_string()),
            publickey_exp: Some("010001".to_string()),
            timestamp: Some(1),
        }
        .encode_to_vec(),
    );

    let call = next_call(&mut peer).await;
    assert_eq!(
        method(&call),
        "Authentication.BeginAuthSessionViaCredentials#1"
    );
    let confirmation = |kind: GuardType| generated::CAuthenticationAllowedConfirmation {
        confirmation_type: Some(kind.to_proto()),
        ..Default::default()
    };
    reply(
        &peer,
        &call,
        generated::CAuthenticationBeginAuthSessionViaCredentialsResponse {
            client_id: Some(5),
            request_id: Some(vec![1, 2, 3]),
            interval: Some(0.01),
            steamid: Some(76561197960287930),
            allowed_confirmations: vec![
                confirmation(GuardType::EmailCode),
                confirmation(GuardType::DeviceConfirmation),
            ],
            ..Default::default()
        }
        .encode_to_vec(),
    );

    let challenge = match begin.await.unwrap().unwrap() {
        CredentialsLoginFlow::NeedsConfirmation(challenge) => challenge,
        _ => panic!("expected a confirmation challenge"),
    };
    let challenge = std::sync::Arc::new(challenge);
    let poll = tokio::spawn({
        let challenge = std::sync::Arc::clone(&challenge);
        async move { challenge.wait_for_tokens().await }
    });
    let submit = tokio::spawn({
        let challenge = std::sync::Arc::clone(&challenge);
        async move { challenge.submit_code("ABCDE", GuardType::EmailCode).await }
    });

    // Hold the first poll unanswered until the code submission is in flight,
    // then answer the submission before the poll.
    let mut pending_poll = None;
    let mut submission = None;
    while pending_poll.is_none() || submission.is_none() {
        let call = next_call(&mut peer).await;
        match method(&call) {
            "Authentication.PollAuthSessionStatus#1" => pending_poll = Some(call),
            "Authentication.UpdateAuthSessionWithSteamGuardCode#1" => submission = Some(call),
            other => panic!("unexpected call {other}"),
        }
    }
    reply(
        &peer,
        &submission.unwrap(),
        generated::CAuthenticationUpdateAuthSessionWithSteamGuardCodeResponse::default()
            .encode_to_vec(),
    );
    reply(
        &peer,
        &pending_poll.unwrap(),
        generated::CAuthenticationPollAuthSessionStatusResponse {
            access_token: Some("access".to_string()),
            refresh_token: Some("refresh".to_string()),
            account_name: Some("account".to_string()),
            ..Default::default()
        }
        .encode_to_vec(),
    );

    tokio::time::timeout(Duration::from_secs(5), submit)
        .await
        .expect("code submission never completed")
        .unwrap()
        .unwrap();
    let tokens = tokio::time::timeout(Duration::from_secs(5), poll)
        .await
        .expect("polling never completed")
        .unwrap()
        .unwrap();
    assert_eq!(tokens.refresh_token, "refresh");
}
