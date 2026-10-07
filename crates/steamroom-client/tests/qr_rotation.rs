//! Steam replaces a pending QR challenge every so often. The flow has to report
//! the new URL and poll with the new client id from then on; polling with the
//! old id never sees the approval.

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
use steamroom_client::login::PreparedLoginBuilder;
use steamroom_client::login::QrPoll;

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

fn polled_client_id(call: &IncomingMsg) -> u64 {
    assert_eq!(method(call), "Authentication.PollAuthSessionStatus#1");
    generated::CAuthenticationPollAuthSessionStatusRequest::decode(&*call.body)
        .unwrap()
        .client_id
        .unwrap()
}

#[tokio::test]
async fn poll_follows_a_replaced_challenge() {
    let (transport, mut peer) = MemoryTransport::pair();
    let (client, _events) = SteamClient::connect_ws(transport).await.unwrap();
    let client = client.prepare().await.unwrap();
    assert_eq!(next_call(&mut peer).await.emsg, EMsg::CLIENT_HELLO);

    let begin = tokio::spawn(PreparedLoginBuilder::new(client).with_qr().begin());
    let call = next_call(&mut peer).await;
    assert_eq!(method(&call), "Authentication.BeginAuthSessionViaQR#1");
    reply(
        &peer,
        &call,
        generated::CAuthenticationBeginAuthSessionViaQrResponse {
            client_id: Some(5),
            request_id: Some(vec![1, 2, 3]),
            challenge_url: Some("https://s.team/q/1/first".to_string()),
            interval: Some(0.01),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    let mut flow = begin.await.unwrap().unwrap();
    assert_eq!(flow.challenge_url(), "https://s.team/q/1/first");

    let poll = tokio::spawn(async move {
        let outcome = flow.poll().await;
        (flow, outcome)
    });
    let call = next_call(&mut peer).await;
    assert_eq!(polled_client_id(&call), 5);
    reply(
        &peer,
        &call,
        generated::CAuthenticationPollAuthSessionStatusResponse {
            new_client_id: Some(9),
            new_challenge_url: Some("https://s.team/q/1/second".to_string()),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    let (mut flow, outcome) = poll.await.unwrap();
    assert!(matches!(outcome.unwrap(), QrPoll::ChallengeChanged));
    assert_eq!(flow.challenge_url(), "https://s.team/q/1/second");

    let poll = tokio::spawn(async move {
        let outcome = flow.poll().await;
        (flow, outcome)
    });
    let call = next_call(&mut peer).await;
    assert_eq!(polled_client_id(&call), 9);
    reply(
        &peer,
        &call,
        generated::CAuthenticationPollAuthSessionStatusResponse {
            access_token: Some("access".to_string()),
            refresh_token: Some("refresh".to_string()),
            account_name: Some("account".to_string()),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    let (flow, outcome) = poll.await.unwrap();
    let QrPoll::Approved(tokens) = outcome.unwrap() else {
        panic!("expected approval");
    };
    assert_eq!(flow.into_approved(tokens).tokens().refresh_token, "refresh");
}
