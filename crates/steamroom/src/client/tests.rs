use super::*;
use crate::generated::CMsgProtoBufHeader;
use crate::transport::memory::MemoryPeer;
use crate::transport::memory::MemoryTransport;
use std::io::Write;
use std::time::Duration;

struct MockServer {
    peer: MemoryPeer,
}

struct SentMsg {
    emsg: EMsg,
    header: CMsgProtoBufHeader,
}

impl MockServer {
    async fn next_sent(&mut self) -> SentMsg {
        let data = tokio::time::timeout(Duration::from_secs(5), self.peer.recv())
            .await
            .expect("client sent nothing")
            .expect("client transport gone");
        let msg = IncomingMsg::parse(&data).expect("client message parses");
        SentMsg {
            emsg: msg.emsg,
            header: msg.header,
        }
    }

    fn push(&self, packet: Vec<u8>) {
        self.peer.send(packet).expect("client gone");
    }

    fn close(&mut self) {
        self.peer.close();
    }
}

fn packet(emsg: EMsg, header: CMsgProtoBufHeader, body: &[u8]) -> Vec<u8> {
    ClientMsg { emsg, header, body }.to_bytes()
}

fn response_to(job: Option<u64>, emsg: EMsg, body: &[u8]) -> Vec<u8> {
    packet(
        emsg,
        CMsgProtoBufHeader {
            jobid_target: job,
            eresult: Some(1),
            ..Default::default()
        },
        body,
    )
}

fn push(emsg: EMsg, body: &[u8]) -> Vec<u8> {
    packet(emsg, CMsgProtoBufHeader::default(), body)
}

fn multi(packets: &[Vec<u8>], gzip: bool) -> Vec<u8> {
    let mut payload = Vec::new();
    for p in packets {
        payload.extend_from_slice(&(p.len() as u32).to_le_bytes());
        payload.extend_from_slice(p);
    }
    let (size_unzipped, message_body) = if gzip {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&payload).unwrap();
        (Some(payload.len() as u32), encoder.finish().unwrap())
    } else {
        (None, payload)
    };
    let body = generated::CMsgMulti {
        size_unzipped,
        message_body: Some(message_body),
    }
    .encode_to_vec();
    push(EMsg::MULTI, &body)
}

fn logon_response() -> Vec<u8> {
    let body = generated::CMsgClientLogonResponse {
        eresult: Some(1),
        heartbeat_seconds: Some(9),
        ..Default::default()
    }
    .encode_to_vec();
    packet(
        EMsg::CLIENT_LOG_ON_RESPONSE,
        CMsgProtoBufHeader {
            steamid: Some(76561197960287930),
            client_sessionid: Some(42),
            ..Default::default()
        },
        &body,
    )
}

async fn ready_client() -> (SteamClient<Ready>, MockServer) {
    let (transport, peer) = MemoryTransport::pair();
    let mut server = MockServer { peer };
    let (client, _events) = SteamClient::connect_ws(transport).await.unwrap();
    let client = client.prepare().await.unwrap();
    assert_eq!(server.next_sent().await.emsg, EMsg::CLIENT_HELLO);
    (client, server)
}

async fn logged_in_client() -> (SteamClient<LoggedIn>, MockServer) {
    let (client, mut server) = ready_client().await;
    let login = tokio::spawn(client.login(ClientMsg::new(EMsg::CLIENT_LOGON)));
    assert_eq!(server.next_sent().await.emsg, EMsg::CLIENT_LOGON);
    server.push(logon_response());
    let (client, _) = login.await.unwrap().unwrap();
    (client, server)
}

async fn next_event(events: &async_channel::Receiver<IncomingMsg>) -> IncomingMsg {
    tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("no event")
        .expect("event channel closed")
}

#[tokio::test]
async fn concurrent_requests_receive_their_own_responses() {
    let (client, mut server) = ready_client().await;
    let a = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .call_service_method_non_authed("A.Method#1", b"")
                .await
        }
    });
    let b = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .call_service_method_non_authed("B.Method#1", b"")
                .await
        }
    });

    let mut jobs = std::collections::HashMap::new();
    for _ in 0..2 {
        let sent = server.next_sent().await;
        assert_eq!(sent.emsg, EMsg::SERVICE_METHOD_CALL_FROM_CLIENT_NON_AUTHED);
        jobs.insert(
            sent.header.target_job_name.clone().unwrap(),
            sent.header.jobid_source,
        );
    }
    assert_ne!(jobs["A.Method#1"], jobs["B.Method#1"]);

    // Answer in the opposite order, B's response inside a MULTI with an
    // unrelated push.
    server.push(multi(
        &[
            push(EMsg::CLIENT_PERSONA_STATE, b"persona"),
            response_to(jobs["B.Method#1"], EMsg::SERVICE_METHOD_RESPONSE, b"for b"),
        ],
        false,
    ));
    server.push(response_to(
        jobs["A.Method#1"],
        EMsg::SERVICE_METHOD_RESPONSE,
        b"for a",
    ));

    assert_eq!(&*a.await.unwrap().unwrap().body, b"for a");
    assert_eq!(&*b.await.unwrap().unwrap().body, b"for b");
    let event = next_event(&client.events()).await;
    assert_eq!(event.emsg, EMsg::CLIENT_PERSONA_STATE);
}

#[tokio::test]
async fn login_keeps_messages_that_share_its_multi() {
    let (client, mut server) = ready_client().await;
    let login = tokio::spawn(client.login(ClientMsg::new(EMsg::CLIENT_LOGON)));
    assert_eq!(server.next_sent().await.emsg, EMsg::CLIENT_LOGON);

    server.push(multi(
        &[
            push(EMsg::CLIENT_LICENSE_LIST, b"licenses"),
            logon_response(),
            push(EMsg::CLIENT_ACCOUNT_INFO, b"account"),
        ],
        true,
    ));
    let (client, response) = login.await.unwrap().unwrap();
    assert_eq!(response.emsg, EMsg::CLIENT_LOG_ON_RESPONSE);

    // Subscribing after login still sees the pushes that came with it.
    let events = client.events();
    assert_eq!(next_event(&events).await.emsg, EMsg::CLIENT_LICENSE_LIST);
    assert_eq!(next_event(&events).await.emsg, EMsg::CLIENT_ACCOUNT_INFO);
}

#[tokio::test]
async fn logged_in_requests_carry_session_and_job() {
    let (client, mut server) = logged_in_client().await;
    let request = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .get_depot_decryption_key(DepotId(11), AppId(10))
                .await
        }
    });
    let sent = server.next_sent().await;
    assert_eq!(sent.emsg, EMsg::CLIENT_GET_DEPOT_DECRYPTION_KEY);
    assert_eq!(sent.header.steamid, Some(76561197960287930));
    assert_eq!(sent.header.client_sessionid, Some(42));
    let body = generated::CMsgClientGetDepotDecryptionKeyResponse {
        eresult: Some(1),
        depot_id: Some(11),
        depot_encryption_key: Some(vec![7; 32]),
    }
    .encode_to_vec();
    server.push(response_to(
        sent.header.jobid_source,
        EMsg::CLIENT_GET_DEPOT_DECRYPTION_KEY_RESPONSE,
        &body,
    ));
    assert_eq!(request.await.unwrap().unwrap().0, [7; 32]);
}

#[tokio::test]
async fn response_with_unexpected_emsg_is_an_error() {
    let (client, mut server) = logged_in_client().await;
    let request = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .get_depot_decryption_key(DepotId(11), AppId(10))
                .await
        }
    });
    let sent = server.next_sent().await;
    server.push(response_to(
        sent.header.jobid_source,
        EMsg::SERVICE_METHOD_RESPONSE,
        b"",
    ));
    assert!(matches!(
        request.await.unwrap(),
        Err(Error::Connection(ConnectionError::UnexpectedEMsg { .. }))
    ));
}

#[tokio::test]
async fn response_for_an_abandoned_job_is_not_an_event() {
    let (client, mut server) = ready_client().await;
    let abandoned = tokio::time::timeout(
        Duration::from_millis(50),
        client.call_service_method_non_authed("Slow.Method#1", b""),
    )
    .await;
    assert!(abandoned.is_err());
    let sent = server.next_sent().await;

    server.push(response_to(
        sent.header.jobid_source,
        EMsg::SERVICE_METHOD_RESPONSE,
        b"late",
    ));
    server.push(push(EMsg::CLIENT_ACCOUNT_INFO, b"account"));
    let event = next_event(&client.events()).await;
    assert_eq!(event.emsg, EMsg::CLIENT_ACCOUNT_INFO);
}

#[tokio::test]
async fn disconnect_fails_pending_and_later_requests() {
    let (client, mut server) = ready_client().await;
    server.push(push(EMsg::CLIENT_ACCOUNT_INFO, b"account"));
    let pending = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .call_service_method_non_authed("A.Method#1", b"")
                .await
        }
    });
    server.next_sent().await;
    server.close();

    assert!(matches!(
        pending.await.unwrap(),
        Err(Error::Connection(ConnectionError::Disconnected))
    ));
    assert!(!client.is_connected());
    assert!(matches!(
        client
            .call_service_method_non_authed("B.Method#1", b"")
            .await,
        Err(Error::Connection(ConnectionError::Disconnected))
    ));
    // Buffered events are still delivered, then the channel reports closed.
    let events = client.events();
    assert_eq!(next_event(&events).await.emsg, EMsg::CLIENT_ACCOUNT_INFO);
    assert!(events.recv().await.is_err());
}

#[tokio::test]
async fn dropping_the_client_stops_the_receive_loop() {
    let (client, server) = ready_client().await;
    let events = client.events();
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !server.peer.transport_dropped() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("transport still held after the last client handle was dropped");
    assert!(events.recv().await.is_err());
}

#[tokio::test]
async fn job_outliving_the_client_is_woken() {
    let (client, mut server) = ready_client().await;
    let mut job = client
        .send_job(ClientMsg::new(EMsg::CLIENT_PICS_ACCESS_TOKEN_REQUEST))
        .await
        .unwrap();
    server.next_sent().await;
    drop(client);
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), job.recv())
            .await
            .expect("job still waiting after the client was dropped"),
        Err(Error::Connection(ConnectionError::Disconnected))
    ));
}

#[tokio::test]
async fn event_buffer_keeps_the_newest_messages() {
    let (client, mut server) = ready_client().await;
    let total = EVENT_BUFFER + 6;
    for i in 0..total {
        server.push(push(EMsg::CLIENT_PERSONA_STATE, &(i as u32).to_le_bytes()));
    }
    // The receive loop handles packets in order, so once this round trip
    // completes every push above has been dispatched.
    let call = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .call_service_method_non_authed("Sync.Method#1", b"")
                .await
        }
    });
    let sent = server.next_sent().await;
    server.push(response_to(
        sent.header.jobid_source,
        EMsg::SERVICE_METHOD_RESPONSE,
        b"",
    ));
    call.await.unwrap().unwrap();

    let events = client.events();
    assert_eq!(events.len(), EVENT_BUFFER);
    let first = next_event(&events).await;
    assert_eq!(&*first.body, &6u32.to_le_bytes());
}

#[tokio::test]
async fn product_info_collects_every_response_part() {
    let (client, mut server) = logged_in_client().await;
    let request = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .pics_get_product_info(&[
                    AccessToken {
                        app_id: AppId(1),
                        token: 0,
                    },
                    AccessToken {
                        app_id: AppId(2),
                        token: 0,
                    },
                    AccessToken {
                        app_id: AppId(3),
                        token: 0,
                    },
                ])
                .await
        }
    });
    let sent = server.next_sent().await;
    assert_eq!(sent.emsg, EMsg::CLIENT_PICS_PRODUCT_INFO_REQUEST);
    for (appid, pending) in [(1, true), (2, true), (3, false)] {
        let body = generated::CMsgClientPicsProductInfoResponse {
            apps: vec![
                generated::c_msg_client_pics_product_info_response::AppInfo {
                    appid: Some(appid),
                    buffer: Some(vec![appid as u8]),
                    ..Default::default()
                },
            ],
            response_pending: Some(pending),
            ..Default::default()
        }
        .encode_to_vec();
        server.push(response_to(
            sent.header.jobid_source,
            EMsg::CLIENT_PICS_PRODUCT_INFO_RESPONSE,
            &body,
        ));
    }
    let apps = request.await.unwrap().unwrap();
    let ids: Vec<u32> = apps.iter().map(|a| a.app_id.unwrap().0).collect();
    assert_eq!(ids, [1, 2, 3]);
}
