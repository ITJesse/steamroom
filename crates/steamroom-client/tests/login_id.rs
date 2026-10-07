use prost::Message;
use std::time::Duration;
use steamroom::client::IncomingMsg;
use steamroom::client::SteamClient;
use steamroom::client::msg::ClientMsg;
use steamroom::generated;
use steamroom::generated::CMsgProtoBufHeader;
use steamroom::generated::c_msg_ip_address;
use steamroom::messages::EMsg;
use steamroom::transport::memory::MemoryPeer;
use steamroom::transport::memory::MemoryTransport;
use steamroom_client::login::PreparedLoginBuilder;

async fn next_sent(peer: &mut MemoryPeer) -> IncomingMsg {
    let data = tokio::time::timeout(Duration::from_secs(5), peer.recv())
        .await
        .expect("client sent nothing")
        .expect("client transport gone");
    IncomingMsg::parse(&data).unwrap()
}

/// Log in with a refresh token and return the `CMsgClientLogon` the client sent.
async fn sent_logon(login_id: Option<u32>) -> generated::CMsgClientLogon {
    let (transport, mut peer) = MemoryTransport::pair();
    let (client, _events) = SteamClient::connect_ws(transport).await.unwrap();
    let client = client.prepare().await.unwrap();
    assert_eq!(next_sent(&mut peer).await.emsg, EMsg::CLIENT_HELLO);

    let mut builder = PreparedLoginBuilder::new(client);
    if let Some(id) = login_id {
        builder = builder.login_id(id);
    }
    let login = tokio::spawn(builder.with_refresh_token("account", "token").login());

    let sent = next_sent(&mut peer).await;
    assert_eq!(sent.emsg, EMsg::CLIENT_LOGON);
    let logon = generated::CMsgClientLogon::decode(&*sent.body).unwrap();

    let body = generated::CMsgClientLogonResponse {
        eresult: Some(1),
        ..Default::default()
    }
    .encode_to_vec();
    peer.send(
        ClientMsg {
            emsg: EMsg::CLIENT_LOG_ON_RESPONSE,
            header: CMsgProtoBufHeader::default(),
            body: &body,
        }
        .to_bytes(),
    )
    .unwrap();
    login.await.unwrap().unwrap();
    logon
}

#[tokio::test]
async fn login_id_is_sent_as_the_obfuscated_private_ip() {
    let logon = sent_logon(Some(0x0102_0304)).await;
    let expected = 0x0102_0304 ^ 0xBAAD_F00D;
    assert_eq!(
        logon.obfuscated_private_ip.and_then(|ip| ip.ip),
        Some(c_msg_ip_address::Ip::V4(expected))
    );
    assert_eq!(logon.deprecated_obfustucated_private_ip, Some(expected));
}

#[tokio::test]
async fn no_login_id_leaves_the_private_ip_out() {
    let logon = sent_logon(None).await;
    assert_eq!(logon.obfuscated_private_ip, None);
    assert_eq!(logon.deprecated_obfustucated_private_ip, None);
}
