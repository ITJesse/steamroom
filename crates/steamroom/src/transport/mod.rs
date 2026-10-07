/// Serializable packet capture format for recording and replaying sessions.
pub mod capture;
/// In-memory transport for tests.
pub mod memory;
/// Wrap a transport to record all packets to a capture file.
pub mod recording;
/// Replay a previously captured session for deterministic testing.
pub mod replay;
/// TCP transport with VT01 framing and session cipher.
pub mod tcp;
/// WebSocket transport over TLS.
pub mod websocket;

use crate::error::Error;
use bytes::Bytes;
use std::time::Duration;

/// Idle time before the first keepalive probe on a CM connection, and the
/// time between probes.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Turn on TCP keepalive for a CM connection. A connection whose peer is
/// gone without a word (the network changed, or a NAT forgot the mapping)
/// then fails within a couple of minutes instead of leaving the receive
/// side waiting forever. Failing to set it is only logged.
pub(crate) fn enable_keepalive(stream: &tokio::net::TcpStream) {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL);
    if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive) {
        tracing::debug!(error = %e, "could not enable TCP keepalive");
    }
}

pub trait Transport: Send + Sync + 'static {
    fn send(
        &self,
        payload: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send + '_>>;

    fn recv(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Bytes, Error>> + Send + '_>>;
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn cm_connections_keep_alive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        super::enable_keepalive(&stream);
        let socket = socket2::SockRef::from(&stream);
        assert!(socket.keepalive().unwrap());
        assert_eq!(socket.tcp_keepalive_time().unwrap(), super::KEEPALIVE_IDLE);
    }
}
