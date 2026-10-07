//! In-memory transport for tests: the test plays the CM side through a
//! [`MemoryPeer`]. Payloads are exchanged unframed and unencrypted, as a
//! WebSocket connection would carry them, so use it with
//! [`SteamClient::connect_ws`](crate::client::SteamClient::connect_ws).

use super::Transport;
use crate::error::ConnectionError;
use crate::error::Error;
use bytes::Bytes;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

pub struct MemoryTransport {
    incoming: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    sent: mpsc::UnboundedSender<Vec<u8>>,
    dropped: Arc<AtomicBool>,
}

/// The CM end of a [`MemoryTransport`].
pub struct MemoryPeer {
    to_client: Option<mpsc::UnboundedSender<Vec<u8>>>,
    from_client: mpsc::UnboundedReceiver<Vec<u8>>,
    transport_dropped: Arc<AtomicBool>,
}

impl MemoryTransport {
    pub fn pair() -> (MemoryTransport, MemoryPeer) {
        let (to_client, incoming) = mpsc::unbounded_channel();
        let (sent, from_client) = mpsc::unbounded_channel();
        let dropped = Arc::new(AtomicBool::new(false));
        (
            MemoryTransport {
                incoming: Mutex::new(incoming),
                sent,
                dropped: Arc::clone(&dropped),
            },
            MemoryPeer {
                to_client: Some(to_client),
                from_client,
                transport_dropped: dropped,
            },
        )
    }
}

impl Drop for MemoryTransport {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl Transport for MemoryTransport {
    fn send(
        &self,
        payload: &[u8],
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send + '_>> {
        let payload = payload.to_vec();
        Box::pin(async move {
            self.sent
                .send(payload)
                .map_err(|_| ConnectionError::Disconnected)?;
            Ok(())
        })
    }

    fn recv(&self) -> Pin<Box<dyn std::future::Future<Output = Result<Bytes, Error>> + Send + '_>> {
        Box::pin(async move {
            self.incoming
                .lock()
                .await
                .recv()
                .await
                .map(Bytes::from)
                .ok_or_else(|| ConnectionError::Disconnected.into())
        })
    }
}

impl MemoryPeer {
    /// Next payload the client sent; `None` once the transport is gone.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.from_client.recv().await
    }

    /// Deliver a payload to the client. Fails after [`close`](Self::close) or
    /// once the transport is gone.
    pub fn send(&self, payload: Vec<u8>) -> Result<(), Error> {
        self.to_client
            .as_ref()
            .ok_or(ConnectionError::Disconnected)?
            .send(payload)
            .map_err(|_| ConnectionError::Disconnected.into())
    }

    /// Close the CM side: the client's next receive reports a disconnect.
    pub fn close(&mut self) {
        self.to_client = None;
    }

    /// Whether the client side has released the transport.
    pub fn transport_dropped(&self) -> bool {
        self.transport_dropped.load(Ordering::SeqCst)
    }
}
