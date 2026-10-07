//! Background receive loop and message routing for a CM connection.
//!
//! One task owns the receive side of the transport. Every packet is decrypted,
//! `MULTI` batches are flattened, and each message is routed:
//!
//! - a message whose header carries a `jobid_target` goes to the request that
//!   registered that job id (responses to a job nobody waits for any more are
//!   dropped);
//! - otherwise a one-shot waiter registered for its EMsg (the logon response)
//!   takes it;
//! - everything else (license list, account info, persona state, CM list,
//!   service notifications) goes to the event channel.
//!
//! Requests therefore never read the transport themselves, so several can be
//! in flight on one connection and no message is lost to a request loop that
//! was waiting for something else.

use super::IncomingMsg;
use super::multi;
use super::parse_incoming;
use crate::connection::encryption::SessionCipher;
use crate::error::ConnectionError;
use crate::error::Error;
use crate::messages::EMsg;
use crate::transport::Transport;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::debug;
use tracing::warn;

/// Messages the event channel holds before the oldest is discarded. Pushes
/// right after logon (license list, account info, persona, CM list) arrive
/// before the caller has had a chance to subscribe, so they are buffered; a
/// caller that never reads the channel costs at most this many messages.
pub const EVENT_BUFFER: usize = 1024;

/// `MULTI` nesting is not used by Steam in practice; the bound keeps a hostile
/// packet from recursing without limit.
const MAX_MULTI_DEPTH: usize = 4;

/// Identifier of a request on a CM connection (`jobid_source` on the request,
/// echoed as `jobid_target` on its responses).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct JobId(pub u64);

impl JobId {
    /// Steam's "no job" value in both the protobuf and the extended header.
    pub const NONE: JobId = JobId(u64::MAX);
}

/// The transport and session cipher, shared by the request side and the
/// receive task.
pub(crate) struct Channel {
    pub(crate) transport: Arc<dyn Transport>,
    pub(crate) cipher: OnceLock<SessionCipher>,
}

impl Channel {
    pub(crate) async fn send(&self, data: &[u8]) -> Result<(), Error> {
        match self.cipher.get() {
            Some(cipher) => self.transport.send(&cipher.encrypt(data)).await,
            None => self.transport.send(data).await,
        }
    }

    async fn recv(&self) -> Result<Vec<u8>, Error> {
        let raw = self.transport.recv().await?;
        match self.cipher.get() {
            Some(cipher) => Ok(cipher
                .decrypt(&raw)
                .map_err(|_| ConnectionError::EncryptionFailed)?),
            None => Ok(raw.to_vec()),
        }
    }
}

struct Routes {
    /// Set once the receive loop has stopped. New registrations fail from then
    /// on, so no request can wait on a connection that will never answer.
    closed: bool,
    jobs: HashMap<JobId, mpsc::UnboundedSender<IncomingMsg>>,
    emsg_waiters: HashMap<EMsg, oneshot::Sender<IncomingMsg>>,
}

pub(crate) struct Dispatcher {
    routes: Mutex<Routes>,
    events_tx: async_channel::Sender<IncomingMsg>,
    /// Kept so the channel stays open, and buffered pushes stay readable, even
    /// while no caller holds a receiver.
    events_rx: async_channel::Receiver<IncomingMsg>,
}

impl Dispatcher {
    pub(crate) fn new() -> Arc<Self> {
        let (events_tx, events_rx) = async_channel::bounded(EVENT_BUFFER);
        Arc::new(Self {
            routes: Mutex::new(Routes {
                closed: false,
                jobs: HashMap::new(),
                emsg_waiters: HashMap::new(),
            }),
            events_tx,
            events_rx,
        })
    }

    pub(crate) fn events(&self) -> async_channel::Receiver<IncomingMsg> {
        self.events_rx.clone()
    }

    fn routes(&self) -> std::sync::MutexGuard<'_, Routes> {
        // A panic while holding this lock can only come from a HashMap
        // operation; the maps stay structurally valid, so keep using them.
        self.routes.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn register_job(self: &Arc<Self>, id: JobId) -> Result<Job, Error> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut routes = self.routes();
        if routes.closed {
            return Err(ConnectionError::Disconnected.into());
        }
        routes.jobs.insert(id, tx);
        Ok(Job {
            id,
            rx,
            dispatcher: Arc::clone(self),
        })
    }

    pub(crate) fn wait_for_emsg(
        &self,
        emsg: EMsg,
    ) -> Result<oneshot::Receiver<IncomingMsg>, Error> {
        let (tx, rx) = oneshot::channel();
        let mut routes = self.routes();
        if routes.closed {
            return Err(ConnectionError::Disconnected.into());
        }
        routes.emsg_waiters.insert(emsg, tx);
        Ok(rx)
    }

    fn dispatch(&self, msg: IncomingMsg) {
        let mut routes = self.routes();
        if let Some(job) = msg.header.jobid_target.map(JobId)
            && job != JobId::NONE
            && job != JobId(0)
        {
            match routes.jobs.get(&job) {
                Some(tx) => {
                    // The receiver is only gone while its `Job` is being
                    // dropped, which also removes the route.
                    let _ = tx.send(msg);
                }
                None => {
                    debug!(job = job.0, emsg = ?msg.emsg, "response for an abandoned job dropped")
                }
            }
            return;
        }
        if let Some(tx) = routes.emsg_waiters.remove(&msg.emsg) {
            let _ = tx.send(msg);
            return;
        }
        drop(routes);
        // `force_send` displaces the oldest buffered event when the buffer is
        // full. It fails only once the channel is closed, which happens after
        // the receive loop (the only sender) has stopped.
        if let Ok(Some(displaced)) = self.events_tx.force_send(msg) {
            debug!(emsg = ?displaced.emsg, "event buffer full, oldest event discarded");
        }
    }

    pub(crate) fn close(&self) {
        let mut routes = self.routes();
        routes.closed = true;
        // Dropping the senders wakes every waiter with "disconnected".
        routes.jobs.clear();
        routes.emsg_waiters.clear();
        drop(routes);
        // Readers drain what is buffered and then see the channel closed.
        self.events_tx.close();
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.routes().closed
    }
}

/// An in-flight request. Responses addressed to its job id arrive here in
/// order; dropping it unregisters the job.
pub struct Job {
    id: JobId,
    rx: mpsc::UnboundedReceiver<IncomingMsg>,
    dispatcher: Arc<Dispatcher>,
}

impl Job {
    pub fn id(&self) -> JobId {
        self.id
    }

    /// Next response for this job. Fails with
    /// [`ConnectionError::Disconnected`] once the connection has closed.
    pub async fn recv(&mut self) -> Result<IncomingMsg, Error> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| ConnectionError::Disconnected.into())
    }

    /// Next response, which must carry `expected`.
    pub async fn recv_expect(&mut self, expected: EMsg) -> Result<IncomingMsg, Error> {
        let msg = self.recv().await?;
        if msg.emsg != expected {
            return Err(ConnectionError::UnexpectedEMsg {
                expected,
                got: msg.emsg,
            }
            .into());
        }
        Ok(msg)
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        self.dispatcher.routes().jobs.remove(&self.id);
    }
}

/// Receive loop. Runs until the transport fails or closes, then closes the
/// dispatcher so every pending request fails instead of hanging.
pub(crate) async fn receive_loop(channel: Arc<Channel>, dispatcher: Arc<Dispatcher>) {
    loop {
        let data = match channel.recv().await {
            Ok(data) => data,
            Err(Error::Connection(ConnectionError::Disconnected)) => {
                debug!("CM connection closed");
                break;
            }
            Err(e) => {
                warn!(error = %e, "CM connection receive failed");
                break;
            }
        };
        if let Err(e) = route_packet(&dispatcher, &data, 0) {
            // A packet that does not parse is dropped; the stream framing is
            // intact (the transport delivered a whole frame), so later packets
            // are still usable.
            warn!(error = %e, "undecodable CM packet dropped");
        }
    }
    dispatcher.close();
}

fn route_packet(dispatcher: &Dispatcher, data: &[u8], depth: usize) -> Result<(), Error> {
    let msg = parse_incoming(data)?;
    if msg.emsg != EMsg::MULTI {
        dispatcher.dispatch(msg);
        return Ok(());
    }
    if depth >= MAX_MULTI_DEPTH {
        return Err(ConnectionError::MultiTooDeep.into());
    }
    for sub in multi::unpack_multi(&msg.body)? {
        if let Err(e) = route_packet(dispatcher, &sub, depth + 1) {
            warn!(error = %e, "undecodable message in MULTI dropped");
        }
    }
    Ok(())
}

/// Background tasks owned by a client; aborted when the last handle to the
/// client is dropped.
#[derive(Default)]
pub(crate) struct Tasks(Mutex<Vec<tokio::task::AbortHandle>>);

impl Tasks {
    pub(crate) fn push(&self, handle: tokio::task::AbortHandle) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(handle);
    }
}

impl Drop for Tasks {
    fn drop(&mut self) {
        for handle in self
            .0
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            handle.abort();
        }
    }
}
