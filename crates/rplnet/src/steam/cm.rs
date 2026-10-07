//! Finding a CM and opening a connection to it.
//!
//! Candidates come from Steam's directory (`GetCMListForConnect`), or from the
//! few servers steamroom has built in when the directory cannot be reached or
//! none of its servers answers. The first few candidates are tried at once and
//! the first to finish the handshake is used.

use crate::error::RplnetError;
use crate::error::RplnetNetworkFailure;
use std::future::Future;
use std::time::Duration;
use std::time::Instant;
use steamroom::client::Ready;
use steamroom::client::SteamClient;
use steamroom::connection::CmServer;
use steamroom::connection::CmServerAddr;
use steamroom::connection::Protocol;
use steamroom::depot::CellId;
use steamroom::transport::tcp::TcpTransport;
use steamroom::transport::websocket::WebSocketTransport;
use tokio::task::JoinSet;
use tracing::info;
use tracing::warn;

/// How long the directory request may take before the built-in servers are
/// used instead.
const DIRECTORY_TIMEOUT: Duration = Duration::from_secs(6);
/// How long one candidate may take to connect and finish the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How many candidates are tried at the same time.
const PARALLEL_CANDIDATES: usize = 4;

#[derive(Clone, Copy, Debug)]
enum Source {
    Directory,
    BuiltIn,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Directory => "directory",
            Self::BuiltIn => "built-in list",
        })
    }
}

/// Connect to a CM and finish the handshake, ready for a logon.
pub(crate) async fn connect() -> Result<SteamClient<Ready>, RplnetError> {
    connect_with(directory(), handshake).await
}

/// [`connect`] with the directory lookup and the handshake supplied, so the
/// fallback order can be tested without a network.
async fn connect_with<T, Fut>(
    directory: impl Future<Output = Option<Vec<CmServer>>>,
    handshake: impl Fn(CmServer) -> Fut + Copy,
) -> Result<T, RplnetError>
where
    T: Send + 'static,
    Fut: Future<Output = Result<T, RplnetError>> + Send + 'static,
{
    let mut last_error = None;
    if let Some(servers) = directory.await {
        match race(&servers, Source::Directory, handshake).await {
            Ok(client) => return Ok(client),
            Err(e) => {
                warn!("no CM from the directory answered ({e}); trying the built-in list");
                last_error = Some(e);
            }
        }
    }
    match race(&CmServer::defaults(), Source::BuiltIn, handshake).await {
        Ok(client) => Ok(client),
        Err(e) => Err(last_error.unwrap_or(e)),
    }
}

/// The directory's best candidates, or `None` when it cannot be used.
async fn directory() -> Option<Vec<CmServer>> {
    let started = Instant::now();
    let http = match crate::net::http() {
        Ok(http) => http,
        Err(e) => {
            warn!("CM directory skipped: {e}");
            return None;
        }
    };
    match tokio::time::timeout(DIRECTORY_TIMEOUT, CmServer::fetch(http, CellId(0))).await {
        Ok(Ok(servers)) if !servers.is_empty() => {
            info!(
                "CM directory returned {} servers in {} ms",
                servers.len(),
                started.elapsed().as_millis()
            );
            Some(servers.into_iter().take(PARALLEL_CANDIDATES).collect())
        }
        Ok(Ok(_)) => {
            warn!("CM directory returned no servers");
            None
        }
        Ok(Err(e)) => {
            warn!("CM directory failed: {}", RplnetError::from(e));
            None
        }
        Err(_) => {
            warn!(
                "CM directory did not answer within {} s",
                DIRECTORY_TIMEOUT.as_secs()
            );
            None
        }
    }
}

/// Try the first servers at once; the first finished handshake wins and the
/// other attempts are dropped.
async fn race<T, Fut>(
    servers: &[CmServer],
    source: Source,
    handshake: impl Fn(CmServer) -> Fut,
) -> Result<T, RplnetError>
where
    T: Send + 'static,
    Fut: Future<Output = Result<T, RplnetError>> + Send + 'static,
{
    let started = Instant::now();
    let mut attempts = JoinSet::new();
    for server in servers.iter().take(PARALLEL_CANDIDATES) {
        let attempt = handshake(server.clone());
        let server = server.clone();
        attempts.spawn(async move {
            let outcome = match tokio::time::timeout(HANDSHAKE_TIMEOUT, attempt).await {
                Ok(outcome) => outcome,
                Err(_) => Err(RplnetError::network(
                    RplnetNetworkFailure::Timeout,
                    format!("no handshake within {} s", HANDSHAKE_TIMEOUT.as_secs()),
                )),
            };
            (server, outcome)
        });
    }
    let mut last_error = None;
    while let Some(joined) = attempts.join_next().await {
        let Ok((server, outcome)) = joined else {
            continue;
        };
        match outcome {
            Ok(client) => {
                info!(
                    "connected to CM {} ({source}) in {} ms",
                    describe(&server),
                    started.elapsed().as_millis()
                );
                return Ok(client);
            }
            Err(e) => {
                warn!("CM {} ({source}) failed: {e}", describe(&server));
                last_error = Some(e);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        RplnetError::network(RplnetNetworkFailure::Unreachable, "no CM servers to try")
    }))
}

async fn handshake(server: CmServer) -> Result<SteamClient<Ready>, RplnetError> {
    let encrypted = match server.protocol {
        Protocol::Tcp => {
            let transport = TcpTransport::connect(&server).await?;
            let (client, _events) = SteamClient::connect(transport).await?;
            client.encrypt().await?
        }
        Protocol::WebSocket => {
            let transport = WebSocketTransport::connect(&server).await?;
            let (client, _events) = SteamClient::connect_ws(transport).await?;
            client
        }
    };
    Ok(encrypted.prepare().await?)
}

fn describe(server: &CmServer) -> String {
    let address = match &server.addr {
        CmServerAddr::Resolved(addr) => addr.to_string(),
        CmServerAddr::Dns { host, port } => format!("{host}:{port}"),
    };
    let protocol = match server.protocol {
        Protocol::Tcp => "tcp",
        Protocol::WebSocket => "websocket",
    };
    format!("{address}/{protocol}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;

    fn server(port: u16) -> CmServer {
        CmServer::from_endpoint(&format!("10.0.0.1:{port}"), Protocol::Tcp).unwrap()
    }

    fn port(server: &CmServer) -> u16 {
        match &server.addr {
            CmServerAddr::Resolved(addr) => addr.port(),
            CmServerAddr::Dns { port, .. } => *port,
        }
    }

    fn refused() -> RplnetError {
        RplnetError::network(RplnetNetworkFailure::Unreachable, "refused")
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_finished_handshake_wins() {
        let servers: Vec<CmServer> = (1..=4).map(server).collect();
        let winner = race(&servers, Source::Directory, |server| async move {
            match port(&server) {
                1 => Err(refused()),
                2 => {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    Ok(2)
                }
                3 => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    Ok(3)
                }
                _ => std::future::pending().await,
            }
        })
        .await
        .unwrap();
        assert_eq!(winner, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn only_the_first_candidates_are_tried() {
        let tried = Arc::new(Mutex::new(Vec::new()));
        let servers: Vec<CmServer> = (1..=6).map(server).collect();
        let outcome: Result<u16, _> = race(&servers, Source::Directory, |server| {
            tried.lock().unwrap().push(port(&server));
            async { Err(refused()) }
        })
        .await;
        assert!(outcome.is_err());
        let mut tried = tried.lock().unwrap().clone();
        tried.sort();
        assert_eq!(tried, vec![1, 2, 3, 4]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_server_times_out() {
        let outcome: Result<u16, _> = race(&[server(1)], Source::Directory, |_| async {
            std::future::pending().await
        })
        .await;
        let Err(RplnetError::Network { reason, .. }) = outcome else {
            panic!("expected a network error");
        };
        assert_eq!(reason, RplnetNetworkFailure::Timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn built_in_servers_follow_a_failed_directory() {
        let builtin: Vec<u16> = CmServer::defaults().iter().map(port).collect();
        let tried = Arc::new(Mutex::new(Vec::new()));
        let handshake = |server: CmServer| {
            let tried = Arc::clone(&tried);
            async move {
                let port = port(&server);
                tried.lock().unwrap().push(port);
                if port == 1 { Err(refused()) } else { Ok(port) }
            }
        };

        // The directory answered, but its server is down.
        let connected = connect_with(async { Some(vec![server(1)]) }, handshake)
            .await
            .unwrap();
        assert!(builtin.contains(&connected));
        assert_eq!(tried.lock().unwrap()[0], 1);

        // The directory could not be reached.
        tried.lock().unwrap().clear();
        let connected = connect_with(async { None }, handshake).await.unwrap();
        assert!(builtin.contains(&connected));
        assert!(!tried.lock().unwrap().contains(&1));
    }

    #[tokio::test(start_paused = true)]
    async fn the_directory_error_is_reported_when_everything_fails() {
        let outcome: Result<u16, _> =
            connect_with(async { Some(vec![server(1)]) }, |server| async move {
                if port(&server) == 1 {
                    Err(RplnetError::network(
                        RplnetNetworkFailure::Tls,
                        "directory server",
                    ))
                } else {
                    Err(refused())
                }
            })
            .await;
        let Err(RplnetError::Network { reason, .. }) = outcome else {
            panic!("expected a network error");
        };
        assert_eq!(reason, RplnetNetworkFailure::Tls);
    }
}
