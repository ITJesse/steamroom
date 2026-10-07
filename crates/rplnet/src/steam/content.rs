//! Depot content: content servers, manifests, and single files, for telling
//! whether a game is Ren'Py and reading its engine version (plan stage 4).

use super::library::RplnetDepotCandidate;
use super::renpy;
use crate::error::RplnetError;
use crate::error::RplnetNetworkFailure;
use crate::error::RplnetSteamFailure;
use bytes::Bytes;
use std::collections::HashMap;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use steamroom::cdn::CdnClient;
use steamroom::cdn::CdnServerPool;
use steamroom::cdn::ContentServer;
use steamroom::cdn::ContentServerLocation;
use steamroom::cdn::server::CdnServer;
use steamroom::client::LoggedIn;
use steamroom::client::SteamClient;
use steamroom::depot::AppId;
use steamroom::depot::ChunkId;
use steamroom::depot::DepotId;
use steamroom::depot::DepotKey;
use steamroom::depot::ManifestId;
use steamroom::depot::manifest::DepotManifest;
use steamroom::depot::manifest::ManifestFile;
use steamroom::error::ConnectionError;
use steamroom_client::download::ChunkFetcher;
use tracing::info;
use tracing::warn;

/// How many content servers to ask the directory for.
const MAX_CONTENT_SERVERS: u32 = 20;
/// Depots tried per game before giving up on it.
const DEPOTS_PER_GAME: usize = 3;
/// `EDepotFileFlag::Directory`.
const DIRECTORY_FLAG: u32 = 0x40;
/// Engine version files are a few KiB; anything larger is not one.
const VERSION_FILE_LIMIT: u64 = 4 * 1024 * 1024;

/// What a game's depots show.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RplnetInspection {
    pub app_id: u32,
    /// The depot and manifest the verdict comes from: the Ren'Py one, or else
    /// the first one that could be read. `None` when none could be read.
    pub depot_id: Option<u32>,
    pub manifest_id: Option<u64>,
    /// Set when the game is Ren'Py.
    pub renpy: Option<RplnetRenPyLayout>,
    /// Candidates whose key Steam refused (the account may not download them).
    pub denied_depots: Vec<u32>,
}

/// Where a Ren'Py game sits in its depot.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RplnetRenPyLayout {
    /// Directory holding `game/` and `renpy/`, relative to the depot root in
    /// the depot's case: empty, or ending in `/`.
    pub root: String,
    /// Story files below the root (`renpy::is_story_file`): what an import
    /// downloads.
    pub file_count: u64,
    pub total_size: u64,
    /// Supporting signs, for logs only.
    pub hints: Vec<String>,
    /// Engine version files written under the requested directory, as paths
    /// relative to it (they keep their depot paths, root included). Empty
    /// when no directory was given.
    pub version_files: Vec<String>,
}

/// A CDN region: Steam picks content servers as if the request came from one
/// of `probe_ips` (`ip_override`). The app has the list of regions.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RplnetContentRegion {
    pub id: String,
    /// Addresses fixed in the region, tried in order.
    pub probe_ips: Vec<String>,
    /// Fragments of the host names expected there; a mismatch is logged.
    pub expect_hosts: Vec<String>,
}

/// How long a content server list is used before it is fetched again.
const SERVERS_TTL: Duration = Duration::from_secs(10 * 60);

/// Content servers for the session, per region, refreshed every
/// [`SERVERS_TTL`].
#[derive(Default)]
pub(crate) struct Content {
    region: std::sync::Mutex<Option<RplnetContentRegion>>,
    servers: tokio::sync::Mutex<Option<CachedServers>>,
}

struct CachedServers {
    region: Option<RplnetContentRegion>,
    fetched: Instant,
    servers: Arc<Servers>,
}

/// The CDN client and server pool every manifest and chunk request of a
/// session shares, with the CDN auth tokens obtained so far.
pub(crate) struct Servers {
    cdn: CdnClient,
    pool: CdnServerPool,
    /// Per (depot, host): some depots need a token for each server.
    tokens: std::sync::Mutex<HashMap<(u32, String), String>>,
}

impl Content {
    /// Use `region` for content servers from now on; `None` lets Steam pick.
    pub(crate) fn set_region(&self, region: Option<RplnetContentRegion>) {
        *self.region.lock().unwrap_or_else(|e| e.into_inner()) = region;
    }

    fn region(&self) -> Option<RplnetContentRegion> {
        self.region
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Forget the server list, so the next request fetches a new one.
    pub(crate) async fn invalidate(&self) {
        *self.servers.lock().await = None;
    }

    pub(crate) async fn servers(
        &self,
        client: &SteamClient<LoggedIn>,
    ) -> Result<Arc<Servers>, RplnetError> {
        let region = self.region();
        let mut cached = self.servers.lock().await;
        if let Some(entry) = cached.as_ref()
            && entry.region == region
            && entry.fetched.elapsed() < SERVERS_TTL
        {
            return Ok(Arc::clone(&entry.servers));
        }
        let servers = match &region {
            None => {
                let directory = client
                    .get_content_servers(
                        ContentServerLocation::Automatic,
                        Some(MAX_CONTENT_SERVERS),
                    )
                    .await?;
                let servers = download_servers(&directory);
                if servers.is_empty() {
                    return Err(RplnetError::network(
                        RplnetNetworkFailure::Unreachable,
                        format!("no usable content server among {}", directory.len()),
                    ));
                }
                info!("content servers (automatic): {}", describe(&servers));
                servers
            }
            Some(region) => regional_servers(client, region).await?,
        };
        let servers = Arc::new(Servers {
            cdn: CdnClient::with_client(crate::net::http()?.clone()),
            pool: CdnServerPool::new(servers),
            tokens: std::sync::Mutex::new(HashMap::new()),
        });
        *cached = Some(CachedServers {
            region,
            fetched: Instant::now(),
            servers: Arc::clone(&servers),
        });
        Ok(servers)
    }

    /// Inspect the depots of a game until one is Ren'Py or
    /// [`DEPOTS_PER_GAME`] have been read. When `version_dir` is set and the
    /// game is Ren'Py, its engine version files are written there.
    pub(crate) async fn inspect(
        &self,
        client: &SteamClient<LoggedIn>,
        app_id: u32,
        depots: &[RplnetDepotCandidate],
        version_dir: Option<&Path>,
    ) -> Result<RplnetInspection, RplnetError> {
        let started = std::time::Instant::now();
        let mut inspection = RplnetInspection {
            app_id,
            depot_id: None,
            manifest_id: None,
            renpy: None,
            denied_depots: Vec::new(),
        };
        let mut read = 0;
        for candidate in depots {
            if read == DEPOTS_PER_GAME {
                break;
            }
            let key = match client
                .get_depot_decryption_key(DepotId(candidate.depot_id), AppId(app_id))
                .await
            {
                Ok(key) => key,
                Err(steamroom::Error::Connection(ConnectionError::DepotAccessDenied(_))) => {
                    inspection.denied_depots.push(candidate.depot_id);
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let (_, manifest) = self.manifest(client, app_id, candidate, &key).await?;
            read += 1;
            if inspection.depot_id.is_none() {
                inspection.depot_id = Some(candidate.depot_id);
                inspection.manifest_id = Some(candidate.manifest_id);
            }
            let Some(layout) = renpy_layout(&manifest) else {
                continue;
            };
            inspection.depot_id = Some(candidate.depot_id);
            inspection.manifest_id = Some(candidate.manifest_id);
            let version_files = match version_dir {
                Some(dir) => {
                    self.write_version_files(
                        client,
                        app_id,
                        candidate.depot_id,
                        &key,
                        &manifest,
                        &layout.root,
                        dir,
                    )
                    .await?
                }
                None => Vec::new(),
            };
            inspection.renpy = Some(RplnetRenPyLayout {
                root: layout.root,
                file_count: layout.file_count,
                total_size: layout.total_size,
                hints: layout.hints,
                version_files,
            });
            break;
        }
        info!(
            "inspected app {app_id}: {} (depot {:?}, {} denied) in {} ms",
            if inspection.renpy.is_some() {
                "Ren'Py"
            } else {
                "not Ren'Py"
            },
            inspection.depot_id,
            inspection.denied_depots.len(),
            started.elapsed().as_millis()
        );
        Ok(inspection)
    }

    /// A depot manifest: the bytes as the CDN sent them, and parsed with its
    /// file names decrypted.
    pub(crate) async fn manifest(
        &self,
        client: &SteamClient<LoggedIn>,
        app_id: u32,
        candidate: &RplnetDepotCandidate,
        key: &DepotKey,
    ) -> Result<(Bytes, DepotManifest), RplnetError> {
        let depot = DepotId(candidate.depot_id);
        let manifest_id = ManifestId(candidate.manifest_id);
        let code = client
            .get_manifest_request_code(AppId(app_id), depot, manifest_id, Some("public"), None)
            .await?
            .unwrap_or(0);
        let servers = self.servers(client).await?;
        let raw = match servers
            .cdn
            .download_manifest_pooled(&servers.pool, depot, manifest_id, code, None)
            .await
        {
            Ok(raw) => raw,
            Err(steamroom::Error::CdnStatus { status, .. })
                if status.as_u16() == 401 || status.as_u16() == 403 =>
            {
                // Some depots need a CDN auth token for the server.
                let (server, _) = servers.pool.pick();
                let server = server.clone();
                let token = servers.token(client, app_id, depot, &server.host).await?;
                servers
                    .cdn
                    .download_manifest(&server, depot, manifest_id, code, token.as_deref())
                    .await?
            }
            Err(e) => return Err(e.into()),
        };
        let manifest = parse_manifest(&raw, key)?;
        Ok((raw, manifest))
    }

    /// Write the files carrying the engine version of the Ren'Py game at
    /// `root` into `dir`, at their depot paths, with the `lib/` directories
    /// the version probe looks at. Returns the paths written.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn write_version_files(
        &self,
        client: &SteamClient<LoggedIn>,
        app_id: u32,
        depot_id: u32,
        key: &DepotKey,
        manifest: &DepotManifest,
        root: &str,
        dir: &Path,
    ) -> Result<Vec<String>, RplnetError> {
        let entries: Vec<_> = manifest
            .files
            .iter()
            .map(|file| (file.normalized_path(), file))
            .collect();
        let listing: Vec<renpy::Entry<'_>> = entries
            .iter()
            .map(|(path, file)| renpy::Entry {
                path,
                size: file.size,
                is_dir: file.flags & DIRECTORY_FLAG != 0,
            })
            .collect();
        let wanted = renpy::version_files(&listing, root);
        let files: Vec<&ManifestFile> = entries
            .iter()
            .filter(|(path, _)| wanted.contains(&path.as_str()))
            .map(|(_, file)| *file)
            .collect();
        let written = self
            .write_files(client, app_id, depot_id, key, &files, dir)
            .await?;
        for lib in renpy::lib_directories(&listing, root) {
            let path = dir.join(root).join("lib").join(lib);
            tokio::fs::create_dir_all(&path).await?;
        }
        Ok(written)
    }

    /// Download whole small files into `dir`, at their depot paths. Every
    /// chunk is checked against its id, every file against its SHA-1.
    async fn write_files(
        &self,
        client: &SteamClient<LoggedIn>,
        app_id: u32,
        depot_id: u32,
        key: &DepotKey,
        files: &[&ManifestFile],
        dir: &Path,
    ) -> Result<Vec<String>, RplnetError> {
        let fetcher = ContentFetcher {
            servers: self.servers(client).await?,
            client: client.clone(),
            app_id,
        };
        let mut written = Vec::new();
        for file in files {
            if file.size > VERSION_FILE_LIMIT {
                warn!("skipped a {} byte engine version file", file.size);
                continue;
            }
            let path = file.normalized_path();
            let destination = contained(dir, &path)?;
            let mut chunks = file.chunks.clone();
            chunks.sort_by_key(|chunk| chunk.offset.unwrap_or(0));
            let mut data = Vec::with_capacity(file.size as usize);
            for chunk in &chunks {
                let raw = fetcher
                    .fetch_chunk(DepotId(depot_id), &chunk.id)
                    .await
                    .map_err(|e| match e.downcast::<steamroom::Error>() {
                        Ok(e) => RplnetError::from(*e),
                        Err(e) => RplnetError::network(RplnetNetworkFailure::ConnectionLost, e),
                    })?;
                let plain = steamroom::depot::chunk::process_chunk(
                    &raw,
                    key,
                    &chunk.id,
                    chunk.uncompressed_size,
                    chunk.checksum,
                )
                .map_err(|e| {
                    RplnetError::steam(RplnetSteamFailure::InvalidResponse, format!("chunk: {e:?}"))
                })?;
                data.extend_from_slice(&plain);
            }
            if let Some(expected) = file.content_sha1() {
                let actual: [u8; 20] = sha1_digest(&data);
                if actual != expected {
                    return Err(RplnetError::steam(
                        RplnetSteamFailure::InvalidResponse,
                        "downloaded file does not match its SHA-1",
                    ));
                }
            }
            if let Some(parent) = destination.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(&destination, &data).await?;
            written.push(path);
        }
        Ok(written)
    }
}

impl Servers {
    /// The CDN auth token for `depot` on `host`, asked for once and kept.
    /// `None` when Steam issues none.
    async fn token(
        &self,
        client: &SteamClient<LoggedIn>,
        app_id: u32,
        depot: DepotId,
        host: &str,
    ) -> Result<Option<String>, RplnetError> {
        let key = (depot.0, host.to_string());
        if let Some(token) = self
            .tokens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            return Ok(Some(token.clone()));
        }
        let token = client
            .get_cdn_auth_token(AppId(app_id), depot, host)
            .await?
            .token
            .filter(|token| !token.is_empty());
        if let Some(token) = &token {
            self.tokens
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key, token.clone());
            info!("CDN auth token obtained for a depot on {host}");
        }
        Ok(token)
    }
}

/// Chunk downloads over the session's server pool. A server that answers
/// 401/403 is retried once with a CDN auth token for that depot and server.
pub(crate) struct ContentFetcher {
    pub(crate) servers: Arc<Servers>,
    pub(crate) client: SteamClient<LoggedIn>,
    pub(crate) app_id: u32,
}

impl ChunkFetcher for ContentFetcher {
    async fn fetch_chunk(
        &self,
        depot_id: DepotId,
        chunk_id: &ChunkId,
    ) -> Result<Bytes, steamroom_client::download::BoxError> {
        let (server, wait) = self.servers.pool.pick();
        let server = server.clone();
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        let cached = self
            .servers
            .tokens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(depot_id.0, server.host.clone()))
            .cloned();
        let mut result = self
            .servers
            .cdn
            .download_chunk(&server, depot_id, chunk_id, cached.as_deref())
            .await;
        if cached.is_none()
            && let Err(steamroom::Error::CdnStatus { status, .. }) = &result
            && (status.as_u16() == 401 || status.as_u16() == 403)
        {
            let token = self
                .servers
                .token(&self.client, self.app_id, depot_id, &server.host)
                .await
                .map_err(|e| Box::new(e) as steamroom_client::download::BoxError)?;
            result = self
                .servers
                .cdn
                .download_chunk(&server, depot_id, chunk_id, token.as_deref())
                .await;
        }
        match result {
            Ok(data) => {
                self.servers.pool.report_success(&server);
                Ok(data)
            }
            Err(e) => {
                let retry_after = match &e {
                    steamroom::Error::CdnStatus { retry_after, .. } => {
                        retry_after.map(Duration::from_secs)
                    }
                    _ => None,
                };
                self.servers.pool.report_failure(&server, retry_after);
                Err(Box::new(e))
            }
        }
    }
}

/// A manifest as the CDN sent it, parsed, with its file names decrypted.
pub(crate) fn parse_manifest(raw: &[u8], key: &DepotKey) -> Result<DepotManifest, RplnetError> {
    let mut manifest = steamroom_client::manifest::parse_cdn_manifest(raw).map_err(|e| {
        RplnetError::steam(
            RplnetSteamFailure::InvalidResponse,
            format!("manifest: {e}"),
        )
    })?;
    if manifest.filenames_encrypted {
        manifest.decrypt_filenames(key).map_err(|e| {
            RplnetError::steam(
                RplnetSteamFailure::InvalidResponse,
                format!("manifest file names: {e}"),
            )
        })?;
    }
    Ok(manifest)
}

/// The Ren'Py layout of a manifest, or `None` when it holds no Ren'Py game.
pub(crate) fn renpy_layout(manifest: &DepotManifest) -> Option<renpy::Layout> {
    let paths: Vec<String> = manifest
        .files
        .iter()
        .map(ManifestFile::normalized_path)
        .collect();
    let listing: Vec<renpy::Entry<'_>> = manifest
        .files
        .iter()
        .zip(&paths)
        .map(|(file, path)| renpy::Entry {
            path,
            size: file.size,
            is_dir: file.flags & DIRECTORY_FLAG != 0,
        })
        .collect();
    renpy::detect(&listing)
}

/// Content servers as Steam places them for `region`: the first probe
/// address that yields any wins. None at all is `RegionUnavailable`.
async fn regional_servers(
    client: &SteamClient<LoggedIn>,
    region: &RplnetContentRegion,
) -> Result<Vec<CdnServer>, RplnetError> {
    for probe in &region.probe_ips {
        let Ok(ip) = probe.parse::<std::net::IpAddr>() else {
            warn!("region {}: {probe} is not an IP address", region.id);
            continue;
        };
        let directory = match client
            .get_content_servers(
                ContentServerLocation::IpOverride(ip),
                Some(MAX_CONTENT_SERVERS),
            )
            .await
        {
            Ok(directory) => directory,
            Err(e) => {
                warn!("region {} via {probe}: {}", region.id, RplnetError::from(e));
                continue;
            }
        };
        let servers = download_servers(&directory);
        if servers.is_empty() {
            warn!("region {} via {probe}: no usable content server", region.id);
            continue;
        }
        let hosts = describe(&servers);
        info!(
            "content servers (region {} via {probe}): {hosts}",
            region.id
        );
        if !region.expect_hosts.is_empty()
            && !servers.iter().any(|s| {
                region
                    .expect_hosts
                    .iter()
                    .any(|expected| s.host.contains(expected.as_str()))
            })
        {
            warn!(
                "region {}: hosts do not match {:?}",
                region.id, region.expect_hosts
            );
        }
        return Ok(servers);
    }
    Err(RplnetError::steam(
        RplnetSteamFailure::RegionUnavailable,
        format!("no content servers for region {}", region.id),
    ))
}

fn describe(servers: &[CdnServer]) -> String {
    servers
        .iter()
        .map(|s| format!("{}{}", s.host, if s.https { "" } else { " (http)" }))
        .collect::<Vec<_>>()
        .join(", ")
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    use sha1::Digest;
    sha1::Sha1::digest(data).into()
}

/// Content servers that can serve any app to this client, least loaded
/// first, over HTTPS where the server offers it.
fn download_servers(directory: &[ContentServer]) -> Vec<CdnServer> {
    let mut usable: Vec<&ContentServer> = directory
        .iter()
        .filter(|server| {
            matches!(server.server_type.as_deref(), Some("CDN" | "SteamCache"))
                && server.allowed_app_ids.is_empty()
                && !server.use_as_proxy
                && !server.steam_china_only
        })
        .collect();
    usable.sort_by(|a, b| {
        a.weighted_load
            .unwrap_or(f32::MAX)
            .total_cmp(&b.weighted_load.unwrap_or(f32::MAX))
    });
    usable
        .into_iter()
        .map(|server| {
            server.to_cdn_server(
                server
                    .https_support
                    .as_ref()
                    .is_some_and(|https| https.allows_https()),
            )
        })
        .collect()
}

/// `relative` under `dir`, refusing anything that would leave it.
fn contained(dir: &Path, relative: &str) -> Result<PathBuf, RplnetError> {
    let relative = Path::new(relative);
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(RplnetError::steam(
            RplnetSteamFailure::InvalidResponse,
            "depot path leaves the target directory",
        ));
    }
    Ok(dir.join(relative))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_stay_inside_the_directory() {
        let dir = Path::new("/tmp/x");
        assert_eq!(
            contained(dir, "G/renpy/vc_version.py").unwrap(),
            PathBuf::from("/tmp/x/G/renpy/vc_version.py")
        );
        assert!(contained(dir, "../escape").is_err());
        assert!(contained(dir, "/etc/passwd").is_err());
        assert!(contained(dir, "a/../../b").is_err());
    }
}
