//! Depot content: content servers, manifests, and single files, for telling
//! whether a game is Ren'Py and reading its engine version (plan stage 4).

use super::library::RplnetDepotCandidate;
use super::renpy;
use crate::error::RplnetError;
use crate::error::RplnetNetworkFailure;
use crate::error::RplnetSteamFailure;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use steamroom::cdn::CdnClient;
use steamroom::cdn::CdnServerPool;
use steamroom::cdn::ContentServer;
use steamroom::cdn::ContentServerLocation;
use steamroom::cdn::server::CdnServer;
use steamroom::client::LoggedIn;
use steamroom::client::SteamClient;
use steamroom::depot::AppId;
use steamroom::depot::DepotId;
use steamroom::depot::DepotKey;
use steamroom::depot::ManifestId;
use steamroom::depot::manifest::DepotManifest;
use steamroom::depot::manifest::ManifestFile;
use steamroom::error::ConnectionError;
use steamroom_client::download::CdnChunkFetcher;
use steamroom_client::download::ChunkFetcher;
use tokio::sync::OnceCell;
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
    /// Files under the root's `game/` and `renpy/`: what an import downloads.
    pub file_count: u64,
    pub total_size: u64,
    /// Supporting signs, for logs only.
    pub hints: Vec<String>,
    /// Engine version files written under the requested directory, as paths
    /// relative to it (they keep their depot paths, root included). Empty
    /// when no directory was given.
    pub version_files: Vec<String>,
}

/// Content servers for the session, fetched on first use.
#[derive(Default)]
pub(crate) struct Content {
    servers: OnceCell<Arc<Servers>>,
}

/// The CDN client and server pool; manifests use them directly, chunks
/// through the fetcher's rotation and cooldown.
type Servers = CdnChunkFetcher;

impl Content {
    async fn servers(&self, client: &SteamClient<LoggedIn>) -> Result<Arc<Servers>, RplnetError> {
        self.servers
            .get_or_try_init(|| async {
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
                info!(
                    "content servers: {}",
                    servers
                        .iter()
                        .map(|s| format!("{}{}", s.host, if s.https { "" } else { " (http)" }))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                Ok(Arc::new(CdnChunkFetcher::new(
                    CdnClient::with_client(crate::net::http()?.clone()),
                    CdnServerPool::new(servers),
                    None,
                )))
            })
            .await
            .cloned()
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
            let manifest = self.manifest(client, app_id, candidate, &key).await?;
            read += 1;
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
            if inspection.depot_id.is_none() {
                inspection.depot_id = Some(candidate.depot_id);
                inspection.manifest_id = Some(candidate.manifest_id);
            }
            let Some(layout) = renpy::detect(&listing) else {
                continue;
            };
            inspection.depot_id = Some(candidate.depot_id);
            inspection.manifest_id = Some(candidate.manifest_id);
            let version_files = match version_dir {
                Some(dir) => {
                    let wanted = renpy::version_files(&listing, &layout.root);
                    let files: Vec<&ManifestFile> = entries
                        .iter()
                        .filter(|(path, _)| wanted.contains(&path.as_str()))
                        .map(|(_, file)| *file)
                        .collect();
                    let written = self
                        .write_files(client, candidate.depot_id, &key, &files, dir)
                        .await?;
                    for lib in renpy::lib_directories(&listing, &layout.root) {
                        let path = dir.join(&layout.root).join("lib").join(lib);
                        tokio::fs::create_dir_all(&path).await?;
                    }
                    written
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

    async fn manifest(
        &self,
        client: &SteamClient<LoggedIn>,
        app_id: u32,
        candidate: &RplnetDepotCandidate,
        key: &DepotKey,
    ) -> Result<DepotManifest, RplnetError> {
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
                let token = client
                    .get_cdn_auth_token(AppId(app_id), depot, &server.host)
                    .await?;
                servers
                    .cdn
                    .download_manifest(&server, depot, manifest_id, code, token.token.as_deref())
                    .await?
            }
            Err(e) => return Err(e.into()),
        };
        let mut manifest = steamroom_client::manifest::parse_cdn_manifest(&raw).map_err(|e| {
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

    /// Download whole small files into `dir`, at their depot paths. Every
    /// chunk is checked against its id, every file against its SHA-1.
    async fn write_files(
        &self,
        client: &SteamClient<LoggedIn>,
        depot_id: u32,
        key: &DepotKey,
        files: &[&ManifestFile],
        dir: &Path,
    ) -> Result<Vec<String>, RplnetError> {
        let fetcher = self.servers(client).await?;
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
