//! Downloading a Ren'Py game's story files from its depot and the depots of
//! its owned DLC (plan stage 5, `renpy::is_story_file`). Files are written at
//! their depot paths under a directory the app owns; running the same
//! download into the same directory again resumes it, keeping every file that
//! already matches the manifest and every chunk of a partly written file that
//! does.

use super::content::Content;
use super::content::ContentFetcher;
use super::library::RplnetDepotCandidate;
use super::renpy;
use crate::error::RplnetError;
use crate::error::RplnetNetworkFailure;
use crate::error::RplnetSteamFailure;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use steamroom::client::LoggedIn;
use steamroom::client::SteamClient;
use steamroom::depot::AppId;
use steamroom::depot::DepotId;
use steamroom::depot::DepotKey;
use steamroom::depot::manifest::DepotManifest;
use steamroom::depot::manifest::ManifestFile;
use steamroom::enums::DepotFileFlags;
use steamroom::error::ConnectionError;
use steamroom_client::download::DepotJob;
use steamroom_client::download::DownloadError;
use steamroom_client::event::DownloadEvent;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing::warn;

/// Chunks fetched at once, across up to as many files at once.
pub(super) const CONCURRENT_CHUNKS: usize = 8;
/// Least time between two progress reports.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);

/// A depot to download from, at one manifest.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RplnetDepotDownload {
    pub depot_id: u32,
    pub manifest_id: u64,
    /// Where to keep the manifest as the CDN sent it.
    pub manifest_file: String,
}

/// A Ren'Py game's story files to download.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RplnetDownloadRequest {
    pub app_id: u32,
    /// The game's depot (the one inspection found the game in) first, then
    /// the depots of its owned DLC. They install into one directory: where
    /// two have the same file, the later one's is kept, so a DLC that
    /// replaces a file of the game gets its way.
    pub depots: Vec<RplnetDepotDownload>,
    /// The Ren'Py root inside the game's depot, as inspection found it: only
    /// the story files below it are downloaded, from every depot.
    pub root: String,
    /// Directory the files are written to, at their depot paths. Running the
    /// same request into it again resumes the download.
    pub destination: String,
}

/// A downloaded file, as the manifest describes it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RplnetDownloadedFile {
    /// Depot path, `/`-separated, in the depot's case (root included).
    pub path: String,
    pub size: u64,
    /// SHA-1 of the content, lowercase hex.
    pub sha1: String,
    /// The depot it comes from.
    pub depot_id: u32,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RplnetDownloadResult {
    pub files: Vec<RplnetDownloadedFile>,
    pub total_size: u64,
    /// DLC depots Steam refused the key for (the DLC is no longer owned):
    /// nothing came from them and their manifest was not written.
    pub skipped_depots: Vec<u32>,
}

/// Progress of a running download.
#[uniffi::export(with_foreign)]
pub trait RplnetDownloadObserver: Send + Sync {
    /// `done` of `total` bytes are on disk. Called a few times a second at
    /// most, from a background thread.
    fn progress(&self, done: u64, total: u64);
}

/// Stops a download (or anything else that takes one) when cancelled.
#[derive(uniffi::Object, Default)]
pub struct RplnetCancellation {
    pub(super) token: CancellationToken,
}

#[uniffi::export]
impl RplnetCancellation {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn cancel(&self) {
        self.token.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }
}

/// Download `request` over `client`, reporting to `observer`, until done or
/// `cancellation` fires.
pub(crate) async fn download(
    content: &Content,
    client: &SteamClient<LoggedIn>,
    request: &RplnetDownloadRequest,
    observer: Arc<dyn RplnetDownloadObserver>,
    cancellation: &RplnetCancellation,
) -> Result<RplnetDownloadResult, RplnetError> {
    let work = async {
        let started = Instant::now();
        let mut layers = Vec::new();
        let mut skipped_depots = Vec::new();
        for (index, depot) in request.depots.iter().enumerate() {
            let Some(key) = depot_key(client, request.app_id, depot.depot_id, index > 0).await?
            else {
                skipped_depots.push(depot.depot_id);
                continue;
            };
            let (raw, manifest) = content
                .manifest(client, request.app_id, &candidate(depot), &key)
                .await?;
            save_manifest(&depot.manifest_file, &raw).await?;
            layers.push(Layer {
                depot_id: depot.depot_id,
                key,
                manifest,
            });
        }
        let Some(game) = layers.first() else {
            return Err(RplnetError::steam(
                RplnetSteamFailure::InvalidResponse,
                "the download names no depot",
            ));
        };
        if downloaded_files(&story_files(&game.manifest, &request.root), game.depot_id).is_empty() {
            return Err(RplnetError::steam(
                RplnetSteamFailure::InvalidResponse,
                "the depot has no game files under the Ren'Py root",
            ));
        }

        let filtered = layered_story_files(&layers, &request.root);
        let files: Vec<RplnetDownloadedFile> = layers
            .iter()
            .zip(&filtered)
            .flat_map(|(layer, manifest)| downloaded_files(manifest, layer.depot_id))
            .collect();
        let total_size: u64 = files.iter().map(|file| file.size).sum();
        let sizes: HashMap<String, u64> = filtered
            .iter()
            .flat_map(|manifest| &manifest.files)
            .map(|file| (file.filename.clone(), file.size))
            .collect();

        let (events, receiver) = tokio::sync::mpsc::unbounded_channel();
        let reporter = tokio::spawn(report_progress(
            receiver,
            Arc::clone(&observer),
            total_size,
            sizes,
        ));
        let servers = content.servers(client).await?;
        let mut fetched = 0;
        let mut present = 0;
        for (layer, manifest) in layers.into_iter().zip(&filtered) {
            if manifest.files.is_empty() {
                continue;
            }
            let job = DepotJob::builder()
                .depot_id(DepotId(layer.depot_id))
                .depot_key(layer.key)
                .install_dir(request.destination.clone().into())
                .max_downloads(CONCURRENT_CHUNKS)
                .verify(true)
                // Write files in place: nothing reads the directory before the
                // download completes, a resumed download keeps the verified
                // chunks of an interrupted file, and no staging directory ends
                // up among the story files.
                .non_atomic(true)
                .event_sender(events.clone())
                .build()
                .map_err(|e| RplnetError::steam(RplnetSteamFailure::InvalidResponse, e))?;
            let fetcher = Arc::new(ContentFetcher {
                servers: Arc::clone(&servers),
                client: client.clone(),
                app_id: request.app_id,
            });
            let stats = job
                .download(manifest, fetcher)
                .await
                .map_err(|report| download_error(report.into_current_context()))?;
            fetched += stats.files_completed;
            present += stats.files_skipped;
        }
        drop(events);
        let _ = reporter.await;
        observer.progress(total_size, total_size);
        info!(
            "downloaded app {} from {} depots ({} skipped): {} files fetched, {} already present, {} bytes in {} s",
            request.app_id,
            filtered.len(),
            skipped_depots.len(),
            fetched,
            present,
            total_size,
            started.elapsed().as_secs()
        );
        Ok(RplnetDownloadResult {
            files,
            total_size,
            skipped_depots,
        })
    };
    let outcome = tokio::select! {
        biased;
        () = cancellation.token.cancelled() => Err(RplnetError::Cancelled),
        outcome = work => outcome,
    };
    if matches!(outcome, Err(RplnetError::Network { .. })) {
        // The servers may be the problem; fetch a new list next time.
        content.invalidate().await;
    }
    outcome
}

/// A depot's manifest, with the key that decrypts its chunks.
pub(super) struct Layer {
    pub(super) depot_id: u32,
    pub(super) key: DepotKey,
    pub(super) manifest: DepotManifest,
}

pub(super) fn candidate(depot: &RplnetDepotDownload) -> RplnetDepotCandidate {
    RplnetDepotCandidate {
        depot_id: depot.depot_id,
        manifest_id: depot.manifest_id,
        size: None,
        owned: true,
    }
}

/// The key of `depot_id`. When `optional` (a DLC depot), Steam refusing it
/// is `None`: the account no longer owns the DLC.
pub(super) async fn depot_key(
    client: &SteamClient<LoggedIn>,
    app_id: u32,
    depot_id: u32,
    optional: bool,
) -> Result<Option<DepotKey>, RplnetError> {
    match client
        .get_depot_decryption_key(DepotId(depot_id), AppId(app_id))
        .await
    {
        Ok(key) => Ok(Some(key)),
        Err(steamroom::Error::Connection(ConnectionError::DepotAccessDenied(_))) if optional => {
            warn!("Steam refused the key of DLC depot {depot_id}; it is left out");
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

pub(super) async fn save_manifest(path: &str, raw: &[u8]) -> Result<(), RplnetError> {
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, raw).await?;
    Ok(())
}

/// `manifest` cut down to the story files below `root` (case-insensitive).
pub(super) fn story_files(manifest: &DepotManifest, root: &str) -> DepotManifest {
    let root = root.to_lowercase();
    let mut filtered = manifest.clone();
    filtered.files.retain(|file| {
        let path = file.normalized_path().to_lowercase();
        path.strip_prefix(root.as_str())
            .is_some_and(renpy::is_story_file)
    });
    filtered
}

/// The story files below `root` of depots installed in the order of
/// `layers`, one manifest per layer: a path several have (compared
/// case-insensitively) is kept in the last one only.
pub(super) fn layered_story_files(layers: &[Layer], root: &str) -> Vec<DepotManifest> {
    let filtered: Vec<DepotManifest> = layers
        .iter()
        .map(|layer| story_files(&layer.manifest, root))
        .collect();
    let mut owner: HashMap<String, usize> = HashMap::new();
    for (index, manifest) in filtered.iter().enumerate() {
        for file in &manifest.files {
            owner.insert(file.normalized_path().to_lowercase(), index);
        }
    }
    filtered
        .into_iter()
        .enumerate()
        .map(|(index, mut manifest)| {
            manifest
                .files
                .retain(|file| owner.get(&file.normalized_path().to_lowercase()) == Some(&index));
            manifest
        })
        .collect()
}

/// The regular files of `manifest`, which is `depot_id`'s.
pub(super) fn downloaded_files(
    manifest: &DepotManifest,
    depot_id: u32,
) -> Vec<RplnetDownloadedFile> {
    manifest
        .files
        .iter()
        .filter(|file| is_regular(file))
        .map(|file| RplnetDownloadedFile {
            path: file.normalized_path(),
            size: file.size,
            sha1: file
                .content_sha1()
                .map(|sha| sha.iter().map(|byte| format!("{byte:02x}")).collect())
                .unwrap_or_default(),
            depot_id,
        })
        .collect()
}

pub(super) fn is_regular(file: &ManifestFile) -> bool {
    let flags = DepotFileFlags::from_bits_retain(file.flags);
    !flags.is_directory() && !flags.is_symlink() && file.link_target.is_none()
}

/// Bytes on disk, from download events. Every byte of a written file arrives
/// as a completed chunk (fetched, reused in place or copied), and a file that
/// already matches arrives as one skip, so the sum only grows while files are
/// transferred concurrently.
struct ProgressTally {
    done: u64,
    sizes: HashMap<String, u64>,
}

impl ProgressTally {
    /// The new total when `event` adds bytes.
    fn record(&mut self, event: DownloadEvent) -> Option<u64> {
        match event {
            DownloadEvent::ChunkCompleted { bytes } => self.done += bytes,
            DownloadEvent::FileSkipped { filename } => {
                self.done += self.sizes.get(&filename).copied().unwrap_or(0);
            }
            _ => return None,
        }
        Some(self.done)
    }
}

/// Turn download events into throttled progress reports.
pub(super) async fn report_progress(
    mut events: tokio::sync::mpsc::UnboundedReceiver<DownloadEvent>,
    observer: Arc<dyn RplnetDownloadObserver>,
    total: u64,
    sizes: HashMap<String, u64>,
) {
    let mut tally = ProgressTally { done: 0, sizes };
    let mut last_report: Option<Instant> = None;
    while let Some(event) = events.recv().await {
        let Some(done) = tally.record(event) else {
            continue;
        };
        if last_report.is_none_or(|at| at.elapsed() >= PROGRESS_INTERVAL) {
            observer.progress(done.min(total), total);
            last_report = Some(Instant::now());
        }
    }
}

pub(super) fn download_error(error: DownloadError) -> RplnetError {
    match error {
        DownloadError::Io(e) => e.into(),
        DownloadError::Fetch { source } => match source.downcast::<steamroom::Error>() {
            Ok(e) => (*e).into(),
            Err(source) => match source.downcast::<RplnetError>() {
                Ok(e) => *e,
                Err(source) => RplnetError::network(RplnetNetworkFailure::ConnectionLost, source),
            },
        },
        other => RplnetError::steam(RplnetSteamFailure::InvalidResponse, other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, size: u64) -> ManifestFile {
        let mut file = ManifestFile::new(path.to_string(), size);
        file.sha_content = Some([0xab; 20]);
        file
    }

    #[test]
    fn only_the_story_files_below_the_root_are_kept() {
        let mut dir = ManifestFile::new("G\\game\\saves".to_string(), 0);
        dir.flags = DepotFileFlags::DIRECTORY.bits();
        let manifest = DepotManifest::new(vec![
            file("G\\Game\\script.rpa", 10),
            file("G\\renpy\\__init__.py", 5),
            dir,
            file("G\\characters\\monika.chr", 3),
            file("G\\lib\\py3-windows-x86_64\\python.exe", 100),
            file("G\\G.exe", 50),
            file("G\\G.py", 2),
            file("other\\game\\x.rpy", 1),
        ]);
        let filtered = story_files(&manifest, "G/");
        let paths: Vec<String> = filtered.files.iter().map(|f| f.normalized_path()).collect();
        assert_eq!(
            paths,
            vec![
                "G/Game/script.rpa",
                "G/renpy/__init__.py",
                "G/game/saves",
                "G/characters/monika.chr"
            ]
        );

        let files = downloaded_files(&filtered, 7);
        assert_eq!(files.len(), 3, "directories are not files");
        assert_eq!(files[0].path, "G/Game/script.rpa");
        assert_eq!(files[0].sha1, "ab".repeat(20));
        assert_eq!(files[0].depot_id, 7);
    }

    fn layer(depot_id: u32, files: Vec<ManifestFile>) -> Layer {
        Layer {
            depot_id,
            key: DepotKey([0; 32]),
            manifest: DepotManifest::new(files),
        }
    }

    #[test]
    fn a_later_depot_replaces_the_files_it_shares() {
        let layers = vec![
            layer(
                1,
                vec![
                    file("G\\game\\script.rpa", 10),
                    file("G\\game\\patch.rpy", 1),
                    file("G\\renpy\\__init__.py", 5),
                ],
            ),
            // The DLC replaces the patch (in another case) and adds a file;
            // its soundtrack is outside the root.
            layer(
                2,
                vec![
                    file("G\\Game\\Patch.rpy", 2),
                    file("G\\game\\dlc.rpa", 20),
                    file("Soundtrack\\01.mp3", 30),
                ],
            ),
            // Another platform's copy of the DLC: nothing below the root.
            layer(
                3,
                vec![file(
                    "G.app\\Contents\\Resources\\autorun\\game\\dlc.rpa",
                    20,
                )],
            ),
        ];
        let layered = layered_story_files(&layers, "G/");
        let paths = |manifest: &DepotManifest| {
            manifest
                .files
                .iter()
                .map(ManifestFile::normalized_path)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            paths(&layered[0]),
            vec!["G/game/script.rpa", "G/renpy/__init__.py"]
        );
        assert_eq!(
            paths(&layered[1]),
            vec!["G/Game/Patch.rpy", "G/game/dlc.rpa"]
        );
        assert!(layered[2].files.is_empty());
    }

    #[test]
    fn progress_keeps_growing_while_files_finish_in_any_order() {
        let mut tally = ProgressTally {
            done: 0,
            sizes: HashMap::from([("present.rpa".to_string(), 7)]),
        };
        let events = [
            DownloadEvent::ChunkCompleted { bytes: 5 },
            DownloadEvent::ChunkCompleted { bytes: 3 },
            // One of two concurrent files completes; the other's chunk
            // bytes stay counted.
            DownloadEvent::DepotProgress {
                completed_bytes: 5,
                total_bytes: 30,
            },
            DownloadEvent::FileSkipped {
                filename: "present.rpa".to_string(),
            },
            DownloadEvent::ChunkCompleted { bytes: 15 },
        ];
        let reports: Vec<u64> = events
            .into_iter()
            .filter_map(|event| tally.record(event))
            .collect();
        assert_eq!(reports, vec![5, 8, 15, 30]);
    }

    #[test]
    fn depot_root_keeps_files_beside_game_and_renpy() {
        let manifest = DepotManifest::new(vec![
            file("game/a.rpy", 1),
            file("renpy/b.py", 1),
            file("readme.txt", 1),
            file("launcher.py", 1),
        ]);
        assert_eq!(story_files(&manifest, "").files.len(), 3);
    }
}
