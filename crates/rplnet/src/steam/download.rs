//! Downloading a Ren'Py game's story files from its depot (plan stage 5,
//! `renpy::is_story_file`). Files are written at their depot paths under a
//! directory the app owns; running the same download into the same directory
//! again resumes it, keeping every file that already matches the manifest and
//! every chunk of a partly written file that does.

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
use steamroom::depot::manifest::DepotManifest;
use steamroom::depot::manifest::ManifestFile;
use steamroom::enums::DepotFileFlags;
use steamroom_client::download::DepotJob;
use steamroom_client::download::DownloadError;
use steamroom_client::event::DownloadEvent;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Chunks fetched at once, across up to as many files at once.
const CONCURRENT_CHUNKS: usize = 8;
/// Least time between two progress reports.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);

/// One depot's Ren'Py files to download.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RplnetDownloadRequest {
    pub app_id: u32,
    pub depot_id: u32,
    pub manifest_id: u64,
    /// The Ren'Py root inside the depot, as inspection found it: only the
    /// story files below it are downloaded.
    pub root: String,
    /// Directory the files are written to, at their depot paths. Running the
    /// same request into it again resumes the download.
    pub destination: String,
    /// Where to keep the manifest as the CDN sent it.
    pub manifest_file: String,
}

/// A downloaded file, as the manifest describes it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RplnetDownloadedFile {
    /// Depot path, `/`-separated, in the depot's case (root included).
    pub path: String,
    pub size: u64,
    /// SHA-1 of the content, lowercase hex.
    pub sha1: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RplnetDownloadResult {
    pub files: Vec<RplnetDownloadedFile>,
    pub total_size: u64,
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
    token: CancellationToken,
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
        let depot = DepotId(request.depot_id);
        let key = client
            .get_depot_decryption_key(depot, AppId(request.app_id))
            .await?;
        let candidate = RplnetDepotCandidate {
            depot_id: request.depot_id,
            manifest_id: request.manifest_id,
            size: None,
            owned: true,
        };
        let (raw, manifest) = content
            .manifest(client, request.app_id, &candidate, &key)
            .await?;
        let manifest_file = Path::new(&request.manifest_file);
        if let Some(parent) = manifest_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(manifest_file, &raw).await?;

        let filtered = story_files(&manifest, &request.root);
        let files = downloaded_files(&filtered);
        if files.is_empty() {
            return Err(RplnetError::steam(
                RplnetSteamFailure::InvalidResponse,
                "the depot has no game files under the Ren'Py root",
            ));
        }
        let total_size: u64 = files.iter().map(|file| file.size).sum();
        let sizes: HashMap<String, u64> = filtered
            .files
            .iter()
            .map(|file| (file.filename.clone(), file.size))
            .collect();

        let (events, receiver) = tokio::sync::mpsc::unbounded_channel();
        let job = DepotJob::builder()
            .depot_id(depot)
            .depot_key(key)
            .install_dir(request.destination.clone().into())
            .max_downloads(CONCURRENT_CHUNKS)
            .verify(true)
            // Write files in place: nothing reads the directory before the
            // download completes, a resumed download keeps the verified
            // chunks of an interrupted file, and no staging directory ends up
            // among the story files.
            .non_atomic(true)
            .event_sender(events)
            .build()
            .map_err(|e| RplnetError::steam(RplnetSteamFailure::InvalidResponse, e))?;
        let reporter = tokio::spawn(report_progress(
            receiver,
            Arc::clone(&observer),
            total_size,
            sizes,
        ));
        let fetcher = Arc::new(ContentFetcher {
            servers: content.servers(client).await?,
            client: client.clone(),
            app_id: request.app_id,
        });
        let outcome = job.download(&filtered, fetcher).await;
        drop(job);
        let _ = reporter.await;
        let stats = outcome.map_err(|report| download_error(report.into_current_context()))?;
        observer.progress(total_size, total_size);
        info!(
            "downloaded depot {}: {} files fetched, {} already present, {} bytes in {} s",
            request.depot_id,
            stats.files_completed,
            stats.files_skipped,
            total_size,
            started.elapsed().as_secs()
        );
        Ok(RplnetDownloadResult { files, total_size })
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

/// `manifest` cut down to the story files below `root` (case-insensitive).
fn story_files(manifest: &DepotManifest, root: &str) -> DepotManifest {
    let root = root.to_lowercase();
    let mut filtered = manifest.clone();
    filtered.files.retain(|file| {
        let path = file.normalized_path().to_lowercase();
        path.strip_prefix(root.as_str())
            .is_some_and(renpy::is_story_file)
    });
    filtered
}

/// The regular files of `manifest`.
fn downloaded_files(manifest: &DepotManifest) -> Vec<RplnetDownloadedFile> {
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
        })
        .collect()
}

fn is_regular(file: &ManifestFile) -> bool {
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
async fn report_progress(
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

fn download_error(error: DownloadError) -> RplnetError {
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

        let files = downloaded_files(&filtered);
        assert_eq!(files.len(), 3, "directories are not files");
        assert_eq!(files[0].path, "G/Game/script.rpa");
        assert_eq!(files[0].sha1, "ab".repeat(20));
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
