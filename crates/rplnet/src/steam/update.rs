//! Updating an imported Ren'Py game to the build Steam lists now (plan 6.7).
//!
//! The app keeps, for every story file it got from Steam, the depot path and
//! Steam's SHA-1 at import, and whether the import left the file as Steam
//! sent it. An update compares those with the new manifest's story files
//! under its Ren'Py root (the root may move between builds, so files are
//! matched by their path below the root, case-insensitively): files whose
//! SHA-1 is unchanged stay as they are, the rest are downloaded into a
//! staging directory the app owns. Chunks that also appear in an unaltered
//! installed file are copied from it rather than fetched, each verified by
//! its SHA-1. The app then applies the staged files to the story.

use super::content::Content;
use super::content::ContentFetcher;
use super::content::parse_manifest;
use super::content::renpy_layout;
use super::download::CONCURRENT_CHUNKS;
use super::download::RplnetCancellation;
use super::download::RplnetDownloadObserver;
use super::download::RplnetDownloadedFile;
use super::download::download_error;
use super::download::downloaded_files;
use super::download::is_regular;
use super::download::report_progress;
use super::download::story_files;
use super::library::RplnetDepotCandidate;
use crate::error::RplnetError;
use crate::error::RplnetSteamFailure;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use steamroom::client::LoggedIn;
use steamroom::client::SteamClient;
use steamroom::depot::AppId;
use steamroom::depot::DepotId;
use steamroom::depot::DepotKey;
use steamroom::depot::manifest::DepotManifest;
use steamroom_client::download::DepotJob;
use steamroom_client::download::OldChunkLoc;
use tracing::info;

/// A story file the app got from Steam.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RplnetInstalledFile {
    /// Depot path in the installed build, root included.
    pub path: String,
    /// Steam's SHA-1 of the installed build's copy, lowercase hex.
    pub sha1: String,
    /// Where the file is, relative to the update's `reuse_dir`, when its
    /// content is still exactly Steam's: its chunks may then be copied.
    /// `None` for a file the import changed.
    pub reusable_at: Option<String>,
}

/// One story's update from the build it has to `manifest_id`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RplnetUpdateRequest {
    pub app_id: u32,
    pub depot_id: u32,
    /// The manifest to update to.
    pub manifest_id: u64,
    /// The installed build's manifest, as the CDN sent it.
    pub previous_manifest_file: String,
    /// Ren'Py root of the installed build, as `RplnetRenPyLayout::root`.
    pub previous_root: String,
    pub installed: Vec<RplnetInstalledFile>,
    /// Directory `RplnetInstalledFile::reusable_at` is relative to.
    pub reuse_dir: String,
    /// Directory the changed files are written to, at their depot paths.
    /// Running the same update into it again resumes it.
    pub destination: String,
    /// Where to keep the new manifest as the CDN sent it. A plan writes it,
    /// and the update reads it back instead of fetching it again.
    pub manifest_file: String,
    /// When set, the new build's engine version files are written here at
    /// their depot paths, as for `inspect`.
    pub version_dir: Option<String>,
}

/// What an update changes.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RplnetUpdatePlan {
    /// Ren'Py root of the new build.
    pub root: String,
    /// Every story file of the new build.
    pub files: Vec<RplnetDownloadedFile>,
    /// Depot paths (new build) of the files to download: new ones and
    /// changed ones.
    pub changed: Vec<String>,
    pub added_count: u64,
    pub modified_count: u64,
    /// Depot paths (installed build) of installed files the new build no
    /// longer has.
    pub removed: Vec<String>,
    /// Bytes to fetch from the CDN (compressed where the manifest says),
    /// counting only chunks no unaltered installed file holds.
    pub download_size: u64,
    /// Size of the changed files once written.
    pub changed_size: u64,
    /// Engine version files written under `version_dir`, relative to it.
    pub version_files: Vec<String>,
}

/// Fetch the new manifest and work out the update; see [`RplnetUpdatePlan`].
pub(crate) async fn plan(
    content: &Content,
    client: &SteamClient<LoggedIn>,
    request: &RplnetUpdateRequest,
) -> Result<RplnetUpdatePlan, RplnetError> {
    let started = Instant::now();
    let key = client
        .get_depot_decryption_key(DepotId(request.depot_id), AppId(request.app_id))
        .await?;
    let manifest = new_manifest(content, client, request, &key, true).await?;
    let previous = previous_manifest(request, &key).await?;
    let mut plan = compare(request, &manifest, &previous)?;
    if let Some(dir) = &request.version_dir {
        plan.version_files = content
            .write_version_files(
                client,
                request.app_id,
                request.depot_id,
                &key,
                &manifest,
                &plan.root,
                Path::new(dir),
            )
            .await?;
    }
    info!(
        "update plan for app {} depot {}: {} added, {} modified, {} removed, {} bytes to fetch, in {} ms",
        request.app_id,
        request.depot_id,
        plan.added_count,
        plan.modified_count,
        plan.removed.len(),
        plan.download_size,
        started.elapsed().as_millis()
    );
    Ok(plan)
}

/// Download the changed files of `request` into its destination, reporting
/// to `observer`, until done or `cancellation` fires.
pub(crate) async fn update(
    content: &Content,
    client: &SteamClient<LoggedIn>,
    request: &RplnetUpdateRequest,
    observer: Arc<dyn RplnetDownloadObserver>,
    cancellation: &RplnetCancellation,
) -> Result<RplnetUpdatePlan, RplnetError> {
    let work = async {
        let started = Instant::now();
        let depot = DepotId(request.depot_id);
        let key = client
            .get_depot_decryption_key(depot, AppId(request.app_id))
            .await?;
        let manifest = new_manifest(content, client, request, &key, false).await?;
        let previous = previous_manifest(request, &key).await?;
        let plan = compare(request, &manifest, &previous)?;

        let changed: HashSet<&str> = plan.changed.iter().map(String::as_str).collect();
        let mut job_manifest = manifest.clone();
        job_manifest
            .files
            .retain(|file| changed.contains(file.normalized_path().as_str()));
        let sizes: HashMap<String, u64> = job_manifest
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
            // The destination is the app's staging directory: files are
            // written in place there, so a resumed update keeps what it has.
            .non_atomic(true)
            .old_file_layouts(reusable_layouts(request, &previous))
            .reuse_dir(request.reuse_dir.clone().into())
            .event_sender(events)
            .build()
            .map_err(|e| RplnetError::steam(RplnetSteamFailure::InvalidResponse, e))?;
        let reporter = tokio::spawn(report_progress(
            receiver,
            Arc::clone(&observer),
            plan.changed_size,
            sizes,
        ));
        let fetcher = Arc::new(ContentFetcher {
            servers: content.servers(client).await?,
            client: client.clone(),
            app_id: request.app_id,
        });
        let outcome = job.download(&job_manifest, fetcher).await;
        drop(job);
        let _ = reporter.await;
        let stats = outcome.map_err(|report| download_error(report.into_current_context()))?;
        observer.progress(plan.changed_size, plan.changed_size);
        info!(
            "updated depot {} to manifest {}: {} files fetched, {} already staged, in {} s",
            request.depot_id,
            request.manifest_id,
            stats.files_completed,
            stats.files_skipped,
            started.elapsed().as_secs()
        );
        Ok(plan)
    };
    let outcome = tokio::select! {
        biased;
        () = cancellation.token.cancelled() => Err(RplnetError::Cancelled),
        outcome = work => outcome,
    };
    if matches!(outcome, Err(RplnetError::Network { .. })) {
        content.invalidate().await;
    }
    outcome
}

/// The new manifest: read back from `manifest_file` when a plan already
/// saved it (unless `refresh`), otherwise fetched and saved there.
async fn new_manifest(
    content: &Content,
    client: &SteamClient<LoggedIn>,
    request: &RplnetUpdateRequest,
    key: &DepotKey,
    refresh: bool,
) -> Result<DepotManifest, RplnetError> {
    let manifest_file = Path::new(&request.manifest_file);
    if !refresh
        && let Ok(raw) = tokio::fs::read(manifest_file).await
        && let Ok(manifest) = parse_manifest(&raw, key)
    {
        return Ok(manifest);
    }
    let candidate = RplnetDepotCandidate {
        depot_id: request.depot_id,
        manifest_id: request.manifest_id,
        size: None,
        owned: true,
    };
    let (raw, manifest) = content
        .manifest(client, request.app_id, &candidate, key)
        .await?;
    if let Some(parent) = manifest_file.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(manifest_file, &raw).await?;
    Ok(manifest)
}

async fn previous_manifest(
    request: &RplnetUpdateRequest,
    key: &DepotKey,
) -> Result<DepotManifest, RplnetError> {
    let raw = tokio::fs::read(&request.previous_manifest_file).await?;
    parse_manifest(&raw, key)
}

/// A story path below its root, for matching builds whose roots differ.
fn key_below(path: &str, root: &str) -> Option<String> {
    let lower = path.to_lowercase();
    lower.strip_prefix(&root.to_lowercase()).map(str::to_string)
}

/// The update from the installed files to `manifest`.
fn compare(
    request: &RplnetUpdateRequest,
    manifest: &DepotManifest,
    previous: &DepotManifest,
) -> Result<RplnetUpdatePlan, RplnetError> {
    let layout = renpy_layout(manifest).ok_or_else(|| {
        RplnetError::steam(
            RplnetSteamFailure::NotRenPy,
            "the new build has no Ren'Py root",
        )
    })?;
    let filtered = story_files(manifest, &layout.root);
    let files = downloaded_files(&filtered);

    let installed: HashMap<String, &RplnetInstalledFile> = request
        .installed
        .iter()
        .filter_map(|file| Some((key_below(&file.path, &request.previous_root)?, file)))
        .collect();
    let mut changed = Vec::new();
    let mut added_count = 0;
    let mut modified_count = 0;
    let mut changed_size = 0;
    let mut kept = HashSet::new();
    for file in &files {
        let Some(key) = key_below(&file.path, &layout.root) else {
            continue;
        };
        match installed.get(&key) {
            Some(old) if old.sha1.eq_ignore_ascii_case(&file.sha1) => {}
            Some(_) => {
                modified_count += 1;
                changed.push(file.path.clone());
                changed_size += file.size;
            }
            None => {
                added_count += 1;
                changed.push(file.path.clone());
                changed_size += file.size;
            }
        }
        kept.insert(key);
    }
    let mut removed: Vec<String> = installed
        .iter()
        .filter(|(key, _)| !kept.contains(*key))
        .map(|(_, file)| file.path.clone())
        .collect();
    removed.sort();

    // Chunks an unaltered installed file holds are copied, not fetched.
    let reusable: HashSet<[u8; 20]> = reusable_layouts(request, previous)
        .into_values()
        .flatten()
        .map(|chunk| chunk.id.0)
        .collect();
    let wanted: HashSet<&str> = changed.iter().map(String::as_str).collect();
    let mut counted = HashSet::new();
    let download_size = filtered
        .files
        .iter()
        .filter(|file| is_regular(file) && wanted.contains(file.normalized_path().as_str()))
        .flat_map(|file| &file.chunks)
        .filter(|chunk| !reusable.contains(&chunk.id.0) && counted.insert(chunk.id.0))
        .map(|chunk| u64::from(chunk.compressed_size.unwrap_or(chunk.uncompressed_size)))
        .sum();

    Ok(RplnetUpdatePlan {
        root: layout.root,
        files,
        changed,
        added_count,
        modified_count,
        removed,
        download_size,
        changed_size,
        version_files: Vec::new(),
    })
}

/// Chunk layouts of the installed files whose content is still Steam's,
/// keyed by where they are below `reuse_dir`.
fn reusable_layouts(
    request: &RplnetUpdateRequest,
    previous: &DepotManifest,
) -> HashMap<String, Vec<OldChunkLoc>> {
    let locations: HashMap<String, &str> = request
        .installed
        .iter()
        .filter_map(|file| Some((file.path.to_lowercase(), file.reusable_at.as_deref()?)))
        .collect();
    previous
        .files
        .iter()
        .filter(|file| is_regular(file))
        .filter_map(|file| {
            let local = locations.get(&file.normalized_path().to_lowercase())?;
            let chunks = file
                .chunks
                .iter()
                .filter_map(|chunk| {
                    Some(OldChunkLoc {
                        id: chunk.id.clone(),
                        offset: chunk.offset?,
                        size: chunk.uncompressed_size,
                    })
                })
                .collect();
            Some(((*local).to_string(), chunks))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use steamroom::depot::ChunkId;
    use steamroom::depot::manifest::ManifestChunk;
    use steamroom::depot::manifest::ManifestFile;

    fn chunk(id: u8, offset: u64, size: u32) -> ManifestChunk {
        let mut chunk = ManifestChunk::new(ChunkId([id; 20]), 0, size);
        chunk.offset = Some(offset);
        chunk.compressed_size = Some(size / 2);
        chunk
    }

    fn file(path: &str, sha: u8, chunks: Vec<ManifestChunk>) -> ManifestFile {
        let size = chunks.iter().map(|c| u64::from(c.uncompressed_size)).sum();
        let mut file = ManifestFile::new(path.to_string(), size);
        file.sha_content = Some([sha; 20]);
        file.chunks = chunks;
        file
    }

    fn installed(path: &str, sha: u8, reusable_at: Option<&str>) -> RplnetInstalledFile {
        RplnetInstalledFile {
            path: path.to_string(),
            sha1: format!("{sha:02x}").repeat(20),
            reusable_at: reusable_at.map(str::to_string),
        }
    }

    fn request(previous_root: &str, files: Vec<RplnetInstalledFile>) -> RplnetUpdateRequest {
        RplnetUpdateRequest {
            app_id: 1,
            depot_id: 2,
            manifest_id: 3,
            previous_manifest_file: String::new(),
            previous_root: previous_root.to_string(),
            installed: files,
            reuse_dir: String::new(),
            destination: String::new(),
            manifest_file: String::new(),
            version_dir: None,
        }
    }

    #[test]
    fn files_are_matched_below_a_moved_root() {
        let previous = DepotManifest::new(vec![
            file(
                "Game-1.0\\game\\script.rpa",
                1,
                vec![chunk(1, 0, 100), chunk(2, 100, 100)],
            ),
            file("Game-1.0\\game\\old.rpy", 2, vec![chunk(3, 0, 10)]),
            file("Game-1.0\\renpy\\__init__.py", 4, vec![chunk(4, 0, 10)]),
            file("Game-1.0\\game\\patched.rpyc", 5, vec![chunk(5, 0, 10)]),
        ]);
        let manifest = DepotManifest::new(vec![
            // Same name below the new root; one chunk kept, one new.
            file(
                "Game-1.1\\Game\\script.rpa",
                6,
                vec![chunk(1, 0, 100), chunk(7, 100, 100)],
            ),
            file("Game-1.1\\renpy\\__init__.py", 4, vec![chunk(4, 0, 10)]),
            file("Game-1.1\\game\\new.rpy", 8, vec![chunk(8, 0, 10)]),
            // Unchanged on Steam, but the import changed the local copy: the
            // update leaves it as it is.
            file("Game-1.1\\game\\patched.rpyc", 5, vec![chunk(5, 0, 10)]),
            file("Game-1.1\\Game.exe", 9, vec![chunk(9, 0, 10)]),
        ]);
        let request = request(
            "Game-1.0/",
            vec![
                installed("Game-1.0/game/script.rpa", 1, Some("game/script.rpa")),
                installed("Game-1.0/game/old.rpy", 2, Some("game/old.rpy")),
                installed("Game-1.0/renpy/__init__.py", 4, Some("renpy/__init__.py")),
                installed("Game-1.0/game/patched.rpyc", 5, None),
            ],
        );
        let plan = compare(&request, &manifest, &previous).unwrap();
        assert_eq!(plan.root, "Game-1.1/");
        assert_eq!(
            plan.changed,
            vec!["Game-1.1/Game/script.rpa", "Game-1.1/game/new.rpy"]
        );
        assert_eq!(plan.added_count, 1);
        assert_eq!(plan.modified_count, 1);
        assert_eq!(plan.removed, vec!["Game-1.0/game/old.rpy"]);
        assert_eq!(plan.files.len(), 4, "the launcher is not a story file");
        // Chunk 1 is in the installed script.rpa; chunks 7 and 8 are fetched.
        assert_eq!(plan.download_size, 50 + 5);
        assert_eq!(plan.changed_size, 210);
    }

    #[test]
    fn chunks_of_files_the_import_changed_are_not_reused() {
        let previous = DepotManifest::new(vec![
            file("game\\a.rpyc", 1, vec![chunk(1, 0, 100)]),
            file("renpy\\__init__.py", 2, vec![chunk(2, 0, 10)]),
        ]);
        let manifest = DepotManifest::new(vec![
            file("game\\b.rpyc", 3, vec![chunk(1, 0, 100)]),
            file("renpy\\__init__.py", 2, vec![chunk(2, 0, 10)]),
        ]);
        let request = request(
            "",
            vec![
                installed("game/a.rpyc", 1, None),
                installed("renpy/__init__.py", 2, Some("renpy/__init__.py")),
            ],
        );
        let plan = compare(&request, &manifest, &previous).unwrap();
        assert_eq!(plan.changed, vec!["game/b.rpyc"]);
        assert_eq!(plan.download_size, 50);
        let layouts = reusable_layouts(&request, &previous);
        assert_eq!(
            layouts.keys().collect::<Vec<_>>(),
            vec!["renpy/__init__.py"]
        );
    }

    #[test]
    fn a_build_without_renpy_is_refused() {
        let manifest = DepotManifest::new(vec![file("Game.exe", 1, vec![chunk(1, 0, 10)])]);
        let error =
            compare(&request("", vec![]), &manifest, &DepotManifest::new(vec![])).unwrap_err();
        assert!(matches!(
            error,
            RplnetError::Steam {
                reason: RplnetSteamFailure::NotRenPy,
                ..
            }
        ));
    }
}
