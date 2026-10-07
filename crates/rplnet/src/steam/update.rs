//! Updating an imported Ren'Py game to the build Steam lists now, with the
//! DLC its account owns now (plan 6.7).
//!
//! The app keeps, for every story file it got from Steam, the depot it came
//! from, its depot path and Steam's SHA-1 at import, and whether the import
//! left the file as Steam sent it. An update lays the new manifests of the
//! game's depot and its DLC depots over each other as a download does
//! (`layered_story_files`) and compares the result with those records, below
//! the Ren'Py root of the game's depot (the root may move between builds, so
//! files are matched by their path below the root, case-insensitively):
//! files whose SHA-1 is unchanged stay as they are, the rest are downloaded
//! into a staging directory the app owns. A DLC bought since the import adds
//! its files; one no longer owned drops them. Chunks that also appear in an
//! unaltered installed file are copied from it rather than fetched, each
//! verified by its SHA-1. The app then applies the staged files to the story.

use super::content::Content;
use super::content::ContentFetcher;
use super::content::parse_manifest;
use super::content::renpy_layout;
use super::download::CONCURRENT_CHUNKS;
use super::download::Layer;
use super::download::RplnetCancellation;
use super::download::RplnetDepotDownload;
use super::download::RplnetDownloadObserver;
use super::download::RplnetDownloadedFile;
use super::download::candidate;
use super::download::depot_key;
use super::download::download_error;
use super::download::downloaded_files;
use super::download::is_regular;
use super::download::layered_story_files;
use super::download::report_progress;
use super::download::save_manifest;
use crate::error::RplnetError;
use crate::error::RplnetSteamFailure;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use steamroom::client::LoggedIn;
use steamroom::client::SteamClient;
use steamroom::depot::DepotId;
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
    /// The depot it came from; `None` in records from before DLC were
    /// downloaded, when it is the game's depot (the first previous
    /// manifest).
    pub depot_id: Option<u32>,
}

/// An installed depot's manifest, as the CDN sent it.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RplnetInstalledManifest {
    pub depot_id: u32,
    pub manifest_file: String,
}

/// One story's update from the depots it has to `depots`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RplnetUpdateRequest {
    pub app_id: u32,
    /// The depots to update to, in install order as for a download: the
    /// game's depot first, then those of the DLC the account owns now. Each
    /// `manifest_file` is where the new manifest is kept: a plan writes it,
    /// and the update reads it back instead of fetching it again.
    pub depots: Vec<RplnetDepotDownload>,
    /// The installed depots' manifests, the game's depot first.
    pub previous_manifests: Vec<RplnetInstalledManifest>,
    /// Ren'Py root of the installed build, as `RplnetRenPyLayout::root`.
    pub previous_root: String,
    pub installed: Vec<RplnetInstalledFile>,
    /// Directory `RplnetInstalledFile::reusable_at` is relative to.
    pub reuse_dir: String,
    /// Directory the changed files are written to, at their depot paths.
    /// Running the same update into it again resumes it.
    pub destination: String,
    /// When set, the new build's engine version files are written here at
    /// their depot paths, as for `inspect`.
    pub version_dir: Option<String>,
}

/// What an update changes.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RplnetUpdatePlan {
    /// Ren'Py root of the new build.
    pub root: String,
    /// Every story file of the new build, from every depot.
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
    /// DLC depots of the request Steam refused the key for (the DLC is no
    /// longer owned): the update leaves them out.
    pub skipped_depots: Vec<u32>,
}

/// Fetch the new manifests and work out the update; see [`RplnetUpdatePlan`].
pub(crate) async fn plan(
    content: &Content,
    client: &SteamClient<LoggedIn>,
    request: &RplnetUpdateRequest,
) -> Result<RplnetUpdatePlan, RplnetError> {
    let started = Instant::now();
    let (layers, skipped_depots) = new_layers(content, client, request, true).await?;
    let previous = previous_manifests(client, request, &layers).await?;
    let mut plan = compare(request, &layers, &previous)?;
    plan.skipped_depots = skipped_depots;
    if let Some(dir) = &request.version_dir {
        let game = &layers[0];
        plan.version_files = content
            .write_version_files(
                client,
                request.app_id,
                game.depot_id,
                &game.key,
                &game.manifest,
                &plan.root,
                Path::new(dir),
            )
            .await?;
    }
    info!(
        "update plan for app {} over {} depots ({} skipped): {} added, {} modified, {} removed, {} bytes to fetch, in {} ms",
        request.app_id,
        layers.len(),
        plan.skipped_depots.len(),
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
        let (layers, skipped_depots) = new_layers(content, client, request, false).await?;
        let previous = previous_manifests(client, request, &layers).await?;
        let mut plan = compare(request, &layers, &previous)?;
        plan.skipped_depots = skipped_depots;

        let changed: HashSet<&str> = plan.changed.iter().map(String::as_str).collect();
        let filtered = layered_story_files(&layers, &plan.root);
        let jobs: Vec<DepotManifest> = filtered
            .into_iter()
            .map(|mut manifest| {
                manifest
                    .files
                    .retain(|file| changed.contains(file.normalized_path().as_str()));
                manifest
            })
            .collect();
        let sizes: HashMap<String, u64> = jobs
            .iter()
            .flat_map(|manifest| &manifest.files)
            .map(|file| (file.filename.clone(), file.size))
            .collect();
        let reusable = reusable_layouts(request, &previous);

        let (events, receiver) = tokio::sync::mpsc::unbounded_channel();
        let reporter = tokio::spawn(report_progress(
            receiver,
            Arc::clone(&observer),
            plan.changed_size,
            sizes,
        ));
        let servers = content.servers(client).await?;
        let mut fetched = 0;
        let mut staged = 0;
        for (layer, manifest) in layers.into_iter().zip(&jobs) {
            if manifest.files.is_empty() {
                continue;
            }
            let job = DepotJob::builder()
                .depot_id(DepotId(layer.depot_id))
                .depot_key(layer.key)
                .install_dir(request.destination.clone().into())
                .max_downloads(CONCURRENT_CHUNKS)
                .verify(true)
                // The destination is the app's staging directory: files are
                // written in place there, so a resumed update keeps what it
                // has.
                .non_atomic(true)
                // Chunks are found by content, so any depot's installed file
                // can give them.
                .old_file_layouts(reusable.clone())
                .reuse_dir(request.reuse_dir.clone().into())
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
            staged += stats.files_skipped;
        }
        drop(events);
        let _ = reporter.await;
        observer.progress(plan.changed_size, plan.changed_size);
        info!(
            "updated app {} over {} depots: {} files fetched, {} already staged, in {} s",
            request.app_id,
            jobs.len(),
            fetched,
            staged,
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

/// The new manifests of the request's depots, with their keys, and the DLC
/// depots Steam refused. Each manifest is read back from its
/// `manifest_file` when a plan already saved it (unless `refresh`),
/// otherwise fetched and saved there.
async fn new_layers(
    content: &Content,
    client: &SteamClient<LoggedIn>,
    request: &RplnetUpdateRequest,
    refresh: bool,
) -> Result<(Vec<Layer>, Vec<u32>), RplnetError> {
    let mut layers = Vec::new();
    let mut skipped = Vec::new();
    for (index, depot) in request.depots.iter().enumerate() {
        let Some(key) = depot_key(client, request.app_id, depot.depot_id, index > 0).await? else {
            skipped.push(depot.depot_id);
            continue;
        };
        let saved = if refresh {
            None
        } else {
            tokio::fs::read(&depot.manifest_file)
                .await
                .ok()
                .and_then(|raw| parse_manifest(&raw, &key).ok())
        };
        let manifest = match saved {
            Some(manifest) => manifest,
            None => {
                let (raw, manifest) = content
                    .manifest(client, request.app_id, &candidate(depot), &key)
                    .await?;
                save_manifest(&depot.manifest_file, &raw).await?;
                manifest
            }
        };
        layers.push(Layer {
            depot_id: depot.depot_id,
            key,
            manifest,
        });
    }
    if layers.is_empty() {
        return Err(RplnetError::steam(
            RplnetSteamFailure::InvalidResponse,
            "the update names no depot",
        ));
    }
    Ok((layers, skipped))
}

/// The installed manifests, the game's depot first. A DLC depot whose key
/// Steam refuses now cannot be read; it is left out, and its files are
/// simply not reused.
async fn previous_manifests(
    client: &SteamClient<LoggedIn>,
    request: &RplnetUpdateRequest,
    layers: &[Layer],
) -> Result<Vec<(u32, DepotManifest)>, RplnetError> {
    let mut previous = Vec::new();
    for (index, installed) in request.previous_manifests.iter().enumerate() {
        let key = match layers
            .iter()
            .find(|layer| layer.depot_id == installed.depot_id)
        {
            Some(layer) => layer.key.clone(),
            None => match depot_key(client, request.app_id, installed.depot_id, index > 0).await? {
                Some(key) => key,
                None => continue,
            },
        };
        let raw = tokio::fs::read(&installed.manifest_file).await?;
        previous.push((installed.depot_id, parse_manifest(&raw, &key)?));
    }
    Ok(previous)
}

/// A story path below its root, for matching builds whose roots differ.
fn key_below(path: &str, root: &str) -> Option<String> {
    let lower = path.to_lowercase();
    lower.strip_prefix(&root.to_lowercase()).map(str::to_string)
}

/// The update from the installed files to the depots of `layers`.
fn compare(
    request: &RplnetUpdateRequest,
    layers: &[Layer],
    previous: &[(u32, DepotManifest)],
) -> Result<RplnetUpdatePlan, RplnetError> {
    let layout = renpy_layout(&layers[0].manifest).ok_or_else(|| {
        RplnetError::steam(
            RplnetSteamFailure::NotRenPy,
            "the new build has no Ren'Py root",
        )
    })?;
    let filtered = layered_story_files(layers, &layout.root);
    let files: Vec<RplnetDownloadedFile> = layers
        .iter()
        .zip(&filtered)
        .flat_map(|(layer, manifest)| downloaded_files(manifest, layer.depot_id))
        .collect();

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
        .iter()
        .flat_map(|manifest| &manifest.files)
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
        skipped_depots: Vec::new(),
    })
}

/// Chunk layouts of the installed files whose content is still Steam's,
/// keyed by where they are below `reuse_dir`. Each file is looked up in the
/// previous manifest of the depot it came from.
fn reusable_layouts(
    request: &RplnetUpdateRequest,
    previous: &[(u32, DepotManifest)],
) -> HashMap<String, Vec<OldChunkLoc>> {
    let game_depot = request.previous_manifests.first().map(|m| m.depot_id);
    let mut locations: HashMap<u32, HashMap<String, &str>> = HashMap::new();
    for file in &request.installed {
        let (Some(local), Some(depot)) =
            (file.reusable_at.as_deref(), file.depot_id.or(game_depot))
        else {
            continue;
        };
        locations
            .entry(depot)
            .or_default()
            .insert(file.path.to_lowercase(), local);
    }
    let mut layouts = HashMap::new();
    for (depot_id, manifest) in previous {
        let Some(locations) = locations.get(depot_id) else {
            continue;
        };
        for file in manifest.files.iter().filter(|file| is_regular(file)) {
            let Some(local) = locations.get(&file.normalized_path().to_lowercase()) else {
                continue;
            };
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
            layouts.insert((*local).to_string(), chunks);
        }
    }
    layouts
}

#[cfg(test)]
mod tests {
    use super::*;
    use steamroom::depot::ChunkId;
    use steamroom::depot::DepotKey;
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
            depot_id: None,
        }
    }

    fn from_depot(mut file: RplnetInstalledFile, depot_id: u32) -> RplnetInstalledFile {
        file.depot_id = Some(depot_id);
        file
    }

    fn layer(depot_id: u32, files: Vec<ManifestFile>) -> Layer {
        Layer {
            depot_id,
            key: DepotKey([0; 32]),
            manifest: DepotManifest::new(files),
        }
    }

    /// A request whose installed build came from `previous_depots`.
    fn request(
        previous_root: &str,
        previous_depots: &[u32],
        files: Vec<RplnetInstalledFile>,
    ) -> RplnetUpdateRequest {
        RplnetUpdateRequest {
            app_id: 1,
            depots: Vec::new(),
            previous_manifests: previous_depots
                .iter()
                .map(|depot_id| RplnetInstalledManifest {
                    depot_id: *depot_id,
                    manifest_file: String::new(),
                })
                .collect(),
            previous_root: previous_root.to_string(),
            installed: files,
            reuse_dir: String::new(),
            destination: String::new(),
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
        let layers = vec![layer(
            2,
            vec![
                // Same name below the new root; one chunk kept, one new.
                file(
                    "Game-1.1\\Game\\script.rpa",
                    6,
                    vec![chunk(1, 0, 100), chunk(7, 100, 100)],
                ),
                file("Game-1.1\\renpy\\__init__.py", 4, vec![chunk(4, 0, 10)]),
                file("Game-1.1\\game\\new.rpy", 8, vec![chunk(8, 0, 10)]),
                // Unchanged on Steam, but the import changed the local copy:
                // the update leaves it as it is.
                file("Game-1.1\\game\\patched.rpyc", 5, vec![chunk(5, 0, 10)]),
                file("Game-1.1\\Game.exe", 9, vec![chunk(9, 0, 10)]),
            ],
        )];
        let request = request(
            "Game-1.0/",
            &[2],
            vec![
                installed("Game-1.0/game/script.rpa", 1, Some("game/script.rpa")),
                installed("Game-1.0/game/old.rpy", 2, Some("game/old.rpy")),
                installed("Game-1.0/renpy/__init__.py", 4, Some("renpy/__init__.py")),
                installed("Game-1.0/game/patched.rpyc", 5, None),
            ],
        );
        let plan = compare(&request, &layers, &[(2, previous)]).unwrap();
        assert_eq!(plan.root, "Game-1.1/");
        assert_eq!(
            plan.changed,
            vec!["Game-1.1/Game/script.rpa", "Game-1.1/game/new.rpy"]
        );
        assert_eq!(plan.added_count, 1);
        assert_eq!(plan.modified_count, 1);
        assert_eq!(plan.removed, vec!["Game-1.0/game/old.rpy"]);
        assert_eq!(plan.files.len(), 4, "the launcher is not a story file");
        assert!(plan.files.iter().all(|f| f.depot_id == 2));
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
        let layers = vec![layer(
            2,
            vec![
                file("game\\b.rpyc", 3, vec![chunk(1, 0, 100)]),
                file("renpy\\__init__.py", 2, vec![chunk(2, 0, 10)]),
            ],
        )];
        let request = request(
            "",
            &[2],
            vec![
                installed("game/a.rpyc", 1, None),
                installed("renpy/__init__.py", 2, Some("renpy/__init__.py")),
            ],
        );
        let previous = [(2, previous)];
        let plan = compare(&request, &layers, &previous).unwrap();
        assert_eq!(plan.changed, vec!["game/b.rpyc"]);
        assert_eq!(plan.download_size, 50);
        let layouts = reusable_layouts(&request, &previous);
        assert_eq!(
            layouts.keys().collect::<Vec<_>>(),
            vec!["renpy/__init__.py"]
        );
    }

    #[test]
    fn a_dlc_bought_after_the_import_adds_its_files() {
        let game = || {
            vec![
                file("G\\game\\script.rpa", 1, vec![chunk(1, 0, 100)]),
                file("G\\renpy\\__init__.py", 2, vec![chunk(2, 0, 10)]),
            ]
        };
        let layers = vec![
            layer(10, game()),
            layer(
                20,
                vec![
                    file("G\\game\\dlc.rpa", 3, vec![chunk(3, 0, 40)]),
                    file("Soundtrack\\01.mp3", 4, vec![chunk(4, 0, 40)]),
                ],
            ),
        ];
        let request = request(
            "G/",
            &[10],
            vec![
                // Records from before DLC: no depot, so the game's.
                installed("G/game/script.rpa", 1, Some("game/script.rpa")),
                installed("G/renpy/__init__.py", 2, Some("renpy/__init__.py")),
            ],
        );
        let previous = [(10, DepotManifest::new(game()))];
        let plan = compare(&request, &layers, &previous).unwrap();
        assert_eq!(plan.changed, vec!["G/game/dlc.rpa"]);
        assert_eq!((plan.added_count, plan.modified_count), (1, 0));
        assert!(plan.removed.is_empty());
        assert_eq!(plan.download_size, 20);
        let dlc = plan
            .files
            .iter()
            .find(|f| f.path == "G/game/dlc.rpa")
            .unwrap();
        assert_eq!(dlc.depot_id, 20);
        // The game's files are found in its manifest for reuse.
        assert_eq!(reusable_layouts(&request, &previous).len(), 2);
    }

    #[test]
    fn a_dlc_no_longer_owned_drops_its_files() {
        let layers = vec![layer(
            10,
            vec![
                file("G\\game\\script.rpa", 1, vec![chunk(1, 0, 100)]),
                file("G\\renpy\\__init__.py", 2, vec![chunk(2, 0, 10)]),
            ],
        )];
        let request = request(
            "G/",
            &[10, 20],
            vec![
                from_depot(
                    installed("G/game/script.rpa", 1, Some("game/script.rpa")),
                    10,
                ),
                from_depot(
                    installed("G/renpy/__init__.py", 2, Some("renpy/__init__.py")),
                    10,
                ),
                from_depot(installed("G/game/dlc.rpa", 3, Some("game/dlc.rpa")), 20),
            ],
        );
        // The DLC's key is refused now, so its manifest cannot be read.
        let plan = compare(&request, &layers, &[]).unwrap();
        assert!(plan.changed.is_empty());
        assert_eq!(plan.removed, vec!["G/game/dlc.rpa"]);
    }

    #[test]
    fn a_dlc_file_replacing_the_games_is_reused_from_the_dlc_manifest() {
        let dlc_previous =
            DepotManifest::new(vec![file("G\\game\\patch.rpy", 5, vec![chunk(5, 0, 10)])]);
        let game_previous =
            DepotManifest::new(vec![file("G\\game\\patch.rpy", 6, vec![chunk(6, 0, 10)])]);
        let request = request(
            "G/",
            &[10, 20],
            vec![from_depot(
                installed("G/game/patch.rpy", 5, Some("game/patch.rpy")),
                20,
            )],
        );
        let layouts = reusable_layouts(&request, &[(10, game_previous), (20, dlc_previous)]);
        assert_eq!(layouts["game/patch.rpy"][0].id, ChunkId([5; 20]));
    }

    #[test]
    fn a_build_without_renpy_is_refused() {
        let layers = vec![layer(1, vec![file("Game.exe", 1, vec![chunk(1, 0, 10)])])];
        let error = compare(&request("", &[1], vec![]), &layers, &[]).unwrap_err();
        assert!(matches!(
            error,
            RplnetError::Steam {
                reason: RplnetSteamFailure::NotRenPy,
                ..
            }
        ));
    }
}
