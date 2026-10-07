//! Telling a Ren'Py game from its depot manifest (plan 6.4).
//!
//! A directory is a Ren'Py root when it holds both `renpy/` with the engine's
//! `__init__` module (source, bytecode, or `__pycache__` bytecode) and `game/`
//! with at least one `.rpa`, `.rpyc` or `.rpy`. The root may be the depot root,
//! a versioned subdirectory (`Game-1.0-pc/`) or a Mac bundle's
//! `*.app/Contents/Resources/autorun/`. Engine copies under `lib/` have no
//! `game/` next to them and so never qualify. Paths compare case-insensitively;
//! the root keeps the depot's own case for downloading.
//!
//! A story is everything under the root except what only a desktop needs to
//! start the game (plan 6.5): engine runtimes under `lib/`, Mac bundles,
//! launchers and native libraries. Games read other files beside `game/`
//! through `config.basedir` (Doki Doki Literature Club keeps `characters/`
//! there), and an archive import keeps them too.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Version of the rules below. Raise it whenever a change could alter a
/// verdict or the files counted for a story, so the app re-inspects games it
/// inspected under older rules.
pub(crate) const RULES_VERSION: u32 = 2;

/// Version of `is_story_file`. Stories record it, so an update can tell
/// which files an older rule left out.
pub(crate) const FILTER_VERSION: u32 = 2;

/// Version of the Ren'Py detection rules; inspections made under another
/// version are stale.
#[uniffi::export]
pub fn rplnet_detection_rules_version() -> u32 {
    RULES_VERSION
}

/// Version of the rule choosing a story's files under the Ren'Py root.
#[uniffi::export]
pub fn rplnet_file_filter_version() -> u32 {
    FILTER_VERSION
}

/// Native code and launchers for a desktop platform.
const PLATFORM_EXTENSIONS: [&str; 8] = ["exe", "dll", "so", "dylib", "pdb", "sh", "bat", "command"];

/// Whether a path below the Ren'Py root (lowercase, without the root) belongs
/// to the story. `game/` and `renpy/` always do; elsewhere `lib/`, `*.app/`,
/// native libraries and launchers do not, nor does the launcher script
/// (`<name>.py`) beside the root.
pub(crate) fn is_story_file(rest: &str) -> bool {
    let (top, below) = rest.split_once('/').unwrap_or((rest, ""));
    if top == "game" || top == "renpy" {
        return true;
    }
    if top == "lib" || top.ends_with(".app") {
        return false;
    }
    let name = rest.rsplit('/').next().unwrap_or(rest);
    let Some((_, extension)) = name.rsplit_once('.') else {
        return true;
    };
    if PLATFORM_EXTENSIONS.contains(&extension) {
        return false;
    }
    !(below.is_empty() && extension == "py")
}

/// One manifest entry, as far as detection needs it.
pub(crate) struct Entry<'a> {
    pub path: &'a str,
    pub size: u64,
    pub is_dir: bool,
}

/// A Ren'Py root found in a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    /// Directory holding `game/` and `renpy/`, relative to the depot root in
    /// the depot's case: empty, or ending in `/`.
    pub root: String,
    /// Files of the story under the root (`is_story_file`).
    pub file_count: u64,
    pub total_size: u64,
    /// Supporting signs (`lib/py3-…`, an exe with a same-named `.py`); logged,
    /// never part of the verdict.
    pub hints: Vec<String>,
}

fn is_engine_init(rest: &str) -> bool {
    matches!(rest, "__init__.py" | "__init__.pyc" | "__init__.pyo")
        || (rest.starts_with("__pycache__/__init__.") && rest.ends_with(".pyc"))
}

fn is_script(path: &str) -> bool {
    path.ends_with(".rpa") || path.ends_with(".rpyc") || path.ends_with(".rpy")
}

/// Every place `dir/` starts a path segment in `path`: (prefix, rest).
fn split_at_dir<'a>(path: &'a str, dir: &str) -> Vec<(&'a str, &'a str)> {
    let needle = format!("{dir}/");
    path.match_indices(&needle)
        .filter(|(i, _)| *i == 0 || path.as_bytes()[i - 1] == b'/')
        .map(|(i, _)| (&path[..i], &path[i + needle.len()..]))
        .collect()
}

/// The Ren'Py root of a depot, or `None` when it is not a Ren'Py game. With
/// several roots the shallowest wins (the depot root over nested copies).
pub(crate) fn detect(entries: &[Entry<'_>]) -> Option<Layout> {
    let lower: Vec<String> = entries.iter().map(|e| e.path.to_lowercase()).collect();
    let mut engine_roots = BTreeSet::new();
    let mut game_roots = BTreeSet::new();
    for (entry, path) in entries.iter().zip(&lower) {
        if entry.is_dir {
            continue;
        }
        for (root, rest) in split_at_dir(path, "renpy") {
            if is_engine_init(rest) {
                engine_roots.insert(root.to_string());
            }
        }
        if is_script(path) {
            for (root, _) in split_at_dir(path, "game") {
                game_roots.insert(root.to_string());
            }
        }
    }
    let root_lower = engine_roots
        .intersection(&game_roots)
        .min_by_key(|root| (root.len(), (*root).clone()))?
        .clone();

    // The root's own case, taken from any entry beneath it. Lowercasing keeps
    // byte offsets for these paths, which are ASCII up to the root in every
    // depot seen so far; fall back to the lowercase form otherwise.
    let root = entries
        .iter()
        .zip(&lower)
        .find(|(_, path)| path.starts_with(&root_lower))
        .and_then(|(entry, _)| entry.path.get(..root_lower.len()))
        .filter(|original| original.to_lowercase() == root_lower)
        .unwrap_or(&root_lower)
        .to_string();

    let mut file_count = 0;
    let mut total_size = 0;
    let mut lib_hints = BTreeSet::new();
    let mut exe_stems = BTreeSet::new();
    let mut side_scripts = BTreeSet::new();
    for (entry, path) in entries.iter().zip(&lower) {
        let Some(rest) = path.strip_prefix(root_lower.as_str()) else {
            continue;
        };
        if !entry.is_dir && is_story_file(rest) {
            file_count += 1;
            total_size += entry.size;
        }
        if let Some(lib) = rest.strip_prefix("lib/") {
            let top = lib.split('/').next().unwrap_or("");
            if top.starts_with("py2-") || top.starts_with("py3-") || top.starts_with("python") {
                lib_hints.insert(format!("lib/{top}"));
            }
        }
        if !rest.contains('/') {
            if let Some(stem) = rest.strip_suffix(".exe") {
                exe_stems.insert(stem.to_string());
            }
            if let Some(stem) = rest
                .strip_suffix(".py")
                .or_else(|| rest.strip_suffix(".sh"))
            {
                side_scripts.insert(stem.to_string());
            }
        }
    }
    let mut hints: Vec<String> = lib_hints.into_iter().collect();
    hints.extend(
        exe_stems
            .intersection(&side_scripts)
            .map(|stem| format!("{stem}.exe+{stem}.py/.sh")),
    );
    Some(Layout {
        root,
        file_count,
        total_size,
        hints,
    })
}

/// Files that carry the engine version (`vc_version` and `__init__`, as
/// source or bytecode, also under `__pycache__/`), as manifest paths.
pub(crate) fn version_files<'a>(entries: &[Entry<'a>], root: &str) -> Vec<&'a str> {
    let root_lower = root.to_lowercase();
    entries
        .iter()
        .filter(|entry| !entry.is_dir)
        .filter(|entry| {
            let path = entry.path.to_lowercase();
            let Some(rest) = path
                .strip_prefix(root_lower.as_str())
                .and_then(|rest| rest.strip_prefix("renpy/"))
            else {
                return false;
            };
            let name = rest.strip_prefix("__pycache__/").unwrap_or(rest);
            if name.contains('/') {
                return false;
            }
            let Some((stem, ext)) = name.split_once('.') else {
                return false;
            };
            matches!(stem, "vc_version" | "__init__")
                && (matches!(ext, "py" | "pyc" | "pyo") || ext.ends_with(".pyc"))
        })
        .map(|entry| entry.path)
        .collect()
}

/// Directories directly under `<root>lib/`, in the depot's case. Their names
/// tell the Python version of a source-only engine.
pub(crate) fn lib_directories(entries: &[Entry<'_>], root: &str) -> Vec<String> {
    let prefix = format!("{}lib/", root.to_lowercase());
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for entry in entries {
        let lower = entry.path.to_lowercase();
        let Some(rest) = lower.strip_prefix(prefix.as_str()) else {
            continue;
        };
        let Some(top) = rest.split('/').next().filter(|top| !top.is_empty()) else {
            continue;
        };
        if !rest.contains('/') && !entry.is_dir {
            continue;
        }
        let start = prefix.len();
        let original = entry
            .path
            .get(start..start + top.len())
            .filter(|original| original.to_lowercase() == top)
            .unwrap_or(top);
        names.insert(top.to_string(), original.to_string());
    }
    names.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str) -> Entry<'_> {
        Entry {
            path,
            size: 1,
            is_dir: false,
        }
    }

    #[test]
    fn windows_layout_at_the_depot_root() {
        let entries = [
            file("Foo.exe"),
            file("Foo.py"),
            file("renpy/__init__.pyc"),
            file("game/archive.rpa"),
            file("lib/py3-windows-x86_64/python.exe"),
        ];
        let layout = detect(&entries).unwrap();
        assert_eq!(layout.root, "");
        assert_eq!(
            layout.file_count, 2,
            "only renpy/ and game/ belong to the story"
        );
        assert!(layout.hints.contains(&"lib/py3-windows-x86_64".to_string()));
        assert!(layout.hints.contains(&"foo.exe+foo.py/.sh".to_string()));
    }

    #[test]
    fn mac_bundle_root_keeps_its_case() {
        let entries = [
            file("Foo.app/Contents/Resources/autorun/renpy/__pycache__/__init__.cpython-39.pyc"),
            file("Foo.app/Contents/Resources/autorun/game/script.rpyc"),
        ];
        assert_eq!(
            detect(&entries).unwrap().root,
            "Foo.app/Contents/Resources/autorun/"
        );
    }

    #[test]
    fn versioned_subdirectory_with_odd_case() {
        let entries = [
            file("MyGame-1.0-pc/renpy/__init__.py"),
            file("MyGame-1.0-pc/Game/a.rpa"),
        ];
        assert_eq!(detect(&entries).unwrap().root, "MyGame-1.0-pc/");
    }

    #[test]
    fn engine_without_game_is_not_renpy() {
        let entries = [
            file("lib/linux-x86_64/lib/python2.7/renpy/__init__.pyo"),
            file("game/readme.txt"),
            file("other/game/script.rpy"),
        ];
        assert_eq!(detect(&entries), None);
    }

    #[test]
    fn shallowest_root_wins() {
        let entries = [
            file("renpy/__init__.py"),
            file("game/a.rpy"),
            file("copy/renpy/__init__.py"),
            file("copy/game/a.rpy"),
        ];
        assert_eq!(detect(&entries).unwrap().root, "");
    }

    #[test]
    fn story_files_leave_out_what_only_a_desktop_needs() {
        for rest in [
            "game/script.rpa",
            "game/python-packages/_speedups.so",
            "renpy/__init__.py",
            "characters/monika.chr",
            "readme.txt",
            "steam_appid.txt",
            "extras/notes.py",
        ] {
            assert!(is_story_file(rest), "{rest}");
        }
        for rest in [
            "lib/py3-windows-x86_64/python.exe",
            "ddlc.app/contents/macos/ddlc",
            "ddlc.exe",
            "ddlc.sh",
            "ddlc.py",
            "steam_api64.dll",
            "redist/vcredist.exe",
            "plugins/libfoo.dylib",
        ] {
            assert!(!is_story_file(rest), "{rest}");
        }
    }

    #[test]
    fn story_size_counts_files_beside_game() {
        let entries = [
            file("DDLC.exe"),
            file("DDLC.py"),
            file("renpy/__init__.pyo"),
            file("game/scripts.rpa"),
            file("characters/monika.chr"),
            file("lib/windows-i686/python.exe"),
        ];
        assert_eq!(detect(&entries).unwrap().file_count, 3);
    }

    #[test]
    fn version_files_and_lib_directories() {
        let entries = [
            file("G/renpy/vc_version.py"),
            file("G/renpy/__init__.pyo"),
            file("G/renpy/__pycache__/vc_version.cpython-39.pyc"),
            file("G/renpy/display/__init__.py"),
            file("G/renpy/vc_version_old.txt"),
            file("G/lib/py3-linux-x86_64/python"),
            file("G/lib/python3.9/os.pyc"),
            file("G/lib/README"),
        ];
        assert_eq!(
            version_files(&entries, "G/"),
            vec![
                "G/renpy/vc_version.py",
                "G/renpy/__init__.pyo",
                "G/renpy/__pycache__/vc_version.cpython-39.pyc"
            ]
        );
        assert_eq!(
            lib_directories(&entries, "G/"),
            vec!["py3-linux-x86_64", "python3.9"]
        );
    }
}
