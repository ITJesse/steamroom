//! The games an account owns: license list → packages → apps → app info,
//! all through PICS on the logged-in CM connection (plan stage 4).

use crate::error::RplnetError;
use crate::error::RplnetSteamFailure;
use futures::StreamExt;
use futures::TryStreamExt;
use prost::Message;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use steamroom::apps::AccessToken;
use steamroom::apps::AppInfo;
use steamroom::apps::PackageAccessToken;
use steamroom::client::LoggedIn;
use steamroom::client::SteamClient;
use steamroom::depot::AppId;
use steamroom::depot::PackageId;
use steamroom::generated::c_msg_client_license_list::License;
use steamroom::types::key_value::KeyValue;
use steamroom::types::key_value::KvValue;
use tracing::info;

/// Steam store tag "Visual Novel".
const VISUAL_NOVEL_TAG: u64 = 3799;
/// PICS requests per batch, and batches in flight at once.
const PACKAGES_PER_REQUEST: usize = 200;
const TOKENS_PER_REQUEST: usize = 500;
const APPS_PER_REQUEST: usize = 100;
const REQUESTS_IN_FLIGHT: usize = 4;
/// Store images live here, under `<appid>/<file>`.
const STORE_ASSETS: &str = "https://shared.akamai.steamstatic.com/store_item_assets/steam/apps";

/// A game in the account's library.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct RplnetOwnedGame {
    pub app_id: u32,
    /// In the requested language when the app has a name for it.
    pub name: String,
    /// PICS change number: changes whenever the app's info changes.
    pub change_number: u32,
    /// Build of the public branch, when Steam lists it.
    pub build_id: Option<u32>,
    /// When the public branch got that build, in seconds since 1970.
    pub build_time: Option<i64>,
    /// Every license for it belongs to another account: it is borrowed
    /// through Steam Family. Its content downloads like an owned game's.
    pub family_shared: bool,
    /// Tagged "Visual Novel" on the store.
    pub visual_novel: bool,
    /// The store's header image (460×215), in the requested language when
    /// there is one.
    pub header_image_url: Option<String>,
    /// Depots worth inspecting, best first (plan 6.5). DLC depots are not
    /// among them; they are in `dlc`.
    pub depots: Vec<RplnetDepotCandidate>,
    /// DLC of the game the account has a license for, of its own or through
    /// Steam Family, that has content to install with it.
    pub dlc: Vec<RplnetDlc>,
}

/// A DLC the account has a license for, with the depots it installs into
/// the game's directory.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RplnetDlc {
    pub app_id: u32,
    /// In the requested language when the DLC has a name for it.
    pub name: String,
    /// Its depots in the game's app info, by depot id: every platform's,
    /// since a depot of another platform simply has nothing under the
    /// game's Ren'Py root.
    pub depots: Vec<RplnetDepotVersion>,
}

/// A depot that may hold the game, with its public manifest.
#[derive(Clone, Debug, PartialEq, Eq, Hash, uniffi::Record)]
pub struct RplnetDepotCandidate {
    pub depot_id: u32,
    pub manifest_id: u64,
    /// Installed size of the public manifest, when Steam lists it.
    pub size: Option<u64>,
    /// Listed in a package the account owns. Other depots are tried after
    /// these and skipped when Steam denies their key.
    pub owned: bool,
}

/// The library of `client`'s account. `licenses` is its license list;
/// `language` a Steam language code (`english`, `schinese`, …) for names and
/// images.
pub(crate) async fn owned_games(
    client: &SteamClient<LoggedIn>,
    licenses: &[License],
    language: &str,
) -> Result<Vec<RplnetOwnedGame>, RplnetError> {
    let started = std::time::Instant::now();
    let ownership = Ownership::read(client, licenses).await?;
    let app_ids: Vec<u32> = ownership.app_packages.keys().copied().collect();
    let infos = app_infos(client, &app_ids).await?;
    let names = dlc_names(&infos, language);

    let mut games = Vec::new();
    for info in &infos {
        let Some(app_id) = info.app_id else {
            continue;
        };
        let Ok(kv) = info.key_values() else {
            continue;
        };
        if let Some(game) = game_from(
            app_id.0,
            info.change_number.unwrap_or(0),
            &kv,
            &ownership,
            &names,
            language,
        ) {
            games.push(game);
        }
    }
    info!(
        "library: {} licenses, {} packages, {} apps, {} games ({} with DLC) in {} ms",
        licenses.len(),
        ownership.package_count,
        infos.len(),
        games.len(),
        games.iter().filter(|game| !game.dlc.is_empty()).count(),
        started.elapsed().as_millis()
    );
    Ok(games)
}

/// What the account's licenses grant: packages → apps and depots.
pub(crate) struct Ownership {
    /// Every app an owned or family-shared package grants, with those
    /// packages.
    app_packages: BTreeMap<u32, Vec<u32>>,
    /// Packages whose license belongs to another account (Steam Family).
    shared_packages: BTreeSet<u32>,
    /// Depots an owned or shared package lists.
    owned_depots: BTreeSet<u32>,
    package_count: usize,
}

impl Ownership {
    pub(crate) async fn read(
        client: &SteamClient<LoggedIn>,
        licenses: &[License],
    ) -> Result<Self, RplnetError> {
        let account_id = client.steam_id().raw() as u32;
        let mut shared_packages = BTreeSet::new();
        let package_tokens: Vec<PackageAccessToken> = licenses
            .iter()
            .filter_map(|license| {
                let package_id = license.package_id?;
                if license.owner_id.is_some_and(|owner| owner != account_id) {
                    shared_packages.insert(package_id);
                }
                Some(PackageAccessToken {
                    package_id: PackageId(package_id),
                    token: license.access_token.unwrap_or(0),
                })
            })
            .collect();
        let packages: Vec<_> =
            futures::stream::iter(batches(&package_tokens, PACKAGES_PER_REQUEST))
                .map(|batch| async move { client.pics_get_package_info(&batch).await })
                .buffer_unordered(REQUESTS_IN_FLIGHT)
                .try_collect::<Vec<_>>()
                .await?
                .into_iter()
                .flatten()
                .collect();
        let mut ownership = Ownership {
            app_packages: BTreeMap::new(),
            shared_packages,
            owned_depots: BTreeSet::new(),
            package_count: packages.len(),
        };
        for package in &packages {
            let Some(package_id) = package.package_id else {
                continue;
            };
            let Ok(kv) = package.key_values() else {
                continue;
            };
            ownership.add_package(package_id.0, &kv);
        }
        Ok(ownership)
    }

    fn add_package(&mut self, package_id: u32, kv: &KeyValue) {
        for depot in numbers(kv.get("depotids")) {
            self.owned_depots.insert(depot as u32);
        }
        for app in numbers(kv.get("appids")) {
            let app = app as u32;
            self.app_packages.entry(app).or_default().push(package_id);
        }
    }

    /// Every license for the app belongs to another account.
    fn family_shared(&self, app_id: u32) -> bool {
        self.app_packages.get(&app_id).is_some_and(|packages| {
            !packages.is_empty()
                && packages
                    .iter()
                    .all(|package| self.shared_packages.contains(package))
        })
    }

    /// A package of the account's own or a family member's grants the app.
    fn licenses(&self, app_id: u32) -> bool {
        self.app_packages.contains_key(&app_id)
    }
}

/// App info of `app_ids`, with their access tokens.
async fn app_infos(
    client: &SteamClient<LoggedIn>,
    app_ids: &[u32],
) -> Result<Vec<AppInfo>, RplnetError> {
    let app_ids: Vec<AppId> = app_ids.iter().copied().map(AppId).collect();
    let tokens: BTreeMap<u32, u64> = futures::stream::iter(batches(&app_ids, TOKENS_PER_REQUEST))
        .map(|batch| async move { client.pics_get_access_tokens(&batch).await })
        .buffer_unordered(REQUESTS_IN_FLIGHT)
        .try_collect::<Vec<_>>()
        .await?
        .into_iter()
        .flatten()
        .map(|token| (token.app_id.0, token.token))
        .collect();
    let requests: Vec<AccessToken> = app_ids
        .iter()
        .map(|app| AccessToken {
            app_id: *app,
            token: tokens.get(&app.0).copied().unwrap_or(0),
        })
        .collect();
    Ok(futures::stream::iter(batches(&requests, APPS_PER_REQUEST))
        .map(|batch| async move { client.pics_get_product_info(&batch).await })
        .buffer_unordered(REQUESTS_IN_FLIGHT)
        .try_collect::<Vec<_>>()
        .await?
        .into_iter()
        .flatten()
        .collect())
}

/// Names of the DLC among `infos`, in `language` when they have one.
fn dlc_names(infos: &[AppInfo], language: &str) -> BTreeMap<u32, String> {
    infos
        .iter()
        .filter_map(|info| {
            let app_id = info.app_id?.0;
            let kv = info.key_values().ok()?;
            let common = kv.get("common")?;
            if !text(common.get("type"))?.eq_ignore_ascii_case("dlc") {
                return None;
            }
            Some((app_id, app_name(app_id, common, language)))
        })
        .collect()
}

fn app_name(app_id: u32, common: &KeyValue, language: &str) -> String {
    localized(common.get("name_localized"), language)
        .or_else(|| text(common.get("name")))
        .unwrap_or_else(|| format!("App {app_id}"))
}

/// The game described by an app's PICS info, or `None` for anything but a
/// game (DLC, tools, demos, applications, …). `dlc_names` names the owned
/// DLC apps.
fn game_from(
    app_id: u32,
    change_number: u32,
    kv: &KeyValue,
    ownership: &Ownership,
    dlc_names: &BTreeMap<u32, String>,
    language: &str,
) -> Option<RplnetOwnedGame> {
    let common = kv.get("common")?;
    if !text(common.get("type"))?.eq_ignore_ascii_case("game") {
        return None;
    }
    let name = app_name(app_id, common, language);
    let header_image_url = localized(common.get("header_image"), language)
        .or_else(|| localized(common.get("header_image"), "english"))
        .map(|file| format!("{STORE_ASSETS}/{app_id}/{file}"));
    Some(RplnetOwnedGame {
        app_id,
        name,
        change_number,
        build_id: public_build_id(kv),
        build_time: public_build_time(kv),
        family_shared: ownership.family_shared(app_id),
        visual_novel: numbers(common.get("store_tags")).any(|tag| tag == VISUAL_NOVEL_TAG),
        header_image_url,
        depots: rank_depots(kv.get("depots"), &ownership.owned_depots),
        dlc: licensed_dlc(kv.get("depots"), ownership, dlc_names),
    })
}

/// The DLC depots of a game's `depots` node whose DLC `ownership` licenses
/// (of the account's own or through Steam Family), by DLC. Depots shared
/// from another app or installed shared, low-violence variants, language
/// variants (no way to tell which one belongs with the game's files) and
/// depots without a public manifest are left out, and so is a DLC left with
/// no depot.
fn licensed_dlc(
    depots: Option<&KeyValue>,
    ownership: &Ownership,
    names: &BTreeMap<u32, String>,
) -> Vec<RplnetDlc> {
    let Some(KvValue::Children(depots)) = depots.map(|d| &d.value) else {
        return Vec::new();
    };
    let mut by_dlc: BTreeMap<u32, Vec<RplnetDepotVersion>> = BTreeMap::new();
    for (key, depot) in depots {
        let Ok(depot_id) = key.parse::<u32>() else {
            continue;
        };
        let Some(dlc) = number(depot.get("dlcappid")).map(|dlc| dlc as u32) else {
            continue;
        };
        if !ownership.licenses(dlc) || !installs_with_the_game(depot) {
            continue;
        }
        let config = depot.get("config");
        if text(config.and_then(|c| c.get("language"))).is_some_and(|l| !l.is_empty()) {
            continue;
        }
        let Some((manifest_id, size)) = public_manifest(depot) else {
            continue;
        };
        by_dlc.entry(dlc).or_default().push(RplnetDepotVersion {
            depot_id,
            manifest_id,
            size,
        });
    }
    by_dlc
        .into_iter()
        .map(|(app_id, mut depots)| {
            depots.sort_by_key(|depot| depot.depot_id);
            RplnetDlc {
                app_id,
                name: names
                    .get(&app_id)
                    .cloned()
                    .unwrap_or_else(|| format!("App {app_id}")),
                depots,
            }
        })
        .collect()
}

/// Not shared from another app, not installed shared (redistributables),
/// not a low-violence variant.
fn installs_with_the_game(depot: &KeyValue) -> bool {
    depot.get("depotfromapp").is_none()
        && !flag(depot.get("sharedinstall"))
        && !flag(depot.get("config").and_then(|c| c.get("lowviolence")))
}

/// Depots that may hold the game, best first (plan 6.5): depots of owned
/// packages before the rest; then no `oslist` (every platform), Linux,
/// Windows, macOS; then no `language` before a language. Depots shared from
/// another app or installed shared (redistributables), low-violence variants,
/// DLC depots (`licensed_dlc`) and depots without a public manifest are left
/// out.
fn rank_depots(
    depots: Option<&KeyValue>,
    owned_depots: &BTreeSet<u32>,
) -> Vec<RplnetDepotCandidate> {
    let Some(KvValue::Children(depots)) = depots.map(|d| &d.value) else {
        return Vec::new();
    };
    let mut ranked: Vec<(u32, RplnetDepotCandidate)> = depots
        .iter()
        .filter_map(|(key, depot)| {
            let depot_id: u32 = key.parse().ok()?;
            if !installs_with_the_game(depot) || depot.get("dlcappid").is_some() {
                return None;
            }
            let config = depot.get("config");
            let (manifest_id, size) = public_manifest(depot)?;
            let os_list = text(config.and_then(|c| c.get("oslist"))).unwrap_or_default();
            let os_rank = if os_list.is_empty() {
                0
            } else if os_list.contains("linux") {
                1
            } else if os_list.contains("windows") {
                2
            } else if os_list.contains("macos") {
                3
            } else {
                4
            };
            let has_language = text(config.and_then(|c| c.get("language")))
                .is_some_and(|language| !language.is_empty());
            let owned = owned_depots.contains(&depot_id);
            let rank = u32::from(!owned) * 100 + u32::from(has_language) * 10 + os_rank;
            Some((
                rank,
                RplnetDepotCandidate {
                    depot_id,
                    manifest_id,
                    size,
                    owned,
                },
            ))
        })
        .collect();
    ranked.sort_by_key(|(rank, candidate)| (*rank, candidate.depot_id));
    ranked.into_iter().map(|(_, candidate)| candidate).collect()
}

/// What Steam lists now for an app's public branch, and the DLC the account
/// owns now: enough to tell whether an imported story is behind (plan 6.7).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RplnetAppVersion {
    pub app_id: u32,
    /// PICS change number: changes whenever the app's info changes.
    pub change_number: u32,
    pub build_id: Option<u32>,
    /// When the public branch got that build, in seconds since 1970.
    pub build_time: Option<i64>,
    /// Every depot with a public manifest.
    pub depots: Vec<RplnetDepotVersion>,
    /// DLC the account has a license for now, as `RplnetOwnedGame::dlc`.
    pub dlc: Vec<RplnetDlc>,
}

/// A depot's public manifest.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RplnetDepotVersion {
    pub depot_id: u32,
    pub manifest_id: u64,
    /// Installed size of the manifest, when Steam lists it.
    pub size: Option<u64>,
}

/// The public branch of each of `app_ids` and the DLC of it `licenses` grant.
/// Apps Steam returns nothing for are left out. `language` is for DLC names.
pub(crate) async fn app_versions(
    client: &SteamClient<LoggedIn>,
    licenses: &[License],
    app_ids: &[u32],
    language: &str,
) -> Result<Vec<RplnetAppVersion>, RplnetError> {
    let started = std::time::Instant::now();
    let ownership = Ownership::read(client, licenses).await?;
    let infos = app_infos(client, app_ids).await?;
    let parsed: Vec<(u32, u32, KeyValue)> = infos
        .iter()
        .filter_map(|info| {
            Some((
                info.app_id?.0,
                info.change_number.unwrap_or(0),
                info.key_values().ok()?,
            ))
        })
        .collect();
    // Licensed DLC of these apps, for their names.
    let dlc_ids: BTreeSet<u32> = parsed
        .iter()
        .flat_map(|(_, _, kv)| licensed_dlc(kv.get("depots"), &ownership, &BTreeMap::new()))
        .map(|dlc| dlc.app_id)
        .collect();
    let names = if dlc_ids.is_empty() {
        BTreeMap::new()
    } else {
        let ids: Vec<u32> = dlc_ids.into_iter().collect();
        dlc_names(&app_infos(client, &ids).await?, language)
    };
    let versions: Vec<RplnetAppVersion> = parsed
        .iter()
        .map(|(app_id, change_number, kv)| {
            let mut version = app_version(*app_id, *change_number, kv);
            version.dlc = licensed_dlc(kv.get("depots"), &ownership, &names);
            version
        })
        .collect();
    info!(
        "app versions: {} of {} apps, {} licensed DLC, in {} ms",
        versions.len(),
        app_ids.len(),
        versions
            .iter()
            .map(|version| version.dlc.len())
            .sum::<usize>(),
        started.elapsed().as_millis()
    );
    Ok(versions)
}

fn app_version(app_id: u32, change_number: u32, kv: &KeyValue) -> RplnetAppVersion {
    let mut depots: Vec<RplnetDepotVersion> = match kv.get("depots").map(|d| &d.value) {
        Some(KvValue::Children(depots)) => depots
            .iter()
            .filter_map(|(key, depot)| {
                let depot_id: u32 = key.parse().ok()?;
                let (manifest_id, size) = public_manifest(depot)?;
                Some(RplnetDepotVersion {
                    depot_id,
                    manifest_id,
                    size,
                })
            })
            .collect(),
        _ => Vec::new(),
    };
    depots.sort_by_key(|depot| depot.depot_id);
    RplnetAppVersion {
        app_id,
        change_number,
        build_id: public_build_id(kv),
        build_time: public_build_time(kv),
        depots,
        dlc: Vec::new(),
    }
}

fn public_branch(kv: &KeyValue) -> Option<&KeyValue> {
    kv.get("depots")?.get("branches")?.get("public")
}

fn public_build_id(kv: &KeyValue) -> Option<u32> {
    number(public_branch(kv)?.get("buildid")).and_then(|id| u32::try_from(id).ok())
}

fn public_build_time(kv: &KeyValue) -> Option<i64> {
    number(public_branch(kv)?.get("timeupdated")).and_then(|time| i64::try_from(time).ok())
}

/// A depot's public manifest id and size.
fn public_manifest(depot: &KeyValue) -> Option<(u64, Option<u64>)> {
    let public = depot.get("manifests").and_then(|m| m.get("public"))?;
    // Newer PICS nests the id as `public/gid`; older has it as the value.
    let manifest_id = number(public.get("gid")).or_else(|| number(Some(public)))?;
    let size = number(public.get("size")).or_else(|| number(depot.get("maxsize")));
    Some((manifest_id, size))
}

/// `items` split into owned batches of `size`, so each request future owns
/// its batch.
fn batches<T: Clone>(items: &[T], size: usize) -> Vec<Vec<T>> {
    items.chunks(size).map(<[T]>::to_vec).collect()
}

fn text(kv: Option<&KeyValue>) -> Option<String> {
    match &kv?.value {
        KvValue::String(s) => Some(s.clone()),
        KvValue::Int32(n) => Some(n.to_string()),
        KvValue::UInt64(n) => Some(n.to_string()),
        KvValue::Int64(n) => Some(n.to_string()),
        _ => None,
    }
}

fn number(kv: Option<&KeyValue>) -> Option<u64> {
    match &kv?.value {
        KvValue::Int32(n) => u64::try_from(*n).ok(),
        KvValue::UInt64(n) => Some(*n),
        KvValue::Int64(n) => u64::try_from(*n).ok(),
        KvValue::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn flag(kv: Option<&KeyValue>) -> bool {
    number(kv).is_some_and(|n| n != 0)
}

/// The numbers in a list-like node (`appids`, `depotids`, `store_tags`).
fn numbers(kv: Option<&KeyValue>) -> impl Iterator<Item = u64> + '_ {
    let children = match kv.map(|kv| &kv.value) {
        Some(KvValue::Children(map)) => Some(map.values()),
        _ => None,
    };
    children
        .into_iter()
        .flatten()
        .filter_map(|child| number(Some(child)))
}

/// The value for `language` in a per-language node (`name_localized`,
/// `header_image`). Some apps key a language with an `sc_` prefix.
fn localized(kv: Option<&KeyValue>, language: &str) -> Option<String> {
    let kv = kv?;
    text(kv.get(language))
        .or_else(|| text(kv.get(&format!("sc_{language}"))))
        .filter(|value| !value.is_empty())
}

/// Decode the license list Steam pushes after logon.
pub(crate) fn decode_licenses(body: &[u8]) -> Result<Vec<License>, RplnetError> {
    let list = steamroom::generated::CMsgClientLicenseList::decode(body).map_err(|e| {
        RplnetError::steam(
            RplnetSteamFailure::InvalidResponse,
            format!("license list: {e}"),
        )
    })?;
    Ok(list.licenses)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(key: &str, value: KvValue) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value,
        }
    }

    fn s(key: &str, value: &str) -> KeyValue {
        node(key, KvValue::String(value.to_string()))
    }

    fn children(key: &str, items: Vec<KeyValue>) -> KeyValue {
        node(
            key,
            KvValue::Children(items.into_iter().map(|kv| (kv.key.clone(), kv)).collect()),
        )
    }

    fn depot(id: &str, extra: Vec<KeyValue>, manifest: &str) -> KeyValue {
        let mut items = extra;
        items.push(children(
            "manifests",
            vec![children(
                "public",
                vec![s("gid", manifest), s("size", "1000")],
            )],
        ));
        children(id, items)
    }

    fn app(depots: Vec<KeyValue>) -> KeyValue {
        children(
            "100",
            vec![
                children(
                    "common",
                    vec![
                        s("type", "Game"),
                        s("name", "Roman's Christmas"),
                        children("name_localized", vec![s("schinese", "罗曼圣诞探案集")]),
                        children(
                            "header_image",
                            vec![
                                s("english", "header.jpg"),
                                s("schinese", "header_schinese.jpg"),
                            ],
                        ),
                        children("store_tags", vec![s("0", "1721"), s("1", "3799")]),
                    ],
                ),
                children("depots", depots),
            ],
        )
    }

    /// Ownership of `owned_depots`, and of `owned_apps` through a package
    /// of the account's own (package 1) or, for `shared_apps`, only through
    /// Steam Family (package 2).
    fn ownership(owned_depots: &[u32], owned_apps: &[u32], shared_apps: &[u32]) -> Ownership {
        let mut ownership = Ownership {
            app_packages: BTreeMap::new(),
            shared_packages: [2].into(),
            owned_depots: owned_depots.iter().copied().collect(),
            package_count: 2,
        };
        let list = |items: &[u32]| {
            children(
                "appids",
                items
                    .iter()
                    .enumerate()
                    .map(|(i, app)| s(&i.to_string(), &app.to_string()))
                    .collect(),
            )
        };
        ownership.add_package(1, &children("1", vec![list(owned_apps)]));
        ownership.add_package(2, &children("2", vec![list(shared_apps)]));
        ownership
    }

    fn game(
        kv: &KeyValue,
        owned_depots: &[u32],
        owned_apps: &[u32],
        language: &str,
    ) -> RplnetOwnedGame {
        let mut apps = vec![100];
        apps.extend_from_slice(owned_apps);
        game_from(
            100,
            7,
            kv,
            &ownership(owned_depots, &apps, &[]),
            &BTreeMap::from([(300, "Extra".to_string())]),
            language,
        )
        .unwrap()
    }

    #[test]
    fn names_and_images_follow_the_language() {
        let kv = app(vec![children(
            "branches",
            vec![children(
                "public",
                vec![s("buildid", "18234567"), s("timeupdated", "1759651200")],
            )],
        )]);
        let chinese = game(&kv, &[], &[], "schinese");
        assert_eq!(chinese.name, "罗曼圣诞探案集");
        assert_eq!(
            chinese.header_image_url.as_deref(),
            Some(
                "https://shared.akamai.steamstatic.com/store_item_assets/steam/apps/100/header_schinese.jpg"
            )
        );
        let english = game(&kv, &[], &[], "english");
        assert_eq!(english.name, "Roman's Christmas");
        assert!(
            english
                .header_image_url
                .unwrap()
                .ends_with("/100/header.jpg")
        );
        assert!(english.visual_novel);
        assert_eq!(english.build_id, Some(18234567));
        assert_eq!(english.build_time, Some(1759651200));
    }

    #[test]
    fn app_versions_list_every_public_depot_manifest() {
        let kv = app(vec![
            depot("102", vec![s("depotfromapp", "228980")], "12"),
            depot("101", vec![], "11"),
            children("103", vec![s("name", "no manifest")]),
            children(
                "branches",
                vec![children(
                    "public",
                    vec![s("buildid", "42"), s("timeupdated", "1759651200")],
                )],
            ),
        ]);
        let version = app_version(100, 9, &kv);
        assert_eq!(version.build_id, Some(42));
        assert_eq!(version.build_time, Some(1759651200));
        assert_eq!(version.change_number, 9);
        // Ranking does not apply: the app's own depot is looked up by id.
        assert_eq!(
            version.depots,
            vec![
                RplnetDepotVersion {
                    depot_id: 101,
                    manifest_id: 11,
                    size: Some(1000)
                },
                RplnetDepotVersion {
                    depot_id: 102,
                    manifest_id: 12,
                    size: Some(1000)
                },
            ]
        );
    }

    #[test]
    fn only_games_are_listed() {
        let mut kv = app(vec![]);
        if let KvValue::Children(root) = &mut kv.value
            && let Some(KvValue::Children(common)) = root.get_mut("common").map(|c| &mut c.value)
        {
            common.insert("type".into(), s("type", "DLC"));
        }
        assert!(
            game_from(
                100,
                7,
                &kv,
                &ownership(&[], &[100], &[]),
                &BTreeMap::new(),
                "english"
            )
            .is_none()
        );
    }

    #[test]
    fn depots_are_ranked_by_ownership_platform_and_language() {
        let config = |items: Vec<KeyValue>| children("config", items);
        let kv = app(vec![
            depot("101", vec![config(vec![s("oslist", "windows")])], "11"),
            depot("102", vec![config(vec![s("oslist", "macos")])], "12"),
            depot("103", vec![], "13"),
            depot("104", vec![config(vec![s("oslist", "linux")])], "14"),
            depot("105", vec![config(vec![s("language", "japanese")])], "15"),
            depot("106", vec![], "16"),
            depot("107", vec![s("depotfromapp", "228980")], "17"),
            depot("108", vec![s("sharedinstall", "1")], "18"),
            depot("109", vec![s("dlcappid", "200")], "19"),
            depot("110", vec![s("dlcappid", "300")], "20"),
            depot("111", vec![config(vec![s("lowviolence", "1")])], "21"),
            children("112", vec![s("name", "no manifest")]),
            children("branches", vec![]),
        ]);
        let ids: Vec<u32> = game(&kv, &[101, 102, 103, 104, 105, 109, 110], &[300], "english")
            .depots
            .iter()
            .map(|d| d.depot_id)
            .collect();
        // 106 is not in an owned package; DLC depots are never candidates.
        assert_eq!(ids, vec![103, 104, 101, 102, 105, 106]);
    }

    #[test]
    fn licensed_dlc_lists_every_platform_but_no_variants() {
        let config = |items: Vec<KeyValue>| children("config", items);
        let kv = app(vec![
            depot("101", vec![], "11"),
            // DLC 300, owned: every platform.
            depot("301", vec![s("dlcappid", "300")], "31"),
            depot(
                "302",
                vec![s("dlcappid", "300"), config(vec![s("oslist", "macos")])],
                "32",
            ),
            // Variants of DLC 300 that cannot be told apart from its files.
            depot(
                "303",
                vec![s("dlcappid", "300"), config(vec![s("language", "german")])],
                "33",
            ),
            depot(
                "304",
                vec![s("dlcappid", "300"), config(vec![s("lowviolence", "1")])],
                "34",
            ),
            children("305", vec![s("dlcappid", "300")]),
            // DLC 400 has no license; DLC 500 one through Steam Family.
            depot("401", vec![s("dlcappid", "400")], "41"),
            depot("501", vec![s("dlcappid", "500")], "51"),
        ]);
        let game = game_from(
            100,
            7,
            &kv,
            &ownership(&[101, 301, 302, 501], &[100, 300], &[500]),
            &BTreeMap::from([(300, "Extra".to_string())]),
            "english",
        )
        .unwrap();
        assert_eq!(
            game.dlc,
            vec![
                RplnetDlc {
                    app_id: 300,
                    name: "Extra".to_string(),
                    depots: vec![
                        RplnetDepotVersion {
                            depot_id: 301,
                            manifest_id: 31,
                            size: Some(1000)
                        },
                        RplnetDepotVersion {
                            depot_id: 302,
                            manifest_id: 32,
                            size: Some(1000)
                        },
                    ],
                },
                RplnetDlc {
                    app_id: 500,
                    name: "App 500".to_string(),
                    depots: vec![RplnetDepotVersion {
                        depot_id: 501,
                        manifest_id: 51,
                        size: Some(1000)
                    }],
                }
            ]
        );
        assert_eq!(
            game.depots.iter().map(|d| d.depot_id).collect::<Vec<_>>(),
            vec![101]
        );
    }

    #[test]
    fn family_shared_when_every_package_is_shared() {
        let kv = app(vec![
            depot("101", vec![], "11"),
            depot("301", vec![s("dlcappid", "300")], "31"),
            depot("401", vec![s("dlcappid", "400")], "41"),
        ]);
        let shared_only = ownership(&[101], &[400], &[100, 300]);
        let game = game_from(100, 7, &kv, &shared_only, &BTreeMap::new(), "english").unwrap();
        assert!(game.family_shared);
        // A borrowed game is inspected and downloaded like an owned one,
        // with the DLC of every license.
        assert_eq!(
            game.depots
                .iter()
                .map(|d| (d.depot_id, d.owned))
                .collect::<Vec<_>>(),
            vec![(101, true)]
        );
        assert_eq!(
            game.dlc.iter().map(|d| d.app_id).collect::<Vec<_>>(),
            vec![300, 400]
        );
        let both = ownership(&[], &[100], &[100]);
        let game = game_from(100, 7, &kv, &both, &BTreeMap::new(), "english").unwrap();
        assert!(!game.family_shared);
    }
}
