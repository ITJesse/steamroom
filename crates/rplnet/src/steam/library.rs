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
    /// Every license for it belongs to another account (Steam Family); its
    /// content cannot be downloaded with this account.
    pub family_shared: bool,
    /// Tagged "Visual Novel" on the store.
    pub visual_novel: bool,
    /// The store's header image (460×215), in the requested language when
    /// there is one.
    pub header_image_url: Option<String>,
    /// Depots worth inspecting, best first (plan 6.5).
    pub depots: Vec<RplnetDepotCandidate>,
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
    let account_id = client.steam_id().raw() as u32;
    let started = std::time::Instant::now();

    // Packages → the apps and depots they grant.
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
    let packages: Vec<_> = futures::stream::iter(batches(&package_tokens, PACKAGES_PER_REQUEST))
        .map(|batch| async move { client.pics_get_package_info(&batch).await })
        .buffer_unordered(REQUESTS_IN_FLIGHT)
        .try_collect::<Vec<_>>()
        .await?
        .into_iter()
        .flatten()
        .collect();
    let mut app_packages: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    let mut owned_depots = BTreeSet::new();
    for package in &packages {
        let Some(package_id) = package.package_id else {
            continue;
        };
        let Ok(kv) = package.key_values() else {
            continue;
        };
        for depot in numbers(kv.get("depotids")) {
            owned_depots.insert(depot as u32);
        }
        for app in numbers(kv.get("appids")) {
            app_packages
                .entry(app as u32)
                .or_default()
                .push(package_id.0);
        }
    }
    // Apps granted by owned packages, including DLC: a DLC depot counts when
    // its DLC is among them.
    let owned_apps: BTreeSet<u32> = app_packages.keys().copied().collect();

    // App access tokens, then app info.
    let app_ids: Vec<AppId> = owned_apps.iter().copied().map(AppId).collect();
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
    let infos: Vec<AppInfo> = futures::stream::iter(batches(&requests, APPS_PER_REQUEST))
        .map(|batch| async move { client.pics_get_product_info(&batch).await })
        .buffer_unordered(REQUESTS_IN_FLIGHT)
        .try_collect::<Vec<_>>()
        .await?
        .into_iter()
        .flatten()
        .collect();

    let mut games = Vec::new();
    for info in &infos {
        let Some(app_id) = info.app_id else {
            continue;
        };
        let Ok(kv) = info.key_values() else {
            continue;
        };
        let packages = app_packages
            .get(&app_id.0)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if let Some(game) = game_from(
            app_id.0,
            info.change_number.unwrap_or(0),
            &kv,
            packages,
            &shared_packages,
            &owned_depots,
            &owned_apps,
            language,
        ) {
            games.push(game);
        }
    }
    info!(
        "library: {} licenses, {} packages, {} apps, {} games in {} ms",
        licenses.len(),
        packages.len(),
        infos.len(),
        games.len(),
        started.elapsed().as_millis()
    );
    Ok(games)
}

/// The game described by an app's PICS info, or `None` for anything but a
/// game (DLC, tools, demos, applications, …).
#[allow(clippy::too_many_arguments)]
fn game_from(
    app_id: u32,
    change_number: u32,
    kv: &KeyValue,
    packages: &[u32],
    shared_packages: &BTreeSet<u32>,
    owned_depots: &BTreeSet<u32>,
    owned_apps: &BTreeSet<u32>,
    language: &str,
) -> Option<RplnetOwnedGame> {
    let common = kv.get("common")?;
    if !text(common.get("type"))?.eq_ignore_ascii_case("game") {
        return None;
    }
    let name = localized(common.get("name_localized"), language)
        .or_else(|| text(common.get("name")))
        .unwrap_or_else(|| format!("App {app_id}"));
    let header_image_url = localized(common.get("header_image"), language)
        .or_else(|| localized(common.get("header_image"), "english"))
        .map(|file| format!("{STORE_ASSETS}/{app_id}/{file}"));
    Some(RplnetOwnedGame {
        app_id,
        name,
        change_number,
        family_shared: !packages.is_empty()
            && packages
                .iter()
                .all(|package| shared_packages.contains(package)),
        visual_novel: numbers(common.get("store_tags")).any(|tag| tag == VISUAL_NOVEL_TAG),
        header_image_url,
        depots: rank_depots(kv.get("depots"), owned_depots, owned_apps),
    })
}

/// Depots that may hold the game, best first (plan 6.5): depots of owned
/// packages before the rest; then no `oslist` (every platform), Linux,
/// Windows, macOS; then no `language` before a language. Depots shared from
/// another app or installed shared (redistributables), low-violence variants,
/// DLC depots of DLC the account does not own, and depots without a public
/// manifest are left out.
fn rank_depots(
    depots: Option<&KeyValue>,
    owned_depots: &BTreeSet<u32>,
    owned_apps: &BTreeSet<u32>,
) -> Vec<RplnetDepotCandidate> {
    let Some(KvValue::Children(depots)) = depots.map(|d| &d.value) else {
        return Vec::new();
    };
    let mut ranked: Vec<(u32, RplnetDepotCandidate)> = depots
        .iter()
        .filter_map(|(key, depot)| {
            let depot_id: u32 = key.parse().ok()?;
            if depot.get("depotfromapp").is_some() || flag(depot.get("sharedinstall")) {
                return None;
            }
            let config = depot.get("config");
            if flag(config.and_then(|c| c.get("lowviolence"))) {
                return None;
            }
            if let Some(dlc) = number(depot.get("dlcappid"))
                && !owned_apps.contains(&(dlc as u32))
            {
                return None;
            }
            let public = depot.get("manifests").and_then(|m| m.get("public"))?;
            // Newer PICS nests the id as `public/gid`; older has it as the value.
            let manifest_id = number(public.get("gid")).or_else(|| number(Some(public)))?;
            let size = number(public.get("size")).or_else(|| number(depot.get("maxsize")));
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

    fn game(
        kv: &KeyValue,
        owned_depots: &[u32],
        owned_apps: &[u32],
        language: &str,
    ) -> RplnetOwnedGame {
        game_from(
            100,
            7,
            kv,
            &[1],
            &BTreeSet::new(),
            &owned_depots.iter().copied().collect(),
            &owned_apps.iter().copied().collect(),
            language,
        )
        .unwrap()
    }

    #[test]
    fn names_and_images_follow_the_language() {
        let kv = app(vec![]);
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
                &[],
                &BTreeSet::new(),
                &BTreeSet::new(),
                &BTreeSet::new(),
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
        let ids: Vec<u32> = game(
            &kv,
            &[101, 102, 103, 104, 105, 109, 110],
            &[100, 300],
            "english",
        )
        .depots
        .iter()
        .map(|d| d.depot_id)
        .collect();
        // 106 is not in an owned package; 109's DLC is not owned.
        assert_eq!(ids, vec![103, 110, 104, 101, 102, 105, 106]);
    }

    #[test]
    fn family_shared_when_every_package_is_shared() {
        let kv = app(vec![]);
        let shared: BTreeSet<u32> = [1].into();
        let game = game_from(
            100,
            7,
            &kv,
            &[1],
            &shared,
            &BTreeSet::new(),
            &BTreeSet::new(),
            "english",
        )
        .unwrap();
        assert!(game.family_shared);
        let game = game_from(
            100,
            7,
            &kv,
            &[1, 2],
            &shared,
            &BTreeSet::new(),
            &BTreeSet::new(),
            "english",
        )
        .unwrap();
        assert!(!game.family_shared);
    }
}
