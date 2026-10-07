//! A game's store page facts (name, summary, developers, release date), from
//! the public store API, saved with an imported story so its info page works
//! offline.

use crate::error::RplnetError;
use crate::error::RplnetSteamFailure;
use serde_json::Value;

const APP_DETAILS: &str = "https://store.steampowered.com/api/appdetails";

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RplnetStoreDetails {
    pub name: String,
    /// Plain text: tags removed and entities decoded.
    pub short_description: String,
    pub developers: Vec<String>,
    pub publishers: Vec<String>,
    /// As the store writes it, in the requested language.
    pub release_date: Option<String>,
    pub header_image_url: Option<String>,
}

/// The store details of `app_id` in `language` (a Steam language code), or
/// `None` when the store has no page for it.
#[uniffi::export(async_runtime = "tokio")]
pub async fn rplnet_store_details(
    app_id: u32,
    language: String,
) -> Result<Option<RplnetStoreDetails>, RplnetError> {
    let url = reqwest::Url::parse_with_params(
        APP_DETAILS,
        &[("appids", app_id.to_string()), ("l", language)],
    )
    .map_err(|e| RplnetError::steam(RplnetSteamFailure::InvalidResponse, e))?;
    let response = crate::net::http()?
        .get(url)
        .send()
        .await?
        .error_for_status()?;
    let body: Value = response.json().await?;
    parse(app_id, &body)
}

fn parse(app_id: u32, body: &Value) -> Result<Option<RplnetStoreDetails>, RplnetError> {
    let entry = body.get(app_id.to_string()).ok_or_else(|| {
        RplnetError::steam(
            RplnetSteamFailure::InvalidResponse,
            "store reply without the app",
        )
    })?;
    if entry.get("success").and_then(Value::as_bool) != Some(true) {
        return Ok(None);
    }
    let Some(data) = entry.get("data") else {
        return Ok(None);
    };
    let text = |key: &str| data.get(key).and_then(Value::as_str).map(str::to_string);
    let list = |key: &str| {
        data.get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(Some(RplnetStoreDetails {
        name: text("name").unwrap_or_default(),
        short_description: plain_text(&text("short_description").unwrap_or_default()),
        developers: list("developers"),
        publishers: list("publishers"),
        release_date: data
            .get("release_date")
            .and_then(|date| date.get("date"))
            .and_then(Value::as_str)
            .filter(|date| !date.is_empty())
            .map(str::to_string),
        header_image_url: text("header_image"),
    }))
}

/// Store text as plain text: tags dropped, the usual entities decoded,
/// whitespace runs collapsed.
fn plain_text(html: &str) -> String {
    let mut without_tags = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                without_tags.push(' ');
            }
            _ if !in_tag => without_tags.push(c),
            _ => {}
        }
    }
    let decoded = without_tags
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&");
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_store_fields() {
        let body: Value = serde_json::from_str(
            r#"{"698780":{"success":true,"data":{
                "name":"Doki Doki Literature Club",
                "short_description":"Hi, Monika here!<br>Welcome to the &quot;Literature Club&quot; &amp; more.",
                "developers":["Team Salvato"],"publishers":["Team Salvato"],
                "release_date":{"coming_soon":false,"date":"22 Sep, 2017"},
                "header_image":"https://shared.akamai.steamstatic.com/store_item_assets/steam/apps/698780/header.jpg"}}}"#,
        )
        .unwrap();
        let details = parse(698780, &body).unwrap().unwrap();
        assert_eq!(details.name, "Doki Doki Literature Club");
        assert_eq!(
            details.short_description,
            "Hi, Monika here! Welcome to the \"Literature Club\" & more."
        );
        assert_eq!(details.developers, vec!["Team Salvato"]);
        assert_eq!(details.release_date.as_deref(), Some("22 Sep, 2017"));
    }

    #[test]
    fn no_page_is_none() {
        let body: Value = serde_json::from_str(r#"{"5":{"success":false}}"#).unwrap();
        assert_eq!(parse(5, &body).unwrap(), None);
        assert!(parse(6, &body).is_err());
    }
}
