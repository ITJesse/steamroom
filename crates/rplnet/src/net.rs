//! The HTTP client every rplnet request shares. Name resolution is the
//! system's.

use crate::error::RplnetError;
use std::sync::OnceLock;
use std::time::Duration;

/// How long to wait for a TCP connection to one address.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

pub(crate) fn http() -> Result<&'static reqwest::Client, RplnetError> {
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    steamroom::tls::ensure_crypto_provider();
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .build()?;
    Ok(CLIENT.get_or_init(|| client))
}

/// Hosts that serve Steam store images and avatars.
const IMAGE_HOSTS: &[&str] = &[
    "shared.akamai.steamstatic.com",
    "shared.fastly.steamstatic.com",
    "cdn.akamai.steamstatic.com",
    "cdn.cloudflare.steamstatic.com",
    "avatars.steamstatic.com",
    "avatars.akamai.steamstatic.com",
    "avatars.fastly.steamstatic.com",
];
/// Store images are well under a megabyte; refuse anything much larger.
const IMAGE_LIMIT: usize = 8 * 1024 * 1024;

/// Download a Steam store image or avatar (an `https` URL on a Steam image
/// host, as `owned_games` and `profile` give them).
#[uniffi::export(async_runtime = "tokio")]
pub async fn rplnet_fetch_image(url: String) -> Result<Vec<u8>, RplnetError> {
    use crate::error::RplnetSteamFailure;
    let parsed = reqwest::Url::parse(&url)
        .map_err(|_| RplnetError::steam(RplnetSteamFailure::InvalidResponse, "not an image URL"))?;
    if parsed.scheme() != "https"
        || !parsed
            .host_str()
            .is_some_and(|host| IMAGE_HOSTS.contains(&host))
    {
        return Err(RplnetError::steam(
            RplnetSteamFailure::InvalidResponse,
            "not a Steam image URL",
        ));
    }
    let response = http()?.get(parsed).send().await?.error_for_status()?;
    let bytes = response.bytes().await?;
    if bytes.len() > IMAGE_LIMIT {
        return Err(RplnetError::steam(
            RplnetSteamFailure::InvalidResponse,
            "image too large",
        ));
    }
    Ok(bytes.to_vec())
}
