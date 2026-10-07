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
