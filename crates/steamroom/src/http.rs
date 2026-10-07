//! HTTP client construction.

use crate::error::Error;

/// A `reqwest::Client` with the crate's rustls provider installed. Callers
/// that need their own settings (timeouts, proxies, connection pooling shared
/// with the rest of an application) can build one themselves after
/// [`ensure_crypto_provider`](crate::tls::ensure_crypto_provider) and pass it
/// wherever this crate takes a client.
pub fn client() -> Result<reqwest::Client, Error> {
    crate::tls::ensure_crypto_provider();
    reqwest::Client::builder().build().map_err(Error::Http)
}
