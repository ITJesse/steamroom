//! Steam accounts: finding a CM, signing in, and the logged-in session.

pub mod auth;
mod cm;
pub mod content;
pub mod download;
pub mod library;
mod renpy;
pub mod session;
pub mod store;
pub mod token;
pub mod update;

/// Settings the app supplies for every Steam connection.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RplnetConnectOptions {
    /// Name Steam shows for this device in the account's authorized devices.
    pub device_name: String,
    /// Tells this connection apart from the account's other sessions. A logon
    /// that repeats the id of a live session replaces that session, so two
    /// connections of one account must use different ids.
    pub login_id: u32,
}

/// What the app keeps to log the account in again: the refresh token goes to
/// the keychain, never to logs.
#[derive(Clone, uniffi::Record)]
pub struct RplnetCredential {
    /// SteamID64.
    pub steam_id: u64,
    /// The name the account signs in with (not the display name).
    pub account_name: String,
    pub refresh_token: String,
    /// Expiry of `refresh_token` in seconds since 1970, when readable.
    pub expires_at: Option<i64>,
}

impl RplnetCredential {
    pub(crate) fn new(steam_id: u64, account_name: String, refresh_token: String) -> Self {
        let expires_at = token::expiry(&refresh_token);
        Self {
            steam_id,
            account_name,
            refresh_token,
            expires_at,
        }
    }
}

impl std::fmt::Debug for RplnetCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RplnetCredential")
            .field("steam_id", &self.steam_id)
            .field("account_name", &self.account_name)
            .field("refresh_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[cfg(test)]
mod tests;
