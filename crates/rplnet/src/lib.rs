//! RenPyLinter's Steam layer. Everything the iOS app calls is exported through
//! UniFFI; `build-xcframework.zsh` packages the static library, the C header
//! and the generated Swift file.
//!
//! The generated Swift is compiled into the app's own module, so every
//! exported type is prefixed `Rplnet` and every exported function `rplnet_`
//! to stay clear of the app's names (the app has its own `LogLevel`).

pub mod error;
pub mod log;

uniffi::setup_scaffolding!();

/// Build identity of the library the app is running.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RplnetVersion {
    /// `rplnet` crate version.
    pub version: String,
    /// Commit of the `ITJesse/steamroom` tree it was built from, set by the
    /// release build; absent in a local build that did not set it.
    pub source_commit: Option<String>,
    /// Rust target triple, e.g. `aarch64-apple-ios`.
    pub target: String,
}

#[uniffi::export]
pub fn rplnet_version() -> RplnetVersion {
    RplnetVersion {
        version: env!("CARGO_PKG_VERSION").to_string(),
        source_commit: option_env!("RPLNET_SOURCE_COMMIT").map(str::to_string),
        target: env!("RPLNET_TARGET").to_string(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_reports_the_crate_and_target() {
        let version = super::rplnet_version();
        assert_eq!(version.version, env!("CARGO_PKG_VERSION"));
        assert!(!version.target.is_empty());
    }
}
