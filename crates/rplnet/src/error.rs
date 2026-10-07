//! Errors returned to the app, grouped by what the user can do about them:
//! the network, the account's authentication, Steam itself, or the device's
//! storage. The app maps each reason to its own message; `detail` is for logs
//! and has URLs and tokens removed.

use crate::log::redact;
use steamroom::enums::EResultError;
use steamroom::error::ConnectionError;
use steamroom_client::login::LoginError;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RplnetError {
    #[error("network ({reason:?}): {detail}")]
    Network {
        reason: RplnetNetworkFailure,
        detail: String,
    },
    #[error("authentication ({reason:?}): {detail}")]
    Auth {
        reason: RplnetAuthFailure,
        detail: String,
    },
    #[error("Steam ({reason:?}): {detail}")]
    Steam {
        reason: RplnetSteamFailure,
        detail: String,
    },
    #[error("storage ({reason:?}): {detail}")]
    Disk {
        reason: RplnetDiskFailure,
        detail: String,
    },
    /// The app cancelled the operation; nothing to show.
    #[error("cancelled")]
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RplnetNetworkFailure {
    /// No answer in time.
    Timeout,
    /// Could not connect: name resolution failed, or the server refused or
    /// could not be reached.
    Unreachable,
    /// An established connection closed.
    ConnectionLost,
    /// The TLS handshake or certificate check failed.
    Tls,
    /// The server answered with an HTTP error status.
    HttpStatus { status: u16 },
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RplnetAuthFailure {
    /// Account name or password rejected.
    InvalidCredentials,
    /// Steam Guard code rejected; the challenge can be retried.
    InvalidGuardCode,
    /// Steam asked for a confirmation method this client cannot drive.
    UnsupportedConfirmation,
    /// The saved login is no longer accepted (expired or revoked); the user
    /// has to sign in again.
    SessionExpired,
    /// Too many attempts; Steam refuses logins for a while.
    RateLimited,
    /// The pending sign-in ended: it was denied in the Steam mobile app or
    /// waited too long. Start over.
    RequestEnded,
    /// Logon refused for another reason, named by Steam's EResult.
    Rejected { eresult: String },
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RplnetSteamFailure {
    /// The account may not access this app, depot or package.
    AccessDenied,
    /// A Steam service call failed with this EResult.
    ServiceError { eresult: String },
    /// A response did not have the expected shape.
    InvalidResponse,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RplnetDiskFailure {
    NoSpace,
    PermissionDenied,
    Io,
}

impl RplnetError {
    pub(crate) fn network(reason: RplnetNetworkFailure, detail: impl std::fmt::Display) -> Self {
        Self::Network {
            reason,
            detail: redact(&detail.to_string()),
        }
    }

    pub(crate) fn auth(reason: RplnetAuthFailure, detail: impl std::fmt::Display) -> Self {
        Self::Auth {
            reason,
            detail: redact(&detail.to_string()),
        }
    }

    pub(crate) fn steam(reason: RplnetSteamFailure, detail: impl std::fmt::Display) -> Self {
        Self::Steam {
            reason,
            detail: redact(&detail.to_string()),
        }
    }

    pub(crate) fn disk(reason: RplnetDiskFailure, detail: impl std::fmt::Display) -> Self {
        Self::Disk {
            reason,
            detail: redact(&detail.to_string()),
        }
    }

    /// An I/O error on a connection (as opposed to on a file).
    fn from_socket_io(e: &std::io::Error) -> Self {
        use std::io::ErrorKind;
        let reason = match e.kind() {
            ErrorKind::TimedOut => RplnetNetworkFailure::Timeout,
            ErrorKind::ConnectionRefused
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
            | ErrorKind::AddrNotAvailable
            | ErrorKind::NotConnected => RplnetNetworkFailure::Unreachable,
            _ => RplnetNetworkFailure::ConnectionLost,
        };
        Self::network(reason, e)
    }

    fn from_logon_eresult(eresult: EResultError, detail: impl std::fmt::Display) -> Self {
        let reason = match eresult {
            EResultError::InvalidPassword => RplnetAuthFailure::InvalidCredentials,
            EResultError::Expired | EResultError::Revoked | EResultError::AccessDenied => {
                RplnetAuthFailure::SessionExpired
            }
            EResultError::RateLimitExceeded | EResultError::LoginDeniedThrottle => {
                RplnetAuthFailure::RateLimited
            }
            EResultError::TwoFactorCodeMismatch => RplnetAuthFailure::InvalidGuardCode,
            other => RplnetAuthFailure::Rejected {
                eresult: other.to_string(),
            },
        };
        Self::auth(reason, detail)
    }
}

impl From<std::io::Error> for RplnetError {
    /// File-system errors. Socket errors arrive wrapped in steamroom or
    /// reqwest errors and are mapped there.
    fn from(e: std::io::Error) -> Self {
        use std::io::ErrorKind;
        let reason = match e.kind() {
            ErrorKind::StorageFull | ErrorKind::QuotaExceeded => RplnetDiskFailure::NoSpace,
            ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem => {
                RplnetDiskFailure::PermissionDenied
            }
            _ => RplnetDiskFailure::Io,
        };
        Self::disk(reason, e)
    }
}

impl From<reqwest::Error> for RplnetError {
    fn from(e: reqwest::Error) -> Self {
        if let Some(status) = e.status() {
            return Self::network(
                RplnetNetworkFailure::HttpStatus {
                    status: status.as_u16(),
                },
                &e,
            );
        }
        let reason = if e.is_timeout() {
            RplnetNetworkFailure::Timeout
        } else if e.is_connect() {
            RplnetNetworkFailure::Unreachable
        } else {
            // The request or response body broke off after connecting.
            RplnetNetworkFailure::ConnectionLost
        };
        Self::network(reason, &e)
    }
}

impl From<ConnectionError> for RplnetError {
    fn from(e: ConnectionError) -> Self {
        match &e {
            ConnectionError::Disconnected => {
                Self::network(RplnetNetworkFailure::ConnectionLost, &e)
            }
            ConnectionError::DnsResolutionFailed => {
                Self::network(RplnetNetworkFailure::Unreachable, &e)
            }
            ConnectionError::Io(io) => Self::from_socket_io(io),
            ConnectionError::TlsConfig(_) | ConnectionError::EncryptionFailed => {
                Self::network(RplnetNetworkFailure::Tls, &e)
            }
            ConnectionError::LogonFailed(eresult) => Self::from_logon_eresult(*eresult, &e),
            ConnectionError::DepotAccessDenied(_) => {
                Self::steam(RplnetSteamFailure::AccessDenied, &e)
            }
            ConnectionError::ServiceMethodFailed(EResultError::AccessDenied) => {
                Self::steam(RplnetSteamFailure::AccessDenied, &e)
            }
            ConnectionError::ServiceMethodFailed(eresult) => Self::steam(
                RplnetSteamFailure::ServiceError {
                    eresult: eresult.to_string(),
                },
                &e,
            ),
            // Malformed or unexpected messages: UnexpectedEMsg, BadMagic,
            // PacketTooShort, MissingField, Parse, MultiTooDeep, and variants
            // added later.
            _ => Self::steam(RplnetSteamFailure::InvalidResponse, &e),
        }
    }
}

impl From<steamroom::Error> for RplnetError {
    fn from(e: steamroom::Error) -> Self {
        match e {
            steamroom::Error::Connection(c) => c.into(),
            steamroom::Error::Http(r) => r.into(),
            steamroom::Error::CdnStatus { status, .. } => Self::network(
                RplnetNetworkFailure::HttpStatus {
                    status: status.as_u16(),
                },
                format!("CDN returned HTTP {}", status.as_u16()),
            ),
            steamroom::Error::Io(io) => io.into(),
            // Decryption, decoding and parsing failures of Steam data:
            // Crypto, ProtobufDecode, Manifest, Parse, Kv, and variants added
            // later.
            other => Self::steam(RplnetSteamFailure::InvalidResponse, &other),
        }
    }
}

impl From<LoginError> for RplnetError {
    fn from(e: LoginError) -> Self {
        match e {
            LoginError::Transport(inner) => inner.into(),
            LoginError::LogonFailed(eresult) => Self::from_logon_eresult(eresult, &e),
            LoginError::InvalidPassword => Self::auth(RplnetAuthFailure::InvalidCredentials, &e),
            LoginError::InvalidGuardCode => Self::auth(RplnetAuthFailure::InvalidGuardCode, &e),
            LoginError::NoSupportedConfirmation => {
                Self::auth(RplnetAuthFailure::UnsupportedConfirmation, &e)
            }
            LoginError::NoCmServers => Self::network(RplnetNetworkFailure::Unreachable, &e),
            // MissingField, and variants added later.
            other => Self::steam(RplnetSteamFailure::InvalidResponse, &other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason_of(e: RplnetError) -> String {
        match e {
            RplnetError::Network { reason, .. } => format!("network {reason:?}"),
            RplnetError::Auth { reason, .. } => format!("auth {reason:?}"),
            RplnetError::Steam { reason, .. } => format!("steam {reason:?}"),
            RplnetError::Disk { reason, .. } => format!("disk {reason:?}"),
            RplnetError::Cancelled => "cancelled".to_string(),
        }
    }

    #[test]
    fn connection_errors_map_to_network_reasons() {
        let cases = [
            (ConnectionError::Disconnected, "network ConnectionLost"),
            (ConnectionError::DnsResolutionFailed, "network Unreachable"),
            (
                ConnectionError::Io(std::io::ErrorKind::TimedOut.into()),
                "network Timeout",
            ),
            (
                ConnectionError::Io(std::io::ErrorKind::ConnectionRefused.into()),
                "network Unreachable",
            ),
            (
                ConnectionError::Io(std::io::ErrorKind::ConnectionReset.into()),
                "network ConnectionLost",
            ),
            (ConnectionError::EncryptionFailed, "network Tls"),
        ];
        for (error, expected) in cases {
            assert_eq!(reason_of(error.into()), expected);
        }
    }

    #[test]
    fn logon_eresults_map_to_auth_reasons() {
        let cases = [
            (EResultError::InvalidPassword, "auth InvalidCredentials"),
            (EResultError::Expired, "auth SessionExpired"),
            (EResultError::Revoked, "auth SessionExpired"),
            (EResultError::AccessDenied, "auth SessionExpired"),
            (EResultError::RateLimitExceeded, "auth RateLimited"),
            (EResultError::LoginDeniedThrottle, "auth RateLimited"),
            (
                EResultError::Banned,
                "auth Rejected { eresult: \"Banned\" }",
            ),
        ];
        for (eresult, expected) in cases {
            assert_eq!(
                reason_of(ConnectionError::LogonFailed(eresult).into()),
                expected
            );
            assert_eq!(reason_of(LoginError::LogonFailed(eresult).into()), expected);
        }
    }

    #[test]
    fn login_flow_errors_keep_their_meaning() {
        assert_eq!(
            reason_of(LoginError::InvalidPassword.into()),
            "auth InvalidCredentials"
        );
        assert_eq!(
            reason_of(LoginError::InvalidGuardCode.into()),
            "auth InvalidGuardCode"
        );
        assert_eq!(
            reason_of(LoginError::NoSupportedConfirmation.into()),
            "auth UnsupportedConfirmation"
        );
        assert_eq!(
            reason_of(LoginError::NoCmServers.into()),
            "network Unreachable"
        );
        assert_eq!(
            reason_of(LoginError::Transport(ConnectionError::Disconnected.into()).into()),
            "network ConnectionLost"
        );
    }

    #[test]
    fn steam_service_errors_keep_the_eresult() {
        assert_eq!(
            reason_of(ConnectionError::DepotAccessDenied(42).into()),
            "steam AccessDenied"
        );
        assert_eq!(
            reason_of(ConnectionError::ServiceMethodFailed(EResultError::AccessDenied).into()),
            "steam AccessDenied"
        );
        assert_eq!(
            reason_of(ConnectionError::ServiceMethodFailed(EResultError::Busy).into()),
            "steam ServiceError { eresult: \"Busy\" }"
        );
        assert_eq!(
            reason_of(ConnectionError::MissingField("eresult").into()),
            "steam InvalidResponse"
        );
    }

    #[test]
    fn file_errors_map_to_disk_reasons() {
        assert_eq!(
            reason_of(std::io::Error::from(std::io::ErrorKind::StorageFull).into()),
            "disk NoSpace"
        );
        assert_eq!(
            reason_of(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into()),
            "disk PermissionDenied"
        );
        assert_eq!(
            reason_of(std::io::Error::from(std::io::ErrorKind::NotFound).into()),
            "disk Io"
        );
    }

    #[test]
    fn cdn_status_is_an_http_status() {
        let e = steamroom::Error::CdnStatus {
            status: reqwest::StatusCode::FORBIDDEN,
            retry_after: None,
        };
        assert_eq!(reason_of(e.into()), "network HttpStatus { status: 403 }");
    }

    #[tokio::test]
    async fn refused_http_connection_is_unreachable() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let client = steamroom::http::client().unwrap();
        let e = client
            .get(format!("http://127.0.0.1:{port}/path?token=secret"))
            .send()
            .await
            .unwrap_err();
        let RplnetError::Network { reason, detail } = e.into() else {
            panic!("expected a network error");
        };
        assert_eq!(reason, RplnetNetworkFailure::Unreachable);
        assert!(
            !detail.contains("secret"),
            "detail leaks the query: {detail}"
        );
    }
}
