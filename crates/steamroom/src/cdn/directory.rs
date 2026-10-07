//! Content server directory (`ContentServerDirectory.GetServersForSteamPipe`).

use super::server::CdnServer;
use crate::depot::AppId;
use crate::depot::CellId;
use crate::generated::CContentServerDirectoryServerInfo;
use std::net::IpAddr;

/// Where Steam should consider the client to be when it picks content
/// servers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentServerLocation {
    /// Steam's own placement, from the address the CM connection comes from.
    Automatic,
    /// A Steam cell id. Steam ignores it on its own (the answer follows the
    /// connection's address); it is only honoured next to an IP override.
    Cell(CellId),
    /// Place the client as if it connected from this address. No cell id is
    /// sent with it: Steam would apply the cell on top of the override and
    /// skew the answer toward that cell.
    IpOverride(IpAddr),
}

/// `https_support` of a content server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpsSupport {
    Mandatory,
    Optional,
    Unavailable,
    /// A value this crate does not know, kept verbatim.
    Other(String),
}

impl HttpsSupport {
    fn from_wire(value: &str) -> Self {
        match value {
            "mandatory" => Self::Mandatory,
            "optional" => Self::Optional,
            "unavailable" => Self::Unavailable,
            other => Self::Other(other.to_string()),
        }
    }

    /// Whether requests to the server can use HTTPS.
    pub fn allows_https(&self) -> bool {
        matches!(self, Self::Mandatory | Self::Optional)
    }
}

/// One entry of the content server directory, with every field Steam sends.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ContentServer {
    /// `CDN`, `SteamCache`, `OpenCache`, ...
    pub server_type: Option<String>,
    pub source_id: Option<i32>,
    pub cell_id: Option<i32>,
    pub load: Option<i32>,
    pub weighted_load: Option<f32>,
    pub num_entries_in_client_list: Option<i32>,
    pub steam_china_only: bool,
    /// Host name without the port.
    pub host: String,
    /// Port given in the directory's `host` field, if any.
    pub port: Option<u16>,
    pub vhost: Option<String>,
    pub use_as_proxy: bool,
    pub proxy_request_path_template: Option<String>,
    pub https_support: Option<HttpsSupport>,
    /// Apps the server may serve; empty means any app.
    pub allowed_app_ids: Vec<AppId>,
    pub priority_class: Option<u32>,
}

impl ContentServer {
    /// `None` for an entry without a host, or whose host carries a port that
    /// is not a number.
    pub(crate) fn from_proto(info: &CContentServerDirectoryServerInfo) -> Option<Self> {
        let raw_host = info.host.as_deref()?;
        let (host, port) = match raw_host.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), Some(port.parse().ok()?)),
            None => (raw_host.to_string(), None),
        };
        Some(Self {
            server_type: info.r#type.clone(),
            source_id: info.source_id,
            cell_id: info.cell_id,
            load: info.load,
            weighted_load: info.weighted_load,
            num_entries_in_client_list: info.num_entries_in_client_list,
            // proto2 defaults: an absent flag is false.
            steam_china_only: info.steam_china_only.unwrap_or(false),
            host,
            port,
            vhost: info.vhost.clone(),
            use_as_proxy: info.use_as_proxy.unwrap_or(false),
            proxy_request_path_template: info.proxy_request_path_template.clone(),
            https_support: info.https_support.as_deref().map(HttpsSupport::from_wire),
            allowed_app_ids: info.allowed_app_ids.iter().copied().map(AppId).collect(),
            priority_class: info.priority_class,
        })
    }

    /// The server as a download target. `https` selects the scheme; the
    /// directory's port is kept, otherwise the scheme's default port is used.
    /// The Host header is the directory's `vhost`, or the host itself.
    pub fn to_cdn_server(&self, https: bool) -> CdnServer {
        CdnServer::new(
            self.host.clone(),
            self.port.unwrap_or(if https { 443 } else { 80 }),
            https,
            self.vhost.clone().unwrap_or_else(|| self.host.clone()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_field_is_carried_over() {
        let info = CContentServerDirectoryServerInfo {
            r#type: Some("CDN".into()),
            source_id: Some(33),
            cell_id: Some(0),
            load: Some(50),
            weighted_load: Some(50.0),
            num_entries_in_client_list: Some(2),
            steam_china_only: Some(true),
            host: Some("xz.pphimalayanrt.com".into()),
            vhost: Some("xz.pphimalayanrt.com".into()),
            use_as_proxy: Some(false),
            proxy_request_path_template: None,
            https_support: Some("unavailable".into()),
            allowed_app_ids: vec![10, 20],
            priority_class: Some(8),
            bypass_proxies_of_type: vec![],
        };
        let server = ContentServer::from_proto(&info).unwrap();
        assert_eq!(server.server_type.as_deref(), Some("CDN"));
        assert_eq!(server.source_id, Some(33));
        assert!(server.steam_china_only);
        assert_eq!(server.https_support, Some(HttpsSupport::Unavailable));
        assert_eq!(server.allowed_app_ids, [AppId(10), AppId(20)]);
        assert_eq!(server.priority_class, Some(8));
        let target = server.to_cdn_server(false);
        assert_eq!(
            target.build_url("/x", None),
            "http://xz.pphimalayanrt.com:80/x"
        );
    }

    #[test]
    fn host_port_and_missing_vhost() {
        let info = CContentServerDirectoryServerInfo {
            host: Some("cache1-tyo3.steamcontent.com:8443".into()),
            https_support: Some("mandatory".into()),
            ..Default::default()
        };
        let server = ContentServer::from_proto(&info).unwrap();
        assert_eq!(server.port, Some(8443));
        let target = server.to_cdn_server(true);
        assert_eq!(target.port, 8443);
        assert_eq!(target.vhost, "cache1-tyo3.steamcontent.com");
        assert!(server.https_support.unwrap().allows_https());
    }

    #[test]
    fn entries_without_a_usable_host_are_rejected() {
        assert!(ContentServer::from_proto(&CContentServerDirectoryServerInfo::default()).is_none());
        let info = CContentServerDirectoryServerInfo {
            host: Some("host:port".into()),
            ..Default::default()
        };
        assert!(ContentServer::from_proto(&info).is_none());
    }
}
