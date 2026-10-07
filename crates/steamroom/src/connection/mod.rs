/// Session cipher (AES-256-CBC with HMAC-derived IV).
pub mod encryption;
/// VT01 packet framing for TCP transport.
pub mod framing;

use crate::depot::CellId;
use crate::error::Error;
use crate::generated;
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct CmServer {
    pub addr: CmServerAddr,
    pub protocol: Protocol,
}

#[derive(Clone, Debug)]
pub enum CmServerAddr {
    Resolved(SocketAddr),
    Dns { host: String, port: u16 },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Protocol {
    Tcp,
    WebSocket,
}

static DEFAULT_CM_ADDRS: &[&str] = &[
    "162.254.193.102:27017",
    "162.254.195.66:27017",
    "205.196.6.148:27017",
];

/// Port of a `cm_websocket_addresses` entry that carries none.
const DEFAULT_WEBSOCKET_PORT: u16 = 443;

impl CmServer {
    /// A few long-lived US TCP CMs, for callers that want a last resort when
    /// no other source of servers works. The library never falls back to
    /// these on its own.
    pub fn defaults() -> Vec<Self> {
        DEFAULT_CM_ADDRS
            .iter()
            .filter_map(|entry| Self::from_endpoint(entry, Protocol::Tcp))
            .collect()
    }

    /// Parse an `ip:port` or `host:port` endpoint as Steam's directory and
    /// CM list report them.
    pub fn from_endpoint(endpoint: &str, protocol: Protocol) -> Option<Self> {
        if let Ok(addr) = endpoint.parse::<SocketAddr>() {
            return Some(CmServer {
                addr: CmServerAddr::Resolved(addr),
                protocol,
            });
        }
        let (host, port) = endpoint.rsplit_once(':')?;
        Some(CmServer {
            addr: CmServerAddr::Dns {
                host: host.to_owned(),
                port: port.parse().ok()?,
            },
            protocol,
        })
    }

    /// Servers from the `CMsgClientCMList` a CM pushes after logon
    /// ([`EMsg::CLIENT_CM_LIST`](crate::messages::EMsg::CLIENT_CM_LIST)).
    /// TCP servers come first, in the order Steam listed them.
    pub fn from_cm_list(list: &generated::CMsgClientCmList) -> Vec<Self> {
        let tcp = list
            .cm_addresses
            .iter()
            .zip(&list.cm_ports)
            .filter_map(|(&ip, &port)| {
                Some(CmServer {
                    // Steam sends the IPv4 address as a big-endian integer.
                    addr: CmServerAddr::Resolved(SocketAddr::new(
                        Ipv4Addr::from(ip).into(),
                        u16::try_from(port).ok()?,
                    )),
                    protocol: Protocol::Tcp,
                })
            });
        let websocket = list.cm_websocket_addresses.iter().filter_map(|endpoint| {
            if endpoint.contains(':') {
                Self::from_endpoint(endpoint, Protocol::WebSocket)
            } else {
                Some(CmServer {
                    addr: CmServerAddr::Dns {
                        host: endpoint.clone(),
                        port: DEFAULT_WEBSOCKET_PORT,
                    },
                    protocol: Protocol::WebSocket,
                })
            }
        });
        tcp.chain(websocket).collect()
    }

    /// Ask Steam's directory Web API (`ISteamDirectory/GetCMListForConnect`)
    /// for CM servers, TCP first. The list can be empty; what to fall back to
    /// is the caller's decision.
    pub async fn fetch(http: &reqwest::Client, cell_id: CellId) -> Result<Vec<Self>, Error> {
        let url = format!(
            "https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v1/?cellid={}",
            cell_id.0
        );
        let resp: CmListResponse = http.get(url).send().await?.json().await?;
        Ok(parse_directory(resp))
    }
}

#[derive(Deserialize)]
struct CmListResponse {
    response: CmListResponseInner,
}

#[derive(Deserialize)]
struct CmListResponseInner {
    #[serde(default)]
    serverlist: Vec<CmServerEntry>,
}

#[derive(Deserialize)]
struct CmServerEntry {
    endpoint: String,
    #[serde(default)]
    r#type: String,
}

fn parse_directory(resp: CmListResponse) -> Vec<CmServer> {
    let mut servers: Vec<CmServer> = resp
        .response
        .serverlist
        .iter()
        .filter_map(|entry| {
            let protocol = match entry.r#type.as_str() {
                "netfilter" => Protocol::Tcp,
                "websockets" => Protocol::WebSocket,
                _ => return None,
            };
            CmServer::from_endpoint(&entry.endpoint, protocol)
        })
        .collect();
    // TCP needs no TLS handshake, so it is tried first.
    servers.sort_by_key(|s| match s.protocol {
        Protocol::Tcp => 0,
        Protocol::WebSocket => 1,
    });
    servers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cm_list_message_yields_tcp_then_websocket_servers() {
        let list = generated::CMsgClientCmList {
            cm_addresses: vec![u32::from(Ipv4Addr::new(103, 28, 54, 162)), 0x2d79_b824],
            cm_ports: vec![27017, 27018],
            cm_websocket_addresses: vec![
                "cmp1-hkg1.steamserver.net:443".to_string(),
                "cmp2-tyo3.steamserver.net".to_string(),
            ],
            percent_default_to_websocket: None,
        };
        let servers = CmServer::from_cm_list(&list);
        let rendered: Vec<String> = servers
            .iter()
            .map(|s| match &s.addr {
                CmServerAddr::Resolved(addr) => format!("{:?} {addr}", s.protocol),
                CmServerAddr::Dns { host, port } => format!("{:?} {host}:{port}", s.protocol),
            })
            .collect();
        assert_eq!(
            rendered,
            [
                "Tcp 103.28.54.162:27017",
                "Tcp 45.121.184.36:27018",
                "WebSocket cmp1-hkg1.steamserver.net:443",
                "WebSocket cmp2-tyo3.steamserver.net:443",
            ]
        );
    }

    #[test]
    fn cm_list_drops_unpaired_and_out_of_range_entries() {
        let list = generated::CMsgClientCmList {
            cm_addresses: vec![1, 2, 3],
            cm_ports: vec![70000, 27017],
            ..Default::default()
        };
        let servers = CmServer::from_cm_list(&list);
        assert_eq!(servers.len(), 1);
        assert!(matches!(
            servers[0].addr,
            CmServerAddr::Resolved(addr) if addr == "0.0.0.2:27017".parse().unwrap()
        ));
    }

    #[test]
    fn directory_response_keeps_known_types_tcp_first() {
        let resp: CmListResponse = serde_json::from_str(
            r#"{"response":{"serverlist":[
                {"endpoint":"cmp1-tyo3.steamserver.net:443","type":"websockets"},
                {"endpoint":"155.133.239.40:27017","type":"netfilter"},
                {"endpoint":"weird:1","type":"other"}
            ],"success":true,"message":""}}"#,
        )
        .unwrap();
        let servers = parse_directory(resp);
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].protocol, Protocol::Tcp);
        assert_eq!(servers[1].protocol, Protocol::WebSocket);
    }

    #[test]
    fn endpoint_parsing_handles_ips_hosts_and_garbage() {
        assert!(matches!(
            CmServer::from_endpoint("1.2.3.4:27017", Protocol::Tcp)
                .unwrap()
                .addr,
            CmServerAddr::Resolved(_)
        ));
        assert!(matches!(
            CmServer::from_endpoint("cm.example:443", Protocol::WebSocket)
                .unwrap()
                .addr,
            CmServerAddr::Dns { port: 443, .. }
        ));
        assert!(CmServer::from_endpoint("no-port", Protocol::Tcp).is_none());
        assert!(CmServer::from_endpoint("host:notaport", Protocol::Tcp).is_none());
    }
}
