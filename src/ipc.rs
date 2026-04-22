//! Wire format between splitwg (host, user) and splitwg-helper (root, per tunnel).
//!
//! One JSON object per line over stdin/stdout. The host resolves DNS, parses
//! the `.conf`, and hands the helper an already-distilled payload; the helper
//! owns the utun device, UDP socket, and routing/DNS side-effects.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Host → helper control messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Command {
    Up(Box<UpParams>),
    Shutdown,
}

/// Helper → host notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Event {
    Ready { iface: String },
    Error { message: String },
    Handshake { peer: String, at: String },
    Stats { tx_bytes: u64, rx_bytes: u64 },
}

/// Rule application mode — mirrors `config::Rules::mode` but strongly typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelMode {
    /// No split — route whatever the peer's AllowedIPs say.
    Full,
    /// Include: AllowedIPs was already rewritten on host; helper applies as-is.
    Include,
    /// Exclude: tunnel carries default; listed CIDRs are bypassed via gateway.
    Exclude,
}

#[derive(Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TransportConfig {
    #[default]
    Direct,
    WebSocket {
        relay_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_urls: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sni_override: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        headers: Option<HashMap<String, String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_token: Option<String>,
    },
}

impl std::fmt::Debug for TransportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "Direct"),
            Self::WebSocket {
                relay_url,
                relay_urls,
                sni_override,
                path,
                headers,
                auth_token,
            } => f
                .debug_struct("WebSocket")
                .field("relay_url", relay_url)
                .field("relay_urls", relay_urls)
                .field("sni_override", sni_override)
                .field("path", path)
                .field("headers", headers)
                .field("auth_token", &auth_token.as_ref().map(|_| "[REDACTED]"))
                .finish(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpParams {
    pub tunnel: String,

    /// Base64-encoded 32-byte Curve25519 static secret (our side).
    pub interface_key: String,
    /// Base64-encoded 32-byte Curve25519 peer public key.
    pub peer_key: String,
    /// Optional base64-encoded 32-byte preshared key.
    pub psk: Option<String>,

    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<String>,
    pub addresses: Vec<String>,
    pub dns: Vec<IpAddr>,

    #[serde(default = "default_mtu")]
    pub mtu: u16,
    pub keepalive: Option<u16>,

    pub mode: TunnelMode,
    /// Exclude mode: CIDRs to bypass via `gateway`. Resolved on host.
    #[serde(default)]
    pub exclude_entries: Vec<String>,
    /// Default gateway captured before the tunnel perturbs routing.
    pub gateway: Option<IpAddr>,

    /// wg-quick-compatible hook commands, forwarded verbatim from the `.conf`.
    /// The helper executes each via `sh -c` as root. Hosts only populate these
    /// when `Settings::hooks_enabled` is true; otherwise all four stay empty.
    /// `%i` in the string is substituted with the interface name at runtime.
    #[serde(default)]
    pub pre_up: Vec<String>,
    #[serde(default)]
    pub post_up: Vec<String>,
    #[serde(default)]
    pub pre_down: Vec<String>,
    #[serde(default)]
    pub post_down: Vec<String>,

    /// Install a pf anchor that blocks all non-tunnel IPv4+IPv6 egress for
    /// the lifetime of the helper. Defaults to `false` so existing clients
    /// that don't emit the field stay unaffected.
    #[serde(default)]
    pub kill_switch: bool,

    #[serde(default)]
    pub transport: TransportConfig,
}

impl std::fmt::Debug for UpParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpParams")
            .field("tunnel", &self.tunnel)
            .field("interface_key", &"[REDACTED]")
            .field("peer_key", &self.peer_key)
            .field("psk", &self.psk.as_ref().map(|_| "[REDACTED]"))
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .field("addresses", &self.addresses)
            .field("dns", &self.dns)
            .field("mtu", &self.mtu)
            .field("keepalive", &self.keepalive)
            .field("mode", &self.mode)
            .field("kill_switch", &self.kill_switch)
            .field("transport", &self.transport)
            .finish()
    }
}

fn default_mtu() -> u16 {
    1420
}

/// Decode a base64 32-byte key shared across IPC.
pub fn decode_key(s: &str) -> Result<[u8; 32], String> {
    use base64::prelude::{Engine, BASE64_STANDARD};
    let bytes = BASE64_STANDARD
        .decode(s.trim())
        .map_err(|e| format!("invalid base64: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Encode a 32-byte key to base64 for IPC transmission.
pub fn encode_key(k: &[u8; 32]) -> String {
    use base64::prelude::{Engine, BASE64_STANDARD};
    BASE64_STANDARD.encode(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "QNpAjV5E06MPqKfN0u3VHYnM3LqHG/U0xk4BCQKYJHg=";
    const PEER: &str = "RmVhbjA3ykCFtABhxzrL7B5dMRv61i3+4RmmQhR0USM=";

    #[test]
    fn up_command_roundtrip() {
        let cmd = Command::Up(Box::new(UpParams {
            tunnel: "work".into(),
            interface_key: KEY.into(),
            peer_key: PEER.into(),
            psk: None,
            endpoint: "1.2.3.4:51820".parse().unwrap(),
            allowed_ips: vec!["0.0.0.0/0".into()],
            addresses: vec!["10.0.0.2/32".into()],
            dns: vec!["1.1.1.1".parse().unwrap()],
            mtu: 1420,
            keepalive: Some(25),
            mode: TunnelMode::Exclude,
            exclude_entries: vec!["10.0.0.0/24".into()],
            gateway: Some("192.168.1.1".parse().unwrap()),
            pre_up: vec![],
            post_up: vec![],
            pre_down: vec![],
            post_down: vec![],
            kill_switch: false,
            transport: TransportConfig::Direct,
        }));
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"up\""));
        assert!(json.contains("\"tunnel\":\"work\""));
        let back: Command = serde_json::from_str(&json).unwrap();
        match back {
            Command::Up(p) => {
                assert_eq!(p.tunnel, "work");
                assert_eq!(p.mode, TunnelMode::Exclude);
                assert_eq!(p.mtu, 1420);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn shutdown_command_roundtrip() {
        let json = serde_json::to_string(&Command::Shutdown).unwrap();
        assert_eq!(json, "{\"type\":\"shutdown\"}");
        let back: Command = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Command::Shutdown));
    }

    #[test]
    fn ready_event_roundtrip() {
        let ev = Event::Ready {
            iface: "utun4".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"type\":\"ready\""));
        assert!(json.contains("\"iface\":\"utun4\""));
        let back: Event = serde_json::from_str(&json).unwrap();
        match back {
            Event::Ready { iface } => assert_eq!(iface, "utun4"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn error_event_roundtrip() {
        let ev = Event::Error {
            message: "boom".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"type\":\"error\""));
    }

    #[test]
    fn mode_serialises_lowercase() {
        assert_eq!(
            serde_json::to_string(&TunnelMode::Include).unwrap(),
            "\"include\""
        );
        assert_eq!(
            serde_json::to_string(&TunnelMode::Exclude).unwrap(),
            "\"exclude\""
        );
        assert_eq!(
            serde_json::to_string(&TunnelMode::Full).unwrap(),
            "\"full\""
        );
    }

    #[test]
    fn mtu_default_when_absent() {
        let body = format!(
            r#"{{"type":"up","tunnel":"w","interface_key":"{KEY}","peer_key":"{PEER}",
                "endpoint":"1.2.3.4:51820","allowed_ips":[],"addresses":[],"dns":[],
                "keepalive":null,"mode":"full","gateway":null,"psk":null}}"#
        );
        let cmd: Command = serde_json::from_str(&body).unwrap();
        match cmd {
            Command::Up(p) => assert_eq!(p.mtu, 1420),
            _ => panic!(),
        }
    }

    #[test]
    fn decode_key_roundtrip() {
        let raw = [7u8; 32];
        let encoded = encode_key(&raw);
        assert_eq!(decode_key(&encoded).unwrap(), raw);
    }

    #[test]
    fn decode_key_rejects_short_input() {
        assert!(decode_key("AAAA").is_err());
    }

    #[test]
    fn websocket_transport_roundtrip() {
        let cmd = Command::Up(Box::new(UpParams {
            tunnel: "obfs".into(),
            interface_key: KEY.into(),
            peer_key: PEER.into(),
            psk: None,
            endpoint: "1.2.3.4:51820".parse().unwrap(),
            allowed_ips: vec!["0.0.0.0/0".into()],
            addresses: vec!["10.0.0.2/32".into()],
            dns: vec![],
            mtu: 1420,
            keepalive: None,
            mode: TunnelMode::Full,
            exclude_entries: vec![],
            gateway: None,
            pre_up: vec![],
            post_up: vec![],
            pre_down: vec![],
            post_down: vec![],
            kill_switch: false,
            transport: TransportConfig::WebSocket {
                relay_url: "wss://relay.example.com/wg".into(),
                relay_urls: None,
                sni_override: Some("cover.example.com".into()),
                path: None,
                headers: None,
                auth_token: Some("secret-token".into()),
            },
        }));
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"websocket\""));
        assert!(json.contains("relay.example.com"));
        let back: Command = serde_json::from_str(&json).unwrap();
        match back {
            Command::Up(p) => match &p.transport {
                TransportConfig::WebSocket {
                    relay_url,
                    sni_override,
                    auth_token,
                    ..
                } => {
                    assert_eq!(relay_url, "wss://relay.example.com/wg");
                    assert_eq!(sni_override.as_deref(), Some("cover.example.com"));
                    assert_eq!(auth_token.as_deref(), Some("secret-token"));
                }
                _ => panic!("expected WebSocket transport"),
            },
            _ => panic!("expected Up command"),
        }
    }

    #[test]
    fn transport_defaults_to_direct_when_absent() {
        let json = format!(
            r#"{{"type":"up","tunnel":"t","interface_key":"{}","peer_key":"{}","endpoint":"1.2.3.4:51820","allowed_ips":[],"addresses":[],"dns":[],"mode":"full"}}"#,
            KEY, PEER
        );
        let cmd: Command = serde_json::from_str(&json).unwrap();
        match cmd {
            Command::Up(p) => assert_eq!(p.transport, TransportConfig::Direct),
            _ => panic!("expected Up command"),
        }
    }
}
