//! Live WireGuard statistics — parse `wg show <iface> dump`.
//!
//! The dump format is tab-separated, one record per line:
//!
//! ```text
//! <private>   <public>   <listen_port>   <fwmark>                          <- interface
//! <pubkey>    <psk>      <endpoint>      <allowed_ips>   <hs>   <rx>   <tx>   <keepalive>   <- peer (repeats)
//! ```
//!
//! `wg show ... dump` is unprivileged on macOS — `wg-quick`'s kernel uapi
//! reads are what require root, and `wg` itself only queries the user-side
//! socket/handshake data.

use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::wg::WG_BIN;

/// Parsed dump for a single interface.
#[derive(Debug, Clone, Default)]
pub struct WgStats {
    pub listen_port: Option<u16>,
    pub peers: Vec<PeerStats>,
}

#[derive(Debug, Clone, Default)]
pub struct PeerStats {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    /// Unix epoch seconds of the last successful handshake. `None` when the
    /// peer has never completed a handshake (`wg` emits `0` in that case).
    pub last_handshake: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub persistent_keepalive: Option<u16>,
}

/// Runs `wg show <iface> dump` and parses the result. Returns `None` on any
/// failure (interface missing, `wg` not in PATH, parse error). Callers should
/// treat the missing case as "no stats yet" rather than an error.
pub fn query(iface: &str) -> Option<WgStats> {
    let out = Command::new(WG_BIN)
        .args(["show", iface, "dump"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Some(parse(&text))
}

/// Parses the textual dump. Public for tests.
pub fn parse(text: &str) -> WgStats {
    let mut lines = text.lines();
    let mut stats = WgStats::default();

    if let Some(iface_line) = lines.next() {
        let cols: Vec<&str> = iface_line.split('\t').collect();
        if cols.len() >= 3 {
            stats.listen_port = cols[2].parse().ok();
        }
    }

    for line in lines {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 6 {
            continue;
        }
        let public_key = cols[0].to_string();
        let endpoint = match cols[2] {
            "" | "(none)" => None,
            s => Some(s.to_string()),
        };
        let allowed_ips: Vec<String> = cols[3]
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let last_handshake = cols
            .get(4)
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&v| v > 0);
        let rx_bytes = cols.get(5).and_then(|v| v.parse().ok()).unwrap_or(0);
        let tx_bytes = cols.get(6).and_then(|v| v.parse().ok()).unwrap_or(0);
        let persistent_keepalive = cols.get(7).and_then(|v| match *v {
            "off" | "0" | "" => None,
            s => s.parse().ok(),
        });
        stats.peers.push(PeerStats {
            public_key,
            endpoint,
            allowed_ips,
            last_handshake,
            rx_bytes,
            tx_bytes,
            persistent_keepalive,
        });
    }

    stats
}

/// Human-readable "N seconds/minutes/hours ago" for a unix-epoch timestamp.
pub fn humanize_handshake(epoch: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    if epoch >= now {
        return "just now".to_string();
    }
    let delta = now - epoch;
    if delta < 60 {
        return format!("{} sec ago", delta);
    }
    if delta < 3600 {
        return format!("{} min ago", delta / 60);
    }
    if delta < 86400 {
        return format!("{} hr ago", delta / 3600);
    }
    format!("{} d ago", delta / 86400)
}

/// `1.23 KiB` / `4.56 MiB` / etc. for WireGuard transfer counters.
pub fn humanize_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    if n == 0 {
        return "0 B".to_string();
    }
    let mut v = n as f64;
    let mut idx = 0;
    while v >= 1024.0 && idx + 1 < UNITS.len() {
        v /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{} {}", n, UNITS[idx])
    } else {
        format!("{:.2} {}", v, UNITS[idx])
    }
}

/// Per-session stats cache keyed by tunnel name. Inserting a fresh snapshot
/// is O(1); the map stays small (one entry per active interface).
pub type StatsCache = HashMap<String, WgStats>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_handles_interface_only() {
        let raw = "privatekey\tpublickey\t51820\toff\n";
        let stats = parse(raw);
        assert_eq!(stats.listen_port, Some(51820));
        assert!(stats.peers.is_empty());
    }

    #[test]
    fn parse_handles_peer_with_none_endpoint() {
        let raw = "priv\tpub\t51820\toff\npeer1\t(none)\t(none)\t10.0.0.0/24\t0\t0\t0\toff\n";
        let stats = parse(raw);
        assert_eq!(stats.peers.len(), 1);
        let peer = &stats.peers[0];
        assert_eq!(peer.public_key, "peer1");
        assert!(peer.endpoint.is_none());
        assert_eq!(peer.allowed_ips, vec!["10.0.0.0/24".to_string()]);
        assert!(peer.last_handshake.is_none());
        assert_eq!(peer.rx_bytes, 0);
        assert_eq!(peer.tx_bytes, 0);
    }

    #[test]
    fn parse_peer_with_handshake_and_transfer() {
        let raw = "priv\tpub\t51820\toff\npeer1\t(none)\t1.2.3.4:51820\t10.0.0.0/24,192.168.1.0/24\t1700000000\t12345\t6789\t25\n";
        let stats = parse(raw);
        let peer = &stats.peers[0];
        assert_eq!(peer.endpoint.as_deref(), Some("1.2.3.4:51820"));
        assert_eq!(peer.allowed_ips.len(), 2);
        assert_eq!(peer.last_handshake, Some(1_700_000_000));
        assert_eq!(peer.rx_bytes, 12_345);
        assert_eq!(peer.tx_bytes, 6_789);
        assert_eq!(peer.persistent_keepalive, Some(25));
    }

    #[test]
    fn humanize_bytes_formats() {
        assert_eq!(humanize_bytes(0), "0 B");
        assert_eq!(humanize_bytes(512), "512 B");
        assert_eq!(humanize_bytes(2048), "2.00 KiB");
        assert_eq!(humanize_bytes(5 * 1024 * 1024), "5.00 MiB");
    }
}
