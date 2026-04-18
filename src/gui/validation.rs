//! Routing-rule entry validation.
//!
//! Moved from the old AppleScript rules editor. The rules themselves are
//! still strings in `Rules::entries`; this module is a central place to
//! answer "is this entry well-formed?" and to classify it for the UI.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::config::Rules;
use crate::wg::conf::WgConfig;

/// Canonical classification of a rule entry. The UI shows a small coloured
/// badge so the user can tell at a glance whether a row is IP, CIDR, a
/// domain, or a wildcard domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Ip,
    Cidr,
    Domain,
    Wildcard,
    /// `country:XX` — resolved at runtime via MaxMind GeoLite2-Country.
    /// `XX` is a two-letter ISO 3166-1 alpha-2 code.
    Geo,
    Invalid,
}

/// Returns true when `s` is a plausible routing rule.
pub fn is_valid_entry(s: &str) -> bool {
    !matches!(classify(s), EntryKind::Invalid)
}

/// Classifies a trimmed entry. Whitespace-only / empty / unparseable inputs
/// return `EntryKind::Invalid`.
pub fn classify(s: &str) -> EntryKind {
    let s = s.trim();
    if s.is_empty() || s.chars().any(|c| c == ' ' || c == '\t') {
        return EntryKind::Invalid;
    }
    if let Some(code) = s.strip_prefix("country:") {
        if code.len() == 2 && code.chars().all(|c| c.is_ascii_alphabetic()) {
            return EntryKind::Geo;
        }
        return EntryKind::Invalid;
    }
    if parse_cidr(s) {
        return EntryKind::Cidr;
    }
    if s.parse::<std::net::IpAddr>().is_ok() {
        return EntryKind::Ip;
    }
    if let Some(rest) = s.strip_prefix("*.") {
        if is_valid_domain(rest) {
            return EntryKind::Wildcard;
        }
        return EntryKind::Invalid;
    }
    if is_valid_domain(s) {
        return EntryKind::Domain;
    }
    EntryKind::Invalid
}

pub fn parse_cidr(s: &str) -> bool {
    let Some((addr, prefix)) = s.split_once('/') else {
        return false;
    };
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(p) = prefix.parse::<u8>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(_) => p <= 32,
        std::net::IpAddr::V6(_) => p <= 128,
    }
}

/// Matches a hostname/domain made of dot-separated alphanumeric labels.
static DOMAIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$",
    )
    .unwrap()
});

pub fn is_valid_domain(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && DOMAIN_RE.is_match(s)
}

/// Informational warnings flagged against an imported `.conf` file.
/// Non-blocking — the Save button stays enabled. Only a failed `conf::parse`
/// (syntactic errors or missing mandatory keys) prevents import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigWarning {
    /// `[Interface] DNS = …` is empty. System DNS leaks out of the tunnel.
    NoDns,
    /// `Rules.mode = include` while a peer advertises `AllowedIPs` that
    /// contains `0.0.0.0/0` or `::/0`. The include-list will override the
    /// catch-all and route nothing through the tunnel.
    IncludeWithCatchAll,
    /// `Interface.MTU` below the WireGuard safe minimum (1280).
    LowMtu,
    /// `Interface.MTU` above standard Ethernet MTU (1500).
    HighMtu,
    /// First peer has no `PersistentKeepalive`. NAT traversal may break
    /// after a few minutes of idle traffic.
    NoKeepalive,
    /// Config declares more than one `[Peer]`. The helper uses the first
    /// peer only; the rest are silently ignored.
    MultiplePeers,
    /// `[Interface] Address` contains no IPv4 CIDR. IPv4 traffic cannot
    /// egress the tunnel.
    NoIpv4Address,
}

/// Validates a parsed WireGuard config. Pass `rules = None` at import time
/// (before any rule file exists); pass `Some(&rules)` to include the
/// include/exclude interaction check.
pub fn validate_wg_config(cfg: &WgConfig, rules: Option<&Rules>) -> Vec<ConfigWarning> {
    let mut out = Vec::new();

    if cfg.interface.dns.is_empty() {
        out.push(ConfigWarning::NoDns);
    }

    if let Some(mtu) = cfg.interface.mtu {
        if mtu < 1280 {
            out.push(ConfigWarning::LowMtu);
        } else if mtu > 1500 {
            out.push(ConfigWarning::HighMtu);
        }
    }

    if !cfg
        .interface
        .addresses
        .iter()
        .any(|n| matches!(n, ipnet::IpNet::V4(_)))
    {
        out.push(ConfigWarning::NoIpv4Address);
    }

    if cfg.peers.len() > 1 {
        out.push(ConfigWarning::MultiplePeers);
    }

    if let Some(peer) = cfg.peers.first() {
        if peer.persistent_keepalive.is_none() {
            out.push(ConfigWarning::NoKeepalive);
        }
        if let Some(r) = rules {
            if r.mode == "include" {
                let catch_all = peer.allowed_ips.iter().any(|n| n.prefix_len() == 0);
                if catch_all {
                    out.push(ConfigWarning::IncludeWithCatchAll);
                }
            }
        }
    }

    out
}

/// Maps a `ConfigWarning` variant to its i18n key, for rendering.
pub fn warning_key(w: ConfigWarning) -> &'static str {
    match w {
        ConfigWarning::NoDns => "gui.add.warning.no_dns",
        ConfigWarning::IncludeWithCatchAll => "gui.add.warning.conflicting_include",
        ConfigWarning::LowMtu => "gui.add.warning.low_mtu",
        ConfigWarning::HighMtu => "gui.add.warning.high_mtu",
        ConfigWarning::NoKeepalive => "gui.add.warning.no_keepalive_nat",
        ConfigWarning::MultiplePeers => "gui.add.warning.multi_peer_unsupported",
        ConfigWarning::NoIpv4Address => "gui.add.warning.ipv4_only_addresses",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_entry_accepts_common_forms() {
        assert!(is_valid_entry("10.0.0.1"));
        assert!(is_valid_entry("10.0.0.0/24"));
        assert!(is_valid_entry("2001:db8::1"));
        assert!(is_valid_entry("2001:db8::/48"));
        assert!(is_valid_entry("example.com"));
        assert!(is_valid_entry("*.example.com"));
        assert!(is_valid_entry("sub.domain.example.co.uk"));
    }

    #[test]
    fn is_valid_entry_rejects_junk() {
        assert!(!is_valid_entry(""));
        assert!(!is_valid_entry("   "));
        assert!(!is_valid_entry("has space"));
        assert!(!is_valid_entry("10.0.0.0/33"));
        assert!(!is_valid_entry("not a domain!"));
    }

    #[test]
    fn classify_returns_correct_kind() {
        assert_eq!(classify("10.0.0.1"), EntryKind::Ip);
        assert_eq!(classify("2001:db8::1"), EntryKind::Ip);
        assert_eq!(classify("10.0.0.0/24"), EntryKind::Cidr);
        assert_eq!(classify("example.com"), EntryKind::Domain);
        assert_eq!(classify("*.example.com"), EntryKind::Wildcard);
        assert_eq!(classify(""), EntryKind::Invalid);
        assert_eq!(classify("*.bad domain"), EntryKind::Invalid);
    }

    #[test]
    fn classify_country_prefix_is_geo() {
        assert_eq!(classify("country:US"), EntryKind::Geo);
        assert_eq!(classify("country:tr"), EntryKind::Geo);
        assert_eq!(classify("country:"), EntryKind::Invalid);
        assert_eq!(classify("country:USA"), EntryKind::Invalid);
        assert_eq!(classify("country:T1"), EntryKind::Invalid);
    }

    use crate::wg::conf::{InterfaceConfig, PeerConfig, WgConfig};

    fn base_cfg() -> WgConfig {
        WgConfig {
            interface: InterfaceConfig {
                private_key: [1u8; 32],
                addresses: vec!["10.0.0.2/32".parse().unwrap()],
                dns: vec!["1.1.1.1".parse().unwrap()],
                mtu: Some(1420),
                listen_port: None,
                pre_up: Vec::new(),
                post_up: Vec::new(),
                pre_down: Vec::new(),
                post_down: Vec::new(),
            },
            peers: vec![PeerConfig {
                public_key: [2u8; 32],
                preshared_key: None,
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
                endpoint: Some("1.2.3.4:51820".parse().unwrap()),
                persistent_keepalive: Some(25),
            }],
        }
    }

    #[test]
    fn validate_clean_config_has_no_warnings() {
        assert!(validate_wg_config(&base_cfg(), None).is_empty());
    }

    #[test]
    fn validate_detects_missing_dns() {
        let mut cfg = base_cfg();
        cfg.interface.dns.clear();
        assert!(validate_wg_config(&cfg, None).contains(&ConfigWarning::NoDns));
    }

    #[test]
    fn validate_detects_low_and_high_mtu() {
        let mut cfg = base_cfg();
        cfg.interface.mtu = Some(1200);
        assert!(validate_wg_config(&cfg, None).contains(&ConfigWarning::LowMtu));
        cfg.interface.mtu = Some(1600);
        assert!(validate_wg_config(&cfg, None).contains(&ConfigWarning::HighMtu));
    }

    #[test]
    fn validate_detects_missing_keepalive() {
        let mut cfg = base_cfg();
        cfg.peers[0].persistent_keepalive = None;
        assert!(validate_wg_config(&cfg, None).contains(&ConfigWarning::NoKeepalive));
    }

    #[test]
    fn validate_detects_multiple_peers() {
        let mut cfg = base_cfg();
        let extra = cfg.peers[0].clone();
        cfg.peers.push(extra);
        assert!(validate_wg_config(&cfg, None).contains(&ConfigWarning::MultiplePeers));
    }

    #[test]
    fn validate_detects_ipv6_only_addresses() {
        let mut cfg = base_cfg();
        cfg.interface.addresses = vec!["fd00::2/128".parse().unwrap()];
        assert!(validate_wg_config(&cfg, None).contains(&ConfigWarning::NoIpv4Address));
    }

    #[test]
    fn validate_flags_include_with_catch_all() {
        let mut cfg = base_cfg();
        cfg.peers[0].allowed_ips = vec!["0.0.0.0/0".parse().unwrap()];
        let rules = Rules {
            mode: "include".to_string(),
            entries: Vec::new(),
            hooks_enabled: false,
            on_demand: None,
        };
        assert!(validate_wg_config(&cfg, Some(&rules))
            .contains(&ConfigWarning::IncludeWithCatchAll));
    }

    #[test]
    fn validate_does_not_flag_exclude_with_catch_all() {
        let mut cfg = base_cfg();
        cfg.peers[0].allowed_ips = vec!["0.0.0.0/0".parse().unwrap()];
        let rules = Rules {
            mode: "exclude".to_string(),
            entries: Vec::new(),
            hooks_enabled: false,
            on_demand: None,
        };
        assert!(!validate_wg_config(&cfg, Some(&rules))
            .contains(&ConfigWarning::IncludeWithCatchAll));
    }
}
