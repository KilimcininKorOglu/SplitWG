//! Domain resolution, CIDR normalisation, include-mode config rewriting,
//! and default-gateway lookup.

use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;

use crate::config::Rules;

use super::dedup_preserving_order;

pub mod geo;

/// Reports whether `s` is a wildcard domain entry of the form `*.something`.
/// A bare `*` with no dot is not considered a valid wildcard entry.
pub fn is_wildcard_entry(s: &str) -> bool {
    s.starts_with("*.") && s.len() > 2
}

/// Strips the leading `*.` prefix from a wildcard entry. Only call on strings
/// where [`is_wildcard_entry`] returns true.
pub fn wildcard_base_domain(s: &str) -> String {
    s.strip_prefix("*.").unwrap_or(s).to_string()
}

/// Resolves domain names to IPs and normalises all entries to CIDR notation.
/// Duplicate entries are suppressed while preserving first-seen order.
///
/// Priority of each entry:
/// 1. Already a valid CIDR → used as-is.
/// 2. Bare IP → appended with `/32` (IPv4) or `/128` (IPv6).
/// 3. Wildcard `*.domain` → strip prefix, resolve base domain via DNS.
/// 4. Domain → DNS lookup, each resolved IP appended as `/32` or `/128`.
pub fn resolve_entries(entries: &[String]) -> Vec<String> {
    let mut collected = Vec::with_capacity(entries.len());

    for raw in entries {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }

        if let Some(code) = is_geo_entry(entry) {
            let expanded = geo::expand_country(&code);
            if expanded.is_empty() {
                log::warn!(
                    "wg: geo: country:{} resolved to 0 CIDRs (mmdb missing?)",
                    code
                );
            }
            for cidr in expanded {
                collected.push(cidr);
            }
            continue;
        }

        if parse_cidr(entry) {
            collected.push(entry.to_string());
            continue;
        }

        if let Ok(ip) = entry.parse::<IpAddr>() {
            collected.push(format_ip_as_host(&ip, entry));
            continue;
        }

        let host: String = if is_wildcard_entry(entry) {
            let base = wildcard_base_domain(entry);
            log::info!(
                "wg: wildcard entry {:?} → resolving base domain {:?}",
                entry,
                base
            );
            base
        } else {
            entry.to_string()
        };

        // DNS lookup — port appended only because ToSocketAddrs requires it;
        // the port does not affect resolution.
        let probe = format!("{}:0", host);
        let Ok(iter) = probe.to_socket_addrs() else {
            continue;
        };
        for sock in iter {
            let ip = sock.ip();
            let ip_str = ip.to_string();
            collected.push(format_ip_as_host(&ip, &ip_str));
        }
    }

    dedup_preserving_order(collected)
}

/// Returns true if `s` parses as an IPv4 or IPv6 CIDR block (e.g. `10.0.0.0/8`).
fn parse_cidr(s: &str) -> bool {
    let Some((addr, prefix)) = s.split_once('/') else {
        return false;
    };
    let ip: IpAddr = match addr.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match ip {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    }
}

/// Detects the `country:XX` entry form and returns the uppercase
/// two-letter country code. Returns `None` for non-matching input so
/// callers can fall through to IP/CIDR/domain handling.
pub fn is_geo_entry(s: &str) -> Option<String> {
    let code = s.strip_prefix("country:")?;
    if code.len() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(code.to_uppercase())
}

/// Formats an IP as a host-style CIDR (`/32` for v4, `/128` for v6) while
/// preserving the original string spelling so round-tripped entries are
/// byte-identical to what the user typed.
fn format_ip_as_host(ip: &IpAddr, original: &str) -> String {
    match ip {
        IpAddr::V4(_) => format!("{}/32", original),
        IpAddr::V6(_) => format!("{}/128", original),
    }
}

/// Returns the current default gateway IP address, falling back through
/// two shell invocations.
pub fn get_default_gateway() -> Result<String, String> {
    let primary = Command::new("sh")
        .arg("-c")
        .arg("route -n get default 2>/dev/null | grep 'gateway:' | awk '{print $2}'")
        .output();
    if let Ok(out) = primary {
        let gw = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !gw.is_empty() {
            return Ok(gw);
        }
    }

    let fallback = Command::new("sh")
        .arg("-c")
        .arg("netstat -rn 2>/dev/null | awk '/^default/{print $2; exit}'")
        .output()
        .map_err(|e| format!("get default gateway: {}", e))?;
    let gw = String::from_utf8_lossy(&fallback.stdout).trim().to_string();
    if gw.is_empty() {
        return Err("could not determine default gateway".to_string());
    }
    Ok(gw)
}

/// Returns a modified WireGuard config where `AllowedIPs` in every `[Peer]`
/// section is replaced with the resolved entries from `rules`. If no entries
/// resolve, the original config is returned unchanged.
pub fn build_include_config(original: &str, rules: &Rules) -> String {
    let resolved = resolve_entries(&rules.entries);
    if resolved.is_empty() {
        return original.to_string();
    }

    let allowed_ips = resolved.join(", ");
    let mut result = Vec::with_capacity(original.lines().count() + 2);
    let mut in_peer = false;
    let mut wrote_allowed_ips = false;

    for line in original.split('\n') {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();

        if lower == "[peer]" {
            in_peer = true;
            wrote_allowed_ips = false;
            result.push(line.to_string());
        } else if lower.starts_with('[') && lower != "[peer]" {
            if in_peer && !wrote_allowed_ips {
                result.push(format!("AllowedIPs = {}", allowed_ips));
            }
            in_peer = false;
            result.push(line.to_string());
        } else if in_peer && lower.starts_with("allowedips") {
            if !wrote_allowed_ips {
                result.push(format!("AllowedIPs = {}", allowed_ips));
                wrote_allowed_ips = true;
            }
            // Drop the original AllowedIPs line.
        } else {
            result.push(line.to_string());
        }
    }

    if in_peer && !wrote_allowed_ips {
        result.push(format!("AllowedIPs = {}", allowed_ips));
    }

    result.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_geo_entry_accepts_two_letter_code() {
        assert_eq!(is_geo_entry("country:US"), Some("US".to_string()));
        assert_eq!(is_geo_entry("country:tr"), Some("TR".to_string()));
    }

    #[test]
    fn is_geo_entry_rejects_bad_input() {
        assert_eq!(is_geo_entry("country:"), None);
        assert_eq!(is_geo_entry("country:USA"), None);
        assert_eq!(is_geo_entry("country:T1"), None);
        assert_eq!(is_geo_entry("CountryUS"), None);
        assert_eq!(is_geo_entry("10.0.0.1"), None);
    }

    #[test]
    fn is_wildcard_entry_matches_go_cases() {
        assert!(is_wildcard_entry("*.example.com"));
        assert!(is_wildcard_entry("*.x"));
        assert!(!is_wildcard_entry("*."));
        assert!(!is_wildcard_entry("*"));
        assert!(!is_wildcard_entry("example.com"));
        assert!(!is_wildcard_entry("*example.com"));
        assert!(!is_wildcard_entry("**example.com"));
    }

    #[test]
    fn wildcard_base_domain_strips_prefix() {
        assert_eq!(wildcard_base_domain("*.example.com"), "example.com");
        assert_eq!(wildcard_base_domain("*.x"), "x");
        assert_eq!(wildcard_base_domain("*.sub.domain.org"), "sub.domain.org");
    }

    #[test]
    fn resolve_entries_passes_cidr_through() {
        let entries = vec!["10.0.0.0/24".to_string(), "2001:db8::/48".to_string()];
        let out = resolve_entries(&entries);
        assert_eq!(out, entries);
    }

    #[test]
    fn resolve_entries_bare_ip_gets_host_suffix() {
        let entries = vec!["10.0.0.1".to_string(), "2001:db8::1".to_string()];
        let out = resolve_entries(&entries);
        assert_eq!(out, vec!["10.0.0.1/32", "2001:db8::1/128"]);
    }

    #[test]
    fn resolve_entries_deduplicates() {
        let entries = vec![
            "10.0.0.0/24".to_string(),
            "10.0.0.0/24".to_string(),
            "10.0.0.1".to_string(),
        ];
        let out = resolve_entries(&entries);
        assert_eq!(out, vec!["10.0.0.0/24", "10.0.0.1/32"]);
    }

    #[test]
    fn resolve_entries_skips_empty_and_whitespace() {
        let entries = vec!["".to_string(), "   ".to_string(), "10.0.0.1".to_string()];
        let out = resolve_entries(&entries);
        assert_eq!(out, vec!["10.0.0.1/32"]);
    }

    #[test]
    fn build_include_config_replaces_peer_allowedips() {
        let original = "[Interface]\nPrivateKey = foo\n\n[Peer]\nPublicKey = bar\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:51820\n";
        let rules = Rules {
            mode: "include".to_string(),
            entries: vec!["10.0.0.0/24".to_string(), "192.168.1.0/24".to_string()],
            hooks_enabled: false,
            on_demand: None,
        };
        let out = build_include_config(original, &rules);
        assert!(out.contains("AllowedIPs = 10.0.0.0/24, 192.168.1.0/24"));
        assert!(!out.contains("AllowedIPs = 0.0.0.0/0"));
        assert!(out.contains("PublicKey = bar"));
        assert!(out.contains("Endpoint = 1.2.3.4:51820"));
    }

    #[test]
    fn build_include_config_inserts_when_absent() {
        let original = "[Interface]\nPrivateKey = foo\n\n[Peer]\nPublicKey = bar\nEndpoint = 1.2.3.4:51820\n";
        let rules = Rules {
            mode: "include".to_string(),
            entries: vec!["10.0.0.0/24".to_string()],
            hooks_enabled: false,
            on_demand: None,
        };
        let out = build_include_config(original, &rules);
        assert!(out.contains("AllowedIPs = 10.0.0.0/24"));
    }

    #[test]
    fn build_include_config_handles_multiple_peers() {
        let original = "[Peer]\nPublicKey = a\nAllowedIPs = 0.0.0.0/0\n\n[Peer]\nPublicKey = b\nAllowedIPs = 10.0.0.0/8\n";
        let rules = Rules {
            mode: "include".to_string(),
            entries: vec!["172.16.0.0/12".to_string()],
            hooks_enabled: false,
            on_demand: None,
        };
        let out = build_include_config(original, &rules);
        assert_eq!(out.matches("AllowedIPs = 172.16.0.0/12").count(), 2);
        assert!(!out.contains("AllowedIPs = 0.0.0.0/0"));
        assert!(!out.contains("AllowedIPs = 10.0.0.0/8"));
    }

    #[test]
    fn build_include_config_returns_original_when_no_entries_resolve() {
        let original = "[Peer]\nAllowedIPs = 0.0.0.0/0\n";
        let rules = Rules {
            mode: "include".to_string(),
            entries: vec![],
            hooks_enabled: false,
            on_demand: None,
        };
        let out = build_include_config(original, &rules);
        assert_eq!(out, original);
    }

    #[test]
    fn parse_cidr_boundaries() {
        assert!(parse_cidr("0.0.0.0/0"));
        assert!(parse_cidr("255.255.255.255/32"));
        assert!(parse_cidr("::/0"));
        assert!(parse_cidr("2001:db8::/128"));
        assert!(!parse_cidr("10.0.0.0/33"));
        assert!(!parse_cidr("10.0.0.0"));
        assert!(!parse_cidr("not an ip/24"));
    }
}
