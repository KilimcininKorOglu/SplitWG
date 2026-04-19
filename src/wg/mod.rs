//! WireGuard tunnel lifecycle and routing.

use std::collections::HashSet;

use thiserror::Error;

mod wgbin_darwin;
pub use wgbin_darwin::{WG_BIN, WG_QUICK_BIN};

mod admin_darwin;
pub use admin_darwin::{run_as_admin, run_as_admin_osascript, with_path, BREW_PATH};

pub mod conf;
pub mod manager;
pub mod on_demand;
pub mod rules;

pub use manager::{extract_peer_public_key, Manager, TunnelState};
pub use rules::{
    build_include_config, get_default_gateway, is_wildcard_entry, resolve_entries,
    wildcard_base_domain,
};

/// Errors returned by the wg layer.
#[derive(Debug, Error)]
pub enum WgError {
    #[error("admin: {0}")]
    Admin(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Msg(String),
}

/// Wraps `s` in single quotes suitable for embedding in a shell command.
/// Replaces embedded `'` with `'\''`.
pub fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Returns true if `cidr` is an IPv6 address block (contains `:`).
pub fn is_ipv6_cidr(cidr: &str) -> bool {
    cidr.contains(':')
}

/// Shell commands to add routes via `gateway`. Each command is suffixed with
/// `|| true` so failures do not abort the chain.
pub fn build_route_add_cmds(cidrs: &[String], gateway: &str) -> Vec<String> {
    cidrs
        .iter()
        .map(|cidr| {
            if is_ipv6_cidr(cidr) {
                format!("route add -inet6 {} {} || true", cidr, gateway)
            } else {
                format!("route add -net {} {} || true", cidr, gateway)
            }
        })
        .collect()
}

/// Shell commands to delete routes. Each command is suffixed with `|| true`
/// so failures do not abort the chain.
pub fn build_route_delete_cmds(cidrs: &[String]) -> Vec<String> {
    cidrs
        .iter()
        .map(|cidr| {
            if is_ipv6_cidr(cidr) {
                format!("route delete -inet6 {} || true", cidr)
            } else {
                format!("route delete -net {} || true", cidr)
            }
        })
        .collect()
}

/// Deduplicates a CIDR list while preserving insertion order.
pub(crate) fn dedup_preserving_order(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(values.len());
    for v in values {
        if seen.insert(v.clone()) {
            out.push(v);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quote_basic() {
        assert_eq!(shell_quote("hello"), "'hello'");
    }

    #[test]
    fn shell_quote_embedded_single_quote() {
        // shell_quote("it's") => "'it'\\''s'"
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn shell_quote_path_with_spaces() {
        assert_eq!(shell_quote("/tmp/my config.conf"), "'/tmp/my config.conf'");
    }

    #[test]
    fn is_ipv6_cidr_detection() {
        assert!(is_ipv6_cidr("2001:db8::/32"));
        assert!(is_ipv6_cidr("::1/128"));
        assert!(!is_ipv6_cidr("10.0.0.0/8"));
        assert!(!is_ipv6_cidr("192.168.1.1/32"));
    }

    #[test]
    fn build_route_add_cmds_split_family() {
        let cidrs = vec!["10.0.0.0/24".to_string(), "2001:db8::/64".to_string()];
        let cmds = build_route_add_cmds(&cidrs, "192.168.1.1");
        assert_eq!(
            cmds,
            vec![
                "route add -net 10.0.0.0/24 192.168.1.1 || true".to_string(),
                "route add -inet6 2001:db8::/64 192.168.1.1 || true".to_string(),
            ]
        );
    }

    #[test]
    fn build_route_delete_cmds_split_family() {
        let cidrs = vec!["10.0.0.0/24".to_string(), "2001:db8::/64".to_string()];
        let cmds = build_route_delete_cmds(&cidrs);
        assert_eq!(
            cmds,
            vec![
                "route delete -net 10.0.0.0/24 || true".to_string(),
                "route delete -inet6 2001:db8::/64 || true".to_string(),
            ]
        );
    }

    #[test]
    fn dedup_preserves_first_occurrence_order() {
        let v = vec![
            "a".to_string(),
            "b".to_string(),
            "a".to_string(),
            "c".to_string(),
            "b".to_string(),
        ];
        assert_eq!(dedup_preserving_order(v), vec!["a", "b", "c"]);
    }
}
