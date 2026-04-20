//! WireGuard `.conf` parser — produces structured types consumed by the
//! userspace tunnel runtime (boringtun helper).
//!
//! `wg-quick` accepts a superset of keys (PreUp/PostUp/Table/FwMark/…); this
//! parser recognises only the fields boringtun/tun2 need to run the tunnel,
//! and silently ignores the rest so existing user configs keep loading.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use base64::prelude::{Engine, BASE64_STANDARD};
use ipnet::IpNet;

/// Full WireGuard configuration parsed from a `.conf` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgConfig {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
}

/// `[Interface]` section.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct InterfaceConfig {
    pub private_key: [u8; 32],
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub mtu: Option<u16>,
    pub listen_port: Option<u16>,
    /// wg-quick-compatible hook commands. Preserved in file order; each entry
    /// is a raw shell command string passed to `sh -c` by the helper when
    /// `Settings::hooks_enabled` is true. Empty by default; an `.conf` without
    /// any PreUp/PostUp/PreDown/PostDown lines simply leaves these empty.
    pub pre_up: Vec<String>,
    pub post_up: Vec<String>,
    pub pre_down: Vec<String>,
    pub post_down: Vec<String>,
}

/// `[Peer]` section.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<u16>,
}

impl std::fmt::Debug for InterfaceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceConfig")
            .field("private_key", &"[REDACTED]")
            .field("addresses", &self.addresses)
            .field("dns", &self.dns)
            .field("mtu", &self.mtu)
            .field("listen_port", &self.listen_port)
            .finish()
    }
}

impl std::fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConfig")
            .field("public_key", &"[REDACTED]")
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("allowed_ips", &self.allowed_ips)
            .field("endpoint", &self.endpoint)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .finish()
    }
}

/// Returns the base64-encoded PublicKey of the first `[Peer]` section, or
/// `None` when no peer / no PublicKey is present. Used by the `wg show`
/// comparison path to decide whether a config corresponds to an active
/// interface.
pub fn first_peer_public_key_base64(content: &str) -> Option<String> {
    let cfg = parse(content).ok()?;
    let peer = cfg.peers.first()?;
    Some(BASE64_STANDARD.encode(peer.public_key))
}

/// Parses a WireGuard configuration file body.
pub fn parse(content: &str) -> Result<WgConfig> {
    log::debug!("splitwg: conf: parsing config ({} bytes)", content.len());
    let mut section = Section::None;
    let mut seen_interface = false;
    let mut iface = InterfaceConfig::default();
    let mut peers: Vec<PeerConfig> = Vec::new();
    let mut peer: Option<PartialPeer> = None;

    for (idx, raw) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let name = line[1..line.len() - 1].trim();
            if name.eq_ignore_ascii_case("Interface") {
                if seen_interface {
                    bail!("line {line_no}: duplicate [Interface] section");
                }
                if let Some(p) = peer.take() {
                    peers.push(p.finish(line_no)?);
                }
                section = Section::Interface;
                seen_interface = true;
            } else if name.eq_ignore_ascii_case("Peer") {
                if let Some(p) = peer.take() {
                    peers.push(p.finish(line_no)?);
                }
                section = Section::Peer;
                peer = Some(PartialPeer::default());
            } else {
                bail!("line {line_no}: unknown section [{name}]");
            }
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("line {line_no}: expected `key = value`"))?;
        let key = key.trim();
        let value = value.trim();
        let key_lc = key.to_ascii_lowercase();

        match section {
            Section::None => bail!("line {line_no}: `{key}` outside of any section"),
            Section::Interface => apply_interface(&mut iface, &key_lc, value, line_no)?,
            Section::Peer => {
                let p = peer.as_mut().expect("peer set when section=Peer");
                apply_peer(p, &key_lc, value, line_no)?;
            }
        }
    }

    if let Some(p) = peer.take() {
        peers.push(p.finish(content.lines().count())?);
    }
    if !seen_interface {
        bail!("missing [Interface] section");
    }
    if iface.private_key == [0u8; 32] {
        bail!("[Interface] missing PrivateKey");
    }

    log::debug!(
        "splitwg: conf: parsed successfully — {} peer(s), {} address(es), {} DNS server(s)",
        peers.len(),
        iface.addresses.len(),
        iface.dns.len(),
    );
    if peers.is_empty() {
        log::warn!("splitwg: conf: config has no [Peer] sections");
    }

    Ok(WgConfig {
        interface: iface,
        peers,
    })
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

#[derive(Default)]
struct PartialPeer {
    public_key: Option<[u8; 32]>,
    preshared_key: Option<[u8; 32]>,
    allowed_ips: Vec<IpNet>,
    endpoint: Option<SocketAddr>,
    persistent_keepalive: Option<u16>,
}

impl PartialPeer {
    fn finish(self, line: usize) -> Result<PeerConfig> {
        let public_key = self
            .public_key
            .ok_or_else(|| anyhow!("[Peer] missing PublicKey (section ending near line {line})"))?;
        Ok(PeerConfig {
            public_key,
            preshared_key: self.preshared_key,
            allowed_ips: self.allowed_ips,
            endpoint: self.endpoint,
            persistent_keepalive: self.persistent_keepalive,
        })
    }
}

fn apply_interface(iface: &mut InterfaceConfig, key: &str, value: &str, line: usize) -> Result<()> {
    match key {
        "privatekey" => {
            iface.private_key =
                decode_key(value).with_context(|| format!("line {line}: PrivateKey"))?;
        }
        "address" => {
            let mut list =
                parse_cidr_list(value).with_context(|| format!("line {line}: Address"))?;
            iface.addresses.append(&mut list);
        }
        "dns" => {
            let mut list = parse_ip_list(value).with_context(|| format!("line {line}: DNS"))?;
            iface.dns.append(&mut list);
        }
        "mtu" => {
            iface.mtu = Some(
                value
                    .parse()
                    .with_context(|| format!("line {line}: MTU `{value}`"))?,
            );
        }
        "listenport" => {
            iface.listen_port = Some(
                value
                    .parse()
                    .with_context(|| format!("line {line}: ListenPort `{value}`"))?,
            );
        }
        "preup" => iface.pre_up.push(value.to_string()),
        "postup" => iface.post_up.push(value.to_string()),
        "predown" => iface.pre_down.push(value.to_string()),
        "postdown" => iface.post_down.push(value.to_string()),
        // wg-quick silently accepts many other keys (Table, FwMark, SaveConfig, …);
        // we don't use them, but we don't reject the file either.
        _ => {}
    }
    Ok(())
}

fn apply_peer(peer: &mut PartialPeer, key: &str, value: &str, line: usize) -> Result<()> {
    match key {
        "publickey" => {
            peer.public_key =
                Some(decode_key(value).with_context(|| format!("line {line}: PublicKey"))?);
        }
        "presharedkey" => {
            peer.preshared_key =
                Some(decode_key(value).with_context(|| format!("line {line}: PresharedKey"))?);
        }
        "allowedips" => {
            let mut list =
                parse_cidr_list(value).with_context(|| format!("line {line}: AllowedIPs"))?;
            peer.allowed_ips.append(&mut list);
        }
        "endpoint" => {
            peer.endpoint =
                Some(parse_endpoint(value).with_context(|| format!("line {line}: Endpoint"))?);
        }
        "persistentkeepalive" => {
            peer.persistent_keepalive = Some(
                value
                    .parse()
                    .with_context(|| format!("line {line}: PersistentKeepalive `{value}`"))?,
            );
        }
        _ => {}
    }
    Ok(())
}

fn strip_comment(line: &str) -> &str {
    let cut = line
        .char_indices()
        .find(|(_, c)| *c == '#' || *c == ';')
        .map(|(i, _)| i)
        .unwrap_or(line.len());
    &line[..cut]
}

fn decode_key(s: &str) -> Result<[u8; 32]> {
    let bytes = BASE64_STANDARD
        .decode(s.trim())
        .map_err(|e| anyhow!("invalid base64: {e}"))?;
    if bytes.len() != 32 {
        bail!("key must decode to 32 bytes, got {}", bytes.len());
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Ok(k)
}

fn parse_cidr_list(s: &str) -> Result<Vec<IpNet>> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(parse_cidr(part)?);
    }
    Ok(out)
}

fn parse_cidr(s: &str) -> Result<IpNet> {
    if s.contains('/') {
        IpNet::from_str(s).map_err(|e| anyhow!("invalid CIDR `{s}`: {e}"))
    } else {
        let ip: IpAddr = s.parse().map_err(|e| anyhow!("invalid IP `{s}`: {e}"))?;
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        IpNet::new(ip, prefix).map_err(|e| anyhow!("CIDR from IP `{s}`: {e}"))
    }
}

fn parse_ip_list(s: &str) -> Result<Vec<IpAddr>> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(
            part.parse()
                .map_err(|e| anyhow!("invalid IP `{part}`: {e}"))?,
        );
    }
    Ok(out)
}

fn parse_endpoint(s: &str) -> Result<SocketAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // Hostname form — resolve via DNS. The host process runs unprivileged so
    // this is safe; the helper receives the already-resolved SocketAddr.
    s.to_socket_addrs()
        .map_err(|e| anyhow!("resolve `{s}`: {e}"))?
        .next()
        .ok_or_else(|| anyhow!("no addresses for `{s}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IFACE_KEY_B64: &str = "QNpAjV5E06MPqKfN0u3VHYnM3LqHG/U0xk4BCQKYJHg=";
    const PEER_KEY_B64: &str = "RmVhbjA3ykCFtABhxzrL7B5dMRv61i3+4RmmQhR0USM=";
    const PSK_B64: &str = "C6XwlO7XhKIzPxI7SYUhD1hXQOcwGQbeDUqsPf82Oks=";

    #[test]
    fn parse_minimal() {
        let body = format!(
            "[Interface]\nPrivateKey = {IFACE_KEY_B64}\nAddress = 10.0.0.2/32\n\n\
             [Peer]\nPublicKey = {PEER_KEY_B64}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:51820\n"
        );
        let cfg = parse(&body).expect("parse ok");
        assert_eq!(
            cfg.interface.addresses,
            vec!["10.0.0.2/32".parse().unwrap()]
        );
        assert_eq!(cfg.peers.len(), 1);
        let peer = &cfg.peers[0];
        assert_eq!(peer.allowed_ips, vec!["0.0.0.0/0".parse().unwrap()]);
        assert_eq!(peer.endpoint, Some("1.2.3.4:51820".parse().unwrap()));
    }

    #[test]
    fn parse_case_insensitive_sections_and_keys() {
        let body = format!(
            "[interface]\nprivatekey={IFACE_KEY_B64}\n\n[peer]\npublickey={PEER_KEY_B64}\n"
        );
        let cfg = parse(&body).expect("parse ok");
        assert_eq!(cfg.peers.len(), 1);
    }

    #[test]
    fn parse_comments_and_blank_lines() {
        let body = format!(
            "# comment\n; another comment\n\n[Interface]\nPrivateKey = {IFACE_KEY_B64} # inline\n\
             [Peer]\nPublicKey = {PEER_KEY_B64} ; trailing\nAllowedIPs = 10.0.0.0/24, 2001:db8::/64\n"
        );
        let cfg = parse(&body).expect("parse ok");
        let allowed = &cfg.peers[0].allowed_ips;
        assert_eq!(allowed.len(), 2);
        assert!(allowed.iter().any(|n| n.to_string() == "10.0.0.0/24"));
        assert!(allowed.iter().any(|n| n.to_string() == "2001:db8::/64"));
    }

    #[test]
    fn parse_bare_ip_address_expands_to_prefix() {
        let body = format!(
            "[Interface]\nPrivateKey = {IFACE_KEY_B64}\nAddress = 10.0.0.2\n[Peer]\nPublicKey = {PEER_KEY_B64}\nAllowedIPs = ::1\n"
        );
        let cfg = parse(&body).expect("parse ok");
        assert_eq!(cfg.interface.addresses[0].to_string(), "10.0.0.2/32");
        assert_eq!(cfg.peers[0].allowed_ips[0].to_string(), "::1/128");
    }

    #[test]
    fn parse_multiple_peers() {
        let body = format!(
            "[Interface]\nPrivateKey = {IFACE_KEY_B64}\n\n\
             [Peer]\nPublicKey = {PEER_KEY_B64}\n\n\
             [Peer]\nPublicKey = {IFACE_KEY_B64}\nAllowedIPs = 10.1.0.0/16\n"
        );
        let cfg = parse(&body).expect("parse ok");
        assert_eq!(cfg.peers.len(), 2);
        assert_eq!(cfg.peers[1].allowed_ips[0].to_string(), "10.1.0.0/16");
    }

    #[test]
    fn parse_dns_mtu_keepalive_psk_listenport() {
        let body = format!(
            "[Interface]\nPrivateKey = {IFACE_KEY_B64}\nDNS = 1.1.1.1, 1.0.0.1\nMTU = 1380\nListenPort = 51820\n\n\
             [Peer]\nPublicKey = {PEER_KEY_B64}\nPresharedKey = {PSK_B64}\nPersistentKeepalive = 25\n"
        );
        let cfg = parse(&body).expect("parse ok");
        assert_eq!(cfg.interface.mtu, Some(1380));
        assert_eq!(cfg.interface.listen_port, Some(51820));
        assert_eq!(cfg.interface.dns.len(), 2);
        assert!(cfg.peers[0].preshared_key.is_some());
        assert_eq!(cfg.peers[0].persistent_keepalive, Some(25));
    }

    #[test]
    fn parse_unknown_keys_are_ignored() {
        // wg-quick-only keys must not fail parsing.
        let body = format!(
            "[Interface]\nPrivateKey = {IFACE_KEY_B64}\nTable = off\nFwMark = 0x42\nSaveConfig = true\n\
             [Peer]\nPublicKey = {PEER_KEY_B64}\n"
        );
        assert!(parse(&body).is_ok());
    }

    #[test]
    fn parse_hooks_preserve_order_and_type() {
        let body = format!(
            "[Interface]\nPrivateKey = {IFACE_KEY_B64}\n\
             PreUp = echo first\n\
             PreUp = echo second\n\
             PostUp = iptables -A FORWARD -i %i -j ACCEPT\n\
             PreDown = logger 'vpn down'\n\
             PostDown = iptables -D FORWARD -i %i -j ACCEPT\n\
             [Peer]\nPublicKey = {PEER_KEY_B64}\n"
        );
        let cfg = parse(&body).expect("parse ok");
        assert_eq!(
            cfg.interface.pre_up,
            vec!["echo first".to_string(), "echo second".to_string()]
        );
        assert_eq!(
            cfg.interface.post_up,
            vec!["iptables -A FORWARD -i %i -j ACCEPT".to_string()]
        );
        assert_eq!(
            cfg.interface.pre_down,
            vec!["logger 'vpn down'".to_string()]
        );
        assert_eq!(
            cfg.interface.post_down,
            vec!["iptables -D FORWARD -i %i -j ACCEPT".to_string()]
        );
    }

    #[test]
    fn parse_hook_keys_are_case_insensitive() {
        let body = format!(
            "[Interface]\nPrivateKey = {IFACE_KEY_B64}\n\
             preup = echo a\n\
             POSTUP = echo b\n\
             PreDOWN = echo c\n\
             postDown = echo d\n\
             [Peer]\nPublicKey = {PEER_KEY_B64}\n"
        );
        let cfg = parse(&body).expect("parse ok");
        assert_eq!(cfg.interface.pre_up, vec!["echo a".to_string()]);
        assert_eq!(cfg.interface.post_up, vec!["echo b".to_string()]);
        assert_eq!(cfg.interface.pre_down, vec!["echo c".to_string()]);
        assert_eq!(cfg.interface.post_down, vec!["echo d".to_string()]);
    }

    #[test]
    fn parse_no_hooks_leaves_vectors_empty() {
        let body = format!(
            "[Interface]\nPrivateKey = {IFACE_KEY_B64}\nAddress = 10.0.0.2/32\n\
             [Peer]\nPublicKey = {PEER_KEY_B64}\nAllowedIPs = 0.0.0.0/0\n"
        );
        let cfg = parse(&body).expect("parse ok");
        assert!(cfg.interface.pre_up.is_empty());
        assert!(cfg.interface.post_up.is_empty());
        assert!(cfg.interface.pre_down.is_empty());
        assert!(cfg.interface.post_down.is_empty());
    }

    #[test]
    fn parse_missing_interface_fails() {
        let body = format!("[Peer]\nPublicKey = {PEER_KEY_B64}\n");
        assert!(parse(&body).is_err());
    }

    #[test]
    fn parse_missing_private_key_fails() {
        let body =
            format!("[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {PEER_KEY_B64}\n");
        assert!(parse(&body).is_err());
    }

    #[test]
    fn parse_missing_peer_public_key_fails() {
        let body =
            format!("[Interface]\nPrivateKey = {IFACE_KEY_B64}\n[Peer]\nAllowedIPs = 0.0.0.0/0\n");
        assert!(parse(&body).is_err());
    }

    #[test]
    fn parse_invalid_base64_fails() {
        let body = "[Interface]\nPrivateKey = not-base64!!!\n[Peer]\nPublicKey = also-bad\n";
        assert!(parse(body).is_err());
    }

    #[test]
    fn parse_short_key_fails() {
        // 32 base64 chars → 24 bytes, not 32.
        let body = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
        assert!(parse(body).is_err());
    }

    #[test]
    fn parse_invalid_cidr_fails() {
        let body = format!(
            "[Interface]\nPrivateKey = {IFACE_KEY_B64}\nAddress = 10.0.0.2/99\n[Peer]\nPublicKey = {PEER_KEY_B64}\n"
        );
        assert!(parse(&body).is_err());
    }

    #[test]
    fn first_peer_public_key_base64_matches_input() {
        let body = format!(
            "[Interface]\nPrivateKey = {IFACE_KEY_B64}\n\n[Peer]\nPublicKey = {PEER_KEY_B64}\n"
        );
        assert_eq!(
            first_peer_public_key_base64(&body),
            Some(PEER_KEY_B64.to_string())
        );
    }

    #[test]
    fn first_peer_public_key_base64_none_when_no_peer() {
        let body = format!("[Interface]\nPrivateKey = {IFACE_KEY_B64}\n");
        assert_eq!(first_peer_public_key_base64(&body), None);
    }

    #[test]
    fn first_peer_public_key_base64_picks_first_of_many() {
        let body = format!(
            "[Interface]\nPrivateKey = {IFACE_KEY_B64}\n[Peer]\nPublicKey = {PEER_KEY_B64}\n[Peer]\nPublicKey = {IFACE_KEY_B64}\n"
        );
        // Matches the legacy extract_peer_public_key: first [Peer] wins.
        assert_eq!(
            first_peer_public_key_base64(&body),
            Some(PEER_KEY_B64.to_string())
        );
    }
}
