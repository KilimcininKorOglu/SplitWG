//! Route-table side effects for a running tunnel.
//!
//! Mirrors `wg-quick`'s `set_routing_table_from_config`: every `AllowedIPs`
//! entry is pushed into the kernel as a route via the utun interface, with a
//! special case for `0.0.0.0/0` / `::/0` (split into two halves so the
//! original default route remains in the FIB and is used for the handshake).
//! In exclude mode, listed CIDRs are bypassed via the physical gateway.
//!
//! Every route added here is remembered; `Drop` removes them all, non-fatal.

use std::net::IpAddr;
use std::process::Command;

use anyhow::{bail, Context, Result};
use ipnet::IpNet;

const SPLIT_V4_A: &str = "0.0.0.0/1";
const SPLIT_V4_B: &str = "128.0.0.0/1";
const SPLIT_V6_A: &str = "::/1";
const SPLIT_V6_B: &str = "8000::/1";

pub struct Routes {
    iface: String,
    added: Vec<AddedRoute>,
}

struct AddedRoute {
    cidr: String,
    ipv6: bool,
}

impl Routes {
    pub fn new(iface: &str) -> Self {
        Self {
            iface: iface.to_string(),
            added: Vec::new(),
        }
    }

    /// AllowedIPs → utun routes. `0.0.0.0/0` and `::/0` are split into two
    /// halves so the kernel keeps the real default route (needed for
    /// handshake / endpoint traffic).
    pub fn apply_tunnel(&mut self, allowed_ips: &[IpNet]) -> Result<()> {
        eprintln!(
            "splitwg-helper: routing: applying {} tunnel route(s) via {}",
            allowed_ips.len(),
            self.iface
        );
        for net in allowed_ips {
            match net {
                IpNet::V4(v4) if v4.prefix_len() == 0 => {
                    eprintln!("splitwg-helper: routing: splitting 0.0.0.0/0 into {SPLIT_V4_A} + {SPLIT_V4_B}");
                    self.add_via_iface(SPLIT_V4_A, false)?;
                    self.add_via_iface(SPLIT_V4_B, false)?;
                }
                IpNet::V6(v6) if v6.prefix_len() == 0 => {
                    eprintln!(
                        "splitwg-helper: routing: splitting ::/0 into {SPLIT_V6_A} + {SPLIT_V6_B}"
                    );
                    self.add_via_iface(SPLIT_V6_A, true)?;
                    self.add_via_iface(SPLIT_V6_B, true)?;
                }
                other => {
                    eprintln!(
                        "splitwg-helper: routing: adding tunnel route {other} via {}",
                        self.iface
                    );
                    let ipv6 = matches!(other, IpNet::V6(_));
                    self.add_via_iface(&other.to_string(), ipv6)?;
                }
            }
        }
        eprintln!(
            "splitwg-helper: routing: {} tunnel route(s) added",
            self.added.len()
        );
        Ok(())
    }

    /// Route the peer endpoint via the physical gateway so WireGuard's own
    /// UDP packets don't recurse through the utun we just created.
    pub fn apply_endpoint_bypass(&mut self, endpoint_ip: IpAddr, gateway: IpAddr) -> Result<()> {
        eprintln!("splitwg-helper: routing: adding endpoint bypass for {endpoint_ip} via gateway {gateway}");
        let (spec, ipv6) = match endpoint_ip {
            IpAddr::V4(v4) => (format!("{v4}/32"), false),
            IpAddr::V6(v6) => (format!("{v6}/128"), true),
        };
        self.add_via_gateway(&spec, gateway, ipv6)?;
        eprintln!("splitwg-helper: routing: endpoint bypass route added");
        Ok(())
    }

    /// Exclude-mode bypass: listed CIDRs skip the tunnel.
    pub fn apply_exclude(&mut self, entries: &[IpNet], gateway: IpAddr) -> Result<()> {
        eprintln!(
            "splitwg-helper: routing: applying {} exclude route(s) via gateway {gateway}",
            entries.len()
        );
        for net in entries {
            eprintln!("splitwg-helper: routing: adding exclude route {net} via {gateway}");
            let ipv6 = matches!(net, IpNet::V6(_));
            self.add_via_gateway(&net.to_string(), gateway, ipv6)?;
        }
        eprintln!("splitwg-helper: routing: exclude routes applied");
        Ok(())
    }

    fn add_via_iface(&mut self, cidr: &str, ipv6: bool) -> Result<()> {
        let family = if ipv6 { "-inet6" } else { "-net" };
        run("route", &["add", family, cidr, "-interface", &self.iface])
            .with_context(|| format!("route add {cidr} -interface {}", self.iface))?;
        self.added.push(AddedRoute {
            cidr: cidr.to_string(),
            ipv6,
        });
        Ok(())
    }

    fn add_via_gateway(&mut self, cidr: &str, gw: IpAddr, ipv6: bool) -> Result<()> {
        let family = if ipv6 { "-inet6" } else { "-net" };
        let gw_str = gw.to_string();
        run("route", &["add", family, cidr, &gw_str])
            .with_context(|| format!("route add {cidr} {gw_str}"))?;
        self.added.push(AddedRoute {
            cidr: cidr.to_string(),
            ipv6,
        });
        Ok(())
    }

    pub fn cleanup(&mut self) {
        let count = self.added.len();
        if count == 0 {
            return;
        }
        eprintln!("splitwg-helper: routing: removing {count} route(s)");
        for r in std::mem::take(&mut self.added) {
            let family = if r.ipv6 { "-inet6" } else { "-net" };
            eprintln!("splitwg-helper: routing: deleting route {}", r.cidr);
            if let Err(e) = run("route", &["delete", family, &r.cidr]) {
                eprintln!("splitwg-helper: routing: route delete {}: {e}", r.cidr);
            }
        }
        eprintln!("splitwg-helper: routing: all routes removed");
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Ask the kernel which gateway + interface a destination would use.
/// Returns `Ok(Some(ip))` when a gateway is available, `Ok(None)` when the
/// route is directly attached (point-to-point / link-local), or `Err` on
/// `route(8)` failure.
pub fn lookup_gateway(dest: IpAddr) -> Result<Option<IpAddr>> {
    let family = if dest.is_ipv6() { "-inet6" } else { "-inet" };
    let dest_s = dest.to_string();
    let out = Command::new("route")
        .args(["-n", "get", family, &dest_s])
        .output()
        .context("spawn route get")?;
    if !out.status.success() {
        bail!(
            "route -n get: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("gateway:") {
            let ip = rest.trim().parse::<IpAddr>().ok();
            return Ok(ip);
        }
    }
    Ok(None)
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("spawn {cmd}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        bail!("{cmd} {}: {stderr}", args.join(" "));
    }
    Ok(())
}
