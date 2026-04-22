//! Route-table side effects for a running tunnel on Linux via `ip route`.

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
    added: Vec<String>,
}

impl Routes {
    pub fn new(iface: &str) -> Self {
        Self {
            iface: iface.to_string(),
            added: Vec::new(),
        }
    }

    pub fn apply_tunnel(&mut self, allowed_ips: &[IpNet]) -> Result<()> {
        eprintln!(
            "splitwg-svc: routing: applying {} tunnel route(s) via {}",
            allowed_ips.len(),
            self.iface
        );
        for net in allowed_ips {
            match net {
                IpNet::V4(v4) if v4.prefix_len() == 0 => {
                    self.add_dev(SPLIT_V4_A)?;
                    self.add_dev(SPLIT_V4_B)?;
                }
                IpNet::V6(v6) if v6.prefix_len() == 0 => {
                    self.add_dev(SPLIT_V6_A)?;
                    self.add_dev(SPLIT_V6_B)?;
                }
                other => {
                    self.add_dev(&other.to_string())?;
                }
            }
        }
        Ok(())
    }

    pub fn apply_endpoint_bypass(&mut self, endpoint_ip: IpAddr, gateway: IpAddr) -> Result<()> {
        let cidr = match endpoint_ip {
            IpAddr::V4(v4) => format!("{v4}/32"),
            IpAddr::V6(v6) => format!("{v6}/128"),
        };
        self.add_via(&cidr, gateway)
    }

    pub fn apply_exclude(&mut self, entries: &[IpNet], gateway: IpAddr) -> Result<()> {
        for net in entries {
            self.add_via(&net.to_string(), gateway)?;
        }
        Ok(())
    }

    pub fn cleanup(&mut self) {
        for cidr in self.added.drain(..) {
            let _ = Command::new("ip").args(["route", "delete", &cidr]).status();
        }
    }

    fn add_dev(&mut self, cidr: &str) -> Result<()> {
        run_ip(&["route", "add", cidr, "dev", &self.iface])?;
        self.added.push(cidr.to_string());
        Ok(())
    }

    fn add_via(&mut self, cidr: &str, gw: IpAddr) -> Result<()> {
        let gw_str = gw.to_string();
        run_ip(&["route", "add", cidr, "via", &gw_str])?;
        self.added.push(cidr.to_string());
        Ok(())
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        self.cleanup();
    }
}

pub fn lookup_gateway(_dest: IpAddr) -> Result<Option<IpAddr>> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("ip route show default")?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("default via ") {
            if let Some(gw) = rest.split_whitespace().next() {
                return Ok(gw.parse().ok());
            }
        }
    }
    Ok(None)
}

fn run_ip(args: &[&str]) -> Result<()> {
    let status = Command::new("ip")
        .args(args)
        .status()
        .with_context(|| format!("ip {}", args.join(" ")))?;
    if !status.success() {
        bail!("ip {} failed: {status}", args.join(" "));
    }
    Ok(())
}
