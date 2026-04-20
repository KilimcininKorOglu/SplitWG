//! Route-table side effects for a running tunnel on Windows.
//!
//! Uses `route add` / `route delete` commands. Same split-default-route
//! strategy as macOS: `0.0.0.0/0` becomes `0.0.0.0/1` + `128.0.0.0/1` so the
//! original default route remains for endpoint traffic.

use std::net::IpAddr;
use std::process::Command;

use anyhow::{bail, Context, Result};
use ipnet::IpNet;

const SPLIT_V4_A: &str = "0.0.0.0";
const SPLIT_V4_A_MASK: &str = "128.0.0.0";
const SPLIT_V4_B: &str = "128.0.0.0";
const SPLIT_V4_B_MASK: &str = "128.0.0.0";
const SPLIT_V6_A: &str = "::/1";
const SPLIT_V6_B: &str = "8000::/1";

pub struct Routes {
    iface_index: u32,
    added: Vec<AddedRoute>,
}

struct AddedRoute {
    dest: String,
    mask: String,
    ipv6: bool,
}

impl Routes {
    pub fn new(iface: &str) -> Self {
        let iface_index = iface.parse::<u32>().unwrap_or(0);
        Self {
            iface_index,
            added: Vec::new(),
        }
    }

    pub fn apply_tunnel(&mut self, allowed_ips: &[IpNet]) -> Result<()> {
        eprintln!(
            "splitwg-svc: routing: applying {} tunnel route(s) via if {}",
            allowed_ips.len(),
            self.iface_index
        );
        for net in allowed_ips {
            match net {
                IpNet::V4(v4) if v4.prefix_len() == 0 => {
                    self.add_v4(SPLIT_V4_A, SPLIT_V4_A_MASK)?;
                    self.add_v4(SPLIT_V4_B, SPLIT_V4_B_MASK)?;
                }
                IpNet::V6(v6) if v6.prefix_len() == 0 => {
                    self.add_v6(SPLIT_V6_A)?;
                    self.add_v6(SPLIT_V6_B)?;
                }
                IpNet::V4(v4) => {
                    let dest = v4.network().to_string();
                    let mask = v4.netmask().to_string();
                    self.add_v4(&dest, &mask)?;
                }
                IpNet::V6(_) => {
                    self.add_v6(&net.to_string())?;
                }
            }
        }
        Ok(())
    }

    pub fn apply_endpoint_bypass(&mut self, endpoint_ip: IpAddr, gateway: IpAddr) -> Result<()> {
        eprintln!("splitwg-svc: routing: endpoint bypass {endpoint_ip} via {gateway}");
        match endpoint_ip {
            IpAddr::V4(v4) => {
                let dest = v4.to_string();
                let gw = gateway.to_string();
                run_route(&["add", &dest, "mask", "255.255.255.255", &gw])?;
                self.added.push(AddedRoute {
                    dest,
                    mask: "255.255.255.255".to_string(),
                    ipv6: false,
                });
            }
            IpAddr::V6(v6) => {
                let spec = format!("{v6}/128");
                let gw = gateway.to_string();
                run_route(&["add", &spec, &gw])?;
                self.added.push(AddedRoute {
                    dest: spec,
                    mask: String::new(),
                    ipv6: true,
                });
            }
        }
        Ok(())
    }

    pub fn apply_exclude(&mut self, entries: &[IpNet], gateway: IpAddr) -> Result<()> {
        let gw = gateway.to_string();
        for net in entries {
            match net {
                IpNet::V4(v4) => {
                    let dest = v4.network().to_string();
                    let mask = v4.netmask().to_string();
                    run_route(&["add", &dest, "mask", &mask, &gw])?;
                    self.added.push(AddedRoute {
                        dest,
                        mask,
                        ipv6: false,
                    });
                }
                IpNet::V6(_) => {
                    let spec = net.to_string();
                    run_route(&["add", &spec, &gw])?;
                    self.added.push(AddedRoute {
                        dest: spec,
                        mask: String::new(),
                        ipv6: true,
                    });
                }
            }
        }
        Ok(())
    }

    pub fn cleanup(&mut self) {
        for route in self.added.drain(..) {
            if route.ipv6 {
                let _ = Command::new("route").args(["delete", &route.dest]).status();
            } else {
                let _ = Command::new("route")
                    .args(["delete", &route.dest, "mask", &route.mask])
                    .status();
            }
        }
    }

    fn add_v4(&mut self, dest: &str, mask: &str) -> Result<()> {
        let if_str = self.iface_index.to_string();
        run_route(&["add", dest, "mask", mask, "0.0.0.0", "if", &if_str])?;
        self.added.push(AddedRoute {
            dest: dest.to_string(),
            mask: mask.to_string(),
            ipv6: false,
        });
        Ok(())
    }

    fn add_v6(&mut self, spec: &str) -> Result<()> {
        let if_str = self.iface_index.to_string();
        run_route(&["-6", "add", spec, "if", &if_str])?;
        self.added.push(AddedRoute {
            dest: spec.to_string(),
            mask: String::new(),
            ipv6: true,
        });
        Ok(())
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        self.cleanup();
    }
}

pub fn lookup_gateway(_dest: IpAddr) -> Result<Option<IpAddr>> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop",
        ])
        .output()
        .context("failed to query default gateway")?;
    let gw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if gw.is_empty() {
        return Ok(None);
    }
    Ok(gw.parse().ok())
}

fn run_route(args: &[&str]) -> Result<()> {
    let status = Command::new("route")
        .args(args)
        .status()
        .with_context(|| format!("failed to run: route {}", args.join(" ")))?;
    if !status.success() {
        bail!("route {} failed: {status}", args.join(" "));
    }
    Ok(())
}
