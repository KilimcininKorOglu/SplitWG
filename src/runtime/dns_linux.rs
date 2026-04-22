//! Linux DNS integration via systemd-resolved, resolvconf, or direct /etc/resolv.conf.

use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

enum Backend {
    SystemdResolved,
    Resolvconf,
    Direct,
}

pub struct Dns {
    iface: Option<String>,
    backend: Backend,
}

impl Dns {
    pub fn empty() -> Self {
        Self {
            iface: None,
            backend: Backend::Direct,
        }
    }

    pub fn apply(iface: &str, servers: &[IpAddr]) -> Result<Self> {
        if servers.is_empty() {
            return Ok(Self::empty());
        }
        let backend = detect_backend();
        let mut dns = Self {
            iface: Some(iface.to_string()),
            backend,
        };
        dns.apply_inner(iface, servers)?;
        Ok(dns)
    }

    fn apply_inner(&self, iface: &str, servers: &[IpAddr]) -> Result<()> {
        match self.backend {
            Backend::SystemdResolved => {
                let addrs: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
                let status = Command::new("resolvectl")
                    .arg("dns")
                    .arg(iface)
                    .args(&addrs)
                    .status()
                    .context("resolvectl dns")?;
                if !status.success() {
                    bail!("resolvectl dns failed: {status}");
                }
                let _ = Command::new("resolvectl")
                    .args(["domain", iface, "~."])
                    .status();
                log::info!("dns: applied via systemd-resolved on {iface}");
            }
            Backend::Resolvconf => {
                let mut child = Command::new("resolvconf")
                    .args(["-a", &format!("{iface}.splitwg")])
                    .stdin(Stdio::piped())
                    .spawn()
                    .context("resolvconf")?;
                if let Some(stdin) = child.stdin.as_mut() {
                    for server in servers {
                        writeln!(stdin, "nameserver {server}")?;
                    }
                }
                child.wait()?;
                log::info!("dns: applied via resolvconf on {iface}");
            }
            Backend::Direct => {
                let _ = std::fs::copy("/etc/resolv.conf", "/etc/resolv.conf.splitwg.bak");
                let mut f = std::fs::File::create("/etc/resolv.conf")?;
                for server in servers {
                    writeln!(f, "nameserver {server}")?;
                }
                log::info!("dns: applied via direct /etc/resolv.conf");
            }
        }
        Ok(())
    }
}

impl Drop for Dns {
    fn drop(&mut self) {
        let Some(iface) = &self.iface else { return };
        match self.backend {
            Backend::SystemdResolved => {
                let _ = Command::new("resolvectl").args(["revert", iface]).status();
            }
            Backend::Resolvconf => {
                let _ = Command::new("resolvconf")
                    .args(["-d", &format!("{iface}.splitwg")])
                    .status();
            }
            Backend::Direct => {
                if Path::new("/etc/resolv.conf.splitwg.bak").exists() {
                    let _ = std::fs::copy("/etc/resolv.conf.splitwg.bak", "/etc/resolv.conf");
                    let _ = std::fs::remove_file("/etc/resolv.conf.splitwg.bak");
                }
            }
        }
    }
}

fn detect_backend() -> Backend {
    if Command::new("resolvectl")
        .arg("status")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        Backend::SystemdResolved
    } else if Path::new("/sbin/resolvconf").exists() || Path::new("/usr/sbin/resolvconf").exists() {
        Backend::Resolvconf
    } else {
        Backend::Direct
    }
}
