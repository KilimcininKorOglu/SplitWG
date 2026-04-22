//! Windows DNS integration via `netsh` and NRPT (Name Resolution Policy Table).
//!
//! Sets per-interface DNS servers via `netsh interface ip set dns`, and adds
//! an NRPT catch-all rule so all system DNS queries route through the tunnel's
//! DNS servers (same function as macOS `SupplementalMatchDomains = ""`).

use std::net::IpAddr;
use std::process::Command;

use anyhow::{bail, Context, Result};

pub struct Dns {
    iface: Option<String>,
    nrpt_active: bool,
}

impl Dns {
    pub fn empty() -> Self {
        Self {
            iface: None,
            nrpt_active: false,
        }
    }

    pub fn apply(iface: &str, servers: &[IpAddr]) -> Result<Self> {
        let mut dns = Self::empty();
        dns.apply_inner(iface, servers)?;
        Ok(dns)
    }

    fn apply_inner(&mut self, iface: &str, servers: &[IpAddr]) -> Result<()> {
        if servers.is_empty() {
            return Ok(());
        }
        self.iface = Some(iface.to_string());

        let primary = servers[0].to_string();
        let status = Command::new("netsh")
            .args(["interface", "ip", "set", "dns", iface, "static", &primary])
            .status()
            .context("failed to run netsh set dns")?;
        if !status.success() {
            bail!("netsh set dns failed: {status}");
        }

        for server in servers.iter().skip(1) {
            let s = server.to_string();
            let status = Command::new("netsh")
                .args(["interface", "ip", "add", "dns", iface, &s])
                .status()
                .context("failed to run netsh add dns")?;
            if !status.success() {
                log::warn!("netsh add dns {s} failed: {status}");
            }
        }

        let dns_csv = servers
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let nrpt_cmd = format!("Add-DnsclientNrptRule -Namespace '.' -NameServers '{dns_csv}'");
        let status = Command::new("powershell")
            .args(["-NoProfile", "-Command", &nrpt_cmd])
            .status()
            .context("failed to add NRPT rule")?;
        if status.success() {
            self.nrpt_active = true;
        } else {
            log::warn!("NRPT rule add failed: {status}");
        }

        log::info!("dns: applied servers {dns_csv} on {iface}");
        Ok(())
    }
}

impl Drop for Dns {
    fn drop(&mut self) {
        if let Some(iface) = &self.iface {
            let _ = Command::new("netsh")
                .args(["interface", "ip", "set", "dns", iface, "dhcp"])
                .status();
        }
        if self.nrpt_active {
            let _ = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "Get-DnsclientNrptRule | Where-Object { $_.Namespace -eq '.' } | Remove-DnsclientNrptRule -Force",
                ])
                .status();
        }
    }
}
