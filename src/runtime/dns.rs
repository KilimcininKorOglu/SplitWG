//! macOS DNS integration via `scutil` dynamic store.
//!
//! Each tunnel owns a `State:/Network/Service/com.kilimcininkoroglu.splitwg-<iface>/DNS`
//! entry. `scutil` is fed a small script on stdin:
//!
//! ```text
//! d.init
//! d.add ServerAddresses * 1.1.1.1 1.0.0.1
//! set State:/Network/Service/com.kilimcininkoroglu.splitwg-utun4/DNS
//! quit
//! ```
//!
//! On drop the `remove` command clears the key; some macOS versions evict it
//! on reboot anyway, but explicit cleanup is still preferred.

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

const KEY_PREFIX: &str = "State:/Network/Service/com.kilimcininkoroglu.splitwg-";

pub struct Dns {
    key: Option<String>,
}

impl Dns {
    pub fn empty() -> Self {
        Self { key: None }
    }

    pub fn apply(iface: &str, servers: &[IpAddr]) -> Result<Self> {
        if servers.is_empty() {
            eprintln!("splitwg-helper: dns: no DNS servers specified, skipping");
            return Ok(Self::empty());
        }
        let key = format!("{KEY_PREFIX}{iface}/DNS");
        let servers_joined = servers
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        eprintln!("splitwg-helper: dns: applying servers [{servers_joined}] via scutil key {key}");
        let mut child = Command::new("scutil")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn scutil")?;
        {
            let stdin = child.stdin.as_mut().context("scutil stdin missing")?;
            writeln!(stdin, "d.init")?;
            writeln!(stdin, "d.add ServerAddresses * {servers_joined}")?;
            // Empty SupplementalMatchDomains makes this the DEFAULT resolver
            // for all domains. Without it, macOS treats the entry as
            // supplemental and keeps using the (now unreachable) en0 DNS.
            writeln!(stdin, "d.add SupplementalMatchDomains * \"\"")?;
            writeln!(stdin, "set {key}")?;
            writeln!(stdin, "quit")?;
        }
        let out = child.wait_with_output().context("wait scutil")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            bail!("scutil exited {}: {stderr}", out.status);
        }
        eprintln!("splitwg-helper: dns: applied successfully");
        Ok(Self { key: Some(key) })
    }

    pub fn remove(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        eprintln!("splitwg-helper: dns: removing scutil key {key}");
        let child = Command::new("scutil")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else {
            eprintln!("splitwg-helper: dns: failed to spawn scutil for removal");
            return;
        };
        if let Some(stdin) = child.stdin.as_mut() {
            let _ = writeln!(stdin, "remove {key}");
            let _ = writeln!(stdin, "quit");
        }
        let _ = child.wait();
        eprintln!("splitwg-helper: dns: removed successfully");
    }
}

impl Drop for Dns {
    fn drop(&mut self) {
        self.remove();
    }
}
