//! Kill-switch via nftables (preferred) or iptables (fallback) on Linux.
//!
//! Creates a per-tunnel nftables table `splitwg_{iface}` with an output chain
//! that drops everything except tunnel + loopback + established traffic.
//! Cleanup on Drop removes the table atomically.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

pub struct NftAnchor {
    iface: String,
    use_nft: bool,
}

impl NftAnchor {
    pub fn load(iface: &str) -> Result<Self> {
        let use_nft = Command::new("nft")
            .arg("--version")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if use_nft {
            load_nft(iface)?;
        } else {
            load_iptables(iface)?;
        }

        eprintln!("splitwg-svc: nft: kill switch active for {iface}");
        Ok(Self {
            iface: iface.to_string(),
            use_nft,
        })
    }

    pub fn unload(&mut self) {
        if self.use_nft {
            unload_nft(&self.iface);
        } else {
            unload_iptables(&self.iface);
        }
    }
}

impl Drop for NftAnchor {
    fn drop(&mut self) {
        self.unload();
    }
}

pub fn preemptive_flush() {
    eprintln!("splitwg-svc: nft: flushing stale kill switch rules");
    if let Ok(output) = Command::new("nft").args(["list", "tables"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("splitwg_") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let _ = Command::new("nft")
                        .args(["delete", "table", parts[1], parts[2]])
                        .status();
                }
            }
        }
    }
    let _ = Command::new("iptables")
        .args(["-D", "OUTPUT", "-j", "SPLITWG"])
        .status();
    let _ = Command::new("iptables").args(["-F", "SPLITWG"]).status();
    let _ = Command::new("iptables").args(["-X", "SPLITWG"]).status();
}

fn load_nft(iface: &str) -> Result<()> {
    let rules = format!(
        r#"table inet splitwg_{iface} {{
    chain output {{
        type filter hook output priority 0; policy drop;
        oifname "{iface}" accept
        oifname "lo" accept
        ct state established,related accept
    }}
}}"#
    );
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .context("nft")?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(rules.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        bail!("nft load failed: {status}");
    }
    Ok(())
}

fn unload_nft(iface: &str) {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", &format!("splitwg_{iface}")])
        .status();
}

fn load_iptables(iface: &str) -> Result<()> {
    let chain = format!("SPLITWG_{}", iface.to_uppercase());
    run_ipt(&["-N", &chain])?;
    run_ipt(&["-A", &chain, "-o", iface, "-j", "ACCEPT"])?;
    run_ipt(&["-A", &chain, "-o", "lo", "-j", "ACCEPT"])?;
    run_ipt(&[
        "-A",
        &chain,
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ])?;
    run_ipt(&["-A", &chain, "-j", "DROP"])?;
    run_ipt(&["-I", "OUTPUT", "-j", &chain])?;
    Ok(())
}

fn unload_iptables(iface: &str) {
    let chain = format!("SPLITWG_{}", iface.to_uppercase());
    let _ = Command::new("iptables")
        .args(["-D", "OUTPUT", "-j", &chain])
        .status();
    let _ = Command::new("iptables").args(["-F", &chain]).status();
    let _ = Command::new("iptables").args(["-X", &chain]).status();
}

fn run_ipt(args: &[&str]) -> Result<()> {
    let status = Command::new("iptables")
        .args(args)
        .status()
        .with_context(|| format!("iptables {}", args.join(" ")))?;
    if !status.success() {
        bail!("iptables {} failed: {status}", args.join(" "));
    }
    Ok(())
}
