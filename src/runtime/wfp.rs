//! Kill-switch via Windows Filtering Platform (WFP).
//!
//! Equivalent to macOS pf anchor: blocks all non-tunnel egress while a tunnel
//! is active. Uses `netsh advfirewall` as a first implementation; a future
//! iteration may use the WFP API directly for atomic rule application.
//!
//! Cleanup: rules are removed on `Drop`. WFP sublayer rules persist across
//! process crashes if not explicitly removed — the service should call
//! `preemptive_flush()` on startup to clear stale rules from a previous crash.

use std::process::Command;

use anyhow::{bail, Context, Result};

const RULE_BLOCK: &str = "SplitWG-KillSwitch-Block";
const RULE_ALLOW_TUNNEL: &str = "SplitWG-KillSwitch-Allow";
const RULE_ALLOW_LOOPBACK: &str = "SplitWG-KillSwitch-Loopback";

pub struct WfpAnchor {
    active: bool,
}

impl WfpAnchor {
    pub fn load(iface: &str) -> Result<Self> {
        eprintln!("splitwg-svc: wfp: loading kill switch for {iface}");

        run_netsh(&[
            "advfirewall", "firewall", "add", "rule",
            &format!("name={RULE_ALLOW_LOOPBACK}"),
            "dir=out", "action=allow", "interface=Loopback",
        ])?;

        run_netsh(&[
            "advfirewall", "firewall", "add", "rule",
            &format!("name={RULE_ALLOW_TUNNEL}"),
            "dir=out", "action=allow",
            &format!("interface={iface}"),
        ])?;

        run_netsh(&[
            "advfirewall", "firewall", "add", "rule",
            &format!("name={RULE_BLOCK}"),
            "dir=out", "action=block",
        ])?;

        eprintln!("splitwg-svc: wfp: kill switch active");
        Ok(Self { active: true })
    }

    pub fn unload(&mut self) {
        if !self.active {
            return;
        }
        eprintln!("splitwg-svc: wfp: removing kill switch rules");
        let _ = delete_rule(RULE_BLOCK);
        let _ = delete_rule(RULE_ALLOW_TUNNEL);
        let _ = delete_rule(RULE_ALLOW_LOOPBACK);
        self.active = false;
    }
}

impl Drop for WfpAnchor {
    fn drop(&mut self) {
        self.unload();
    }
}

pub fn preemptive_flush() {
    eprintln!("splitwg-svc: wfp: flushing stale kill switch rules");
    let _ = delete_rule(RULE_BLOCK);
    let _ = delete_rule(RULE_ALLOW_TUNNEL);
    let _ = delete_rule(RULE_ALLOW_LOOPBACK);
}

fn delete_rule(name: &str) -> Result<()> {
    run_netsh(&[
        "advfirewall", "firewall", "delete", "rule",
        &format!("name={name}"),
    ])
}

fn run_netsh(args: &[&str]) -> Result<()> {
    let status = Command::new("netsh")
        .args(args)
        .status()
        .with_context(|| format!("failed to run: netsh {}", args.join(" ")))?;
    if !status.success() {
        bail!("netsh {} failed: {status}", args.join(" "));
    }
    Ok(())
}
