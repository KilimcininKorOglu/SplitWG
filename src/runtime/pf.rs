//! Kill-switch pf anchor — blocks all non-tunnel traffic while a tunnel
//! is active.
//!
//! The helper runs as root, so we can drive `pfctl` directly. We load a
//! single-level anchor named `splitwg/<iface>` with rules that allow only
//! egress through the tunnel interface and loopback, blocking everything
//! else on IPv4 and IPv6. The anchor is torn down in `Drop` so a normal
//! helper shutdown cleans up automatically.
//!
//! Crash-safety: `preemptive_flush` is invoked from the helper's `main()`
//! before it opens any stdin/stdout, so a crashed previous helper's anchor
//! is wiped before the next tunnel comes up. Without this, a SIGKILL'd
//! helper would leave the machine unable to reach anything on the current
//! interface.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};

/// Top-level anchor name. Per-tunnel sub-anchors are `splitwg/<iface>`,
/// so a blanket flush of `splitwg` (via [`preemptive_flush`]) clears every
/// sub-anchor in one shot without touching the user's main ruleset.
pub const ANCHOR_ROOT: &str = "splitwg";

/// Pre-built rule text for a tunnel. `iface` is interpolated into the
/// `pass out quick on <iface>` clause. Kept as a pure helper so it can be
/// unit-tested without touching `pfctl`.
pub fn rules_for_iface(iface: &str) -> String {
    format!(
        "pass out quick on {iface} all\n\
         pass out quick on lo0 all\n\
         block drop out inet all\n\
         block drop out inet6 all\n"
    )
}

/// Fully-qualified anchor path for a specific tunnel interface.
pub fn anchor_name_for(iface: &str) -> String {
    format!("{ANCHOR_ROOT}/{iface}")
}

/// One kill-switch anchor, scoped to a single helper's tunnel. Dropping the
/// value flushes the anchor; if the helper is SIGKILLed the anchor leaks
/// and is cleaned up by [`preemptive_flush`] on the next helper boot.
pub struct PfAnchor {
    anchor: String,
    #[allow(dead_code)]
    iface: String,
}

impl PfAnchor {
    /// Loads the kill-switch anchor for `iface`. Returns an error if the
    /// `pfctl` binary is missing or rejects the rule text. Enables pf if it
    /// was previously disabled — we explicitly do NOT rewrite the main
    /// ruleset, so any other pf rules the user has configured remain in
    /// place alongside our anchor.
    pub fn load(iface: &str) -> Result<Self> {
        eprintln!("splitwg-helper: pf: enabling pf via pfctl -E");
        let _ = Command::new("pfctl").arg("-E").output();

        let anchor = anchor_name_for(iface);
        let rules = rules_for_iface(iface);
        eprintln!("splitwg-helper: pf: loading anchor {anchor} via pfctl -a {anchor} -f -");
        let mut child = Command::new("pfctl")
            .args(["-a", &anchor, "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn pfctl -a ... -f -")?;
        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| anyhow!("pfctl stdin unavailable"))?;
            stdin
                .write_all(rules.as_bytes())
                .context("write pf rules to pfctl stdin")?;
        }
        let output = child.wait_with_output().context("wait pfctl")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            bail!("pfctl anchor load failed: {stderr}");
        }
        eprintln!("splitwg-helper: pf: anchor {anchor} loaded successfully");
        Ok(PfAnchor {
            anchor,
            iface: iface.to_string(),
        })
    }

    /// Flushes this anchor's rules. Safe to call multiple times; subsequent
    /// calls no-op. Invoked from `Drop` on the tunnel teardown path.
    pub fn unload(&self) {
        eprintln!("splitwg-helper: pf: unloading anchor {}", self.anchor);
        let status = Command::new("pfctl")
            .args(["-a", &self.anchor, "-F", "all"])
            .output();
        match status {
            Ok(o) if o.status.success() => {
                eprintln!("splitwg-helper: pf: anchor {} flushed successfully", self.anchor);
            }
            Ok(o) => {
                eprintln!(
                    "splitwg-helper: pf: flush {} failed: {}",
                    self.anchor,
                    String::from_utf8_lossy(&o.stderr)
                );
            }
            Err(e) => eprintln!("splitwg-helper: pf: flush {} error: {e}", self.anchor),
        }
    }
}

impl Drop for PfAnchor {
    fn drop(&mut self) {
        self.unload();
    }
}

/// Wipes every `splitwg/*` anchor. Called once at helper startup so a
/// previous helper that crashed (SIGKILL, panic) cannot leave the machine
/// offline via a stale kill-switch anchor. Non-fatal if pfctl isn't
/// available — the next `load` will surface any real failure.
pub fn preemptive_flush() {
    eprintln!("splitwg-helper: pf: preemptive flush of all {ANCHOR_ROOT}/* anchors");
    let result = Command::new("pfctl")
        .args(["-a", ANCHOR_ROOT, "-F", "all"])
        .output();
    match result {
        Ok(o) if o.status.success() => {
            eprintln!("splitwg-helper: pf: preemptive flush completed");
        }
        Ok(_) => {
            eprintln!("splitwg-helper: pf: preemptive flush returned non-zero (no stale anchors or pf disabled)");
        }
        Err(e) => {
            eprintln!("splitwg-helper: pf: preemptive flush failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_interpolate_iface_name() {
        let text = rules_for_iface("utun7");
        assert!(text.contains("pass out quick on utun7 all"));
        assert!(text.contains("pass out quick on lo0 all"));
        assert!(text.contains("block drop out inet all"));
        assert!(text.contains("block drop out inet6 all"));
    }

    #[test]
    fn anchor_name_uses_scoped_prefix() {
        assert_eq!(anchor_name_for("utun3"), "splitwg/utun3");
    }
}
