//! Sudoers rule installation for SplitWG 2.0.
//!
//! The tray spawns `splitwg-helper` via `sudo -n`; the one-time rule below
//! grants passwordless root *only* for that exact binary path. Route / DNS /
//! `sh` are no longer whitelisted — all privileged work now runs inside the
//! helper process after escalation.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The one-time NOPASSWD rule lives here. Root-owned, mode 0440; not
/// user-readable — we rely on `Path::exists` (stat) to probe for it.
pub const SUDOERS_PATH: &str = "/etc/sudoers.d/splitwg";

/// Reports whether the sudoers rule is already installed.
pub fn is_setup_done() -> bool {
    Path::new(SUDOERS_PATH).exists()
}

/// Builds the sudoers rule text for `helper_path`. Kept as a pure function so
/// it can be unit-tested without invoking osascript.
pub fn sudoers_rule(helper_path: &Path) -> String {
    format!(
        "%admin ALL=(ALL) NOPASSWD: {}",
        helper_path.display()
    )
}

/// Installs the sudoers rule via a one-time password prompt.
///
/// Uses `echo` (not `printf`) — otherwise the literal `%` in `%admin` would be
/// interpreted by the shell/printf format.
pub fn run_first_time_setup() -> Result<(), String> {
    let helper = locate_helper()?;
    let rule = sudoers_rule(&helper);
    let script = format!(
        "do shell script \"echo '{rule}' > {path} && chmod 440 {path}\" with administrator privileges",
        path = SUDOERS_PATH,
    );
    let out = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| format!("setup failed: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "setup failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Finds the helper binary so the sudoers rule pins a real path. Production
/// path: sibling of the tray binary in the .app bundle. Dev path: the Cargo
/// `target/{debug,release}/splitwg-helper` fallback, or the `SPLITWG_HELPER`
/// env override.
fn locate_helper() -> Result<PathBuf, String> {
    if let Ok(env) = std::env::var("SPLITWG_HELPER") {
        let p = PathBuf::from(env);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("splitwg-helper");
            if candidate.is_file() {
                return candidate
                    .canonicalize()
                    .map_err(|e| format!("canonicalize helper path: {e}"));
            }
        }
    }
    if let Some(manifest) = option_env!("CARGO_MANIFEST_DIR") {
        for profile in ["release", "debug"] {
            let p = Path::new(manifest)
                .join("target")
                .join(profile)
                .join("splitwg-helper");
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    Err("splitwg-helper binary not found next to splitwg".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudoers_path_uses_splitwg_name() {
        assert!(SUDOERS_PATH.ends_with("/splitwg"));
    }

    #[test]
    fn sudoers_rule_pins_helper_path() {
        let rule = sudoers_rule(Path::new("/Applications/SplitWG.app/Contents/MacOS/splitwg-helper"));
        assert_eq!(
            rule,
            "%admin ALL=(ALL) NOPASSWD: /Applications/SplitWG.app/Contents/MacOS/splitwg-helper"
        );
    }

    #[test]
    fn sudoers_rule_has_no_shell_escape() {
        // No `/bin/sh`, no wildcards — only the pinned helper path.
        let rule = sudoers_rule(Path::new("/tmp/splitwg-helper"));
        assert!(!rule.contains("/bin/sh"));
        assert!(!rule.contains("*"));
    }
}
