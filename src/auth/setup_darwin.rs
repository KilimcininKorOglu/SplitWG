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
    let exists = Path::new(SUDOERS_PATH).exists();
    if exists {
        log::info!("splitwg: setup: sudoers rule exists at {}", SUDOERS_PATH);
    } else {
        log::info!("splitwg: setup: sudoers rule missing at {}", SUDOERS_PATH);
    }
    exists
}

pub fn sudoers_rule(helper_path: &Path) -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    format!("{user} ALL=(ALL) NOPASSWD: {}", helper_path.display())
}

/// Installs the sudoers rule via a one-time password prompt.
///
/// Uses `echo` (not `printf`) to avoid shell format-string interpretation.
pub fn run_first_time_setup() -> Result<(), String> {
    log::info!("splitwg: setup: starting first-time setup");
    let helper = locate_helper()?;
    log::info!("splitwg: setup: helper located at {}", helper.display());
    let rule = sudoers_rule(&helper);
    let escaped_rule = crate::wg::shell_quote(&rule);
    let script = format!(
        "do shell script \"printf '%s\\n' {escaped_rule} > {path} && chmod 440 {path}\" with administrator privileges",
        path = SUDOERS_PATH,
    );
    log::info!("splitwg: setup: invoking osascript for sudoers installation");
    let out = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| {
            log::error!("splitwg: setup: osascript invocation failed: {}", e);
            format!("setup failed: {}", e)
        })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        log::error!("splitwg: setup: osascript failed: {}", stderr);
        return Err(format!("setup failed: {}", stderr));
    }
    log::info!("splitwg: setup: first-time setup completed successfully");
    Ok(())
}

/// Finds the helper binary so the sudoers rule pins a real path. Production
/// path: sibling of the tray binary in the .app bundle. Dev path: the Cargo
/// `target/{debug,release}/splitwg-helper` fallback, or the `SPLITWG_HELPER`
/// env override.
fn locate_helper() -> Result<PathBuf, String> {
    if let Ok(env) = std::env::var("SPLITWG_HELPER") {
        log::info!("splitwg: setup: trying SPLITWG_HELPER env: {}", env);
        let p = PathBuf::from(&env);
        if p.is_file() {
            log::info!("splitwg: setup: found helper via env override");
            return p
                .canonicalize()
                .map_err(|e| format!("canonicalize env helper path: {e}"));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("splitwg-helper");
            log::info!(
                "splitwg: setup: trying sibling path {}",
                candidate.display()
            );
            if candidate.is_file() {
                log::info!("splitwg: setup: found helper as sibling of executable");
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
            log::info!("splitwg: setup: trying cargo target path {}", p.display());
            if p.is_file() {
                log::info!("splitwg: setup: found helper in cargo target/{}", profile);
                return Ok(p);
            }
        }
    }
    log::error!("splitwg: setup: helper binary not found in any search path");
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
        let rule = sudoers_rule(Path::new(
            "/Applications/SplitWG.app/Contents/MacOS/splitwg-helper",
        ));
        let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
        assert_eq!(
            rule,
            format!("{user} ALL=(ALL) NOPASSWD: /Applications/SplitWG.app/Contents/MacOS/splitwg-helper")
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
