//! Three-tier privilege escalation (sudo -n → helper → osascript).
//!
//! Phase 2 contains a two-tier version (sudo -n → osascript). Phase 3a plugs
//! in `auth::setup::run_first_time_setup` to restore the three-tier chain.

use std::process::Command;

use super::WgError;

/// Homebrew directories (both Apple Silicon and Intel) plus system paths so
/// that `wg-quick` and its dependencies (bash 4+, `wg`, etc.) are found when
/// the app is launched via Launch Services, which provides only a minimal
/// `PATH`.
pub const BREW_PATH: &str = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin";

/// Prepends a `PATH` export so shell commands resolve the Homebrew binaries.
pub fn with_path(cmd: &str) -> String {
    format!("export PATH={}; {}", BREW_PATH, cmd)
}

/// Executes `shell_cmd` with root privileges.
///
/// Escalation order:
/// 1. `sudo -n sh -c <cmd>` (silent; works if NOPASSWD sudoers rule exists).
/// 2. `crate::auth::setup::run_first_time_setup()` (single password prompt) → retry `sudo -n`.
/// 3. Fallback to the native macOS password dialog via `osascript`.
pub fn run_as_admin(shell_cmd: &str) -> Result<(), WgError> {
    let patched = with_path(shell_cmd);

    if sudo_n(&patched).is_ok() {
        return Ok(());
    }

    log::warn!("sudo -n failed, attempting setup");

    match crate::auth::run_first_time_setup() {
        Ok(()) => {
            if sudo_n(&patched).is_ok() {
                return Ok(());
            }
            log::warn!("sudo -n still failed after setup, falling back to osascript");
        }
        Err(e) => {
            log::warn!("setup failed ({}), falling back to osascript", e);
        }
    }

    run_as_admin_osascript(&patched)
}

/// Runs `sh -c <cmd>` as root via `sudo -n` (non-interactive).
fn sudo_n(cmd: &str) -> Result<(), WgError> {
    let out = Command::new("sudo")
        .args(["-n", "sh", "-c", cmd])
        .output()
        .map_err(|e| WgError::Admin(format!("sudo -n spawn: {}", e)))?;
    if !out.status.success() {
        return Err(WgError::Admin(format!(
            "sudo -n failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Requests the password via the native macOS dialog.
///
/// The command is wrapped in `sh -c <shell_quoted>` so all shell
/// metacharacters (`$()`, backticks, `!`, etc.) are neutralized by
/// single-quote escaping. The AppleScript string only needs `\` and `"`
/// escaped for the outer literal.
pub fn run_as_admin_osascript(shell_cmd: &str) -> Result<(), WgError> {
    let quoted = super::shell_quote(shell_cmd);
    let inner = format!("sh -c {quoted}");
    let mut escaped = inner.replace('\\', "\\\\");
    escaped = escaped.replace('"', "\\\"");
    let script = format!(
        "do shell script \"{}\" with administrator privileges",
        escaped
    );
    let out = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| WgError::Admin(format!("osascript spawn: {}", e)))?;
    if !out.status.success() {
        return Err(WgError::Admin(format!(
            "osascript: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_path_prepends_brew_path() {
        assert_eq!(
            with_path("wg-quick up /tmp/x.conf"),
            format!("export PATH={}; wg-quick up /tmp/x.conf", BREW_PATH),
        );
    }
}
