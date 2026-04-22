//! Linux privilege setup — checks if the splitwg systemd service is running.

pub const SUDOERS_PATH: &str = "/etc/systemd/system/splitwg.service";

pub fn is_setup_done() -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "splitwg"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn run_first_time_setup() -> Result<(), String> {
    log::info!("splitwg: setup: checking systemd service");
    if is_setup_done() {
        return Ok(());
    }
    log::info!("splitwg: setup: service not running, attempting start");
    let status = std::process::Command::new("pkexec")
        .args(["systemctl", "enable", "--now", "splitwg"])
        .status()
        .map_err(|e| format!("pkexec systemctl: {e}"))?;
    if !status.success() {
        return Err("failed to enable splitwg service".to_string());
    }
    Ok(())
}
