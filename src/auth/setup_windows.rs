//! Windows privilege setup — service installation check and trigger.
//!
//! On Windows, privilege escalation is handled by the Windows Service running
//! as SYSTEM. The "setup" step is ensuring the service is installed and running.

pub const SUDOERS_PATH: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\splitwg";

pub fn is_setup_done() -> bool {
    crate::service::is_installed()
}

pub fn run_first_time_setup() -> Result<(), String> {
    log::info!("splitwg: setup: installing Windows service");
    crate::service::install()?;

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let status = Command::new("sc")
            .args(["start", "splitwg"])
            .status()
            .map_err(|e| format!("failed to start service: {e}"))?;
        if !status.success() {
            return Err(format!("sc start failed: {status}"));
        }
    }

    log::info!("splitwg: setup: service installed and started");
    Ok(())
}
