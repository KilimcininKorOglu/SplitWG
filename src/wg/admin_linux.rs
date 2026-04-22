//! Privilege escalation stubs for Linux.
//!
//! On Linux the service model (`splitwg-svc`) handles all privileged
//! operations via Unix domain socket IPC. Direct admin escalation from
//! the GUI is not needed. These stubs exist for API parity with
//! `admin_darwin.rs`.

use super::WgError;

pub const BREW_PATH: &str = "";

pub fn with_path(cmd: &str) -> String {
    cmd.to_string()
}

pub fn run_as_admin(_cmd: &str) -> Result<(), WgError> {
    Err(WgError::Admin(
        "direct admin escalation not available on Linux".into(),
    ))
}

pub fn run_as_admin_osascript(_cmd: &str) -> Result<(), WgError> {
    Err(WgError::Admin("osascript not available on Linux".into()))
}
