//! "Launch at login" toggle backed by `SMAppService.mainApp`.
//!
//! Uses the `smappservice-rs` wrapper so we do not hand-roll `msg_send!` for
//! the ServiceManagement framework. Requires macOS 13+ (enforced via the
//! deployment target set in `.cargo/config.toml`).

use smappservice_rs::{AppService, ServiceStatus, ServiceType};

/// Current state of the login-item registration, mapped to a non-repr-based
/// enum so the rest of the app does not depend on `smappservice_rs` types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginItemState {
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
}

impl From<ServiceStatus> for LoginItemState {
    fn from(s: ServiceStatus) -> Self {
        match s {
            ServiceStatus::NotRegistered => LoginItemState::NotRegistered,
            ServiceStatus::Enabled => LoginItemState::Enabled,
            ServiceStatus::RequiresApproval => LoginItemState::RequiresApproval,
            ServiceStatus::NotFound => LoginItemState::NotFound,
        }
    }
}

fn service() -> AppService {
    AppService::new(ServiceType::MainApp)
}

/// Reads the current registration state.
pub fn status() -> LoginItemState {
    service().status().into()
}

pub fn register() -> Result<(), String> {
    service().register().map_err(|e| e.to_string())
}

pub fn unregister() -> Result<(), String> {
    service().unregister().map_err(|e| e.to_string())
}

/// Opens System Settings → General → Login Items so the user can approve a
/// pending registration.
pub fn open_login_items_settings() {
    AppService::open_system_settings_login_items();
}
