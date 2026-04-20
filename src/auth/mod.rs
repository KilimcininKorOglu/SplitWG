//! Biometric authentication and privilege setup.

pub mod touchid;
pub use touchid::AuthResult;

#[cfg(target_os = "macos")]
mod setup_darwin;
#[cfg(target_os = "macos")]
pub use setup_darwin::{is_setup_done, run_first_time_setup, SUDOERS_PATH};

#[cfg(target_os = "windows")]
mod setup_windows;
#[cfg(target_os = "windows")]
pub use setup_windows::{is_setup_done, run_first_time_setup, SUDOERS_PATH};

#[cfg(target_os = "macos")]
mod touchid_darwin;
#[cfg(target_os = "macos")]
pub use touchid_darwin::authenticate;

#[cfg(target_os = "windows")]
mod hello_windows;
#[cfg(target_os = "windows")]
pub use hello_windows::authenticate;
