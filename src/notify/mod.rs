//! Native platform notifications.

#[cfg(target_os = "macos")]
mod notify_darwin;
#[cfg(target_os = "macos")]
pub use notify_darwin::{error, info};

#[cfg(target_os = "windows")]
mod notify_windows;
#[cfg(target_os = "windows")]
pub use notify_windows::{error, info};

#[cfg(target_os = "linux")]
mod notify_linux;
#[cfg(target_os = "linux")]
pub use notify_linux::{error, info};
