//! Native platform notifications.

#[cfg(target_os = "macos")]
mod notify_darwin;
#[cfg(target_os = "macos")]
pub use notify_darwin::{error, info};
