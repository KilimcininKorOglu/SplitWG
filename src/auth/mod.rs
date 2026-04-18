//! Touch ID authentication and sudoers-rule bootstrap.

pub mod touchid;
pub use touchid::AuthResult;

mod setup_darwin;
pub use setup_darwin::{is_setup_done, run_first_time_setup, SUDOERS_PATH};

mod touchid_darwin;
pub use touchid_darwin::authenticate;
