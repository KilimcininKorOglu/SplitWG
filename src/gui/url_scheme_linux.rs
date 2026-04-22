//! URL scheme registration for `x-splitwg://` on Linux.
//!
//! Stub — XDG desktop entry registration will be implemented in a future
//! phase. The functions mirror `url_scheme_windows.rs` for API parity.

pub fn is_registered() -> bool {
    false
}

pub fn register() -> Result<(), String> {
    log::info!("splitwg: url_scheme: Linux registration not yet implemented");
    Ok(())
}

pub fn unregister() -> Result<(), String> {
    log::info!("splitwg: url_scheme: Linux unregistration not yet implemented");
    Ok(())
}
