//! Embedded tray icon PNG bytes.

/// Returns the PNG bytes for the "connected" (green) tray icon.
pub fn connected() -> &'static [u8] {
    include_bytes!("../../icon/tray_connected.png")
}

/// Returns the PNG bytes for the "disconnected" (grey) tray icon.
pub fn disconnected() -> &'static [u8] {
    include_bytes!("../../icon/tray_disconnected.png")
}
