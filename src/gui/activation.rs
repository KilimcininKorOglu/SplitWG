//! NSApp activation policy — keeps SplitWG out of the Dock.
//!
//! `Info.plist` already sets `LSUIElement=true`, which is the primary
//! guarantee that the app launches as a menu-bar-only agent. This runtime
//! call is a second belt for binaries that bypass the Info.plist lookup
//! (e.g. `cargo run` without `make bundle`).

use objc2::rc::autoreleasepool;
use objc2::MainThreadMarker;
use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};

/// Sets the running NSApp to `.Accessory` so no Dock icon appears when the
/// main eframe window is visible. Must be called from the main thread before
/// eframe opens its first viewport.
pub fn set_accessory() {
    autoreleasepool(|_| {
        let Some(mtm) = MainThreadMarker::new() else {
            log::warn!("gui: activation: set_accessory called off the main thread");
            return;
        };
        let app = NSApplication::sharedApplication(mtm);
        app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    });
}
