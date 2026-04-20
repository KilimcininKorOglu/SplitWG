//! eframe-based GUI — tray host + Manage Tunnels window.
//!
//! Entry point: [`run`]. Invoked from `main.rs` in place of the old
//! `ui::run_tray`. Owns the single NSApp/winit event loop for the whole
//! process; the tray menu is polled from within `App::update`.

#[cfg(target_os = "macos")]
pub mod activation;
pub mod app;
pub mod detail;
pub mod detail_panel;
pub mod geodb;
pub mod log_tail;
#[cfg(target_os = "macos")]
pub mod login_item;
#[cfg(target_os = "windows")]
#[path = "login_item_windows.rs"]
pub mod login_item;
pub mod modals;
pub mod network_monitor;
pub mod package;
pub mod qr;
pub mod sparkline;
pub mod tasks;
pub mod theme;
pub mod tray_host;
pub mod tunnels_panel;
pub mod update;
pub mod url_scheme;
#[cfg(target_os = "windows")]
pub mod url_scheme_windows;
pub mod validation;
pub mod wg_stat;

use crate::i18n;

/// Starts the eframe native event loop. Blocks the calling (main) thread
/// until the app exits. The window boots hidden — the tray is the canonical
/// entry point; users must pick "Manage Tunnels…" to reveal it.
pub fn run() -> eframe::Result<()> {
    // Set the activation policy BEFORE eframe opens a viewport so the Dock
    // never flashes a bouncing icon. `LSUIElement=true` in Info.plist is
    // the primary guarantee; this runtime call backs it up for `cargo run`.
    activation::set_accessory();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(i18n::t("gui.window.title"))
            .with_inner_size([960.0, 600.0])
            .with_min_inner_size([720.0, 440.0])
            .with_visible(false),
        persist_window: true,
        ..Default::default()
    };

    eframe::run_native(
        "SplitWG",
        options,
        Box::new(|cc| {
            let app = app::App::new(cc)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::<dyn std::error::Error + Send + Sync>::from(e.to_string())
                })?;
            Ok(Box::new(app))
        }),
    )
}
