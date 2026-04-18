//! System theme polling — applies macOS light/dark mode to egui.
//!
//! `dark-light` 1.x returns a cached mode that we re-check once per second
//! and push into `egui::Context::set_visuals` only on change. Cheap — the
//! comparison is a single enum match and `set_visuals` is idempotent.

use std::time::{Duration, Instant};

pub struct ThemeState {
    last_check: Instant,
    last_mode: Option<dark_light::Mode>,
}

impl Default for ThemeState {
    fn default() -> Self {
        Self {
            last_check: Instant::now() - Duration::from_secs(10),
            last_mode: None,
        }
    }
}

impl ThemeState {
    /// Polls the system theme and applies it to the egui context when
    /// changed. Must be called on the UI thread from `App::update`.
    pub fn update(&mut self, ctx: &egui::Context) {
        if self.last_check.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_check = Instant::now();

        let mode = dark_light::detect();
        if self.last_mode == Some(mode) {
            return;
        }
        self.last_mode = Some(mode);

        let visuals = match mode {
            dark_light::Mode::Light => egui::Visuals::light(),
            dark_light::Mode::Dark | dark_light::Mode::Default => egui::Visuals::dark(),
        };
        ctx.set_visuals(visuals);
    }
}
