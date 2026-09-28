//! System theme polling — applies macOS light/dark mode to egui.
//!
//! `dark-light` returns a cached mode that we re-check every 5 s and push
//! into `egui::Context::set_visuals` only on change. A 1 s poll measured
//! as idle wakeups for no user-visible benefit — theme switches are rare
//! and still apply within 5 s.

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
        if self.last_check.elapsed() < Duration::from_secs(5) {
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
