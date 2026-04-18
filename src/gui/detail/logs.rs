//! Logs tab — renders the last N lines of `splitwg.log` with an optional
//! per-tunnel filter.

use crate::i18n;

use crate::gui::log_tail::LogTail;

pub struct LogsTabState {
    pub filter_current_only: bool,
}

impl Default for LogsTabState {
    fn default() -> Self {
        Self {
            filter_current_only: true,
        }
    }
}

pub fn show(
    ui: &mut egui::Ui,
    tail: &LogTail,
    state: &mut LogsTabState,
    selected_tunnel: Option<&str>,
) {
    ui.horizontal(|ui| {
        ui.checkbox(
            &mut state.filter_current_only,
            i18n::t("gui.logs.filter_this"),
        );
        ui.separator();
        ui.label(
            egui::RichText::new(i18n::t("gui.logs.hint"))
                .small()
                .color(egui::Color32::DARK_GRAY),
        );
    });

    ui.separator();

    let needle = if state.filter_current_only {
        selected_tunnel
    } else {
        None
    };
    let lines = tail.snapshot(needle);

    egui::ScrollArea::vertical()
        .stick_to_bottom(true)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if lines.is_empty() {
                ui.label(i18n::t("gui.logs.empty"));
                return;
            }
            for line in lines {
                ui.monospace(line);
            }
        });
}
