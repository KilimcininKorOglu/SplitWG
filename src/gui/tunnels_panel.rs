//! Left panel — tunnel list with live status dot + bottom action bar.

use std::collections::HashMap;

use crate::config::Config;
use crate::i18n;
use crate::wg;

use crate::gui::wg_stat::WgStats;

/// Renders the tunnel list. Returns an action emitted this frame (bottom
/// bar buttons) so the caller can dispatch to the correct flow.
pub fn show(
    ui: &mut egui::Ui,
    configs: &[Config],
    selected: &mut Option<String>,
    mgr: &wg::Manager,
    stats: &HashMap<String, WgStats>,
) -> PanelEvent {
    let mut event = PanelEvent::None;

    egui::TopBottomPanel::bottom("tunnels_bottom_bar")
        .resizable(false)
        .show_inside(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.menu_button(i18n::t("gui.tunnels.add"), |ui| {
                    if ui.button(i18n::t("gui.tunnels.add_menu.file")).clicked() {
                        event = PanelEvent::AddConfig;
                        ui.close_menu();
                    }
                    if ui
                        .button(i18n::t("gui.tunnels.add_menu.qr_file"))
                        .clicked()
                    {
                        event = PanelEvent::AddConfigQrFile;
                        ui.close_menu();
                    }
                    if ui
                        .button(i18n::t("gui.tunnels.add_menu.qr_clipboard"))
                        .clicked()
                    {
                        event = PanelEvent::AddConfigQrClipboard;
                        ui.close_menu();
                    }
                });
                let delete_enabled = selected.is_some();
                if ui
                    .add_enabled(
                        delete_enabled,
                        egui::Button::new(i18n::t("gui.tunnels.delete")),
                    )
                    .clicked()
                {
                    event = PanelEvent::DeleteSelected;
                }
                if ui
                    .button(i18n::t("gui.tunnels.preferences"))
                    .clicked()
                {
                    event = PanelEvent::OpenPreferences;
                }
            });
            ui.add_space(4.0);
        });

    egui::CentralPanel::default().show_inside(ui, |ui| {
        ui.heading(i18n::t("gui.tunnels.header"));
        ui.separator();

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if configs.is_empty() {
                    ui.add_space(12.0);
                    ui.label(i18n::t("gui.tunnels.empty"));
                    return;
                }
                for cfg in configs {
                    let is_active = mgr.is_active(&cfg.name)
;
                    let dot_color = if is_active {
                        egui::Color32::from_rgb(80, 180, 100)
                    } else {
                        egui::Color32::GRAY
                    };

                    let is_selected = selected.as_deref() == Some(cfg.name.as_str());

                    let response = ui.horizontal(|ui| {
                        ui.colored_label(dot_color, "●");
                        ui.selectable_label(is_selected, &cfg.name)
                    });

                    if response.inner.clicked() {
                        *selected = Some(cfg.name.clone());
                    }

                    if is_active {
                        if let Some(peer) = stats
                            .get(&cfg.name)
                            .and_then(|s| s.peers.first())
                            .filter(|p| p.last_handshake.is_some())
                        {
                            let age = crate::gui::wg_stat::humanize_handshake(
                                peer.last_handshake.unwrap(),
                            );
                            ui.horizontal(|ui| {
                                ui.add_space(18.0);
                                ui.label(
                                    egui::RichText::new(age)
                                        .small()
                                        .color(egui::Color32::DARK_GRAY),
                                );
                            });
                        }
                    }
                }
            });
    });

    event
}

pub enum PanelEvent {
    None,
    AddConfig,
    AddConfigQrFile,
    AddConfigQrClipboard,
    DeleteSelected,
    OpenPreferences,
}
