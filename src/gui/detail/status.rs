//! Status tab — interface key + peer cards + live handshake/transfer.

use crate::config::Config;
use crate::i18n;
use crate::wg;

use crate::gui::app::PingDisplay;
use crate::gui::sparkline::{RttHistory, Sparkline, TransferHistory};
use crate::gui::wg_stat::{self, WgStats};

/// User actions the Status tab can emit this frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusEvent {
    None,
    /// Toggle the current tunnel: activate when inactive, deactivate when
    /// active. Callers are expected to route this through `tasks::spawn_toggle`.
    Toggle,
    /// Ping the peer at the given endpoint. Caller routes to `spawn_ping`.
    PingPeer { endpoint: String },
    /// Open the config editor modal for the selected tunnel.
    EditConfig,
    /// Rename the selected tunnel.
    Rename,
}

/// Renders the Status tab for the selected tunnel. Returns a `StatusEvent`
/// describing what the user clicked this frame; the caller spawns the
/// matching background task.
#[allow(clippy::too_many_arguments)]
pub fn show(
    ui: &mut egui::Ui,
    cfg: &Config,
    stats: Option<&WgStats>,
    history: Option<&TransferHistory>,
    ping: Option<&PingDisplay>,
    rtt: Option<&RttHistory>,
    is_active: bool,
    busy: bool,
) -> StatusEvent {
    let mut event = StatusEvent::None;

    ui.horizontal(|ui| {
        ui.heading(&cfg.name);
        ui.add_space(8.0);
        if is_active {
            ui.colored_label(
                egui::Color32::from_rgb(80, 180, 100),
                format!("● {}", i18n::t("gui.detail.status.active")),
            );
        } else {
            ui.colored_label(
                egui::Color32::GRAY,
                format!("○ {}", i18n::t("gui.detail.status.inactive")),
            );
        }
    });

    ui.add_space(4.0);
    ui.horizontal(|ui| {
        let label = if busy {
            if is_active {
                i18n::t_with("gui.detail.status.deactivating", &[("name", &cfg.name)])
            } else {
                i18n::t_with("gui.detail.status.activating", &[("name", &cfg.name)])
            }
        } else if is_active {
            i18n::t("gui.detail.status.deactivate")
        } else {
            i18n::t("gui.detail.status.activate")
        };
        if ui
            .add_enabled(!busy, egui::Button::new(label))
            .clicked()
        {
            event = StatusEvent::Toggle;
        }
        if ui
            .button(i18n::t("gui.detail.status.edit_config"))
            .clicked()
        {
            event = StatusEvent::EditConfig;
        }
        if ui
            .button(i18n::t("gui.detail.status.rename"))
            .clicked()
        {
            event = StatusEvent::Rename;
        }
    });

    ui.separator();

    // Parse the .conf body for Interface/Peer metadata. Failure to parse
    // is non-fatal — we render the raw file_path as fallback context.
    let parsed = std::fs::read_to_string(&cfg.file_path)
        .ok()
        .and_then(|body| wg::conf::parse(&body).ok());

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.group(|ui| {
            ui.heading(i18n::t("gui.detail.interface.title"));
            if let Some(ref parsed) = parsed {
                use base64::prelude::{Engine, BASE64_STANDARD};
                // The .conf ships the private key — derive and show the
                // public key instead (safer in a UI).
                let secret = x25519_dalek::StaticSecret::from(parsed.interface.private_key);
                let public = x25519_dalek::PublicKey::from(&secret);
                let public_b64 = BASE64_STANDARD.encode(public.to_bytes());
                labelled_row(ui, &i18n::t("gui.detail.interface.public_key"), &public_b64, true);

                let addrs = parsed
                    .interface
                    .addresses
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                labelled_row(ui, &i18n::t("gui.detail.interface.addresses"), &addrs, false);

                if !parsed.interface.dns.is_empty() {
                    let dns = parsed
                        .interface
                        .dns
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    labelled_row(ui, &i18n::t("gui.detail.interface.dns"), &dns, false);
                }

                let listen_port = stats
                    .and_then(|s| s.listen_port)
                    .or(parsed.interface.listen_port);
                if let Some(port) = listen_port {
                    labelled_row(
                        ui,
                        &i18n::t("gui.detail.interface.listen_port"),
                        &port.to_string(),
                        false,
                    );
                }
            } else {
                ui.label(cfg.file_path.to_string_lossy());
            }
        });

        ui.add_space(8.0);

        if let Some(ref parsed) = parsed {
            for (idx, peer) in parsed.peers.iter().enumerate() {
                use base64::prelude::{Engine, BASE64_STANDARD};
                let public_b64 = BASE64_STANDARD.encode(peer.public_key);
                let peer_stats = stats
                    .and_then(|s| s.peers.iter().find(|p| p.public_key == public_b64));

                ui.group(|ui| {
                    ui.heading(format!(
                        "{} #{}",
                        i18n::t("gui.detail.peer.title"),
                        idx + 1
                    ));

                    labelled_row(
                        ui,
                        &i18n::t("gui.detail.peer.public_key"),
                        &public_b64,
                        true,
                    );

                    let allowed = peer
                        .allowed_ips
                        .iter()
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    labelled_row(
                        ui,
                        &i18n::t("gui.detail.peer.allowed_ips"),
                        &allowed,
                        false,
                    );

                    let endpoint = peer_stats
                        .and_then(|s| s.endpoint.clone())
                        .or_else(|| peer.endpoint.map(|e| e.to_string()));
                    if let Some(endpoint) = endpoint.as_deref() {
                        labelled_row(
                            ui,
                            &i18n::t("gui.detail.peer.endpoint"),
                            endpoint,
                            false,
                        );
                    }

                    if let (true, Some(endpoint)) = (is_active, endpoint.clone()) {
                        if idx == 0 {
                            let inflight = ping.map(|p| p.inflight).unwrap_or(false);
                            ui.horizontal(|ui| {
                                let btn = ui.add_enabled(
                                    !inflight,
                                    egui::Button::new(i18n::t("gui.detail.peer.ping")),
                                );
                                if btn.clicked() {
                                    event = StatusEvent::PingPeer {
                                        endpoint: endpoint.clone(),
                                    };
                                }
                                if let Some(p) = ping {
                                    if p.inflight {
                                        ui.label(i18n::t(
                                            "gui.detail.peer.ping_inflight",
                                        ));
                                    } else if p.last_was_timeout {
                                        ui.colored_label(
                                            egui::Color32::from_rgb(220, 120, 120),
                                            i18n::t("gui.detail.peer.ping_timeout"),
                                        );
                                    } else if let Some(ms) = p.last_ms {
                                        let color = ping_color(ms);
                                        ui.colored_label(
                                            color,
                                            i18n::t_with(
                                                "gui.detail.peer.ping_result_ms",
                                                &[("ms", &ms.to_string())],
                                            ),
                                        );
                                    }
                                }
                            });
                            ui.label(
                                egui::RichText::new(i18n::t(
                                    "gui.detail.peer.ping_hint_note",
                                ))
                                .small()
                                .color(egui::Color32::DARK_GRAY),
                            );
                            if let Some(h) = rtt {
                                ui.add_space(4.0);
                                rtt_row(ui, h, ping);
                            }
                        }
                    }

                    let hs_text = match peer_stats.and_then(|s| s.last_handshake) {
                        Some(epoch) => wg_stat::humanize_handshake(epoch),
                        None => i18n::t("gui.detail.peer.never"),
                    };
                    labelled_row(
                        ui,
                        &i18n::t("gui.detail.peer.last_handshake"),
                        &hs_text,
                        false,
                    );

                    if let Some(ps) = peer_stats {
                        let transfer = format!(
                            "{}: {}   {}: {}",
                            i18n::t("gui.detail.peer.rx"),
                            wg_stat::humanize_bytes(ps.rx_bytes),
                            i18n::t("gui.detail.peer.tx"),
                            wg_stat::humanize_bytes(ps.tx_bytes),
                        );
                        labelled_row(
                            ui,
                            &i18n::t("gui.detail.peer.transfer"),
                            &transfer,
                            false,
                        );
                    }

                    // Sparkline is rendered once per tunnel (aggregate of
                    // all peers), so only draw it under the first peer card.
                    if idx == 0 {
                        if let Some(h) = history {
                            let (rx_rate, tx_rate) = h.latest();
                            ui.add_space(4.0);
                            throughput_row(
                                ui,
                                &i18n::t("gui.detail.peer.throughput_rx"),
                                &h.rx_samples,
                                rx_rate,
                                egui::Color32::from_rgb(80, 180, 100),
                            );
                            throughput_row(
                                ui,
                                &i18n::t("gui.detail.peer.throughput_tx"),
                                &h.tx_samples,
                                tx_rate,
                                egui::Color32::from_rgb(90, 150, 220),
                            );
                        }
                    }
                });
                ui.add_space(6.0);
            }
        }
    });

    event
}

/// Green for snappy RTT, amber for slow, red for very slow.
fn ping_color(ms: u32) -> egui::Color32 {
    if ms < 50 {
        egui::Color32::from_rgb(80, 180, 100)
    } else if ms < 200 {
        egui::Color32::from_rgb(220, 180, 80)
    } else {
        egui::Color32::from_rgb(220, 120, 120)
    }
}

/// Renders the RTT row: label + sparkline + current ms (or "timeout").
/// The sparkline colour tracks the latest successful reading; during a
/// timeout burst we fall back to grey so the colour doesn't lie.
fn rtt_row(ui: &mut egui::Ui, history: &RttHistory, ping: Option<&PingDisplay>) {
    // Prefer the in-flight PingDisplay for "is this currently timed out?"
    // so the label flips immediately on a fresh failure, even if history
    // still carries a successful `last_ms`.
    let live_timeout = ping.map(|p| p.last_was_timeout).unwrap_or(false)
        || history.last_was_timeout;
    let color = if live_timeout {
        egui::Color32::GRAY
    } else {
        match history.latest() {
            Some(ms) => ping_color(ms),
            None => egui::Color32::GRAY,
        }
    };

    ui.horizontal(|ui| {
        ui.add(egui::Label::new(
            egui::RichText::new(i18n::t("gui.detail.peer.rtt_label")).strong(),
        ));
        ui.add_space(4.0);
        Sparkline {
            values: &history.samples,
            size: egui::vec2(180.0, 18.0),
            color,
        }
        .show(ui);
        ui.add_space(4.0);
        if live_timeout {
            ui.colored_label(
                egui::Color32::from_rgb(220, 120, 120),
                i18n::t("gui.detail.peer.rtt_timeout"),
            );
        } else if let Some(ms) = history.latest() {
            ui.monospace(i18n::t_with(
                "gui.detail.peer.rtt_current_ms",
                &[("ms", &ms.to_string())],
            ));
        }
    });
    ui.label(
        egui::RichText::new(i18n::t("gui.detail.peer.rtt_hint"))
            .small()
            .color(egui::Color32::DARK_GRAY),
    );
}

/// Renders a throughput row: label + live sparkline + current bytes/sec.
fn throughput_row(
    ui: &mut egui::Ui,
    label: &str,
    samples: &std::collections::VecDeque<f32>,
    rate: f32,
    color: egui::Color32,
) {
    ui.horizontal(|ui| {
        ui.add(egui::Label::new(egui::RichText::new(label).strong()));
        ui.add_space(4.0);
        Sparkline {
            values: samples,
            size: egui::vec2(180.0, 18.0),
            color,
        }
        .show(ui);
        ui.add_space(4.0);
        ui.monospace(format!("{}/s", wg_stat::humanize_bytes(rate as u64)));
    });
}

/// Renders a `<label>: <value>` row with an optional copy button. The value
/// is selectable so the user can drag-select sub-portions of a long key.
fn labelled_row(ui: &mut egui::Ui, label: &str, value: &str, copyable: bool) {
    ui.horizontal(|ui| {
        ui.add(egui::Label::new(
            egui::RichText::new(label).strong(),
        ));
        ui.add_space(4.0);
        ui.add(
            egui::Label::new(egui::RichText::new(value).monospace()).wrap(),
        );
        if copyable
            && ui
                .add(egui::Button::new(i18n::t("gui.detail.copy")).small())
                .clicked()
        {
            ui.ctx().copy_text(value.to_string());
        }
    });
}
