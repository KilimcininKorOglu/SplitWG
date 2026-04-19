//! Right panel — tabbed detail view for the selected tunnel.

use std::collections::HashMap;

use crate::config::Config;
use crate::i18n;
use crate::wg;

use crate::config::Rules;

use crate::gui::app::PingDisplay;
use crate::gui::detail::logs::{self, LogsTabState};
use crate::gui::detail::rules::{self, RulesEvent, RulesTabState};
use crate::gui::detail::status::{self, StatusEvent};
use crate::gui::log_tail::LogTail;
use crate::gui::sparkline::{RttHistory, TransferHistory};
use crate::gui::wg_stat::WgStats;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DetailTab {
    #[default]
    Status,
    Rules,
    Logs,
}

/// Actions the detail pane wants to bubble up to `App::update`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetailEvent {
    None,
    ToggleTunnel(String),
    ApplyRules { name: String, rules: Rules },
    PingPeer { name: String, endpoint: String },
    EditConfig(String),
    Rename(String),
}

#[allow(clippy::too_many_arguments)]
pub fn show(
    ui: &mut egui::Ui,
    configs: &[Config],
    selected: &Option<String>,
    active_tab: &mut DetailTab,
    mgr: &wg::Manager,
    stats: &HashMap<String, WgStats>,
    transfer_history: &HashMap<String, TransferHistory>,
    ping_results: &HashMap<String, PingDisplay>,
    rtt_history: &HashMap<String, RttHistory>,
    busy: bool,
    rules_state: &mut Option<RulesTabState>,
    global_hooks_on: bool,
    logs_state: &mut LogsTabState,
    log_tail: &LogTail,
) -> DetailEvent {
    let Some(name) = selected.as_deref() else {
        ui.centered_and_justified(|ui| {
            ui.label(i18n::t("gui.detail.empty"));
        });
        return DetailEvent::None;
    };

    let Some(cfg) = configs.iter().find(|c| c.name == name) else {
        ui.centered_and_justified(|ui| {
            ui.label(i18n::t("gui.detail.empty"));
        });
        return DetailEvent::None;
    };

    let is_active = mgr.is_active(&cfg.name);

    let mut event = DetailEvent::None;

    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            ui.selectable_value(
                active_tab,
                DetailTab::Status,
                i18n::t("gui.detail.tab_status"),
            );
            ui.selectable_value(
                active_tab,
                DetailTab::Rules,
                i18n::t("gui.detail.tab_rules"),
            );
            ui.selectable_value(
                active_tab,
                DetailTab::Logs,
                i18n::t("gui.detail.tab_logs"),
            );
        });
        ui.separator();

        match *active_tab {
            DetailTab::Status => {
                let s = stats.get(&cfg.name);
                let h = transfer_history.get(&cfg.name);
                let p = ping_results.get(&cfg.name);
                let r = rtt_history.get(&cfg.name);
                match status::show(ui, cfg, s, h, p, r, is_active, busy) {
                    StatusEvent::None => {}
                    StatusEvent::Toggle => {
                        event = DetailEvent::ToggleTunnel(cfg.name.clone());
                    }
                    StatusEvent::PingPeer { endpoint } => {
                        event = DetailEvent::PingPeer {
                            name: cfg.name.clone(),
                            endpoint,
                        };
                    }
                    StatusEvent::EditConfig => {
                        event = DetailEvent::EditConfig(cfg.name.clone());
                    }
                    StatusEvent::Rename => {
                        event = DetailEvent::Rename(cfg.name.clone());
                    }
                }
            }
            DetailTab::Rules => {
                // Lazily create or replace the draft when the selected
                // tunnel changes. Unsaved drafts for a different tunnel are
                // dropped on selection change — the Save/Cancel semantics
                // here match native WireGuard.app.
                let needs_reset = match rules_state {
                    Some(state) => state.name != cfg.name,
                    None => true,
                };
                if needs_reset {
                    *rules_state = Some(RulesTabState::new(cfg));
                }
                if let Some(state) = rules_state.as_mut() {
                    if let RulesEvent::Apply { name, rules } =
                        rules::show(ui, state, global_hooks_on)
                    {
                        event = DetailEvent::ApplyRules { name, rules };
                    }
                }
            }
            DetailTab::Logs => {
                logs::show(ui, log_tail, logs_state, Some(&cfg.name));
            }
        }
    });

    event
}
