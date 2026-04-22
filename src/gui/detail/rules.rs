//! Rules tab — edit split-tunnel entries, mode, per-tunnel hook toggle.

use crate::config::{Config, OnDemandRule, Rules, ScheduleRule};
use crate::{i18n, notify};

use crate::gui::detail::templates::{self, TEMPLATES};
use crate::gui::validation::{classify, is_valid_entry, EntryKind};

/// Persistent per-tunnel editor state. Held by `App` across frames so the
/// user's in-progress edits survive a refresh of the config list. We cache
/// both `original` (the last-saved snapshot) and `current` so we can detect
/// "dirty" and provide Discard.
#[derive(Debug, Clone)]
pub struct RulesTabState {
    pub name: String,
    pub original: Rules,
    pub current: Rules,
    pub new_entry: String,
    pub editing: Option<(usize, String)>,
    /// Whether the "On-demand" collapsing header's checkbox is on. Driven
    /// separately from `current.on_demand` so the user can toggle a rule
    /// off without losing the SSID list they typed in.
    pub on_demand_enabled: bool,
    /// CSV drafts for the SSID lists. Parsed into `Vec<String>` on Apply.
    pub trusted_ssids_draft: String,
    pub untrusted_ssids_draft: String,
    /// Schedule section drafts — parsed into `ScheduleRule` on Apply.
    pub schedule_enabled: bool,
    pub schedule_days: [bool; 7],
    pub schedule_hour_start: u8,
    pub schedule_hour_end: u8,
    /// Draft for the optional exclusive-group label. Empty string means
    /// "ungrouped"; the rule is normalised to `None` on commit.
    pub exclusive_group_draft: String,
}

impl RulesTabState {
    pub fn new(cfg: &Config) -> Self {
        let (on_demand_enabled, trusted_ssids_draft, untrusted_ssids_draft) =
            match cfg.rules.on_demand.as_ref() {
                Some(r) => (
                    true,
                    r.trusted_ssids.join(", "),
                    r.untrusted_ssids.join(", "),
                ),
                None => (false, String::new(), String::new()),
            };
        let (schedule_enabled, schedule_days, schedule_hour_start, schedule_hour_end) = match cfg
            .rules
            .on_demand
            .as_ref()
            .and_then(|r| r.schedule.as_ref())
        {
            Some(s) => {
                let mut days = [false; 7];
                for (i, d) in days.iter_mut().enumerate() {
                    *d = s.weekdays_mask & (1 << i) != 0;
                }
                (true, days, s.hour_start, s.hour_end)
            }
            // Sensible default draft when the user first enables schedule:
            // Mon-Fri (bits 0..=4), 09:00–18:00. Disabled until the user
            // ticks the box.
            None => (false, [true, true, true, true, true, false, false], 9, 18),
        };
        let exclusive_group_draft = cfg
            .rules
            .on_demand
            .as_ref()
            .and_then(|r| r.exclusive_group.clone())
            .unwrap_or_default();
        Self {
            name: cfg.name.clone(),
            original: cfg.rules.clone(),
            current: cfg.rules.clone(),
            new_entry: String::new(),
            editing: None,
            on_demand_enabled,
            trusted_ssids_draft,
            untrusted_ssids_draft,
            schedule_enabled,
            schedule_days,
            schedule_hour_start,
            schedule_hour_end,
            exclusive_group_draft,
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.current != self.original
    }

    /// Parses the CSV drafts into a concrete `OnDemandRule` (or `None` if
    /// the on-demand section is disabled) and writes it into `current`.
    /// Called on Apply so the persisted value matches the UI.
    pub fn commit_on_demand(&mut self) {
        if !self.on_demand_enabled {
            self.current.on_demand = None;
            return;
        }
        let mut rule = self.current.on_demand.clone().unwrap_or_default();
        rule.trusted_ssids = parse_csv(&self.trusted_ssids_draft);
        rule.untrusted_ssids = parse_csv(&self.untrusted_ssids_draft);
        rule.schedule = if self.schedule_enabled {
            let mut mask = 0u8;
            for (i, d) in self.schedule_days.iter().enumerate() {
                if *d {
                    mask |= 1 << i;
                }
            }
            Some(ScheduleRule {
                weekdays_mask: mask,
                hour_start: self.schedule_hour_start.min(23),
                hour_end: self.schedule_hour_end.min(23),
            })
        } else {
            None
        };
        let trimmed = self.exclusive_group_draft.trim();
        rule.exclusive_group = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
        self.current.on_demand = Some(rule);
    }
}

fn parse_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Events the Rules tab may emit this frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulesEvent {
    None,
    /// User hit "Apply & Reconnect" — persist rules and (if active) cycle
    /// the tunnel. `Rules` is passed by value to simplify the worker.
    Apply {
        name: String,
        rules: Box<Rules>,
    },
}

/// Renders the Rules tab. `state` is borrowed mutably so inline edits and
/// the ComboBox mutate the draft directly; `App` persists once the user
/// hits Apply.
pub fn show(ui: &mut egui::Ui, state: &mut RulesTabState, global_hooks_on: bool) -> RulesEvent {
    let mut event = RulesEvent::None;

    // Warn the user when `country:XX` entries are present but the mmdb is
    // missing — the entries will be silently skipped at bringup otherwise.
    let has_geo = state
        .current
        .entries
        .iter()
        .any(|e| matches!(classify(e), EntryKind::Geo));
    if has_geo && !crate::wg::rules::geo::mmdb_available() {
        ui.colored_label(
            egui::Color32::from_rgb(220, 180, 80),
            i18n::t("gui.rules.geo.mmdb_missing"),
        );
        ui.separator();
    }

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(i18n::t("gui.rules.mode_label")).strong());
        let current_label = if state.current.mode == "include" {
            i18n::t("gui.rules.mode_include")
        } else {
            i18n::t("gui.rules.mode_exclude")
        };
        egui::ComboBox::from_id_salt("rules_mode")
            .selected_text(current_label)
            .show_ui(ui, |ui| {
                let mut mode = state.current.mode.clone();
                if ui
                    .selectable_value(
                        &mut mode,
                        "exclude".to_string(),
                        i18n::t("gui.rules.mode_exclude"),
                    )
                    .clicked()
                    || ui
                        .selectable_value(
                            &mut mode,
                            "include".to_string(),
                            i18n::t("gui.rules.mode_include"),
                        )
                        .clicked()
                {
                    state.current.mode = mode;
                }
            });
    });

    ui.horizontal(|ui| {
        let hooks_tip = if global_hooks_on {
            i18n::t("gui.rules.hooks_label")
        } else {
            i18n::t("gui.rules.hooks_global_off")
        };
        ui.add_enabled(
            global_hooks_on,
            egui::Checkbox::new(&mut state.current.hooks_enabled, hooks_tip),
        )
        .on_disabled_hover_text(i18n::t("gui.rules.hooks_global_off"));
    });

    ui.separator();

    // Entry table.
    egui::ScrollArea::vertical()
        .max_height(260.0)
        .show(ui, |ui| {
            use egui_extras::{Column, TableBuilder};

            TableBuilder::new(ui)
                .striped(true)
                .column(Column::exact(32.0))
                .column(Column::remainder().clip(true))
                .column(Column::exact(110.0))
                .column(Column::exact(120.0))
                .header(22.0, |mut header| {
                    header.col(|ui| {
                        ui.strong(i18n::t("gui.rules.column_index"));
                    });
                    header.col(|ui| {
                        ui.strong(i18n::t("gui.rules.column_entry"));
                    });
                    header.col(|ui| {
                        ui.strong(i18n::t("gui.rules.column_type"));
                    });
                    header.col(|ui| {
                        ui.strong(i18n::t("gui.rules.column_actions"));
                    });
                })
                .body(|mut body| {
                    let mut remove_idx: Option<usize> = None;
                    let mut commit_idx: Option<(usize, String)> = None;
                    let mut begin_edit: Option<usize> = None;
                    let mut cancel_edit = false;
                    for (idx, entry) in state.current.entries.iter().enumerate() {
                        body.row(26.0, |mut row| {
                            row.col(|ui| {
                                ui.label(format!("{}", idx + 1));
                            });
                            row.col(|ui| match &state.editing {
                                Some((editing_idx, draft)) if *editing_idx == idx => {
                                    let mut text = draft.clone();
                                    let resp = ui.add(
                                        egui::TextEdit::singleline(&mut text)
                                            .desired_width(f32::INFINITY),
                                    );
                                    if resp.lost_focus()
                                        && ui.input(|i| i.key_pressed(egui::Key::Enter))
                                    {
                                        commit_idx = Some((idx, text.clone()));
                                    } else if resp.changed() {
                                        // Propagate draft change via the same
                                        // channel so the outer state updates.
                                        commit_idx = Some((idx, text));
                                    }
                                }
                                _ => {
                                    ui.monospace(entry);
                                }
                            });
                            row.col(|ui| {
                                let kind_label = kind_label(classify(entry));
                                ui.label(kind_label);
                            });
                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    let editing = matches!(state.editing, Some((i, _)) if i == idx);
                                    if editing {
                                        if ui.small_button("✓").clicked() {
                                            cancel_edit = true;
                                        }
                                        if ui.small_button("✕").clicked() {
                                            cancel_edit = true;
                                        }
                                    } else {
                                        if ui.small_button(i18n::t("gui.rules.edit")).clicked() {
                                            begin_edit = Some(idx);
                                        }
                                        if ui.small_button(i18n::t("gui.rules.delete")).clicked() {
                                            remove_idx = Some(idx);
                                        }
                                    }
                                });
                            });
                        });
                    }
                    if let Some(idx) = remove_idx {
                        state.current.entries.remove(idx);
                        state.editing = None;
                    }
                    if let Some((idx, text)) = commit_idx {
                        state.editing = Some((idx, text.clone()));
                        if is_valid_entry(&text) {
                            state.current.entries[idx] = text.trim().to_string();
                        }
                    }
                    if let Some(idx) = begin_edit {
                        let current_text =
                            state.current.entries.get(idx).cloned().unwrap_or_default();
                        state.editing = Some((idx, current_text));
                    }
                    if cancel_edit {
                        state.editing = None;
                    }
                });
        });

    ui.separator();

    ui.horizontal(|ui| {
        let is_valid = is_valid_entry(&state.new_entry) || state.new_entry.trim().is_empty();
        let bg = if state.new_entry.trim().is_empty() || is_valid {
            ui.visuals().extreme_bg_color
        } else {
            egui::Color32::from_rgb(90, 30, 30)
        };
        let frame = egui::Frame::none()
            .fill(bg)
            .inner_margin(egui::Margin::same(2.0));
        frame.show(ui, |ui| {
            ui.add(
                egui::TextEdit::singleline(&mut state.new_entry)
                    .desired_width(260.0)
                    .hint_text(i18n::t("gui.rules.add_placeholder")),
            );
        });
        let add_enabled = !state.new_entry.trim().is_empty() && is_valid_entry(&state.new_entry);
        if ui
            .add_enabled(
                add_enabled,
                egui::Button::new(i18n::t("gui.rules.add_button")),
            )
            .clicked()
        {
            state
                .current
                .entries
                .push(state.new_entry.trim().to_string());
            state.new_entry.clear();
        }
        if !state.new_entry.trim().is_empty() && !is_valid_entry(&state.new_entry) {
            ui.colored_label(
                egui::Color32::from_rgb(220, 120, 120),
                i18n::t("gui.rules.invalid"),
            );
        }
    });

    // Preset CIDR templates — one-click import of common CDN / service
    // blocks. Selecting a template appends its entries (skipping duplicates)
    // and fires a notification with the added count.
    ui.horizontal(|ui| {
        ui.label(i18n::t("gui.rules.templates.picker_label"));
        let placeholder = i18n::t("gui.rules.templates.picker_placeholder");
        let mut picked: Option<usize> = None;
        egui::ComboBox::from_id_salt("rules_templates")
            .selected_text(&placeholder)
            .width(220.0)
            .show_ui(ui, |ui| {
                for (idx, tmpl) in TEMPLATES.iter().enumerate() {
                    let label = i18n::t(&format!("gui.rules.templates.{}", tmpl.key));
                    if ui.selectable_label(false, label).clicked() {
                        picked = Some(idx);
                    }
                }
            });
        if let Some(idx) = picked {
            let tmpl = &TEMPLATES[idx];
            let tmpl_label = i18n::t(&format!("gui.rules.templates.{}", tmpl.key));
            let added = templates::apply_template(&mut state.current, tmpl);
            notify::info(
                &i18n::t("notify.splitwg"),
                &i18n::t_with(
                    "gui.rules.templates.added",
                    &[("count", &added.to_string()), ("name", &tmpl_label)],
                ),
            );
        }
    });

    ui.separator();

    // On-demand auto-connect section.
    egui::CollapsingHeader::new(i18n::t("gui.rules.on_demand.header"))
        .default_open(state.on_demand_enabled)
        .show(ui, |ui| {
            ui.checkbox(
                &mut state.on_demand_enabled,
                i18n::t("gui.rules.on_demand.enable_label"),
            );
            ui.add_enabled_ui(state.on_demand_enabled, |ui| {
                let mut rule = state.current.on_demand.clone().unwrap_or_default();
                let mut changed = false;
                if ui
                    .checkbox(
                        &mut rule.always,
                        i18n::t("gui.rules.on_demand.always_label"),
                    )
                    .changed()
                {
                    changed = true;
                }
                if ui
                    .checkbox(
                        &mut rule.activate_on_ethernet,
                        i18n::t("gui.rules.on_demand.ethernet_label"),
                    )
                    .changed()
                {
                    changed = true;
                }
                if ui
                    .checkbox(
                        &mut rule.activate_on_wifi,
                        i18n::t("gui.rules.on_demand.wifi_label"),
                    )
                    .changed()
                {
                    changed = true;
                }
                ui.horizontal(|ui| {
                    ui.label(i18n::t("gui.rules.on_demand.trusted_ssids_label"));
                    ui.add(
                        egui::TextEdit::singleline(&mut state.trusted_ssids_draft)
                            .desired_width(260.0)
                            .hint_text(i18n::t("gui.rules.on_demand.trusted_ssids_placeholder")),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label(i18n::t("gui.rules.on_demand.untrusted_ssids_label"));
                    ui.add(
                        egui::TextEdit::singleline(&mut state.untrusted_ssids_draft)
                            .desired_width(260.0)
                            .hint_text(i18n::t("gui.rules.on_demand.untrusted_ssids_placeholder")),
                    );
                });
                if changed {
                    state.current.on_demand = Some(rule);
                }

                ui.separator();
                ui.checkbox(
                    &mut state.schedule_enabled,
                    i18n::t("gui.rules.on_demand.schedule.header"),
                );
                ui.add_enabled_ui(state.schedule_enabled, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(i18n::t("gui.rules.on_demand.schedule.days_label"));
                        let day_keys = [
                            "gui.rules.on_demand.schedule.day_mon",
                            "gui.rules.on_demand.schedule.day_tue",
                            "gui.rules.on_demand.schedule.day_wed",
                            "gui.rules.on_demand.schedule.day_thu",
                            "gui.rules.on_demand.schedule.day_fri",
                            "gui.rules.on_demand.schedule.day_sat",
                            "gui.rules.on_demand.schedule.day_sun",
                        ];
                        for (i, key) in day_keys.iter().enumerate() {
                            ui.checkbox(&mut state.schedule_days[i], i18n::t(key));
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label(i18n::t("gui.rules.on_demand.schedule.hour_range_label"));
                        ui.add(
                            egui::DragValue::new(&mut state.schedule_hour_start)
                                .range(0..=23)
                                .suffix(":00"),
                        );
                        ui.label("–");
                        ui.add(
                            egui::DragValue::new(&mut state.schedule_hour_end)
                                .range(0..=23)
                                .suffix(":00"),
                        );
                    });
                    ui.label(
                        egui::RichText::new(i18n::t("gui.rules.on_demand.schedule.hint_overnight"))
                            .italics()
                            .small(),
                    );
                });

                ui.label(
                    egui::RichText::new(i18n::t("gui.rules.on_demand.manual_override_hint"))
                        .italics()
                        .small(),
                );
            });
        });

    ui.separator();

    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                state.is_dirty() || draft_differs_from_original(state),
                egui::Button::new(i18n::t("gui.rules.discard")),
            )
            .clicked()
        {
            state.current = state.original.clone();
            state.editing = None;
            state.new_entry.clear();
            // Also rebuild the on-demand drafts so discard truly resets.
            let (enabled, trusted, untrusted) = match state.original.on_demand.as_ref() {
                Some(r) => (
                    true,
                    r.trusted_ssids.join(", "),
                    r.untrusted_ssids.join(", "),
                ),
                None => (false, String::new(), String::new()),
            };
            state.on_demand_enabled = enabled;
            state.trusted_ssids_draft = trusted;
            state.untrusted_ssids_draft = untrusted;
            // Rebuild schedule drafts from the pristine `original`.
            let sched = state
                .original
                .on_demand
                .as_ref()
                .and_then(|r| r.schedule.as_ref());
            match sched {
                Some(s) => {
                    for i in 0..7 {
                        state.schedule_days[i] = s.weekdays_mask & (1 << i) != 0;
                    }
                    state.schedule_hour_start = s.hour_start;
                    state.schedule_hour_end = s.hour_end;
                    state.schedule_enabled = true;
                }
                None => {
                    state.schedule_enabled = false;
                    state.schedule_days = [true, true, true, true, true, false, false];
                    state.schedule_hour_start = 9;
                    state.schedule_hour_end = 18;
                }
            }
        }

        ui.horizontal(|ui| {
            ui.label(i18n::t("gui.rules.on_demand.exclusive_group_label"));
            ui.add(
                egui::TextEdit::singleline(&mut state.exclusive_group_draft)
                    .desired_width(160.0)
                    .hint_text(i18n::t("gui.rules.on_demand.exclusive_group_placeholder")),
            );
        });
        ui.label(
            egui::RichText::new(i18n::t("gui.rules.on_demand.exclusive_group_hint"))
                .small()
                .weak(),
        );

        let dirty = state.is_dirty() || draft_differs_from_original(state);
        if ui
            .add_enabled(dirty, egui::Button::new(i18n::t("gui.rules.apply")))
            .clicked()
        {
            state.commit_on_demand();
            event = RulesEvent::Apply {
                name: state.name.clone(),
                rules: Box::new(state.current.clone()),
            };
        }
    });

    event
}

/// The on-demand drafts live outside `current` until Apply, so plain
/// equality is not enough to detect dirtiness. This computes a temporary
/// `OnDemandRule` from the drafts and compares it with `original`.
fn draft_differs_from_original(state: &RulesTabState) -> bool {
    let computed: Option<OnDemandRule> = if state.on_demand_enabled {
        let mut rule = state.current.on_demand.clone().unwrap_or_default();
        rule.trusted_ssids = parse_csv(&state.trusted_ssids_draft);
        rule.untrusted_ssids = parse_csv(&state.untrusted_ssids_draft);
        rule.schedule = if state.schedule_enabled {
            let mut mask = 0u8;
            for (i, d) in state.schedule_days.iter().enumerate() {
                if *d {
                    mask |= 1 << i;
                }
            }
            Some(ScheduleRule {
                weekdays_mask: mask,
                hour_start: state.schedule_hour_start.min(23),
                hour_end: state.schedule_hour_end.min(23),
            })
        } else {
            None
        };
        let trimmed = state.exclusive_group_draft.trim();
        rule.exclusive_group = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
        Some(rule)
    } else {
        None
    };
    computed != state.original.on_demand
}

fn kind_label(kind: EntryKind) -> String {
    match kind {
        EntryKind::Ip => i18n::t("gui.rules.entry_type_ip"),
        EntryKind::Cidr => i18n::t("gui.rules.entry_type_cidr"),
        EntryKind::Domain => i18n::t("gui.rules.entry_type_domain"),
        EntryKind::Wildcard => i18n::t("gui.rules.entry_type_wildcard"),
        EntryKind::Geo => i18n::t("gui.rules.entry_type_geo"),
        EntryKind::Invalid => i18n::t("gui.rules.invalid"),
    }
}
