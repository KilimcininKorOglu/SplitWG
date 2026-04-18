//! Modal overlays shared by the App: Add Config, Delete, Preferences.
//!
//! Rendered as `egui::Window`s with a blocking backdrop so the user cannot
//! interact with the main panels until they resolve the prompt. Each modal
//! owns a tiny draft state struct that the App keeps in `Option<…>`.

use std::path::{Path, PathBuf};

use crate::config::{self, Settings};
use crate::gui::validation::{self, ConfigWarning};
use crate::i18n::{self, Lang};
use crate::wg::conf;

// ============================================================================
// Add Config
// ============================================================================

pub struct AddFlow {
    pub src: PathBuf,
    pub stem: String,
    pub preview: String,
    pub warnings: Vec<ConfigWarning>,
}

impl AddFlow {
    pub fn open(src: PathBuf) -> Self {
        let stem = src
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("vpn")
            .to_string();
        let body = std::fs::read_to_string(&src).unwrap_or_else(|_| String::new());
        let preview = mask_preview(&body);
        let warnings = conf::parse(&body)
            .ok()
            .map(|cfg| validation::validate_wg_config(&cfg, None))
            .unwrap_or_default();
        AddFlow {
            src,
            stem,
            preview,
            warnings,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddEvent {
    None,
    Save,
    Cancel,
}

pub fn show_add(ctx: &egui::Context, flow: &mut AddFlow) -> AddEvent {
    let mut event = AddEvent::None;
    let mut open = true;

    egui::Window::new(i18n::t("gui.add.preview_title"))
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .default_width(480.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.label(i18n::t("gui.add.stem_label"));
            ui.text_edit_singleline(&mut flow.stem);

            let stem_valid = !flow.stem.trim().is_empty()
                && !flow.stem.contains(|c: char| {
                    matches!(c, '/' | '\\' | '\0' | ':') || c.is_whitespace()
                });
            if !stem_valid {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 120, 120),
                    i18n::t("gui.add.invalid_name"),
                );
            }

            let existing =
                config::config_dir().join(format!("{}.conf", flow.stem.trim()));
            let duplicate = stem_valid && existing.exists();
            if duplicate {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 180, 80),
                    i18n::t("gui.add.duplicate"),
                );
            }

            ui.separator();
            ui.label(i18n::t("gui.add.preview_title"));
            egui::ScrollArea::vertical()
                .max_height(220.0)
                .show(ui, |ui| {
                    ui.monospace(&flow.preview);
                });

            if !flow.warnings.is_empty() {
                ui.separator();
                ui.label(
                    egui::RichText::new(i18n::t("gui.add.warning.title"))
                        .strong()
                        .color(egui::Color32::from_rgb(220, 170, 60)),
                );
                for w in &flow.warnings {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            egui::RichText::new("⚠")
                                .color(egui::Color32::from_rgb(220, 170, 60)),
                        );
                        ui.label(i18n::t(validation::warning_key(*w)));
                    });
                }
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new(i18n::t("gui.add.warning.help"))
                        .italics()
                        .color(egui::Color32::from_rgb(160, 160, 160)),
                );
            }

            ui.separator();
            ui.horizontal(|ui| {
                if ui.button(i18n::t("gui.add.cancel")).clicked() {
                    event = AddEvent::Cancel;
                }
                if ui
                    .add_enabled(
                        stem_valid && !duplicate,
                        egui::Button::new(i18n::t("gui.add.save")),
                    )
                    .clicked()
                {
                    event = AddEvent::Save;
                }
            });
        });

    if !open && event == AddEvent::None {
        event = AddEvent::Cancel;
    }
    event
}

/// Masks `PrivateKey = …` lines in the `.conf` preview so the user doesn't
/// stare at raw key material while importing.
pub fn mask_preview(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    for line in body.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("PrivateKey") {
            let (indent_len, _) = line
                .char_indices()
                .find(|(_, c)| !c.is_whitespace())
                .unwrap_or((0, ' '));
            out.push_str(&line[..indent_len]);
            out.push_str("PrivateKey");
            let _ = rest; // drop the original value
            out.push_str(" = ");
            out.push_str(&i18n::t("gui.add.private_key_masked"));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

// ============================================================================
// Delete
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteEvent {
    None,
    Confirm,
    Cancel,
}

pub fn show_delete(ctx: &egui::Context, name: &str) -> DeleteEvent {
    let mut event = DeleteEvent::None;
    let mut open = true;

    egui::Window::new(i18n::t("gui.delete.title"))
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(380.0)
        .show(ctx, |ui| {
            ui.label(i18n::t_with("gui.delete.body", &[("name", name)]));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button(i18n::t("gui.delete.cancel")).clicked() {
                    event = DeleteEvent::Cancel;
                }
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new(i18n::t("gui.delete.confirm"))
                                .color(egui::Color32::from_rgb(220, 120, 120)),
                        ),
                    )
                    .clicked()
                {
                    event = DeleteEvent::Confirm;
                }
            });
        });

    if !open && event == DeleteEvent::None {
        event = DeleteEvent::Cancel;
    }
    event
}

// ============================================================================
// Preferences
// ============================================================================

pub struct PrefsFlow {
    pub draft: Settings,
    pub original: Settings,
    pub launch_at_login_draft: bool,
    pub launch_at_login_original: bool,
    pub launch_at_login_requires_approval: bool,
}

/// Formats a UNIX epoch timestamp as `YYYY-MM-DD HH:MM` in the local tz.
/// Returns the i18n "never" string when `ts` is `None`.
fn format_last_check(ts: Option<u64>) -> String {
    format_epoch_or_key(ts, "gui.prefs.updates.last_check_never")
}

/// Variant of `format_last_check` that substitutes the GeoDB-specific
/// "never" copy when the user has not triggered a pull yet.
fn format_last_geodb_update(ts: Option<u64>) -> String {
    format_epoch_or_key(ts, "gui.prefs.geodb.last_update_never")
}

fn format_epoch_or_key(ts: Option<u64>, never_key: &str) -> String {
    let Some(secs) = ts else {
        return i18n::t(never_key);
    };
    let output = std::process::Command::new("/bin/date")
        .args(["-r", &secs.to_string(), "+%Y-%m-%d %H:%M"])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        }
        _ => secs.to_string(),
    }
}

impl PrefsFlow {
    pub fn open() -> Self {
        let original = config::load_settings();
        let state = crate::gui::login_item::status();
        let enabled = matches!(state, crate::gui::login_item::LoginItemState::Enabled);
        let requires_approval = matches!(
            state,
            crate::gui::login_item::LoginItemState::RequiresApproval
        );
        PrefsFlow {
            draft: original.clone(),
            original,
            launch_at_login_draft: enabled,
            launch_at_login_original: enabled,
            launch_at_login_requires_approval: requires_approval,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrefsEvent {
    None,
    Apply,
    Cancel,
    TriggerExport,
    TriggerImport,
    TriggerUpdateCheck,
    TriggerGeoDbUpdate,
}

pub fn show_prefs(ctx: &egui::Context, flow: &mut PrefsFlow) -> PrefsEvent {
    let mut event = PrefsEvent::None;
    let mut open = true;

    egui::Window::new(i18n::t("gui.prefs.window_title"))
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(480.0)
        .show(ctx, |ui| {
            ui.label(i18n::t("gui.prefs.hooks_description"));
            ui.add_space(4.0);
            ui.checkbox(
                &mut flow.draft.hooks_enabled,
                i18n::t("gui.prefs.hooks_label"),
            );

            ui.separator();

            ui.label(i18n::t("gui.prefs.language_label"));
            let current_lang = flow
                .draft
                .language
                .as_deref()
                .and_then(Lang::from_code)
                .unwrap_or(Lang::En);
            let mut selected_lang = current_lang;
            egui::ComboBox::from_id_salt("prefs_language_combo")
                .selected_text(selected_lang.display_name())
                .show_ui(ui, |ui| {
                    for lang in [Lang::En, Lang::Tr] {
                        ui.selectable_value(
                            &mut selected_lang,
                            lang,
                            lang.display_name(),
                        );
                    }
                });
            if selected_lang != current_lang {
                flow.draft.language = Some(selected_lang.code().to_string());
            }

            ui.separator();

            ui.label(i18n::t("gui.prefs.launch_at_login_description"));
            ui.checkbox(
                &mut flow.launch_at_login_draft,
                i18n::t("gui.prefs.launch_at_login_label"),
            );

            ui.separator();

            ui.label(i18n::t("gui.prefs.kill_switch.description"));
            ui.checkbox(
                &mut flow.draft.kill_switch,
                i18n::t("gui.prefs.kill_switch.label"),
            );
            if flow.draft.kill_switch && !flow.original.kill_switch {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 170, 60),
                    i18n::t("gui.prefs.kill_switch.first_use_warning"),
                );
            }
            ui.label(
                egui::RichText::new(i18n::t("gui.prefs.kill_switch.apply_hint"))
                    .italics()
                    .small(),
            );
            if flow.launch_at_login_requires_approval {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 180, 80),
                        i18n::t("gui.prefs.launch_at_login_requires_approval"),
                    );
                    if ui
                        .button(i18n::t("gui.prefs.open_login_items_settings"))
                        .clicked()
                    {
                        crate::gui::login_item::open_login_items_settings();
                    }
                });
            }

            ui.separator();
            ui.label(
                egui::RichText::new(i18n::t("gui.prefs.updates.section_header")).strong(),
            );
            ui.label(
                egui::RichText::new(i18n::t("gui.prefs.updates.auto_check_description"))
                    .italics()
                    .small(),
            );
            ui.checkbox(
                &mut flow.draft.update_check_enabled,
                i18n::t("gui.prefs.updates.auto_check_label"),
            );
            ui.horizontal(|ui| {
                if ui
                    .button(i18n::t("gui.prefs.updates.check_now_button"))
                    .clicked()
                {
                    event = PrefsEvent::TriggerUpdateCheck;
                }
                ui.label(
                    egui::RichText::new(i18n::t_with(
                        "gui.prefs.updates.last_check",
                        &[("time", &format_last_check(flow.draft.last_update_check))],
                    ))
                    .italics()
                    .small(),
                );
            });

            ui.separator();
            ui.label(
                egui::RichText::new(i18n::t("gui.prefs.geodb.section_header")).strong(),
            );
            ui.label(
                egui::RichText::new(i18n::t("gui.prefs.geodb.description"))
                    .italics()
                    .small(),
            );
            ui.checkbox(
                &mut flow.draft.geodb_auto_update_enabled,
                i18n::t("gui.prefs.geodb.auto_check_label"),
            );
            ui.horizontal(|ui| {
                if ui
                    .button(i18n::t("gui.prefs.geodb.update_now_button"))
                    .clicked()
                {
                    event = PrefsEvent::TriggerGeoDbUpdate;
                }
                ui.label(
                    egui::RichText::new(i18n::t_with(
                        "gui.prefs.geodb.last_update",
                        &[("time", &format_last_geodb_update(
                            flow.draft.last_geodb_update,
                        ))],
                    ))
                    .italics()
                    .small(),
                );
            });

            ui.separator();
            ui.horizontal(|ui| {
                if ui
                    .button(i18n::t("gui.prefs.export_button"))
                    .clicked()
                {
                    event = PrefsEvent::TriggerExport;
                }
                if ui
                    .button(i18n::t("gui.prefs.import_button"))
                    .clicked()
                {
                    event = PrefsEvent::TriggerImport;
                }
            });

            ui.separator();
            ui.horizontal(|ui| {
                if ui.button(i18n::t("gui.prefs.cancel")).clicked() {
                    event = PrefsEvent::Cancel;
                }
                let dirty = flow.draft != flow.original
                    || flow.launch_at_login_draft != flow.launch_at_login_original;
                if ui
                    .add_enabled(dirty, egui::Button::new(i18n::t("gui.prefs.apply")))
                    .clicked()
                {
                    event = PrefsEvent::Apply;
                }
            });
        });

    if !open && event == PrefsEvent::None {
        event = PrefsEvent::Cancel;
    }
    event
}

// ============================================================================
// Export / Import package
// ============================================================================

pub struct ExportFlow {
    pub selection: Vec<(String, bool)>,
    pub password: String,
    pub show_plain: bool,
}

impl ExportFlow {
    pub fn open(configs: &[crate::config::Config]) -> Self {
        ExportFlow {
            selection: configs
                .iter()
                .map(|c| (c.name.clone(), true))
                .collect(),
            password: String::new(),
            show_plain: false,
        }
    }

    pub fn selected_names(&self) -> Vec<String> {
        self.selection
            .iter()
            .filter(|(_, on)| *on)
            .map(|(n, _)| n.clone())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportEvent {
    None,
    Save,
    Cancel,
}

pub fn show_export(ctx: &egui::Context, flow: &mut ExportFlow) -> ExportEvent {
    let mut event = ExportEvent::None;
    let mut open = true;

    egui::Window::new(i18n::t("gui.export.title"))
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(440.0)
        .show(ctx, |ui| {
            ui.label(i18n::t("gui.export.description"));
            ui.add_space(4.0);

            if ui.button(i18n::t("gui.export.select_all")).clicked() {
                let all_on = flow.selection.iter().all(|(_, on)| *on);
                for (_, on) in &mut flow.selection {
                    *on = !all_on;
                }
            }
            egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                for (name, on) in &mut flow.selection {
                    ui.checkbox(on, name.clone());
                }
            });

            ui.separator();
            ui.label(i18n::t("gui.export.password_label"));
            ui.horizontal(|ui| {
                let field = egui::TextEdit::singleline(&mut flow.password)
                    .password(!flow.show_plain)
                    .desired_width(260.0);
                ui.add(field);
                ui.checkbox(&mut flow.show_plain, i18n::t("gui.export.show_password"));
            });
            if flow.password.chars().count() < super::package::MIN_PASSWORD_LEN {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 180, 80),
                    i18n::t("gui.export.min_length_warning"),
                );
            }

            ui.separator();
            ui.horizontal(|ui| {
                if ui.button(i18n::t("gui.export.cancel")).clicked() {
                    event = ExportEvent::Cancel;
                }
                let ready = flow
                    .password
                    .chars()
                    .count()
                    >= super::package::MIN_PASSWORD_LEN
                    && flow.selection.iter().any(|(_, on)| *on);
                if ui
                    .add_enabled(ready, egui::Button::new(i18n::t("gui.export.save")))
                    .clicked()
                {
                    event = ExportEvent::Save;
                }
            });
        });

    if !open && event == ExportEvent::None {
        event = ExportEvent::Cancel;
    }
    event
}

pub struct ImportFlow {
    pub src: PathBuf,
    pub password: String,
    pub show_plain: bool,
    pub last_error: Option<String>,
}

impl ImportFlow {
    pub fn open(src: PathBuf) -> Self {
        ImportFlow {
            src,
            password: String::new(),
            show_plain: false,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportEvent {
    None,
    Confirm,
    Cancel,
}

pub fn show_import(ctx: &egui::Context, flow: &mut ImportFlow) -> ImportEvent {
    let mut event = ImportEvent::None;
    let mut open = true;

    egui::Window::new(i18n::t("gui.import.title"))
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(440.0)
        .show(ctx, |ui| {
            ui.label(i18n::t("gui.import.source_label"));
            ui.monospace(flow.src.display().to_string());
            ui.separator();

            ui.label(i18n::t("gui.import.password_label"));
            ui.horizontal(|ui| {
                let field = egui::TextEdit::singleline(&mut flow.password)
                    .password(!flow.show_plain)
                    .desired_width(260.0);
                ui.add(field);
                ui.checkbox(&mut flow.show_plain, i18n::t("gui.export.show_password"));
            });

            if let Some(err) = &flow.last_error {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 120, 120),
                    err.clone(),
                );
            }

            ui.separator();
            ui.horizontal(|ui| {
                if ui.button(i18n::t("gui.import.cancel")).clicked() {
                    event = ImportEvent::Cancel;
                }
                let ready = !flow.password.is_empty();
                if ui
                    .add_enabled(ready, egui::Button::new(i18n::t("gui.import.confirm")))
                    .clicked()
                {
                    event = ImportEvent::Confirm;
                }
            });
        });

    if !open && event == ImportEvent::None {
        event = ImportEvent::Cancel;
    }
    event
}

/// Suppresses `Path` + `Settings` unused warnings on non-macOS targets.
#[allow(dead_code)]
fn _deps_used(_: &Path, _: &Settings) {}
