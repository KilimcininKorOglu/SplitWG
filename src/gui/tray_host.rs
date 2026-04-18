//! Tray menu host — 20-slot layout, polled from the eframe update loop.
//!
//! The tray icon and menu are built on the main thread inside
//! `TrayHost::new` (called from `eframe::App::new`) and `TrayHost::poll`
//! is invoked on every frame to drain pending menu events and periodically
//! refresh slot labels + the tray icon.
//!
//! Menu events are bridged from muda's global `MenuEvent::receiver()` onto
//! a private `mpsc` channel. A background thread blocks on the global
//! receiver and forwards each event, calling
//! `egui::Context::request_repaint` so the UI wakes up even when the main
//! window is hidden.

use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use muda::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use crate::i18n::{self, Lang};
use crate::icon as app_icon;
use crate::{auth, config, notify, wg};

use super::login_item::{self, LoginItemState};

/// Maximum number of slot submenus ever shown. The slots themselves are
/// pre-allocated so their `MenuId`s stay stable across refreshes, but only
/// as many as there are configs are inserted into the top-level menu on any
/// given tick — the rest stay detached so the menu does not fill with empty
/// `—` rows when the user has one or zero tunnels.
const MAX_SLOTS: usize = 20;

/// Action the App should take after draining tray events. The tray itself
/// cannot reach into the eframe viewport state, so it reports intents up to
/// `App::update` which executes them.
#[derive(Debug, Clone)]
pub enum TrayAction {
    None,
    ShowManageTunnels,
    /// Tray slot ▸ Edit Rules → open the Manage Tunnels window focused on
    /// the given tunnel with the Rules tab active.
    EditRules(String),
    /// Tray ▸ Add Config → open the rfd file picker + import modal. The
    /// tray itself can't render egui; the App performs the work.
    OpenAddConfig,
    /// Tray ▸ Preferences ▸ Hooks — open the in-window Preferences modal.
    OpenPreferences,
    /// Tray ▸ Preferences ▸ Check for updates — fire a manual update
    /// check. Handled by `App::trigger_manual_update_check`.
    CheckUpdates,
    /// Tray ▸ Preferences ▸ Update GeoIP DB — fire a manual GeoLite2
    /// pull. Handled by `App::trigger_manual_geodb_update`.
    UpdateGeoDb,
    Quit,
}

/// One pre-allocated slot in the tray menu.
///
/// `in_menu` tracks whether the slot's submenu is currently attached to the
/// top-level `Menu`. We flip it in `refresh` so we do not double-insert or
/// remove-what-is-not-there — muda's `remove` returns an error if the item
/// is not a child.
struct Slot {
    submenu: Submenu,
    toggle_item: MenuItem,
    edit_item: MenuItem,
    hooks_item: MenuItem,
    name: Mutex<String>,
    config_path: Mutex<PathBuf>,
    in_menu: Mutex<bool>,
}

/// Owns the tray icon, muda menu handles, and the channel that bridges
/// global muda events into the eframe update loop.
pub struct TrayHost {
    // Kept alive so the tray icon stays on the status bar.
    _tray: TrayIcon,
    menu: Menu,
    slots: Vec<Slot>,

    // Top-level items — kept alive so `set_text` on language switch works.
    add_item: MenuItem,
    open_dir_item: MenuItem,
    logs_item: MenuItem,
    manage_tunnels_item: MenuItem,
    prefs_submenu: Submenu,
    hooks_toggle_item: MenuItem,
    launch_at_login_item: MenuItem,
    kill_switch_item: MenuItem,
    check_updates_item: MenuItem,
    update_geodb_item: MenuItem,
    lang_submenu: Submenu,
    lang_en_item: MenuItem,
    lang_tr_item: MenuItem,
    quit_item: MenuItem,

    // IDs captured at build time for event dispatch (MenuId is cheap to
    // clone; doing it once avoids re-hashing on every click).
    add_id: MenuId,
    open_dir_id: MenuId,
    logs_id: MenuId,
    manage_tunnels_id: MenuId,
    hooks_toggle_id: MenuId,
    launch_at_login_id: MenuId,
    kill_switch_id: MenuId,
    check_updates_id: MenuId,
    update_geodb_id: MenuId,
    lang_en_id: MenuId,
    lang_tr_id: MenuId,
    quit_id: MenuId,

    connected_icon: Icon,
    disconnected_icon: Icon,

    menu_rx: mpsc::Receiver<MenuId>,
    last_refresh: Instant,
    /// Latest aggregate throughput in bytes/sec (rx, tx). Updated from the
    /// App refresh loop via `set_throughput`; rendered in the tooltip.
    last_rate: (f32, f32),
}

impl TrayHost {
    /// Builds the tray icon + menu and spawns the muda → egui bridge thread.
    /// Must be called on the main thread (enforced by macOS; eframe's
    /// `CreationContext` callback satisfies this).
    pub fn new(ctx: &egui::Context) -> Result<Self, Box<dyn std::error::Error>> {
        let menu = Menu::new();
        let mut slots: Vec<Slot> = Vec::with_capacity(MAX_SLOTS);
        for _ in 0..MAX_SLOTS {
            let toggle_item = MenuItem::new(i18n::t("tray.menu.connect"), false, None);
            let edit_item = MenuItem::new(i18n::t("tray.menu.edit_rules"), false, None);
            let hooks_item = MenuItem::new(i18n::t("tray.hooks.off_click_enable"), false, None);
            let submenu = Submenu::new(i18n::t("tray.slot.empty"), false);
            submenu.append(&toggle_item)?;
            submenu.append(&edit_item)?;
            submenu.append(&hooks_item)?;
            slots.push(Slot {
                submenu,
                toggle_item,
                edit_item,
                hooks_item,
                name: Mutex::new(String::new()),
                config_path: Mutex::new(PathBuf::new()),
                in_menu: Mutex::new(false),
            });
        }

        menu.append(&PredefinedMenuItem::separator())?;
        let add_item = MenuItem::new(i18n::t("tray.menu.add_config"), true, None);
        let open_dir_item = MenuItem::new(i18n::t("tray.menu.open_config_dir"), true, None);
        let logs_item = MenuItem::new(i18n::t("tray.menu.view_logs"), true, None);
        let manage_tunnels_item =
            MenuItem::new(i18n::t("tray.menu.manage_tunnels"), true, None);

        let prefs_submenu = Submenu::new(i18n::t("tray.menu.preferences"), true);
        let hooks_toggle_item = MenuItem::new(hooks_toggle_label(), true, None);
        let launch_at_login_item = MenuItem::new(launch_at_login_label(), true, None);
        let kill_switch_item = MenuItem::new(kill_switch_label(), true, None);
        let check_updates_item = MenuItem::new(
            i18n::t("tray.submenu.preferences.check_updates"),
            true,
            None,
        );
        let update_geodb_item = MenuItem::new(
            i18n::t("tray.submenu.preferences.update_geodb"),
            true,
            None,
        );
        let lang_submenu = Submenu::new(language_label(), true);
        let lang_en_item = MenuItem::new(
            i18n::t("tray.submenu.preferences.language.english"),
            true,
            None,
        );
        let lang_tr_item = MenuItem::new(
            i18n::t("tray.submenu.preferences.language.turkish"),
            true,
            None,
        );
        lang_submenu.append(&lang_en_item)?;
        lang_submenu.append(&lang_tr_item)?;
        prefs_submenu.append(&hooks_toggle_item)?;
        prefs_submenu.append(&launch_at_login_item)?;
        prefs_submenu.append(&kill_switch_item)?;
        prefs_submenu.append(&check_updates_item)?;
        prefs_submenu.append(&update_geodb_item)?;
        prefs_submenu.append(&lang_submenu)?;

        menu.append(&add_item)?;
        menu.append(&open_dir_item)?;
        menu.append(&logs_item)?;
        menu.append(&PredefinedMenuItem::separator())?;
        menu.append(&manage_tunnels_item)?;
        menu.append(&prefs_submenu)?;
        menu.append(&PredefinedMenuItem::separator())?;
        let quit_item = MenuItem::new(i18n::t("tray.menu.quit"), true, None);
        menu.append(&quit_item)?;

        let disconnected_icon = load_icon(app_icon::disconnected())?;
        let connected_icon = load_icon(app_icon::connected())?;

        let add_id = add_item.id().clone();
        let open_dir_id = open_dir_item.id().clone();
        let logs_id = logs_item.id().clone();
        let manage_tunnels_id = manage_tunnels_item.id().clone();
        let hooks_toggle_id = hooks_toggle_item.id().clone();
        let launch_at_login_id = launch_at_login_item.id().clone();
        let kill_switch_id = kill_switch_item.id().clone();
        let check_updates_id = check_updates_item.id().clone();
        let update_geodb_id = update_geodb_item.id().clone();
        let lang_en_id = lang_en_item.id().clone();
        let lang_tr_id = lang_tr_item.id().clone();
        let quit_id = quit_item.id().clone();

        // `with_icon_as_template(true)` lets macOS recolour the icon to
        // match the menu bar (light/dark) without shipping two variants —
        // only the PNG's alpha channel is used.
        let tray = TrayIconBuilder::new()
            .with_icon(disconnected_icon.clone())
            .with_icon_as_template(true)
            .with_tooltip(initial_tooltip())
            .with_menu(Box::new(menu.clone()))
            .build()?;

        // Bridge muda's global MenuEvent receiver into our private channel,
        // waking the egui context so the main thread drains the queue on
        // the next frame.
        let (tx, rx) = mpsc::channel::<MenuId>();
        {
            let ctx = ctx.clone();
            thread::spawn(move || {
                let rx = MenuEvent::receiver();
                while let Ok(event) = rx.recv() {
                    if tx.send(event.id).is_err() {
                        break;
                    }
                    ctx.request_repaint();
                }
            });
        }

        Ok(TrayHost {
            _tray: tray,
            menu,
            slots,
            add_item,
            open_dir_item,
            logs_item,
            manage_tunnels_item,
            prefs_submenu,
            hooks_toggle_item,
            launch_at_login_item,
            kill_switch_item,
            check_updates_item,
            update_geodb_item,
            lang_submenu,
            lang_en_item,
            lang_tr_item,
            quit_item,
            add_id,
            open_dir_id,
            logs_id,
            manage_tunnels_id,
            hooks_toggle_id,
            launch_at_login_id,
            kill_switch_id,
            check_updates_id,
            update_geodb_id,
            lang_en_id,
            lang_tr_id,
            quit_id,
            connected_icon,
            disconnected_icon,
            menu_rx: rx,
            last_refresh: Instant::now() - Duration::from_secs(10),
            last_rate: (0.0, 0.0),
        })
    }

    /// Updates the aggregate throughput shown in the tooltip. Called each
    /// second from `App::refresh`. When the delta is large enough, the
    /// tooltip is rebuilt next frame via `force_refresh`; small changes are
    /// debounced to avoid macOS menu-bar flicker.
    pub fn set_throughput(&mut self, rx_bps: f32, tx_bps: f32) {
        let prev = self.last_rate;
        self.last_rate = (rx_bps, tx_bps);
        let rx_change = (prev.0 - rx_bps).abs() / prev.0.max(1.0);
        let tx_change = (prev.1 - tx_bps).abs() / prev.1.max(1.0);
        if rx_change > 0.05 || tx_change > 0.05 {
            self.force_refresh();
        }
    }

    /// Drains pending menu events and runs the periodic refresh. Called
    /// from `eframe::App::update` on every frame. Returns the net action
    /// the caller must handle (viewport show, app quit, etc.).
    pub fn poll(&mut self, ctx: &egui::Context, mgr: &Arc<wg::Manager>) -> TrayAction {
        let mut action = TrayAction::None;
        while let Ok(id) = self.menu_rx.try_recv() {
            let next = self.dispatch(id, mgr);
            if !matches!(next, TrayAction::None) {
                action = next;
            }
        }

        if self.last_refresh.elapsed() > Duration::from_secs(3) {
            self.refresh(mgr);
            self.last_refresh = Instant::now();
        }

        // Keep the update cadence even when the window is hidden, so slot
        // labels and the tray icon stay fresh.
        ctx.request_repaint_after(Duration::from_secs(1));
        action
    }

    fn dispatch(&mut self, id: MenuId, mgr: &Arc<wg::Manager>) -> TrayAction {
        if id == self.quit_id {
            log::info!("gui: tray: quit clicked");
            mgr.disconnect_all();
            return TrayAction::Quit;
        }
        if id == self.manage_tunnels_id {
            log::info!("gui: tray: manage tunnels clicked");
            return TrayAction::ShowManageTunnels;
        }
        if id == self.add_id {
            return TrayAction::OpenAddConfig;
        }
        if id == self.open_dir_id {
            let _ = config::ensure_config_dir();
            let _ = std::process::Command::new("open")
                .arg(config::config_dir())
                .spawn();
            return TrayAction::None;
        }
        if id == self.logs_id {
            let log_path = config::config_dir().join("splitwg.log");
            let _ = std::process::Command::new("open")
                .arg("-a")
                .arg("TextEdit")
                .arg(log_path)
                .spawn();
            return TrayAction::None;
        }
        if id == self.hooks_toggle_id {
            return TrayAction::OpenPreferences;
        }
        if id == self.launch_at_login_id {
            self.handle_launch_at_login_toggle();
            return TrayAction::None;
        }
        if id == self.kill_switch_id {
            self.handle_kill_switch_toggle();
            return TrayAction::None;
        }
        if id == self.check_updates_id {
            return TrayAction::CheckUpdates;
        }
        if id == self.update_geodb_id {
            return TrayAction::UpdateGeoDb;
        }
        if id == self.lang_en_id {
            self.handle_language_switch(Lang::En);
            return TrayAction::None;
        }
        if id == self.lang_tr_id {
            self.handle_language_switch(Lang::Tr);
            return TrayAction::None;
        }

        // Slot click? Map menu id to slot index + kind.
        for slot in self.slots.iter() {
            let name = slot.name.lock().unwrap().clone();
            if name.is_empty() {
                continue;
            }
            if id == *slot.toggle_item.id() {
                let mgr = mgr.clone();
                thread::spawn(move || toggle_tunnel(&mgr, &name));
                return TrayAction::None;
            }
            if id == *slot.edit_item.id() {
                let _ = mgr; // handled by App via the returned action
                return TrayAction::EditRules(name);
            }
            if id == *slot.hooks_item.id() {
                thread::spawn(move || toggle_tunnel_hooks(&name));
                return TrayAction::None;
            }
        }
        TrayAction::None
    }

    /// Flips the login-item registration. When the system returns
    /// `RequiresApproval` we fire a notification pointing at
    /// System Settings → Login Items but leave the registration pending.
    fn handle_launch_at_login_toggle(&mut self) {
        let current = login_item::status();
        let result = match current {
            LoginItemState::Enabled => login_item::unregister(),
            _ => login_item::register(),
        };
        match result {
            Ok(()) => {
                let new_state = login_item::status();
                let (title_key, body_key) = match new_state {
                    LoginItemState::Enabled => (
                        "notify.splitwg",
                        "notify.launch_at_login.enabled",
                    ),
                    LoginItemState::RequiresApproval => (
                        "notify.splitwg",
                        "notify.launch_at_login.requires_approval",
                    ),
                    _ => ("notify.splitwg", "notify.launch_at_login.disabled"),
                };
                notify::info(&i18n::t(title_key), &i18n::t(body_key));
                log::info!("gui: tray: launch at login → {:?}", new_state);
            }
            Err(e) => {
                log::warn!("gui: tray: launch at login toggle: {e}");
                notify::error(
                    &i18n::t("notify.login_item_failed"),
                    &e,
                );
            }
        }
        self.last_refresh = Instant::now() - Duration::from_secs(10);
    }

    /// Flips `Settings.kill_switch` and persists. Like the Preferences
    /// modal, the change takes effect only on the next connect — already
    /// active tunnels keep their previous pf state. First-time enablement
    /// surfaces the manual flush hint so the user knows the escape hatch.
    fn handle_kill_switch_toggle(&mut self) {
        let mut settings = config::load_settings();
        let next = !settings.kill_switch;
        let was_off = !settings.kill_switch;
        settings.kill_switch = next;
        if let Err(e) = config::save_settings(&settings) {
            log::warn!("gui: tray: save_settings kill_switch: {e}");
            notify::error(
                &i18n::t("notify.preferences_title"),
                &i18n::t_with(
                    "notify.preferences_save_failed",
                    &[("error", &e.to_string())],
                ),
            );
            return;
        }
        let body_key = if next {
            "notify.kill_switch.enabled"
        } else {
            "notify.kill_switch.disabled"
        };
        let mut body = i18n::t(body_key);
        if next && was_off {
            body.push('\n');
            body.push_str(&i18n::t("gui.prefs.kill_switch.first_use_warning"));
        }
        notify::info(&i18n::t("notify.splitwg"), &body);
        log::info!("gui: tray: kill_switch → {next}");
        self.last_refresh = Instant::now() - Duration::from_secs(10);
    }

    fn handle_language_switch(&mut self, lang: Lang) {
        i18n::set_current(lang);
        let mut s = config::load_settings();
        s.language = Some(lang.code().to_string());
        if let Err(e) = config::save_settings(&s) {
            log::warn!("gui: tray: save_settings language: {e}");
            notify::error(
                &i18n::t("notify.preferences_title"),
                &i18n::t_with(
                    "notify.preferences_save_failed",
                    &[("error", &e.to_string())],
                ),
            );
            return;
        }
        log::info!("gui: tray: language set to {}", lang.code());
        notify::info(
            &i18n::t("notify.language_changed.title"),
            &i18n::t_with(
                "notify.language_changed.body",
                &[("language", lang.display_name())],
            ),
        );
        // Force the next poll cycle to re-apply labels.
        self.last_refresh = Instant::now() - Duration::from_secs(10);
    }

    /// Forces the next `poll()` cycle to re-apply labels and icons. Called
    /// by the App when settings change through a path that bypasses the
    /// tray menu (e.g. the Preferences modal).
    pub fn force_refresh(&mut self) {
        self.last_refresh = Instant::now() - Duration::from_secs(10);
    }

    /// Refreshes icon, tooltip, slot labels, and top-level menu text from
    /// disk state. Idempotent — safe to call every tick.
    fn refresh(&self, mgr: &wg::Manager) {
        let cfgs = match config::load_configs() {
            Ok(c) => c,
            Err(e) => {
                log::warn!("gui: tray: refresh load configs: {}", e);
                Vec::new()
            }
        };

        let mut any_connected = false;
        let global_hooks_on = config::load_settings().hooks_enabled;

        for (i, slot) in self.slots.iter().enumerate() {
            let mut in_menu = slot.in_menu.lock().unwrap();
            if let Some(cfg) = cfgs.get(i) {
                let connected = mgr.is_active(&cfg.name)
                    || wg::interface_for_config(&cfg.file_path).is_some();
                if connected {
                    any_connected = true;
                }
                let label = if connected {
                    i18n::t_with("tray.slot.connected", &[("name", &cfg.name)])
                } else {
                    i18n::t_with("tray.slot.disconnected", &[("name", &cfg.name)])
                };
                slot.submenu.set_text(&label);
                slot.submenu.set_enabled(true);
                slot.toggle_item.set_text(if connected {
                    i18n::t("tray.menu.disconnect")
                } else {
                    i18n::t("tray.menu.connect")
                });
                slot.toggle_item.set_enabled(true);
                slot.edit_item.set_text(i18n::t("tray.menu.edit_rules"));
                slot.edit_item.set_enabled(true);

                let hooks_label = match (global_hooks_on, cfg.rules.hooks_enabled) {
                    (false, _) => i18n::t("tray.hooks.disabled_globally"),
                    (true, true) => i18n::t("tray.hooks.on_click_disable"),
                    (true, false) => i18n::t("tray.hooks.off_click_enable"),
                };
                slot.hooks_item.set_text(&hooks_label);
                slot.hooks_item.set_enabled(global_hooks_on);

                *slot.name.lock().unwrap() = cfg.name.clone();
                *slot.config_path.lock().unwrap() = cfg.file_path.clone();

                if !*in_menu {
                    if let Err(e) = self.menu.insert(&slot.submenu, i) {
                        log::warn!("gui: tray: menu insert slot {}: {}", i, e);
                    } else {
                        *in_menu = true;
                    }
                }
            } else {
                slot.name.lock().unwrap().clear();
                *slot.config_path.lock().unwrap() = PathBuf::new();

                if *in_menu {
                    if let Err(e) = self.menu.remove(&slot.submenu) {
                        log::warn!("gui: tray: menu remove slot {}: {}", i, e);
                    } else {
                        *in_menu = false;
                    }
                }
            }
        }

        // Re-apply top-level labels so a language change propagates.
        self.add_item.set_text(i18n::t("tray.menu.add_config"));
        self.open_dir_item
            .set_text(i18n::t("tray.menu.open_config_dir"));
        self.logs_item.set_text(i18n::t("tray.menu.view_logs"));
        self.manage_tunnels_item
            .set_text(i18n::t("tray.menu.manage_tunnels"));
        self.quit_item.set_text(i18n::t("tray.menu.quit"));
        self.prefs_submenu
            .set_text(i18n::t("tray.menu.preferences"));
        self.hooks_toggle_item.set_text(hooks_toggle_label());
        self.launch_at_login_item
            .set_text(launch_at_login_label());
        self.kill_switch_item.set_text(kill_switch_label());
        self.check_updates_item
            .set_text(i18n::t("tray.submenu.preferences.check_updates"));
        self.update_geodb_item
            .set_text(i18n::t("tray.submenu.preferences.update_geodb"));
        self.lang_submenu.set_text(language_label());
        self.lang_en_item
            .set_text(i18n::t("tray.submenu.preferences.language.english"));
        self.lang_tr_item
            .set_text(i18n::t("tray.submenu.preferences.language.turkish"));

        let mut tooltip = i18n::t("tray.tooltip.prefix");
        for cfg in &cfgs {
            let connected = mgr.is_active(&cfg.name)
                || wg::interface_for_config(&cfg.file_path).is_some();
            let line = if connected {
                i18n::t_with("tray.tooltip.connected_line", &[("name", &cfg.name)])
            } else {
                i18n::t_with("tray.tooltip.disconnected_line", &[("name", &cfg.name)])
            };
            tooltip.push('\n');
            tooltip.push_str(&line);
        }
        if cfgs.is_empty() {
            tooltip.push('\n');
            tooltip.push_str(&i18n::t("tray.tooltip.no_configs"));
        }
        if any_connected {
            tooltip.push('\n');
            tooltip.push_str(&i18n::t_with(
                "tray.tooltip.throughput_line",
                &[
                    ("rx", &humanize_bytes_per_sec(self.last_rate.0)),
                    ("tx", &humanize_bytes_per_sec(self.last_rate.1)),
                ],
            ));
        }

        let _ = self._tray.set_tooltip(Some(&tooltip));
        let next_icon = if any_connected {
            self.connected_icon.clone()
        } else {
            self.disconnected_icon.clone()
        };
        let _ = self._tray.set_icon_with_as_template(Some(next_icon), true);
    }
}

/// Handles toggle_item clicks: Touch ID → connect, or disconnect.
fn toggle_tunnel(mgr: &wg::Manager, name: &str) {
    log::info!("gui: tray: toggle tunnel for {:?}", name);

    let cfgs = match config::load_configs() {
        Ok(c) => c,
        Err(e) => {
            log::warn!("gui: tray: toggle load configs: {}", e);
            notify::error(
                &i18n::t("notify.load_failed"),
                &format!("{}: {}", name, e),
            );
            return;
        }
    };
    let Some(cfg) = cfgs.iter().find(|c| c.name == name).cloned() else {
        notify::error(&i18n::t("notify.config_not_found"), name);
        return;
    };

    let is_active = mgr.is_active(name) || wg::interface_for_config(&cfg.file_path).is_some();

    if is_active {
        match mgr.disconnect(name) {
            Ok(()) => notify::info(&i18n::t("notify.disconnected"), name),
            Err(e) => notify::error(
                &i18n::t("notify.disconnect_failed"),
                &format!("{}: {}", name, e),
            ),
        }
        return;
    }

    let result = auth::authenticate(&i18n::t_with("auth.touchid_prompt", &[("name", name)]));
    match result {
        auth::AuthResult::Success => {}
        auth::AuthResult::NotAvailable => {
            log::info!(
                "gui: tray: Touch ID not available for {:?}, proceeding without biometric",
                name
            );
        }
        auth::AuthResult::Denied => {
            log::info!("gui: tray: Touch ID denied for {:?}", name);
            return;
        }
    }

    match mgr.connect(&cfg) {
        Ok(()) => notify::info(&i18n::t("notify.connected"), name),
        Err(e) => notify::error(
            &i18n::t("notify.connect_failed"),
            &format!("{}: {}", name, e),
        ),
    }
}

/// Flips the per-tunnel `hooks_enabled` flag and persists it. The global
/// flag is checked by the refresh path before this entry is even clickable.
fn toggle_tunnel_hooks(name: &str) {
    log::info!("gui: tray: toggle hooks for {:?}", name);

    let cfgs = match config::load_configs() {
        Ok(c) => c,
        Err(e) => {
            log::warn!("gui: tray: toggle hooks load configs: {}", e);
            notify::error(
                &i18n::t("notify.load_failed"),
                &format!("{}: {}", name, e),
            );
            return;
        }
    };
    let Some(cfg) = cfgs.iter().find(|c| c.name == name).cloned() else {
        notify::error(&i18n::t("notify.config_not_found"), name);
        return;
    };

    let mut new_rules = cfg.rules.clone();
    new_rules.hooks_enabled = !new_rules.hooks_enabled;

    match config::save_rules(name, &new_rules) {
        Ok(()) => {
            let state_key = if new_rules.hooks_enabled {
                "notify.state.enabled"
            } else {
                "notify.state.disabled"
            };
            let state = i18n::t(state_key);
            notify::info(
                &i18n::t("notify.splitwg"),
                &i18n::t_with(
                    "notify.tunnel_hooks_state",
                    &[("state", &state), ("name", name)],
                ),
            );
        }
        Err(e) => {
            log::warn!("gui: tray: save_rules: {e}");
            notify::error(
                &i18n::t("notify.toggle_hooks_failed"),
                &format!("{}: {}", name, e),
            );
        }
    }
}

fn hooks_toggle_label() -> String {
    let state_key = if config::load_settings().hooks_enabled {
        "tray.submenu.preferences.hooks_state.on"
    } else {
        "tray.submenu.preferences.hooks_state.off"
    };
    let state = i18n::t(state_key);
    i18n::t_with(
        "tray.submenu.preferences.hooks_label",
        &[("state", &state)],
    )
}

fn launch_at_login_label() -> String {
    match login_item::status() {
        LoginItemState::Enabled => i18n::t_with(
            "tray.submenu.preferences.launch_at_login_label",
            &[("state", &i18n::t("tray.submenu.preferences.hooks_state.on"))],
        ),
        LoginItemState::RequiresApproval => {
            i18n::t("tray.submenu.preferences.launch_at_login.requires_approval")
        }
        _ => i18n::t_with(
            "tray.submenu.preferences.launch_at_login_label",
            &[("state", &i18n::t("tray.submenu.preferences.hooks_state.off"))],
        ),
    }
}

fn kill_switch_label() -> String {
    let state_key = if config::load_settings().kill_switch {
        "tray.submenu.preferences.hooks_state.on"
    } else {
        "tray.submenu.preferences.hooks_state.off"
    };
    let state = i18n::t(state_key);
    i18n::t_with(
        "tray.submenu.preferences.kill_switch_label",
        &[("state", &state)],
    )
}

fn language_label() -> String {
    i18n::t_with(
        "tray.submenu.preferences.language_label",
        &[("name", i18n::current().display_name())],
    )
}

fn initial_tooltip() -> String {
    let mut t = i18n::t("tray.tooltip.prefix");
    t.push('\n');
    t.push_str(&i18n::t("tray.tooltip.no_configs"));
    t
}

/// Human-readable bytes-per-second for the tray tooltip. Parallels
/// `wg_stat::humanize_bytes` but appends `/s` and leaves zero-rate visible
/// as `0 B/s` so the user sees the throughput line even when idle.
fn humanize_bytes_per_sec(bps: f32) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bps.max(0.0) as f64;
    if v < 1.0 {
        return "0 B/s".to_string();
    }
    let mut idx = 0;
    while v >= 1024.0 && idx + 1 < UNITS.len() {
        v /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{:.0} {}/s", v, UNITS[idx])
    } else {
        format!("{:.2} {}/s", v, UNITS[idx])
    }
}

fn load_icon(bytes: &[u8]) -> Result<Icon, Box<dyn std::error::Error>> {
    let img = image::load_from_memory(bytes)?;
    let w = img.width();
    let h = img.height();
    let rgba = img.to_rgba8().into_raw();
    Ok(Icon::from_rgba(rgba, w, h)?)
}
