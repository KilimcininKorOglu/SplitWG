//! eframe `App` — hosts the tray, holds GUI state, renders master/detail.
//!
//! Window lifecycle: the viewport is created with `with_visible(false)` so
//! the app boots tray-only. When the user picks "Manage Tunnels…" from the
//! tray we flip visibility on; when they hit the red close button we
//! intercept the close request and flip visibility back off instead of
//! exiting. The only true exit paths are the tray's Quit entry and Cmd-Q
//! after the window has already been shown.

use std::collections::{HashMap, HashSet};
use std::sync::{mpsc, Arc, RwLock};
use std::time::{Duration, Instant};

use crate::config::{self, Config};
use crate::ipc::Event as IpcEvent;
use crate::wg::on_demand::{self, Desired, NetState};
use crate::{i18n, notify, wg};

use super::detail::logs::LogsTabState;
use super::detail::rules::RulesTabState;
use super::detail_panel::{self, DetailEvent, DetailTab};
use super::log_tail::LogTail;
use super::modals::{
    self, AddEvent, AddFlow, ConfigEditorEvent, ConfigEditorFlow, DeleteEvent, ExportEvent,
    ExportFlow, ImportEvent, ImportFlow, PrefsEvent, PrefsFlow, RenameEvent, RenameFlow,
};
use super::package;
use super::sparkline::{RttHistory, TransferHistory};
use super::tasks::{self, TaskResult, TaskRx, TaskTx};

/// UI state for a tunnel's ping button + last result. Kept alive across
/// frames so the previous RTT stays on screen until the next click.
#[derive(Debug, Default, Clone)]
pub struct PingDisplay {
    pub inflight: bool,
    pub last_ms: Option<u32>,
    pub last_was_timeout: bool,
}
use super::theme::ThemeState;
use super::tray_host::{TrayAction, TrayHost};
use super::tunnels_panel::{self, PanelEvent};
use super::wg_stat::{self, StatsCache};

pub struct App {
    mgr: Arc<wg::Manager>,
    tray: TrayHost,

    configs: Vec<Config>,
    selected: Option<String>,
    active_tab: DetailTab,
    stats: StatsCache,
    peer_key_cache: HashMap<String, String>,
    /// Per-tunnel per-second throughput history keyed by tunnel name. Only
    /// populated for tunnels with live `WgStats` — torn-down tunnels get
    /// their history dropped by `refresh`.
    transfer_history: HashMap<String, TransferHistory>,
    /// Per-tunnel ping status. Entry exists while a ping is in flight or
    /// after the first result; cleared when the tunnel is torn down.
    ping_results: HashMap<String, PingDisplay>,
    /// Per-tunnel rolling RTT history for the Status tab sparkline. Fed by
    /// both manual Ping clicks and the 5 s periodic probe below.
    rtt_history: HashMap<String, RttHistory>,
    /// Last time a periodic RTT probe was scheduled, keyed by tunnel name.
    /// Gates the 5 s cooldown so we don't flood `/sbin/ping` with parallel
    /// probes while the Status tab is open.
    last_rtt_ping: HashMap<String, Instant>,
    theme: ThemeState,

    /// Tunnels currently being connected or disconnected. UI uses this to
    /// disable the Activate/Deactivate button and show the "…ing" label.
    in_progress: HashSet<String>,
    task_tx: TaskTx,
    task_rx: TaskRx,

    /// Draft rules for the currently-selected tunnel. Dropped on selection
    /// change — unsaved edits for a different tunnel are discarded.
    rules_state: Option<RulesTabState>,
    logs_state: LogsTabState,
    log_tail: LogTail,

    add_flow: Option<AddFlow>,
    delete_flow: Option<String>,
    prefs_flow: Option<PrefsFlow>,
    export_flow: Option<ExportFlow>,
    import_flow: Option<ImportFlow>,
    about_flow: Option<modals::AboutFlow>,
    config_editor_flow: Option<ConfigEditorFlow>,
    rename_flow: Option<RenameFlow>,

    /// Tracks whether the main window is currently shown. The tray owns
    /// the canonical state (it's the one that asks for show/hide), but we
    /// mirror it here so we can gate per-frame work (config reload, stats
    /// query) when the user isn't looking.
    window_visible: bool,
    last_refresh: Instant,

    /// Shared network state snapshot updated by the background monitor.
    /// The main thread doesn't read it directly (changes arrive via
    /// `net_rx`); we keep the `Arc` alive so the monitor's clone keeps
    /// pointing at a live value.
    #[allow(dead_code)]
    net_state: Arc<RwLock<NetState>>,
    /// Receiver end of the monitor's change-notification channel.
    net_rx: mpsc::Receiver<NetState>,
    /// Tunnels the user has toggled manually this session — the on-demand
    /// monitor will not override these until the app restarts or the user
    /// edits the tunnel's on-demand rule.
    manual_override: HashSet<String>,

    /// Per-tunnel auto-reconnect watchdog state — consecutive failures and
    /// a cooldown timestamp so three bad attempts suspend the watchdog for
    /// that tunnel for ten minutes.
    watchdog_state: HashMap<String, WatchdogEntry>,
    /// Last time the watchdog scanned the active tunnels. Scans run every
    /// 15 s so stale handshakes are detected without spamming `wg show dump`.
    last_watchdog_check: Instant,
    /// Receiver for `x-splitwg://` URL scheme events. Populated by the
    /// AppleEvent handler installed at `App::new`; drained every frame.
    url_rx: mpsc::Receiver<super::url_scheme::UrlAction>,
    pending_url_action: Option<(super::url_scheme::UrlAction, Config)>,

    /// Latest update announcement seeded by `TaskResult::UpdateAvailable`.
    /// Phase 3 extends this into a download/ready state machine; Phase 2
    /// only populates the announced state.
    pub(crate) pending_update: Option<PendingUpdate>,
    /// Guard flag set while a check is mid-flight so the app does not stack
    /// multiple background requests. Cleared on every terminal variant.
    update_check_inflight: bool,
    /// Debounce for the manual "Check now" button.
    last_manual_update_click: Option<Instant>,

    /// Guard flag set while a GeoDB pull is in flight so neither the
    /// background scheduler nor rapid manual clicks can stack requests.
    geodb_update_inflight: bool,
    /// Debounce for the manual "Update now" GeoDB button.
    last_manual_geodb_click: Option<Instant>,

    /// `true` when the tray Quit entry was clicked. Flips the next
    /// `close_requested()` from "hide the window" to "actually exit".
    /// Without this the intercept below swallows `ViewportCommand::
    /// Close` and the app can never quit through the tray.
    quit_requested: bool,
}

/// Lifecycle of an in-progress update. Transitions:
/// `Announced → Downloading → Ready` on the happy path; any of the first
/// two can fall through to `Failed` on verification or network errors.
#[derive(Debug, Clone)]
pub enum PendingUpdate {
    Announced {
        version: String,
        changelog: String,
        dmg_url: String,
        minisig_url: String,
        digest: Option<String>,
    },
    Downloading {
        version: String,
        changelog: String,
        downloaded: u64,
        total: u64,
    },
    Ready {
        version: String,
        changelog: String,
        app_path: std::path::PathBuf,
        mount_point: std::path::PathBuf,
        dmg_image_path: std::path::PathBuf,
    },
    Failed {
        version: String,
        reason: String,
    },
}

impl PendingUpdate {
    /// Borrow the cached changelog regardless of which stage the update is
    /// currently in. Phase 4 displays it in the install modal.
    pub fn changelog(&self) -> &str {
        match self {
            PendingUpdate::Announced { changelog, .. }
            | PendingUpdate::Downloading { changelog, .. }
            | PendingUpdate::Ready { changelog, .. } => changelog,
            PendingUpdate::Failed { .. } => "",
        }
    }

    pub fn version(&self) -> &str {
        match self {
            PendingUpdate::Announced { version, .. }
            | PendingUpdate::Downloading { version, .. }
            | PendingUpdate::Ready { version, .. }
            | PendingUpdate::Failed { version, .. } => version,
        }
    }
}

/// Per-tunnel watchdog bookkeeping. `consecutive_failures` is reset on a
/// successful reconnect; after three failures the watchdog cools down for
/// `cooldown_until` so a broken config does not burn CPU + notifications.
#[derive(Debug, Default)]
pub struct WatchdogEntry {
    pub consecutive_failures: u8,
    pub cooldown_until: Option<Instant>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Result<Self, Box<dyn std::error::Error>> {
        // Wipe downloaded DMGs and extracted .app bundles older than a
        // week. Runs exactly once per process — a second App::new inside
        // the same process (tests) skips it.
        static CLEANUP: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        CLEANUP.get_or_init(super::update::cleanup_stale_downloads);

        let mgr = Arc::new(wg::Manager::new());
        let tray = TrayHost::new(&cc.egui_ctx)?;

        // Seed the config list on boot so the first show is instant.
        let configs = config::load_configs().unwrap_or_default();
        let (task_tx, task_rx) = tasks::channel();

        // Network monitor + change channel. The initial snapshot is taken
        // on the main thread so the first rule evaluation sees a real
        // NetState rather than the default (all-off) value.
        let net_state = Arc::new(RwLock::new(super::network_monitor::current_state()));
        let (net_tx, net_rx) = mpsc::channel();
        super::network_monitor::start(cc.egui_ctx.clone(), net_state.clone(), net_tx);

        // Install the macOS URL scheme handler — `x-splitwg://connect/...`
        // et al. Runs on the main thread while eframe boots; the AppleEvent
        // registration is idempotent across warm restarts.
        let url_rx = super::url_scheme::install(cc.egui_ctx.clone());

        Ok(App {
            mgr,
            tray,
            configs,
            selected: None,
            active_tab: DetailTab::default(),
            stats: StatsCache::new(),
            peer_key_cache: HashMap::new(),
            transfer_history: HashMap::new(),
            ping_results: HashMap::new(),
            rtt_history: HashMap::new(),
            last_rtt_ping: HashMap::new(),
            theme: ThemeState::default(),
            in_progress: HashSet::new(),
            task_tx,
            task_rx,
            rules_state: None,
            logs_state: LogsTabState::default(),
            log_tail: LogTail::default(),
            add_flow: None,
            delete_flow: None,
            prefs_flow: None,
            export_flow: None,
            import_flow: None,
            about_flow: None,
            config_editor_flow: None,
            rename_flow: None,
            window_visible: false,
            last_refresh: Instant::now() - Duration::from_secs(10),
            net_state,
            net_rx,
            manual_override: HashSet::new(),
            watchdog_state: HashMap::new(),
            last_watchdog_check: Instant::now() - Duration::from_secs(60),
            url_rx,
            pending_url_action: None,
            pending_update: None,
            update_check_inflight: false,
            last_manual_update_click: None,
            geodb_update_inflight: false,
            last_manual_geodb_click: None,
            quit_requested: false,
        })
    }

    /// Kicks off a background GitHub Releases check when the user has
    /// opted in and the 7-day cooldown has elapsed. Persists
    /// `last_update_check` ahead of the request so a network failure does
    /// not retry every frame.
    fn maybe_check_for_updates(&mut self, ctx: &egui::Context) {
        if self.update_check_inflight {
            return;
        }
        let mut settings = config::load_settings();
        if !settings.update_check_enabled {
            return;
        }
        if !super::update::cooldown_elapsed(settings.last_update_check) {
            return;
        }
        settings.last_update_check = Some(super::update::now_epoch());
        if let Err(e) = config::save_settings(&settings) {
            log::warn!("gui: update: save_settings failed: {e}");
            return;
        }
        self.update_check_inflight = true;
        tasks::spawn_update_check(self.task_tx.clone(), ctx.clone(), false);
    }

    /// Triggers an immediate update check without touching the cooldown
    /// timer. Called from the Preferences "Check now" button and the tray
    /// submenu entry. Debounces rapid duplicate clicks (10 s window).
    pub(crate) fn trigger_manual_update_check(&mut self, ctx: &egui::Context) {
        if self.update_check_inflight {
            return;
        }
        if let Some(ts) = self.last_manual_update_click {
            if ts.elapsed() < Duration::from_secs(10) {
                return;
            }
        }
        self.last_manual_update_click = Some(Instant::now());
        let mut settings = config::load_settings();
        settings.last_update_check = Some(super::update::now_epoch());
        let _ = config::save_settings(&settings);
        self.update_check_inflight = true;
        tasks::spawn_update_check(self.task_tx.clone(), ctx.clone(), true);
    }

    /// Kicks off a background GeoDB pull when the user has opted in and
    /// the 24-hour cooldown has elapsed. Persists `last_geodb_update`
    /// ahead of the request so a network failure does not retry every
    /// frame.
    fn maybe_update_geodb(&mut self, ctx: &egui::Context) {
        if self.geodb_update_inflight {
            return;
        }
        let mut settings = config::load_settings();
        if !settings.geodb_auto_update_enabled {
            return;
        }
        if !super::geodb::cooldown_elapsed(settings.last_geodb_update) {
            return;
        }
        settings.last_geodb_update = Some(super::geodb::now_epoch());
        if let Err(e) = config::save_settings(&settings) {
            log::warn!("gui: geodb: save_settings failed: {e}");
            return;
        }
        self.geodb_update_inflight = true;
        tasks::spawn_geodb_update(self.task_tx.clone(), ctx.clone(), false);
    }

    /// Triggers an immediate GeoDB pull without touching the cooldown
    /// timer. Called from the Preferences "Update now" button and the
    /// tray submenu entry. Debounces rapid duplicate clicks (10 s).
    pub(crate) fn trigger_manual_geodb_update(&mut self, ctx: &egui::Context) {
        if self.geodb_update_inflight {
            return;
        }
        if let Some(ts) = self.last_manual_geodb_click {
            if ts.elapsed() < Duration::from_secs(10) {
                return;
            }
        }
        self.last_manual_geodb_click = Some(Instant::now());
        let mut settings = config::load_settings();
        settings.last_geodb_update = Some(super::geodb::now_epoch());
        let _ = config::save_settings(&settings);
        self.geodb_update_inflight = true;
        tasks::spawn_geodb_update(self.task_tx.clone(), ctx.clone(), true);
    }

    /// Drains any `x-splitwg://` URL events delivered since the last frame
    /// and dispatches them through the existing `spawn_toggle` worker. The
    /// `manual_override` set is seeded so the on-demand evaluator does not
    /// immediately fight a Shortcuts-triggered state change.
    fn drain_url_events(&mut self, _ctx: &egui::Context) {
        use super::url_scheme::UrlAction;
        while let Ok(action) = self.url_rx.try_recv() {
            let name = match &action {
                UrlAction::Connect(n) | UrlAction::Disconnect(n) | UrlAction::Toggle(n) => {
                    n.clone()
                }
            };
            let Some(cfg) = self.configs.iter().find(|c| c.name == name).cloned() else {
                log::warn!("splitwg: url_scheme: tunnel not found: {name}");
                notify::error(
                    &i18n::t("notify.splitwg"),
                    &i18n::t_with(
                        "notify.url_scheme.unknown_tunnel",
                        &[("name", &name)],
                    ),
                );
                continue;
            };
            let verb = match &action {
                UrlAction::Connect(_) => "connect",
                UrlAction::Disconnect(_) => "disconnect",
                UrlAction::Toggle(_) => "toggle",
            };
            log::info!("splitwg: url_scheme: queuing confirmation for {verb} {name}");
            self.pending_url_action = Some((action, cfg));
        }
    }

    fn show_url_confirmation(&mut self, ctx: &egui::Context) {
        let Some((ref action, ref cfg)) = self.pending_url_action else {
            return;
        };
        use super::url_scheme::UrlAction;
        let verb = match action {
            UrlAction::Connect(_) => i18n::t("gui.url_confirm.connect"),
            UrlAction::Disconnect(_) => i18n::t("gui.url_confirm.disconnect"),
            UrlAction::Toggle(_) => i18n::t("gui.url_confirm.toggle"),
        };
        let name = cfg.name.clone();
        let mut accepted = false;
        let mut dismissed = false;

        egui::Window::new(i18n::t("gui.url_confirm.title"))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(i18n::t_with(
                    "gui.url_confirm.message",
                    &[("action", &verb), ("name", &name)],
                ));
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button(i18n::t("gui.url_confirm.allow")).clicked() {
                        accepted = true;
                    }
                    if ui.button(i18n::t("gui.url_confirm.deny")).clicked() {
                        dismissed = true;
                    }
                });
            });

        if accepted {
            let (action, cfg) = self.pending_url_action.take().unwrap();
            let is_active = self.mgr.is_active(&cfg.name);
            let should_spawn = match &action {
                UrlAction::Connect(_) => !is_active,
                UrlAction::Disconnect(_) => is_active,
                UrlAction::Toggle(_) => true,
            };
            if should_spawn {
                self.in_progress.insert(cfg.name.clone());
                self.manual_override.insert(cfg.name.clone());
                tasks::spawn_toggle(
                    self.task_tx.clone(),
                    ctx.clone(),
                    self.mgr.clone(),
                    cfg,
                    is_active,
                );
            }
        } else if dismissed {
            log::info!("splitwg: url_scheme: user denied URL action");
            self.pending_url_action = None;
        }
    }

    /// Processes Stats / Handshake events forwarded from helper stdout via
    /// `Manager::drain_events`. Populates the same `StatsCache` that the UI
    /// reads, replacing the old `wg show dump` path.
    fn drain_ipc_events(&mut self) {
        for (name, ev) in self.mgr.drain_events() {
            let peer_key = self.peer_key_cache.entry(name.clone()).or_insert_with(|| {
                wg::conf::first_peer_public_key_base64(
                    &std::fs::read_to_string(config::conf_path(&name)).unwrap_or_default(),
                )
                .unwrap_or_default()
            }).clone();
            match ev {
                IpcEvent::Stats { tx_bytes, rx_bytes } => {
                    let entry = self.stats.entry(name.clone()).or_default();
                    if let Some(peer) = entry.peers.first_mut() {
                        peer.tx_bytes = tx_bytes;
                        peer.rx_bytes = rx_bytes;
                    } else {
                        entry.peers.push(wg_stat::PeerStats {
                            public_key: peer_key,
                            tx_bytes,
                            rx_bytes,
                            ..Default::default()
                        });
                    }
                }
                IpcEvent::Handshake { at, .. } => {
                    if let Ok(epoch) = at.parse::<u64>() {
                        let entry = self.stats.entry(name.clone()).or_default();
                        if let Some(peer) = entry.peers.first_mut() {
                            peer.last_handshake = Some(epoch);
                        } else {
                            entry.peers.push(wg_stat::PeerStats {
                                public_key: peer_key,
                                last_handshake: Some(epoch),
                                ..Default::default()
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn drain_task_results(&mut self) {
        while let Ok(result) = self.task_rx.try_recv() {
            match result {
                TaskResult::Connected(name) => {
                    self.in_progress.remove(&name);
                    notify::info(&i18n::t("notify.connected"), &name);
                    self.last_refresh = Instant::now() - Duration::from_secs(10);
                }
                TaskResult::Disconnected(name) => {
                    self.in_progress.remove(&name);
                    notify::info(&i18n::t("notify.disconnected"), &name);
                    self.last_refresh = Instant::now() - Duration::from_secs(10);
                }
                TaskResult::AuthDenied(name) => {
                    self.in_progress.remove(&name);
                    notify::info(
                        &i18n::t("notify.splitwg"),
                        &i18n::t("gui.detail.status.auth_denied"),
                    );
                }
                TaskResult::Error { name, message } => {
                    self.in_progress.remove(&name);
                    notify::error(
                        &i18n::t("notify.connect_failed"),
                        &format!("{}: {}", name, message),
                    );
                }
                TaskResult::RulesApplied(name) => {
                    self.in_progress.remove(&name);
                    notify::info(
                        &i18n::t("notify.splitwg"),
                        &i18n::t("notify.rules_applied"),
                    );
                    self.last_refresh = Instant::now() - Duration::from_secs(10);
                    let _ = name;
                }
                TaskResult::Pinged { name, result } => {
                    let entry = self.ping_results.entry(name.clone()).or_default();
                    entry.inflight = false;
                    entry.last_ms = result;
                    entry.last_was_timeout = result.is_none();
                    self.rtt_history
                        .entry(name)
                        .or_default()
                        .record(result);
                }
                TaskResult::OnDemandTriggered { name, connected } => {
                    self.in_progress.remove(&name);
                    let key = if connected {
                        "notify.on_demand.activated"
                    } else {
                        "notify.on_demand.deactivated"
                    };
                    notify::info(&i18n::t("notify.splitwg"), &i18n::t_with(key, &[("name", &name)]));
                    self.last_refresh = Instant::now() - Duration::from_secs(10);
                }
                TaskResult::UpdateAvailable {
                    version,
                    changelog,
                    dmg_url,
                    minisig_url,
                    digest,
                } => {
                    self.update_check_inflight = false;
                    notify::info(
                        &i18n::t("notify.update.available_title"),
                        &i18n::t_with(
                            "notify.update.available_body",
                            &[("version", &version)],
                        ),
                    );
                    self.pending_update = Some(PendingUpdate::Announced {
                        version,
                        changelog,
                        dmg_url,
                        minisig_url,
                        digest,
                    });
                }
                TaskResult::UpdateUpToDate {
                    version,
                    user_initiated,
                } => {
                    self.update_check_inflight = false;
                    if user_initiated {
                        notify::info(
                            &i18n::t("notify.splitwg"),
                            &i18n::t_with(
                                "notify.update.up_to_date",
                                &[("version", &version)],
                            ),
                        );
                    }
                }
                TaskResult::UpdateCheckFailed {
                    message,
                    user_initiated,
                } => {
                    self.update_check_inflight = false;
                    log::warn!("gui: update: check failed: {message}");
                    if user_initiated {
                        notify::error(
                            &i18n::t("notify.splitwg"),
                            &i18n::t_with(
                                "notify.update.check_failed",
                                &[("error", &message)],
                            ),
                        );
                    }
                }
                TaskResult::UpdateDownloadProgress {
                    version,
                    downloaded,
                    total,
                } => {
                    if let Some(PendingUpdate::Downloading {
                        version: current,
                        downloaded: dl,
                        total: tot,
                        ..
                    }) = self.pending_update.as_mut()
                    {
                        if *current == version {
                            *dl = downloaded;
                            *tot = total;
                        }
                    }
                }
                TaskResult::UpdateReady {
                    version,
                    app_path,
                    dmg_image_path,
                    mount_point,
                } => {
                    let changelog = self
                        .pending_update
                        .as_ref()
                        .map(|p| p.changelog().to_string())
                        .unwrap_or_default();
                    self.pending_update = Some(PendingUpdate::Ready {
                        version,
                        changelog,
                        app_path,
                        mount_point,
                        dmg_image_path,
                    });
                }
                TaskResult::UpdateVerificationFailed { version, reason } => {
                    log::warn!(
                        "gui: update: verification failed for {version}: {reason}"
                    );
                    self.pending_update = Some(PendingUpdate::Failed { version, reason });
                }
                TaskResult::UpdateInstallFailed { version, reason } => {
                    log::warn!(
                        "gui: update: install failed for {version}: {reason}"
                    );
                    notify::error(
                        &i18n::t("notify.splitwg"),
                        &i18n::t_with(
                            "notify.update.install_failed",
                            &[("reason", &reason)],
                        ),
                    );
                    self.pending_update = Some(PendingUpdate::Failed { version, reason });
                }
                TaskResult::GeoDbUpdated {
                    updated,
                    total_bytes,
                    user_initiated: _,
                } => {
                    self.geodb_update_inflight = false;
                    notify::info(
                        &i18n::t("notify.splitwg"),
                        &i18n::t_with(
                            "notify.geodb.updated",
                            &[
                                ("files", &updated.len().to_string()),
                                ("size", &humanize_bytes(total_bytes)),
                            ],
                        ),
                    );
                }
                TaskResult::GeoDbUpToDate { user_initiated } => {
                    self.geodb_update_inflight = false;
                    if user_initiated {
                        notify::info(
                            &i18n::t("notify.splitwg"),
                            &i18n::t("notify.geodb.up_to_date"),
                        );
                    }
                }
                TaskResult::GeoDbUpdateFailed {
                    message,
                    user_initiated,
                } => {
                    self.geodb_update_inflight = false;
                    log::warn!("gui: geodb: pull failed: {message}");
                    if user_initiated {
                        notify::error(
                            &i18n::t("notify.splitwg"),
                            &i18n::t_with(
                                "notify.geodb.update_failed",
                                &[("error", &message)],
                            ),
                        );
                    }
                }
                TaskResult::WatchdogReconnect { name, ok } => {
                    self.in_progress.remove(&name);
                    let entry = self.watchdog_state.entry(name.clone()).or_default();
                    if ok {
                        entry.consecutive_failures = 0;
                        notify::info(
                            &i18n::t("notify.splitwg"),
                            &i18n::t_with(
                                "notify.watchdog.succeeded",
                                &[("name", &name)],
                            ),
                        );
                        self.last_refresh = Instant::now() - Duration::from_secs(10);
                    } else {
                        entry.consecutive_failures =
                            entry.consecutive_failures.saturating_add(1);
                        if entry.consecutive_failures >= 3 {
                            entry.cooldown_until =
                                Some(Instant::now() + Duration::from_secs(600));
                            entry.consecutive_failures = 0;
                            notify::info(
                                &i18n::t("notify.splitwg"),
                                &i18n::t_with(
                                    "notify.watchdog.cooldown",
                                    &[("name", &name)],
                                ),
                            );
                        } else {
                            notify::error(
                                &i18n::t("notify.watchdog.failed"),
                                &name,
                            );
                        }
                    }
                }
            }
        }
    }

    /// Drains net-state changes and evaluates every tunnel's on-demand
    /// rule against the new snapshot. Manual overrides skip evaluation.
    fn drain_network_changes(&mut self, ctx: &egui::Context) {
        let mut latest: Option<NetState> = None;
        while let Ok(state) = self.net_rx.try_recv() {
            latest = Some(state);
        }
        let Some(state) = latest else { return };
        self.apply_on_demand(ctx, &state);
    }

    fn apply_on_demand(&mut self, ctx: &egui::Context, state: &NetState) {
        // First pass — compute each tunnel's pure `decide()` answer and
        // capture whether it's already active. Tunnels under a manual
        // override or without a rule at all are skipped entirely (they
        // must not participate in group arbitration either).
        let mut candidates: Vec<Candidate> = Vec::new();
        for cfg in self.configs.clone() {
            if self.manual_override.contains(&cfg.name) {
                continue;
            }
            let Some(rule) = cfg.rules.on_demand.as_ref() else {
                continue;
            };
            let is_active = self.mgr.is_active(&cfg.name)
;
            let desired = on_demand::decide(rule, state);
            let group = rule
                .exclusive_group
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            candidates.push(Candidate {
                cfg,
                desired,
                is_active,
                group,
            });
        }

        // Second pass — arbitrate groups. Within each non-empty group, the
        // currently-active Connect claimant wins; otherwise the first
        // candidate in `configs` order wins. Losers are demoted to
        // Disconnect so only one tunnel in the group stays up.
        let winners = select_group_winners(&candidates);

        for (idx, cand) in candidates.into_iter().enumerate() {
            let desired = match cand.group {
                Some(_) if !winners.contains(&idx) => Desired::Disconnect,
                _ => cand.desired,
            };
            match desired {
                Desired::Untouched => {}
                Desired::Connect if !cand.is_active => {
                    self.spawn_on_demand(ctx, cand.cfg, true);
                }
                Desired::Disconnect if cand.is_active => {
                    self.spawn_on_demand(ctx, cand.cfg, false);
                }
                _ => {}
            }
        }
    }

    fn spawn_on_demand(&mut self, ctx: &egui::Context, cfg: Config, connect: bool) {
        self.in_progress.insert(cfg.name.clone());
        let tx = self.task_tx.clone();
        let ctx = ctx.clone();
        let mgr = self.mgr.clone();
        std::thread::spawn(move || {
            let name = cfg.name.clone();
            let result = if connect {
                tasks::ensure_connected(&mgr, &cfg, false)
                    .map_err(|e| match e {
                        tasks::ConnectError::SetupFailed(msg)
                        | tasks::ConnectError::ConnectFailed(msg) => msg,
                        tasks::ConnectError::AuthDenied => "auth denied".into(),
                    })
            } else {
                mgr.disconnect(&name).map_err(|e| e.to_string())
            };
            match result {
                Ok(()) => {
                    log::info!(
                        "splitwg: on-demand: {} {}",
                        if connect { "connected" } else { "disconnected" },
                        name
                    );
                    let _ = tx.send(TaskResult::OnDemandTriggered {
                        name,
                        connected: connect,
                    });
                }
                Err(msg) => {
                    let _ = tx.send(TaskResult::Error {
                        name,
                        message: format!("on-demand: {msg}"),
                    });
                }
            }
            ctx.request_repaint();
        });
    }

    /// Scans every managed tunnel for a stale handshake and cycles it when
    /// the peer has been silent for more than `max(3 * keepalive, 180 s)`.
    /// Runs every 15 s regardless of window visibility so the watchdog
    /// works while SplitWG sits in the tray. Skips tunnels under manual
    /// override or currently in-flight (manual connect/disconnect / prior
    /// watchdog spawn) and respects per-tunnel cooldown after three
    /// consecutive failures.
    fn check_watchdog(&mut self, ctx: &egui::Context) {
        if self.last_watchdog_check.elapsed() < Duration::from_secs(15) {
            return;
        }
        self.last_watchdog_check = Instant::now();

        let configs = self.configs.clone();
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for cfg in &configs {
            if self.manual_override.contains(&cfg.name) {
                continue;
            }
            if self.in_progress.contains(&cfg.name) {
                continue;
            }
            let entry = self.watchdog_state.entry(cfg.name.clone()).or_default();
            if let Some(until) = entry.cooldown_until {
                if Instant::now() < until {
                    continue;
                }
                entry.cooldown_until = None;
            }
            if !self.mgr.is_active(&cfg.name) {
                continue;
            }

            // Handshake info comes from IPC stats events. If no stats
            // exist yet for this tunnel, skip.
            let Some(stats) = self.stats.get(&cfg.name) else {
                continue;
            };
            let Some(peer) = stats.peers.first() else {
                continue;
            };
            let Some(last_hs) = peer.last_handshake else {
                continue;
            };
            let ka = peer.persistent_keepalive.unwrap_or(25).max(1) as u64;
            let threshold = (3u64.saturating_mul(ka)).max(180);
            if now_epoch.saturating_sub(last_hs) <= threshold {
                continue;
            }

            log::warn!(
                "splitwg: watchdog: {} handshake stale ({}s > {}s), cycling",
                cfg.name,
                now_epoch.saturating_sub(last_hs),
                threshold
            );
            self.in_progress.insert(cfg.name.clone());
            notify::info(
                &i18n::t("notify.splitwg"),
                &i18n::t_with("notify.watchdog.reconnecting", &[("name", &cfg.name)]),
            );
            tasks::spawn_watchdog_reconnect(
                self.task_tx.clone(),
                ctx.clone(),
                self.mgr.clone(),
                cfg.name.clone(),
            );
        }
    }

    /// Re-reads configs and feeds IPC-sourced stats into the transfer
    /// history / sparkline. Called once per second while the window is visible.
    fn refresh(&mut self, ctx: &egui::Context) {
        self.configs = config::load_configs().unwrap_or_default();

        // Stats are only meaningful for active tunnels; drop entries for
        // configs that were removed or torn down.
        self.stats.retain(|name, _| {
            self.configs.iter().any(|c| c.name == *name) && self.mgr.is_active(name)
        });

        // IPC events have already populated self.stats via drain_ipc_events.
        // Here we just update the per-second throughput history.
        for cfg in &self.configs {
            if let Some(stats) = self.stats.get(&cfg.name) {
                let (rx_total, tx_total) = stats
                    .peers
                    .iter()
                    .fold((0u64, 0u64), |(r, t), p| {
                        (r.saturating_add(p.rx_bytes), t.saturating_add(p.tx_bytes))
                    });
                self.transfer_history
                    .entry(cfg.name.clone())
                    .and_modify(|h| {
                        h.record(rx_total, tx_total);
                    })
                    .or_insert_with(|| TransferHistory::new(rx_total, tx_total));
            }
        }

        // Drop history for tunnels that are no longer active.
        self.transfer_history
            .retain(|name, _| self.stats.contains_key(name));
        // Same for ping results — only keep entries for currently-known
        // tunnels so stale RTTs don't reappear after a rename/delete.
        self.ping_results
            .retain(|name, _| self.configs.iter().any(|c| &c.name == name));
        // RTT history tracks *active* tunnels only — freshly-connected
        // tunnels start with an empty sparkline.
        self.rtt_history
            .retain(|name, _| self.stats.contains_key(name));
        self.last_rtt_ping
            .retain(|name, _| self.stats.contains_key(name));

        // Schedule a periodic RTT probe for the selected tunnel when the
        // Status tab is visible. All seven gates from the plan are
        // evaluated here in order; missing any one of them skips the probe.
        self.maybe_schedule_rtt_probe(ctx);

        // Aggregate latest throughput across all active tunnels and push
        // the total into the tray tooltip. `TransferHistory::latest()`
        // reads without mutating, so no sample is consumed here.
        let (rx_sum, tx_sum) = self
            .transfer_history
            .values()
            .fold((0.0f32, 0.0f32), |(r, t), h| {
                let (rr, tt) = h.latest();
                (r + rr, t + tt)
            });
        self.tray.set_throughput(rx_sum, tx_sum);
    }

    /// Fires a background ping for every active tunnel every 5 s so the
    /// sparkline collects RTT data continuously. Cooldown is keyed
    /// per-tunnel. Skipped when a ping is already in flight.
    fn maybe_schedule_rtt_probe(&mut self, ctx: &egui::Context) {
        let active_names: Vec<String> = self.mgr.active_names();
        for name in active_names {
            self.schedule_rtt_for_tunnel(ctx, &name);
        }
    }

    fn schedule_rtt_for_tunnel(&mut self, ctx: &egui::Context, name: &str) {
        let Some(cfg) = self.configs.iter().find(|c| c.name == name).cloned() else {
            return;
        };
        if self
            .ping_results
            .get(name)
            .map(|p| p.inflight)
            .unwrap_or(false)
        {
            return;
        }
        let endpoint = self
            .stats
            .get(name)
            .and_then(|s| s.peers.first().and_then(|p| p.endpoint.clone()))
            .or_else(|| {
                std::fs::read_to_string(&cfg.file_path)
                    .ok()
                    .and_then(|body| wg::conf::parse(&body).ok())
                    .and_then(|parsed| {
                        parsed.peers.first().and_then(|p| p.endpoint).map(|e| e.to_string())
                    })
            });
        let Some(endpoint) = endpoint else {
            return;
        };
        if let Some(last) = self.last_rtt_ping.get(name) {
            if last.elapsed() < Duration::from_secs(5) {
                return;
            }
        }

        let dns: Vec<String> = std::fs::read_to_string(&cfg.file_path)
            .ok()
            .and_then(|body| wg::conf::parse(&body).ok())
            .map(|parsed| parsed.interface.dns.iter().map(|ip| ip.to_string()).collect::<Vec<_>>())
            .unwrap_or_default();
        self.ping_results.entry(name.to_string()).or_default().inflight = true;
        self.last_rtt_ping.insert(name.to_string(), Instant::now());
        tasks::spawn_ping(self.task_tx.clone(), ctx.clone(), name.to_string(), endpoint, dns);
    }
}

/// Intermediate view of a tunnel during on-demand arbitration.
struct Candidate {
    cfg: Config,
    desired: Desired,
    is_active: bool,
    /// Normalised group name — trimmed, empty-stripped. `None` means this
    /// tunnel does not participate in any exclusive group.
    group: Option<String>,
}

/// Returns the set of candidate indices that are allowed to enter the
/// `Connect` state given their exclusive-group constraints. Within each
/// group, at most one winner is chosen: prefer the tunnel that is already
/// active, otherwise the first candidate in list order. Candidates whose
/// desired state is not `Connect` are always considered winners (the
/// constraint only matters for Connect arbitration).
fn select_group_winners(candidates: &[Candidate]) -> std::collections::HashSet<usize> {
    let mut winners: std::collections::HashSet<usize> =
        (0..candidates.len()).collect();

    // Bucket Connect candidates by group.
    let mut by_group: std::collections::HashMap<&str, Vec<usize>> =
        std::collections::HashMap::new();
    for (idx, cand) in candidates.iter().enumerate() {
        if !matches!(cand.desired, Desired::Connect) {
            continue;
        }
        let Some(group) = cand.group.as_deref() else {
            continue;
        };
        by_group.entry(group).or_default().push(idx);
    }

    for (_group, members) in by_group {
        if members.len() < 2 {
            continue;
        }
        // Prefer currently-active member; fall back to list order (already
        // the insertion order of `members`).
        let winner = members
            .iter()
            .copied()
            .find(|&i| candidates[i].is_active)
            .unwrap_or(members[0]);
        for idx in members {
            if idx != winner {
                winners.remove(&idx);
            }
        }
    }
    winners
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        match self.tray.poll(ctx, &self.mgr) {
            TrayAction::None => {}
            TrayAction::ShowManageTunnels => {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                self.window_visible = true;
                self.last_refresh = Instant::now() - Duration::from_secs(10);
            }
            TrayAction::EditRules(name) => {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                self.window_visible = true;
                self.selected = Some(name);
                self.active_tab = DetailTab::Rules;
                self.rules_state = None;
                self.last_refresh = Instant::now() - Duration::from_secs(10);
            }
            TrayAction::OpenAddConfig => {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                self.window_visible = true;
                self.start_add_flow();
            }
            TrayAction::OpenPreferences => {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                self.window_visible = true;
                self.prefs_flow = Some(PrefsFlow::open());
            }
            TrayAction::CheckUpdates => {
                self.trigger_manual_update_check(ctx);
            }
            TrayAction::UpdateGeoDb => {
                self.trigger_manual_geodb_update(ctx);
            }
            TrayAction::ShowAbout => {
                self.about_flow = Some(modals::AboutFlow::new());
                self.window_visible = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            }
            TrayAction::Quit => {
                self.quit_requested = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }

        if ctx.input(|i| i.viewport().close_requested()) {
            if self.quit_requested {
                // Tray Quit: let eframe tear down the viewport normally.
                return;
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.window_visible = false;
        }

        self.theme.update(ctx);
        self.maybe_check_for_updates(ctx);
        self.maybe_update_geodb(ctx);
        self.handle_dropped_files(ctx);
        self.drain_url_events(ctx);
        self.show_url_confirmation(ctx);
        self.drain_task_results();
        self.drain_ipc_events();
        self.drain_network_changes(ctx);
        self.check_watchdog(ctx);

        if self.window_visible && self.last_refresh.elapsed() > Duration::from_secs(1) {
            self.refresh(ctx);
            self.last_refresh = Instant::now();
            ctx.request_repaint_after(Duration::from_secs(1));
        }

        let panel_event = egui::SidePanel::left("tunnels")
            .resizable(true)
            .default_width(240.0)
            .min_width(180.0)
            .show(ctx, |ui| {
                tunnels_panel::show(
                    ui,
                    &self.configs,
                    &mut self.selected,
                    &self.mgr,
                    &self.stats,
                )
            })
            .inner;

        match panel_event {
            PanelEvent::None => {}
            PanelEvent::AddConfig => self.start_add_flow(),
            PanelEvent::AddConfigQrFile => self.start_add_flow_qr_file(),
            PanelEvent::AddConfigQrClipboard => self.start_add_flow_qr_clipboard(),
            PanelEvent::DeleteSelected => {
                if let Some(ref name) = self.selected {
                    self.delete_flow = Some(name.clone());
                }
            }
            PanelEvent::OpenPreferences => {
                self.prefs_flow = Some(PrefsFlow::open());
            }
        }

        let busy = self
            .selected
            .as_deref()
            .map(|n| self.in_progress.contains(n))
            .unwrap_or(false);

        let global_hooks_on = config::load_settings().hooks_enabled;

        let detail_event = egui::CentralPanel::default()
            .show(ctx, |ui| {
                detail_panel::show(
                    ui,
                    &self.configs,
                    &self.selected,
                    &mut self.active_tab,
                    &self.mgr,
                    &self.stats,
                    &self.transfer_history,
                    &self.ping_results,
                    &self.rtt_history,
                    busy,
                    &mut self.rules_state,
                    global_hooks_on,
                    &mut self.logs_state,
                    &self.log_tail,
                )
            })
            .inner;

        match detail_event {
            DetailEvent::None => {}
            DetailEvent::ToggleTunnel(name) => {
                if let Some(cfg) = self.configs.iter().find(|c| c.name == name).cloned() {
                    let is_active = self.mgr.is_active(&cfg.name)
        ;
                    self.in_progress.insert(name.clone());
                    // Manual toggle shields the tunnel from on-demand
                    // overrides until the user restarts or edits the rule.
                    self.manual_override.insert(name.clone());
                    tasks::spawn_toggle(
                        self.task_tx.clone(),
                        ctx.clone(),
                        self.mgr.clone(),
                        cfg,
                        is_active,
                    );
                }
            }
            DetailEvent::ApplyRules { name, rules } => {
                self.in_progress.insert(name.clone());
                // Editing on-demand settings clears the manual override so
                // the new rule can take effect immediately.
                self.manual_override.remove(&name);
                // Clear the draft so the next frame reloads from disk.
                self.rules_state = None;
                tasks::spawn_rules_apply(
                    self.task_tx.clone(),
                    ctx.clone(),
                    self.mgr.clone(),
                    name,
                    rules,
                );
            }
            DetailEvent::PingPeer { name, endpoint } => {
                let entry = self.ping_results.entry(name.clone()).or_default();
                entry.inflight = true;
                let dns: Vec<String> = std::fs::read_to_string(config::conf_path(&name))
                    .ok()
                    .and_then(|body| wg::conf::parse(&body).ok())
                    .map(|parsed| parsed.interface.dns.iter().map(|ip| ip.to_string()).collect::<Vec<_>>())
                    .unwrap_or_default();
                tasks::spawn_ping(
                    self.task_tx.clone(),
                    ctx.clone(),
                    name,
                    endpoint,
                    dns,
                );
            }
            DetailEvent::EditConfig(name) => {
                self.config_editor_flow =
                    Some(ConfigEditorFlow::open(&name));
            }
            DetailEvent::Rename(name) => {
                self.rename_flow = Some(RenameFlow {
                    old_name: name.clone(),
                    new_name: name,
                });
            }
        }

        self.render_modals(ctx);

        // Re-apply the viewport title each frame so a language change picks
        // up the new string without closing the window.
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(
            i18n::t("gui.window.title"),
        ));
    }
}

impl App {
    /// Intercepts files dropped onto the main viewport. The first `.conf`
    /// in the batch opens the existing AddFlow modal; any additional files
    /// produce a single "extra files ignored" notification. Non-`.conf`
    /// drops are silently logged — the viewport is a valid drop target
    /// whenever it's visible, so we cannot refuse the drop itself.
    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if dropped.is_empty() {
            return;
        }

        let mut confs: Vec<std::path::PathBuf> = dropped
            .iter()
            .filter_map(|f| f.path.clone())
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .map(|s| s.eq_ignore_ascii_case("conf"))
                    .unwrap_or(false)
            })
            .collect();

        if confs.is_empty() {
            log::info!(
                "splitwg: drop: ignored {} non-.conf file(s)",
                dropped.len()
            );
            notify::info(
                &i18n::t("notify.splitwg"),
                &i18n::t("notify.drop.not_a_conf"),
            );
            return;
        }

        let first = confs.remove(0);
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        self.window_visible = true;
        self.last_refresh = Instant::now() - Duration::from_secs(10);
        self.add_flow = Some(AddFlow::open(first));

        if !confs.is_empty() {
            notify::info(
                &i18n::t("notify.splitwg"),
                &i18n::t_with(
                    "notify.drop.multiple_ignored",
                    &[("count", &confs.len().to_string())],
                ),
            );
        }
    }

    fn start_add_flow(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title(i18n::t("gui.add.picker_title"))
            .add_filter("WireGuard conf", &["conf"])
            .pick_file()
        else {
            return;
        };
        self.add_flow = Some(AddFlow::open(path));
    }

    fn start_add_flow_qr_file(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title(i18n::t("gui.add.qr.picker_title"))
            .add_filter("Image", &["png", "jpg", "jpeg", "tiff", "bmp"])
            .pick_file()
        else {
            return;
        };
        match super::qr::decode_from_path(&path) {
            Ok(payload) => self.open_add_flow_from_qr_text(&payload),
            Err(e) => self.qr_error(e),
        }
    }

    fn start_add_flow_qr_clipboard(&mut self) {
        match super::qr::decode_from_clipboard() {
            Ok(payload) => self.open_add_flow_from_qr_text(&payload),
            Err(e) => self.qr_error(e),
        }
    }

    fn open_add_flow_from_qr_text(&mut self, payload: &str) {
        // Drop the decoded `.conf` to a temp file so `AddFlow::open` (which
        // wants a `PathBuf` for the preview) can reuse the existing import
        // modal without special-casing QR sources.
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("splitwg-qr-{pid}-{nanos}.conf"));
        if let Err(e) = std::fs::write(&tmp, payload.as_bytes()) {
            notify::error(
                &i18n::t("notify.splitwg"),
                &format!("{}: {}", i18n::t("gui.add.qr.decode_failed"), e),
            );
            return;
        }
        self.add_flow = Some(AddFlow::open(tmp));
    }

    fn qr_error(&self, err: super::qr::QrError) {
        use super::qr::QrError;
        let key = match err {
            QrError::ClipboardEmpty => "gui.add.qr.clipboard_no_image",
            QrError::NotAConfig => "gui.add.qr.not_a_config",
            _ => "gui.add.qr.decode_failed",
        };
        notify::error(&i18n::t("notify.splitwg"), &i18n::t(key));
    }

    fn render_modals(&mut self, ctx: &egui::Context) {
        // Preferences
        if let Some(flow) = self.prefs_flow.as_mut() {
            match modals::show_prefs(ctx, flow) {
                PrefsEvent::None => {}
                PrefsEvent::Cancel => {
                    self.prefs_flow = None;
                }
                PrefsEvent::TriggerExport => {
                    self.export_flow = Some(ExportFlow::open(&self.configs));
                    self.prefs_flow = None;
                }
                PrefsEvent::TriggerImport => {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title(i18n::t("gui.import.picker_title"))
                        .add_filter("SplitWG Package", &["splitwgpkg", "zip"])
                        .pick_file()
                    {
                        self.import_flow = Some(ImportFlow::open(path));
                    }
                    self.prefs_flow = None;
                }
                PrefsEvent::TriggerUpdateCheck => {
                    self.trigger_manual_update_check(ctx);
                }
                PrefsEvent::TriggerGeoDbUpdate => {
                    self.trigger_manual_geodb_update(ctx);
                }
                PrefsEvent::Apply => {
                    let draft = flow.draft.clone();
                    let original = flow.original.clone();
                    let login_draft = flow.launch_at_login_draft;
                    let login_original = flow.launch_at_login_original;
                    if login_draft != login_original {
                        let outcome = if login_draft {
                            super::login_item::register()
                        } else {
                            super::login_item::unregister()
                        };
                        if let Err(e) = outcome {
                            notify::error(
                                &i18n::t("notify.splitwg"),
                                &format!(
                                    "{}: {}",
                                    i18n::t("notify.login_item_failed"),
                                    e
                                ),
                            );
                        }
                    }
                    match config::save_settings(&draft) {
                        Ok(()) => {
                            if draft.language != original.language {
                                if let Some(lang) = draft
                                    .language
                                    .as_deref()
                                    .and_then(i18n::Lang::from_code)
                                {
                                    i18n::set_current(lang);
                                    self.tray.force_refresh();
                                }
                            }
                            notify::info(
                                &i18n::t("notify.splitwg"),
                                &i18n::t("gui.prefs.saved_toast"),
                            );
                        }
                        Err(e) => {
                            notify::error(
                                &i18n::t("notify.preferences_title"),
                                &i18n::t_with(
                                    "notify.preferences_save_failed",
                                    &[("error", &e.to_string())],
                                ),
                            );
                        }
                    }
                    self.prefs_flow = None;
                }
            }
        }

        // Add Config
        if let Some(flow) = self.add_flow.as_mut() {
            match modals::show_add(ctx, flow) {
                AddEvent::None => {}
                AddEvent::Cancel => {
                    self.add_flow = None;
                }
                AddEvent::Save => {
                    let stem = flow.stem.trim().to_string();
                    match config::copy_config_file(&flow.src, &stem) {
                        Ok(()) => {
                            self.selected = Some(stem.clone());
                            self.last_refresh =
                                Instant::now() - Duration::from_secs(10);
                            notify::info(&i18n::t("notify.splitwg"), &stem);
                        }
                        Err(e) => {
                            notify::error(
                                &i18n::t("notify.load_failed"),
                                &format!("{}: {}", stem, e),
                            );
                        }
                    }
                    self.add_flow = None;
                }
            }
        }

        // Delete
        if let Some(name) = self.delete_flow.clone() {
            match modals::show_delete(ctx, &name) {
                DeleteEvent::None => {}
                DeleteEvent::Cancel => {
                    self.delete_flow = None;
                }
                DeleteEvent::Confirm => {
                    // Disconnect first if the tunnel is active — the helper
                    // unlinks the kernel device; we just unlink the files.
                    if self.mgr.is_active(&name) {
                        let _ = self.mgr.disconnect(&name);
                    }
                    match config::delete_config(&name) {
                        Ok(()) => {
                            if self.selected.as_deref() == Some(name.as_str()) {
                                self.selected = None;
                            }
                            self.last_refresh =
                                Instant::now() - Duration::from_secs(10);
                            notify::info(&i18n::t("notify.splitwg"), &name);
                        }
                        Err(e) => {
                            notify::error(
                                &i18n::t("notify.load_failed"),
                                &format!("{}: {}", name, e),
                            );
                        }
                    }
                    self.delete_flow = None;
                }
            }
        }

        // Export package
        if let Some(flow) = self.export_flow.as_mut() {
            match modals::show_export(ctx, flow) {
                ExportEvent::None => {}
                ExportEvent::Cancel => {
                    self.export_flow = None;
                }
                ExportEvent::Save => {
                    let Some(dest) = rfd::FileDialog::new()
                        .set_title(i18n::t("gui.export.picker_title"))
                        .add_filter("SplitWG Package", &["splitwgpkg"])
                        .set_file_name("tunnels.splitwgpkg")
                        .save_file()
                    else {
                        // User cancelled the save dialog — keep the modal open.
                        return;
                    };
                    let names = flow.selected_names();
                    let password = flow.password.clone();
                    match package::export(&dest, &names, &password) {
                        Ok(()) => {
                            notify::info(
                                &i18n::t("notify.splitwg"),
                                &i18n::t_with(
                                    "notify.export.completed",
                                    &[("count", &names.len().to_string())],
                                ),
                            );
                            self.export_flow = None;
                        }
                        Err(e) => {
                            notify::error(
                                &i18n::t("notify.splitwg"),
                                &format!("{}: {}", i18n::t("notify.export.failed"), e),
                            );
                        }
                    }
                }
            }
        }

        // Import package
        if let Some(flow) = self.import_flow.as_mut() {
            match modals::show_import(ctx, flow) {
                ImportEvent::None => {}
                ImportEvent::Cancel => {
                    self.import_flow = None;
                }
                ImportEvent::Confirm => {
                    let password = flow.password.clone();
                    match package::import(&flow.src, &password) {
                        Ok(names) => {
                            notify::info(
                                &i18n::t("notify.splitwg"),
                                &i18n::t_with(
                                    "notify.import.completed",
                                    &[("count", &names.len().to_string())],
                                ),
                            );
                            self.last_refresh =
                                Instant::now() - Duration::from_secs(10);
                            self.import_flow = None;
                        }
                        Err(package::PackageError::WrongPassword) => {
                            flow.last_error =
                                Some(i18n::t("gui.import.wrong_password"));
                        }
                        Err(e) => {
                            flow.last_error = Some(format!(
                                "{}: {}",
                                i18n::t("gui.import.invalid_package"),
                                e
                            ));
                        }
                    }
                }
            }
        }

        modals::show_about(ctx, &mut self.about_flow);

        if let Some(flow) = self.config_editor_flow.as_mut() {
            match modals::show_config_editor(ctx, flow) {
                ConfigEditorEvent::Save => {
                    let path = config::conf_path(&flow.name);
                    if let Err(e) = std::fs::write(&path, &flow.draft) {
                        log::error!(
                            "splitwg: config editor: write failed: {e}"
                        );
                    } else {
                        self.configs =
                            config::load_configs().unwrap_or_default();
                    }
                    self.config_editor_flow = None;
                }
                ConfigEditorEvent::Cancel => {
                    self.config_editor_flow = None;
                }
                ConfigEditorEvent::None => {}
            }
        }

        if let Some(flow) = self.rename_flow.as_mut() {
            match modals::show_rename(ctx, flow) {
                RenameEvent::Confirm => {
                    let old = flow.old_name.clone();
                    let new_name = flow.new_name.trim().to_string();

                    if self.mgr.is_active(&old) {
                        let _ = self.mgr.disconnect(&old);
                    }

                    match config::rename_config(&old, &new_name) {
                        Ok(()) => {
                            self.rekey_tunnel_state(&old, &new_name);
                            self.configs =
                                config::load_configs().unwrap_or_default();
                        }
                        Err(e) => {
                            notify::error(
                                &i18n::t("notify.splitwg"),
                                &format!("{}: {}", old, e),
                            );
                        }
                    }
                    self.rename_flow = None;
                }
                RenameEvent::Cancel => {
                    self.rename_flow = None;
                }
                RenameEvent::None => {}
            }
        }

        self.render_update_modal(ctx);
    }

    /// Draws the update modal on top of everything else when a
    /// `pending_update` exists. Phase 3 handles Announced (Download button),
    /// Downloading (progress bar), Ready (skeleton), and Failed (dismiss).
    fn rekey_tunnel_state(&mut self, old: &str, new: &str) {
        if self.selected.as_deref() == Some(old) {
            self.selected = Some(new.to_string());
        }
        if let Some(v) = self.stats.remove(old) {
            self.stats.insert(new.to_string(), v);
        }
        if let Some(v) = self.peer_key_cache.remove(old) {
            self.peer_key_cache.insert(new.to_string(), v);
        }
        if let Some(v) = self.transfer_history.remove(old) {
            self.transfer_history.insert(new.to_string(), v);
        }
        if let Some(v) = self.ping_results.remove(old) {
            self.ping_results.insert(new.to_string(), v);
        }
        if let Some(v) = self.rtt_history.remove(old) {
            self.rtt_history.insert(new.to_string(), v);
        }
        if let Some(v) = self.last_rtt_ping.remove(old) {
            self.last_rtt_ping.insert(new.to_string(), v);
        }
        if let Some(v) = self.watchdog_state.remove(old) {
            self.watchdog_state.insert(new.to_string(), v);
        }
        if self.in_progress.remove(old) {
            self.in_progress.insert(new.to_string());
        }
        if self.manual_override.remove(old) {
            self.manual_override.insert(new.to_string());
        }
        if let Some(ref mut rs) = self.rules_state {
            if rs.name == old {
                rs.name = new.to_string();
            }
        }
    }

    fn render_update_modal(&mut self, ctx: &egui::Context) {
        let Some(state) = self.pending_update.clone() else {
            return;
        };
        if !self.window_visible {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            self.window_visible = true;
        }
        let mut open = true;
        let mut action = UpdateModalAction::None;

        egui::Window::new(i18n::t("gui.update.modal.title"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(480.0)
            .show(ctx, |ui| match &state {
                PendingUpdate::Announced { version, changelog, .. } => {
                    ui.label(i18n::t_with(
                        "gui.update.modal.available",
                        &[("version", version)],
                    ));
                    render_changelog(ui, changelog);
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(i18n::t("gui.update.modal.cancel_button")).clicked() {
                            action = UpdateModalAction::Dismiss;
                        }
                        if ui.button(i18n::t("gui.update.modal.download_button")).clicked() {
                            action = UpdateModalAction::Download;
                        }
                    });
                }
                PendingUpdate::Downloading { downloaded, total, .. } => {
                    let pct = if *total > 0 {
                        ((*downloaded as f64 / *total as f64) * 100.0).clamp(0.0, 100.0)
                    } else {
                        0.0
                    };
                    ui.label(i18n::t_with(
                        "gui.update.modal.downloading",
                        &[("pct", &format!("{:.0}", pct))],
                    ));
                    let progress = if *total > 0 {
                        (*downloaded as f32 / *total as f32).clamp(0.0, 1.0)
                    } else {
                        0.0
                    };
                    ui.add(egui::ProgressBar::new(progress).show_percentage());
                }
                PendingUpdate::Ready { version, changelog, app_path, .. } => {
                    ui.label(
                        egui::RichText::new(i18n::t_with(
                            "gui.update.modal.ready_headline",
                            &[("version", version)],
                        ))
                        .strong(),
                    );
                    render_changelog(ui, changelog);
                    ui.separator();
                    ui.label(i18n::t("gui.update.modal.quit_notice"));
                    let install_target = super::update::current_install_path()
                        .unwrap_or_else(|_| app_path.clone());
                    if matches!(
                        super::update::detect_install_mode(&install_target),
                        super::update::InstallMode::AdminReplace
                    ) {
                        ui.label(
                            egui::RichText::new(i18n::t("gui.update.modal.admin_notice"))
                                .italics()
                                .small(),
                        );
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(i18n::t("gui.update.modal.later_button")).clicked() {
                            action = UpdateModalAction::Dismiss;
                        }
                        if ui.button(i18n::t("gui.update.modal.install_button")).clicked() {
                            action = UpdateModalAction::Install;
                        }
                    });
                }
                PendingUpdate::Failed { reason, .. } => {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 120, 120),
                        i18n::t_with(
                            "gui.update.modal.verification_failed",
                            &[("reason", reason)],
                        ),
                    );
                    ui.separator();
                    if ui.button(i18n::t("gui.update.modal.cancel_button")).clicked() {
                        action = UpdateModalAction::Dismiss;
                    }
                }
            });

        if !open {
            action = UpdateModalAction::Dismiss;
        }

        match action {
            UpdateModalAction::None => {}
            UpdateModalAction::Dismiss => {
                self.pending_update = None;
            }
            UpdateModalAction::Install => {
                if let PendingUpdate::Ready {
                    version,
                    app_path,
                    mount_point,
                    ..
                } = state
                {
                    tasks::spawn_update_install(
                        self.task_tx.clone(),
                        ctx.clone(),
                        version,
                        app_path,
                        mount_point,
                    );
                }
            }
            UpdateModalAction::Download => {
                if let PendingUpdate::Announced {
                    version,
                    changelog,
                    dmg_url,
                    minisig_url,
                    digest,
                } = state
                {
                    let Ok(parsed) = semver::Version::parse(&version) else {
                        self.pending_update = Some(PendingUpdate::Failed {
                            version: version.clone(),
                            reason: "invalid version".into(),
                        });
                        return;
                    };
                    self.pending_update = Some(PendingUpdate::Downloading {
                        version: version.clone(),
                        changelog,
                        downloaded: 0,
                        total: 0,
                    });
                    tasks::spawn_update_download(
                        self.task_tx.clone(),
                        ctx.clone(),
                        dmg_url,
                        minisig_url,
                        digest,
                        parsed,
                    );
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateModalAction {
    None,
    Dismiss,
    Download,
    Install,
}

/// Human-readable byte size for the "GeoIP updated (N files, SIZE)"
/// toast. Bytes always surface as a single-line scalar — we never
/// show bits-per-second here (that's the tray tooltip's job).
fn humanize_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB"];
    let mut v = bytes as f64;
    let mut idx = 0;
    while v >= 1024.0 && idx + 1 < UNITS.len() {
        v /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{} {}", bytes, UNITS[idx])
    } else {
        format!("{:.1} {}", v, UNITS[idx])
    }
}

/// Renders the release changelog in a scrollable block. Kept small and
/// monospace — GitHub release bodies are short markdown we just want to
/// surface verbatim.
fn render_changelog(ui: &mut egui::Ui, changelog: &str) {
    if changelog.is_empty() {
        return;
    }
    ui.separator();
    ui.label(
        egui::RichText::new(i18n::t("gui.update.modal.changelog_header")).strong(),
    );
    egui::ScrollArea::vertical()
        .max_height(160.0)
        .show(ui, |ui| {
            ui.monospace(changelog);
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mk(name: &str, desired: Desired, is_active: bool, group: Option<&str>) -> Candidate {
        Candidate {
            cfg: Config {
                name: name.into(),
                file_path: PathBuf::from(format!("/tmp/{name}.conf")),
                rules: config::Rules::default(),
            },
            desired,
            is_active,
            group: group.map(|g| g.to_string()),
        }
    }

    #[test]
    fn no_group_all_winners() {
        let cs = vec![
            mk("a", Desired::Connect, false, None),
            mk("b", Desired::Disconnect, true, None),
        ];
        let w = select_group_winners(&cs);
        assert!(w.contains(&0));
        assert!(w.contains(&1));
    }

    #[test]
    fn group_prefers_active_member() {
        let cs = vec![
            mk("a", Desired::Connect, false, Some("work")),
            mk("b", Desired::Connect, true, Some("work")),
        ];
        let w = select_group_winners(&cs);
        assert!(!w.contains(&0));
        assert!(w.contains(&1));
    }

    #[test]
    fn group_falls_back_to_list_order_when_none_active() {
        let cs = vec![
            mk("a", Desired::Connect, false, Some("work")),
            mk("b", Desired::Connect, false, Some("work")),
        ];
        let w = select_group_winners(&cs);
        assert!(w.contains(&0));
        assert!(!w.contains(&1));
    }

    #[test]
    fn non_connect_desires_never_excluded_by_group() {
        // Even though `a` is grouped with `b`, `a` wants Disconnect — it's
        // never a contender for "the single active", so group arbitration
        // is a no-op for it.
        let cs = vec![
            mk("a", Desired::Disconnect, false, Some("work")),
            mk("b", Desired::Connect, false, Some("work")),
        ];
        let w = select_group_winners(&cs);
        assert!(w.contains(&0));
        assert!(w.contains(&1));
    }

    #[test]
    fn different_groups_do_not_interfere() {
        let cs = vec![
            mk("a", Desired::Connect, false, Some("work")),
            mk("b", Desired::Connect, false, Some("personal")),
        ];
        let w = select_group_winners(&cs);
        assert!(w.contains(&0));
        assert!(w.contains(&1));
    }
}
