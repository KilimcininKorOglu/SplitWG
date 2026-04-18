//! Background task runner — connect/disconnect on worker threads with
//! results fed back to the egui update loop via an `mpsc` channel.
//!
//! Why threads and not `tokio::spawn`? The `wg::Manager::connect` /
//! `disconnect` APIs are synchronous (they spawn `splitwg-helper` via
//! `sudo -n` and block on stdout/stdin). Running them on the UI thread
//! would freeze the window for 1–3 s per activation; running them on a
//! thread pool is overkill given SplitWG almost never has more than a
//! handful of in-flight ops.

use std::net::SocketAddr;
use std::process::Command;
use std::str::FromStr;
use std::sync::{mpsc, Arc};
use std::thread;

use crate::config::{self, Config, Rules};
use crate::i18n;
use crate::{auth, wg};

use super::update;

/// Result of a background connect/disconnect attempt, delivered to the
/// main thread so it can refresh state and render a toast/notification.
#[derive(Debug)]
pub enum TaskResult {
    Connected(String),
    Disconnected(String),
    AuthDenied(String),
    Error {
        name: String,
        message: String,
    },
    /// Rules saved + tunnel reconnected (Phase 4).
    RulesApplied(String),
    /// Result of a user-initiated peer ping. `result` is `Some(ms)` on a
    /// successful reply or `None` on timeout / unreachable.
    Pinged {
        name: String,
        result: Option<u32>,
    },
    /// The network monitor triggered an automatic connect/disconnect. UI
    /// surfaces a toast so the user understands why the state changed.
    OnDemandTriggered {
        name: String,
        connected: bool,
    },
    /// Auto-reconnect watchdog finished a cycle. `ok = true` when the
    /// tunnel is back up; `false` otherwise (App increments the failure
    /// counter and may cool down the watchdog for the tunnel).
    WatchdogReconnect {
        name: String,
        ok: bool,
    },
    /// Background update check found a newer release. The App surfaces a
    /// notification and seeds `pending_update` so the user can trigger a
    /// download.
    UpdateAvailable {
        version: String,
        changelog: String,
        dmg_url: String,
        minisig_url: String,
        digest: Option<String>,
    },
    /// Background update check completed and the current build is the
    /// newest available. Only surfaced when the user clicked "Check now"
    /// manually; the scheduled check stays silent.
    UpdateUpToDate {
        version: String,
        /// When `true` the App should emit a notification; background
        /// checks set this to `false` to stay quiet.
        user_initiated: bool,
    },
    /// Update check failed (network error, HTTP 404, JSON parse error).
    /// The App logs and only notifies on user-initiated checks.
    UpdateCheckFailed {
        message: String,
        user_initiated: bool,
    },
    /// Periodic download progress. `total = 0` when the server did not
    /// publish a Content-Length header.
    UpdateDownloadProgress {
        version: String,
        downloaded: u64,
        total: u64,
    },
    /// Downloaded + verified + extracted. The `.app` at `app_path` is
    /// ready to be swapped in by the install stage.
    UpdateReady {
        version: String,
        app_path: std::path::PathBuf,
        dmg_image_path: std::path::PathBuf,
        mount_point: std::path::PathBuf,
    },
    /// Any step of the download / verify / extract pipeline failed. The
    /// App surfaces this as a modal error with a retry affordance.
    UpdateVerificationFailed {
        version: String,
        reason: String,
    },
    /// Install step failed (bundle swap or relaunch refused). On success
    /// the process has already exited; only the failure path reaches the
    /// tx channel.
    UpdateInstallFailed {
        version: String,
        reason: String,
    },
    /// GeoLite2 MMDB pull completed and at least one edition was
    /// rewritten on disk.
    GeoDbUpdated {
        updated: Vec<String>,
        total_bytes: u64,
        user_initiated: bool,
    },
    /// GeoLite2 MMDB pull completed — no hashes changed.
    GeoDbUpToDate { user_initiated: bool },
    /// GeoLite2 MMDB pull failed (network, digest mismatch, missing
    /// entry). Surfaced as a toast only when the user initiated it.
    GeoDbUpdateFailed {
        message: String,
        user_initiated: bool,
    },
}

/// Channel the App creates once and hands out clones to workers.
pub type TaskTx = mpsc::Sender<TaskResult>;
pub type TaskRx = mpsc::Receiver<TaskResult>;

pub fn channel() -> (TaskTx, TaskRx) {
    mpsc::channel()
}

/// Spawns a Touch-ID gated connect. Disconnect short-circuits the prompt
/// because disabling the tunnel is considered non-destructive — the user
/// clicked the button deliberately.
pub fn spawn_toggle(
    tx: TaskTx,
    ctx: egui::Context,
    mgr: Arc<wg::Manager>,
    cfg: Config,
    currently_active: bool,
) {
    thread::spawn(move || {
        let name = cfg.name.clone();

        if currently_active {
            let result = match mgr.disconnect(&name) {
                Ok(()) => TaskResult::Disconnected(name),
                Err(e) => TaskResult::Error {
                    name,
                    message: e.to_string(),
                },
            };
            let _ = tx.send(result);
            ctx.request_repaint();
            return;
        }

        let prompt = i18n::t_with("auth.touchid_prompt", &[("name", &name)]);
        match auth::authenticate(&prompt) {
            auth::AuthResult::Success => {}
            auth::AuthResult::NotAvailable => {
                log::info!(
                    "gui: tasks: Touch ID not available for {:?}, proceeding",
                    name
                );
            }
            auth::AuthResult::Denied => {
                let _ = tx.send(TaskResult::AuthDenied(name));
                ctx.request_repaint();
                return;
            }
        }

        let result = match mgr.connect(&cfg) {
            Ok(()) => TaskResult::Connected(name),
            Err(e) => TaskResult::Error {
                name,
                message: e.to_string(),
            },
        };
        let _ = tx.send(result);
        ctx.request_repaint();
    });
}

/// Persists rules for `name`, then — if the tunnel is currently active —
/// disconnects and reconnects so the new rules take effect immediately.
pub fn spawn_rules_apply(
    tx: TaskTx,
    ctx: egui::Context,
    mgr: Arc<wg::Manager>,
    name: String,
    rules: Rules,
) {
    thread::spawn(move || {
        if let Err(e) = config::save_rules(&name, &rules) {
            let _ = tx.send(TaskResult::Error {
                name: name.clone(),
                message: i18n::t_with(
                    "notify.preferences_save_failed",
                    &[("error", &e.to_string())],
                ),
            });
            ctx.request_repaint();
            return;
        }

        // Reload the config so connect() picks up the freshly-saved rules.
        let cfg = match config::load_configs() {
            Ok(cs) => cs.into_iter().find(|c| c.name == name),
            Err(_) => None,
        };

        if let Some(cfg) = cfg {
            let is_active = mgr.is_active(&name)
                || wg::interface_for_config(&cfg.file_path).is_some();
            if is_active {
                if let Err(e) = mgr.disconnect(&name) {
                    let _ = tx.send(TaskResult::Error {
                        name: name.clone(),
                        message: e.to_string(),
                    });
                    ctx.request_repaint();
                    return;
                }
                if let Err(e) = mgr.connect(&cfg) {
                    let _ = tx.send(TaskResult::Error {
                        name: name.clone(),
                        message: e.to_string(),
                    });
                    ctx.request_repaint();
                    return;
                }
            }
        }

        let _ = tx.send(TaskResult::RulesApplied(name));
        ctx.request_repaint();
    });
}

/// Cycles a stale tunnel on a worker thread. Skips Touch ID — the watchdog
/// runs without user interaction, and declining the prompt silently would
/// be worse than just reconnecting. Disconnect errors are swallowed by
/// `Manager::reconnect` so only the connect half can report `ok = false`.
pub fn spawn_watchdog_reconnect(
    tx: TaskTx,
    ctx: egui::Context,
    mgr: Arc<wg::Manager>,
    name: String,
) {
    thread::spawn(move || {
        let ok = mgr.reconnect(&name).is_ok();
        let _ = tx.send(TaskResult::WatchdogReconnect { name, ok });
        ctx.request_repaint();
    });
}

/// Runs a GitHub Releases check on a worker thread and posts the result to
/// the App. `user_initiated` is plumbed back through so background checks
/// can stay silent on "up-to-date" and error paths.
pub fn spawn_update_check(tx: TaskTx, ctx: egui::Context, user_initiated: bool) {
    thread::spawn(move || {
        let result = match update::fetch_latest() {
            Ok(info) => {
                if update::is_newer(&info.version) {
                    match (info.dmg_asset, info.minisig_asset) {
                        (Some(dmg), Some(sig)) => TaskResult::UpdateAvailable {
                            version: info.version.to_string(),
                            changelog: info.body,
                            dmg_url: dmg.url,
                            minisig_url: sig.url,
                            digest: dmg.digest_sha256,
                        },
                        _ => TaskResult::UpdateCheckFailed {
                            message: "release missing DMG or minisig asset".into(),
                            user_initiated,
                        },
                    }
                } else {
                    TaskResult::UpdateUpToDate {
                        version: update::current_version().to_string(),
                        user_initiated,
                    }
                }
            }
            Err(e) => TaskResult::UpdateCheckFailed {
                message: e.to_string(),
                user_initiated,
            },
        };
        let _ = tx.send(result);
        ctx.request_repaint();
    });
}

/// Downloads + verifies a release asset on a worker thread. Streams
/// progress back via `UpdateDownloadProgress`; posts either `UpdateReady`
/// or `UpdateVerificationFailed` as the terminal variant.
pub fn spawn_update_download(
    tx: TaskTx,
    ctx: egui::Context,
    dmg_url: String,
    minisig_url: String,
    digest: Option<String>,
    version: semver::Version,
) {
    thread::spawn(move || {
        let progress_tx = tx.clone();
        let progress_ctx = ctx.clone();
        let version_str = version.to_string();
        let progress_version = version_str.clone();
        let result = update::download_and_verify(
            &dmg_url,
            &minisig_url,
            digest.as_deref(),
            version.clone(),
            move |dl, total| {
                let _ = progress_tx.send(TaskResult::UpdateDownloadProgress {
                    version: progress_version.clone(),
                    downloaded: dl,
                    total,
                });
                progress_ctx.request_repaint();
            },
        );
        let final_result = match result {
            Ok(ready) => TaskResult::UpdateReady {
                version: version_str,
                app_path: ready.app_path,
                dmg_image_path: ready.dmg_path,
                mount_point: ready.mount_point,
            },
            Err(e) => TaskResult::UpdateVerificationFailed {
                version: version_str,
                reason: e.to_string(),
            },
        };
        let _ = tx.send(final_result);
        ctx.request_repaint();
    });
}

/// Swaps the running `.app` for `new_app`, detaches the mount, relaunches
/// via `open -n`, and exits the current process. Never returns on success
/// — the process exits 0 before `tx::send` runs. Only the failure path
/// emits a `TaskResult`.
pub fn spawn_update_install(
    tx: TaskTx,
    ctx: egui::Context,
    version: String,
    new_app: std::path::PathBuf,
    mount_point: std::path::PathBuf,
) {
    thread::spawn(move || {
        let current_app = match update::current_install_path() {
            Ok(p) => p,
            Err(e) => {
                let _ = tx.send(TaskResult::UpdateInstallFailed {
                    version,
                    reason: e.to_string(),
                });
                ctx.request_repaint();
                return;
            }
        };
        match update::install_and_relaunch(&new_app, &current_app, &mount_point) {
            Ok(()) => {
                // Give the relaunched process ~250 ms to come up before
                // we quit so the tray doesn't disappear for a whole second.
                std::thread::sleep(std::time::Duration::from_millis(250));
                std::process::exit(0);
            }
            Err(e) => {
                let _ = tx.send(TaskResult::UpdateInstallFailed {
                    version,
                    reason: e.to_string(),
                });
                ctx.request_repaint();
            }
        }
    });
}

/// Pulls the GeoLite2 MMDB files off the `geodb` branch on a worker
/// thread. `user_initiated` is plumbed back so background pulls stay
/// quiet on the "up to date" and failure paths while the manual button
/// always surfaces a toast.
pub fn spawn_geodb_update(tx: TaskTx, ctx: egui::Context, user_initiated: bool) {
    thread::spawn(move || {
        let result = match super::geodb::pull_once() {
            Ok(outcome) if outcome.updated.is_empty() => {
                TaskResult::GeoDbUpToDate { user_initiated }
            }
            Ok(outcome) => TaskResult::GeoDbUpdated {
                updated: outcome.updated,
                total_bytes: outcome.total_bytes,
                user_initiated,
            },
            Err(e) => TaskResult::GeoDbUpdateFailed {
                message: e.to_string(),
                user_initiated,
            },
        };
        let _ = tx.send(result);
        ctx.request_repaint();
    });
}

/// Fires a single `/sbin/ping -c 1 -W 1000 <host>` in a worker thread and
/// posts the measured RTT (in milliseconds) back to the UI. On timeout or
/// unreachable host the result is `None`.
pub fn spawn_ping(tx: TaskTx, ctx: egui::Context, name: String, endpoint: String) {
    thread::spawn(move || {
        let host = parse_host(&endpoint);
        let output = Command::new("/sbin/ping")
            .args(["-c", "1", "-W", "1000", &host])
            .output();
        let result = output.ok().and_then(|o| {
            if !o.status.success() {
                return None;
            }
            let body = String::from_utf8_lossy(&o.stdout);
            parse_ping_ms(&body)
        });
        let _ = tx.send(TaskResult::Pinged { name, result });
        ctx.request_repaint();
    });
}

/// Extracts just the hostname/IP from a WG endpoint string. Accepts plain
/// IPv4 (`1.2.3.4:51820`), bracketed IPv6 (`[::1]:51820`), and bare hosts.
fn parse_host(endpoint: &str) -> String {
    if let Ok(sa) = SocketAddr::from_str(endpoint) {
        return sa.ip().to_string();
    }
    // Strip trailing `:<port>` if there is exactly one colon (IPv4 or host).
    if endpoint.matches(':').count() == 1 {
        if let Some((host, _)) = endpoint.rsplit_once(':') {
            return host.to_string();
        }
    }
    // Bracketed IPv6 without port, or raw host — leave as-is.
    endpoint.trim_matches(|c| c == '[' || c == ']').to_string()
}

/// Pulls the `time=xx.xxx ms` field out of `ping` stdout. Returns the value
/// rounded to the nearest millisecond. Returns `None` when not found.
fn parse_ping_ms(body: &str) -> Option<u32> {
    // Scan for the literal "time=" anchor; avoid pulling in regex for a
    // single tiny parse.
    for token in body.split_whitespace() {
        if let Some(rest) = token.strip_prefix("time=") {
            if let Ok(ms) = rest.parse::<f32>() {
                return Some(ms.round() as u32);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_strips_ipv4_port() {
        assert_eq!(parse_host("1.2.3.4:51820"), "1.2.3.4");
    }

    #[test]
    fn parse_host_strips_ipv6_port() {
        assert_eq!(parse_host("[2001:db8::1]:51820"), "2001:db8::1");
    }

    #[test]
    fn parse_host_passes_bare_host() {
        assert_eq!(parse_host("example.com"), "example.com");
    }

    #[test]
    fn parse_ping_extracts_time() {
        let sample = "PING 1.1.1.1 (1.1.1.1): 56 data bytes\n\
            64 bytes from 1.1.1.1: icmp_seq=0 ttl=56 time=12.345 ms\n";
        assert_eq!(parse_ping_ms(sample), Some(12));
    }

    #[test]
    fn parse_ping_returns_none_on_timeout() {
        let sample = "Request timeout for icmp_seq 0";
        assert_eq!(parse_ping_ms(sample), None);
    }
}

