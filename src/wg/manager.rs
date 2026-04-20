//! Tunnel lifecycle for SplitWG 2.0 — spawns a per-tunnel `splitwg-helper`
//! process via `sudo -n` and communicates over stdin/stdout JSON lines.
//!
//! The helper owns the utun device, UDP socket, and all root-only side
//! effects (routes, DNS). The tray simply orchestrates: parse the `.conf`,
//! resolve DNS, pick a gateway, spawn the helper, wait for `Ready`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{self, Rules};
use crate::ipc::{self, Command as IpcCmd, Event as IpcEvent, TunnelMode, UpParams};

use super::{conf, rules::get_default_gateway, rules::resolve_entries, WgError};

const READY_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Runtime state of a managed WireGuard tunnel.
pub struct TunnelState {
    pub config_path: PathBuf,
    pub rules: Rules,
    pub iface: String,
    child: Arc<Mutex<Child>>,
}

impl Clone for TunnelState {
    fn clone(&self) -> Self {
        Self {
            config_path: self.config_path.clone(),
            rules: self.rules.clone(),
            iface: self.iface.clone(),
            child: self.child.clone(),
        }
    }
}

pub struct Manager {
    active: RwLock<HashMap<String, TunnelState>>,
    event_tx: mpsc::Sender<(String, IpcEvent)>,
    event_rx: Mutex<mpsc::Receiver<(String, IpcEvent)>>,
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

impl Manager {
    pub fn new() -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        Manager {
            active: RwLock::new(HashMap::new()),
            event_tx,
            event_rx: Mutex::new(event_rx),
        }
    }

    /// Non-blocking drain of all pending IPC events from active helpers.
    pub fn drain_events(&self) -> Vec<(String, IpcEvent)> {
        let rx = match self.event_rx.lock() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        while let Ok(item) = rx.try_recv() {
            out.push(item);
        }
        out
    }

    /// Returns the utun interface name for a managed tunnel, if active.
    pub fn iface_for(&self, name: &str) -> Option<String> {
        self.active
            .read()
            .ok()
            .and_then(|m| m.get(name).map(|s| s.iface.clone()))
    }

    pub fn is_active(&self, name: &str) -> bool {
        self.active
            .read()
            .map(|m| m.contains_key(name))
            .unwrap_or(false)
    }

    /// Brings up a tunnel by spawning `splitwg-helper`.
    pub fn connect(&self, cfg: &config::Config) -> Result<(), WgError> {
        {
            let map = self
                .active
                .read()
                .map_err(|_| WgError::Msg("manager lock poisoned".into()))?;
            if map.contains_key(&cfg.name) {
                return Err(WgError::Msg(format!(
                    "tunnel {:?} is already active",
                    cfg.name
                )));
            }
        }

        let body = std::fs::read_to_string(&cfg.file_path).map_err(|e| {
            WgError::Msg(format!("read {}: {}", cfg.file_path.display(), e))
        })?;
        let parsed = conf::parse(&body).map_err(|e| WgError::Msg(format!("parse conf: {e}")))?;
        let peer = parsed
            .peers
            .first()
            .ok_or_else(|| WgError::Msg("no [Peer] section in config".into()))?;
        if parsed.peers.len() > 1 {
            log::warn!(
                "splitwg: manager: {} has {} peers, only first is used",
                cfg.name,
                parsed.peers.len()
            );
        }
        let endpoint = peer
            .endpoint
            .ok_or_else(|| WgError::Msg("peer missing Endpoint".into()))?;

        let mode = match cfg.rules.mode.as_str() {
            "include" => TunnelMode::Include,
            "exclude" => TunnelMode::Exclude,
            _ => TunnelMode::Full,
        };
        let (allowed_ips, exclude_entries) = match mode {
            TunnelMode::Include if !cfg.rules.entries.is_empty() => {
                (resolve_entries(&cfg.rules.entries), Vec::<String>::new())
            }
            TunnelMode::Exclude if !cfg.rules.entries.is_empty() => (
                peer.allowed_ips.iter().map(|n| n.to_string()).collect(),
                resolve_entries(&cfg.rules.entries),
            ),
            _ => (
                peer.allowed_ips.iter().map(|n| n.to_string()).collect(),
                Vec::new(),
            ),
        };

        let gateway: Option<IpAddr> = get_default_gateway()
            .ok()
            .and_then(|s| s.parse::<IpAddr>().ok());

        // Hooks are a two-gate opt-in:
        //   1. Global `Settings::hooks_enabled` — one flick to disarm everything.
        //   2. Per-tunnel `Rules::hooks_enabled` — each `.conf` opts in
        //      individually, even after the global switch is on.
        // Either gate closed => no hooks forwarded. Both must be true. The
        // per-tunnel default is `false`, so a user who enables the global
        // flag does NOT retroactively arm hooks for existing configs.
        let settings = config::load_settings();
        let hook_count = parsed.interface.pre_up.len()
            + parsed.interface.post_up.len()
            + parsed.interface.pre_down.len()
            + parsed.interface.post_down.len();
        let (pre_up, post_up, pre_down, post_down) = if settings.hooks_enabled
            && cfg.rules.hooks_enabled
        {
            log::info!(
                "splitwg: manager: hooks enabled for {:?} — forwarding {} PreUp / {} PostUp / {} PreDown / {} PostDown",
                cfg.name,
                parsed.interface.pre_up.len(),
                parsed.interface.post_up.len(),
                parsed.interface.pre_down.len(),
                parsed.interface.post_down.len(),
            );
            (
                parsed.interface.pre_up.clone(),
                parsed.interface.post_up.clone(),
                parsed.interface.pre_down.clone(),
                parsed.interface.post_down.clone(),
            )
        } else {
            if hook_count > 0 {
                let reason = match (settings.hooks_enabled, cfg.rules.hooks_enabled) {
                    (false, _) => "global hooks disabled",
                    (true, false) => "per-tunnel hooks disabled",
                    _ => unreachable!(),
                };
                log::info!(
                    "splitwg: manager: {reason} — skipping {hook_count} hook(s) in {:?}",
                    cfg.name
                );
            }
            (Vec::new(), Vec::new(), Vec::new(), Vec::new())
        };

        let params = UpParams {
            tunnel: cfg.name.clone(),
            interface_key: ipc::encode_key(&parsed.interface.private_key),
            peer_key: ipc::encode_key(&peer.public_key),
            psk: peer.preshared_key.as_ref().map(ipc::encode_key),
            endpoint,
            allowed_ips,
            addresses: parsed
                .interface
                .addresses
                .iter()
                .map(|n| n.to_string())
                .collect(),
            dns: parsed.interface.dns.clone(),
            mtu: parsed.interface.mtu.unwrap_or(1420),
            keepalive: peer.persistent_keepalive,
            mode,
            exclude_entries,
            gateway,
            pre_up,
            post_up,
            pre_down,
            post_down,
            kill_switch: config::load_settings().kill_switch,
        };

        let helper = helper_path()?;
        let helper_s = helper
            .to_str()
            .ok_or_else(|| WgError::Msg("helper path not UTF-8".into()))?;
        log::info!("splitwg: manager: spawning helper at {helper_s}");

        let mut child = Command::new("sudo")
            .args(["-n", "--", helper_s])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| WgError::Msg(format!("spawn helper: {e}")))?;
        log::info!("splitwg: manager: helper spawned (pid={})", child.id());

        let up_json = serde_json::to_string(&IpcCmd::Up(Box::new(params)))
            .map_err(|e| WgError::Msg(format!("serialize up: {e}")))?;
        log::info!("splitwg: manager: sending Up command ({} bytes)", up_json.len());
        if let Some(stdin) = child.stdin.as_mut() {
            writeln!(stdin, "{up_json}")
                .map_err(|e| WgError::Msg(format!("write helper stdin: {e}")))?;
            let _ = stdin.flush();
        } else {
            let _ = child.kill();
            return Err(WgError::Msg("helper stdin missing".into()));
        }

        log::info!("splitwg: manager: waiting for Ready event (timeout={}s)", READY_TIMEOUT.as_secs());
        let stderr_rx = spawn_stderr_logger(&mut child, cfg.name.clone());
        let iface = match read_ready(&mut child, READY_TIMEOUT, cfg.name.clone(), self.event_tx.clone()) {
            Ok(iface) => {
                log::info!("splitwg: manager: helper ready on {iface}");
                iface
            }
            Err(e) => {
                log::error!("splitwg: manager: helper bringup failed: {e}");
                let _ = child.kill();
                let _ = child.wait();
                drop(stderr_rx);
                return Err(WgError::Msg(format!("helper bringup: {e}")));
            }
        };

        let state = TunnelState {
            config_path: cfg.file_path.clone(),
            rules: cfg.rules.clone(),
            iface,
            child: Arc::new(Mutex::new(child)),
        };

        let mut map = self
            .active
            .write()
            .map_err(|_| WgError::Msg("manager lock poisoned".into()))?;
        map.insert(cfg.name.clone(), state);
        Ok(())
    }

    /// Asks the helper to shut down, then waits up to `SHUTDOWN_TIMEOUT` and
    /// kills if unresponsive.
    pub fn disconnect(&self, name: &str) -> Result<(), WgError> {
        log::info!("splitwg: manager: disconnecting {:?}", name);
        let state = {
            let mut map = self
                .active
                .write()
                .map_err(|_| WgError::Msg("manager lock poisoned".into()))?;
            map.remove(name)
                .ok_or_else(|| WgError::Msg(format!("{name} is not tracked")))?
        };

        let mut child = state
            .child
            .lock()
            .map_err(|_| WgError::Msg("child mutex poisoned".into()))?;

        if let Some(stdin) = child.stdin.as_mut() {
            log::info!("splitwg: manager: sending Shutdown command to {:?}", name);
            let _ = writeln!(stdin, "{}", serde_json::to_string(&IpcCmd::Shutdown).unwrap());
            let _ = stdin.flush();
        }

        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    log::info!("splitwg: manager: helper {:?} exited cleanly ({})", name, status);
                    return Ok(());
                }
                Ok(None) => {}
                Err(e) => {
                    log::warn!("splitwg: manager: try_wait({name}): {e}");
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                log::warn!("splitwg: manager: helper {name} unresponsive after {}s, killing", SHUTDOWN_TIMEOUT.as_secs());
                let _ = child.kill();
                let _ = child.wait();
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    /// Cycles a tunnel — disconnect (idempotent, "not tracked" is ignored)
    /// then load the current config from disk and connect. Used by the
    /// auto-reconnect watchdog when a handshake has gone stale. The lookup
    /// re-reads the config directory so a rename or edit between the
    /// original connect and the watchdog trigger does not revive a stale
    /// copy.
    pub fn reconnect(&self, name: &str) -> Result<(), WgError> {
        log::info!("splitwg: manager: reconnecting {:?}", name);
        let _ = self.disconnect(name);
        log::info!("splitwg: manager: reloading config for {:?} from disk", name);
        let cfgs = config::load_configs()
            .map_err(|e| WgError::Msg(format!("load configs: {e}")))?;
        let cfg = cfgs
            .into_iter()
            .find(|c| c.name == name)
            .ok_or_else(|| WgError::Msg(format!("config {name} no longer exists")))?;
        self.connect(&cfg)
    }

    pub fn disconnect_all(&self) {
        let names: Vec<String> = self
            .active
            .read()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        for name in names {
            if let Err(e) = self.disconnect(&name) {
                log::warn!("splitwg: manager: disconnect {name} on exit: {e}");
            }
        }
    }

    pub fn active_names(&self) -> Vec<String> {
        self.active
            .read()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// utun names of tunnels this Manager owns. Replaces the old
    /// `wg show interfaces` shell-out.
    pub fn iface_names(&self) -> Vec<String> {
        self.active
            .read()
            .map(|m| m.values().map(|s| s.iface.clone()).collect())
            .unwrap_or_default()
    }
}

fn spawn_stderr_logger(child: &mut Child, tunnel: String) -> Option<thread::JoinHandle<()>> {
    let stderr = child.stderr.take()?;
    Some(thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            log::info!("splitwg: helper[{tunnel}]: {line}");
        }
    }))
}

/// Blocks until the helper emits a `Ready` or `Error` event, or the timeout
/// expires. After `Ready` arrives, a background thread continues draining
/// stdout and forwards parsed events to `event_fwd` so the GUI can consume
/// Stats / Handshake updates.
fn read_ready(
    child: &mut Child,
    timeout: Duration,
    tunnel_name: String,
    event_fwd: mpsc::Sender<(String, IpcEvent)>,
) -> Result<String, String> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "helper stdout missing".to_string())?;
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + timeout;
    let iface = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("ready event timed out".into());
        }
        match rx.recv_timeout(remaining.min(Duration::from_millis(500))) {
            Ok(line) => {
                match serde_json::from_str::<IpcEvent>(&line) {
                    Ok(IpcEvent::Ready { iface }) => break iface,
                    Ok(IpcEvent::Error { message }) => return Err(message),
                    Ok(_) => continue,
                    Err(e) => return Err(format!("malformed event `{line}`: {e}")),
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("helper stdout closed before Ready".into())
            }
        }
    };

    // Keep draining — forward parsed Stats/Handshake events to the GUI.
    thread::spawn(move || {
        for line in rx {
            match serde_json::from_str::<IpcEvent>(&line) {
                Ok(ev @ (IpcEvent::Stats { .. } | IpcEvent::Handshake { .. })) => {
                    if event_fwd.send((tunnel_name.clone(), ev)).is_err() {
                        break;
                    }
                }
                Ok(IpcEvent::Error { message }) => {
                    log::warn!("splitwg: helper[{tunnel_name}]: error event: {message}");
                }
                Ok(_) => {}
                Err(e) => {
                    log::debug!("splitwg: helper[{tunnel_name}]: unparseable line: {e}");
                }
            }
        }
    });

    Ok(iface)
}

/// Locates the `splitwg-helper` binary.
///
/// Preference:
/// 1. `SPLITWG_HELPER` env var (tests / developers override).
/// 2. Sibling of the current executable (bundle layout).
/// 3. Cargo's `target/{debug,release}/splitwg-helper` (dev fallback).
pub fn helper_path() -> Result<PathBuf, WgError> {
    if let Ok(env) = std::env::var("SPLITWG_HELPER") {
        let p = PathBuf::from(env);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("splitwg-helper");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    // Dev fallback: next to the main binary in target/.
    if let Some(manifest) = option_env!("CARGO_MANIFEST_DIR") {
        for profile in ["release", "debug"] {
            let p = Path::new(manifest)
                .join("target")
                .join(profile)
                .join("splitwg-helper");
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    Err(WgError::Msg(
        "splitwg-helper binary not found (set SPLITWG_HELPER or install alongside splitwg)".into(),
    ))
}

/// Legacy helper retained for tests. Delegates to the new `conf` parser so
/// behaviour is identical (first `[Peer]` wins, returns base64 PublicKey).
pub fn extract_peer_public_key(cfg_path: &std::path::Path) -> Option<String> {
    let data = std::fs::read_to_string(cfg_path).ok()?;
    conf::first_peer_public_key_base64(&data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const IFACE_KEY: &str = "QNpAjV5E06MPqKfN0u3VHYnM3LqHG/U0xk4BCQKYJHg=";
    const PEER_KEY: &str = "RmVhbjA3ykCFtABhxzrL7B5dMRv61i3+4RmmQhR0USM=";

    fn write_tmp(content: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "splitwg-mgr-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wg.conf");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn extract_peer_public_key_matches_legacy_behaviour() {
        let cfg = format!(
            "[Interface]\nPrivateKey = {IFACE_KEY}\n\n[Peer]\nPublicKey = {PEER_KEY}\nEndpoint = 1.2.3.4:51820\n"
        );
        let path = write_tmp(&cfg);
        assert_eq!(extract_peer_public_key(&path), Some(PEER_KEY.to_string()));
    }

    #[test]
    fn extract_peer_public_key_none_when_missing() {
        let cfg = format!(
            "[Interface]\nPrivateKey = {IFACE_KEY}\n\n[Peer]\nEndpoint = 1.2.3.4:51820\n"
        );
        let path = write_tmp(&cfg);
        // Missing PublicKey → parse fails → None
        assert_eq!(extract_peer_public_key(&path), None);
    }

    #[test]
    fn manager_is_active_false_by_default() {
        let m = Manager::new();
        assert!(!m.is_active("nothing"));
    }

    #[test]
    fn helper_path_reads_env_override() {
        let path = std::env::temp_dir().join("splitwg-helper-test-shim");
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        std::env::set_var("SPLITWG_HELPER", &path);
        let found = helper_path().unwrap();
        std::env::remove_var("SPLITWG_HELPER");
        let _ = std::fs::remove_file(&path);
        assert_eq!(found, path);
    }
}
