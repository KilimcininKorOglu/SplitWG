//! `.conf` and `<name>.rules.json` persistence layer.

use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Routing rules for a WireGuard tunnel — persisted as `<name>.rules.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rules {
    /// `"exclude"` or `"include"`. Unknown values are treated as `"exclude"`
    /// by the wg layer.
    pub mode: String,
    /// IPs, CIDRs, bare domains, or wildcard domains (`*.example.com`).
    pub entries: Vec<String>,
    /// Per-tunnel opt-in for wg-quick hook execution. Gated by the global
    /// `Settings::hooks_enabled` as well: if either is `false`, no hooks
    /// run for this tunnel. Default `false` so an existing
    /// `<name>.rules.json` without this key never accidentally gains hook
    /// execution when the user flips the global flag on.
    #[serde(default)]
    pub hooks_enabled: bool,
    /// When set, background `network_monitor` will auto-connect /
    /// disconnect the tunnel based on the user's current Wi-Fi SSID or
    /// wired state. Absent (`None`) means the tunnel is never auto-managed,
    /// which preserves the legacy semantics of pre-Phase-6 rule files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_demand: Option<OnDemandRule>,
}

/// Auto-connect rules for a single tunnel. Evaluated by
/// `wg::on_demand::decide` against the current `NetState`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnDemandRule {
    /// When `true`, the tunnel is kept connected regardless of network
    /// state (takes precedence over any other criterion).
    #[serde(default)]
    pub always: bool,
    /// Connect whenever the default route is a wired interface.
    #[serde(default)]
    pub activate_on_ethernet: bool,
    /// Connect whenever a Wi-Fi SSID is active (any network, trusted or not).
    #[serde(default)]
    pub activate_on_wifi: bool,
    /// SSID allowlist. Matching the current SSID forces Connect even when
    /// `activate_on_wifi` is off. Overrides `untrusted_ssids`.
    #[serde(default)]
    pub trusted_ssids: Vec<String>,
    /// SSID denylist. Matching forces Disconnect regardless of other flags.
    #[serde(default)]
    pub untrusted_ssids: Vec<String>,
    /// Optional time-of-day gate. Evaluated before every other criterion:
    /// when the current local time is outside the schedule window, the
    /// evaluator returns `Disconnect`. `None` disables the gate entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<ScheduleRule>,
    /// Optional coordination group. When two or more tunnels share the same
    /// non-empty group name, at most one of them may be active at a time;
    /// the tray's on-demand evaluator arbitrates by preferring the currently
    /// active tunnel, falling back to config-list order. `None` or empty
    /// string disables the constraint for this tunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusive_group: Option<String>,
}

/// Schedule gate for on-demand — active weekday mask + hour window.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScheduleRule {
    /// Bit 0 = Monday … bit 6 = Sunday. `0x7F` = every day. A mask of `0`
    /// means the rule never matches; the evaluator returns `Disconnect`
    /// when a non-`None` schedule has no active days.
    #[serde(default)]
    pub weekdays_mask: u8,
    /// Inclusive start hour (`0..=23`). When `hour_start == hour_end` the
    /// window covers the whole day. When `hour_start > hour_end` the window
    /// wraps midnight (e.g. `22..6`).
    #[serde(default)]
    pub hour_start: u8,
    /// Exclusive end hour (`0..=23`).
    #[serde(default)]
    pub hour_end: u8,
}

impl Default for Rules {
    fn default() -> Self {
        Rules {
            mode: "exclude".to_string(),
            entries: Vec::new(),
            hooks_enabled: false,
            on_demand: None,
        }
    }
}

/// A WireGuard config plus its associated routing rules.
#[derive(Debug, Clone)]
pub struct Config {
    pub name: String,
    pub file_path: PathBuf,
    pub rules: Rules,
}

/// Global application settings — persisted as `settings.json` in the config
/// directory. Kept intentionally small; new flags added here must default to
/// the safer value so an absent or malformed file yields `Settings::default()`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    /// When `true`, the manager forwards PreUp/PostUp/PreDown/PostDown commands
    /// from `.conf` files to the root helper for execution. Default `false`
    /// because hooks run as root and anyone with write access to a `.conf`
    /// could otherwise achieve RCE.
    #[serde(default)]
    pub hooks_enabled: bool,
    /// BCP-47-ish short code for the UI language (`"en"`, `"tr"`). `None`
    /// means "not yet chosen" — the app will detect the system locale on each
    /// boot until the user picks one from the tray, at which point the choice
    /// is persisted here.
    #[serde(default)]
    pub language: Option<String>,
    /// When `true`, `splitwg-helper` installs a pf anchor that blocks all
    /// non-tunnel IPv4/IPv6 egress while a tunnel is up. Default `false`
    /// because an accidental kill-switch combined with a crashed helper
    /// would leave the machine offline until the user runs
    /// `sudo pfctl -a splitwg -F all` from Terminal.
    #[serde(default)]
    pub kill_switch: bool,
    /// Opt-in daily check against GitHub Releases. Default `false` so we
    /// never make outbound HTTP requests without explicit user consent.
    #[serde(default)]
    pub update_check_enabled: bool,
    /// UNIX epoch seconds of the most recent update check (success or
    /// failure). Persisted so the 7-day cooldown survives restarts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_update_check: Option<u64>,
    /// Opt-in daily pull of GeoLite2 MMDB files from the `geodb` branch.
    /// Default `false` so SplitWG never makes outbound HTTP without the
    /// user's explicit consent.
    #[serde(default)]
    pub geodb_auto_update_enabled: bool,
    /// UNIX epoch seconds of the most recent GeoDB pull (success or
    /// failure). Enforces the 24-hour cooldown between background pulls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_geodb_update: Option<u64>,
}

/// Errors the config layer may return.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("save rules {name}: {source}")]
    SaveRules { name: String, source: io::Error },
}

/// Returns the path to the splitwg configuration directory.
///
/// Honours `$HOME`; falls back to a relative `.config/splitwg` when
/// `$HOME` is unset.
pub fn config_dir() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(h) if !h.is_empty() => PathBuf::from(h).join(".config").join("splitwg"),
        _ => PathBuf::from(".config").join("splitwg"),
    }
}

pub fn conf_path(name: &str) -> PathBuf {
    config_dir().join(format!("{name}.conf"))
}

pub fn rules_path(name: &str) -> PathBuf {
    config_dir().join(format!("{name}.rules.json"))
}

/// Creates the config directory if it does not exist (mode 0755).
pub fn ensure_config_dir() -> io::Result<()> {
    let dir = config_dir();
    if !dir.exists() {
        log::info!(
            "splitwg: config: creating config directory {}",
            dir.display()
        );
    }
    fs::create_dir_all(&dir)?;
    // create_dir_all respects existing permissions; set them explicitly on
    // create only so `0o755` applies without clobbering user-tightened perms.
    #[cfg(unix)]
    if let Ok(md) = fs::metadata(&dir) {
        let current = md.permissions().mode() & 0o777;
        if current == 0 {
            let mut p = md.permissions();
            p.set_mode(0o755);
            let _ = fs::set_permissions(&dir, p);
        }
    }
    Ok(())
}

/// Reads all `*.conf` files from the config directory.
///
/// For each `.conf`, loads `<name>.rules.json` if present, else defaults to
/// `{"mode":"exclude","entries":[]}`.
pub fn load_configs() -> Result<Vec<Config>, ConfigError> {
    let dir = config_dir();
    log::debug!("splitwg: config: loading configs from {}", dir.display());
    ensure_config_dir()?;

    let mut out = Vec::new();
    let iter = match fs::read_dir(&dir) {
        Ok(it) => it,
        Err(e) => return Err(ConfigError::Io(e)),
    };

    // Collect first so ordering is stable (read_dir is unordered on some fs).
    let mut entries: Vec<fs::DirEntry> = iter.filter_map(|r| r.ok()).collect();
    entries.sort_by_key(|e| e.file_name());

    for e in entries {
        let ft = match e.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_dir() {
            continue;
        }
        let name_os = e.file_name();
        let fname = match name_os.to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };
        if !fname.ends_with(".conf") {
            continue;
        }
        let name = fname.trim_end_matches(".conf").to_string();
        let file_path = dir.join(&fname);

        let rules_path = dir.join(format!("{name}.rules.json"));
        let rules = load_rules_file(&rules_path).unwrap_or_default();

        log::debug!("splitwg: config: loaded tunnel {:?}", name);
        out.push(Config {
            name,
            file_path,
            rules,
        });
    }

    log::debug!("splitwg: config: {} config(s) found", out.len());
    Ok(out)
}

/// Parses a `<name>.rules.json` file. Returns an error if missing or malformed.
pub fn load_rules_file(path: &Path) -> Result<Rules, ConfigError> {
    let data = fs::read(path)?;
    let r: Rules = serde_json::from_slice(&data)?;
    Ok(r)
}

/// Creates a default rules file if one does not already exist; returns the path.
pub fn ensure_rules_file(name: &str) -> Result<PathBuf, ConfigError> {
    let path = rules_path(name);
    if !path.exists() {
        log::info!(
            "splitwg: config: creating default rules file for {:?}",
            name
        );
        let r = Rules::default();
        let data = serde_json::to_vec_pretty(&r)?;
        write_with_mode(&path, &data, 0o644)?;
    } else {
        log::info!("splitwg: config: rules file already exists for {:?}", name);
    }
    Ok(path)
}

/// Copies `src` into the config directory as `<name>.conf` with mode 0600.
pub fn copy_config_file(src: &Path, name: &str) -> io::Result<()> {
    let dst = conf_path(name);
    log::info!(
        "splitwg: config: copying config {} -> {}",
        src.display(),
        dst.display()
    );
    let data = fs::read(src)?;
    write_with_mode(&dst, &data, 0o600)
}

/// Deletes `<name>.conf` and `<name>.rules.json` from the config directory.
/// Missing files are ignored — the operation is idempotent. Returns an
/// error only when unlink fails for a file that actually exists.
pub fn delete_config(name: &str) -> io::Result<()> {
    log::info!("splitwg: config: deleting config {:?}", name);
    let dir = config_dir();
    let conf = dir.join(format!("{name}.conf"));
    let rules = dir.join(format!("{name}.rules.json"));
    if conf.exists() {
        log::info!("splitwg: config: removing {}", conf.display());
        fs::remove_file(&conf)?;
    }
    if rules.exists() {
        log::info!("splitwg: config: removing {}", rules.display());
        fs::remove_file(&rules)?;
    }
    log::info!("splitwg: config: config {:?} deleted", name);
    Ok(())
}

/// Renames `<old>.conf` → `<new>.conf` and `<old>.rules.json` →
/// `<new>.rules.json`. Returns `AlreadyExists` if the target `.conf`
/// file is already present. A missing `.rules.json` is silently skipped.
pub fn rename_config(old_name: &str, new_name: &str) -> io::Result<()> {
    log::info!("splitwg: config: renaming {:?} to {:?}", old_name, new_name);
    let dir = config_dir();
    let old_conf = dir.join(format!("{old_name}.conf"));
    let new_conf = dir.join(format!("{new_name}.conf"));
    let old_rules = dir.join(format!("{old_name}.rules.json"));
    let new_rules = dir.join(format!("{new_name}.rules.json"));

    if new_conf.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{new_name}.conf already exists"),
        ));
    }

    fs::rename(&old_conf, &new_conf)?;

    if old_rules.exists() {
        fs::rename(&old_rules, &new_rules)?;
    }

    log::info!(
        "splitwg: config: config {:?} renamed to {:?}",
        old_name,
        new_name
    );
    Ok(())
}

/// Returns the path to the global settings file (`settings.json`) inside the
/// config directory. The file may be absent; callers use `load_settings` which
/// returns `Settings::default()` in that case.
pub fn settings_path() -> PathBuf {
    config_dir().join("settings.json")
}

/// Loads global settings from `settings.json`. On any error (missing file,
/// malformed JSON, permission issue) returns `Settings::default()` so the app
/// always has a usable value. The safer default (hooks off) is enforced by
/// `Settings::default()`.
pub fn load_settings() -> Settings {
    let path = settings_path();
    match fs::read(&path) {
        Ok(data) => match serde_json::from_slice(&data) {
            Ok(s) => s,
            Err(e) => {
                log::warn!(
                    "splitwg: config: malformed settings.json, falling back to defaults: {}",
                    e
                );
                Settings::default()
            }
        },
        Err(_) => {
            log::warn!("splitwg: config: settings.json not found, using defaults");
            Settings::default()
        }
    }
}

/// Persists global settings to `settings.json` with mode 0644. Creates the
/// config directory if missing.
pub fn save_settings(s: &Settings) -> Result<(), ConfigError> {
    ensure_config_dir()?;
    let path = settings_path();
    log::info!("splitwg: config: saving settings to {}", path.display());
    let data = serde_json::to_vec_pretty(s)?;
    write_with_mode(&path, &data, 0o644)?;
    log::info!("splitwg: config: settings saved");
    Ok(())
}

/// Persists rules for the named config to `<ConfigDir>/<name>.rules.json` with
/// mode 0644.
pub fn save_rules(name: &str, rules: &Rules) -> Result<(), ConfigError> {
    let path = rules_path(name);
    log::info!(
        "splitwg: config: saving rules for {:?} to {}",
        name,
        path.display()
    );

    let data = serde_json::to_vec_pretty(rules).map_err(|e| ConfigError::SaveRules {
        name: name.to_string(),
        source: io::Error::other(e),
    })?;
    write_with_mode(&path, &data, 0o644).map_err(|e| ConfigError::SaveRules {
        name: name.to_string(),
        source: e,
    })?;

    log::info!("splitwg: config: rules saved for {:?}", name);
    Ok(())
}

fn write_with_mode(path: &Path, data: &[u8], _mode: u32) -> io::Result<()> {
    use std::io::Write;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(_mode);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    #[cfg(target_os = "windows")]
    restrict_file_acl(path);
    Ok(())
}

#[cfg(target_os = "windows")]
fn restrict_file_acl(path: &Path) {
    let path_str = path.to_string_lossy();
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "SYSTEM".to_string());
    let _ = std::process::Command::new("icacls")
        .args([
            &*path_str,
            "/inheritance:r",
            "/grant:r",
            &format!("{user}:F"),
        ])
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    // HOME manipulation affects process global state; serialize tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct HomeGuard<'a> {
        _lock: MutexGuard<'a, ()>,
        previous: Option<std::ffi::OsString>,
    }

    impl<'a> HomeGuard<'a> {
        fn set(home: &Path) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let previous = std::env::var_os("HOME");
            std::env::set_var("HOME", home);
            HomeGuard {
                _lock: lock,
                previous,
            }
        }
    }

    impl<'a> Drop for HomeGuard<'a> {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    fn tmp() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir();
        let n: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pid = std::process::id();
        let seq = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = base.join(format!("splitwg-test-{pid}-{n}-{seq}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn save_rules_creates_file() {
        let home = tmp();
        let _g = HomeGuard::set(&home);
        fs::create_dir_all(config_dir()).unwrap();

        let rules = Rules {
            mode: "exclude".to_string(),
            entries: vec!["192.168.1.0/24".into(), "10.0.0.1".into()],
            hooks_enabled: false,
            on_demand: None,
        };
        save_rules("myvpn", &rules).unwrap();

        let path = home.join(".config/splitwg/myvpn.rules.json");
        assert!(path.exists(), "rules file must be created at {:?}", path);
    }

    #[test]
    fn save_rules_overwrites_existing() {
        let home = tmp();
        let _g = HomeGuard::set(&home);
        fs::create_dir_all(config_dir()).unwrap();

        save_rules(
            "myvpn",
            &Rules {
                mode: "exclude".into(),
                entries: vec!["1.2.3.4".into()],
                hooks_enabled: false,
                on_demand: None,
            },
        )
        .unwrap();

        save_rules(
            "myvpn",
            &Rules {
                mode: "include".into(),
                entries: vec!["8.8.8.8".into(), "8.8.4.4".into()],
                hooks_enabled: false,
                on_demand: None,
            },
        )
        .unwrap();

        let loaded = load_rules_file(&home.join(".config/splitwg/myvpn.rules.json")).unwrap();
        assert_eq!(loaded.mode, "include");
        assert_eq!(loaded.entries.len(), 2);
    }

    #[test]
    fn save_rules_roundtrip() {
        let home = tmp();
        let _g = HomeGuard::set(&home);
        fs::create_dir_all(config_dir()).unwrap();

        let want = Rules {
            mode: "include".into(),
            entries: vec![
                "example.com".into(),
                "10.0.0.0/8".into(),
                "2001:db8::1/128".into(),
            ],
            hooks_enabled: false,
            on_demand: None,
        };
        save_rules("roundtrip", &want).unwrap();

        let got = load_rules_file(&home.join(".config/splitwg/roundtrip.rules.json")).unwrap();
        assert_eq!(got.mode, want.mode);
        assert_eq!(got.entries, want.entries);
    }

    #[test]
    fn save_rules_invalid_dir() {
        let home = tmp();
        let _g = HomeGuard::set(&home);

        // Create a regular file where the config dir would go so write fails.
        let parent = home.join(".config");
        fs::create_dir_all(&parent).unwrap();
        let block = parent.join("splitwg");
        fs::write(&block, b"block").unwrap();

        let err = save_rules(
            "test",
            &Rules {
                mode: "exclude".into(),
                entries: vec![],
                hooks_enabled: false,
                on_demand: None,
            },
        );
        assert!(err.is_err(), "expected error when config dir is a file");
    }

    #[test]
    fn ensure_rules_file_creates_default() {
        let home = tmp();
        let _g = HomeGuard::set(&home);
        fs::create_dir_all(config_dir()).unwrap();

        let path = ensure_rules_file("vpn1").unwrap();
        assert!(path.exists());
        let r = load_rules_file(&path).unwrap();
        assert_eq!(r.mode, "exclude");
        assert!(r.entries.is_empty());
    }

    #[test]
    fn copy_config_file_sets_0600() {
        let home = tmp();
        let _g = HomeGuard::set(&home);
        fs::create_dir_all(config_dir()).unwrap();

        let src = home.join("some.conf");
        fs::write(&src, b"[Interface]\n").unwrap();

        copy_config_file(&src, "vpn2").unwrap();
        let dst = home.join(".config/splitwg/vpn2.conf");
        assert!(dst.exists());
        let perms = fs::metadata(&dst).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn load_settings_missing_returns_default() {
        let home = tmp();
        let _g = HomeGuard::set(&home);
        let s = load_settings();
        assert_eq!(s, Settings::default());
        assert!(!s.hooks_enabled);
    }

    #[test]
    fn save_settings_roundtrip() {
        let home = tmp();
        let _g = HomeGuard::set(&home);

        let want = Settings {
            hooks_enabled: true,
            language: None,
            kill_switch: false,
            update_check_enabled: true,
            last_update_check: Some(1_700_000_000),
            geodb_auto_update_enabled: true,
            last_geodb_update: Some(1_700_100_000),
        };
        save_settings(&want).unwrap();

        let got = load_settings();
        assert_eq!(got, want);

        let path = settings_path();
        let perms = fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o644);
    }

    #[test]
    fn load_settings_malformed_returns_default() {
        let home = tmp();
        let _g = HomeGuard::set(&home);
        fs::create_dir_all(config_dir()).unwrap();
        fs::write(settings_path(), b"{ not json").unwrap();

        let s = load_settings();
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn load_configs_reads_conf_and_rules() {
        let home = tmp();
        let _g = HomeGuard::set(&home);
        let dir = home.join(".config/splitwg");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.conf"), b"[Interface]\n").unwrap();
        fs::write(dir.join("b.conf"), b"[Interface]\n").unwrap();
        fs::write(
            dir.join("a.rules.json"),
            br#"{"mode":"include","entries":["1.1.1.1"]}"#,
        )
        .unwrap();

        let cfgs = load_configs().unwrap();
        assert_eq!(cfgs.len(), 2);
        // Alphabetical — a first, b second.
        assert_eq!(cfgs[0].name, "a");
        assert_eq!(cfgs[0].rules.mode, "include");
        assert_eq!(cfgs[1].name, "b");
        assert_eq!(cfgs[1].rules.mode, "exclude"); // default
    }
}
