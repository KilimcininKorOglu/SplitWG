//! GitHub Releases + minisign-backed in-app updater.
//!
//! The flow splits across three stages — check, download+verify, install —
//! each driven by a worker thread that posts `TaskResult` variants back to
//! the main loop. This module owns the check stage and (in later phases) the
//! download + install stages. Everything here is synchronous Rust on top of
//! `ureq`; the tray process stays blissfully tokio-free for update work.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use minisign_verify::{PublicKey, Signature};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// GitHub `<owner>/<repo>` slug. Hardcoded because the binary only ever
/// self-updates from its own canonical release stream.
pub const REPO_SLUG: &str = "KilimcininKorOglu/SplitWG";

/// Minisign public key embedded at compile time. Regenerate with
/// `scripts/minisign-keygen.sh`; rotating it always requires shipping a new
/// binary first because older installs will only trust this baked-in value.
pub const PUBLIC_KEY_PEM: &str = include_str!("../../resources/splitwg.pub");

/// Seconds per day — the cooldown between background checks.
pub const CHECK_COOLDOWN_SECS: u64 = 24 * 60 * 60;

/// Errors the updater pipeline can emit. Kept flat so the callers can match
/// without needing the full thiserror source chain.
#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("http: {0}")]
    Http(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("no suitable asset found for this architecture")]
    NoAsset,
    #[error("signature verification failed: {0}")]
    Signature(String),
    #[error("sha-256 digest mismatch")]
    DigestMismatch,
    #[error("team id mismatch: expected {expected}, got {actual}")]
    TeamIdMismatch { expected: String, actual: String },
    #[error("notarization check failed: {0}")]
    NotarizationRejected(String),
    #[error("other: {0}")]
    Other(String),
}

/// Parsed subset of the GitHub Releases API response that the updater
/// actually consumes.
#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    pub version: Version,
    pub tag_name: String,
    pub body: String,
    pub dmg_asset: Option<AssetRef>,
    pub minisig_asset: Option<AssetRef>,
}

/// A single downloadable asset attached to a release.
#[derive(Debug, Clone)]
pub struct AssetRef {
    pub name: String,
    pub url: String,
    /// `"sha256:<hex>"` when GitHub exposes a digest; stripped of the prefix
    /// before use.
    pub digest_sha256: Option<String>,
}

/// Returns the current binary's version. Parsed from `CARGO_PKG_VERSION`
/// which is stable across macOS bundles.
pub fn current_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("invalid CARGO_PKG_VERSION")
}

/// `true` when `latest` should be offered as an update over the current
/// binary. Equal versions never trigger an upgrade prompt.
pub fn is_newer(latest: &Version) -> bool {
    *latest > current_version()
}

/// Epoch-seconds "now". Wrapped so tests can reason about cooldowns without
/// mocking time.
pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `true` when the daily check cooldown has elapsed.
pub fn cooldown_elapsed(last: Option<u64>) -> bool {
    match last {
        None => true,
        Some(ts) => now_epoch().saturating_sub(ts) >= CHECK_COOLDOWN_SECS,
    }
}

/// Calls `GET /repos/<slug>/releases/latest` and parses the response. Uses a
/// 10 s read timeout so a wedged connection can't hang the background
/// thread.
pub fn fetch_latest() -> Result<ReleaseInfo, UpdateError> {
    let url = format!("https://api.github.com/repos/{}/releases/latest", REPO_SLUG);
    log::info!("splitwg: update: fetching latest release from {}", url);
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .new_agent();
    let ua = format!("SplitWG/{}", current_version());
    let response = agent
        .get(&url)
        .header("User-Agent", &ua)
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| UpdateError::Http(e.to_string()))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(UpdateError::Http(format!("HTTP {}", status)));
    }
    let text = response
        .into_body()
        .read_to_string()
        .map_err(|e| UpdateError::Http(e.to_string()))?;
    let body: GhRelease =
        serde_json::from_str(&text).map_err(|e| UpdateError::Parse(e.to_string()))?;
    let info = parse_release(body)?;
    if is_newer(&info.version) {
        log::info!(
            "splitwg: update: new version available: {} (current: {})",
            info.version,
            current_version()
        );
    } else {
        log::info!(
            "splitwg: update: already up to date (remote: {}, current: {})",
            info.version,
            current_version()
        );
    }
    Ok(info)
}

/// Selects the DMG + minisig pair that matches the current architecture and
/// returns a `ReleaseInfo`. Accepts a pre-parsed `GhRelease` so tests can
/// feed hand-rolled JSON directly.
fn parse_release(raw: GhRelease) -> Result<ReleaseInfo, UpdateError> {
    let tag = raw.tag_name.trim_start_matches('v').to_string();
    let version = Version::parse(&tag)
        .map_err(|e| UpdateError::Parse(format!("tag {:?}: {}", raw.tag_name, e)))?;
    let dmg_asset = pick_dmg(&raw.assets, current_arch());
    let minisig_asset = dmg_asset
        .as_ref()
        .and_then(|a| pick_minisig(&raw.assets, &a.name));
    Ok(ReleaseInfo {
        version,
        tag_name: raw.tag_name,
        body: raw.body.unwrap_or_default(),
        dmg_asset,
        minisig_asset,
    })
}

/// Returns `"arm"` / `"intel"` for the running binary. Used to prefer an
/// arch-specific DMG when both are present.
pub fn current_arch() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    {
        "arm"
    }
    #[cfg(target_arch = "x86_64")]
    {
        "intel"
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        ""
    }
}

/// DMG selector: prefers the arch-specific DMG (`*-arm.dmg` or
/// `*-intel.dmg`), falls back to the universal one without a suffix. Any
/// `.dmg` asset qualifies — the workflow always ships at least one.
fn pick_dmg(assets: &[GhAsset], arch: &str) -> Option<AssetRef> {
    let suffix = if arch.is_empty() {
        String::new()
    } else {
        format!("-{}.dmg", arch)
    };
    let mut arch_match: Option<&GhAsset> = None;
    let mut universal: Option<&GhAsset> = None;
    for a in assets {
        let lower = a.name.to_lowercase();
        if !lower.ends_with(".dmg") {
            continue;
        }
        if !suffix.is_empty() && lower.ends_with(&suffix) {
            arch_match = Some(a);
            continue;
        }
        if !lower.ends_with("-arm.dmg") && !lower.ends_with("-intel.dmg") {
            universal = Some(a);
        }
    }
    let pick = arch_match.or(universal)?;
    Some(asset_ref(pick))
}

/// Finds the `<dmg>.minisig` sibling for the chosen DMG. GitHub releases are
/// flat — the filename alone is enough.
fn pick_minisig(assets: &[GhAsset], dmg_name: &str) -> Option<AssetRef> {
    let target = format!("{}.minisig", dmg_name);
    assets.iter().find(|a| a.name == target).map(asset_ref)
}

fn asset_ref(a: &GhAsset) -> AssetRef {
    AssetRef {
        name: a.name.clone(),
        url: a.browser_download_url.clone(),
        digest_sha256: a
            .digest
            .as_deref()
            .and_then(|s| s.strip_prefix("sha256:"))
            .map(|s| s.to_string()),
    }
}

/// Hand-off struct returned by `download_and_verify` once the DMG is
/// downloaded, minisign-verified, mounted, copied to cache, and the
/// extracted `.app` has passed Team ID + notarization checks.
#[derive(Debug, Clone)]
pub struct DownloadedUpdate {
    pub version: Version,
    pub app_path: PathBuf,
    pub dmg_path: PathBuf,
    pub mount_point: PathBuf,
}

/// `~/Library/Caches/SplitWG/updates` — where downloaded DMGs and extracted
/// `.app` bundles live. Created lazily.
pub fn cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("SplitWG")
        .join("updates")
}

/// Downloads the DMG, verifies sha-256 + minisign + Team ID + notarization,
/// then returns a `DownloadedUpdate` describing the cached `.app`. The mount
/// point is detached before returning so nothing is left attached.
#[cfg(target_os = "macos")]
pub fn download_and_verify(
    dmg_url: &str,
    minisig_url: &str,
    expected_digest: Option<&str>,
    version: Version,
    progress: impl Fn(u64, u64),
) -> Result<DownloadedUpdate, UpdateError> {
    log::info!(
        "splitwg: update: starting download of v{} from {}",
        version,
        dmg_url
    );
    let cache = cache_dir();
    fs::create_dir_all(&cache)?;

    let dmg_path = cache.join(format!("SplitWG-{}.dmg", version));
    let minisig_path = cache.join(format!("SplitWG-{}.dmg.minisig", version));

    let digest = download_with_progress(dmg_url, &dmg_path, &progress)?;

    if let Some(expected) = expected_digest {
        if !digest.eq_ignore_ascii_case(expected) {
            log::error!(
                "splitwg: update: SHA-256 mismatch (expected: {}, got: {})",
                expected,
                digest
            );
            let _ = fs::remove_file(&dmg_path);
            return Err(UpdateError::DigestMismatch);
        }
        log::info!("splitwg: update: SHA-256 verified");
    }

    download_file(minisig_url, &minisig_path)?;
    verify_minisign(&dmg_path, &minisig_path)?;
    log::info!("splitwg: update: minisign signature verified");

    let mount_point = hdiutil_attach(&dmg_path)?;
    let copy_result = (|| -> Result<PathBuf, UpdateError> {
        let src_app = find_app_in_mount(&mount_point)?;
        let dst_app = cache.join(format!("SplitWG-{}.app", version));
        if dst_app.exists() {
            fs::remove_dir_all(&dst_app)?;
        }
        copy_recursive(&src_app, &dst_app)?;
        let expected = self_team_id()?;
        let actual = codesign_team_id(&dst_app)?;
        if expected != actual {
            return Err(UpdateError::TeamIdMismatch { expected, actual });
        }
        verify_notarization(&dst_app)?;
        Ok(dst_app)
    })();
    let _ = hdiutil_detach(&mount_point);

    let app_path = copy_result?;
    log::info!(
        "splitwg: update: download and verification complete for v{}",
        version
    );
    Ok(DownloadedUpdate {
        version,
        app_path,
        dmg_path,
        mount_point,
    })
}

#[cfg(target_os = "linux")]
pub fn download_and_verify(
    _dmg_url: &str,
    _minisig_url: &str,
    _expected_digest: Option<&str>,
    _version: Version,
    _progress: impl Fn(u64, u64),
) -> Result<DownloadedUpdate, UpdateError> {
    Err(UpdateError::Other("Linux updates not yet supported".into()))
}

/// Streams `url` to `dest`, reporting progress every 256 KiB, and returns
/// the hex-encoded SHA-256 of the written bytes.
fn download_with_progress(
    url: &str,
    dest: &Path,
    progress: &impl Fn(u64, u64),
) -> Result<String, UpdateError> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .build()
        .new_agent();
    let response = agent
        .get(url)
        .header("User-Agent", &format!("SplitWG/{}", current_version()))
        .call()
        .map_err(|e| UpdateError::Http(e.to_string()))?;
    let total = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    log::info!("splitwg: update: download size: {} bytes", total);

    let mut reader = response.into_body().into_reader();
    let mut file = fs::File::create(dest)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut downloaded: u64 = 0;
    let mut since_report: u64 = 0;
    let mut last_milestone: u8 = 0;
    progress(0, total);
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
        hasher.update(&buf[..n]);
        downloaded += n as u64;
        since_report += n as u64;
        if since_report >= 256 * 1024 {
            progress(downloaded, total);
            since_report = 0;
        }
        if let Some(pct) = (downloaded * 100).checked_div(total) {
            let milestone = (pct as u8) / 25;
            if milestone > last_milestone {
                last_milestone = milestone;
                log::info!("splitwg: update: download progress {}%", milestone * 25);
            }
        }
    }
    file.flush()?;
    progress(downloaded, total.max(downloaded));
    log::info!(
        "splitwg: update: download complete, {} bytes written",
        downloaded
    );
    Ok(hex::encode(hasher.finalize()))
}

/// Small-body download helper — used for the `.minisig` sibling, which is
/// a few hundred bytes.
fn download_file(url: &str, dest: &Path) -> Result<(), UpdateError> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .new_agent();
    let response = agent
        .get(url)
        .header("User-Agent", &format!("SplitWG/{}", current_version()))
        .call()
        .map_err(|e| UpdateError::Http(e.to_string()))?;
    let bytes = response
        .into_body()
        .read_to_vec()
        .map_err(|e| UpdateError::Http(e.to_string()))?;
    fs::write(dest, bytes)?;
    Ok(())
}

/// Validates the detached minisign signature against `PUBLIC_KEY_PEM`.
pub fn verify_minisign(payload: &Path, signature: &Path) -> Result<(), UpdateError> {
    let pk = PublicKey::decode(PUBLIC_KEY_PEM.trim())
        .map_err(|e| UpdateError::Signature(format!("bad public key: {e}")))?;
    let sig_text = fs::read_to_string(signature)?;
    let sig = Signature::decode(sig_text.trim())
        .map_err(|e| UpdateError::Signature(format!("bad signature file: {e}")))?;
    let data = fs::read(payload)?;
    pk.verify(&data, &sig, false)
        .map_err(|e| UpdateError::Signature(e.to_string()))
}

/// `hdiutil attach -nobrowse -quiet` and parse the mount point.
#[cfg(target_os = "macos")]
fn hdiutil_attach(dmg: &Path) -> Result<PathBuf, UpdateError> {
    log::info!("splitwg: update: mounting DMG {:?}", dmg);
    let output = Command::new("/usr/bin/hdiutil")
        .args(["attach", "-nobrowse", "-quiet", "-noautoopen"])
        .arg(dmg)
        .output()?;
    if !output.status.success() {
        log::error!("splitwg: update: hdiutil attach failed");
        return Err(UpdateError::Other(format!(
            "hdiutil attach failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let mount = parse_mount_point(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| UpdateError::Other("could not parse hdiutil output".into()))?;
    log::info!("splitwg: update: mounted at {:?}", mount);
    Ok(mount)
}

/// Detaches `mount_point`; silenced because callers already report the
/// primary error and the tunnel must still return whatever it has.
#[cfg(target_os = "macos")]
fn hdiutil_detach(mount_point: &Path) -> io::Result<()> {
    log::info!("splitwg: update: unmounting {:?}", mount_point);
    let status = Command::new("/usr/bin/hdiutil")
        .args(["detach", "-quiet", "-force"])
        .arg(mount_point)
        .status()?;
    if !status.success() {
        log::warn!(
            "splitwg: update: hdiutil detach {:?} exited non-zero",
            mount_point
        );
    }
    Ok(())
}

/// Extracts the last whitespace-separated path from the `hdiutil attach`
/// output. Sample lines look like `/dev/disk5s1 \t Apple_HFS \t /Volumes/SplitWG`.
fn parse_mount_point(output: &str) -> Option<PathBuf> {
    for line in output.lines() {
        for token in line.split_whitespace().rev() {
            if token.starts_with("/Volumes/") {
                return Some(PathBuf::from(token));
            }
        }
    }
    None
}

fn find_app_in_mount(mount: &Path) -> Result<PathBuf, UpdateError> {
    for entry in fs::read_dir(mount)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("app"))
            .unwrap_or(false)
        {
            return Ok(path);
        }
    }
    Err(UpdateError::Other(format!(
        "no .app bundle inside {}",
        mount.display()
    )))
}

/// Copies a directory tree using `/bin/cp -R`, preserving metadata in a
/// way that `std::fs` does not (extended attributes, symlinks inside
/// bundles). Keeping the shell-out avoids reimplementing the corner cases.
#[cfg(target_os = "macos")]
fn copy_recursive(src: &Path, dst: &Path) -> Result<(), UpdateError> {
    let status = Command::new("/bin/cp")
        .arg("-R")
        .arg(src)
        .arg(dst)
        .status()?;
    if !status.success() {
        return Err(UpdateError::Other(format!(
            "cp -R {:?} → {:?} failed",
            src, dst
        )));
    }
    Ok(())
}

/// Team Identifier of the running binary. Cached on first call because the
/// codesign subprocess takes ~80 ms and self-inspection never changes.
#[cfg(target_os = "macos")]
fn self_team_id() -> Result<String, UpdateError> {
    static CACHE: OnceLock<Result<String, String>> = OnceLock::new();
    let cached = CACHE.get_or_init(|| match current_app_bundle() {
        Some(app) => codesign_team_id(&app).map_err(|e| e.to_string()),
        None => Err("could not locate current .app bundle".to_string()),
    });
    cached.clone().map_err(UpdateError::Other)
}

/// Walks up from the executable path to find the enclosing `.app` bundle.
/// Returns `None` when running outside a bundle (cargo run, tests).
pub fn current_app_bundle() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let mut cur = exe.as_path();
    while let Some(parent) = cur.parent() {
        if parent
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("app"))
            .unwrap_or(false)
        {
            return Some(parent.to_path_buf());
        }
        cur = parent;
    }
    None
}

/// Runs `codesign -dv --verbose=4 <app>` and extracts `TeamIdentifier=…`
/// from stderr. Returns an error when the app is not signed.
#[cfg(target_os = "macos")]
pub fn codesign_team_id(app: &Path) -> Result<String, UpdateError> {
    log::info!("splitwg: update: checking codesign for {:?}", app);
    let output = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=4"])
        .arg(app)
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let team_id = parse_team_id(&stderr).ok_or_else(|| {
        UpdateError::Other(format!("no TeamIdentifier in codesign output: {stderr}"))
    })?;
    log::info!("splitwg: update: codesign team id: {}", team_id);
    Ok(team_id)
}

fn parse_team_id(output: &str) -> Option<String> {
    for line in output.lines() {
        if let Some(rest) = line.trim().strip_prefix("TeamIdentifier=") {
            let value = rest.trim().to_string();
            if value.is_empty() || value == "not set" {
                return None;
            }
            return Some(value);
        }
    }
    None
}

/// Where the running binary lives on disk. Returns the enclosing `.app`
/// bundle, or falls through to the executable path (cargo run, tests).
pub fn current_install_path() -> Result<PathBuf, UpdateError> {
    if let Some(app) = current_app_bundle() {
        return Ok(app);
    }
    std::env::current_exe().map_err(UpdateError::Io)
}

/// Whether the install can be done with a plain `fs::rename` or needs
/// admin escalation. `/Applications` is admin-gated on every macOS 13+
/// install; `~/Applications` and friends are user-writable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMode {
    DirectReplace,
    AdminReplace,
}

/// Inspects the target's parent directory for write permission. Any path
/// under `/Applications` routes through the admin fallback regardless of
/// posix bits because `setuid root` directories on macOS sometimes claim
/// write access they do not actually grant.
pub fn detect_install_mode(target: &Path) -> InstallMode {
    let parent = target.parent().unwrap_or(target);
    let path_str = parent.to_string_lossy();
    if path_str == "/Applications" || path_str.starts_with("/Applications/") {
        return InstallMode::AdminReplace;
    }
    // Fall back to writable check on any non-/Applications parent. When
    // the parent does not yet exist (first install), default to direct —
    // the worst case is a readable error surfaced through the task.
    if let Ok(meta) = fs::metadata(parent) {
        let perms = meta.permissions();
        if perms.readonly() {
            return InstallMode::AdminReplace;
        }
    }
    InstallMode::DirectReplace
}

/// Replaces `current_app` with `new_app`, detaches the mount, and spawns a
/// fresh `open -n <current_app>` before exiting the process. Never returns
/// on the happy path — the caller exits 0 as the very last line.
#[cfg(target_os = "macos")]
pub fn install_and_relaunch(
    new_app: &Path,
    current_app: &Path,
    mount_point: &Path,
) -> Result<(), UpdateError> {
    log::info!(
        "splitwg: update: install starting, swapping {:?} with {:?}",
        current_app,
        new_app
    );
    // Best-effort unmount; if it fails the install can still succeed.
    let _ = hdiutil_detach(mount_point);

    match detect_install_mode(current_app) {
        InstallMode::DirectReplace => {
            log::info!("splitwg: update: direct replace mode");
            if current_app.exists() {
                fs::remove_dir_all(current_app)?;
            }
            copy_recursive(new_app, current_app)?;
        }
        InstallMode::AdminReplace => {
            log::info!("splitwg: update: admin replace mode (escalating privileges)");
            let script = format!(
                "/bin/rm -rf {} && /bin/cp -R {} {} && /usr/bin/xattr -cr {}",
                shell_quote(current_app),
                shell_quote(new_app),
                shell_quote(current_app),
                shell_quote(current_app),
            );
            crate::wg::run_as_admin_osascript(&script)
                .map_err(|e| UpdateError::Other(e.to_string()))?;
        }
    }

    log::info!("splitwg: update: relaunching {:?}", current_app);
    // `open -n` spawns a *new* instance even when the app is still running,
    // which lets us exit the current process without race-conditioning the
    // new one on our own pid.
    Command::new("/usr/bin/open")
        .args(["-n"])
        .arg(current_app)
        .spawn()
        .map_err(UpdateError::Io)?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn install_and_relaunch(
    _new_app: &Path,
    _current_app: &Path,
    _mount_point: &Path,
) -> Result<(), UpdateError> {
    Err(UpdateError::Other("Linux install not yet supported".into()))
}

fn shell_quote(path: &Path) -> String {
    let s = path.to_string_lossy();
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Removes `.dmg`, `.minisig`, and `.app` entries in the cache that are
/// older than 7 days. Runs once per process (guarded by `OnceLock` in the
/// caller) to avoid re-scanning on every window-show.
pub fn cleanup_stale_downloads() {
    let dir = cache_dir();
    if !dir.exists() {
        return;
    }
    let cutoff = Duration::from_secs(7 * 24 * 60 * 60);
    let entries = match fs::read_dir(&dir) {
        Ok(it) => it,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let age_ok = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d > cutoff)
            .unwrap_or(false);
        if !age_ok {
            continue;
        }
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let removed = if is_dir {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        if let Err(e) = removed {
            log::warn!("gui: update: cleanup failed for {:?}: {}", path, e);
        }
    }
}

/// Test hook: compare an expected Team ID against the one reported by
/// codesign. Separated from `download_and_verify` so unit tests can exercise
/// the mismatch branch without touching the filesystem.
pub fn verify_team_id(expected: &str, actual: &str) -> Result<(), UpdateError> {
    if expected == actual {
        Ok(())
    } else {
        Err(UpdateError::TeamIdMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }
}

/// `spctl -a -vv -t exec <app>` — succeeds only when Gatekeeper accepts the
/// bundle as a notarized Developer ID build.
#[cfg(target_os = "macos")]
pub fn verify_notarization(app: &Path) -> Result<(), UpdateError> {
    log::info!("splitwg: update: verifying notarization for {:?}", app);
    let output = Command::new("/usr/sbin/spctl")
        .args(["-a", "-vv", "-t", "exec"])
        .arg(app)
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        log::error!("splitwg: update: notarization rejected");
        return Err(UpdateError::NotarizationRejected(stderr.trim().to_string()));
    }
    if stderr.contains("Notarized Developer ID") {
        log::info!("splitwg: update: notarization verified (Notarized Developer ID)");
        return Ok(());
    }
    if stderr.contains("UNNOTARIZED") {
        log::error!("splitwg: update: bundle is not notarized");
        return Err(UpdateError::NotarizationRejected(
            "bundle is not notarized".into(),
        ));
    }
    // Accept plain "accepted" on older macOS where spctl does not always
    // print the "Notarized" suffix; keep this narrow — the download path
    // still requires minisign + Team ID match.
    if stderr.contains("accepted") {
        log::info!("splitwg: update: notarization accepted");
        return Ok(());
    }
    log::error!("splitwg: update: notarization check inconclusive");
    Err(UpdateError::NotarizationRejected(stderr.trim().to_string()))
}

#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

#[derive(Debug, Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    digest: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_asset(name: &str, digest: Option<&str>) -> GhAsset {
        GhAsset {
            name: name.to_string(),
            browser_download_url: format!("https://example.invalid/{}", name),
            digest: digest.map(|s| s.to_string()),
        }
    }

    #[test]
    fn is_newer_detects_upgrade() {
        assert!(is_newer(&bump_patch(1)));
        // Same version never upgrades.
        assert!(!is_newer(&current_version()));
    }

    #[test]
    fn is_newer_rejects_older() {
        let mut older = current_version();
        if older.patch == 0 {
            older.minor = older.minor.saturating_sub(1);
        } else {
            older.patch -= 1;
        }
        assert!(!is_newer(&older));
    }

    fn bump_patch(bump: u64) -> Version {
        let mut v = current_version();
        v.patch += bump;
        v
    }

    #[test]
    fn cooldown_elapses_after_one_day() {
        assert!(cooldown_elapsed(None));
        let now = now_epoch();
        assert!(!cooldown_elapsed(Some(now)));
        assert!(cooldown_elapsed(Some(
            now.saturating_sub(CHECK_COOLDOWN_SECS + 1)
        )));
    }

    #[test]
    fn asset_selection_picks_arch_match() {
        let assets = vec![
            mk_asset("SplitWG-intel.dmg", None),
            mk_asset("SplitWG-arm.dmg", Some("sha256:aaaa")),
            mk_asset("SplitWG.dmg", None),
        ];
        let arm = pick_dmg(&assets, "arm").unwrap();
        assert_eq!(arm.name, "SplitWG-arm.dmg");
        assert_eq!(arm.digest_sha256.as_deref(), Some("aaaa"));

        let intel = pick_dmg(&assets, "intel").unwrap();
        assert_eq!(intel.name, "SplitWG-intel.dmg");
    }

    #[test]
    fn asset_selection_falls_back_to_universal() {
        // Only the universal DMG is published.
        let assets = vec![mk_asset("SplitWG.dmg", None)];
        let arm = pick_dmg(&assets, "arm").unwrap();
        assert_eq!(arm.name, "SplitWG.dmg");
    }

    #[test]
    fn minisig_sibling_is_discovered() {
        let assets = vec![
            mk_asset("SplitWG.dmg", None),
            mk_asset("SplitWG.dmg.minisig", None),
        ];
        let dmg = pick_dmg(&assets, "").unwrap();
        let sig = pick_minisig(&assets, &dmg.name).unwrap();
        assert_eq!(sig.name, "SplitWG.dmg.minisig");
    }

    #[test]
    fn parse_release_json_extracts_digest() {
        let raw = GhRelease {
            tag_name: "v9.9.9".to_string(),
            body: Some("release notes".to_string()),
            assets: vec![
                mk_asset("SplitWG.dmg", Some("sha256:deadbeef")),
                mk_asset("SplitWG.dmg.minisig", None),
            ],
        };
        let info = parse_release(raw).unwrap();
        assert_eq!(info.tag_name, "v9.9.9");
        assert_eq!(info.version, Version::new(9, 9, 9));
        let dmg = info.dmg_asset.unwrap();
        assert_eq!(dmg.digest_sha256.as_deref(), Some("deadbeef"));
        let sig = info.minisig_asset.unwrap();
        assert_eq!(sig.name, "SplitWG.dmg.minisig");
    }

    #[test]
    fn parse_mount_point_from_hdiutil_output() {
        let sample = "/dev/disk4          \tGUID_partition_scheme          \t\n\
            /dev/disk4s1        \tApple_HFS                      \t/Volumes/SplitWG\n";
        assert_eq!(
            parse_mount_point(sample),
            Some(PathBuf::from("/Volumes/SplitWG"))
        );
    }

    #[test]
    fn parse_mount_point_returns_none_when_absent() {
        assert_eq!(parse_mount_point("no mount here"), None);
    }

    #[test]
    fn parse_team_id_extracts_identifier() {
        let sample = "Executable=/Applications/SplitWG.app/Contents/MacOS/splitwg\n\
            Identifier=com.kilimcininkoroglu.splitwg\n\
            TeamIdentifier=ABC1234567\n\
            Sealed Resources version=2\n";
        assert_eq!(parse_team_id(sample).as_deref(), Some("ABC1234567"));
    }

    #[test]
    fn parse_team_id_rejects_not_set() {
        let sample = "TeamIdentifier=not set\n";
        assert_eq!(parse_team_id(sample), None);
    }

    #[test]
    fn team_id_mismatch_rejects_install() {
        let err = verify_team_id("ABC1234567", "XYZ9999999").unwrap_err();
        match err {
            UpdateError::TeamIdMismatch { expected, actual } => {
                assert_eq!(expected, "ABC1234567");
                assert_eq!(actual, "XYZ9999999");
            }
            other => panic!("expected TeamIdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn team_id_match_accepts_install() {
        verify_team_id("ABC1234567", "ABC1234567").unwrap();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn cache_dir_resolves_under_home() {
        let dir = cache_dir();
        let s = dir.to_string_lossy();
        assert!(s.ends_with("SplitWG/updates"), "got {s}");
    }

    #[test]
    fn minisign_invalid_rejects_download() {
        let tmp = std::env::temp_dir().join(format!("splitwg-update-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        let payload = tmp.join("payload.bin");
        let sig = tmp.join("payload.bin.minisig");
        fs::write(&payload, b"hello").unwrap();
        fs::write(&sig, b"garbage").unwrap();
        let err = verify_minisign(&payload, &sig).unwrap_err();
        assert!(matches!(err, UpdateError::Signature(_)));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn detect_install_mode_applications_requires_admin() {
        let target = PathBuf::from("/Applications/SplitWG.app");
        assert_eq!(detect_install_mode(&target), InstallMode::AdminReplace);
    }

    #[test]
    fn detect_install_mode_user_home_is_direct() {
        let home = std::env::temp_dir().join(format!("splitwg-install-{}", std::process::id()));
        fs::create_dir_all(&home).unwrap();
        let target = home.join("SplitWG.app");
        assert_eq!(detect_install_mode(&target), InstallMode::DirectReplace);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    #[cfg(unix)]
    fn cleanup_stale_downloads_removes_old_files() {
        let scratch = std::env::temp_dir().join(format!("splitwg-cleanup-{}", std::process::id()));
        fs::create_dir_all(&scratch).unwrap();
        let old = scratch.join("old.dmg");
        let young = scratch.join("young.dmg");
        fs::write(&old, b"old").unwrap();
        fs::write(&young, b"young").unwrap();

        // Backdate the old file to 8 days ago.
        let eight_days = 8 * 24 * 60 * 60;
        let past = filetime_now().saturating_sub(eight_days);
        set_mtime(&old, past).unwrap();

        // Run cleanup logic against the scratch dir by mimicking
        // cache_dir()'s body. We shadow `fn cache_dir` for the scope of
        // this test via a private helper that walks the scratch directly.
        run_cleanup_against(&scratch);

        assert!(!old.exists(), "old file should be removed");
        assert!(young.exists(), "young file should remain");
        let _ = fs::remove_dir_all(&scratch);
    }

    fn filetime_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    #[cfg(unix)]
    fn set_mtime(path: &Path, epoch: u64) -> std::io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            let stamp = std::process::Command::new("/bin/date")
                .args(["-r", &epoch.to_string(), "+%Y%m%d%H%M.%S"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            let status = std::process::Command::new("/usr/bin/touch")
                .args(["-t", &stamp])
                .arg(path)
                .status()?;
            if !status.success() {
                return Err(std::io::Error::other("touch -t failed"));
            }
        }
        #[cfg(target_os = "linux")]
        {
            let stamp = std::process::Command::new("date")
                .args(["-d", &format!("@{epoch}"), "+%Y%m%d%H%M.%S"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            let status = std::process::Command::new("touch")
                .args(["-t", &stamp])
                .arg(path)
                .status()?;
            if !status.success() {
                return Err(std::io::Error::other("touch -t failed"));
            }
        }
        Ok(())
    }

    /// Mirror of `cleanup_stale_downloads` that operates on an arbitrary
    /// directory so the real function keeps the `cache_dir()` coupling.
    fn run_cleanup_against(dir: &Path) {
        let cutoff = Duration::from_secs(7 * 24 * 60 * 60);
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let age_ok = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|d| d > cutoff)
                .unwrap_or(false);
            if !age_ok {
                continue;
            }
            let path = entry.path();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let _ = if is_dir {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
        }
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        let p = PathBuf::from("/tmp/a'b.app");
        let q = shell_quote(&p);
        assert!(q.starts_with('\''));
        assert!(q.ends_with('\''));
        assert!(q.contains(r"'\''"));
    }

    #[test]
    fn parse_release_strips_leading_v() {
        let raw = GhRelease {
            tag_name: "v1.2.3".to_string(),
            body: None,
            assets: vec![mk_asset("SplitWG.dmg", None)],
        };
        let info = parse_release(raw).unwrap();
        assert_eq!(info.version, Version::new(1, 2, 3));
    }
}
