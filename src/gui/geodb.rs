//! GeoLite2 MMDB auto-updater — pulls `SHA256SUMS` plus any changed mmdb
//! files from the `geodb` branch on raw.githubusercontent.com and lands
//! them atomically in `~/.config/splitwg/`.
//!
//! The workflow defined in `.github/workflows/GeoLite.yml` publishes
//! `GeoLite2-ASN.mmdb`, `GeoLite2-City.mmdb`, and `GeoLite2-Country.mmdb`
//! under `Geolite-DB/` on the `geodb` branch alongside a `SHA256SUMS`
//! sidecar. The app checks that sidecar daily (when opted in) and only
//! re-downloads the editions whose hashes have changed.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config;

/// Raw GitHub URL of the published `Geolite-DB/` directory on the `geodb`
/// branch. Hardcoded because the app only ever consumes its own canonical
/// artefact stream.
pub const BASE_URL: &str =
    "https://raw.githubusercontent.com/KilimcininKorOglu/SplitWG/geodb/Geolite-DB";

/// The three MMDB editions we mirror. City and ASN are downloaded for
/// future features (reader cache currently only covers Country).
pub const EDITIONS: &[&str] = &[
    "GeoLite2-Country.mmdb",
    "GeoLite2-City.mmdb",
    "GeoLite2-ASN.mmdb",
];

/// Seconds between automatic background pulls. Manual "Update now" clicks
/// bypass this cooldown entirely.
pub const COOLDOWN_SECS: u64 = 24 * 60 * 60;

/// Errors the updater pipeline can emit.
#[derive(Debug, Error)]
pub enum GeoDbError {
    #[error("http: {0}")]
    Http(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("digest mismatch for {0}")]
    Digest(String),
    #[error("malformed SHA256SUMS")]
    MalformedSums,
    #[error("missing edition {0} in SHA256SUMS")]
    MissingEntry(String),
}

/// Outcome of a pull. `updated` lists the mmdb filenames that were
/// rewritten on disk; empty when everything was already up to date.
#[derive(Debug, Clone, Default)]
pub struct PullOutcome {
    pub updated: Vec<String>,
    pub total_bytes: u64,
}

/// Target directory for downloaded mmdb files. Matches the first entry in
/// `wg::rules::geo::search_paths()` so freshly-pulled DBs are picked up
/// by the Country reader.
pub fn target_dir() -> PathBuf {
    config::config_dir()
}

/// Epoch-seconds "now". Separated so tests can reason about cooldowns
/// without mocking the system clock.
pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `true` when the 24-hour cooldown has elapsed since the last pull.
pub fn cooldown_elapsed(last: Option<u64>) -> bool {
    match last {
        None => true,
        Some(ts) => now_epoch().saturating_sub(ts) >= COOLDOWN_SECS,
    }
}

/// Parses `<hex>  <filename>` lines from a `shasum -a 256` output.
/// Returns a map keyed by filename. Any non-empty line without exactly
/// two whitespace-separated fields triggers `MalformedSums`.
pub fn parse_sha256sums(body: &str) -> Result<HashMap<String, String>, GeoDbError> {
    let mut out = HashMap::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let hash = parts.next().ok_or(GeoDbError::MalformedSums)?;
        let name = parts.next().ok_or(GeoDbError::MalformedSums)?;
        if parts.next().is_some() {
            return Err(GeoDbError::MalformedSums);
        }
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(GeoDbError::MalformedSums);
        }
        out.insert(name.to_string(), hash.to_ascii_lowercase());
    }
    Ok(out)
}

/// `true` when the on-disk file is absent or its sha256 differs from
/// `expected_hex`. IO failures are treated as "needs update" so a
/// transient read error does not silently skip the download.
pub fn needs_update(path: &Path, expected_hex: &str) -> bool {
    if !path.exists() {
        return true;
    }
    match sha256_hex_of_file(path) {
        Ok(Some(actual)) => !actual.eq_ignore_ascii_case(expected_hex),
        _ => true,
    }
}

/// Streams the file through a SHA-256 hasher and returns the hex digest.
/// Returns `Ok(None)` for a missing file (the caller's check beats a
/// race, but keep the branch so `needs_update` never panics).
fn sha256_hex_of_file(path: &Path) -> std::io::Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(Some(hex::encode(hasher.finalize())))
}

/// Downloads `SHA256SUMS`, computes local hashes, downloads only the
/// differing editions, verifies each, and atomically renames into place.
/// Invalidates the Country reader cache on success so a running tunnel
/// picks up the fresh DB on the next `country:XX` expansion.
pub fn pull_once() -> Result<PullOutcome, GeoDbError> {
    log::info!("splitwg: geodb: starting pull");
    config::ensure_config_dir()?;
    let dir = target_dir();

    let sums_url = format!("{}/SHA256SUMS", BASE_URL);
    log::info!("splitwg: geodb: fetching SHA256SUMS from {}", sums_url);
    let sums_body = http_get_string(&sums_url)?;
    let sums = parse_sha256sums(&sums_body)?;

    let mut outcome = PullOutcome::default();

    for edition in EDITIONS {
        let expected = sums
            .get(*edition)
            .ok_or_else(|| GeoDbError::MissingEntry((*edition).to_string()))?;
        let dst = dir.join(edition);
        if !needs_update(&dst, expected) {
            continue;
        }

        log::info!("splitwg: geodb: downloading {}", edition);
        let tmp = dst.with_extension("mmdb.tmp");
        let url = format!("{}/{}", BASE_URL, edition);
        let (bytes_written, digest) = download_to_file_with_digest(&url, &tmp)?;
        if !digest.eq_ignore_ascii_case(expected) {
            log::error!("splitwg: geodb: digest mismatch for {}", edition);
            let _ = fs::remove_file(&tmp);
            return Err(GeoDbError::Digest((*edition).to_string()));
        }
        log::info!(
            "splitwg: geodb: verified and wrote {} ({} bytes)",
            edition,
            bytes_written
        );
        fs::rename(&tmp, &dst)?;
        outcome.updated.push((*edition).to_string());
        outcome.total_bytes = outcome.total_bytes.saturating_add(bytes_written);
    }

    if !outcome.updated.is_empty() {
        log::info!("splitwg: geodb: updated editions: {:?}", outcome.updated);
        crate::wg::rules::geo::invalidate();
    } else {
        log::info!("splitwg: geodb: all editions up to date");
    }
    Ok(outcome)
}

/// Fetches a small text payload (≤1 MiB) — used for `SHA256SUMS`.
fn http_get_string(url: &str) -> Result<String, GeoDbError> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .new_agent();
    let response = agent
        .get(url)
        .header("User-Agent", &user_agent())
        .call()
        .map_err(|e| GeoDbError::Http(e.to_string()))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(GeoDbError::Http(format!("HTTP {}", status)));
    }
    response
        .into_body()
        .read_to_string()
        .map_err(|e| GeoDbError::Http(e.to_string()))
}

/// Streams `url` into `dest`, returning `(bytes_written, sha256_hex)`.
/// No progress reporting — the files are tiny by GitHub-raw standards
/// (≤70 MiB) and the UI only renders a single spinner.
fn download_to_file_with_digest(url: &str, dest: &Path) -> Result<(u64, String), GeoDbError> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .build()
        .new_agent();
    let response = agent
        .get(url)
        .header("User-Agent", &user_agent())
        .call()
        .map_err(|e| GeoDbError::Http(e.to_string()))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(GeoDbError::Http(format!("HTTP {}", status)));
    }
    let mut reader = response.into_body().into_reader();
    let mut file = fs::File::create(dest)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader.read(&mut buf).map_err(GeoDbError::Io)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    file.flush()?;
    Ok((total, hex::encode(hasher.finalize())))
}

fn user_agent() -> String {
    format!("SplitWG-GeoDB/{}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sha256sums_extracts_entries() {
        let body = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  GeoLite2-Country.mmdb
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  GeoLite2-City.mmdb
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  GeoLite2-ASN.mmdb
";
        let map = parse_sha256sums(body).unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.get("GeoLite2-Country.mmdb").map(String::as_str),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        );
    }

    #[test]
    fn parse_sha256sums_rejects_malformed() {
        let body = "not-a-hash  GeoLite2-Country.mmdb\n";
        assert!(matches!(
            parse_sha256sums(body),
            Err(GeoDbError::MalformedSums)
        ));
    }

    #[test]
    fn parse_sha256sums_ignores_blank_lines() {
        let body = "\n\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  GeoLite2-Country.mmdb\n\n";
        let map = parse_sha256sums(body).unwrap();
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn needs_update_true_when_file_missing() {
        let path =
            std::env::temp_dir().join(format!("splitwg-geodb-missing-{}.mmdb", std::process::id()));
        assert!(needs_update(&path, "deadbeef"));
    }

    #[test]
    fn needs_update_false_when_hash_matches() {
        let dir = std::env::temp_dir().join(format!("splitwg-geodb-match-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.mmdb");
        fs::write(&path, b"hello world").unwrap();
        // sha256("hello world")
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(!needs_update(&path, expected));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn needs_update_true_when_hash_differs() {
        let dir = std::env::temp_dir().join(format!("splitwg-geodb-diff-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.mmdb");
        fs::write(&path, b"hello world").unwrap();
        assert!(needs_update(&path, "0".repeat(64).as_str()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cooldown_elapses_after_24h() {
        assert!(cooldown_elapsed(None));
        let now = now_epoch();
        assert!(!cooldown_elapsed(Some(now)));
        assert!(cooldown_elapsed(Some(
            now.saturating_sub(COOLDOWN_SECS + 1)
        )));
    }
}
