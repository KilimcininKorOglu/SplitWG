//! MaxMind GeoLite2 expansion for `country:XX` and `asn:NNNNN` rule entries.
//!
//! The user supplies the mmdb files themselves — we do NOT bundle the
//! databases (licensing + redistribute issues, and MaxMind now requires a
//! free account to download). Lookup locations searched, in order:
//!
//! 1. `$HOME/.config/splitwg/GeoLite2-{Country,ASN}.mmdb`
//! 2. `<app bundle>/Contents/Resources/GeoLite2-{Country,ASN}.mmdb`
//!
//! If a mmdb is missing, `expand_country`/`expand_asn` returns an empty vec
//! and logs a warning; the rule is effectively skipped at bringup time.

use std::path::PathBuf;
use std::sync::Mutex;

use once_cell::sync::Lazy;

/// Cached mmdb reader. `Lazy` defers the first load until someone actually
/// uses a `country:XX` rule; `Mutex<Option<...>>` lets us try again (after
/// the user places the file) without restarting the app.
static READER: Lazy<Mutex<Option<maxminddb::Reader<Vec<u8>>>>> =
    Lazy::new(|| Mutex::new(None));

static ASN_READER: Lazy<Mutex<Option<maxminddb::Reader<Vec<u8>>>>> =
    Lazy::new(|| Mutex::new(None));

/// Returns the full filesystem path search order for `GeoLite2-Country.mmdb`.
/// Exposed for the Rules tab so it can show an informative message when
/// nothing is found.
pub fn search_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        out.push(
            PathBuf::from(home)
                .join(".config")
                .join("splitwg")
                .join("GeoLite2-Country.mmdb"),
        );
    }
    if let Ok(exe) = std::env::current_exe() {
        // exe: …/SplitWG.app/Contents/MacOS/splitwg → …/Contents/Resources/
        if let Some(macos_dir) = exe.parent() {
            if let Some(contents_dir) = macos_dir.parent() {
                out.push(
                    contents_dir
                        .join("Resources")
                        .join("GeoLite2-Country.mmdb"),
                );
            }
        }
    }
    out
}

/// Reports whether the mmdb is installed in one of the known locations.
/// Used by the Rules tab to gate the "DB missing" warning.
pub fn mmdb_available() -> bool {
    search_paths().iter().any(|p| p.exists())
}

/// Drops the cached Country reader so the next `expand_country` call
/// re-reads the mmdb from disk. Called by the geodb updater after a
/// successful refresh. No-op when the cache is empty.
pub fn invalidate() {
    if let Ok(mut g) = READER.lock() {
        *g = None;
    }
    if let Ok(mut g) = ASN_READER.lock() {
        *g = None;
    }
}

pub fn asn_search_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        out.push(
            PathBuf::from(home)
                .join(".config")
                .join("splitwg")
                .join("GeoLite2-ASN.mmdb"),
        );
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(macos_dir) = exe.parent() {
            if let Some(contents_dir) = macos_dir.parent() {
                out.push(
                    contents_dir
                        .join("Resources")
                        .join("GeoLite2-ASN.mmdb"),
                );
            }
        }
    }
    out
}

pub fn asn_mmdb_available() -> bool {
    asn_search_paths().iter().any(|p| p.exists())
}

fn load_asn_reader() -> Option<maxminddb::Reader<Vec<u8>>> {
    for path in asn_search_paths() {
        if !path.exists() {
            continue;
        }
        match maxminddb::Reader::open_readfile(&path) {
            Ok(r) => {
                log::info!("splitwg: geo: loaded ASN mmdb {:?}", path);
                return Some(r);
            }
            Err(e) => {
                log::warn!("splitwg: geo: failed to open ASN {:?}: {}", path, e);
            }
        }
    }
    None
}

fn load_reader() -> Option<maxminddb::Reader<Vec<u8>>> {
    for path in search_paths() {
        if !path.exists() {
            continue;
        }
        match maxminddb::Reader::open_readfile(&path) {
            Ok(r) => {
                log::info!("splitwg: geo: loaded mmdb {:?}", path);
                return Some(r);
            }
            Err(e) => {
                log::warn!("splitwg: geo: failed to open {:?}: {}", path, e);
            }
        }
    }
    None
}

/// Walks the GeoLite2-Country mmdb and returns every CIDR whose country
/// ISO code matches `code` (ASCII uppercase). Returns an empty vec if the
/// mmdb is missing or no matches are found. Traversal is O(table size);
/// called once per tunnel bringup so the ~100 ms cost is acceptable.
pub fn expand_country(code: &str) -> Vec<String> {
    // First-use lazy load of the reader. Subsequent calls reuse the same
    // reader; if it failed to load we return empty every time until the
    // user drops the mmdb in place and restarts.
    let mut guard = match READER.lock() {
        Ok(g) => g,
        Err(e) => {
            log::warn!("splitwg: geo: reader mutex poisoned: {e}");
            return Vec::new();
        }
    };
    if guard.is_none() {
        *guard = load_reader();
    }
    let Some(reader) = guard.as_ref() else {
        return Vec::new();
    };

    let wanted = code.to_ascii_uppercase();
    let mut out = Vec::new();

    for net in [
        "0.0.0.0/0".parse::<ipnetwork::IpNetwork>().unwrap(),
        "::/0".parse::<ipnetwork::IpNetwork>().unwrap(),
    ] {
        let iter = match reader.within(net, Default::default()) {
            Ok(it) => it,
            Err(e) => {
                log::warn!("splitwg: geo: within failed for {net}: {e}");
                continue;
            }
        };
        for item in iter.flatten() {
            let country = match item.decode::<maxminddb::geoip2::Country>() {
                Ok(Some(c)) => c,
                _ => continue,
            };
            let matches_country = country
                .country
                .iso_code
                .map(|iso: &str| iso.eq_ignore_ascii_case(&wanted))
                .unwrap_or(false);
            if matches_country {
                if let Ok(net) = item.network() {
                    out.push(net.to_string());
                }
            }
        }
    }
    log::info!(
        "splitwg: geo: country:{} → {} CIDRs",
        wanted,
        out.len()
    );
    out
}

pub fn expand_asn(target_asn: u32) -> Vec<String> {
    let mut guard = match ASN_READER.lock() {
        Ok(g) => g,
        Err(e) => {
            log::warn!("splitwg: geo: ASN reader mutex poisoned: {e}");
            return Vec::new();
        }
    };
    if guard.is_none() {
        *guard = load_asn_reader();
    }
    let Some(reader) = guard.as_ref() else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for net in [
        "0.0.0.0/0".parse::<ipnetwork::IpNetwork>().unwrap(),
        "::/0".parse::<ipnetwork::IpNetwork>().unwrap(),
    ] {
        let iter = match reader.within(net, Default::default()) {
            Ok(it) => it,
            Err(e) => {
                log::warn!("splitwg: geo: ASN within failed for {net}: {e}");
                continue;
            }
        };
        for item in iter.flatten() {
            let asn = match item.decode::<maxminddb::geoip2::Asn>() {
                Ok(Some(a)) => a,
                _ => continue,
            };
            if asn.autonomous_system_number == Some(target_asn) {
                if let Ok(net) = item.network() {
                    out.push(net.to_string());
                }
            }
        }
    }
    log::info!("splitwg: geo: asn:{target_asn} → {} CIDRs", out.len());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_paths_includes_home_config() {
        let paths = search_paths();
        assert!(
            paths.iter().any(|p| {
                p.to_string_lossy()
                    .ends_with(".config/splitwg/GeoLite2-Country.mmdb")
            }),
            "search_paths should include …/.config/splitwg/GeoLite2-Country.mmdb, got: {paths:?}"
        );
    }

    #[test]
    fn expand_country_invalid_code_returns_empty() {
        if let Ok(mut g) = READER.lock() {
            *g = None;
        }
        let out = expand_country("ZZ");
        assert!(out.is_empty());
    }

    #[test]
    fn asn_search_paths_includes_home_config() {
        let paths = asn_search_paths();
        assert!(
            paths.iter().any(|p| {
                p.to_string_lossy()
                    .ends_with(".config/splitwg/GeoLite2-ASN.mmdb")
            }),
            "asn_search_paths should include …/.config/splitwg/GeoLite2-ASN.mmdb, got: {paths:?}"
        );
    }

    #[test]
    fn expand_asn_nonexistent_returns_empty() {
        if let Ok(mut g) = ASN_READER.lock() {
            *g = None;
        }
        let out = expand_asn(999_999_999);
        assert!(out.is_empty());
    }
}
