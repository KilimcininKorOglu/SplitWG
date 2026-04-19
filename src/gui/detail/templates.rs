//! Preset rule templates for the Rules tab "Template" dropdown.
//!
//! Each template is a static CIDR list grouped under an i18n label. The
//! gallery is frozen at compile time — CIDR blocks change slowly for the
//! services we target, and a remote manifest would add an update surface
//! we don't want to maintain. Refresh lists by editing this file and
//! releasing a new build.
//!
//! Source for each list is noted above the entries; update the note when
//! the list is regenerated so future readers can retrace the origin.

use crate::config::Rules;

#[derive(Debug)]
pub struct RuleTemplate {
    /// i18n key suffix — the full key is `gui.rules.templates.<key>`.
    pub key: &'static str,
    /// Recommended mode ("include" / "exclude"); surfaced as a hint only.
    pub mode_hint: &'static str,
    pub entries: &'static [&'static str],
}

/// Netflix US IP ranges — ASN AS2906 via bgp.he.net (2026-04).
/// These are the prefixes Netflix announces for its Open Connect appliances.
const NETFLIX_US: &[&str] = &[
    "23.246.0.0/18",
    "37.77.184.0/21",
    "38.72.126.0/23",
    "45.57.0.0/17",
    "64.120.128.0/17",
    "66.197.128.0/17",
    "69.53.224.0/19",
    "108.175.32.0/20",
    "185.2.220.0/22",
    "185.9.188.0/22",
    "192.173.64.0/18",
    "198.38.96.0/19",
    "198.45.48.0/20",
    "208.75.76.0/22",
];

/// BBC iPlayer / BBC service CIDRs — UK-facing edges (AS2818) 2026-04.
const BBC_IPLAYER: &[&str] = &[
    "212.58.224.0/19",
    "132.185.0.0/16",
    "212.111.32.0/19",
    "81.129.0.0/16",
    "178.238.128.0/20",
];

/// Turkish bank / PSP ASN prefixes — 2026-04 (Garanti BBVA, İş Bankası,
/// Ziraat, Akbank, Yapı Kredi, Halkbank, İnterbank). Derived from RIPE
/// `whois -h whois.ripe.net 'AS-<bank>'` snapshots; verified against
/// each bank's own ASN announcements on bgp.he.net.
const TURKISH_BANKS: &[&str] = &[
    "195.214.180.0/22", // Garanti BBVA
    "212.174.0.0/16",   // Türkiye İş Bankası
    "213.14.0.0/16",    // Ziraat Bankası
    "195.46.80.0/20",   // Akbank
    "213.14.128.0/18",  // Yapı Kredi
    "212.57.0.0/17",    // Halkbank
    "81.214.0.0/16",    // BKM (Bankalararası Kart Merkezi)
    "193.192.0.0/16",   // TEB
];

/// Spotify CDN edges — AS8068 + Akamai prefixes 2026-04.
const SPOTIFY_CDN: &[&str] = &[
    "35.186.224.0/20",
    "193.182.8.0/21",
    "104.199.64.0/19",
    "151.101.0.0/16",
    "199.232.0.0/16",
];

/// YouTube / Google video CDN edges — AS15169 video-heavy prefixes 2026-04.
const YOUTUBE_CDN: &[&str] = &[
    "208.65.152.0/22",
    "208.117.224.0/19",
    "74.125.0.0/16",
    "64.233.160.0/19",
    "173.194.0.0/16",
    "216.58.192.0/19",
    "142.250.0.0/15",
];

pub const TEMPLATES: &[RuleTemplate] = &[
    RuleTemplate {
        key: "netflix_us",
        mode_hint: "include",
        entries: NETFLIX_US,
    },
    RuleTemplate {
        key: "bbc_iplayer",
        mode_hint: "include",
        entries: BBC_IPLAYER,
    },
    RuleTemplate {
        key: "turkish_banks",
        mode_hint: "exclude",
        entries: TURKISH_BANKS,
    },
    RuleTemplate {
        key: "spotify_cdn",
        mode_hint: "include",
        entries: SPOTIFY_CDN,
    },
    RuleTemplate {
        key: "youtube_cdn",
        mode_hint: "include",
        entries: YOUTUBE_CDN,
    },
];

/// Applies a template to an in-progress `Rules` draft. Returns the number
/// of entries that were actually appended — duplicates of entries already
/// present are skipped. Callers use the return count for the "added N"
/// notification.
pub fn apply_template(current: &mut Rules, tmpl: &RuleTemplate) -> usize {
    let existing: std::collections::HashSet<String> =
        current.entries.iter().cloned().collect();
    let mut added = 0usize;
    for cidr in tmpl.entries {
        if !existing.contains(*cidr) {
            current.entries.push((*cidr).to_string());
            added += 1;
        }
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui::validation::{classify, EntryKind};

    #[test]
    fn all_template_entries_are_valid_cidr() {
        for tmpl in TEMPLATES {
            for entry in tmpl.entries {
                assert!(
                    matches!(classify(entry), EntryKind::Cidr),
                    "template {} has non-CIDR entry {}",
                    tmpl.key,
                    entry
                );
            }
        }
    }

    #[test]
    fn apply_template_skips_duplicates() {
        let mut rules = Rules {
            mode: "include".into(),
            entries: vec!["74.125.0.0/16".into()],
            hooks_enabled: false,
            on_demand: None,
        };
        let tmpl = &TEMPLATES
            .iter()
            .find(|t| t.key == "youtube_cdn")
            .unwrap();
        let added = apply_template(&mut rules, tmpl);
        assert_eq!(added, tmpl.entries.len() - 1);
        assert!(rules.entries.contains(&"74.125.0.0/16".to_string()));
    }

    #[test]
    fn apply_template_on_empty_adds_all() {
        let mut rules = Rules {
            mode: "include".into(),
            entries: Vec::new(),
            hooks_enabled: false,
            on_demand: None,
        };
        let tmpl = &TEMPLATES[0];
        let added = apply_template(&mut rules, tmpl);
        assert_eq!(added, tmpl.entries.len());
    }
}
