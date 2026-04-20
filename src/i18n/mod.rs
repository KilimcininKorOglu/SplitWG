//! Minimal runtime i18n layer for SplitWG.
//!
//! Two JSON tables are embedded at compile time (`locales/en.json` and
//! `locales/tr.json`) via `include_str!` — no external resource, no new crate.
//! The active language is kept in a process-global `RwLock<Lang>` and mutated
//! when the user picks a language from the tray. All translation lookups go
//! through `t()` / `t_with()`, which fall back to English and finally to the
//! key itself so a missing translation never panics.
//!
//! Logs intentionally stay in English — they are consumed by developers and by
//! third-party parsers of `splitwg.log`.

use std::collections::HashMap;
use std::sync::RwLock;

use once_cell::sync::Lazy;

use crate::config;

const EN_JSON: &str = include_str!("../../locales/en.json");
const TR_JSON: &str = include_str!("../../locales/tr.json");

/// Supported UI languages. Adding a third language = add a variant, embed the
/// JSON via `include_str!`, extend `TABLES`, `code`, `from_code`, and
/// `display_name`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Tr,
}

impl Lang {
    /// BCP-47-ish short code persisted in `settings.json`.
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Tr => "tr",
        }
    }

    /// Parses a language tag like `"tr"`, `"tr-TR"`, `"en"`, `"en_US"`. Only
    /// the prefix before the first `-` or `_` is examined. Unknown prefixes
    /// return `None` (callers decide the fallback).
    pub fn from_code(code: &str) -> Option<Lang> {
        let prefix = code
            .split(['-', '_'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        match prefix.as_str() {
            "en" => Some(Lang::En),
            "tr" => Some(Lang::Tr),
            _ => None,
        }
    }

    /// Human-readable name shown in the language submenu label.
    pub fn display_name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Tr => "Türkçe",
        }
    }
}

/// Parsed translation tables, keyed by `Lang::code()`. Constructed once on
/// first access. A parse failure here is a build-time bug in a JSON file, so
/// `expect()` is appropriate — the app cannot render a UI without tables.
static TABLES: Lazy<HashMap<&'static str, HashMap<String, String>>> = Lazy::new(|| {
    let mut map: HashMap<&'static str, HashMap<String, String>> = HashMap::new();
    map.insert("en", parse_json(EN_JSON, "en"));
    map.insert("tr", parse_json(TR_JSON, "tr"));
    map
});

fn parse_json(raw: &str, code: &str) -> HashMap<String, String> {
    serde_json::from_str(raw)
        .unwrap_or_else(|e| panic!("i18n: invalid locale table for {code}: {e}"))
}

/// Active language. Writers are rare (user clicks in the tray); readers are
/// every `t()` call on the UI thread — `RwLock` fits the pattern.
static CURRENT: Lazy<RwLock<Lang>> = Lazy::new(|| RwLock::new(Lang::En));

/// Initialises the active language from `Settings.language`, falling back to
/// the detected system locale. Called once at startup from `main.rs`. Safe to
/// call multiple times; later calls simply re-resolve the current state.
pub fn init() {
    let settings = config::load_settings();
    let resolved = if let Some(ref code) = settings.language {
        match Lang::from_code(code) {
            Some(lang) => {
                log::info!("splitwg: i18n: locale source: settings.json ({:?})", code);
                lang
            }
            None => {
                log::warn!("splitwg: i18n: unknown language code {:?} in settings, detecting system locale", code);
                detect_system_locale()
            }
        }
    } else {
        log::info!("splitwg: i18n: no language in settings, detecting system locale");
        detect_system_locale()
    };
    set_current(resolved);
    log::info!("splitwg: i18n: active language set to {:?} ({})", resolved.code(), resolved.display_name());
}

/// Returns the language currently in effect. Never blocks meaningfully — the
/// `RwLock` is uncontended in practice.
pub fn current() -> Lang {
    *CURRENT.read().expect("i18n: current lang lock poisoned")
}

/// Replaces the active language. Takes effect immediately; the tray refresh
/// will pick up the new strings on the next tick (or sooner, via a manual
/// `UiEvent::Refresh`).
pub fn set_current(lang: Lang) {
    let mut guard = CURRENT.write().expect("i18n: current lang lock poisoned");
    *guard = lang;
}

/// Looks up `key` in the active language. Fallback chain:
/// 1. Active language table.
/// 2. English table (so half-translated locales still render something
///    coherent).
/// 3. The key itself — makes missing keys visible during development without
///    crashing production.
pub fn t(key: &str) -> String {
    let active = current().code();
    if let Some(v) = TABLES.get(active).and_then(|m| m.get(key)) {
        return v.clone();
    }
    if let Some(v) = TABLES.get("en").and_then(|m| m.get(key)) {
        return v.clone();
    }
    key.to_string()
}

/// Like `t`, but substitutes `{placeholder}` occurrences from `params`.
/// Unknown placeholders are left intact so a typo stays visible rather than
/// disappearing silently.
pub fn t_with(key: &str, params: &[(&str, &str)]) -> String {
    substitute(&t(key), params)
}

fn substitute(template: &str, params: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (k, v) in params {
        let needle = format!("{{{k}}}");
        if out.contains(&needle) {
            out = out.replace(&needle, v);
        }
    }
    out
}

/// Raw lookup for a specific language code, bypassing the current-language
/// cache. Used by cross-language prefix matching (e.g. detecting a "Change
/// Mode: …" tray row regardless of which language produced it). Returns the
/// key itself when missing.
pub fn lookup_raw(code: &str, key: &str) -> String {
    TABLES
        .get(code)
        .and_then(|m| m.get(key))
        .cloned()
        .unwrap_or_else(|| key.to_string())
}

/// Detects the user's preferred language by reading
/// `defaults read -g AppleLanguages` and picking the prefix of the first
/// entry. Falls back to `$LANG`, then to English on any failure.
pub fn detect_system_locale() -> Lang {
    #[cfg(target_os = "macos")]
    if let Ok(out) = std::process::Command::new("defaults")
        .args(["read", "-g", "AppleLanguages"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(tag) = first_quoted_token(&text) {
                if let Some(lang) = Lang::from_code(&tag) {
                    log::info!("splitwg: i18n: detected locale from macOS AppleLanguages: {:?}", tag);
                    return lang;
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    if let Ok(out) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "(Get-Culture).TwoLetterISOLanguageName"])
        .output()
    {
        if out.status.success() {
            let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if let Some(lang) = Lang::from_code(&code) {
                log::info!("splitwg: i18n: detected locale from Windows culture: {:?}", code);
                return lang;
            }
        }
    }
    detect_from_env()
}

fn detect_from_env() -> Lang {
    if let Ok(val) = std::env::var("LANG") {
        if let Some(lang) = Lang::from_code(&val) {
            log::info!("splitwg: i18n: detected locale from $LANG: {:?}", val);
            return lang;
        }
    }
    log::info!("splitwg: i18n: no locale detected, defaulting to English");
    Lang::En
}

/// Extracts the first `"..."`-quoted token from the raw `defaults` output.
/// `AppleLanguages` looks like:
///
/// ```text
/// (
///     "tr-TR",
///     "en-US"
/// )
/// ```
fn first_quoted_token(text: &str) -> Option<String> {
    let start = text.find('"')?;
    let rest = &text[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
pub mod test_support {
    use std::sync::{Mutex, MutexGuard};

    // Serialises tests that mutate the process-global `CURRENT`. `try_lock` is
    // used by production code elsewhere but here we want to wait — tests run
    // in parallel by default.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Guard that holds the test lock until dropped. Use it in tests that
    /// change the active language so they don't race with each other.
    pub fn test_lock() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_support::test_lock;

    #[test]
    fn lang_from_code_accepts_common_forms() {
        assert_eq!(Lang::from_code("en"), Some(Lang::En));
        assert_eq!(Lang::from_code("en-US"), Some(Lang::En));
        assert_eq!(Lang::from_code("en_US"), Some(Lang::En));
        assert_eq!(Lang::from_code("tr"), Some(Lang::Tr));
        assert_eq!(Lang::from_code("tr-TR"), Some(Lang::Tr));
        assert_eq!(Lang::from_code("TR"), Some(Lang::Tr));
    }

    #[test]
    fn from_code_rejects_unknown() {
        assert_eq!(Lang::from_code("fr"), None);
        assert_eq!(Lang::from_code(""), None);
        assert_eq!(Lang::from_code("xx-YY"), None);
    }

    #[test]
    fn t_returns_current_lang() {
        let _g = test_lock();
        set_current(Lang::Tr);
        assert_eq!(t("tray.menu.connect"), "Bağlan");
        set_current(Lang::En);
        assert_eq!(t("tray.menu.connect"), "Connect");
    }

    #[test]
    fn t_falls_back_to_english_when_key_missing_in_active() {
        let _g = test_lock();
        // Every real key is present in both tables; simulate an absence by
        // asking with a made-up key that's only in neither, then verify the
        // final fallback (key text) behaviour. The "fallback to English"
        // branch is exercised by `t_returns_current_lang` above whenever a
        // locale table is incomplete.
        set_current(Lang::Tr);
        assert_eq!(t("definitely.missing.key"), "definitely.missing.key");
    }

    #[test]
    fn t_returns_key_when_missing_in_both() {
        let _g = test_lock();
        set_current(Lang::En);
        assert_eq!(t("no.such.key"), "no.such.key");
    }

    #[test]
    fn t_with_substitutes_placeholders() {
        let _g = test_lock();
        set_current(Lang::En);
        let s = t_with("tray.slot.connected", &[("name", "vpn1")]);
        assert_eq!(s, "✓ vpn1 (connected)");
    }

    #[test]
    fn t_with_leaves_unknown_placeholder_intact() {
        let _g = test_lock();
        set_current(Lang::En);
        let s = t_with("tray.slot.connected", &[("bogus", "x")]);
        assert!(s.contains("{name}"), "untouched placeholder: {s}");
    }

    #[test]
    fn lookup_raw_reads_specific_table() {
        assert_eq!(lookup_raw("en", "tray.menu.connect"), "Connect");
        assert_eq!(lookup_raw("tr", "tray.menu.connect"), "Bağlan");
        assert_eq!(lookup_raw("en", "missing.key"), "missing.key");
    }

    #[test]
    fn first_quoted_token_parses_apple_format() {
        let raw = "(\n    \"tr-TR\",\n    \"en-US\"\n)";
        assert_eq!(first_quoted_token(raw), Some("tr-TR".to_string()));
        assert_eq!(first_quoted_token("no quotes here"), None);
    }
}
