//! `x-splitwg://` URL scheme glue.
//!
//! macOS LaunchServices delivers `open x-splitwg://...` invocations to a
//! running process as a `kInternetEventClass/kAEGetURL` AppleEvent. The
//! ObjC shim (`url_handler_bridge.m`) installs a handler on the shared
//! `NSAppleEventManager`; when it fires we push a decoded `UrlAction` into
//! an `mpsc` channel that `App::drain_url_events` reads on the next frame.
//!
//! Single-instance behaviour comes for free — `LSUIElement=true` + a
//! matching `CFBundleURLTypes` entry means LaunchServices forwards the
//! event to the existing process rather than spawning a second instance.

use std::sync::mpsc;
use std::sync::Mutex;

use once_cell::sync::OnceCell;

/// Parsed URL actions. Tunnel name is kept as a plain `String` — the
/// caller looks it up against the current config list, so unknown names
/// are handled there (surface a notification, skip).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlAction {
    Connect(String),
    Disconnect(String),
    Toggle(String),
}

/// Global sender + repaint ctx, set once at install time. The AppleEvent
/// callback fires on the main thread; it only writes to the channel and
/// requests a repaint, so a plain `Mutex` is enough.
static CHANNEL: OnceCell<Mutex<Option<Sink>>> = OnceCell::new();

struct Sink {
    tx: mpsc::Sender<UrlAction>,
    ctx: egui::Context,
}

#[cfg(target_os = "macos")]
extern "C" {
    fn splitwg_install_url_handler(cb: extern "C" fn(*const std::os::raw::c_char));
}

#[cfg(target_os = "macos")]
extern "C" fn url_callback(ptr: *const std::os::raw::c_char) {
    if ptr.is_null() {
        return;
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(ptr) };
    let url = match bytes.to_str() {
        Ok(s) => s.to_string(),
        Err(e) => {
            log::warn!("splitwg: url_scheme: non-utf8 payload ({e})");
            return;
        }
    };
    log::info!("splitwg: url_scheme: received URL: {}", url);
    let Some(action) = parse_url(&url) else {
        log::warn!("splitwg: url_scheme: ignored malformed url: {url}");
        return;
    };
    log::info!("splitwg: url_scheme: parsed action: {:?}", action);
    if let Some(cell) = CHANNEL.get() {
        if let Ok(guard) = cell.lock() {
            if let Some(sink) = guard.as_ref() {
                if sink.tx.send(action).is_err() {
                    log::warn!("splitwg: url_scheme: receiver dropped");
                } else {
                    log::info!("splitwg: url_scheme: action dispatched");
                }
                sink.ctx.request_repaint();
            }
        }
    }
}

/// Install the AppleEvent handler and return the receiver end of the
/// channel. Must be called on the main thread before `eframe::run_native`
/// so AppleEvents dispatched at launch are not missed. Second calls
/// replace the sink (testing / hot-restart) but keep the native handler
/// in place.
pub fn install(ctx: egui::Context) -> mpsc::Receiver<UrlAction> {
    let (tx, rx) = mpsc::channel();
    let sink = Sink { tx, ctx };
    let cell = CHANNEL.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = cell.lock() {
        *guard = Some(sink);
    }
    #[cfg(target_os = "macos")]
    unsafe {
        splitwg_install_url_handler(url_callback);
    }
    rx
}

/// Parses an `x-splitwg://` URL into a `UrlAction`. Returns `None` for any
/// malformed, unknown-action, or empty-name input. Percent-encoded names
/// are decoded (currently only `%20` / `+` → space; we don't add a crate
/// for full RFC 3986 until needed).
pub fn parse_url(url: &str) -> Option<UrlAction> {
    let rest = url.strip_prefix("x-splitwg://")?;
    let rest = rest.trim_end_matches('/');
    let (action, name) = rest.split_once('/')?;
    let name = decode_name(name);
    if name.is_empty() {
        return None;
    }
    match action.to_ascii_lowercase().as_str() {
        "connect" => Some(UrlAction::Connect(name)),
        "disconnect" => Some(UrlAction::Disconnect(name)),
        "toggle" => Some(UrlAction::Toggle(name)),
        _ => None,
    }
}

fn decode_name(raw: &str) -> String {
    // Minimal URL decoder: `+` → space, `%xx` → byte. Good enough for the
    // tunnel-name payload we expect; full percent-decoding is out of scope.
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex(bytes[i + 1]);
                let lo = hex(bytes[i + 2]);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| raw.to_string())
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect_ok() {
        assert_eq!(
            parse_url("x-splitwg://connect/home"),
            Some(UrlAction::Connect("home".into()))
        );
    }

    #[test]
    fn parse_disconnect_ok() {
        assert_eq!(
            parse_url("x-splitwg://disconnect/work"),
            Some(UrlAction::Disconnect("work".into()))
        );
    }

    #[test]
    fn parse_toggle_ok() {
        assert_eq!(
            parse_url("x-splitwg://toggle/office-vpn"),
            Some(UrlAction::Toggle("office-vpn".into()))
        );
    }

    #[test]
    fn unknown_action_rejected() {
        assert_eq!(parse_url("x-splitwg://explode/home"), None);
    }

    #[test]
    fn missing_name_rejected() {
        assert_eq!(parse_url("x-splitwg://connect/"), None);
        assert_eq!(parse_url("x-splitwg://connect"), None);
    }

    #[test]
    fn percent_encoded_space_decoded() {
        assert_eq!(
            parse_url("x-splitwg://connect/home%20office"),
            Some(UrlAction::Connect("home office".into()))
        );
    }

    #[test]
    fn trailing_slash_tolerated() {
        assert_eq!(
            parse_url("x-splitwg://connect/home/"),
            Some(UrlAction::Connect("home".into()))
        );
    }

    #[test]
    fn wrong_scheme_rejected() {
        assert_eq!(parse_url("https://connect/home"), None);
    }

    #[test]
    fn action_is_case_insensitive() {
        assert_eq!(
            parse_url("x-splitwg://CONNECT/home"),
            Some(UrlAction::Connect("home".into()))
        );
    }
}
