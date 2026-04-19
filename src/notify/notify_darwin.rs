//! Fire-and-forget AppleScript `display notification`.

use std::process::Command;

/// Shows a macOS error notification with the "Basso" sound.
pub fn error(title: &str, message: &str) {
    log::info!("splitwg: notify: error notification: {}", title);
    let script = format!(
        "display notification {} with title {} subtitle \"SplitWG\" sound name \"Basso\"",
        quote(message),
        quote(title),
    );
    spawn(&script);
}

/// Shows a macOS notification without sound.
pub fn info(title: &str, message: &str) {
    log::info!("splitwg: notify: info notification: {}", title);
    let script = format!(
        "display notification {} with title {} subtitle \"SplitWG\"",
        quote(message),
        quote(title),
    );
    spawn(&script);
}

/// AppleScript-safe double-quoted string (escapes backslashes and double quotes).
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Spawns osascript without waiting.
fn spawn(script: &str) {
    let _ = Command::new("osascript").args(["-e", script]).spawn();
}

#[cfg(test)]
mod tests {
    use super::quote;

    #[test]
    fn quote_escapes_double_quote() {
        assert_eq!(quote("he said \"hi\""), "\"he said \\\"hi\\\"\"");
    }

    #[test]
    fn quote_escapes_backslash() {
        assert_eq!(quote("path\\with\\slash"), "\"path\\\\with\\\\slash\"");
    }
}
