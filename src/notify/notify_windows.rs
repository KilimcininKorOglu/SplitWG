//! Windows toast notifications via PowerShell BurntToast or WinRT.
//!
//! Uses PowerShell `New-BurntToastNotification` as a simple cross-version
//! approach. Falls back silently if BurntToast is not installed — notifications
//! are fire-and-forget, same as the macOS implementation.

use std::process::Command;

pub fn error(title: &str, message: &str) {
    log::info!("splitwg: notify: error notification: {}", title);
    show_toast(title, message, true);
}

pub fn info(title: &str, message: &str) {
    log::info!("splitwg: notify: info notification: {}", title);
    show_toast(title, message, false);
}

fn show_toast(title: &str, message: &str, is_error: bool) {
    let title_escaped = escape_ps(title);
    let msg_escaped = escape_ps(message);
    let sound = if is_error { " -Sound 'Default'" } else { "" };

    let script = format!(
        "New-BurntToastNotification -AppLogo '' \
         -Text '{title_escaped}','{msg_escaped}'{sound}"
    );

    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .spawn();
}

fn escape_ps(s: &str) -> String {
    s.replace('\'', "''")
}
