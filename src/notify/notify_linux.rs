//! Linux notifications via notify-send (D-Bus).

use std::process::Command;

pub fn error(title: &str, message: &str) {
    log::info!("splitwg: notify: error notification: {}", title);
    let _ = Command::new("notify-send")
        .args(["--urgency=critical", "--app-name=SplitWG", title, message])
        .spawn();
}

pub fn info(title: &str, message: &str) {
    log::info!("splitwg: notify: info notification: {}", title);
    let _ = Command::new("notify-send")
        .args(["--app-name=SplitWG", title, message])
        .spawn();
}
