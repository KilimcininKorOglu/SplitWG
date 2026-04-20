//! Background Wi-Fi / Ethernet state poller for on-demand rules (Windows).
//!
//! Uses `netsh wlan show interfaces` to read the current SSID and connection
//! state. Polls every 5 seconds, same as the macOS implementation.

use std::process::Command;
use std::sync::mpsc::Sender;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use crate::wg::on_demand::{LocalTime, NetState};

const POLL_INTERVAL: Duration = Duration::from_secs(5);

pub fn start(ctx: egui::Context, state: Arc<RwLock<NetState>>, notify: Sender<NetState>) {
    thread::spawn(move || {
        let mut first = true;
        loop {
            let next = current_state();
            let changed = {
                let prev = state.read().ok().map(|s| s.clone()).unwrap_or_default();
                prev != next
            };
            if first {
                log::info!(
                    "splitwg: network_monitor: initial state ssid={:?} wifi={} wired={}",
                    next.active_ssid, next.wifi_up, next.wired_up
                );
                first = false;
            }
            if changed {
                log::info!(
                    "splitwg: network_monitor: state changed ssid={:?} wifi={} wired={}",
                    next.active_ssid, next.wifi_up, next.wired_up
                );
                if let Ok(mut guard) = state.write() {
                    *guard = next.clone();
                }
                let _ = notify.send(next);
                ctx.request_repaint();
            }
            thread::sleep(POLL_INTERVAL);
        }
    });
}

pub fn current_state() -> NetState {
    let active_ssid = read_current_ssid();
    let wifi_up = active_ssid.is_some();
    let wired_up = check_wired_connection();

    NetState {
        active_ssid,
        wired_up,
        wifi_up,
        local_time: Some(read_local_time()),
    }
}

fn read_current_ssid() -> Option<String> {
    let out = Command::new("netsh")
        .args(["wlan", "show", "interfaces"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("SSID") {
            if let Some(ssid) = rest.strip_prefix(":") {
                let ssid = ssid.trim();
                if !ssid.is_empty() {
                    return Some(ssid.to_string());
                }
            }
        }
    }
    None
}

fn check_wired_connection() -> bool {
    let out = Command::new("netsh")
        .args(["interface", "show", "interface"])
        .output();
    match out {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            text.lines().any(|line| {
                line.contains("Connected") && line.contains("Ethernet")
            })
        }
        _ => false,
    }
}

fn read_local_time() -> LocalTime {
    unsafe {
        let t: libc::time_t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        let weekday = ((tm.tm_wday + 6) % 7) as u8;
        let hour = tm.tm_hour.clamp(0, 23) as u8;
        LocalTime { weekday, hour }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_state_does_not_panic() {
        let _ = current_state();
    }
}
