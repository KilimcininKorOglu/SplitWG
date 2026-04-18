//! Background Wi-Fi / Ethernet state poller for on-demand rules.
//!
//! The design is deliberately simple: a worker thread wakes every 5 seconds,
//! reads the current Wi-Fi SSID (via `CoreWLAN`) and the default-route
//! interface (via `/sbin/route -n get default`), and publishes a
//! `NetState` snapshot into an `Arc<RwLock<_>>` plus a change notification
//! through an `mpsc` channel so the UI can react.
//!
//! This is lower-powered than `SCDynamicStore` callbacks but avoids the
//! thread-local `CFRunLoop` dance and works without Location Services
//! authorisation (SSID simply stays `None` if Apple refuses the query).

use std::process::Command;
use std::sync::mpsc::Sender;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use objc2::rc::autoreleasepool;
use objc2_core_wlan::CWWiFiClient;

use crate::wg::on_demand::{LocalTime, NetState};

/// Poll interval — deliberately slow enough to be battery-friendly while
/// still feeling interactive when the user switches Wi-Fi networks.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Launches the monitor on a detached thread. The thread runs for the
/// lifetime of the process; on app shutdown the OS reclaims it.
pub fn start(ctx: egui::Context, state: Arc<RwLock<NetState>>, notify: Sender<NetState>) {
    thread::spawn(move || loop {
        let next = current_state();
        let changed = {
            let prev = state.read().ok().map(|s| s.clone()).unwrap_or_default();
            prev != next
        };
        if changed {
            if let Ok(mut guard) = state.write() {
                *guard = next.clone();
            }
            let _ = notify.send(next);
            ctx.request_repaint();
        }
        thread::sleep(POLL_INTERVAL);
    });
}

/// Snapshots the current network state synchronously.
pub fn current_state() -> NetState {
    let active_ssid = read_current_ssid();
    let default_iface = read_default_interface();
    let wifi_iface = read_wifi_interface_name();

    let wifi_up = active_ssid.is_some();
    let wired_up = match (default_iface.as_deref(), wifi_iface.as_deref()) {
        (Some(dflt), Some(wifi)) => dflt.starts_with("en") && dflt != wifi,
        (Some(dflt), None) => dflt.starts_with("en"),
        _ => false,
    };

    NetState {
        active_ssid,
        wired_up,
        wifi_up,
        local_time: Some(read_local_time()),
    }
}

/// Reads the current local time via `libc::localtime_r`. `tm_wday` in libc
/// is 0 = Sunday; we rotate to 0 = Monday to match `ScheduleRule`'s bit
/// layout.
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

fn read_current_ssid() -> Option<String> {
    autoreleasepool(|_| unsafe {
        let client = CWWiFiClient::sharedWiFiClient();
        let iface = client.interface()?;
        iface.ssid().map(|s| s.to_string())
    })
}

fn read_wifi_interface_name() -> Option<String> {
    autoreleasepool(|_| unsafe {
        let client = CWWiFiClient::sharedWiFiClient();
        let iface = client.interface()?;
        iface.interfaceName().map(|s| s.to_string())
    })
}

fn read_default_interface() -> Option<String> {
    let out = Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("interface:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_state_does_not_panic() {
        // Basic smoke — we don't assert anything about the host network.
        let _ = current_state();
    }
}
