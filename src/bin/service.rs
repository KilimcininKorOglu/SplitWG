//! splitwg-svc — Windows Service that manages all WireGuard tunnels.
//!
//! Listens on a named pipe (`\\.\pipe\splitwg`) for JSON commands from the
//! GUI process. On macOS this binary exits immediately — the macOS
//! architecture uses per-tunnel sudo helpers instead.

fn main() {
    #[cfg(target_os = "windows")]
    splitwg::service::run();

    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("splitwg-svc is only available on Windows");
        std::process::exit(1);
    }
}
