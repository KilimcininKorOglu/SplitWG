//! splitwg-svc — service binary that manages all WireGuard tunnels.
//!
//! Windows: Windows Service listening on named pipe.
//! Linux: systemd service listening on Unix domain socket.
//! macOS: not used (per-tunnel sudo helpers instead).

fn main() {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    splitwg::service::run();

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        eprintln!("splitwg-svc is only available on Windows and Linux");
        std::process::exit(1);
    }
}
