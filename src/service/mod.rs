//! Service infrastructure for splitwg-svc (Windows + Linux).
//!
//! Windows: Windows Service + named pipe IPC.
//! Linux: systemd service + Unix domain socket IPC.

#[cfg(target_os = "windows")]
mod installer;
#[cfg(target_os = "windows")]
mod pipe_server;
#[cfg(target_os = "linux")]
mod unix_server;

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{watch, Mutex};

use crate::ipc::{Command, Event};
use crate::runtime::Tunnel;

#[cfg(target_os = "windows")]
pub use installer::{install, is_installed, uninstall};

#[cfg(target_os = "linux")]
pub fn is_installed() -> bool {
    std::process::Command::new("systemctl")
        .args(["is-enabled", "--quiet", "splitwg"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
pub fn install() -> Result<(), String> {
    Err("Linux: install the .deb/.rpm package to register the systemd service".to_string())
}

#[cfg(target_os = "linux")]
pub fn uninstall() -> Result<(), String> {
    std::process::Command::new("systemctl")
        .args(["disable", "--now", "splitwg"])
        .status()
        .map_err(|e| format!("systemctl disable: {e}"))?;
    Ok(())
}

type TunnelMap = Arc<Mutex<HashMap<String, TunnelState>>>;

struct TunnelState {
    tunnel: Arc<Tunnel>,
    task: tokio::task::JoinHandle<()>,
    shutdown_tx: watch::Sender<bool>,
}

pub fn run() {
    service_main();
}

#[cfg(target_os = "windows")]
fn service_main() {
    use windows_service::service_dispatcher;

    let _ = service_dispatcher::start("splitwg", ffi_service_main);
}

#[cfg(target_os = "windows")]
windows_service::define_windows_service!(ffi_service_main, win_service_main);

#[cfg(target_os = "windows")]
fn win_service_main(_arguments: Vec<std::ffi::OsString>) {
    use windows_service::service::*;
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register("splitwg", event_handler).unwrap();

    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })
        .unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        crate::runtime::wfp::preemptive_flush();

        let tunnels: TunnelMap = Arc::new(Mutex::new(HashMap::new()));
        pipe_server::serve(tunnels, shutdown_rx).await;
    });

    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })
        .unwrap();
}

#[cfg(target_os = "linux")]
fn service_main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        crate::runtime::nft::preemptive_flush();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        tokio::spawn(async move {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .unwrap()
                .recv()
                .await;
            let _ = shutdown_tx.send(true);
        });

        let tunnels: TunnelMap = Arc::new(Mutex::new(HashMap::new()));
        unix_server::serve(tunnels, shutdown_rx).await;
    });
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn service_main() {
    eprintln!("splitwg-svc: service module is not available on this platform");
}
