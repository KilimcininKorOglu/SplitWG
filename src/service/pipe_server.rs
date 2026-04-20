//! Named pipe server for splitwg-svc.
//!
//! Listens on `\\.\pipe\splitwg`, accepts one client at a time (the GUI),
//! and dispatches JSON commands to the tunnel manager.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{watch, Mutex};

use crate::ipc::{Command, Event};
use crate::runtime::Tunnel;

use super::TunnelState;

type TunnelMap = Arc<Mutex<HashMap<String, TunnelState>>>;

pub const PIPE_NAME: &str = r"\\.\pipe\splitwg";

#[cfg(target_os = "windows")]
pub async fn serve(tunnels: TunnelMap, mut shutdown: watch::Receiver<bool>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;

    loop {
        // reject_remote_clients prevents network pipe access.
        // TODO: Add SDDL-based SecurityAttributes via CreateNamedPipeW
        // to restrict local access to Administrators + SYSTEM only.
        let server = match ServerOptions::new()
            .first_pipe_instance(false)
            .reject_remote_clients(true)
            .create(PIPE_NAME)
        {
            Ok(s) => s,
            Err(e) => {
                eprintln!("splitwg-svc: pipe: failed to create: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            res = server.connect() => {
                if let Err(e) = res {
                    eprintln!("splitwg-svc: pipe: connect failed: {e}");
                    continue;
                }
                let tunnels_clone = tunnels.clone();
                let shutdown_clone = shutdown.clone();
                tokio::spawn(handle_client(server, tunnels_clone, shutdown_clone));
            }
        }
    }

    let mut guard = tunnels.lock().await;
    for (name, state) in guard.drain() {
        eprintln!("splitwg-svc: shutting down tunnel {name}");
        let _ = state.shutdown_tx.send(true);
        let _ = state.task.await;
    }
}

#[cfg(target_os = "windows")]
async fn handle_client(
    pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    tunnels: TunnelMap,
    mut shutdown: watch::Receiver<bool>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (reader, mut writer) = tokio::io::split(pipe);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            res = reader.read_line(&mut line) => {
                match res {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }

        let cmd: Command = match serde_json::from_str(line.trim()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("splitwg-svc: pipe: invalid command: {e}");
                continue;
            }
        };

        match cmd {
            Command::Up(params) => {
                let tunnel_name = params.tunnel.clone();
                eprintln!("splitwg-svc: pipe: Up for {tunnel_name}");

                let (tx, rx) = watch::channel(false);
                match Tunnel::bringup(&params).await {
                    Ok(tunnel) => {
                        let arc = Arc::new(tunnel);
                        let arc2 = arc.clone();
                        let shutdown_rx2 = rx.clone();
                        let task = tokio::spawn(async move {
                            let _ = arc2.run(shutdown_rx2).await;
                        });
                        let state = TunnelState {
                            tunnel: arc,
                            task,
                            shutdown_tx: tx,
                        };
                        tunnels.lock().await.insert(tunnel_name.clone(), state);
                        let event = Event::Ready {
                            iface: tunnel_name.clone(),
                        };
                        let json = serde_json::to_string(&event).unwrap();
                        let _ = writer.write_all(format!("{json}\n").as_bytes()).await;
                    }
                    Err(e) => {
                        let event = Event::Error {
                            message: format!("{e:#}"),
                        };
                        let json = serde_json::to_string(&event).unwrap();
                        let _ = writer.write_all(format!("{json}\n").as_bytes()).await;
                    }
                }
            }
            Command::Shutdown => {
                eprintln!("splitwg-svc: pipe: Shutdown received");
                let mut guard = tunnels.lock().await;
                for (name, state) in guard.drain() {
                    eprintln!("splitwg-svc: shutting down tunnel {name}");
                    let _ = state.shutdown_tx.send(true);
                    let _ = state.task.await;
                }
                break;
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub async fn serve(_tunnels: TunnelMap, _shutdown: watch::Receiver<bool>) {}
