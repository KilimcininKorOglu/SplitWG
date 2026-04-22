//! Unix domain socket server for splitwg-svc on Linux.
//!
//! Listens on `/run/splitwg/splitwg.sock`, accepts clients from the GUI,
//! and dispatches JSON commands to the tunnel manager.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{watch, Mutex};

use crate::ipc::{Command, Event};
use crate::runtime::Tunnel;

use super::TunnelState;

type TunnelMap = Arc<Mutex<HashMap<String, TunnelState>>>;

pub const SOCKET_PATH: &str = "/run/splitwg/splitwg.sock";

#[cfg(target_os = "linux")]
pub async fn serve(tunnels: TunnelMap, mut shutdown: watch::Receiver<bool>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    if let Some(parent) = std::path::Path::new(SOCKET_PATH).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(SOCKET_PATH);
    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("splitwg-svc: socket: failed to bind: {e}");
            return;
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o660));
    }

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            res = listener.accept() => {
                match res {
                    Ok((stream, _addr)) => {
                        let tunnels_clone = tunnels.clone();
                        let shutdown_clone = shutdown.clone();
                        tokio::spawn(handle_client(stream, tunnels_clone, shutdown_clone));
                    }
                    Err(e) => {
                        eprintln!("splitwg-svc: socket: accept failed: {e}");
                    }
                }
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

#[cfg(target_os = "linux")]
async fn handle_client(
    stream: tokio::net::UnixStream,
    tunnels: TunnelMap,
    mut shutdown: watch::Receiver<bool>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (reader, mut writer) = stream.into_split();
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
                eprintln!("splitwg-svc: socket: invalid command: {e}");
                continue;
            }
        };

        match cmd {
            Command::Up(params) => {
                let tunnel_name = params.tunnel.clone();
                eprintln!("splitwg-svc: socket: Up for {tunnel_name}");

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
                eprintln!("splitwg-svc: socket: Shutdown received");
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

#[cfg(not(target_os = "linux"))]
pub async fn serve(_tunnels: TunnelMap, _shutdown: watch::Receiver<bool>) {}
