//! splitwg-helper — root-owned userspace WireGuard tunnel process.
//!
//! Launched by the tray via `sudo -n splitwg-helper`. One helper = one tunnel.
//! Reads JSON `Command`s from stdin, writes JSON `Event`s to stdout. All
//! diagnostic logging goes to stderr (the host pipes it into `splitwg.log`).
//!
//! SIGTERM / SIGINT → graceful shutdown: routing + DNS cleanup (Phase 4),
//! tunnel tasks abort, utun device closes on drop.

use std::io::Write;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::watch;

use splitwg::ipc::{Command, Event};
#[cfg(target_os = "macos")]
use splitwg::runtime::pf;
use splitwg::runtime::Tunnel;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let code = run().await;
    std::process::exit(code);
}

async fn run() -> i32 {
    eprintln!("splitwg-helper: main: helper starting");

    #[cfg(target_os = "macos")]
    pf::preemptive_flush();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // SIGTERM / SIGINT → shutdown.
    spawn_signal_handler(shutdown_tx.clone());

    let mut reader = BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    let mut tunnel_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut stats_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut tunnel_arc: Option<Arc<Tunnel>> = None;
    let mut main_shutdown = shutdown_rx.clone();

    loop {
        tokio::select! {
            biased;
            _ = main_shutdown.changed() => {
                eprintln!("splitwg-helper: shutdown signalled");
                break;
            }
            res = reader.read_line(&mut line) => {
                match res {
                    Ok(0) => {
                        eprintln!("splitwg-helper: stdin EOF");
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        emit_error(format!("stdin read: {e}"));
                        return 1;
                    }
                }

                let trimmed = line.trim().to_string();
                line.clear();
                if trimmed.is_empty() {
                    continue;
                }

                let cmd: Command = match serde_json::from_str(&trimmed) {
                    Ok(c) => c,
                    Err(e) => {
                        emit_error(format!("parse command: {e}"));
                        continue;
                    }
                };

                match cmd {
                    Command::Up(params) => {
                        eprintln!("splitwg-helper: main: received Up command (endpoint={})", params.endpoint);
                        if tunnel_task.is_some() {
                            emit_error("tunnel already up for this helper".into());
                            continue;
                        }
                        match Tunnel::bringup(&params).await {
                            Ok(tunnel) => {
                                let arc = Arc::new(tunnel);
                                let iface = arc.iface.clone();
                                eprintln!("splitwg-helper: main: emitting Ready event (iface={iface})");
                                emit(&Event::Ready { iface });

                                // Data plane task
                                let t = arc.clone();
                                let rx = shutdown_rx.clone();
                                tunnel_task = Some(tokio::spawn(async move {
                                    if let Err(e) = t.run(rx).await {
                                        eprintln!("splitwg-helper: tunnel run: {e}");
                                    }
                                }));

                                // Stats emitter task — pushes boringtun
                                // counters to the tray every 2 s.
                                let t2 = arc.clone();
                                let mut stats_shutdown = shutdown_rx.clone();
                                stats_task = Some(tokio::spawn(async move {
                                    let mut interval = tokio::time::interval(
                                        std::time::Duration::from_secs(2),
                                    );
                                    loop {
                                        tokio::select! {
                                            biased;
                                            _ = stats_shutdown.changed() => break,
                                            _ = interval.tick() => {}
                                        }
                                        let (hs, tx, rx) = t2.stats().await;
                                        eprintln!(
                                            "splitwg-helper: stats: hs={:?} tx={} rx={}",
                                            hs, tx, rx
                                        );
                                        emit(&Event::Stats {
                                            tx_bytes: tx as u64,
                                            rx_bytes: rx as u64,
                                        });
                                        if let Some(d) = &hs {
                                            let epoch = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_secs()
                                                .saturating_sub(d.as_secs());
                                            emit(&Event::Handshake {
                                                peer: String::new(),
                                                at: epoch.to_string(),
                                            });
                                        }
                                    }
                                }));

                                tunnel_arc = Some(arc);
                            }
                            Err(e) => {
                                emit_error(format!("bringup: {e:#}"));
                                return 1;
                            }
                        }
                    }
                    Command::Shutdown => {
                        eprintln!("splitwg-helper: shutdown command received");
                        break;
                    }
                }
            }
        }
    }

    let _ = shutdown_tx.send(true);
    if let Some(task) = stats_task {
        let _ = task.await;
    }
    if let Some(task) = tunnel_task {
        eprintln!("splitwg-helper: main: waiting for tunnel task to finish");
        let _ = task.await;
    }
    if let Some(arc) = tunnel_arc {
        Tunnel::shutdown_arc(arc).await;
    }
    eprintln!("splitwg-helper: main: clean exit");
    0
}

fn spawn_signal_handler(shutdown_tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("splitwg-helper: SIGTERM handler: {e}");
                return;
            }
        };
        let mut int = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("splitwg-helper: SIGINT handler: {e}");
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => eprintln!("splitwg-helper: SIGTERM"),
            _ = int.recv() => eprintln!("splitwg-helper: SIGINT"),
        }
        let _ = shutdown_tx.send(true);
    });
}

fn emit(ev: &Event) {
    match serde_json::to_string(ev) {
        Ok(s) => {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{s}");
            let _ = out.flush();
        }
        Err(e) => eprintln!("splitwg-helper: serialize event: {e}"),
    }
}

fn emit_error(msg: String) {
    emit(&Event::Error { message: msg });
}
