use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio::net::UdpSocket;

pub async fn handle_session(
    ws: WebSocket,
    target: SocketAddr,
    idle_timeout: Duration,
    max_frame_bytes: usize,
) {
    let bind_addr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let udp = match UdpSocket::bind(bind_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log::error!("udp bind failed: {e}");
            return;
        }
    };

    if let Err(e) = udp.connect(target).await {
        log::error!("udp connect to {target} failed: {e}");
        return;
    }

    log::info!("session started: target={target}");

    let (mut ws_tx, mut ws_rx) = ws.split();
    let udp_rx = Arc::clone(&udp);

    let mut ws_to_udp = tokio::spawn({
        let udp = Arc::clone(&udp);
        async move {
            while let Ok(Some(msg)) = tokio::time::timeout(idle_timeout, ws_rx.next()).await {
                match msg {
                    Ok(Message::Binary(data)) => {
                        if data.len() > max_frame_bytes {
                            log::warn!("oversize ws frame: {} bytes, closing", data.len());
                            break;
                        }
                        if let Err(e) = udp.send(&data).await {
                            log::error!("udp send failed: {e}");
                            break;
                        }
                    }
                    Ok(Message::Close(_)) => break,
                    Ok(_) => {}
                    Err(e) => {
                        log::debug!("ws recv error: {e}");
                        break;
                    }
                }
            }
        }
    });

    let buf_cap = max_frame_bytes.min(65535);
    let mut udp_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_cap];
        loop {
            match tokio::time::timeout(idle_timeout, udp_rx.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    if ws_tx
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    log::error!("udp recv failed: {e}");
                    break;
                }
                Err(_) => {
                    log::info!("session idle timeout");
                    let _ = ws_tx.close().await;
                    break;
                }
            }
        }
    });

    tokio::select! {
        _ = &mut ws_to_udp => { udp_to_ws.abort(); }
        _ = &mut udp_to_ws => { ws_to_udp.abort(); }
    }

    log::info!("session ended: target={target}");
}
