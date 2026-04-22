use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use tokio::net::UdpSocket;

use crate::config::PaddingConfig;

fn strip_padding(frame: &[u8]) -> Vec<u8> {
    if frame.len() < 2 {
        return frame.to_vec();
    }
    let payload_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    if payload_len == 0 || 2 + payload_len > frame.len() {
        return frame.to_vec();
    }
    frame[2..2 + payload_len].to_vec()
}

fn apply_padding(payload: &[u8], config: &PaddingConfig) -> Vec<u8> {
    let min = config.min_bytes as usize;
    let max = config.max_bytes as usize;
    let pad_len = if max > min {
        rand::rng().random_range(min..=max)
    } else {
        min
    };
    let total = 2 + payload.len() + pad_len;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        rand::rng().fill(&mut pad[..]);
        frame.extend_from_slice(&pad);
    }
    frame
}

pub async fn handle_session(
    ws: WebSocket,
    target: SocketAddr,
    idle_timeout: Duration,
    max_frame_bytes: usize,
    padding: Option<PaddingConfig>,
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

    log::info!(
        "session started: target={target}, padding={}",
        padding.is_some()
    );

    let (mut ws_tx, mut ws_rx) = ws.split();
    let udp_rx = Arc::clone(&udp);
    let padding_for_ws = padding.clone();

    let mut ws_to_udp = tokio::spawn({
        let udp = Arc::clone(&udp);
        let pad_enabled = padding.is_some();
        async move {
            while let Ok(Some(msg)) = tokio::time::timeout(idle_timeout, ws_rx.next()).await {
                match msg {
                    Ok(Message::Binary(data)) => {
                        if data.len() > max_frame_bytes {
                            log::warn!("oversize ws frame: {} bytes, closing", data.len());
                            break;
                        }
                        let payload = if pad_enabled {
                            strip_padding(&data)
                        } else {
                            data.to_vec()
                        };
                        if let Err(e) = udp.send(&payload).await {
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
                    let frame = match &padding_for_ws {
                        Some(cfg) => apply_padding(&buf[..n], cfg),
                        None => buf[..n].to_vec(),
                    };
                    if ws_tx.send(Message::Binary(frame.into())).await.is_err() {
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
