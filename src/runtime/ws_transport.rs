//! WebSocket transport for WireGuard datagrams over TLS.
//!
//! Each WireGuard datagram becomes one WebSocket binary frame. A
//! supervisor task manages the connection lifecycle: when the link
//! drops it reconnects with exponential backoff and failover across
//! relay URLs. The public `send`/`recv` go through mpsc channels and
//! are oblivious to reconnections.
//!
//! Optional frame padding defeats DPI packet-size fingerprinting.
//! Wire format when padding is enabled:
//!   [2 bytes: payload_len (big-endian)] [payload] [random padding]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::ipc::PaddingConfig;

use super::transport::WgTransport;

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const MAX_FAILURES: u32 = 10;

struct ConnectConfig {
    urls: Vec<String>,
    sni_override: Option<String>,
    auth_token: Option<String>,
    padding: Option<PaddingConfig>,
}

pub struct WsTransport {
    outgoing_tx: mpsc::Sender<Vec<u8>>,
    incoming_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    supervisor_handle: tokio::task::JoinHandle<()>,
}

impl Drop for WsTransport {
    fn drop(&mut self) {
        self.supervisor_handle.abort();
    }
}

type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type WsStream = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

fn apply_padding(payload: &[u8], cfg: &PaddingConfig) -> Vec<u8> {
    let len = payload.len().min(u16::MAX as usize);
    let min = cfg.min_bytes as usize;
    let max = cfg.max_bytes as usize;
    let pad_len = if max > min {
        rand::rng().random_range(min..=max)
    } else {
        min
    };
    let total = 2 + len + pad_len;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&(len as u16).to_be_bytes());
    frame.extend_from_slice(&payload[..len]);
    if pad_len > 0 {
        let start = frame.len();
        frame.resize(total, 0);
        rand::rng().fill(&mut frame[start..]);
    }
    frame
}

fn strip_padding(frame: &[u8]) -> Vec<u8> {
    if frame.len() < 2 {
        return frame.to_vec();
    }
    let payload_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    if 2 + payload_len > frame.len() {
        return frame.to_vec();
    }
    frame[2..2 + payload_len].to_vec()
}

impl WsTransport {
    pub async fn connect(
        urls: Vec<String>,
        sni_override: Option<&str>,
        auth_token: Option<&str>,
        padding: Option<PaddingConfig>,
    ) -> Result<Self> {
        let config = Arc::new(ConnectConfig {
            urls,
            sni_override: sni_override.map(String::from),
            auth_token: auth_token.map(String::from),
            padding,
        });

        let (sink, source) = Self::inner_connect(&config.urls[0], &config).await?;

        let (outgoing_tx, outgoing_rx) = mpsc::channel::<Vec<u8>>(256);
        let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>(256);

        let supervisor_handle = tokio::spawn(Self::supervisor_task(
            Arc::clone(&config),
            sink,
            source,
            outgoing_rx,
            incoming_tx,
        ));

        Ok(Self {
            outgoing_tx,
            incoming_rx: Mutex::new(incoming_rx),
            supervisor_handle,
        })
    }

    async fn inner_connect(url: &str, config: &ConnectConfig) -> Result<(WsSink, WsStream)> {
        let mut request = url.into_client_request()?;
        if let Some(token) = &config.auth_token {
            request.headers_mut().insert(
                "Authorization",
                HeaderValue::from_str(&format!("Bearer {token}"))?,
            );
        }
        if let Some(sni) = &config.sni_override {
            request
                .headers_mut()
                .insert("Host", HeaderValue::from_str(sni)?);
        }

        eprintln!("splitwg-helper: ws: connecting to {url}");
        let (ws_stream, _response) = tokio_tungstenite::connect_async(request).await?;
        eprintln!("splitwg-helper: ws: connected to {url}");
        Ok(ws_stream.split())
    }

    async fn supervisor_task(
        config: Arc<ConnectConfig>,
        initial_sink: WsSink,
        initial_source: WsStream,
        outgoing_rx: mpsc::Receiver<Vec<u8>>,
        incoming_tx: mpsc::Sender<Vec<u8>>,
    ) {
        let mut outgoing_rx = Self::run_session(
            initial_sink,
            initial_source,
            outgoing_rx,
            &incoming_tx,
            &config.padding,
        )
        .await;

        let mut backoff = INITIAL_BACKOFF;
        let mut failed_cycles: u32 = 0;

        'reconnect: loop {
            for url in &config.urls {
                match Self::inner_connect(url, &config).await {
                    Ok((sink, source)) => {
                        backoff = INITIAL_BACKOFF;
                        failed_cycles = 0;
                        outgoing_rx = Self::run_session(
                            sink,
                            source,
                            outgoing_rx,
                            &incoming_tx,
                            &config.padding,
                        )
                        .await;
                        eprintln!("splitwg-helper: ws: connection lost, reconnecting...");
                        continue 'reconnect;
                    }
                    Err(e) => {
                        eprintln!("splitwg-helper: ws: connect to {url} failed: {e}");
                    }
                }
            }

            failed_cycles += 1;
            if failed_cycles >= MAX_FAILURES {
                eprintln!(
                    "splitwg-helper: ws: fatal — {failed_cycles} consecutive failed cycles, giving up"
                );
                return;
            }

            eprintln!("splitwg-helper: ws: all URLs failed, backing off for {backoff:?}...");
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    async fn run_session(
        sink: WsSink,
        source: WsStream,
        outgoing_rx: mpsc::Receiver<Vec<u8>>,
        incoming_tx: &mpsc::Sender<Vec<u8>>,
        padding: &Option<PaddingConfig>,
    ) -> mpsc::Receiver<Vec<u8>> {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (pong_tx, pong_rx) = mpsc::channel::<Vec<u8>>(8);

        let mut writer = tokio::spawn(Self::writer_task(
            sink,
            outgoing_rx,
            pong_rx,
            cancel_rx,
            padding.clone(),
        ));
        let mut reader = tokio::spawn(Self::reader_task(
            source,
            incoming_tx.clone(),
            pong_tx,
            padding.is_some(),
        ));

        tokio::select! {
            result = &mut writer => {
                reader.abort();
                result.expect("writer task panicked")
            }
            _ = &mut reader => {
                let _ = cancel_tx.send(true);
                writer.await.expect("writer task panicked")
            }
        }
    }

    async fn writer_task(
        mut sink: WsSink,
        mut outgoing_rx: mpsc::Receiver<Vec<u8>>,
        mut pong_rx: mpsc::Receiver<Vec<u8>>,
        mut cancel_rx: watch::Receiver<bool>,
        padding: Option<PaddingConfig>,
    ) -> mpsc::Receiver<Vec<u8>> {
        loop {
            tokio::select! {
                biased;
                _ = cancel_rx.changed() => break,
                Some(payload) = pong_rx.recv() => {
                    if sink.send(Message::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                Some(data) = outgoing_rx.recv() => {
                    let frame = match &padding {
                        Some(cfg) => apply_padding(&data, cfg),
                        None => data,
                    };
                    if sink.send(Message::Binary(frame)).await.is_err() {
                        break;
                    }
                }
                else => break,
            }
        }
        outgoing_rx
    }

    async fn reader_task(
        mut stream: WsStream,
        incoming_tx: mpsc::Sender<Vec<u8>>,
        pong_tx: mpsc::Sender<Vec<u8>>,
        padding_enabled: bool,
    ) {
        while let Some(result) = stream.next().await {
            let msg = match result {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("splitwg-helper: ws: reader error: {e}");
                    break;
                }
            };
            match msg {
                Message::Binary(data) => {
                    let payload = if padding_enabled {
                        strip_padding(&data)
                    } else {
                        data
                    };
                    let _ = incoming_tx.send(payload).await;
                }
                Message::Ping(d) => {
                    let _ = pong_tx.try_send(d);
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    }
}

impl WgTransport for WsTransport {
    fn send<'a>(&'a self, buf: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.outgoing_tx
                .send(buf.to_vec())
                .await
                .map_err(|_| anyhow!("WebSocket writer closed"))?;
            Ok(())
        })
    }

    fn recv<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let mut rx = self.incoming_rx.lock().await;
            let data = rx
                .recv()
                .await
                .ok_or_else(|| anyhow!("WebSocket reader closed"))?;
            if data.len() > buf.len() {
                anyhow::bail!(
                    "WebSocket frame too large for buffer ({} > {})",
                    data.len(),
                    buf.len()
                );
            }
            let len = data.len();
            buf[..len].copy_from_slice(&data[..len]);
            Ok(len)
        })
    }

    fn display_name(&self) -> &str {
        "WSS"
    }
}
