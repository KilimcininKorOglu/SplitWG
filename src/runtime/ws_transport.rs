//! WebSocket transport for WireGuard datagrams over TLS.
//!
//! Each WireGuard datagram becomes one WebSocket binary frame. A
//! supervisor task manages the connection lifecycle: when the link
//! drops it reconnects with exponential backoff and failover across
//! relay URLs. The public `send`/`recv` go through mpsc channels and
//! are oblivious to reconnections.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::transport::WgTransport;

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const MAX_FAILURES: u32 = 10;

struct ConnectConfig {
    urls: Vec<String>,
    sni_override: Option<String>,
    auth_token: Option<String>,
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

impl WsTransport {
    pub async fn connect(
        urls: Vec<String>,
        sni_override: Option<&str>,
        auth_token: Option<&str>,
    ) -> Result<Self> {
        let config = ConnectConfig {
            urls,
            sni_override: sni_override.map(String::from),
            auth_token: auth_token.map(String::from),
        };

        let (sink, source) = Self::inner_connect(&config.urls[0], &config).await?;

        let (outgoing_tx, outgoing_rx) = mpsc::channel::<Vec<u8>>(256);
        let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>(256);

        let supervisor_handle = tokio::spawn(Self::supervisor_task(
            config,
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
        config: ConnectConfig,
        initial_sink: WsSink,
        initial_source: WsStream,
        outgoing_rx: mpsc::Receiver<Vec<u8>>,
        incoming_tx: mpsc::Sender<Vec<u8>>,
    ) {
        let mut outgoing_rx =
            Self::run_session(initial_sink, initial_source, outgoing_rx, &incoming_tx).await;

        let mut backoff = INITIAL_BACKOFF;
        let mut failures: u32 = 0;

        'reconnect: loop {
            for url in &config.urls {
                eprintln!("splitwg-helper: ws: reconnecting in {backoff:?}...");
                tokio::time::sleep(backoff).await;

                match Self::inner_connect(url, &config).await {
                    Ok((sink, source)) => {
                        backoff = INITIAL_BACKOFF;
                        failures = 0;
                        outgoing_rx =
                            Self::run_session(sink, source, outgoing_rx, &incoming_tx).await;
                        continue 'reconnect;
                    }
                    Err(e) => {
                        failures += 1;
                        eprintln!(
                            "splitwg-helper: ws: connect to {url} failed ({failures}/{MAX_FAILURES}): {e}"
                        );
                        if failures >= MAX_FAILURES {
                            eprintln!(
                                "splitwg-helper: ws: fatal — {failures} consecutive failures, giving up"
                            );
                            return;
                        }
                    }
                }
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    async fn run_session(
        sink: WsSink,
        source: WsStream,
        outgoing_rx: mpsc::Receiver<Vec<u8>>,
        incoming_tx: &mpsc::Sender<Vec<u8>>,
    ) -> mpsc::Receiver<Vec<u8>> {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (pong_tx, pong_rx) = mpsc::channel::<Vec<u8>>(8);

        let mut writer = tokio::spawn(Self::writer_task(sink, outgoing_rx, pong_rx, cancel_rx));
        let mut reader = tokio::spawn(Self::reader_task(source, incoming_tx.clone(), pong_tx));

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
                    if sink.send(Message::Binary(data)).await.is_err() {
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
                    let _ = incoming_tx.send(data).await;
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
