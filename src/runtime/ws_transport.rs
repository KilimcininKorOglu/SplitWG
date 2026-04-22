//! WebSocket transport for WireGuard datagrams over TLS.
//!
//! Each WireGuard datagram becomes one WebSocket binary frame. The relay
//! server extracts the payload and forwards it as UDP to the real peer.
//!
//! Architecture: two spawned tasks (reader + writer) own the split
//! WebSocket stream exclusively. The public `send`/`recv` methods
//! communicate via mpsc channels — no Mutex contention between the
//! data-plane tasks.

use std::future::Future;
use std::pin::Pin;

use anyhow::{anyhow, Result};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::transport::WgTransport;

pub struct WsTransport {
    outgoing_tx: mpsc::Sender<Vec<u8>>,
    incoming_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl WsTransport {
    pub async fn connect(
        url: &str,
        sni_override: Option<&str>,
        auth_token: Option<&str>,
    ) -> Result<Self> {
        let mut request = url.into_client_request()?;
        if let Some(token) = auth_token {
            request.headers_mut().insert(
                "Authorization",
                HeaderValue::from_str(&format!("Bearer {token}"))?,
            );
        }
        if let Some(sni) = sni_override {
            request
                .headers_mut()
                .insert("Host", HeaderValue::from_str(sni)?);
        }

        eprintln!("splitwg-helper: ws: connecting to {url}");
        let (ws_stream, _response) = tokio_tungstenite::connect_async(request).await?;
        eprintln!("splitwg-helper: ws: connected");

        let (ws_sink, ws_source) = ws_stream.split();

        let (outgoing_tx, outgoing_rx) = mpsc::channel::<Vec<u8>>(256);
        let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>(256);
        let (pong_tx, pong_rx) = mpsc::channel::<Vec<u8>>(8);

        tokio::spawn(Self::writer_task(ws_sink, outgoing_rx, pong_rx));
        tokio::spawn(Self::reader_task(ws_source, incoming_tx, pong_tx));

        Ok(Self {
            outgoing_tx,
            incoming_rx: Mutex::new(incoming_rx),
        })
    }

    async fn writer_task(
        mut sink: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
        mut outgoing_rx: mpsc::Receiver<Vec<u8>>,
        mut pong_rx: mpsc::Receiver<Vec<u8>>,
    ) {
        loop {
            tokio::select! {
                Some(data) = outgoing_rx.recv() => {
                    if sink.send(Message::Binary(data)).await.is_err() {
                        break;
                    }
                }
                Some(payload) = pong_rx.recv() => {
                    if sink.send(Message::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                else => break,
            }
        }
    }

    async fn reader_task(
        mut stream: futures_util::stream::SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        incoming_tx: mpsc::Sender<Vec<u8>>,
        pong_tx: mpsc::Sender<Vec<u8>>,
    ) {
        while let Some(Ok(msg)) = stream.next().await {
            match msg {
                Message::Binary(data) => {
                    let _ = incoming_tx.send(data).await;
                }
                Message::Ping(d) => {
                    let _ = pong_tx.send(d).await;
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
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok(len)
        })
    }

    fn display_name(&self) -> &str {
        "WSS"
    }
}
