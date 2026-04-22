//! Transport abstraction for WireGuard encrypted datagrams.
//!
//! `WgTransport` decouples gotatun's encrypted output from the network
//! layer. The default `UdpTransport` wraps a connected `UdpSocket` (the
//! existing behavior). Future transports (WebSocket, QUIC) implement the
//! same trait so the data-plane tasks are transport-agnostic.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;

pub trait WgTransport: Send + Sync + 'static {
    fn send<'a>(&'a self, buf: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

    fn recv<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + 'a>>;

    fn display_name(&self) -> &str;
}

pub struct UdpTransport {
    socket: Arc<UdpSocket>,
}

impl UdpTransport {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
        }
    }
}

impl WgTransport for UdpTransport {
    fn send<'a>(&'a self, buf: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.socket.send(buf).await?;
            Ok(())
        })
    }

    fn recv<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize>> + Send + 'a>> {
        Box::pin(async move { Ok(self.socket.recv(buf).await?) })
    }

    fn display_name(&self) -> &str {
        "UDP"
    }
}
