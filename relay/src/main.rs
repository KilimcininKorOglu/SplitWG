//! splitwg-relay — WebSocket-to-UDP relay for SplitWG obfuscation.
//!
//! Accepts WSS connections from SplitWG clients, extracts WireGuard
//! datagrams from binary frames, and forwards them as UDP to the
//! configured WireGuard peer endpoint. Serves a decoy website on
//! normal HTTP requests.
//!
//! Usage:
//!   splitwg-relay --config relay.toml
//!   splitwg-relay                        # uses ./relay.toml

mod config;

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;

struct AppState {
    config: config::RelayConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config_path = parse_args();
    log::info!(
        "splitwg-relay: loading config from {}",
        config_path.display()
    );
    let config = config::load(&config_path)?;

    let listen = config.server.listen.clone();
    let path = config.server.path.clone();

    log::info!("splitwg-relay: listening on {listen}, path: {path}");

    let state = Arc::new(AppState { config });

    let app = Router::new()
        .route(&path, get(ws_handler))
        .with_state(state);

    let listener = TcpListener::bind(&listen).await?;
    log::info!("splitwg-relay: server started");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(handle_socket)
}

async fn handle_socket(mut socket: WebSocket) {
    log::info!("splitwg-relay: new WebSocket connection");
    while let Some(Ok(msg)) = socket.recv().await {
        match msg {
            Message::Binary(data) => {
                log::debug!("splitwg-relay: received {} bytes", data.len());
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    log::info!("splitwg-relay: connection closed");
}

fn parse_args() -> PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            if let Some(path) = args.next() {
                return PathBuf::from(path);
            }
        }
    }
    PathBuf::from("relay.toml")
}
