mod auth;
mod config;
mod session;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;

struct AppState {
    config: config::RelayConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match parse_command() {
        Command::HashToken(plaintext) => hash_token(&plaintext),
        Command::Serve(config_path) => serve(config_path).await,
    }
}

async fn serve(config_path: PathBuf) -> anyhow::Result<()> {
    env_logger::init();

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
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    auth::validate_token(&headers, &state.config.auth.token_hashes)?;

    let target = parse_target(&headers)?;
    check_peer(&state.config.peers, target)?;

    let idle_timeout = Duration::from_secs(state.config.limits.idle_timeout_secs);
    let max_frame_bytes = state.config.limits.max_frame_bytes;

    Ok(ws
        .on_upgrade(move |socket| {
            session::handle_session(socket, target, idle_timeout, max_frame_bytes)
        })
        .into_response())
}

fn parse_target(headers: &HeaderMap) -> Result<SocketAddr, StatusCode> {
    headers
        .get("X-Target")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?
        .parse::<SocketAddr>()
        .map_err(|_| StatusCode::BAD_REQUEST)
}

fn check_peer(peers: &config::PeersConfig, target: SocketAddr) -> Result<(), StatusCode> {
    if peers.allow_any {
        return Ok(());
    }
    if peers.allowed.contains(&target) {
        return Ok(());
    }
    Err(StatusCode::FORBIDDEN)
}

fn hash_token(plaintext: &str) -> anyhow::Result<()> {
    use argon2::{Argon2, PasswordHasher};
    use password_hash::rand_core::OsRng;
    use password_hash::SaltString;

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{hash}");
    Ok(())
}

enum Command {
    HashToken(String),
    Serve(PathBuf),
}

fn parse_command() -> Command {
    let mut args = std::env::args().skip(1);
    if let Some(arg) = args.next() {
        if arg == "hash-token" {
            let plaintext = args.next().unwrap_or_else(|| {
                eprintln!("usage: splitwg-relay hash-token <plaintext>");
                std::process::exit(1);
            });
            return Command::HashToken(plaintext);
        }
        if arg == "--config" {
            if let Some(path) = args.next() {
                return Command::Serve(PathBuf::from(path));
            }
        }
    }
    Command::Serve(PathBuf::from("relay.toml"))
}
