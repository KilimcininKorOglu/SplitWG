//! TOML configuration for splitwg-relay.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RelayConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub peers: PeersConfig,
    pub camouflage: Option<CamouflageConfig>,
    #[serde(default)]
    pub padding: Option<PaddingConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PaddingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub min_bytes: u16,
    #[serde(default = "default_padding_max")]
    pub max_bytes: u16,
}

fn default_padding_max() -> u16 {
    256
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_path")]
    pub path: String,
}

fn default_listen() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_path() -> String {
    "/wg".to_string()
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub token_hashes: Vec<String>,
    #[serde(default = "default_max_failed_per_ip")]
    pub max_failed_per_ip: u32,
}

fn default_max_failed_per_ip() -> u32 {
    5
}

#[derive(Debug, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_per_ip_limit")]
    pub per_ip_limit: usize,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            per_ip_limit: default_per_ip_limit(),
            idle_timeout_secs: default_idle_timeout(),
            max_frame_bytes: default_max_frame_bytes(),
        }
    }
}

fn default_max_connections() -> usize {
    100
}
fn default_per_ip_limit() -> usize {
    5
}
fn default_idle_timeout() -> u64 {
    300
}
fn default_max_frame_bytes() -> usize {
    65536
}

#[derive(Debug, Deserialize)]
pub struct PeersConfig {
    #[serde(default = "default_true")]
    pub allow_any: bool,
    #[serde(default)]
    pub allowed: Vec<SocketAddr>,
}

impl Default for PeersConfig {
    fn default() -> Self {
        Self {
            allow_any: true,
            allowed: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize)]
pub struct CamouflageConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_camo_mode")]
    pub mode: String,
    pub site_dir: Option<PathBuf>,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

fn default_camo_mode() -> String {
    "static".to_string()
}

pub fn load(path: &Path) -> Result<RelayConfig> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let config: RelayConfig =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(config)
}
