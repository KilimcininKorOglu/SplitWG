//! SplitWG — minimal macOS WireGuard tray app with per-config split tunneling.
//!
//! Top-level modules:
//! - [`config`] — Config/Rules types, directory layout, persistence.
//! - [`icon`] — tray icon byte slices (include_bytes).
//! - [`auth`], [`notify`], [`ui`], [`wg`], [`ipc`], [`i18n`], [`runtime`]
//!   — the rest of the runtime surface.

#[cfg(not(target_os = "macos"))]
compile_error!("SplitWG only supports macOS");

pub mod auth;
pub mod config;
pub mod gui;
pub mod i18n;
pub mod icon;
pub mod ipc;
pub mod notify;
pub mod runtime;
pub mod wg;
