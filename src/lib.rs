//! SplitWG — minimal macOS WireGuard tray app with per-config split tunneling.
//!
//! Top-level modules:
//! - [`config`] — Config/Rules types, directory layout, persistence.
//! - [`icon`] — tray icon byte slices (include_bytes).
//! - [`auth`], [`notify`], [`ui`], [`wg`], [`ipc`], [`i18n`], [`runtime`]
//!   — the rest of the runtime surface.

#![cfg_attr(
    any(target_os = "windows", target_os = "linux"),
    allow(unused_imports, unused_variables, dead_code, unused_parens)
)]

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
compile_error!("SplitWG supports macOS, Windows, and Linux only");

pub mod auth;
pub mod config;
pub mod gui;
pub mod i18n;
pub mod icon;
pub mod ipc;
pub mod notify;
pub mod runtime;
#[cfg(any(target_os = "windows", target_os = "linux"))]
pub mod service;
pub mod wg;
