//! SplitWG — minimal macOS WireGuard tray app with per-config split tunneling.
//!
//! Top-level modules:
//! - [`config`] — Config/Rules types, directory layout, persistence.
//! - [`icon`] — tray icon byte slices (include_bytes).
//! - [`auth`], [`notify`], [`ui`], [`wg`], [`ipc`], [`i18n`], [`runtime`]
//!   — the rest of the runtime surface.

#![cfg_attr(
    target_os = "windows",
    allow(unused_imports, unused_variables, dead_code, unused_parens)
)]

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
compile_error!("SplitWG supports macOS and Windows only");

pub mod auth;
pub mod config;
pub mod gui;
pub mod i18n;
pub mod icon;
pub mod ipc;
pub mod notify;
pub mod runtime;
#[cfg(target_os = "windows")]
pub mod service;
pub mod wg;
