# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-18

### Added

- Initial public release of SplitWG — a minimal macOS WireGuard tray app with per-config split tunneling.
- Two-binary architecture: user-level tray (`splitwg`) and root helper (`splitwg-helper`) communicating over JSON-lines IPC.
- Per-tunnel split-tunnel rules (include/exclude modes) with IP, CIDR, bare domain, and wildcard domain support.
- On-demand activation driven by SSID (trusted/untrusted), wired Ethernet, and "always" rules.
- Per-tunnel kill switch implemented as a scoped pfctl anchor.
- wg-quick-style PreUp/PostUp/PreDown/PostDown hooks, gated by global and per-tunnel opt-ins.
- Touch ID authentication for privileged operations.
- Internationalization (English and Turkish) with macOS locale auto-detection.
- GeoLite2 auto-updater (ASN, City, Country) pulling from the project's `geodb` branch.
- In-app updater with triple verification: minisign signature, SHA-256 digest, and codesign/spctl notarization check.
- `x-splitwg://` URL scheme for `connect`, `disconnect`, and `toggle` commands.
- RTT sparkline and live RX/TX graph on the Status tab.
- Encrypted `.splitwgpkg` import/export using AES-256.
- QR code decoding for WireGuard config import.
- "Launch at login" toggle via `SMAppService` (requires macOS 13.0+).
- Universal, Intel-only, and Apple Silicon-only DMG build targets.
- GitHub Actions release pipeline with Developer ID codesign, hardened runtime, notarization, and minisign signing.
- Homebrew cask distribution via `KilimcininKorOglu/homebrew-tap`.
