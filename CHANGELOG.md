# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-04-19

### Added

- About SplitWG window accessible from the tray menu, showing app logo, version, GitHub repository link, and developer profile link.

### Changed

- Extract `find_config` helper in tray_host to eliminate duplicated config-load-and-notify blocks in `toggle_tunnel` and `toggle_tunnel_hooks`.
- Add `conf_path` and `rules_path` helpers to the config module, replacing scattered `config_dir().join(format!(...))` calls.

## [1.1.0] - 2026-04-19

### Changed

- Unify three separate connect paths (GUI toggle, tray menu, on-demand) into a single `ensure_connected` function with a `ConnectError` enum, eliminating duplicated sudoers-check and Touch ID logic.

### Fixed

- Add sudoers setup guard to the tray menu and on-demand connect paths. The previous fix (v1.0.4) only covered the GUI window activate button; tray menu clicks still failed silently with `sudo: a password is required`.

## [1.0.4] - 2026-04-19

### Changed

- Rewrite README for end-user audience with full feature coverage, example rules, and GUI-managed workflow clarification.
- Sync `Contents/Info.plist` with root plist (add missing `LSMinimumSystemVersion`, location usage descriptions, and URL scheme entries).

### Fixed

- Trigger one-time sudoers setup before first tunnel connect. `Manager::connect` uses `sudo -n` which silently fails when `/etc/sudoers.d/splitwg` is missing; the activate button now runs the setup prompt automatically.
- Eliminate flaky `search_paths_includes_home_config` test caused by concurrent `HOME` env var mutations across parallel test threads.

## [1.0.3] - 2026-04-19

### Changed

- Remove unnecessary hardened-runtime entitlements that were tripping Gatekeeper. `com.apple.security.cs.disable-library-validation` affects Gatekeeper (per Apple DTS) and was superfluous because SplitWG's binaries only load `/System/Library/*` frameworks and `/usr/lib/*` — no `@rpath`, no third-party dylibs. `com.apple.security.network.client` is an App Sandbox entitlement and the sandbox is disabled. The remaining `com.apple.security.automation.apple-events` is kept for `osascript` notifications under the hardened runtime.

## [1.0.2] - 2026-04-19

### Changed

- Rename bundle id from `com.local.splitwg` to `com.kilimcininkoroglu.splitwg`. The `com.local.*` namespace is silently rejected by Apple Gatekeeper's CloudKit allow-list even when `notarytool` reports `Accepted`. Moving to a real reverse-DNS identifier allows the notarized build to launch cleanly on end-user machines.

## [1.0.1] - 2026-04-18

### Changed

- Update README table formatting.
- Ignore `RELEASE-GUIDE.md` in the project gitignore.

### Fixed

- Fail the release pipeline on notarize, staple, or signing errors. The Makefile `notarize` and `sign-minisign` loops now run under `set -euo pipefail` and validate the stapled ticket; the workflow Verify step no longer swallows `spctl` rejection with `|| true` and now invokes `xcrun stapler validate`, so an unnotarized DMG aborts CI before `Publish GitHub Release` and the Homebrew cask bump.

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
