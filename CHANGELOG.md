# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.1.0] - 2026-04-19

### Added

- Auto-show window when a new update is available
- Tunnel rename with full state re-keying
- Inline config editor modal for editing .conf files from the Status tab

### Fixed

- Correct copyright holder name

## [1.0.0] - 2026-04-19

### Added

- Userspace WireGuard data plane via gotatun (Mullvad's boringtun fork)
- Per-tunnel split tunneling with include and exclude modes
- Rule entries: IP, CIDR, domain, wildcard domain, country code, ASN number
- On-demand activation with SSID, ethernet, wifi, schedule, and exclusive group support
- Kill switch via per-tunnel pf anchor
- Connection watchdog with auto-reconnect and cooldown
- Hook execution (PreUp, PostUp, PreDown, PostDown) with two-gate opt-in
- QR code and drag-and-drop config import
- Encrypted backup export (.splitwgpkg, AES-256)
- URL scheme (x-splitwg://connect, disconnect, toggle)
- Live status with RTT sparkline and RX/TX throughput graph
- Real-time log viewer with per-tunnel filter
- In-app updater with three-layer signature verification (Developer ID, Apple notary, minisign)
- GeoLite2 auto-updater for country and ASN databases
- Launch at login via SMAppService
- Dark and light mode with automatic detection
- English and Turkish localization
- Homebrew cask distribution
