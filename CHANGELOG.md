# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.1.1] - 2026-04-20

### Added

- Ping all active tunnels from tray menu

### Fixed

- Resolve RUSTSEC-2025-0132: upgrade maxminddb 0.24 to 0.27 (unsound `open_mmap`)
- Set tunnel DNS as system default resolver via SupplementalMatchDomains
- Reject tunnel names with path traversal characters on package import
- Restrict GeoLite workflow repository_dispatch to typed events only
- Gate release workflow behind production environment
- Shell-quote helper path in sudoers setup to prevent injection
- Wrap osascript shell command in shell_quote to neutralize metacharacters
- Require user confirmation for URL scheme tunnel actions
- Pin all GitHub Actions to immutable SHA digests
- Create log file with owner-only permissions (0600)
- Redact key material in Debug output of IPC and config structs
- Eliminate TOCTOU race in write_with_mode by setting permissions at creation
- Scope sudoers NOPASSWD rule to the installing user instead of entire admin group

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
