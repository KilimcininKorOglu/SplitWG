# SplitWG

A native macOS menu-bar application for WireGuard with per-tunnel split tunneling, on-demand activation, and an auditable update pipeline.

SplitWG is built for users who understand WireGuard and want a focused, transparent tool on macOS. The entire data plane runs in userspace -- no kernel module, no `wg-quick` binary, no dependency on `wireguard-go`. It runs as a tray-only application with a clear privilege boundary between the user-facing process and a root helper, and ships every release with three independent signature layers.

---

## Requirements

- macOS 13.0 Ventura or newer
- Apple Silicon or Intel (every release ships a universal binary)

## Installation

**Homebrew (recommended):**

```
brew install --cask KilimcininKorOglu/tap/splitwg
```

The cask is updated automatically on every release, so `brew upgrade splitwg` always resolves to the latest signed build.

**Direct download:**

Every release publishes three DMGs -- universal, Intel-only, and Apple Silicon-only -- each accompanied by a `.minisig` signature file. See the [Releases](https://github.com/KilimcininKorOglu/SplitWG/releases) page.

## Uninstall

```
brew uninstall --cask --zap splitwg
```

The `--zap` flag removes `~/.config/splitwg/`, the cache directory, the preferences plist, and saved application state.

---

## Features

### Split Tunneling

Route traffic selectively on a per-tunnel basis. Each tunnel operates in one of two modes:

- **Include** -- only the listed destinations are routed through the tunnel.
- **Exclude** -- everything is routed through the tunnel except the listed destinations.

Rules accept IPs, CIDRs, bare domains, wildcard domains (`*.example.com`), country codes (`country:TR`), and ASN numbers (`asn:13335`) resolved against GeoLite2 databases. Built-in rule templates provide ready-made CIDR lists for popular services so you can apply them in one click.

### On-Demand Activation

Tunnels can connect and disconnect automatically based on network conditions. The evaluator checks the following in order; the first match wins:

| Priority | Condition                                        | Action     |
|----------|--------------------------------------------------|------------|
| 1        | Current SSID is on the untrusted list            | Disconnect |
| 2        | Current SSID is on the trusted list              | Connect    |
| 3        | Tunnel is marked always-on                       | Connect    |
| 4        | `activate_on_ethernet` is set and link is wired  | Connect    |
| 5        | `activate_on_wifi` is set and any SSID is active | Connect    |
| 6        | None of the above                                | Disconnect |

An optional **schedule gate** can restrict on-demand rules to specific days and hours. Select the active weekdays and an hour window (e.g. Monday--Friday, 09:00--18:00); outside that window the tunnel is automatically disconnected regardless of network state. Overnight windows that wrap past midnight are supported.

Tunnels can be grouped with an **exclusive group** tag: when two or more tunnels share the same group, at most one may be active at a time. The on-demand evaluator arbitrates automatically.

An empty rule never forces state. Manual toggles from the tray install a one-shot override that the evaluator honours until the rule is edited or the app restarts.

### Kill Switch

An optional per-tunnel firewall anchor that blocks all non-tunnel traffic while the tunnel is active. The anchor is scoped to the tunnel's interface and is automatically flushed on teardown.

### Connection Watchdog

Active tunnels are monitored for stale handshakes. When connectivity drops, SplitWG automatically attempts to reconnect. After three consecutive failures the watchdog enters a 10-minute cooldown to avoid burning resources on a broken config. Each reconnect attempt and cooldown event is surfaced as a notification.

### Hook Execution

Standard `PreUp`, `PostUp`, `PreDown`, and `PostDown` hooks from `.conf` files are supported. Hooks run as root with a 30-second timeout and `%i` interface substitution. Execution requires explicit opt-in at two levels: a global switch in Preferences and a per-tunnel flag in the rules file.

### Authentication

The helper process runs as root via `sudo`. On first launch, SplitWG prompts for your password to configure passwordless `sudo` for the helper binary. Subsequent connections require no authentication. Touch ID gating can be re-enabled in the source if desired.

### Import and Export

- **File import** -- open a `.conf` file through the Add dialog or drag and drop it onto the main window. The config is parsed and validated before import; warnings are shown for missing DNS, unusual MTU values, missing PersistentKeepalive, catch-all AllowedIPs in include mode, or multiple peers. Private keys are masked in the preview.
- **QR code import** -- paste a screenshot of a WireGuard QR code and SplitWG decodes and imports the configuration.
- **Encrypted backup** -- export selected configurations as a `.splitwgpkg` archive (AES-256 encrypted) for portable backup or sharing.

### URL Scheme

Control tunnels from Shortcuts, AppleScript, or any launcher:

```
open x-splitwg://connect/<tunnel-name>
open x-splitwg://disconnect/<tunnel-name>
open x-splitwg://toggle/<tunnel-name>
```

Events are routed to the running instance; a second copy is never spawned.

### Tray Menu

Each tunnel has its own submenu with a connect/disconnect toggle, an Edit Rules shortcut, and a per-tunnel hooks indicator. The Preferences submenu provides quick access to hooks, language, launch at login, kill switch, update checks, and GeoIP database sync -- all without opening the main window. The tray tooltip shows per-tunnel connection status and aggregated throughput. An "Open Config Directory" item reveals `~/.config/splitwg/` in Finder.

### Additional Features

- **Live status** -- RTT sparkline and RX/TX throughput graph on the Status tab, with parsed interface and peer details (public key, endpoint, last handshake, transfer counters).
- **Log viewer** -- real-time log tailing on the Logs tab with an optional per-tunnel filter.
- **Launch at login** -- opt-in toggle backed by `SMAppService`.
- **Dark and light mode** -- follows the macOS system appearance automatically.
- **Localization** -- English and Turkish with automatic macOS locale detection.
- **Automatic updates** -- background check every 24 hours with full signature verification before install. The check can be disabled from Preferences.
- **GeoLite2 sync** -- country database is kept current via daily automatic updates.

---

## Configuration

All user data lives under `~/.config/splitwg/`:

| File                | Permissions | Description                                 |
|---------------------|-------------|---------------------------------------------|
| `<name>.conf`       | 0600        | WireGuard configuration                     |
| `<name>.rules.json` | 0644        | Split-tunnel rules and per-tunnel flags     |
| `settings.json`     | 0644        | Global preferences (language, hooks, etc.)  |
| `splitwg.log`       | 0644        | Append-only application log                 |

User configurations are never auto-deleted or overwritten. Only `settings.json` is written by the app during normal operation.

### Rules

Split-tunnel rules are managed entirely through the Rules tab in the Manage Tunnels window. Select include or exclude mode, add entries, apply built-in templates, and configure on-demand and schedule settings -- all from the GUI. Changes are persisted automatically as `<name>.rules.json` in the config directory.

Supported entry types:

| Type          | Example             | Description                                |
|---------------|---------------------|--------------------------------------------|
| CIDR range    | `10.0.0.0/8`        | IPv4 or IPv6 prefix                        |
| Single IP     | `192.0.2.15`        | Individual address                         |
| Exact host    | `vpn.example.com`   | Resolved to A and AAAA records             |
| Wildcard host | `*.example.net`     | Matches all subdomains                     |
| Country code  | `country:TR`        | ISO 3166 alpha-2, resolved via GeoLite2    |
| ASN number    | `asn:13335`         | Autonomous system, resolved via GeoLite2   |

### Example Rules

The JSON examples below show the underlying format for reference. In practice, these are created and edited through the GUI.

**Stream Netflix US through a US exit node** -- include mode routes only Netflix traffic through the tunnel, everything else goes direct:

```json
{
  "mode": "include",
  "entries": [
    "23.246.0.0/18",
    "45.57.0.0/17",
    "64.120.128.0/17",
    "108.175.32.0/20",
    "192.173.64.0/18"
  ],
  "hooks_enabled": false
}
```

**Route everything except Turkish banks through the tunnel** -- exclude mode keeps banking traffic on the local ISP for latency and compliance:

```json
{
  "mode": "exclude",
  "entries": [
    "195.214.180.0/22",
    "212.174.0.0/16",
    "213.14.0.0/16",
    "195.46.80.0/20",
    "81.214.0.0/16"
  ],
  "hooks_enabled": false
}
```

**Route an entire country through the tunnel:**

```json
{
  "mode": "include",
  "entries": [
    "country:DE"
  ],
  "hooks_enabled": false
}
```

**Block ads and trackers by domain while tunneled:**

```json
{
  "mode": "exclude",
  "entries": [
    "*.doubleclick.net",
    "*.googlesyndication.com",
    "*.facebook.com",
    "analytics.google.com"
  ],
  "hooks_enabled": false
}
```

Built-in templates for Netflix US, BBC iPlayer, Turkish banks, Spotify, and YouTube are available in the Rules tab and can be applied in one click.

---

## Security

### Update Verification

Every downloaded update is verified through three independent checks before installation:

| Layer        | What it proves                                         |
|--------------|--------------------------------------------------------|
| Developer ID | Binary is signed with a hardened runtime and timestamp |
| Apple notary | Apple has scanned and approved the build               |
| Minisign     | Build originates from this project's signing key       |

A SHA-256 digest check against the GitHub release metadata provides an additional integrity gate. A failure at any stage aborts the update and reports the reason.

### Privilege Separation

The application enforces a strict two-process architecture. The tray process runs as the current user and handles all UI, configuration, and decision-making. Network operations that require root -- creating the tunnel interface, setting routes, managing DNS, and loading firewall anchors -- are handled by a separate helper process invoked via `sudo`. The two communicate over a typed JSON protocol on standard I/O. Neither process exceeds its role.

---

## Build from Source

```
cargo build --release --bin splitwg --bin splitwg-helper
cargo test --lib
cargo clippy --all-targets -- -D warnings
```

Requires Rust 1.88 or newer. macOS bundle and distribution targets:

```
make bundle              # native-arch .app (Developer ID or ad-hoc)
make bundle-universal    # universal (Intel + Apple Silicon) .app
make dmg                 # universal DMG in dist/
make release             # signed + notarized + minisign release
make install             # copy SplitWG.app to /Applications
```

The release profile produces a compact binary with `opt-level = "z"`, LTO, single codegen unit, symbol stripping, and abort-on-panic.

## Contributing

Issues and pull requests are welcome. Before submitting a PR:

```
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --lib
```

SplitWG is intentionally small. New features should have a clear connection to WireGuard, macOS integration, or the security pipeline. Cross-platform ports are out of scope.

## License

SplitWG is released under the [MIT License](LICENSE).
