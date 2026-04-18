# SplitWG

Minimal macOS WireGuard tray app with per-config split tunneling.

## Features

- Per-tunnel split tunneling with **include** (whitelist) or **exclude** (blacklist) modes. Rules accept IPs, CIDRs, bare domains, wildcard domains, and `country:XX` entries backed by GeoLite2.
- On-demand activation driven by SSID (trusted / untrusted lists), wired Ethernet, or an always-on flag.
- Per-tunnel kill switch implemented as a scoped `pfctl` anchor — blocks all non-tunnel egress while active.
- `wg-quick`-style PreUp / PostUp / PreDown / PostDown hooks, gated by both a global and a per-tunnel opt-in.
- Touch ID authentication for privileged operations.
- In-app updater with triple verification: minisign signature, SHA-256 digest, and `spctl` / `codesign` notarization check.
- GeoLite2 auto-updater (ASN, City, Country) pulled from a dedicated branch.
- Encrypted `.splitwgpkg` import / export (AES-256) for config backup and sharing.
- QR code decoding for WireGuard config import.
- `x-splitwg://` URL scheme (`connect`, `disconnect`, `toggle`).
- Launch at login via `SMAppService`.
- RTT sparkline and live RX / TX graph on the Status tab.
- Internationalization: English and Turkish, with macOS locale auto-detection.

## Requirements

- macOS 13.0 (Ventura) or newer.
- Apple Silicon or Intel — a universal build is published for each release.

## Install

Via the official Homebrew tap:

```
brew install --cask KilimcininKorOglu/tap/splitwg
```

The cask lives in [`KilimcininKorOglu/homebrew-tap`](https://github.com/KilimcininKorOglu/homebrew-tap) and is refreshed automatically by the release workflow on every `v*` tag push.

## Uninstall

```
brew uninstall --cask --zap splitwg
```

The `--zap` flag also removes `~/.config/splitwg/`, cached data, the preferences plist, and saved application state.

## Configuration

All user data lives under `~/.config/splitwg/`:

| File                    | Mode   | Purpose                                      |
|-------------------------|--------|----------------------------------------------|
| `<name>.conf`           | `0600` | WireGuard config (user-owned).              |
| `<name>.rules.json`     | `0644` | Split-tunnel rules and per-tunnel flags.    |
| `settings.json`         | `0644` | Global preferences (language, hooks, etc.). |
| `splitwg.log`           | `0644` | Append-only app log.                         |

User configs are never deleted or overwritten without an explicit user action. Only `settings.json` is freely rewritten by the app.

## URL scheme

SplitWG registers the `x-splitwg://` scheme via LaunchServices:

```
open x-splitwg://connect/<tunnel-name>
open x-splitwg://disconnect/<tunnel-name>
open x-splitwg://toggle/<tunnel-name>
```

The app is single-instance (`LSUIElement=true`); LaunchServices routes events to the existing process.

## Build from source

```
cargo build --release --bin splitwg --bin splitwg-helper
cargo test --lib
cargo clippy --all-targets -- -D warnings
```

macOS bundle and distribution targets:

```
make bundle              # native-arch .app (Developer ID if in keychain, else ad-hoc)
make bundle-universal    # universal (Intel + Apple Silicon) .app
make dmg                 # universal DMG in dist/
make release             # full signed + notarized + minisign-signed release (CI)
make install             # copy SplitWG.app to /Applications
```

The build is macOS-only: `src/lib.rs` hard-fails on any other target at compile time.

## Release pipeline

Releases are produced by `.github/workflows/release.yml` on `v*` tag pushes. Every artifact receives three independent signatures:

1. Apple Developer ID (codesign, hardened runtime, timestamped).
2. Apple notarization ticket stapled into the DMG.
3. Minisign (ed25519) detached `.minisig` sibling file.

The app verifies the minisign signature and the Team ID of downloaded updates at runtime before installing them, so all three layers must remain trustworthy.

### One-time setup

1. Generate the minisign keypair (runs once per project, private key stored outside git):

   ```
   ./scripts/minisign-keygen.sh
   git add resources/splitwg.pub
   git commit -m "chore: add minisign public key"
   ```

2. Export the Developer ID Application certificate from Keychain Access as a `.p12` file. Note the password.

3. Create an app-specific password at appleid.apple.com.

4. Add the following secrets to the GitHub repository:

   | Secret                        | Value                                                  |
   |-------------------------------|--------------------------------------------------------|
   | `APPLE_DEVELOPER_ID_CERT_P12` | `base64 -i cert.p12`                                   |
   | `APPLE_DEVELOPER_ID_CERT_PWD` | .p12 password                                          |
   | `APPLE_ID`                    | Developer account email                                |
   | `APPLE_TEAM_ID`               | 10-character Team ID (e.g. `ABC1234567`)               |
   | `APPLE_APP_SPECIFIC_PWD`      | App-specific password from appleid.apple.com           |
   | `MINISIGN_KEY`                | `base64 -i ~/.minisign/splitwg.key`                    |
   | `MINISIGN_KEY_PWD`            | Minisign key passphrase                                |
   | `HOMEBREW_TAP_TOKEN`          | GitHub PAT with `repo` scope on `homebrew-tap`         |

### Local release smoke test

With a Developer ID in the keychain and the notary profile seeded via `xcrun notarytool store-credentials splitwg-notary …`:

```
make release
spctl -a -vv -t install dist/SplitWG.dmg
minisign -V -p resources/splitwg.pub -m dist/SplitWG.dmg
```

`spctl` should print `accepted, source=Notarized Developer ID`.

### Cutting a release

The automated path is the Claude Code `/version-update [major | minor | patch]` skill, which bumps all version files, regenerates the changelog, tags, and pushes in one step.

The equivalent manual flow:

```
# Bump version in Cargo.toml, Cargo.lock (splitwg block only),
# Info.plist, Contents/Info.plist, and homebrew-tap/Casks/splitwg.rb.
cargo build --release --bin splitwg --bin splitwg-helper
# Update CHANGELOG.md.
git add -A
git commit -m "chore: bump version to 1.0.1"
git tag -a v1.0.1 -m "v1.0.1"
git push && git push --tags
```

The workflow then builds all three DMGs, notarizes and staples each one, signs them with minisign, publishes a GitHub Release with six assets (three DMGs and three `.minisig` siblings), and rewrites the Homebrew tap cask.

### Key rotation

The minisign public key is compiled into the binary via `include_str!`. Rotating the private key therefore requires cutting a new release with the new public key first; users running older versions must install the new build manually before future auto-updates resume.
