# SplitWG

Minimal macOS WireGuard tray app with per-config split tunneling.

## Install (Homebrew)

```
brew install --cask KilimcininKorOglu/tap/splitwg
```

The cask lives in the [`KilimcininKorOglu/homebrew-tap`](https://github.com/KilimcininKorOglu/homebrew-tap)
tap and is refreshed automatically by the release workflow on every
`v*` tag push. macOS 13 Ventura or newer is required.

## Build

```
cargo build --release --bin splitwg --bin splitwg-helper
cargo test --lib
cargo clippy --all-targets -- -D warnings
```

macOS bundle:

```
make bundle              # native arch .app (Developer ID if in keychain, else ad-hoc)
make bundle-universal    # universal (Intel + Apple Silicon) .app
make dmg                 # universal DMG in dist/
make release             # full signed + notarized + minisign-signed release (CI)
make install             # copy SplitWG.app to /Applications
```

Platform: macOS 13.0+ only. Do not attempt to build on Linux — `src/lib.rs`
hard-fails at compile time.

## Release pipeline

Releases are produced by `.github/workflows/release.yml` on `v*` tag pushes.
Every artifact receives three independent signatures:

1. Apple Developer ID (codesign, hardened runtime, timestamped).
2. Apple notarization ticket stapled into the DMG.
3. Minisign (ed25519) detached signature as a `.minisig` sibling file.

The app verifies the minisign signature and the Team ID of downloaded updates
at runtime before installing them, so all three layers must remain trustworthy.

### One-time setup

1. Generate the minisign keypair (runs once per project, stored outside git):

   ```
   ./scripts/minisign-keygen.sh
   git add resources/splitwg.pub
   git commit -m "chore: add minisign public key"
   ```

2. Export the Developer ID Application certificate from Keychain Access as a
   `.p12` file. Note the password.

3. Create an app-specific password at appleid.apple.com.

4. Add the following secrets to the GitHub repository:

   | Secret                        | Value                                                   |
   |-------------------------------|---------------------------------------------------------|
   | `APPLE_DEVELOPER_ID_CERT_P12` | `base64 -i cert.p12`                                     |
   | `APPLE_DEVELOPER_ID_CERT_PWD` | .p12 password                                            |
   | `APPLE_ID`                    | Developer account email                                  |
   | `APPLE_TEAM_ID`               | 10-character Team ID (e.g. `ABC1234567`)                 |
   | `APPLE_APP_SPECIFIC_PWD`      | App-specific password from appleid.apple.com            |
   | `MINISIGN_KEY`                | `base64 -i ~/.minisign/splitwg.key`                      |
   | `MINISIGN_KEY_PWD`            | Minisign key passphrase                                  |
   | `HOMEBREW_TAP_TOKEN`          | GitHub PAT with `repo` scope on `homebrew-tap`           |

### Local release smoke test

With a Developer ID in the keychain and the notary profile seeded via
`xcrun notarytool store-credentials splitwg-notary …`:

```
make release
spctl -a -vv -t install dist/SplitWG.dmg
minisign -V -p resources/splitwg.pub -m dist/SplitWG.dmg
```

`spctl` should print `accepted, source=Notarized Developer ID`.

### Cutting a release

```
git tag v0.2.2
git push origin v0.2.2
```

The workflow builds all three DMGs, notarizes and staples each one, signs them
with minisign, and publishes a GitHub Release with six assets (three DMGs and
three `.minisig` siblings).

### Key rotation

The minisign public key is compiled into the binary via `include_str!`. Rotating
the private key therefore requires cutting a new release with the new public
key first; users running older versions will need to install the new build
manually before future auto-updates resume.
