#!/usr/bin/env bash
# Create a drag-to-Applications DMG for macOS.
# Uses create-dmg (brew) if available; falls back to built-in hdiutil.
#
# Usage: make-dmg.sh <Source.app> <output.dmg> <VolumeName>

set -euo pipefail

APP=${1:?"Usage: $0 <Source.app> <output.dmg> <VolumeName>"}
DMG=${2:?}
VOLNAME=${3:?}
APPNAME="SplitWG.app"

rm -f "$DMG"

# Always rename to SplitWG.app inside the DMG, regardless of source bundle name.
STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT
cp -r "$APP" "$STAGING/$APPNAME"

# Install.command — double-click installer that copies the app and strips
# the quarantine attribute so Gatekeeper doesn't block it on first launch.
cat > "$STAGING/Install SplitWG.command" <<'EOF'
#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "Installing SplitWG to /Applications ..."
cp -r "$SCRIPT_DIR/SplitWG.app" /Applications/
xattr -cr /Applications/SplitWG.app
echo "Done. Launching SplitWG..."
open /Applications/SplitWG.app
EOF
chmod +x "$STAGING/Install SplitWG.command"

if command -v create-dmg &>/dev/null; then
    # Produces a polished DMG with background arrow and window layout.
    create-dmg \
        --volname   "$VOLNAME" \
        --window-size 540 380 \
        --icon-size 128 \
        --icon      "$APPNAME" 130 170 \
        --app-drop-link 400 170 \
        --hide-extension "$APPNAME" \
        "$DMG" \
        "$STAGING/$APPNAME"
else
    # Built-in hdiutil fallback — no extra dependencies, works in CI.
    ln -s /Applications "$STAGING/Applications"
    hdiutil create \
        -volname    "$VOLNAME" \
        -srcfolder  "$STAGING" \
        -ov \
        -format     UDBZ \
        "$DMG"
fi

echo "$(basename "$DMG")  ($(du -sh "$DMG" | cut -f1))"
