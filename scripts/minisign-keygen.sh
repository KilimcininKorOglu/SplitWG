#!/usr/bin/env bash
# Generates a minisign keypair for signing SplitWG release artifacts.
#
# Usage:
#   ./scripts/minisign-keygen.sh
#
# This script should be run ONCE during project setup. After running:
#
#   1. Commit `resources/splitwg.pub` to the repository. This public key is
#      compiled into the binary via `include_str!` and used to verify every
#      downloaded update.
#
#   2. Store `~/.minisign/splitwg.key` as a GitHub secret named MINISIGN_KEY
#      (base64-encoded) and its password as MINISIGN_KEY_PWD.
#
#      base64 -i ~/.minisign/splitwg.key | pbcopy
#
#   3. NEVER commit the private key. Rotating it requires releasing a new
#      binary (because the public key is embedded at compile time).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MINISIGN_DIR="${HOME}/.minisign"
PRIVATE_KEY="${MINISIGN_DIR}/splitwg.key"
PUBLIC_KEY="${MINISIGN_DIR}/splitwg.pub"
PUBLIC_KEY_DEST="${REPO_ROOT}/resources/splitwg.pub"

if ! command -v minisign >/dev/null 2>&1; then
    echo "error: minisign is not installed. Install with: brew install minisign" >&2
    exit 1
fi

mkdir -p "${MINISIGN_DIR}"
mkdir -p "${REPO_ROOT}/resources"

if [[ -f "${PRIVATE_KEY}" ]]; then
    echo "error: ${PRIVATE_KEY} already exists. Refusing to overwrite." >&2
    echo "       Remove it manually if you truly want to rotate keys." >&2
    exit 1
fi

minisign -G -s "${PRIVATE_KEY}" -p "${PUBLIC_KEY}"
cp "${PUBLIC_KEY}" "${PUBLIC_KEY_DEST}"

echo ""
echo "Public key written to:  ${PUBLIC_KEY_DEST}"
echo "Private key written to: ${PRIVATE_KEY}"
echo ""
echo "Next steps:"
echo "  1. git add resources/splitwg.pub && git commit"
echo "  2. Add GitHub secret MINISIGN_KEY:"
echo "       base64 -i ${PRIVATE_KEY} | pbcopy"
echo "  3. Add GitHub secret MINISIGN_KEY_PWD with the passphrase you just set."
