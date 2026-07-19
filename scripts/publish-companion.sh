#!/usr/bin/env bash
# Publish companion/ to the PUBLIC deploy-mirror repo
# (github.com/ObjSal/chain-notes-companion → GitHub Pages).
# Canonical source stays here; never edit the mirror directly.
set -euo pipefail

MIRROR="${COMPANION_MIRROR:-$HOME/Projects/chain-notes-companion}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

[ -d "$MIRROR/.git" ] || { echo "mirror checkout not found at $MIRROR" >&2; exit 1; }
cp "$HERE/companion/index.html" "$HERE/companion/viewer.html" \
   "$HERE/companion/note.html" "$HERE/companion/chain-scan.js" \
   "$HERE/companion/owner-probe.js" \
   "$HERE/companion/server.py" \
   "$HERE/companion/jsqr.js" "$HERE/companion/qrcode-gen.js" \
   "$HERE/companion/ur.js" "$MIRROR/"
cd "$MIRROR"
if [ -z "$(git status --porcelain)" ]; then
    echo "mirror already up to date"
    exit 0
fi
git add index.html viewer.html note.html chain-scan.js owner-probe.js server.py jsqr.js qrcode-gen.js ur.js
git commit -m "Sync from prime-chain-notes companion/ ($(cd "$HERE" && git rev-parse --short HEAD))"
git push
echo "published — https://objsal.github.io/chain-notes-companion/"
