#!/usr/bin/env bash
# Publish companion/ to the PUBLIC deploy-mirror repo
# (github.com/ObjSal/chain-notes-companion → GitHub Pages).
# Canonical source stays here; never edit the mirror directly.
set -euo pipefail

MIRROR="${COMPANION_MIRROR:-$HOME/Projects/chain-notes-companion}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

[ -d "$MIRROR/.git" ] || { echo "mirror checkout not found at $MIRROR" >&2; exit 1; }
cp "$HERE/companion/index.html" "$HERE/companion/server.py" "$MIRROR/"
cd "$MIRROR"
if git diff --quiet && git diff --cached --quiet; then
    echo "mirror already up to date"
    exit 0
fi
git add index.html server.py
git commit -m "Sync from prime-chain-notes companion/ ($(cd "$HERE" && git rev-parse --short HEAD))"
git push
echo "published — https://objsal.github.io/chain-notes-companion/"
