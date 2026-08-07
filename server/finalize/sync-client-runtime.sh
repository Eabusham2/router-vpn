#!/usr/bin/env bash
set -euo pipefail
BASE=${1:-/opt/router-vpn}
BUNDLE="$BASE/client-bundle"
mkdir -p "$BUNDLE"

# Refresh only public runtime/build files. Never replace generated private profiles,
# router choices, tokens, or the client config created for this installation.
cp /src/configs/client/modes.json "$BUNDLE/modes.json"
rm -rf "$BUNDLE/modes" "$BUNDLE/client" "$BUNDLE/dist"
cp -a /src/modes "$BUNDLE/modes"
cp -a /src/client "$BUNDLE/client"
cp -a /src/dist "$BUNDLE/dist"
chmod +x "$BUNDLE/modes/"*.sh "$BUNDLE/client/"*.sh 2>/dev/null || true
printf 'Synced current client runtime/catalog without replacing private generated profiles.\n'
