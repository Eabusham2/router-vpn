#!/usr/bin/env bash
set -euo pipefail
BASE=${1:-/opt/router-vpn}
BUNDLE="$BASE/client-bundle"
mkdir -p "$BUNDLE"

# Refresh only the small public runtime/catalog. Never replace generated private
# profiles, router choices, tokens, or the client config created for this node.
# Platform binaries remain in immutable /src/dist inside the server image and
# are read only for an on-demand local fallback package; they are not duplicated
# into persistent AI Board storage.
cp /src/configs/client/modes.json "$BUNDLE/modes.json"
cp /src/configs/client/logical-modes.json "$BUNDLE/logical-modes.json"
cp /src/LICENSE "$BUNDLE/LICENSE"
rm -rf "$BUNDLE/modes" "$BUNDLE/client" "$BUNDLE/dist"
cp -a /src/modes "$BUNDLE/modes"
cp -a /src/client "$BUNDLE/client"
chmod +x "$BUNDLE/modes/"*.sh "$BUNDLE/client/"*.sh 2>/dev/null || true
printf 'Synced current client runtime/catalog/license; platform binaries stay in the image and are packaged only on demand.\n'
