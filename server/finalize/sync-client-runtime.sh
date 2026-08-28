#!/usr/bin/env bash
set -euo pipefail
BASE=${1:-/opt/router-vpn}
BUNDLE="$BASE/client-bundle"
PRIVATE_DIR=/src/server/scripts/private-directory.py
PRIVATE_BATCH=/src/server/scripts/atomic-private-batch.py
VERIFIED_READ=/src/server/scripts/verified-regular-read.py

python3 "$PRIVATE_DIR" "$BUNDLE"
STAGE=$(mktemp -d "$BUNDLE/.runtime-metadata.XXXXXX")
cleanup(){ rm -rf -- "$STAGE"; }
trap cleanup EXIT

# Persistent state owns only the small catalogs/license used by node metadata.
# Runtime code itself is injected from the immutable exact-image source tree
# when an on-demand private bundle is built, so interrupted sync can never
# publish mixed old/new modes or client directories.
for spec in \
  "/src/configs/client/modes.json|modes.json" \
  "/src/configs/client/logical-modes.json|logical-modes.json" \
  "/src/LICENSE|LICENSE"; do
  src=${spec%%|*}; name=${spec#*|}
  python3 "$VERIFIED_READ" "$src" >"$STAGE/$name"
  chmod 600 "$STAGE/$name"
done

python3 "$PRIVATE_BATCH" \
  "$BUNDLE/modes.json=$STAGE/modes.json" \
  "$BUNDLE/logical-modes.json=$STAGE/logical-modes.json" \
  "$BUNDLE/LICENSE=$STAGE/LICENSE"

trap - EXIT
cleanup
printf 'Synced current client catalogs/license atomically; runtime code is injected from exact source only when a private bundle is built.\n'
