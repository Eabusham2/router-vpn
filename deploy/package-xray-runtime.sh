#!/usr/bin/env bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TARGET=${1:?native target required}
PACKAGE=${2:?package staging directory required}
POLICY=$(python3 "$ROOT/deploy/prepare-xray-runtime.py" --digest)
CACHE="$ROOT/dist/engines/xray/$POLICY/${TARGET//\//-}"
python3 "$ROOT/deploy/build-xray-runtime.py" "$TARGET" "$CACHE"
mkdir -p "$PACKAGE/runtime/xray" "$PACKAGE/client"
cp -a "$CACHE/." "$PACKAGE/runtime/xray/"
cp "$ROOT/client/verify-bundled-xray.py" "$PACKAGE/client/verify-bundled-xray.py"
