#!/usr/bin/env bash
# Stage only a complete engine with the current source/target/payload receipt.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TARGET=${1:?target is required}
PACKAGE=${2:?package directory is required}
python3 "$ROOT/deploy/native-runtime-bundle.py" package "$TARGET" "$PACKAGE"
