#!/usr/bin/env bash
# This package was authenticated by exact-SHA release delivery. Resolve its
# architecture- and checksum-verified corrected engine, never an arbitrary PATH
# binary which only happens to report the upstream version.
set -euo pipefail
XRAY_PACKAGE_ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
XRAY_BIN=$(python3 "$XRAY_PACKAGE_ROOT/client/verify-bundled-xray.py" "$XRAY_PACKAGE_ROOT/runtime/xray" --path)
[[ -x "$XRAY_BIN" ]] || { echo 'Corrected packaged Xray is missing' >&2; return 1 2>/dev/null || exit 1; }
