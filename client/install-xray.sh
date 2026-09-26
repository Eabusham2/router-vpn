#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUNDLE=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
case "$(uname -s)/$(uname -m)" in
 Linux/x86_64|Linux/amd64) TARGET=linux-amd64;;
 Linux/aarch64|Linux/arm64) TARGET=linux-arm64;;
 Darwin/x86_64) TARGET=darwin-amd64;;
 Darwin/arm64) TARGET=darwin-arm64;;
 *) echo 'Unsupported Xray platform' >&2;exit 1;;
esac
SOURCE="$BUNDLE/runtime/xray"
[[ -d "$SOURCE" ]] || SOURCE="$BUNDLE/dist/xray/$TARGET"
python3 "$SCRIPT_DIR/verify-bundled-xray.py" "$SOURCE" >/dev/null
SUDO=();[[ ${EUID:-$(id -u)} -eq 0 ]] || SUDO=(sudo)
"${SUDO[@]}" python3 "$SCRIPT_DIR/install-bundled-xray.py" "$SOURCE" /opt/router-vpn-client/runtime/xray
