#!/bin/bash
set -euo pipefail
[[ $EUID -ne 0 ]] || { echo 'Run this as your normal Mac user, not with sudo.' >&2; exit 1; }
[[ $# -le 1 ]] || { echo 'Usage: install-macos-final.sh [extracted-package-directory]' >&2; exit 2; }

BUNDLE=$(cd -- "${1:-.}" && pwd -P)
APP_SRC="$BUNDLE/RouterVPN.app"
[[ -x "$APP_SRC/Contents/MacOS/RouterVPN" ]] || { echo 'This package does not contain the native RouterVPN.app.' >&2; exit 1; }
[[ -x "$BUNDLE/router-vpn-client" && -f "$BUNDLE/client.json" ]] || { echo 'Native Router VPN runtime files are missing from this package.' >&2; exit 1; }
[[ -f "$BUNDLE/LICENSE" ]] || { echo 'Router VPN LICENSE is missing from this package.' >&2; exit 1; }

# Enter the fixed sibling wrapper exactly once. The native transaction owns
# protected installation, private-state preservation and download quarantine.
# A successful child must not resume the retired user-copy installation path.
ENTRY=${BASH_SOURCE[0]}
[[ "$ENTRY" == */* ]] || ENTRY="./$ENTRY"
INSTALLER_DIR=$(cd -- "${ENTRY%/*}" && pwd -P)
NATIVE_INSTALLER="$INSTALLER_DIR/install-macos-native.sh"
[[ -f "$NATIVE_INSTALLER" && ! -L "$NATIVE_INSTALLER" ]] || { echo 'The adjacent native macOS installer is missing or linked.' >&2; exit 1; }
exec /bin/bash "$NATIVE_INSTALLER" "$BUNDLE"
