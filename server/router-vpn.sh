#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
INSTALL_STATE="$ROOT_DIR/server/scripts/install-state.py"
command -v python3 >/dev/null 2>&1 || { echo 'Python 3 is required to classify Router VPN install state.' >&2; exit 1; }
state_rc=0
python3 "$INSTALL_STATE" /opt/router-vpn >/dev/null 2>&1 || state_rc=$?
case "$state_rc" in
  0) exec bash "$ROOT_DIR/server/upgrade.sh" "$@" ;;
  3) exec bash "$ROOT_DIR/server/install.sh" "$@" ;;
  *) echo 'Router VPN install state is partial, redirected, or unsafe; refusing to guess install versus upgrade.' >&2; exit "$state_rc" ;;
esac
