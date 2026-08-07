#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ -s /opt/router-vpn/.env && -s /opt/router-vpn/.initialized ]]; then
  exec bash "$ROOT_DIR/server/upgrade.sh" "$@"
fi
exec bash "$ROOT_DIR/server/install.sh" "$@"
