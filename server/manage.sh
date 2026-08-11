#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo: sudo bash server/manage.sh'; exit 1; }
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

# Keep terminal management aligned with Portainer. The exact images pinned in
# server/portainer-current.yaml are preferred. If a custom Router VPN image is
# unavailable, Compose builds that service from the already-checked-out source.
if [[ ! -s /opt/router-vpn/.env || ! -s /opt/router-vpn/.initialized ]]; then
  exec bash "$ROOT_DIR/server/install.sh"
fi
exec bash "$ROOT_DIR/server/upgrade.sh"
