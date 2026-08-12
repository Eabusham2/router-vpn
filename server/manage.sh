#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo: sudo bash server/manage.sh'; exit 1; }
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

# Keep terminal management aligned with the image-only Portainer production
# stack. Router-local compilation is reserved for requested client packages in
# the Setup Center broker, not for Portainer server service images.
if [[ ! -s /opt/router-vpn/.env || ! -s /opt/router-vpn/.initialized ]]; then
  exec bash "$ROOT_DIR/server/install.sh"
fi
exec bash "$ROOT_DIR/server/upgrade.sh"
