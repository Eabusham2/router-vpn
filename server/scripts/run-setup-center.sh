#!/bin/sh
set -eu

BASE=${ROUTER_VPN_BASE:-/opt/router-vpn}
BIND=${ROUTER_VPN_SETUP_BIND:-0.0.0.0}
PORT=${ROUTER_VPN_SETUP_PORT:-8786}
SCRIPT=/src/server/scripts/setup-center-product-server.py

[ -r "$SCRIPT" ] || {
  echo "Router VPN Setup Center entrypoint missing: $SCRIPT" >&2
  exit 1
}

# The product wrapper preserves the existing authenticated Setup Center, Full
# Guide, device UX, and server-side AI Help, then adds read-only exact-SHA
# release/recovery status. It deliberately does not grant Setup Center
# Docker/Portainer authority or expose provider secrets to the browser.
exec python3 "$SCRIPT" --base "$BASE" --bind "$BIND" --port "$PORT"
