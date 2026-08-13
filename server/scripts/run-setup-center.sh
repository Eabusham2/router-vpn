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

# Compatibility note for the older AI-entrypoint contract: the product wrapper
# composes setup-center-ai-server.py rather than replacing or bypassing its
# authentication/provider boundary. The actual executable remains $SCRIPT.
# setup-center-ai-server.py
exec python3 "$SCRIPT" --base "$BASE" --bind "$BIND" --port "$PORT"
