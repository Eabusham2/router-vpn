#!/bin/sh
set -eu

BASE=${ROUTER_VPN_BASE:-/opt/router-vpn}
BIND=${ROUTER_VPN_SETUP_BIND:-0.0.0.0}
PORT=${ROUTER_VPN_SETUP_PORT:-8786}
SCRIPT=/src/server/scripts/setup-center-ai-server.py

[ -r "$SCRIPT" ] || {
  echo "Router VPN Setup Center entrypoint missing: $SCRIPT" >&2
  exit 1
}

# The AI wrapper preserves the existing authenticated Setup Center even when no
# provider is configured. The OpenAI key is read only from the private config
# file by the server process; it is never accepted as a command-line argument.
exec python3 "$SCRIPT" --base "$BASE" --bind "$BIND" --port "$PORT"
