#!/usr/bin/env bash
set -euo pipefail
BASE=${1:-/opt/router-vpn}
ENDPOINT=${2:-router.invalid}
RP_PORT=${3:-51822}
STATE_HELPER=/src/server/scripts/rosenpass-private-state.py

STATE=$(python3 "$STATE_HELPER" probe "$BASE")
case "$STATE" in
  present)
    python3 "$STATE_HELPER" refresh "$BASE" "$ENDPOINT" "$RP_PORT"
    echo 'Preserved complete Rosenpass identity and atomically refreshed owned client metadata.' >&2
    exit 0
    ;;
  absent)
    ;;
  *)
    echo "Unexpected Rosenpass state result: $STATE" >&2
    exit 1
    ;;
esac

# First generation reads WG/AWG base identity through the same strict private
# file boundary. The helper emits only fixed shell assignment names quoted with
# shlex.quote; no config path is opened directly by this shell.
eval "$(python3 "$STATE_HELPER" base-keys "$BASE")"
WG_SERVER_PUB=$(printf '%s' "$WG_SERVER_PRIV" | wg pubkey)
AWG_SERVER_PUB=$(printf '%s' "$AWG_SERVER_PRIV" | wg pubkey)
[[ -n "$WG_SERVER_PUB" && -n "$AWG_SERVER_PUB" && -n "$WG_CLIENT_PUB" && -n "$AWG_CLIENT_PUB" ]] || {
  echo 'WG/AWG base identity is incomplete; refusing Rosenpass generation.' >&2
  exit 1
}

bash /src/server/scripts/generate-rosenpass.sh \
  "$BASE" "$ENDPOINT" "$RP_PORT" \
  "$WG_SERVER_PUB" "$WG_CLIENT_PUB" "$AWG_SERVER_PUB" "$AWG_CLIENT_PUB"
