#!/usr/bin/env bash
set -euo pipefail
CONF=${ROSENPASS_CONFIG:-/data/server.toml}
ENV_FILE=${ROSENPASS_ENV:-/data/server.env}
if [[ ! -s "$CONF" || ! -s "$ENV_FILE" ]]; then
  echo 'Rosenpass PQ is disabled because no generated server config is present.'
  exec sleep infinity
fi
# shellcheck disable=SC1090
source "$ENV_FILE"

PIDS=()
cleanup(){
  for pid in "${PIDS[@]:-}"; do kill "$pid" >/dev/null 2>&1 || true; done
  wait >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

cd /data
rosenpass exchange-config "$CONF" &
PIDS+=("$!")

bash /usr/local/lib/router-vpn/rosenpass-key-watch.sh \
  "$ROSENPASS_WG_TOOL" "$ROSENPASS_WG_INTERFACE" "$ROSENPASS_WG_PEER" "$ROSENPASS_WG_KEY_OUT" &
PIDS+=("$!")

bash /usr/local/lib/router-vpn/rosenpass-key-watch.sh \
  "$ROSENPASS_AWG_TOOL" "$ROSENPASS_AWG_INTERFACE" "$ROSENPASS_AWG_PEER" "$ROSENPASS_AWG_KEY_OUT" &
PIDS+=("$!")

# Fail the container if Rosenpass itself exits. Watchers intentionally retry because
# WG/AWG interfaces may appear a moment after this service starts.
wait "${PIDS[0]}"
