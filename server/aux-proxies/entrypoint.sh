#!/bin/sh
set -eu
AUX_DIR=${ROUTER_VPN_AUX_DIR:-/router-vpn}
OVER_TLS_CONFIG=${OVERTLS_SERVER_CONFIG:-$AUX_DIR/overtls-server.json}
SSR_CONFIG=${SSR_SERVER_CONFIG:-$AUX_DIR/ssr-server.json}
START_LAYER_KEY_CONFIG=${ROUTER_VPN_START_LAYER_KEY_CONFIG:-$AUX_DIR/transports-server.json}
START_LAYER_PORT=${ROUTER_VPN_START_LAYER_PORT:-8389}
START_LAYER_TARGET_PORT=${ROUTER_VPN_START_LAYER_TARGET_PORT:-8388}
PIDS=''

cleanup(){
  for p in $PIDS; do kill "$p" >/dev/null 2>&1 || true; done
  wait >/dev/null 2>&1 || true
}
trap cleanup INT TERM EXIT

if [ -s "$OVER_TLS_CONFIG" ]; then
  overtls-bin -r server -c "$OVER_TLS_CONFIG" &
  PIDS="$PIDS $!"
else
  echo 'OverTLS config absent; SOCKS5+TLS compatibility service disabled.'
fi

if [ -s "$SSR_CONFIG" ]; then
  ssr-server -c "$SSR_CONFIG" &
  PIDS="$PIDS $!"
else
  echo 'ShadowsocksR config absent; legacy SSR compatibility service disabled.'
fi

if [ -s "$START_LAYER_KEY_CONFIG" ]; then
  router-vpn-start-layer-relay \
    --mode server \
    --listen ":$START_LAYER_PORT" \
    --target "127.0.0.1:$START_LAYER_TARGET_PORT" \
    --key-config "$START_LAYER_KEY_CONFIG" &
  PIDS="$PIDS $!"
else
  echo 'Start-layer AES/XOR key source absent; XOR whitening listener disabled.'
fi

[ -n "$PIDS" ] || exec sleep infinity
sleep 1
for p in $PIDS; do
  kill -0 "$p" >/dev/null 2>&1 || { echo "Auxiliary proxy process $p exited during startup" >&2; exit 1; }
done

while :; do
  sleep 30
  for p in $PIDS; do
    kill -0 "$p" >/dev/null 2>&1 || { echo "Auxiliary proxy process $p exited" >&2; exit 1; }
  done
done