#!/bin/sh
set -eu
SETTINGS=${ROUTER_VPN_TLS_SETTINGS:-/router-vpn/settings.env}
if [ ! -s "$SETTINGS" ]; then
  echo 'TLS alternate settings are not available; SS+V2Ray TLS is disabled.'
  exec sleep infinity
fi
# shellcheck disable=SC1090
. "$SETTINGS"
: "${TLS_NAME:?missing TLS_NAME}"
: "${SS_V2RAY_PORT:?missing SS_V2RAY_PORT}"
: "${SS_V2RAY_PASSWORD:?missing SS_V2RAY_PASSWORD}"
: "${SS_V2RAY_PATH:?missing SS_V2RAY_PATH}"
SS_V2RAY_METHOD=${SS_V2RAY_METHOD:-2022-blake3-aes-256-gcm}

CERT=''
KEY=''
tries=0
while :; do
  CERT=$(find /caddy-data/caddy/certificates -type f -path "*/${TLS_NAME}/${TLS_NAME}.crt" 2>/dev/null | head -n 1 || true)
  KEY=$(find /caddy-data/caddy/certificates -type f -path "*/${TLS_NAME}/${TLS_NAME}.key" 2>/dev/null | head -n 1 || true)
  if [ -n "$CERT" ] && [ -s "$CERT" ] && [ -n "$KEY" ] && [ -s "$KEY" ]; then
    break
  fi
  tries=$((tries+1))
  if [ $((tries % 30)) -eq 1 ]; then
    echo "Waiting for Caddy to obtain the public TLS certificate for ${TLS_NAME}..."
  fi
  sleep 2
done

exec ssserver --log-without-time \
  -s "[::]:${SS_V2RAY_PORT}" \
  -m "$SS_V2RAY_METHOD" \
  -k "$SS_V2RAY_PASSWORD" \
  --plugin v2ray-plugin \
  --plugin-opts "server;tls;host=${TLS_NAME};path=${SS_V2RAY_PATH};cert=${CERT};key=${KEY}"
