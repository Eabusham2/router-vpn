#!/bin/sh
set -eu
SETTINGS=${ROUTER_VPN_TLS_SETTINGS:-/router-vpn/settings.env}
ACME_HTTP_PORT=${ACME_HTTP_PORT:-18080}
if [ ! -s "$SETTINGS" ]; then
  echo 'TLS alternate settings are not available; Naive server is disabled.'
  exec sleep infinity
fi
# shellcheck disable=SC1090
. "$SETTINGS"
: "${TLS_NAME:?missing TLS_NAME}"
: "${NAIVE_PORT:?missing NAIVE_PORT}"
: "${NAIVE_USER:?missing NAIVE_USER}"
: "${NAIVE_PASSWORD:?missing NAIVE_PASSWORD}"

cat >/tmp/Caddyfile <<EOF
{
  order forward_proxy before file_server
  http_port ${ACME_HTTP_PORT}
  https_port ${NAIVE_PORT}
  auto_https disable_redirects
  log {
    exclude http.log.access
    exclude http.log.error
  }
}

:${NAIVE_PORT}, ${TLS_NAME} {
  encode
  forward_proxy {
    basic_auth ${NAIVE_USER} ${NAIVE_PASSWORD}
    hide_ip
    hide_via
    probe_resistance
  }
  root * /srv
  file_server
}
EOF

exec caddy run --config /tmp/Caddyfile --adapter caddyfile
