#!/usr/bin/env sh
set -eu
BASE=${BASE:-/opt/router-vpn}
CONFIG="$BASE/config"
KEY_FILE="$CONFIG/portainer-api.key"
PIN_FILE="$CONFIG/portainer-tls.sha256"
PORTAINER_HOST=${PORTAINER_HOST:-127.0.0.1}
PORTAINER_PORT=${PORTAINER_PORT:-9443}

[ "$(id -u)" -eq 0 ] || { echo 'Run as root on the AI Board.' >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo 'openssl is required to pin the local Portainer TLS certificate.' >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo 'curl is required to validate the Portainer API key.' >&2; exit 1; }
case "$PORTAINER_HOST" in
  127.0.0.1|::1) ;;
  *) echo 'Portainer Update is intentionally restricted to local loopback Portainer.' >&2; exit 1 ;;
esac
case "$PORTAINER_PORT" in ''|*[!0-9]*) echo 'Invalid Portainer port.' >&2; exit 1;; esac
[ "$PORTAINER_PORT" -ge 1 ] && [ "$PORTAINER_PORT" -le 65535 ] || { echo 'Invalid Portainer port.' >&2; exit 1; }

mkdir -p "$CONFIG"
chmod 700 "$CONFIG" 2>/dev/null || true
printf 'Portainer API key (stored only on the AI Board): ' >&2
stty -echo
IFS= read -r API_KEY || API_KEY=''
stty echo
printf '\n' >&2
[ "${#API_KEY}" -ge 16 ] || { echo 'Portainer API key is too short.' >&2; exit 1; }

CONNECT_HOST=$PORTAINER_HOST
[ "$CONNECT_HOST" != '::1' ] || CONNECT_HOST='[::1]'
PIN=$(
  openssl s_client -connect "$CONNECT_HOST:$PORTAINER_PORT" -servername localhost </dev/null 2>/dev/null \
    | openssl x509 -outform DER 2>/dev/null \
    | openssl dgst -sha256 -r 2>/dev/null \
    | awk '{print tolower($1)}'
)
case "$PIN" in
  ''|*[!0-9a-f]*) echo 'Could not obtain the local Portainer TLS certificate fingerprint.' >&2; exit 1;;
esac
[ "${#PIN}" -eq 64 ] || { echo 'Invalid Portainer TLS certificate fingerprint.' >&2; exit 1; }

# Validate the credential only against loopback. -k is used solely for this
# one-time probe after capturing the certificate; runtime traffic is pinned to
# the exact SHA-256 fingerprint and never uses an unverified TLS connection.
STATUS=$(curl -ksS --max-time 8 -o /dev/null -w '%{http_code}' \
  -H "X-API-Key: $API_KEY" "https://$CONNECT_HOST:$PORTAINER_PORT/api/stacks" || true)
[ "$STATUS" = 200 ] || { echo "Portainer API key validation failed (HTTP $STATUS)." >&2; exit 1; }

umask 077
KEY_TMP="$KEY_FILE.tmp.$$"
PIN_TMP="$PIN_FILE.tmp.$$"
printf '%s\n' "$API_KEY" >"$KEY_TMP"
printf '%s\n' "$PIN" >"$PIN_TMP"
chmod 600 "$KEY_TMP" "$PIN_TMP"
mv -f "$KEY_TMP" "$KEY_FILE"
mv -f "$PIN_TMP" "$PIN_FILE"
unset API_KEY

echo 'Portainer Update configured.'
echo "Pinned local Portainer TLS SHA-256: $PIN"
echo 'The API key remains server-side and is never returned to Setup Center browser code.'
