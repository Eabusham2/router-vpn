#!/usr/bin/env sh
set -eu

BASE=${BASE:-/opt/router-vpn}
CONFIG="$BASE/config"
KEY_FILE="$CONFIG/portainer-api.key"
PIN_FILE="$CONFIG/portainer-tls.sha256"
PORTAINER_HOST=${PORTAINER_HOST:-127.0.0.1}
PORTAINER_PORT=${PORTAINER_PORT:-9443}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PRIVATE_BATCH="$SCRIPT_DIR/atomic-private-batch.py"

[ "$(id -u)" -eq 0 ] || { echo 'Run as root on the AI Board.' >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo 'openssl is required to pin the local Portainer TLS certificate.' >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo 'curl is required to validate the Portainer API key.' >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo 'python3 is required for private Portainer credential publication.' >&2; exit 1; }
[ -f "$PRIVATE_BATCH" ] && [ ! -L "$PRIVATE_BATCH" ] || { echo 'Router VPN private batch publisher is missing or unsafe.' >&2; exit 1; }

case "$PORTAINER_HOST" in
  127.0.0.1|::1) ;;
  *) echo 'Portainer Update is intentionally restricted to local loopback Portainer.' >&2; exit 1 ;;
esac
case "$PORTAINER_PORT" in ''|*[!0-9]*) echo 'Invalid Portainer port.' >&2; exit 1;; esac
[ "$PORTAINER_PORT" -ge 1 ] && [ "$PORTAINER_PORT" -le 65535 ] || { echo 'Invalid Portainer port.' >&2; exit 1; }

# Establish the private destination parent through the same path-validation
# primitive used for adoption. This refuses symlink/non-directory ancestors
# before chmod or credential staging can touch a redirected tree.
python3 - "$PRIVATE_BATCH" "$KEY_FILE" <<'PY'
import os
from pathlib import Path
import runpy
import sys

helper = runpy.run_path(sys.argv[1])
target = Path(sys.argv[2])
helper["ensure_private_parent"](target)
os.chmod(target.parent, 0o700)
PY

umask 077
KEY_TMP=''
PIN_TMP=''
TTY_ECHO_OFF=0
API_KEY=''

cleanup(){
  if [ "$TTY_ECHO_OFF" -eq 1 ]; then
    stty echo 2>/dev/null || true
    TTY_ECHO_OFF=0
  fi
  [ -z "$KEY_TMP" ] || rm -f -- "$KEY_TMP"
  [ -z "$PIN_TMP" ] || rm -f -- "$PIN_TMP"
  unset API_KEY
}
signal_exit(){
  trap - HUP INT TERM
  cleanup
  exit 1
}
trap cleanup EXIT
trap signal_exit HUP INT TERM

printf 'Portainer API key (stored only on the AI Board): ' >&2
stty -echo
TTY_ECHO_OFF=1
IFS= read -r API_KEY || API_KEY=''
stty echo
TTY_ECHO_OFF=0
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

# The API key and TLS fingerprint form one recovery/security identity. Stage
# random private inputs and let the shared batch publisher fsync + adopt both,
# rolling the first back if adoption of the second fails.
KEY_TMP=$(mktemp "$CONFIG/.portainer-api.key.input.XXXXXX")
PIN_TMP=$(mktemp "$CONFIG/.portainer-tls.sha256.input.XXXXXX")
printf '%s\n' "$API_KEY" >"$KEY_TMP"
printf '%s\n' "$PIN" >"$PIN_TMP"
chmod 600 "$KEY_TMP" "$PIN_TMP"
python3 "$PRIVATE_BATCH" "$KEY_FILE=$KEY_TMP" "$PIN_FILE=$PIN_TMP"

unset API_KEY

echo 'Portainer Update configured.'
echo "Pinned local Portainer TLS SHA-256: $PIN"
echo 'The API key remains server-side and is never returned to Setup Center browser code.'
