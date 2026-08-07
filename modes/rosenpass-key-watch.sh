#!/usr/bin/env bash
set -euo pipefail
TOOL=${1:?wg or awg command}
IFACE=${2:?interface}
PEER=${3:?peer public key}
KEY_FILE=${4:?Rosenpass key_out file}

LAST=$(mktemp)
trap 'rm -f "$LAST"' EXIT INT TERM
: >"$LAST"

while :; do
  if [[ -s "$KEY_FILE" ]] && ! cmp -s "$KEY_FILE" "$LAST"; then
    if "$TOOL" set "$IFACE" peer "$PEER" preshared-key "$KEY_FILE"; then
      cp "$KEY_FILE" "$LAST"
    fi
  fi
  sleep 1
done
