#!/usr/bin/env bash
set -euo pipefail
BASE=${1:-/opt/router-vpn}
ENDPOINT=${2:-router.invalid}
RP_PORT=${3:-51822}

if [[ -s "$BASE/config/rosenpass/server.toml" \
   && -s "$BASE/client-bundle/generated/wg-pq/rosenpass.toml" \
   && -s "$BASE/client-bundle/generated/awg2-pq/rosenpass.toml" ]]; then
  exit 0
fi

WG_CONF="$BASE/config/wireguard/wg0.conf"
AWG_CONF="$BASE/config/awg2/awg0.conf"
[[ -s "$WG_CONF" && -s "$AWG_CONF" ]] || { echo 'WG/AWG base configs are required before Rosenpass generation.' >&2; exit 1; }

read_value(){
  local file=$1 section=$2 key=$3
  python3 - "$file" "$section" "$key" <<'PY'
import sys
path, wanted, key = sys.argv[1:]
section=''
for raw in open(path):
    line=raw.strip()
    if line.startswith('[') and line.endswith(']'):
        section=line[1:-1]
        continue
    if section == wanted and '=' in line:
        k,v=line.split('=',1)
        if k.strip()==key:
            print(v.strip()); raise SystemExit
raise SystemExit(1)
PY
}

WG_SERVER_PRIV=$(read_value "$WG_CONF" Interface PrivateKey)
WG_CLIENT_PUB=$(read_value "$WG_CONF" Peer PublicKey)
AWG_SERVER_PRIV=$(read_value "$AWG_CONF" Interface PrivateKey)
AWG_CLIENT_PUB=$(read_value "$AWG_CONF" Peer PublicKey)
WG_SERVER_PUB=$(printf '%s' "$WG_SERVER_PRIV" | wg pubkey)
AWG_SERVER_PUB=$(printf '%s' "$AWG_SERVER_PRIV" | wg pubkey)

bash /src/server/scripts/generate-rosenpass.sh \
  "$BASE" "$ENDPOINT" "$RP_PORT" \
  "$WG_SERVER_PUB" "$WG_CLIENT_PUB" "$AWG_SERVER_PUB" "$AWG_CLIENT_PUB"
