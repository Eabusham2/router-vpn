#!/usr/bin/env bash
set -euo pipefail
BASE=${1:-/opt/router-vpn}
ENDPOINT=${2:-router.invalid}
RP_PORT=${3:-51822}
PRIVATE_BATCH=/src/server/scripts/atomic-private-batch.py

SERVER="$BASE/config/rosenpass"
WG_CLIENT="$BASE/client-bundle/generated/wg-pq"
AWG_CLIENT="$BASE/client-bundle/generated/awg2-pq"
EXISTING=(
  "$SERVER/server-public" "$SERVER/server-secret" "$SERVER/wg-client-public" "$SERVER/awg-client-public"
  "$SERVER/server.toml" "$SERVER/server.env"
  "$WG_CLIENT/rosenpass-client-secret" "$WG_CLIENT/rosenpass-client-public" "$WG_CLIENT/rosenpass-server-public" "$WG_CLIENT/rosenpass.toml" "$WG_CLIENT/rosenpass.env"
  "$AWG_CLIENT/rosenpass-client-secret" "$AWG_CLIENT/rosenpass-client-public" "$AWG_CLIENT/rosenpass-server-public" "$AWG_CLIENT/rosenpass.toml" "$AWG_CLIENT/rosenpass.env"
)
family_present=0
for path in "${EXISTING[@]}"; do
  if [[ -e "$path" || -L "$path" ]]; then family_present=1; break; fi
done

if (( family_present )); then
  for required in "${EXISTING[@]}"; do
    [[ -s "$required" && ! -L "$required" ]] || {
      echo "Existing Rosenpass identity is partial/unsafe at $required; refusing silent key rotation." >&2
      exit 1
    }
  done
  cmp -s "$SERVER/server-public" "$WG_CLIENT/rosenpass-server-public" || {
    echo 'WG-PQ Rosenpass server public key disagrees with preserved server identity.' >&2; exit 1;
  }
  cmp -s "$SERVER/server-public" "$AWG_CLIENT/rosenpass-server-public" || {
    echo 'AWG-PQ Rosenpass server public key disagrees with preserved server identity.' >&2; exit 1;
  }
  cmp -s "$SERVER/wg-client-public" "$WG_CLIENT/rosenpass-client-public" || {
    echo 'WG-PQ Rosenpass client public key disagrees with preserved server peer identity.' >&2; exit 1;
  }
  cmp -s "$SERVER/awg-client-public" "$AWG_CLIENT/rosenpass-client-public" || {
    echo 'AWG-PQ Rosenpass client public key disagrees with preserved server peer identity.' >&2; exit 1;
  }

  # Repair only owned endpoint/interface metadata using staged replacements. The
  # cryptographic identity files above are never regenerated on an upgrade.
  TMP=$(mktemp -d "$SERVER/.repair.XXXXXX")
  trap 'rm -rf "${TMP:-}"' EXIT
  sed -e 's/^ROSENPASS_INTERFACE=.*/ROSENPASS_INTERFACE=wg/' "$WG_CLIENT/rosenpass.env" > "$TMP/wg.env"
  sed -e 's/^ROSENPASS_INTERFACE=.*/ROSENPASS_INTERFACE=awg/' "$AWG_CLIENT/rosenpass.env" > "$TMP/awg.env"
  sed -e "s#^endpoint = .*#endpoint = \"$ENDPOINT:$RP_PORT\"#" "$WG_CLIENT/rosenpass.toml" > "$TMP/wg.toml"
  sed -e "s#^endpoint = .*#endpoint = \"$ENDPOINT:$RP_PORT\"#" "$AWG_CLIENT/rosenpass.toml" > "$TMP/awg.toml"
  for staged in "$TMP/wg.env" "$TMP/awg.env" "$TMP/wg.toml" "$TMP/awg.toml"; do
    [[ -s "$staged" ]] || { echo "Rosenpass metadata staging failed: $staged" >&2; exit 1; }
    chmod 600 "$staged"
  done
  grep -Fq "endpoint = \"$ENDPOINT:$RP_PORT\"" "$TMP/wg.toml"
  grep -Fq "endpoint = \"$ENDPOINT:$RP_PORT\"" "$TMP/awg.toml"
  python3 "$PRIVATE_BATCH" \
    "$WG_CLIENT/rosenpass.env=$TMP/wg.env" \
    "$AWG_CLIENT/rosenpass.env=$TMP/awg.env" \
    "$WG_CLIENT/rosenpass.toml=$TMP/wg.toml" \
    "$AWG_CLIENT/rosenpass.toml=$TMP/awg.toml"
  rm -rf "$TMP"
  TMP=
  trap - EXIT
  echo 'Preserved complete Rosenpass identity and atomically refreshed owned client metadata.' >&2
  exit 0
fi

WG_CONF="$BASE/config/wireguard/wg0.conf"
AWG_CONF="$BASE/config/awg2/awg0.conf"
[[ -s "$WG_CONF" && ! -L "$WG_CONF" && -s "$AWG_CONF" && ! -L "$AWG_CONF" ]] || {
  echo 'WG/AWG base configs are required before Rosenpass generation.' >&2
  exit 1
}

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
