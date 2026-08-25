#!/usr/bin/env bash
set -euo pipefail
BASE=${1:?base directory}
ENDPOINT=${2:-router.invalid}
RP_PORT=${3:-51822}
WG_SERVER_PUB=${4:?WireGuard server public key}
WG_CLIENT_PUB=${5:?WireGuard client public key}
AWG_SERVER_PUB=${6:?AmneziaWG server public key}
AWG_CLIENT_PUB=${7:?AmneziaWG client public key}
PRIVATE_BATCH=/src/server/scripts/atomic-private-batch.py

command -v rosenpass >/dev/null 2>&1 || { echo 'rosenpass binary is required' >&2; exit 1; }
[[ $RP_PORT =~ ^[0-9]+$ ]] && (( RP_PORT >= 1 && RP_PORT <= 65535 )) || { echo 'invalid Rosenpass port' >&2; exit 1; }

SERVER="$BASE/config/rosenpass"
WG_CLIENT="$BASE/client-bundle/generated/wg-pq"
AWG_CLIENT="$BASE/client-bundle/generated/awg2-pq"
mkdir -p "$SERVER" "$WG_CLIENT" "$AWG_CLIENT"

# Key generation is allowed only for a genuinely new family. Existing/partial
# state must be reconciled by ensure-rosenpass.sh rather than silently rotated.
for existing in \
  "$SERVER/server-public" "$SERVER/server-secret" "$SERVER/wg-client-public" "$SERVER/awg-client-public" \
  "$WG_CLIENT/rosenpass-client-secret" "$WG_CLIENT/rosenpass-client-public" "$WG_CLIENT/rosenpass-server-public" \
  "$AWG_CLIENT/rosenpass-client-secret" "$AWG_CLIENT/rosenpass-client-public" "$AWG_CLIENT/rosenpass-server-public"; do
  if [[ -e "$existing" || -L "$existing" ]]; then
    echo "Refusing to overwrite existing Rosenpass identity material: $existing" >&2
    exit 1
  fi
done

TMP=$(mktemp -d "$SERVER/.generate.XXXXXX")
trap 'rm -rf "${TMP:-}"' EXIT
mkdir -p "$TMP/server" "$TMP/wg" "$TMP/awg"
rosenpass gen-keys --public-key="$TMP/server/server-public" --secret-key="$TMP/server/server-secret"
rosenpass gen-keys --public-key="$TMP/server/wg-client-public" --secret-key="$TMP/wg/rosenpass-client-secret"
rosenpass gen-keys --public-key="$TMP/server/awg-client-public" --secret-key="$TMP/awg/rosenpass-client-secret"
cp "$TMP/server/wg-client-public" "$TMP/wg/rosenpass-client-public"
cp "$TMP/server/awg-client-public" "$TMP/awg/rosenpass-client-public"
cp "$TMP/server/server-public" "$TMP/wg/rosenpass-server-public"
cp "$TMP/server/server-public" "$TMP/awg/rosenpass-server-public"

cat >"$TMP/server/server.toml" <<CFG
public_key = "/data/server-public"
secret_key = "/data/server-secret"
listen = ["0.0.0.0:$RP_PORT", "[::]:$RP_PORT"]
verbosity = "Quiet"

[[peers]]
public_key = "/data/wg-client-public"
key_out = "/data/wg.psk"

[[peers]]
public_key = "/data/awg-client-public"
key_out = "/data/awg.psk"
CFG
cat >"$TMP/server/server.env" <<CFG
ROSENPASS_PORT=$RP_PORT
ROSENPASS_WG_TOOL=wg
ROSENPASS_WG_INTERFACE=wg0
ROSENPASS_WG_PEER=$WG_CLIENT_PUB
ROSENPASS_WG_KEY_OUT=/data/wg.psk
ROSENPASS_AWG_TOOL=awg
ROSENPASS_AWG_INTERFACE=awg0
ROSENPASS_AWG_PEER=$AWG_CLIENT_PUB
ROSENPASS_AWG_KEY_OUT=/data/awg.psk
CFG

write_client(){
  local dir=$1 server_wg_pub=$2 tool=$3 iface=$4
  cat >"$dir/rosenpass.toml" <<CFG
public_key = "rosenpass-client-public"
secret_key = "rosenpass-client-secret"
listen = []
verbosity = "Quiet"

[[peers]]
public_key = "rosenpass-server-public"
endpoint = "$ENDPOINT:$RP_PORT"
key_out = "rosenpass.psk"
CFG
  cat >"$dir/rosenpass.env" <<CFG
ROSENPASS_TOOL=$tool
ROSENPASS_INTERFACE=$iface
ROSENPASS_WG_PEER=$server_wg_pub
ROSENPASS_KEY_OUT=rosenpass.psk
ROSENPASS_PORT=$RP_PORT
CFG
}
write_client "$TMP/wg" "$WG_SERVER_PUB" wg wg
write_client "$TMP/awg" "$AWG_SERVER_PUB" awg awg

for required in \
  "$TMP/server/server-public" "$TMP/server/server-secret" "$TMP/server/wg-client-public" "$TMP/server/awg-client-public" \
  "$TMP/server/server.toml" "$TMP/server/server.env" \
  "$TMP/wg/rosenpass-client-secret" "$TMP/wg/rosenpass-client-public" "$TMP/wg/rosenpass-server-public" "$TMP/wg/rosenpass.toml" "$TMP/wg/rosenpass.env" \
  "$TMP/awg/rosenpass-client-secret" "$TMP/awg/rosenpass-client-public" "$TMP/awg/rosenpass-server-public" "$TMP/awg/rosenpass.toml" "$TMP/awg/rosenpass.env"; do
  [[ -s "$required" && ! -L "$required" ]] || { echo "Generated Rosenpass staging file missing/unsafe: $required" >&2; exit 1; }
  chmod 600 "$required"
done

python3 "$PRIVATE_BATCH" \
  "$SERVER/server-public=$TMP/server/server-public" \
  "$SERVER/server-secret=$TMP/server/server-secret" \
  "$SERVER/wg-client-public=$TMP/server/wg-client-public" \
  "$SERVER/awg-client-public=$TMP/server/awg-client-public" \
  "$SERVER/server.toml=$TMP/server/server.toml" \
  "$SERVER/server.env=$TMP/server/server.env" \
  "$WG_CLIENT/rosenpass-client-secret=$TMP/wg/rosenpass-client-secret" \
  "$WG_CLIENT/rosenpass-client-public=$TMP/wg/rosenpass-client-public" \
  "$WG_CLIENT/rosenpass-server-public=$TMP/wg/rosenpass-server-public" \
  "$WG_CLIENT/rosenpass.toml=$TMP/wg/rosenpass.toml" \
  "$WG_CLIENT/rosenpass.env=$TMP/wg/rosenpass.env" \
  "$AWG_CLIENT/rosenpass-client-secret=$TMP/awg/rosenpass-client-secret" \
  "$AWG_CLIENT/rosenpass-client-public=$TMP/awg/rosenpass-client-public" \
  "$AWG_CLIENT/rosenpass-server-public=$TMP/awg/rosenpass-server-public" \
  "$AWG_CLIENT/rosenpass.toml=$TMP/awg/rosenpass.toml" \
  "$AWG_CLIENT/rosenpass.env=$TMP/awg/rosenpass.env"
rm -rf "$TMP"
TMP=
trap - EXIT
printf 'Generated Rosenpass server plus WG/AWG client PQ profiles on UDP %s as one private transaction.\n' "$RP_PORT"
