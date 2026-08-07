#!/usr/bin/env bash
set -euo pipefail
BASE=${1:?base directory}
ENDPOINT=${2:-router.invalid}
RP_PORT=${3:-51822}
WG_SERVER_PUB=${4:?WireGuard server public key}
WG_CLIENT_PUB=${5:?WireGuard client public key}
AWG_SERVER_PUB=${6:?AmneziaWG server public key}
AWG_CLIENT_PUB=${7:?AmneziaWG client public key}

command -v rosenpass >/dev/null 2>&1 || { echo 'rosenpass binary is required' >&2; exit 1; }
[[ $RP_PORT =~ ^[0-9]+$ ]] && (( RP_PORT >= 1 && RP_PORT <= 65535 )) || { echo 'invalid Rosenpass port' >&2; exit 1; }

SERVER="$BASE/config/rosenpass"
WG_CLIENT="$BASE/client-bundle/generated/wg-pq"
AWG_CLIENT="$BASE/client-bundle/generated/awg2-pq"
rm -rf "$SERVER"
mkdir -p "$SERVER" "$WG_CLIENT" "$AWG_CLIENT"

rosenpass gen-keys --public-key="$SERVER/server-public" --secret-key="$SERVER/server-secret"
rosenpass gen-keys --public-key="$SERVER/wg-client-public" --secret-key="$WG_CLIENT/rosenpass-client-secret"
rosenpass gen-keys --public-key="$SERVER/awg-client-public" --secret-key="$AWG_CLIENT/rosenpass-client-secret"
cp "$SERVER/wg-client-public" "$WG_CLIENT/rosenpass-client-public"
cp "$SERVER/awg-client-public" "$AWG_CLIENT/rosenpass-client-public"
cp "$SERVER/server-public" "$WG_CLIENT/rosenpass-server-public"
cp "$SERVER/server-public" "$AWG_CLIENT/rosenpass-server-public"

cat >"$SERVER/server.toml" <<CFG
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
cat >"$SERVER/server.env" <<CFG
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
write_client "$WG_CLIENT" "$WG_SERVER_PUB" wg wg0
write_client "$AWG_CLIENT" "$AWG_SERVER_PUB" awg awg0

chmod 600 "$SERVER"/* "$WG_CLIENT"/rosenpass-* "$AWG_CLIENT"/rosenpass-* "$WG_CLIENT/rosenpass.toml" "$AWG_CLIENT/rosenpass.toml" 2>/dev/null || true
printf 'Generated Rosenpass server plus WG/AWG client PQ profiles on UDP %s.\n' "$RP_PORT"
