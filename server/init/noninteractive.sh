#!/usr/bin/env bash
set -euo pipefail
BASE=/opt/router-vpn
WAN_INTERFACE=${WAN_INTERFACE:-eth0}
LAN_CIDR=${LAN_CIDR:-192.168.50.0/24}
ADGUARD4=${ADGUARD4:-192.168.50.133}
ENDPOINT=${ENDPOINT:-}
CONFIG_ENDPOINT=${ENDPOINT:-router.invalid}
WG_PORT=${WG_PORT:-51820}
AWG_PORT=${AWG_PORT:-585}
REALITY_PORT=${REALITY_PORT:-443}
HY2_PORT=${HY2_PORT:-8443}
SS_PORT=${SS_PORT:-8388}
XRAY_PQ_PORT=${XRAY_PQ_PORT:-10443}
REALITY_TARGET=${REALITY_TARGET:-www.microsoft.com:443}
PRIVATE_WRITE=/src/server/scripts/atomic-private-write.py
PRIVATE_DIR=/src/server/scripts/private-directory.py
VERIFIED_READ=/src/server/scripts/verified-regular-read.py
umask 077
for dir in \
  "$BASE" \
  "$BASE/config" \
  "$BASE/config/wireguard" \
  "$BASE/config/awg2" \
  "$BASE/client-bundle" \
  "$BASE/client-bundle/generated" \
  "$BASE/scripts" \
  "$BASE/logs" \
  "$BASE/downloads"; do
  python3 "$PRIVATE_DIR" "$dir"
done

# Setup Center authentication is a router-local credential. Preserve it across
# safe upgrades, never print it, and never copy it into a client/node bundle.
python3 /src/server/scripts/ensure-setup-auth.py "$BASE" >/dev/null

# Private node bundles are always generated on demand. Remove cached credential
# ZIPs/files left by older releases even on an already-initialized upgrade path.
# The authenticated Setup Center builds the private link bundle only on demand.
rm -f "$BASE/downloads/router-vpn-client-bundle.zip" "$BASE/router-vpn-client-bundle.zip" \
      "$BASE/downloads/router-vpn-bundle.json" "$BASE/downloads/CREDENTIALS.txt"

rm -rf "$BASE/source"
mkdir -p "$BASE/source"
cp -a /src/. "$BASE/source/"
if [[ -e "$BASE/.initialized" || -L "$BASE/.initialized" ]]; then
  marker=$(python3 "$VERIFIED_READ" --private "$BASE/.initialized") || {
    echo 'Existing initialization marker is unsafe; refusing credential regeneration.' >&2
    exit 1
  }
  [[ "$marker" == initialized ]] || {
    echo 'Existing initialization marker is invalid; refusing credential regeneration.' >&2
    exit 1
  }
  echo 'Router VPN config already initialized; keeping current keys and Setup Center access token.'
  /src/server/scripts/apply-runtime.sh "$WAN_INTERFACE" "$LAN_CIDR"
  exit 0
fi
TOKEN=$(openssl rand -hex 32)
SOCKS_USER="vpn$(openssl rand -hex 3)"
SOCKS_PASSWORD=$(openssl rand -base64 24 | tr -d '\n=/+' | head -c 28)
keypair(){ local prefix=$1 priv pub; priv=$(wg genkey); pub=$(printf '%s' "$priv" | wg pubkey); printf -v "${prefix}_PRIV" '%s' "$priv"; printf -v "${prefix}_PUB" '%s' "$pub"; }
keypair WG_SERVER; keypair WG_CLIENT; keypair AWG_SERVER; keypair AWG_CLIENT
WG_PSK=$(wg genpsk); AWG_PSK=$(wg genpsk)

python3 "$PRIVATE_WRITE" "$BASE/config/wireguard/wg0.conf" <<CFG
[Interface]
Address = 10.77.0.1/24, fd77:77::1/64
ListenPort = $WG_PORT
PrivateKey = $WG_SERVER_PRIV
MTU = 1420
[Peer]
PublicKey = $WG_CLIENT_PUB
PresharedKey = $WG_PSK
AllowedIPs = 10.77.0.2/32, fd77:77::2/128
CFG
for mode in wg wg-pq; do
  mkdir -p "$BASE/client-bundle/generated/$mode"
  python3 "$PRIVATE_WRITE" "$BASE/client-bundle/generated/$mode/wg.conf" <<CFG
[Interface]
Address = 10.77.0.2/24, fd77:77::2/64
PrivateKey = $WG_CLIENT_PRIV
DNS = $ADGUARD4
MTU = 1420
[Peer]
PublicKey = $WG_SERVER_PUB
PresharedKey = $WG_PSK
Endpoint = $CONFIG_ENDPOINT:$WG_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
CFG
done
python3 "$PRIVATE_WRITE" "$BASE/client-bundle/generated/wg/wg-socks.conf" <<CFG
[Interface]
Address = 10.77.0.2/24, fd77:77::2/64
PrivateKey = $WG_CLIENT_PRIV
MTU = 1420
[Peer]
PublicKey = $WG_SERVER_PUB
PresharedKey = $WG_PSK
Endpoint = $CONFIG_ENDPOINT:$WG_PORT
AllowedIPs = 10.77.0.0/24, fd77:77::/64, $LAN_CIDR
PersistentKeepalive = 25
CFG
python3 "$PRIVATE_WRITE" "$BASE/client-bundle/generated/wg-pq/wg-socks.conf" < "$BASE/client-bundle/generated/wg/wg-socks.conf"

python3 "$PRIVATE_WRITE" "$BASE/config/awg2/awg0.conf" <<CFG
[Interface]
Address = 10.78.0.1/24, fd78:78::1/64
ListenPort = $AWG_PORT
PrivateKey = $AWG_SERVER_PRIV
MTU = 1400
S1 = 56
S2 = 48
S3 = 24
S4 = 32
H1 = 10000000-19999999
H2 = 20000000-29999999
H3 = 30000000-39999999
H4 = 40000000-49999999
[Peer]
PublicKey = $AWG_CLIENT_PUB
PresharedKey = $AWG_PSK
AllowedIPs = 10.78.0.2/32, fd78:78::2/128
CFG
make_awg(){
  local mode=$1 jc=$2 jmax=$3 mtu=$4
  mkdir -p "$BASE/client-bundle/generated/$mode"
  python3 "$PRIVATE_WRITE" "$BASE/client-bundle/generated/$mode/awg.conf" <<CFG
[Interface]
Address = 10.78.0.2/24, fd78:78::2/64
PrivateKey = $AWG_CLIENT_PRIV
DNS = $ADGUARD4
MTU = $mtu
Jc = $jc
Jmin = 40
Jmax = $jmax
S1 = 56
S2 = 48
S3 = 24
S4 = 32
H1 = 10000000-19999999
H2 = 20000000-29999999
H3 = 30000000-39999999
H4 = 40000000-49999999
[Peer]
PublicKey = $AWG_SERVER_PUB
PresharedKey = $AWG_PSK
Endpoint = $CONFIG_ENDPOINT:$AWG_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
CFG
}
make_awg awg2-fast 3 900 1400
make_awg awg2-strong 8 1200 1360
mkdir -p "$BASE/client-bundle/generated/awg2-pq"
python3 "$PRIVATE_WRITE" "$BASE/client-bundle/generated/awg2-pq/awg.conf" < "$BASE/client-bundle/generated/awg2-fast/awg.conf"
for mode in awg2-fast awg2-strong awg2-pq; do
  tmp=$(mktemp)
  sed "s#AllowedIPs = 0.0.0.0/0, ::/0#AllowedIPs = 10.78.0.0/24, fd78:78::/64, $LAN_CIDR#" "$BASE/client-bundle/generated/$mode/awg.conf" > "$tmp"
  python3 "$PRIVATE_WRITE" "$BASE/client-bundle/generated/$mode/awg-socks.conf" < "$tmp"
  rm -f "$tmp"
done

/src/server/scripts/generate-transports.sh "$BASE" "$CONFIG_ENDPOINT" "$ADGUARD4" "$REALITY_PORT" "$HY2_PORT" "$SS_PORT" "$REALITY_TARGET"
/src/server/scripts/generate-xray-pq.sh "$BASE" "$CONFIG_ENDPOINT" "$ADGUARD4" "$XRAY_PQ_PORT" "$REALITY_TARGET" "$REALITY_PORT"
python3 - "$TOKEN" "$WAN_INTERFACE" <<'PY' | python3 "$PRIVATE_WRITE" "$BASE/config/router-agent.json"
import json,sys
x=json.load(open('/src/configs/router/router-agent.json.example')); x['token']=sys.argv[1]; x['wan_interface']=sys.argv[2]
print(json.dumps(x,indent=2))
PY
python3 - "$SOCKS_USER" "$SOCKS_PASSWORD" "$ADGUARD4" <<'PY' | python3 "$PRIVATE_WRITE" "$BASE/config/socks5.json"
import json,sys
x=json.load(open('/src/configs/router/socks5.json.example')); x['inbounds'][0]['users'][0]={'username':sys.argv[1],'password':sys.argv[2]}; x['dns']['servers'][0]['server']=sys.argv[3]
print(json.dumps(x,indent=2))
PY
# Publish only catalog metadata persistently. Runtime code/binaries are injected
# from the exact immutable source image during on-demand package construction.
python3 "$PRIVATE_WRITE" "$BASE/client-bundle/modes.json" < /src/configs/client/modes.json
python3 "$PRIVATE_WRITE" "$BASE/client-bundle/logical-modes.json" < /src/configs/client/logical-modes.json
python3 "$PRIVATE_WRITE" "$BASE/client-bundle/LICENSE" < /src/LICENSE
python3 "$PRIVATE_WRITE" "$BASE/client-bundle/CREDENTIALS.txt" <<TXT
Endpoint: ${ENDPOINT:-CHOOSE_IN_APP}
WireGuard UDP: $WG_PORT
AmneziaWG UDP: $AWG_PORT
REALITY TCP: $REALITY_PORT
Hysteria2 UDP: $HY2_PORT
Shadowsocks TCP/UDP: $SS_PORT
PQ REALITY TCP: $XRAY_PQ_PORT
SOCKS5 after VPN: $ADGUARD4:1080
SOCKS5 username: $SOCKS_USER
SOCKS5 password: $SOCKS_PASSWORD
Router API client-control token: $TOKEN
Setup Center access credential is NOT in this bundle; it remains only on the router at /opt/router-vpn/config/setup-center.token.
TXT
/src/server/scripts/create-bundle-json.py "$BASE" "$ENDPOINT" "$TOKEN" "http://$ADGUARD4:8787" "$ADGUARD4" "$SOCKS_USER" "$SOCKS_PASSWORD"
/src/server/scripts/apply-runtime.sh "$WAN_INTERFACE" "$LAN_CIDR"
printf 'initialized\n' | python3 "$PRIVATE_WRITE" "$BASE/.initialized"
echo 'Initialization complete: private node material prepared; Setup Center authentication stays router-local and client bundles are built only on demand.'
