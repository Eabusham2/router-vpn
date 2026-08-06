#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run this installer with sudo.'; exit 1; }
command -v docker >/dev/null || { echo 'Docker is required. Open ASUS AI Board > Portainer first, then rerun.'; exit 1; }
docker compose version >/dev/null 2>&1 || { echo 'Docker Compose v2 is required.'; exit 1; }
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
INSTALL=/opt/router-vpn
DEFAULT_WAN=$(ip -4 route show default 2>/dev/null | awk 'NR==1{print $5}')
DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
DEFAULT_IP=${DEFAULT_IP:-192.168.50.133}
PUBLIC_GUESS=$(curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)

prompt(){ local var=$1 text=$2 def=$3 value; read -r -p "$text [$def]: " value; printf -v "$var" '%s' "${value:-$def}"; }
prompt WAN_INTERFACE 'AI Board network interface' "${DEFAULT_WAN:-eth0}"
prompt LAN_CIDR 'Home LAN IPv4 subnet' '192.168.50.0/24'
prompt ADGUARD4 'AdGuard Home IPv4 address' "$DEFAULT_IP"
prompt ENDPOINT 'Home public IPv4 or one hostname' "${PUBLIC_GUESS:-YOUR_PUBLIC_IP}"
prompt WG_PORT 'Raw WireGuard UDP port' '51820'
prompt AWG_PORT 'AmneziaWG UDP port' '585'
prompt REALITY_PORT 'REALITY/Vision TCP port' '443'
prompt HY2_PORT 'Hysteria2 QUIC UDP port' '8443'
prompt SS_PORT 'Shadowsocks TCP/UDP port' '8388'
prompt REALITY_TARGET 'REALITY target host:port' 'www.microsoft.com:443'

for command_name in wg curl openssl python3 zip nft; do
  command -v "$command_name" >/dev/null 2>&1 && continue
  if command -v apt-get >/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools curl openssl python3 zip nftables
    break
  fi
  echo 'Install wireguard-tools, curl, openssl, python3, zip, and nftables, then rerun.'; exit 1
done

umask 077
mkdir -p "$INSTALL"/{config/{wireguard,awg2},source,client-bundle/generated,scripts,logs,downloads}
rm -rf "$INSTALL/source"
mkdir -p "$INSTALL/source"
cp -a "$ROOT_DIR/." "$INSTALL/source/"
rm -rf "$INSTALL/source/dist" "$INSTALL/source/.git"

TOKEN=$(openssl rand -hex 32)
SOCKS_USER="vpn$(openssl rand -hex 3)"
SOCKS_PASSWORD=$(openssl rand -base64 24 | tr -d '\n=/+' | head -c 28)

WG_SERVER_PRIV=$(wg genkey); WG_SERVER_PUB=$(printf '%s' "$WG_SERVER_PRIV" | wg pubkey)
WG_CLIENT_PRIV=$(wg genkey); WG_CLIENT_PUB=$(printf '%s' "$WG_CLIENT_PRIV" | wg pubkey)
WG_PSK=$(wg genpsk)
AWG_SERVER_PRIV=$(wg genkey); AWG_SERVER_PUB=$(printf '%s' "$AWG_SERVER_PRIV" | wg pubkey)
AWG_CLIENT_PRIV=$(wg genkey); AWG_CLIENT_PUB=$(printf '%s' "$AWG_CLIENT_PRIV" | wg pubkey)
AWG_PSK=$(wg genpsk)

cat >"$INSTALL/config/wireguard/wg0.conf" <<CFG
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
  mkdir -p "$INSTALL/client-bundle/generated/$mode"
  cat >"$INSTALL/client-bundle/generated/$mode/wg.conf" <<CFG
[Interface]
Address = 10.77.0.2/24, fd77:77::2/64
PrivateKey = $WG_CLIENT_PRIV
DNS = $ADGUARD4
MTU = 1420

[Peer]
PublicKey = $WG_SERVER_PUB
PresharedKey = $WG_PSK
Endpoint = $ENDPOINT:$WG_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
CFG
done

cat >"$INSTALL/config/awg2/awg0.conf" <<CFG
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

make_awg_client(){
  local mode=$1 jc=$2 jmin=$3 jmax=$4 mtu=$5
  mkdir -p "$INSTALL/client-bundle/generated/$mode"
  cat >"$INSTALL/client-bundle/generated/$mode/awg.conf" <<CFG
[Interface]
Address = 10.78.0.2/24, fd78:78::2/64
PrivateKey = $AWG_CLIENT_PRIV
DNS = $ADGUARD4
MTU = $mtu
Jc = $jc
Jmin = $jmin
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
Endpoint = $ENDPOINT:$AWG_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
CFG
}
make_awg_client awg2-fast 3 40 900 1400
make_awg_client awg2-strong 8 64 1200 1360
cp -a "$INSTALL/client-bundle/generated/awg2-fast" "$INSTALL/client-bundle/generated/awg2-pq"
"$ROOT_DIR/server/scripts/generate-transports.sh" "$INSTALL" "$ENDPOINT" "$ADGUARD4" "$REALITY_PORT" "$HY2_PORT" "$SS_PORT" "$REALITY_TARGET"

python3 - "$ROOT_DIR/configs/router/router-agent.json.example" "$INSTALL/config/router-agent.json" "$TOKEN" "$WAN_INTERFACE" <<'PY'
import json,sys
src,dst,token,wan=sys.argv[1:]
x=json.load(open(src)); x['token']=token; x['wan_interface']=wan
json.dump(x,open(dst,'w'),indent=2); open(dst,'a').write('\n')
PY
python3 - "$ROOT_DIR/configs/router/socks5.json.example" "$INSTALL/config/socks5.json" "$SOCKS_USER" "$SOCKS_PASSWORD" "$ADGUARD4" <<'PY'
import json,sys
src,dst,user,password,dns=sys.argv[1:]
x=json.load(open(src)); x['inbounds'][0]['users'][0]={'username':user,'password':password}; x['dns']['servers'][0]['server']=dns
json.dump(x,open(dst,'w'),indent=2); open(dst,'a').write('\n')
PY

cat >"$INSTALL/.env" <<ENV
WAN_INTERFACE=$WAN_INTERFACE
ENV
cat >"$INSTALL/client-bundle/client.json" <<CFG
{
  "listen": "127.0.0.1:8788",
  "router_api": "http://$ADGUARD4:8787",
  "api_token": "$TOKEN",
  "health_url": "https://connectivitycheck.gstatic.com/generate_204",
  "adguard_ipv4": "$ADGUARD4",
  "adguard_ipv6": "fd77:77::1",
  "auto_test_seconds": 8,
  "modes_file": "./modes.json",
  "state_file": "./state.json",
  "scripts_dir": "./modes",
  "socks_host": "$ADGUARD4",
  "socks_port": 1080,
  "socks_username": "$SOCKS_USER",
  "socks_password": "$SOCKS_PASSWORD"
}
CFG
cp "$ROOT_DIR/configs/client/modes.json" "$INSTALL/client-bundle/modes.json"
cp -a "$ROOT_DIR/modes" "$INSTALL/client-bundle/modes"
cp -a "$ROOT_DIR/dist" "$INSTALL/client-bundle/dist"
cat >"$INSTALL/client-bundle/CREDENTIALS.txt" <<TXT
Endpoint: $ENDPOINT
WireGuard UDP: $WG_PORT
AmneziaWG UDP: $AWG_PORT
REALITY TCP: $REALITY_PORT
Hysteria2 UDP: $HY2_PORT
Shadowsocks TCP/UDP: $SS_PORT
SOCKS5 after VPN connects: $ADGUARD4:1080
SOCKS5 username: $SOCKS_USER
SOCKS5 password: $SOCKS_PASSWORD
Router API token: $TOKEN
TXT
"$ROOT_DIR/server/scripts/create-bundle-json.py" "$INSTALL" "$ENDPOINT" "$TOKEN" "http://$ADGUARD4:8787" "$ADGUARD4" "$SOCKS_USER" "$SOCKS_PASSWORD"

chmod 600 "$INSTALL/client-bundle/CREDENTIALS.txt" "$INSTALL/config/"*.json "$INSTALL/config/wireguard/wg0.conf" "$INSTALL/config/awg2/awg0.conf"

cat >/etc/sysctl.d/99-router-vpn.conf <<SYS
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
net.ipv6.conf.all.accept_ra=2
SYS
sysctl --system >/dev/null

cat >"$INSTALL/scripts/apply-guard.sh" <<GUARD
#!/usr/bin/env bash
set -euo pipefail
export WG_PORT=$WG_PORT AWG_PORT=$AWG_PORT REALITY_PORT=$REALITY_PORT HY2_PORT=$HY2_PORT SS_PORT=$SS_PORT
exec "$INSTALL/source/server/scripts/apply-runtime.sh" "$WAN_INTERFACE" "$LAN_CIDR"
GUARD
chmod +x "$INSTALL/scripts/apply-guard.sh"
"$INSTALL/scripts/apply-guard.sh"

cd "$INSTALL/source/server"
docker compose --env-file "$INSTALL/.env" -f compose.yaml up -d --build

cd "$INSTALL/client-bundle"
zip -qr "$INSTALL/downloads/router-vpn-client-bundle.zip" .
cp "$INSTALL/downloads/router-vpn-client-bundle.zip" "$INSTALL/router-vpn-client-bundle.zip"

cat <<DONE

Router VPN installed.

ASUS port forwards to this AI Board:
  UDP $WG_PORT  -> $ADGUARD4:$WG_PORT
  UDP $AWG_PORT -> $ADGUARD4:$AWG_PORT
  TCP $REALITY_PORT -> $ADGUARD4:$REALITY_PORT
  UDP $HY2_PORT -> $ADGUARD4:$HY2_PORT
  TCP+UDP $SS_PORT -> $ADGUARD4:$SS_PORT

Do NOT forward TCP 1080, TCP 8787, SSH, Portainer, or AdGuard admin.

Client bundle:
  $INSTALL/downloads/router-vpn-client-bundle.zip
  LAN download: http://$ADGUARD4:8786/router-vpn-client-bundle.zip

SOCKS5 is available only after VPN connection:
  $ADGUARD4:1080
  username: $SOCKS_USER
  password: $SOCKS_PASSWORD

Run diagnostics:
  sudo $INSTALL/source/server/scripts/doctor.sh
DONE
