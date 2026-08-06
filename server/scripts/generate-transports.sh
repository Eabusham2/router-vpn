#!/usr/bin/env bash
set -euo pipefail
BASE=${1:?base directory}
ENDPOINT=${2:?public IP or hostname}
ADGUARD4=${3:?AdGuard IPv4}
REALITY_PORT=${4:-443}
HY2_PORT=${5:-8443}
SS_PORT=${6:-8388}
REALITY_TARGET=${7:-www.microsoft.com:443}
SING_BOX_IMAGE=${SING_BOX_IMAGE:-ghcr.io/sagernet/sing-box:1.13.12}

mkdir -p "$BASE/config/transports" \
  "$BASE/client-bundle/generated/reality-vision" \
  "$BASE/client-bundle/generated/hysteria2" \
  "$BASE/client-bundle/generated/shadowsocks"

sb(){
  if command -v sing-box >/dev/null 2>&1; then sing-box "$@"; else docker run --rm "$SING_BOX_IMAGE" "$@"; fi
}

PAIR=$(sb generate reality-keypair)
REALITY_PRIV=$(printf '%s\n' "$PAIR" | awk -F': *' 'tolower($1) ~ /private/ {print $2; exit}')
REALITY_PUB=$(printf '%s\n' "$PAIR" | awk -F': *' 'tolower($1) ~ /public/ {print $2; exit}')
[[ -n $REALITY_PRIV && -n $REALITY_PUB ]] || { echo 'Could not parse sing-box REALITY keypair.' >&2; exit 1; }
UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())')
SHORT_ID=$(openssl rand -hex 8)
SS_KEY=$(openssl rand -base64 32 | tr -d '\n')
HY2_PASSWORD=$(openssl rand -base64 24 | tr -d '\n=/+' | head -c 28)
TARGET_HOST=${REALITY_TARGET%:*}
TARGET_PORT=${REALITY_TARGET##*:}
[[ $TARGET_PORT =~ ^[0-9]+$ ]] || { TARGET_HOST=$REALITY_TARGET; TARGET_PORT=443; }

CERT_NAME=${ROUTER_VPN_TLS_NAME:-router-vpn.home}
SAN="DNS:$CERT_NAME"
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
  -subj "/CN=$CERT_NAME" -addext "subjectAltName=$SAN" \
  -keyout "$BASE/config/transports/key.pem" -out "$BASE/config/transports/cert.pem" >/dev/null 2>&1
cp "$BASE/config/transports/cert.pem" "$BASE/client-bundle/generated/hysteria2/cert.pem"

python3 - "$BASE" "$ENDPOINT" "$ADGUARD4" "$REALITY_PORT" "$HY2_PORT" "$SS_PORT" "$TARGET_HOST" "$TARGET_PORT" "$REALITY_PRIV" "$REALITY_PUB" "$UUID" "$SHORT_ID" "$SS_KEY" "$HY2_PASSWORD" "$CERT_NAME" <<'PY'
import json,sys,os
(base,endpoint,dns,rp,hp,sp,target,target_port,rpriv,rpub,uuid,shortid,sskey,hy2pass,tls_name)=sys.argv[1:]
rp,hp,sp,target_port=map(int,(rp,hp,sp,target_port))
server={
 "log":{"level":"warn"},
 "inbounds":[
  {"type":"vless","tag":"reality-in","listen":"::","listen_port":rp,
   "users":[{"name":"router-vpn","uuid":uuid,"flow":"xtls-rprx-vision"}],
   "tls":{"enabled":True,"server_name":target,
     "reality":{"enabled":True,"handshake":{"server":target,"server_port":target_port},"private_key":rpriv,"short_id":[shortid],"max_time_difference":"2m"}}},
  {"type":"hysteria2","tag":"hy2-in","listen":"::","listen_port":hp,
   "obfs":{"type":"salamander","password":hy2pass},
   "users":[{"name":"router-vpn","password":hy2pass}],
   "ignore_client_bandwidth":True,
   "tls":{"enabled":True,"certificate_path":"/etc/sing-box/cert.pem","key_path":"/etc/sing-box/key.pem"},
   "masquerade":{"type":"string","status_code":404,"headers":{"content-type":"text/html"},"content":"<html><body>Not found</body></html>"}},
  {"type":"shadowsocks","tag":"ss-in","listen":"::","listen_port":sp,
   "method":"2022-blake3-aes-256-gcm","password":sskey}
 ],
 "outbounds":[{"type":"direct","tag":"direct"}],
 "route":{"final":"direct"}
}
os.makedirs(f"{base}/config/transports",exist_ok=True)
json.dump(server,open(f"{base}/config/transports/server.json","w"),indent=2); open(f"{base}/config/transports/server.json","a").write("\n")

def client(outbound,mtu):
 return {
  "log":{"level":"warn"},
  "dns":{"servers":[{"type":"udp","tag":"home-dns","server":dns,"server_port":53,"detour":"proxy"}],"final":"home-dns"},
  "inbounds":[{"type":"tun","tag":"tun-in","interface_name":"router-vpn","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"mtu":mtu,"auto_route":True,"strict_route":True}],
  "outbounds":[outbound,{"type":"direct","tag":"direct"}],
  "route":{"rules":[{"protocol":"dns","action":"hijack-dns"}],"auto_detect_interface":True,"final":"proxy"}
 }

reality={"type":"vless","tag":"proxy","server":endpoint,"server_port":rp,"uuid":uuid,"flow":"xtls-rprx-vision","network":"tcp","packet_encoding":"xudp",
 "tls":{"enabled":True,"server_name":target,"utls":{"enabled":True,"fingerprint":"chrome"},"reality":{"enabled":True,"public_key":rpub,"short_id":shortid}}}
hy2={"type":"hysteria2","tag":"proxy","server":endpoint,"server_port":hp,"password":hy2pass,"obfs":{"type":"salamander","password":hy2pass},
 "tls":{"enabled":True,"server_name":tls_name,"certificate_path":"cert.pem"}}
ss={"type":"shadowsocks","tag":"proxy","server":endpoint,"server_port":sp,"method":"2022-blake3-aes-256-gcm","password":sskey}
for name,obj,mtu in (("reality-vision",reality,1380),("hysteria2",hy2,1360),("shadowsocks",ss,1380)):
 path=f"{base}/client-bundle/generated/{name}/sing-box.json"
 json.dump(client(obj,mtu),open(path,"w"),indent=2); open(path,"a").write("\n")

secrets={"reality_uuid":uuid,"reality_public_key":rpub,"reality_short_id":shortid,"reality_target":f"{target}:{target_port}","hysteria2_password":hy2pass,"shadowsocks_key":sskey}
json.dump(secrets,open(f"{base}/config/transports/generated-secrets.json","w"),indent=2); open(f"{base}/config/transports/generated-secrets.json","a").write("\n")
PY
chmod 600 "$BASE/config/transports/"* "$BASE/client-bundle/generated/hysteria2/cert.pem" "$BASE/client-bundle/generated/"*/sing-box.json
