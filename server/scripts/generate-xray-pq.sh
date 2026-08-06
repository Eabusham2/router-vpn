#!/usr/bin/env bash
set -euo pipefail
BASE=${1:?base}
ENDPOINT=${2:?endpoint}
ADGUARD4=${3:?adguard ipv4}
PORT=${4:-9443}
TARGET=${5:-www.microsoft.com:443}
xr(){ if command -v xray >/dev/null 2>&1; then xray "$@"; else docker run --rm ghcr.io/xtls/xray-core:latest "$@"; fi; }
mkdir -p "$BASE/config/xray" "$BASE/client-bundle/generated/reality-pq-vision"

UUID=$(xr uuid | awk 'NF{print $1; exit}')
PAIR=$(xr x25519)
REALITY_PRIVATE=$(printf '%s\n' "$PAIR" | awk -F': *' 'tolower($1) ~ /privatekey/ {print $2; exit}')
REALITY_PASSWORD=$(printf '%s\n' "$PAIR" | awk -F': *' 'tolower($1) ~ /password|publickey/ {print $2; exit}')
MLDSA=$(xr mldsa65)
MLDSA_SEED=$(printf '%s\n' "$MLDSA" | awk -F': *' 'tolower($1) ~ /^seed/ {print $2; exit}')
MLDSA_VERIFY=$(printf '%s\n' "$MLDSA" | awk -F': *' 'tolower($1) ~ /verify/ {print $2; exit}')
VLESS=$(xr vlessenc)
SERVER_DEC=$(printf '%s\n' "$VLESS" | awk '/Authentication: ML-KEM-768/{f=1;next} f && /"decryption"/{sub(/^[^:]*:[[:space:]]*"/,""); sub(/"[,]?$/,""); print; exit}')
CLIENT_ENC=$(printf '%s\n' "$VLESS" | awk '/Authentication: ML-KEM-768/{f=1;next} f && /"encryption"/{sub(/^[^:]*:[[:space:]]*"/,""); sub(/"[,]?$/,""); print; exit}')
SHORT_ID=$(openssl rand -hex 8)
TARGET_HOST=${TARGET%:*}; TARGET_PORT=${TARGET##*:}
[[ $TARGET_PORT =~ ^[0-9]+$ ]] || { TARGET_HOST=$TARGET; TARGET_PORT=443; }
for v in UUID REALITY_PRIVATE REALITY_PASSWORD SERVER_DEC CLIENT_ENC; do [[ -n ${!v} ]] || { echo "Failed generating $v" >&2; exit 1; }; done

python3 - "$BASE" "$ENDPOINT" "$ADGUARD4" "$PORT" "$TARGET_HOST" "$TARGET_PORT" "$UUID" "$REALITY_PRIVATE" "$REALITY_PASSWORD" "$SHORT_ID" "$SERVER_DEC" "$CLIENT_ENC" "$MLDSA_SEED" "$MLDSA_VERIFY" <<'PY'
import json,sys,os
(base,endpoint,dns,port,target,tport,uuid,rpriv,rpass,shortid,sdec,cenc,mseed,mverify)=sys.argv[1:]
port,tport=int(port),int(tport)
reality={"show":False,"target":f"{target}:{tport}","xver":0,"serverNames":[target],"privateKey":rpriv,"minClientVer":"26.3.27","maxTimeDiff":120000,"shortIds":[shortid]}
# ML-DSA is included only when key generation succeeded. Target suitability still must be verified with xray tls ping.
# ML-DSA keys are exported for an optional hardened profile after target verification.
server={
 "log":{"loglevel":"warning"},
 "inbounds":[{"tag":"pq-reality-in","listen":"::","port":port,"protocol":"vless",
   "settings":{"clients":[{"id":uuid,"email":"router-vpn","flow":"xtls-rprx-vision"}],"decryption":sdec},
   "streamSettings":{"network":"raw","security":"reality","realitySettings":reality},
   "sniffing":{"enabled":True,"destOverride":["http","tls","quic"],"routeOnly":True}}],
 "outbounds":[{"protocol":"freedom","tag":"direct"}]
}
client_xray={
 "log":{"loglevel":"warning"},
 "inbounds":[{"tag":"local-socks","listen":"127.0.0.1","port":1090,"protocol":"socks","settings":{"auth":"noauth","udp":True}}],
 "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":endpoint,"port":port,"users":[{"id":uuid,"flow":"xtls-rprx-vision","encryption":cenc}]}]},
   "streamSettings":{"network":"raw","security":"reality","realitySettings":{"serverName":target,"fingerprint":"chrome","password":rpass,"shortId":shortid}}}]
}
wrapper={
 "log":{"level":"warn"},
 "dns":{"servers":[{"type":"udp","tag":"home-dns","server":dns,"server_port":53,"detour":"proxy"}],"final":"home-dns"},
 "inbounds":[{"type":"tun","tag":"tun-in","interface_name":"router-vpn","address":["172.19.4.1/30","fdfe:dcba:9876:4::1/126"],"mtu":1360,"auto_route":True,"strict_route":True}],
 "outbounds":[{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1090,"version":"5"},{"type":"direct","tag":"direct"}],
 "route":{"rules":[{"protocol":"dns","action":"hijack-dns"}],"auto_detect_interface":True,"final":"proxy"}
}
os.makedirs(f"{base}/config/xray",exist_ok=True)
json.dump(server,open(f"{base}/config/xray/server.json","w"),indent=2); open(f"{base}/config/xray/server.json","a").write("\n")
os.makedirs(f"{base}/client-bundle/generated/reality-pq-vision",exist_ok=True)
json.dump(client_xray,open(f"{base}/client-bundle/generated/reality-pq-vision/xray.json","w"),indent=2); open(f"{base}/client-bundle/generated/reality-pq-vision/xray.json","a").write("\n")
json.dump(wrapper,open(f"{base}/client-bundle/generated/reality-pq-vision/sing-box.json","w"),indent=2); open(f"{base}/client-bundle/generated/reality-pq-vision/sing-box.json","a").write("\n")
json.dump({"target":f"{target}:{tport}","uuid":uuid,"short_id":shortid,"reality_password":rpass,"vless_encryption":cenc,"mldsa65_verify":mverify},open(f"{base}/config/xray/generated-secrets.json","w"),indent=2)
PY
chmod 600 "$BASE/config/xray/"*.json "$BASE/client-bundle/generated/reality-pq-vision/"*.json
