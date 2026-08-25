#!/usr/bin/env bash
set -euo pipefail
BASE=${1:?base}
ENDPOINT=${2:?endpoint}
ADGUARD4=${3:?adguard ipv4}
PQ_PORT=${4:-10443}
TARGET=${5:-www.microsoft.com:443}
REALITY_PORT=${6:-443}
PRIVATE_BATCH=/src/server/scripts/atomic-private-batch.py
xr(){ if command -v xray >/dev/null 2>&1; then xray "$@"; else docker run --rm -v "$BASE:$BASE" ghcr.io/xtls/xray-core:26.7.11 "$@"; fi; }
sb(){ if command -v sing-box >/dev/null 2>&1; then sing-box "$@"; else docker run --rm -v "$BASE:$BASE" ghcr.io/sagernet/sing-box:v1.13.12 "$@"; fi; }
umask 077
mkdir -p "$BASE/config/xray" \
  "$BASE/client-bundle/generated/reality-vision" \
  "$BASE/client-bundle/generated/reality-pq-vision"

PRESERVED=$(python3 /src/server/scripts/preserve-generated-state.py xray "$BASE" 2>/dev/null || true)
if [[ -n "$PRESERVED" ]]; then
  eval "$PRESERVED"
  MLDSA_SEED=''
  echo 'Preserving existing standard/PQ REALITY identity for same-deployment upgrade.' >&2
else
  STD_UUID=$(xr uuid | awk 'NF{print $1; exit}')
  PQ_UUID=$(xr uuid | awk 'NF{print $1; exit}')
  PAIR=$(xr x25519)
  REALITY_PRIVATE=$(printf '%s\n' "$PAIR" | awk -F': *' 'tolower($1) ~ /privatekey/ {print $2; exit}')
  REALITY_PASSWORD=$(printf '%s\n' "$PAIR" | awk -F': *' 'tolower($1) ~ /password|publickey/ {print $2; exit}')
  MLDSA=$(xr mldsa65 2>/dev/null || true)
  MLDSA_SEED=$(printf '%s\n' "$MLDSA" | awk -F': *' 'tolower($1) ~ /^seed/ {print $2; exit}')
  MLDSA_VERIFY=$(printf '%s\n' "$MLDSA" | awk -F': *' 'tolower($1) ~ /verify/ {print $2; exit}')
  VLESS=$(xr vlessenc)
  SERVER_DEC=$(printf '%s\n' "$VLESS" | awk '/Authentication: ML-KEM-768/{f=1;next} f && /"decryption"/{sub(/^[^:]*:[[:space:]]*"/,""); sub(/"[,]?$/,""); print; exit}')
  CLIENT_ENC=$(printf '%s\n' "$VLESS" | awk '/Authentication: ML-KEM-768/{f=1;next} f && /"encryption"/{sub(/^[^:]*:[[:space:]]*"/,""); sub(/"[,]?$/,""); print; exit}')
  STD_SHORT_ID=$(openssl rand -hex 8)
  PQ_SHORT_ID=$(openssl rand -hex 8)
fi

TARGET_HOST=${TARGET%:*}; TARGET_PORT=${TARGET##*:}
[[ $TARGET_PORT =~ ^[0-9]+$ ]] || { TARGET_HOST=$TARGET; TARGET_PORT=443; }
for v in STD_UUID PQ_UUID REALITY_PRIVATE REALITY_PASSWORD SERVER_DEC CLIENT_ENC STD_SHORT_ID PQ_SHORT_ID; do
  [[ -n ${!v} ]] || { echo "Failed generating/preserving $v" >&2; exit 1; }
done

GEN_TMP=$(mktemp -d "$BASE/config/xray/.generate.XXXXXX")
trap 'rm -rf "${GEN_TMP:-}"' EXIT
python3 - "$BASE/config/xray/server.json" "$GEN_TMP" "$ENDPOINT" "$ADGUARD4" "$REALITY_PORT" "$PQ_PORT" "$TARGET_HOST" "$TARGET_PORT" "$STD_UUID" "$PQ_UUID" "$REALITY_PRIVATE" "$REALITY_PASSWORD" "$STD_SHORT_ID" "$PQ_SHORT_ID" "$SERVER_DEC" "$CLIENT_ENC" "$MLDSA_SEED" "$MLDSA_VERIFY" <<'PY'
import json,os,pathlib,stat,sys
(old_server,tmp,endpoint,dns,std_port,pq_port,target,tport,std_uuid,pq_uuid,rpriv,rpass,std_short,pq_short,sdec,cenc,mseed,mverify)=sys.argv[1:]
tmp=pathlib.Path(tmp); std_port,pq_port,tport=map(int,(std_port,pq_port,tport))
kept=[]
try:
    info=os.lstat(old_server)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError('refusing non-regular/symlink existing Xray server config')
    old=json.load(open(old_server))
    kept=[x for x in old.get('inbounds',[]) if isinstance(x,dict) and x.get('tag')=='max-xhttp-in']
except FileNotFoundError:
    kept=[]

def reality(short_id):
    return {"show":False,"target":f"{target}:{tport}","xver":0,"serverNames":[target],"privateKey":rpriv,"minClientVer":"26.3.27","maxTimeDiff":120000,"shortIds":[short_id]}

def inbound(tag,port,uuid,decryption,short_id,email):
    return {
      "tag":tag,"listen":"::","port":port,"protocol":"vless",
      "settings":{"clients":[{"id":uuid,"email":email,"flow":"xtls-rprx-vision"}],"decryption":decryption},
      "streamSettings":{"network":"raw","security":"reality","realitySettings":reality(short_id)},
      "sniffing":{"enabled":True,"destOverride":["http","tls","quic"],"routeOnly":True}
    }

server={
 "log":{"loglevel":"warning"},
 "inbounds":[
   inbound("reality-in",std_port,std_uuid,"none",std_short,"router-vpn-reality"),
   inbound("pq-reality-in",pq_port,pq_uuid,sdec,pq_short,"router-vpn-pq")
 ] + kept,
 "outbounds":[{"protocol":"freedom","tag":"direct"}]
}

def client_xray(uuid,port,encryption,short_id,socks_port):
    return {
      "log":{"loglevel":"warning"},
      "inbounds":[{"tag":"local-socks","listen":"127.0.0.1","port":socks_port,"protocol":"socks","settings":{"auth":"noauth","udp":True}}],
      "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":endpoint,"port":port,"users":[{"id":uuid,"flow":"xtls-rprx-vision","encryption":encryption}]}]},
        "streamSettings":{"network":"raw","security":"reality","realitySettings":{"serverName":target,"fingerprint":"chrome","password":rpass,"shortId":short_id}}}]
    }

def wrapper(name,mtu,socks_port,v4,v6):
    return {
      "log":{"level":"warn"},
      "dns":{"servers":[{"type":"udp","tag":"home-dns","server":dns,"server_port":53,"detour":"proxy"}],"final":"home-dns"},
      "inbounds":[{"type":"tun","tag":"tun-in","interface_name":name,"address":[v4,v6],"mtu":mtu,"auto_route":True,"strict_route":True}],
      "outbounds":[{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":socks_port,"version":"5"},{"type":"direct","tag":"direct"}],
      "route":{"rules":[{"protocol":"dns","action":"hijack-dns"}],"auto_detect_interface":True,"final":"proxy"}
    }

values={
 "server.json":server,
 "reality-xray.json":client_xray(std_uuid,std_port,"none",std_short,1091),
 "reality-sing-box.json":wrapper("router-vpn-reality",1380,1091,"172.19.3.1/30","fdfe:dcba:9876:3::1/126"),
 "pq-xray.json":client_xray(pq_uuid,pq_port,cenc,pq_short,1090),
 "pq-sing-box.json":wrapper("router-vpn-pq",1360,1090,"172.19.4.1/30","fdfe:dcba:9876:4::1/126"),
 "generated-secrets.json":{
   "target":f"{target}:{tport}",
   "reality_public_key":rpass,
   "standard_uuid":std_uuid,"standard_short_id":std_short,
   "pq_uuid":pq_uuid,"pq_short_id":pq_short,
   "vless_encryption":cenc,"mldsa65_verify":mverify
 },
}
for name,value in values.items():
    (tmp/name).write_text(json.dumps(value,indent=2)+"\n",encoding="utf-8")
PY

# Validate the complete candidate generation before any authoritative file is
# replaced. A validation failure therefore leaves the prior working identity and
# client configs untouched.
xr run -test -c "$GEN_TMP/server.json" >/dev/null
xr run -test -c "$GEN_TMP/reality-xray.json" >/dev/null
sb check -D "$GEN_TMP" -c "$GEN_TMP/reality-sing-box.json" >/dev/null
xr run -test -c "$GEN_TMP/pq-xray.json" >/dev/null
sb check -D "$GEN_TMP" -c "$GEN_TMP/pq-sing-box.json" >/dev/null

python3 "$PRIVATE_BATCH" \
  "$BASE/config/xray/server.json=$GEN_TMP/server.json" \
  "$BASE/client-bundle/generated/reality-vision/xray.json=$GEN_TMP/reality-xray.json" \
  "$BASE/client-bundle/generated/reality-vision/sing-box.json=$GEN_TMP/reality-sing-box.json" \
  "$BASE/client-bundle/generated/reality-pq-vision/xray.json=$GEN_TMP/pq-xray.json" \
  "$BASE/client-bundle/generated/reality-pq-vision/sing-box.json=$GEN_TMP/pq-sing-box.json" \
  "$BASE/config/xray/generated-secrets.json=$GEN_TMP/generated-secrets.json"
rm -rf "$GEN_TMP"
GEN_TMP=
trap - EXIT
