#!/usr/bin/env bash
set -euo pipefail
BASE=${1:?base directory}
ENDPOINT=${2:?public endpoint}
ADGUARD4=${3:?AdGuard IPv4}
SS_V2RAY_PORT=${SS_V2RAY_PORT:-12443}
NAIVE_PORT=${NAIVE_PORT:-13443}
SS_V2RAY_PATH=${SS_V2RAY_PATH:-/cdn/assets}
SING_BOX_IMAGE=${SING_BOX_IMAGE:-ghcr.io/sagernet/sing-box:v1.13.12}
PRIVATE_BATCH=/src/server/scripts/atomic-private-batch.py
umask 077

sb(){
  if command -v sing-box >/dev/null 2>&1; then sing-box "$@"; else docker run --rm -v "$BASE:$BASE" "$SING_BOX_IMAGE" "$@"; fi
}

TLS_NAME=${ROUTER_VPN_TLS_NAME:-}
if [[ -z "$TLS_NAME" ]]; then
  TLS_NAME=$(python3 - "$ENDPOINT" <<'PY'
import ipaddress,re,sys
value=sys.argv[1].strip().strip('[]')
try:
    ip=ipaddress.ip_address(value)
except ValueError:
    if re.fullmatch(r'(?i)[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',value):
        print(value.lower())
    raise SystemExit
if ip.version==4 and ip.is_global:
    print(str(ip).replace('.','-')+'.sslip.io')
PY
  )
fi
if [[ -z "$TLS_NAME" ]]; then
  echo 'TLS alternates require a public IPv4 endpoint or ROUTER_VPN_TLS_NAME hostname.' >&2
  exit 1
fi

mkdir -p "$BASE/config/tls" \
  "$BASE/client-bundle/generated/ss-v2ray" \
  "$BASE/client-bundle/generated/naive-h2" \
  "$BASE/client-bundle/generated/naive-h3"
TLS_SETTINGS="$BASE/config/tls/settings.env"
if [[ -e "$TLS_SETTINGS" || -e "$BASE/client-bundle/generated/ss-v2ray/sslocal.json" || -e "$BASE/client-bundle/generated/naive-h2/sing-box.json" || -e "$BASE/client-bundle/generated/naive-h3/sing-box.json" ]]; then
  if [[ ! -e "$TLS_SETTINGS" ]]; then
    echo 'Existing TLS alternate client state has no credential settings; refusing silent credential rotation.' >&2
    exit 1
  fi
  if ! PRESERVED=$(python3 /src/server/scripts/preserve-generated-state.py tls "$BASE"); then
    echo 'Existing SS+V2Ray/Naive credential state is corrupt/incomplete; refusing silent credential rotation.' >&2
    exit 1
  fi
  eval "$PRESERVED"
  echo 'Preserving existing SS+V2Ray/Naive credentials for same-deployment upgrade.' >&2
else
  SS_V2RAY_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
  NAIVE_USER=rvpn$(openssl rand -hex 4)
  NAIVE_PASSWORD=$(openssl rand -base64 24 | tr -d '\n=/+' | head -c 28)
fi

GEN_TMP=$(mktemp -d "$BASE/config/tls/.generate.XXXXXX")
trap 'rm -rf "${GEN_TMP:-}"' EXIT
mkdir -p "$GEN_TMP/ss-v2ray" "$GEN_TMP/naive-h2" "$GEN_TMP/naive-h3"
cat >"$GEN_TMP/settings.env" <<EOF
TLS_NAME='$TLS_NAME'
SS_V2RAY_PORT='$SS_V2RAY_PORT'
SS_V2RAY_METHOD='2022-blake3-aes-256-gcm'
SS_V2RAY_PASSWORD='$SS_V2RAY_PASSWORD'
SS_V2RAY_PATH='$SS_V2RAY_PATH'
NAIVE_PORT='$NAIVE_PORT'
NAIVE_USER='$NAIVE_USER'
NAIVE_PASSWORD='$NAIVE_PASSWORD'
EOF
chmod 600 "$GEN_TMP/settings.env"

python3 - "$BASE" "$GEN_TMP" "$ENDPOINT" "$ADGUARD4" "$TLS_NAME" "$SS_V2RAY_PORT" "$SS_V2RAY_PASSWORD" "$SS_V2RAY_PATH" "$NAIVE_PORT" "$NAIVE_USER" "$NAIVE_PASSWORD" <<'PY'
from pathlib import Path
import copy,json,os,stat,sys
(base,tmp,endpoint,dns,tls_name,ss_port,ss_pw,ss_path,naive_port,naive_user,naive_pw)=sys.argv[1:]
base=Path(base); tmp=Path(tmp); ss_port=int(ss_port); naive_port=int(naive_port)
gen=base/'client-bundle'/'generated'
hy_path=gen/'hysteria2'/'sing-box.json'
info=hy_path.lstat()
if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
    raise RuntimeError('refusing non-regular/symlink Hysteria2 source profile')
hy=json.loads(hy_path.read_text(encoding='utf-8'))
hy_out=copy.deepcopy(next(x for x in hy.get('outbounds',[]) if x.get('tag')=='proxy'))
hy_out['tag']='udp-stack'

def tun(name,mtu):
    return {"type":"tun","tag":"tun-in","interface_name":name,"address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"mtu":mtu,"auto_route":True,"strict_route":True}

def dns_cfg(detour='proxy'):
    return {"servers":[{"type":"udp","tag":"home-dns","server":dns,"server_port":53,"detour":detour}],"final":"home-dns"}

sslocal={
  "server":endpoint,"server_port":ss_port,
  "password":ss_pw,"method":"2022-blake3-aes-256-gcm",
  "local_address":"127.0.0.1","local_port":1092,
  "mode":"tcp_only","plugin":"v2ray-plugin",
  "plugin_opts":f"tls;host={tls_name};path={ss_path}"
}
ss_socks={"type":"socks","tag":"tcp-stack","server":"127.0.0.1","server_port":1092,"version":"5"}
ss_tun={
  "log":{"level":"warn"},"dns":dns_cfg('tcp-stack'),"inbounds":[tun('router-vpn-ss-v2ray',1320)],
  "outbounds":[ss_socks,hy_out,{"type":"direct","tag":"direct"}],
  "route":{"rules":[{"protocol":"dns","action":"hijack-dns"},{"network":"tcp","action":"route","outbound":"tcp-stack"},{"network":"udp","action":"route","outbound":"udp-stack"}],"auto_detect_interface":True,"final":"tcp-stack"}
}

def naive(quic: bool, name: str):
    outbound={
      "type":"naive","tag":"proxy","server":endpoint,"server_port":naive_port,
      "username":naive_user,"password":naive_pw,
      "udp_over_tcp":False if quic else {"enabled":True,"version":2},"quic":quic,
      "tls":{"enabled":True,"server_name":tls_name}
    }
    return {
      "log":{"level":"warn"},"dns":dns_cfg('proxy'),"inbounds":[tun(name,1300 if quic else 1320)],
      "outbounds":[outbound,{"type":"direct","tag":"direct"}],
      "route":{"rules":[{"protocol":"dns","action":"hijack-dns"}],"auto_detect_interface":True,"final":"proxy"}
    }

(tmp/'ss-v2ray'/'sslocal.json').write_text(json.dumps(sslocal,indent=2)+'\n',encoding='utf-8')
(tmp/'ss-v2ray'/'sing-box.json').write_text(json.dumps(ss_tun,indent=2)+'\n',encoding='utf-8')
cert=gen/'hysteria2'/'cert.pem'
cert_info=cert.lstat()
if stat.S_ISLNK(cert_info.st_mode) or not stat.S_ISREG(cert_info.st_mode) or cert_info.st_size <= 0:
    raise RuntimeError('refusing invalid Hysteria2 certificate source')
(tmp/'ss-v2ray'/'cert.pem').write_bytes(cert.read_bytes())
(tmp/'naive-h2'/'sing-box.json').write_text(json.dumps(naive(False,'router-vpn-naive-h2'),indent=2)+'\n',encoding='utf-8')
(tmp/'naive-h3'/'sing-box.json').write_text(json.dumps(naive(True,'router-vpn-naive-h3'),indent=2)+'\n',encoding='utf-8')
meta={
  "tls_name":tls_name,"certificate":"automatic public ACME certificate managed by Caddy",
  "certificate_http_challenge_port":80,"ss_v2ray_port":ss_port,"naive_port":naive_port,
  "ss_v2ray_path":ss_path
}
(tmp/'generated.json').write_text(json.dumps(meta,indent=2)+'\n',encoding='utf-8')
for path in tmp.rglob('*'):
    if path.is_file(): os.chmod(path,0o600)
PY

# Validate every candidate supported by this validator before adopting any
# authoritative TLS credential/client state.
sb check -D "$GEN_TMP/ss-v2ray" -c "$GEN_TMP/ss-v2ray/sing-box.json" >/dev/null
if sb version 2>&1 | grep -q 'with_naive_outbound'; then
  for d in naive-h2 naive-h3; do
    sb check -D "$GEN_TMP/$d" -c "$GEN_TMP/$d/sing-box.json" >/dev/null
  done
else
  echo 'sing-box validator lacks with_naive_outbound; Naive profile validation deferred to the client readiness check.' >&2
fi

python3 "$PRIVATE_BATCH" \
  "$BASE/config/tls/settings.env=$GEN_TMP/settings.env" \
  "$BASE/config/tls/generated.json=$GEN_TMP/generated.json" \
  "$BASE/client-bundle/generated/ss-v2ray/sslocal.json=$GEN_TMP/ss-v2ray/sslocal.json" \
  "$BASE/client-bundle/generated/ss-v2ray/sing-box.json=$GEN_TMP/ss-v2ray/sing-box.json" \
  "$BASE/client-bundle/generated/ss-v2ray/cert.pem=$GEN_TMP/ss-v2ray/cert.pem" \
  "$BASE/client-bundle/generated/naive-h2/sing-box.json=$GEN_TMP/naive-h2/sing-box.json" \
  "$BASE/client-bundle/generated/naive-h3/sing-box.json=$GEN_TMP/naive-h3/sing-box.json"
rm -rf "$GEN_TMP"
GEN_TMP=
trap - EXIT
printf 'Generated TLS hostname %s and validated available SS+V2Ray / Naive client profiles.\n' "$TLS_NAME"
