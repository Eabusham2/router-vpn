#!/usr/bin/env bash
set -euo pipefail
MODE=${1:?mode}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/profile-id.sh"
PROFILE_ID=$(homevpn_profile_id)
RUN="$ROOT/run"
ENDPOINT=${HOMEVPN_ENDPOINT:?Choose a router backend in the app first}
mkdir -p "$RUN"

if [[ $MODE == all ]]; then
  CONF="$RUN/profile-$PROFILE_ID-all"
  rm -rf "$CONF"
  mkdir -p "$CONF"
else
  SOURCE_CONF="$ROOT/generated/$PROFILE_ID/$MODE"
  [[ -d "$SOURCE_CONF" ]] || SOURCE_CONF="$ROOT/generated/$MODE"
  CONF="$RUN/profile-$PROFILE_ID-$MODE"
  rm -rf "$CONF"
  cp -a "$SOURCE_CONF" "$CONF"
  python3 - "$CONF" "$ENDPOINT" <<'PY_ENDPOINT'
from pathlib import Path
import json,re,sys
root=Path(sys.argv[1]); endpoint=sys.argv[2].strip().strip('[]')
wg_host=f'[{endpoint}]' if ':' in endpoint else endpoint

def patch_json(obj):
    if isinstance(obj,dict):
        outbounds=obj.get('outbounds')
        if isinstance(outbounds,list):
            for outbound in outbounds:
                if not isinstance(outbound,dict): continue
                if outbound.get('tag') in ('proxy','outer','transport') and isinstance(outbound.get('server'),str): outbound['server']=endpoint
                settings=outbound.get('settings')
                if isinstance(settings,dict):
                    for vnext in settings.get('vnext',[]) if isinstance(settings.get('vnext'),list) else []:
                        if isinstance(vnext,dict) and 'address' in vnext: vnext['address']=endpoint
        for key,value in list(obj.items()):
            if key in ('endpoint','remote_address') and isinstance(value,str): obj[key]=endpoint
            elif key in ('certificate_path','key_path') and isinstance(value,str) and not value.startswith('/'): obj[key]=str(root/value)
            else: patch_json(value)
    elif isinstance(obj,list):
        for value in obj: patch_json(value)

def patch_text_endpoint(match):
    prefix, old, quote = match.group(1), match.group(2), match.group(3)
    port_match=re.search(r':(\d+)$',old)
    if not port_match: return f'{prefix}{endpoint}{quote}'
    port=port_match.group(1); host=f'[{endpoint}]' if ':' in endpoint else endpoint
    return f'{prefix}{host}:{port}{quote}'

for p in root.rglob('*'):
    if not p.is_file(): continue
    if p.suffix.lower()=='.json':
        try: data=json.loads(p.read_text())
        except Exception: continue
        patch_json(data); p.write_text(json.dumps(data,indent=2)+'\n'); continue
    try: text=p.read_text()
    except UnicodeDecodeError: continue
    text=re.sub(r'(?m)^(Endpoint\s*=\s*).*:(\d+)\s*$', lambda m:f'{m.group(1)}{wg_host}:{m.group(2)}', text)
    text=re.sub(r'(?m)^(endpoint\s*=\s*["\'])(.*?)(["\'])', patch_text_endpoint, text)
    p.write_text(text)
PY_ENDPOINT
fi

export HOMEVPN_MODE="$MODE"
export HOMEVPN_MTU=${HOMEVPN_MTU:-1380}
python3 "$SCRIPT_DIR/mtu-policy.py" apply "$CONF"
"$SCRIPT_DIR/check-mode.sh" "$MODE" >/dev/null
# shellcheck disable=SC2046
eval "$(python3 "$SCRIPT_DIR/dns-policy.py" env)"
export HOMEVPN_DNS_MODE HOMEVPN_DNS_PROTOCOL HOMEVPN_DNS_HOST HOMEVPN_DNS_PORT HOMEVPN_DNS_SERVER_NAME HOMEVPN_DNS_PATH

start_bg(){ "$@" >>"$RUN/$MODE.log" 2>&1 & echo $! >>"$RUN/$MODE.pids"; }
set_dns_hint(){ printf '%s\n' "mode=$HOMEVPN_DNS_MODE" "protocol=$HOMEVPN_DNS_PROTOCOL" "server=$HOMEVPN_DNS_HOST:$HOMEVPN_DNS_PORT" >"$RUN/dns.txt"; }
set_dns_hint
: >"$RUN/$MODE.pids"
socks_only(){ [[ ${HOMEVPN_SOCKS:-false} == true ]]; }
dns_binary(){ if command -v router-vpn-dns >/dev/null 2>&1; then command -v router-vpn-dns; return; fi; if [[ -x "$ROOT/router-vpn-dns" ]]; then printf '%s\n' "$ROOT/router-vpn-dns"; return; fi; echo 'router-vpn-dns is missing; reinstall the current client bundle' >&2; return 1; }
patch_kernel_dns(){ local cfg=$1; python3 - "$cfg" <<'PY'
from pathlib import Path
import re,sys
p=Path(sys.argv[1]); text=p.read_text()
if re.search(r'(?mi)^DNS\s*=',text): text=re.sub(r'(?mi)^DNS\s*=.*$', 'DNS = 127.0.0.1', text)
else: text=text.replace('[Interface]\n','[Interface]\nDNS = 127.0.0.1\n',1)
p.write_text(text)
PY
}
start_dns_proxy(){ local bin pid; bin=$(dns_binary); sudo env HOMEVPN_DNS_PROTOCOL="$HOMEVPN_DNS_PROTOCOL" HOMEVPN_DNS_HOST="$HOMEVPN_DNS_HOST" HOMEVPN_DNS_PORT="$HOMEVPN_DNS_PORT" HOMEVPN_DNS_SERVER_NAME="$HOMEVPN_DNS_SERVER_NAME" HOMEVPN_DNS_PATH="$HOMEVPN_DNS_PATH" "$bin" --listen 127.0.0.1:53 >>"$RUN/$MODE-dns.log" 2>&1 & pid=$!; echo "$pid" >>"$RUN/$MODE.pids"; sleep 0.2; kill -0 "$pid" >/dev/null 2>&1 || { echo 'DNS proxy failed to start' >&2; return 1; }; }
make_local_socks_chain(){ local out="$RUN/local-socks-chain.json"; python3 - "$out" <<'PY'
import json,os,sys
host=os.environ.get('HOMEVPN_SOCKS_HOST','10.77.0.1');port=int(os.environ.get('HOMEVPN_SOCKS_PORT','1080'));server={"type":"socks","tag":"home-socks","server":host,"server_port":port,"version":"5"};cfg={"log":{"level":"warn"},"inbounds":[{"type":"socks","tag":"local-socks","listen":"127.0.0.1","listen_port":1080,"users":[]}],"outbounds":[server],"route":{"final":"home-socks"}};json.dump(cfg,open(sys.argv[1],'w'),indent=2);open(sys.argv[1],'a').write('\n')
PY
printf '%s' "$out"; }
run_kernel_tunnel(){ local tool=$1 full=$2 split=$3; local cfg=$full; socks_only && cfg=$split; if ! socks_only; then patch_kernel_dns "$cfg"; fi; sudo "$tool" up "$cfg"; cleanup_kernel(){ sudo "$tool" down "$cfg" >/dev/null 2>&1 || true; }; trap cleanup_kernel EXIT INT TERM; if socks_only; then local proxy_cfg; proxy_cfg=$(make_local_socks_chain); sudo sing-box run -c "$proxy_cfg"; return; fi; start_dns_proxy; while sleep 3600; do :; done; }
run_sing_box(){ local cfg="$CONF/sing-box.json"; local tmp="$RUN/$MODE-sing-box.json"; python3 "$SCRIPT_DIR/dns-policy.py" patch-sing "$cfg"; if [[ ${HOMEVPN_JUMBO:-false} == true || ${HOMEVPN_SOCKS:-false} == true ]]; then python3 - "$cfg" "$tmp" <<'PY'
import json,os,sys
x=json.load(open(sys.argv[1]))
if os.environ.get('HOMEVPN_SOCKS','false')=='true': x['inbounds']=[{"type":"socks","tag":"socks-in","listen":"127.0.0.1","listen_port":1080,"users":[]}]
else:
    for inbound in x.get('inbounds',[]):
        if inbound.get('type')=='tun' and os.environ.get('HOMEVPN_JUMBO','false')=='true': inbound['mtu']=9000
json.dump(x,open(sys.argv[2],'w'),indent=2);open(sys.argv[2],'a').write('\n')
PY
cfg="$tmp"; fi; sing-box check -D "$CONF" -c "$cfg" >/dev/null; exec sudo sing-box run -D "$CONF" -c "$cfg"; }
run_xray_tun(){ start_bg sudo xray run -c "$CONF/xray.json"; local pid; pid=$(tail -n 1 "$RUN/$MODE.pids"); sleep 1; kill -0 "$pid" >/dev/null 2>&1 || { echo 'Xray REALITY process failed to start' >&2; exit 1; }; run_sing_box; }
case "$MODE" in
  wg) run_kernel_tunnel wg-quick "$CONF/wg.conf" "$CONF/wg-socks.conf" ;;
  awg2-fast|awg2-strong) run_kernel_tunnel awg-quick "$CONF/awg.conf" "$CONF/awg-socks.conf" ;;
  wg-pq|awg2-pq) exec bash "$SCRIPT_DIR/run-pq.sh" "$MODE" "$CONF" ;;
  hysteria2|shadowsocks|naive-h2|naive-h3) run_sing_box ;;
  reality-vision|reality-pq-vision) run_xray_tun ;;
  ss-v2ray) python3 "$SCRIPT_DIR/dns-policy.py" patch-sing "$CONF/sing-box.json"; exec bash "$SCRIPT_DIR/run-ss-v2ray.sh" "$CONF" ;;
  reality-xhttp) exec bash "$SCRIPT_DIR/run-xhttp.sh" ;;
  max-tls-wg|max-quic-wg|max-tls-awg|max-quic-awg) exec bash "$SCRIPT_DIR/run-max.sh" "$MODE" ;;
  all) exec bash "$SCRIPT_DIR/run-all.sh" ;;
  *) echo "unknown mode: $MODE" >&2; exit 2 ;;
esac
