#!/usr/bin/env bash
set -euo pipefail
MODE=${1:?mode}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
PROFILE_ID=$(printf '%s' "${HOMEVPN_PROFILE_ID:-router}" | tr -cd 'A-Za-z0-9_.-')
PROFILE_ID=${PROFILE_ID:-router}
SOURCE_CONF="$ROOT/generated/$PROFILE_ID/$MODE"
[[ -d "$SOURCE_CONF" ]] || SOURCE_CONF="$ROOT/generated/$MODE"
RUN="$ROOT/run"
ENDPOINT=${HOMEVPN_ENDPOINT:?Choose a router backend in the app first}
CONF="$RUN/profile-$PROFILE_ID-$MODE"
rm -rf "$CONF"
mkdir -p "$RUN"
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
                if outbound.get('tag')=='proxy' and isinstance(outbound.get('server'),str):
                    outbound['server']=endpoint
                settings=outbound.get('settings')
                if isinstance(settings,dict):
                    for vnext in settings.get('vnext',[]) if isinstance(settings.get('vnext'),list) else []:
                        if isinstance(vnext,dict) and 'address' in vnext: vnext['address']=endpoint
        for key,value in list(obj.items()):
            if key in ('endpoint','remote_address') and isinstance(value,str): obj[key]=endpoint
            elif key in ('certificate_path','key_path') and isinstance(value,str) and not value.startswith('/'):
                obj[key]=str(root/value)
            else: patch_json(value)
    elif isinstance(obj,list):
        for value in obj: patch_json(value)

for p in root.rglob('*'):
    if not p.is_file(): continue
    if p.suffix.lower()=='.json':
        try: data=json.loads(p.read_text())
        except Exception: continue
        patch_json(data)
        p.write_text(json.dumps(data,indent=2)+'\n')
        continue
    try: text=p.read_text()
    except UnicodeDecodeError: continue
    text=re.sub(r'(?m)^(Endpoint\s*=\s*).*:(\d+)\s*$', lambda m:f'{m.group(1)}{wg_host}:{m.group(2)}', text)
    text=re.sub(r'(?m)^(endpoint\s*=\s*["\']).*?(["\'])', lambda m:f'{m.group(1)}{endpoint}{m.group(2)}', text)
    p.write_text(text)
PY_ENDPOINT
export HOMEVPN_MODE="$MODE"
export HOMEVPN_MTU=${HOMEVPN_MTU:-1380}
"$(dirname "$0")/check-mode.sh" "$MODE" >/dev/null
start_bg(){ "$@" >>"$RUN/$MODE.log" 2>&1 & echo $! >>"$RUN/$MODE.pids"; }
set_dns_hint(){ printf '%s\n%s\n' "${HOMEVPN_ADGUARD4:-}" "${HOMEVPN_ADGUARD6:-}" >"$RUN/dns.txt"; }
set_dns_hint
: >"$RUN/$MODE.pids"

socks_only(){ [[ ${HOMEVPN_SOCKS:-false} == true ]]; }

make_local_socks_chain(){
  local out="$RUN/local-socks-chain.json"
  python3 - "$out" <<'PY'
import json,os,sys
host=os.environ.get('HOMEVPN_SOCKS_HOST','192.168.50.133')
port=int(os.environ.get('HOMEVPN_SOCKS_PORT','1080'))
user=os.environ.get('HOMEVPN_SOCKS_USER','')
pw=os.environ.get('HOMEVPN_SOCKS_PASSWORD','')
server={"type":"socks","tag":"home-socks","server":host,"server_port":port,"version":"5"}
if user or pw: server["username"],server["password"]=user,pw
cfg={
 "log":{"level":"warn"},
 "inbounds":[{"type":"socks","tag":"local-socks","listen":"127.0.0.1","listen_port":1080,"users":[]}],
 "outbounds":[server],
 "route":{"final":"home-socks"}
}
json.dump(cfg,open(sys.argv[1],'w'),indent=2); open(sys.argv[1],'a').write('\n')
PY
  printf '%s' "$out"
}

run_kernel_tunnel(){
  local tool=$1 full=$2 split=$3
  local cfg=$full
  socks_only && cfg=$split
  sudo "$tool" up "$cfg"
  cleanup_kernel(){ sudo "$tool" down "$cfg" >/dev/null 2>&1 || true; }
  trap cleanup_kernel EXIT INT TERM
  if socks_only; then
    local proxy_cfg
    proxy_cfg=$(make_local_socks_chain)
    exec sudo sing-box run -c "$proxy_cfg"
  fi
  while sleep 3600; do :; done
}

run_sing_box(){
  local cfg="$CONF/sing-box.json"
  local tmp="$RUN/$MODE-sing-box.json"
  if [[ ${HOMEVPN_JUMBO:-false} == true || ${HOMEVPN_SOCKS:-false} == true ]]; then
    python3 - "$cfg" "$tmp" <<'PY'
import json,os,sys
x=json.load(open(sys.argv[1]))
if os.environ.get('HOMEVPN_SOCKS','false')=='true':
    x['inbounds']=[{"type":"socks","tag":"socks-in","listen":"127.0.0.1","listen_port":1080,"users":[]}]
else:
    for inbound in x.get('inbounds',[]):
        if inbound.get('type')=='tun' and os.environ.get('HOMEVPN_JUMBO','false')=='true': inbound['mtu']=9000
json.dump(x,open(sys.argv[2],'w'),indent=2); open(sys.argv[2],'a').write('\n')
PY
    cfg="$tmp"
  fi
  exec sudo sing-box run -c "$cfg"
}

case "$MODE" in
  wg)
    run_kernel_tunnel wg-quick "$CONF/wg.conf" "$CONF/wg-socks.conf"
    ;;
  awg2-fast|awg2-strong)
    run_kernel_tunnel awg-quick "$CONF/awg.conf" "$CONF/awg-socks.conf"
    ;;
  wg-pq)
    start_bg sudo rosenpass exchange-config "$CONF/rosenpass.toml"
    sleep 1
    run_kernel_tunnel wg-quick "$CONF/wg.conf" "$CONF/wg-socks.conf"
    ;;
  awg2-pq)
    start_bg sudo rosenpass exchange-config "$CONF/rosenpass.toml"
    sleep 1
    run_kernel_tunnel awg-quick "$CONF/awg.conf" "$CONF/awg-socks.conf"
    ;;
  reality-vision|hysteria2|shadowsocks|ss-v2ray|naive-h2|naive-h3)
    run_sing_box
    ;;
  reality-pq-vision)
    start_bg sudo xray run -c "$CONF/xray.json"
    sleep 1
    run_sing_box
    ;;
  reality-xhttp)
    exec sudo xray run -c "$CONF/xray.json"
    ;;
  wg-quic)
    [[ ${HOMEVPN_DAITA:-false} == true ]] && export GOTATUN_DAITA=1
    exec sudo gotatun --config "$CONF/gotatun.json"
    ;;
  wg-ss-v2ray)
    start_bg sudo sing-box run -c "$CONF/sing-box.json"
    sleep 1
    run_kernel_tunnel wg-quick "$CONF/wg.conf" "$CONF/wg-socks.conf"
    ;;
  max-tls|max-quic)
    set -a; source "$CONF/chain.env"; set +a
    [[ ${HOMEVPN_DAITA:-false} == true ]] && export GOTATUN_DAITA=1
    start_bg sudo xray run -c "$CONF/outer-xray.json"
    start_bg sudo sing-box run -c "$CONF/middle-sing-box.json"
    start_bg sudo rosenpass exchange-config "$CONF/rosenpass.toml"
    sleep 2
    run_kernel_tunnel wg-quick "$CONF/wg.conf" "$CONF/wg-socks.conf"
    ;;
  *) echo "unknown mode: $MODE" >&2; exit 2 ;;
esac
