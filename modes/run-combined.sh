#!/usr/bin/env bash
set -euo pipefail
MODE=${1:?combined mode}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
PROFILE_ID=$(printf '%s' "${HOMEVPN_PROFILE_ID:-router}" | tr -cd 'A-Za-z0-9_.-'); PROFILE_ID=${PROFILE_ID:-router}
ENDPOINT=${HOMEVPN_ENDPOINT:?Choose a router backend first}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE="$ROOT/generated/$PROFILE_ID/$MODE"; [[ -d "$SOURCE" ]] || SOURCE="$ROOT/generated/$MODE"
RUN="$ROOT/run"; CONF="$RUN/profile-$PROFILE_ID-$MODE"; rm -rf "$CONF"; mkdir -p "$RUN"; cp -a "$SOURCE" "$CONF"
python3 - "$CONF" "$ENDPOINT" <<'PY'
from pathlib import Path
import json,sys
root=Path(sys.argv[1]);endpoint=sys.argv[2].strip().strip('[]')
def patch(x):
    if isinstance(x,dict):
        if isinstance(x.get('server'),str) and x.get('tag') in {'proxy','tcp-stack','udp-stack'}: x['server']=endpoint
        settings=x.get('settings')
        if isinstance(settings,dict):
            for v in settings.get('vnext',[]) if isinstance(settings.get('vnext'),list) else []:
                if isinstance(v,dict) and 'address' in v:v['address']=endpoint
        for k,v in list(x.items()):
            if k in {'certificate_path','key_path'} and isinstance(v,str) and not v.startswith('/'):x[k]=str(root/v)
            else:patch(v)
    elif isinstance(x,list):
        for v in x:patch(v)
for p in root.glob('*.json'):
    data=json.load(open(p));patch(data);p.write_text(json.dumps(data,indent=2)+'\n')
PY
export HOMEVPN_MODE="$MODE"; export HOMEVPN_MTU=${HOMEVPN_MTU:-1380}
python3 "$SCRIPT_DIR/mtu-policy.py" apply "$CONF"
"$SCRIPT_DIR/check-combined.sh" "$MODE" >/dev/null
python3 "$SCRIPT_DIR/dns-policy.py" patch-sing "$CONF/sing-box.json"
: >"$RUN/$MODE.pids"; start_bg(){ "$@" >>"$RUN/$MODE.log" 2>&1 & echo $! >>"$RUN/$MODE.pids"; }
CFG="$CONF/sing-box.json";TMP="$RUN/$MODE-sing-box.json"
if [[ ${HOMEVPN_SOCKS:-false} == true || ${HOMEVPN_JUMBO:-false} == true ]]; then
python3 - "$CFG" "$TMP" <<'PY'
import json,os,sys
x=json.load(open(sys.argv[1]))
if os.environ.get('HOMEVPN_SOCKS','false')=='true':x['inbounds']=[{'type':'socks','tag':'socks-in','listen':'127.0.0.1','listen_port':1080,'users':[]}]
elif os.environ.get('HOMEVPN_JUMBO','false')=='true':
    for inbound in x.get('inbounds',[]):
        if inbound.get('type')=='tun':inbound['mtu']=9000
json.dump(x,open(sys.argv[2],'w'),indent=2);open(sys.argv[2],'a').write('\n')
PY
CFG="$TMP";fi
xray run -test -c "$CONF/xray.json" >/dev/null;sing-box check -D "$CONF" -c "$CFG" >/dev/null
start_bg sudo xray run -c "$CONF/xray.json";XPID=$(tail -n 1 "$RUN/$MODE.pids");sleep 1;kill -0 "$XPID" >/dev/null 2>&1||{ echo 'combined REALITY Xray branch failed to start' >&2;exit 1; }
exec sudo sing-box run -D "$CONF" -c "$CFG"
