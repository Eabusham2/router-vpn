#!/usr/bin/env bash
set -euo pipefail
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
PROFILE_ID=$(printf '%s' "${HOMEVPN_PROFILE_ID:-router}" | tr -cd 'A-Za-z0-9_.-')
PROFILE_ID=${PROFILE_ID:-router}
ENDPOINT=${HOMEVPN_ENDPOINT:?Choose a router backend first}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE="$ROOT/generated/$PROFILE_ID/reality-xhttp"
[[ -d "$SOURCE" ]] || SOURCE="$ROOT/generated/reality-xhttp"
RUN="$ROOT/run"
CONF="$RUN/profile-$PROFILE_ID-reality-xhttp"
rm -rf "$CONF"; mkdir -p "$RUN"; cp -a "$SOURCE" "$CONF"
HOMEVPN_PROFILE_ID="$PROFILE_ID" "$SCRIPT_DIR/check-mode.sh" reality-xhttp >/dev/null

python3 - "$CONF/xray.json" "$ENDPOINT" <<'PY'
import json,sys
p=sys.argv[1]; endpoint=sys.argv[2].strip().strip('[]'); x=json.load(open(p))
for out in x.get('outbounds',[]):
    settings=out.get('settings',{}) if isinstance(out,dict) else {}
    for v in settings.get('vnext',[]) if isinstance(settings.get('vnext'),list) else []:
        if isinstance(v,dict) and 'address' in v: v['address']=endpoint
json.dump(x,open(p,'w'),indent=2); open(p,'a').write('\n')
PY
python3 "$SCRIPT_DIR/dns-policy.py" patch-sing "$CONF/sing-box.json"
xray run -test -c "$CONF/xray.json" >/dev/null
sing-box check -D "$CONF" -c "$CONF/sing-box.json" >/dev/null

: >"$RUN/reality-xhttp.pids"
sudo xray run -c "$CONF/xray.json" >>"$RUN/reality-xhttp.log" 2>&1 &
XPID=$!
echo "$XPID" >>"$RUN/reality-xhttp.pids"
sleep 1
kill -0 "$XPID" >/dev/null 2>&1 || { echo 'XHTTP Xray outer process failed to start' >&2; exit 1; }

CFG="$CONF/sing-box.json"
if [[ ${HOMEVPN_SOCKS:-false} == true || ${HOMEVPN_JUMBO:-false} == true ]]; then
  TMP="$RUN/reality-xhttp-sing-box.json"
  python3 - "$CFG" "$TMP" <<'PY'
import json,os,sys
x=json.load(open(sys.argv[1]))
if os.environ.get('HOMEVPN_SOCKS','false')=='true':
    x['inbounds']=[{'type':'socks','tag':'socks-in','listen':'127.0.0.1','listen_port':1080,'users':[]}]
elif os.environ.get('HOMEVPN_JUMBO','false')=='true':
    for inbound in x.get('inbounds',[]):
        if inbound.get('type')=='tun': inbound['mtu']=9000
json.dump(x,open(sys.argv[2],'w'),indent=2); open(sys.argv[2],'a').write('\n')
PY
  CFG="$TMP"
fi
sing-box check -D "$CONF" -c "$CFG" >/dev/null
exec sudo sing-box run -D "$CONF" -c "$CFG"
