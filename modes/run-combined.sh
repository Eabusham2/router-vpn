#!/usr/bin/env bash
set -euo pipefail
MODE=${1:?combined mode}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/profile-id.sh"
PROFILE_ID=$(homevpn_profile_id)
ENDPOINT=${HOMEVPN_ENDPOINT:?Choose a router backend first}
RUN="$ROOT/run"
# Combined profiles use the same strict per-session staging transaction as every
# other native launcher. Never copy/patch generated private material in place.
CONF=$(python3 "$SCRIPT_DIR/prepare-runtime-profile.py" "$ROOT" "$PROFILE_ID" "$MODE" "$ENDPOINT")
export HOMEVPN_MODE="$MODE"; export HOMEVPN_MTU=${HOMEVPN_MTU:-1380}
python3 "$SCRIPT_DIR/mtu-policy.py" apply "$CONF"
HOMEVPN_PROFILE_ID="$PROFILE_ID" "$SCRIPT_DIR/check-combined.sh" "$MODE" >/dev/null
HOMEVPN_PROFILE_ID="$PROFILE_ID" python3 "$SCRIPT_DIR/dns-policy.py" patch-sing "$CONF/sing-box.json"
python3 "$SCRIPT_DIR/runtime-pids.py" init "$ROOT" "$MODE"
LAST_BG_PID=''
start_bg(){
  "$@" >>"$RUN/$MODE.log" 2>&1 &
  LAST_BG_PID=$!
  python3 "$SCRIPT_DIR/runtime-pids.py" record "$ROOT" "$MODE" "$LAST_BG_PID"
}
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
start_bg sudo xray run -c "$CONF/xray.json";XPID=$LAST_BG_PID;sleep 1;kill -0 "$XPID" >/dev/null 2>&1||{ echo 'combined REALITY Xray branch failed to start' >&2;exit 1; }
exec sudo sing-box run -D "$CONF" -c "$CFG"
