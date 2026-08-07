#!/usr/bin/env bash
set -euo pipefail
CONF=${1:?profile directory}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
RUN="$ROOT/run"
ENDPOINT=${HOMEVPN_ENDPOINT:?Choose a router backend in the app first}
mkdir -p "$RUN"
command -v sslocal >/dev/null 2>&1 || { echo 'missing command: sslocal' >&2; exit 1; }
command -v v2ray-plugin >/dev/null 2>&1 || { echo 'missing command: v2ray-plugin' >&2; exit 1; }
command -v sing-box >/dev/null 2>&1 || { echo 'missing command: sing-box' >&2; exit 1; }
[[ -s "$CONF/sslocal.json" && -s "$CONF/sing-box.json" ]] || { echo 'missing SS+V2Ray profile' >&2; exit 1; }

# Router profiles are runtime-selectable. Keep the certificate hostname/SNI fixed,
# but always send the transport to the currently selected router endpoint.
python3 - "$CONF/sslocal.json" "$ENDPOINT" <<'PY'
import json,sys
p=sys.argv[1]; x=json.load(open(p)); x['server']=sys.argv[2].strip().strip('[]')
json.dump(x,open(p,'w'),indent=2); open(p,'a').write('\n')
PY

SS_PID=''
cleanup(){
  [[ -n "$SS_PID" ]] && kill "$SS_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

sslocal --log-without-time -c "$CONF/sslocal.json" >>"$RUN/ss-v2ray.log" 2>&1 &
SS_PID=$!
echo "$SS_PID" >>"$RUN/ss-v2ray.pids"
sleep 1
kill -0 "$SS_PID" >/dev/null 2>&1 || { echo 'sslocal/v2ray-plugin failed to start' >&2; exit 1; }

if [[ ${HOMEVPN_SOCKS:-false} == true ]]; then
  # The plugin-backed sslocal process already exposes a standard local SOCKS5.
  # Rebind it to 1080 for app-only mode without starting a TUN.
  kill "$SS_PID" >/dev/null 2>&1 || true
  python3 - "$CONF/sslocal.json" "$RUN/ss-v2ray-socks.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); x['local_port']=1080
json.dump(x,open(sys.argv[2],'w'),indent=2); open(sys.argv[2],'a').write('\n')
PY
  exec sslocal --log-without-time -c "$RUN/ss-v2ray-socks.json"
fi

exec sudo sing-box run -D "$CONF" -c "$CONF/sing-box.json"
