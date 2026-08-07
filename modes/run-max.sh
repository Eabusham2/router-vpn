#!/usr/bin/env bash
set -euo pipefail
MODE=${1:?MAX mode}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
PROFILE_ID=$(printf '%s' "${HOMEVPN_PROFILE_ID:-router}" | tr -cd 'A-Za-z0-9_.-')
PROFILE_ID=${PROFILE_ID:-router}
ENDPOINT=${HOMEVPN_ENDPOINT:?Choose a router backend first}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE="$ROOT/generated/$PROFILE_ID/$MODE"
[[ -d "$SOURCE" ]] || SOURCE="$ROOT/generated/$MODE"
RUN="$ROOT/run"
CONF="$RUN/profile-$PROFILE_ID-$MODE"
rm -rf "$CONF"; mkdir -p "$RUN"; cp -a "$SOURCE" "$CONF"
HOMEVPN_PROFILE_ID="$PROFILE_ID" "$SCRIPT_DIR/check-mode.sh" "$MODE" >/dev/null

case "$MODE" in
  max-tls-wg|max-quic-wg) BASE_KIND=wg; QUICK=wg-quick; FULL="$CONF/wg.conf"; SPLIT="$CONF/wg-socks.conf" ;;
  max-tls-awg|max-quic-awg) BASE_KIND=awg; QUICK=awg-quick; FULL="$CONF/awg.conf"; SPLIT="$CONF/awg-socks.conf"; export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go ;;
  *) echo "unsupported MAX mode: $MODE" >&2; exit 2 ;;
esac

python3 - "$CONF" "$ENDPOINT" <<'PY'
from pathlib import Path
import json,sys
root=Path(sys.argv[1]); endpoint=sys.argv[2].strip().strip('[]')
def patch(x):
    if isinstance(x,dict):
        if isinstance(x.get('server'),str) and x.get('tag') in {'proxy','outer','transport'}:
            x['server']=endpoint
        settings=x.get('settings')
        if isinstance(settings,dict):
            for v in settings.get('vnext',[]) if isinstance(settings.get('vnext'),list) else []:
                if isinstance(v,dict) and 'address' in v: v['address']=endpoint
        for k,v in x.items():
            if isinstance(v,(dict,list)): patch(v)
    elif isinstance(x,list):
        for v in x: patch(v)
for p in root.glob('*.json'):
    try: x=json.load(open(p))
    except Exception: continue
    patch(x); p.write_text(json.dumps(x,indent=2)+'\n')
PY

# shellcheck disable=SC1090
source "$CONF/chain.env"
[[ ${CHAIN_READY:-0} == 1 && ${PQ_BASE:-0} == 1 ]] || { echo 'MAX profile is not validated with PQ base' >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONF/rosenpass.env"
RP_KEY="$CONF/${ROSENPASS_KEY_OUT:-rosenpass.psk}"
# shellcheck disable=SC2046
eval "$(python3 "$SCRIPT_DIR/dns-policy.py" env)"
export HOMEVPN_DNS_MODE HOMEVPN_DNS_PROTOCOL HOMEVPN_DNS_HOST HOMEVPN_DNS_PORT HOMEVPN_DNS_SERVER_NAME HOMEVPN_DNS_PATH

CFG=$FULL
[[ ${HOMEVPN_SOCKS:-false} == true ]] && CFG=$SPLIT
PIDS=(); BASE_UP=0
add_bg(){ "$@" >>"$RUN/$MODE.log" 2>&1 & PIDS+=("$!"); echo "$!" >>"$RUN/$MODE.pids"; }
cleanup(){
  for p in "${PIDS[@]:-}"; do sudo kill "$p" >/dev/null 2>&1 || true; done
  if (( BASE_UP )); then sudo "$QUICK" down "$CFG" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT INT TERM
: >"$RUN/$MODE.pids"

case "${OUTER_ENGINE:-}" in
  xray) add_bg sudo xray run -c "$CONF/outer-xray.json" ;;
  sing-box|none) ;;
  *) echo "invalid MAX OUTER_ENGINE: ${OUTER_ENGINE:-unset}" >&2; exit 1 ;;
esac
add_bg sudo sing-box run -D "$CONF" -c "$CONF/middle-sing-box.json"
sleep 1
for p in "${PIDS[@]}"; do kill -0 "$p" >/dev/null 2>&1 || { echo 'MAX outer chain failed to start' >&2; exit 1; }; done

if [[ ${HOMEVPN_SOCKS:-false} != true ]]; then
  python3 - "$CFG" <<'PY'
from pathlib import Path
import re,sys
p=Path(sys.argv[1]); t=p.read_text()
if re.search(r'(?mi)^DNS\s*=',t): t=re.sub(r'(?mi)^DNS\s*=.*$','DNS = 127.0.0.1',t)
else: t=t.replace('[Interface]\n','[Interface]\nDNS = 127.0.0.1\n',1)
p.write_text(t)
PY
fi
sudo "$QUICK" up "$CFG"; BASE_UP=1

# Rosenpass endpoint in MAX profiles is the router's private WG/AWG tunnel address,
# so PQ exchange itself travels through the already-established outer MAX path.
(
  cd "$CONF"
  exec sudo rosenpass exchange-config rosenpass.toml
) >>"$RUN/$MODE.log" 2>&1 &
RP_PID=$!; PIDS+=("$RP_PID"); echo "$RP_PID" >>"$RUN/$MODE.pids"
add_bg sudo bash "$SCRIPT_DIR/rosenpass-key-watch.sh" \
  "$ROSENPASS_TOOL" "$ROSENPASS_INTERFACE" "$ROSENPASS_WG_PEER" "$RP_KEY"

if [[ ${HOMEVPN_SOCKS:-false} == true ]]; then
  PROXY="$RUN/$MODE-local-socks.json"
  python3 - "$PROXY" "$BASE_KIND" <<'PY'
import json,os,sys
host='10.77.0.1' if sys.argv[2]=='wg' else '10.78.0.1'
server={"type":"socks","tag":"home-socks","server":host,"server_port":int(os.environ.get('HOMEVPN_SOCKS_PORT','1080')),"version":"5"}
cfg={"log":{"level":"warn"},"inbounds":[{"type":"socks","tag":"local-socks","listen":"127.0.0.1","listen_port":1080,"users":[]}],"outbounds":[server],"route":{"final":"home-socks"}}
json.dump(cfg,open(sys.argv[1],'w'),indent=2); open(sys.argv[1],'a').write('\n')
PY
  add_bg sudo sing-box run -c "$PROXY"
else
  if command -v router-vpn-dns >/dev/null 2>&1; then DNS_BIN=$(command -v router-vpn-dns)
  elif [[ -x "$ROOT/router-vpn-dns" ]]; then DNS_BIN="$ROOT/router-vpn-dns"
  else echo 'router-vpn-dns is missing; reinstall current client bundle' >&2; exit 1
  fi
  add_bg sudo env \
    HOMEVPN_DNS_PROTOCOL="$HOMEVPN_DNS_PROTOCOL" HOMEVPN_DNS_HOST="$HOMEVPN_DNS_HOST" \
    HOMEVPN_DNS_PORT="$HOMEVPN_DNS_PORT" HOMEVPN_DNS_SERVER_NAME="$HOMEVPN_DNS_SERVER_NAME" \
    HOMEVPN_DNS_PATH="$HOMEVPN_DNS_PATH" "$DNS_BIN" --listen 127.0.0.1:53
fi

sleep 1
while :; do
  for p in "${PIDS[@]}"; do
    kill -0 "$p" >/dev/null 2>&1 || { echo "MAX component exited; stopping $MODE instead of silently degrading" >&2; exit 1; }
  done
  sleep 2
done
