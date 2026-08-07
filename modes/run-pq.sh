#!/usr/bin/env bash
set -euo pipefail
MODE=${1:?mode}
CONF=${2:?profile directory}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
RUN="$ROOT/run"
ENDPOINT=${HOMEVPN_ENDPOINT:?Choose a router backend in the app first}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$RUN"

# shellcheck disable=SC1090
source "$CONF/rosenpass.env"
RP_PORT=${ROSENPASS_PORT:-51822}
RP_KEY="$CONF/${ROSENPASS_KEY_OUT:-rosenpass.psk}"
# shellcheck disable=SC2046
eval "$(python3 "$SCRIPT_DIR/dns-policy.py" env)"
export HOMEVPN_DNS_MODE HOMEVPN_DNS_PROTOCOL HOMEVPN_DNS_HOST HOMEVPN_DNS_PORT HOMEVPN_DNS_SERVER_NAME HOMEVPN_DNS_PATH

# run-mode patches generic endpoint fields, but Rosenpass needs its dedicated UDP port.
python3 - "$CONF/rosenpass.toml" "$ENDPOINT" "$RP_PORT" <<'PY'
from pathlib import Path
import re,sys
path=Path(sys.argv[1]); endpoint=sys.argv[2].strip().strip('[]'); port=int(sys.argv[3])
host=f'[{endpoint}]' if ':' in endpoint else endpoint
text=path.read_text()
text=re.sub(r'(?m)^endpoint\s*=\s*["\'][^"\']*["\']\s*$', f'endpoint = "{host}:{port}"', text)
path.write_text(text)
PY

case "$MODE" in
  wg-pq)
    QUICK=wg-quick
    FULL="$CONF/wg.conf"
    SPLIT="$CONF/wg-socks.conf"
    ;;
  awg2-pq)
    QUICK=awg-quick
    FULL="$CONF/awg.conf"
    SPLIT="$CONF/awg-socks.conf"
    export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
    ;;
  *) echo "unsupported PQ mode: $MODE" >&2; exit 2 ;;
esac

CFG=$FULL
[[ ${HOMEVPN_SOCKS:-false} == true ]] && CFG=$SPLIT
RP_PID=''; WATCH_PID=''; SOCKS_PID=''; DNS_PID=''
cleanup(){
  [[ -n "$DNS_PID" ]] && sudo kill "$DNS_PID" >/dev/null 2>&1 || true
  [[ -n "$SOCKS_PID" ]] && sudo kill "$SOCKS_PID" >/dev/null 2>&1 || true
  [[ -n "$WATCH_PID" ]] && sudo kill "$WATCH_PID" >/dev/null 2>&1 || true
  [[ -n "$RP_PID" ]] && sudo kill "$RP_PID" >/dev/null 2>&1 || true
  sudo "$QUICK" down "$CFG" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if [[ ${HOMEVPN_SOCKS:-false} != true ]]; then
  python3 - "$CFG" <<'PY'
from pathlib import Path
import re,sys
p=Path(sys.argv[1]); text=p.read_text()
if re.search(r'(?mi)^DNS\s*=',text): text=re.sub(r'(?mi)^DNS\s*=.*$','DNS = 127.0.0.1',text)
else: text=text.replace('[Interface]\n','[Interface]\nDNS = 127.0.0.1\n',1)
p.write_text(text)
PY
fi
sudo "$QUICK" up "$CFG"

if [[ ${HOMEVPN_SOCKS:-false} != true ]]; then
  if command -v router-vpn-dns >/dev/null 2>&1; then DNS_BIN=$(command -v router-vpn-dns)
  elif [[ -x "$ROOT/router-vpn-dns" ]]; then DNS_BIN="$ROOT/router-vpn-dns"
  else echo 'router-vpn-dns is missing; reinstall the current client bundle' >&2; exit 1
  fi
  sudo env \
    HOMEVPN_DNS_PROTOCOL="$HOMEVPN_DNS_PROTOCOL" HOMEVPN_DNS_HOST="$HOMEVPN_DNS_HOST" \
    HOMEVPN_DNS_PORT="$HOMEVPN_DNS_PORT" HOMEVPN_DNS_SERVER_NAME="$HOMEVPN_DNS_SERVER_NAME" \
    HOMEVPN_DNS_PATH="$HOMEVPN_DNS_PATH" \
    "$DNS_BIN" --listen 127.0.0.1:53 >>"$RUN/$MODE-dns.log" 2>&1 &
  DNS_PID=$!
  echo "$DNS_PID" >>"$RUN/$MODE.pids"
  sleep 0.2
  kill -0 "$DNS_PID" >/dev/null 2>&1 || { echo 'DNS proxy failed to start' >&2; exit 1; }
fi

# Run Rosenpass from the profile directory so its relative key paths remain private
# to this imported router profile.
(
  cd "$CONF"
  exec sudo rosenpass exchange-config rosenpass.toml
) >>"$RUN/$MODE.log" 2>&1 &
RP_PID=$!
echo "$RP_PID" >>"$RUN/$MODE.pids"

sudo bash "$SCRIPT_DIR/rosenpass-key-watch.sh" \
  "$ROSENPASS_TOOL" "$ROSENPASS_INTERFACE" "$ROSENPASS_WG_PEER" "$RP_KEY" \
  >>"$RUN/$MODE.log" 2>&1 &
WATCH_PID=$!
echo "$WATCH_PID" >>"$RUN/$MODE.pids"

if [[ ${HOMEVPN_SOCKS:-false} == true ]]; then
  command -v sing-box >/dev/null 2>&1 || { echo 'sing-box is required for SOCKS5-only mode' >&2; exit 1; }
  PROXY="$RUN/$MODE-local-socks.json"
  python3 - "$PROXY" <<'PY'
import json,os,sys
server={
  "type":"socks","tag":"home-socks",
  "server":os.environ.get("HOMEVPN_SOCKS_HOST","10.77.0.1"),
  "server_port":int(os.environ.get("HOMEVPN_SOCKS_PORT","1080")),
  "version":"5"
}
cfg={
  "log":{"level":"warn"},
  "inbounds":[{"type":"socks","tag":"local-socks","listen":"127.0.0.1","listen_port":1080,"users":[]}],
  "outbounds":[server],"route":{"final":"home-socks"}
}
json.dump(cfg,open(sys.argv[1],"w"),indent=2); open(sys.argv[1],"a").write("\n")
PY
  sudo sing-box run -c "$PROXY" >>"$RUN/$MODE.log" 2>&1 &
  SOCKS_PID=$!
  echo "$SOCKS_PID" >>"$RUN/$MODE.pids"
fi

# The bootstrap WG/AWG PSK keeps the tunnel usable while the first PQ exchange occurs.
# If Rosenpass exits, fail this mode instead of silently continuing as non-PQ WireGuard.
while kill -0 "$RP_PID" >/dev/null 2>&1; do
  if [[ -n "$SOCKS_PID" ]] && ! kill -0 "$SOCKS_PID" >/dev/null 2>&1; then
    echo 'local SOCKS5 proxy exited' >&2
    exit 1
  fi
  if [[ -n "$DNS_PID" ]] && ! kill -0 "$DNS_PID" >/dev/null 2>&1; then
    echo 'DNS proxy exited' >&2
    exit 1
  fi
  sleep 2
done
echo 'Rosenpass exited; PQ mode stopped instead of falling back silently.' >&2
exit 1
