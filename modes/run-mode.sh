#!/usr/bin/env bash
set -euo pipefail
MODE=${1:?mode}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
CONF="$ROOT/generated/$MODE"
RUN="$ROOT/run"
mkdir -p "$RUN"
export HOMEVPN_MODE="$MODE"
export HOMEVPN_MTU=${HOMEVPN_MTU:-1380}
"$(dirname "$0")/check-mode.sh" "$MODE" >/dev/null
start_bg(){ "$@" >>"$RUN/$MODE.log" 2>&1 & echo $! >>"$RUN/$MODE.pids"; }
set_dns_hint(){ printf '%s\n%s\n' "${HOMEVPN_ADGUARD4:-}" "${HOMEVPN_ADGUARD6:-}" >"$RUN/dns.txt"; }
set_dns_hint
: >"$RUN/$MODE.pids"
run_sing_box(){
  local cfg="$CONF/sing-box.json"
  if [[ ${HOMEVPN_JUMBO:-false} == true ]]; then
    local tmp="$RUN/$MODE-sing-box.json"
    python3 - "$cfg" "$tmp" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
for inbound in x.get('inbounds',[]):
    if inbound.get('type')=='tun': inbound['mtu']=9000
json.dump(x,open(sys.argv[2],'w'),indent=2)
PY
    cfg="$tmp"
  fi
  exec sudo sing-box run -c "$cfg"
}
case "$MODE" in
  wg)
    exec sudo wg-quick up "$CONF/wg.conf"
    ;;
  awg2-fast|awg2-strong)
    exec sudo awg-quick up "$CONF/awg.conf"
    ;;
  wg-pq)
    start_bg sudo rosenpass exchange-config "$CONF/rosenpass.toml"
    sleep 1
    exec sudo wg-quick up "$CONF/wg.conf"
    ;;
  awg2-pq)
    start_bg sudo rosenpass exchange-config "$CONF/rosenpass.toml"
    sleep 1
    exec sudo awg-quick up "$CONF/awg.conf"
    ;;
  reality-vision|hysteria2|shadowsocks|ss-v2ray|naive-h2|naive-h3)
    run_sing_box
    ;;
  reality-xhttp)
    exec sudo xray run -c "$CONF/xray.json"
    ;;
  wg-quic)
    if [[ ${HOMEVPN_DAITA:-false} == true ]]; then export GOTATUN_DAITA=1; fi
    exec sudo gotatun --config "$CONF/gotatun.json"
    ;;
  wg-ss-v2ray)
    start_bg sudo sing-box run -c "$CONF/sing-box.json"
    sleep 1
    exec sudo wg-quick up "$CONF/wg.conf"
    ;;
  max-tls|max-quic)
    # Configs define local hop ports and routes. The launcher supervises all compatible layers.
    set -a; source "$CONF/chain.env"; set +a
    [[ ${HOMEVPN_DAITA:-false} == true ]] && export GOTATUN_DAITA=1
    start_bg sudo xray run -c "$CONF/outer-xray.json"
    start_bg sudo sing-box run -c "$CONF/middle-sing-box.json"
    start_bg sudo rosenpass exchange-config "$CONF/rosenpass.toml"
    sleep 2
    exec sudo wg-quick up "$CONF/wg.conf"
    ;;
  *) echo "unknown mode: $MODE" >&2; exit 2 ;;
esac
