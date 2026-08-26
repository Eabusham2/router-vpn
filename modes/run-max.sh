#!/usr/bin/env bash
set -euo pipefail
MODE=${1:?MAX mode}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/profile-id.sh"
PROFILE_ID=$(homevpn_profile_id)
ENDPOINT=${HOMEVPN_ENDPOINT:?Choose a router backend first}
RUN="$ROOT/run"

# MAX is also launched directly by ALL, so it must own the same safe staging
# boundary as run-mode instead of assuming a caller already prepared CONF.
CONF=$(python3 "$SCRIPT_DIR/prepare-runtime-profile.py" "$ROOT" "$PROFILE_ID" "$MODE" "$ENDPOINT")
python3 "$SCRIPT_DIR/runtime-pids.py" init "$ROOT" "$MODE"
export HOMEVPN_MODE="$MODE"
export HOMEVPN_MTU=${HOMEVPN_MTU:-1280}

case "$MODE" in
  max-tls-wg|max-quic-wg)
    BASE_KIND=wg; QUICK=wg-quick; FULL="$CONF/wg.conf"; SPLIT="$CONF/wg-socks.conf"
    ;;
  max-tls-awg|max-quic-awg)
    BASE_KIND=awg; QUICK=awg-quick; FULL="$CONF/awg.conf"; SPLIT="$CONF/awg-socks.conf"
    export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
    ;;
  *)
    echo "unsupported MAX mode: $MODE" >&2
    exit 2
    ;;
esac

python3 "$SCRIPT_DIR/mtu-policy.py" apply "$CONF"
HOMEVPN_PROFILE_ID="$PROFILE_ID" "$SCRIPT_DIR/check-mode.sh" "$MODE" >/dev/null
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
PIDS=()
BASE_UP=0
LAST_BG_PID=''
add_bg(){
  "$@" >>"$RUN/$MODE.log" 2>&1 &
  LAST_BG_PID=$!
  PIDS+=("$LAST_BG_PID")
  python3 "$SCRIPT_DIR/runtime-pids.py" record "$ROOT" "$MODE" "$LAST_BG_PID"
}
cleanup(){
  for p in "${PIDS[@]:-}"; do sudo kill "$p" >/dev/null 2>&1 || true; done
  if (( BASE_UP )); then sudo "$QUICK" down "$CFG" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT INT TERM

case "${OUTER_ENGINE:-}" in
  xray) add_bg sudo xray run -c "$CONF/outer-xray.json" ;;
  sing-box|none) ;;
  *) echo "invalid MAX OUTER_ENGINE: ${OUTER_ENGINE:-unset}" >&2; exit 1 ;;
esac
add_bg sudo sing-box run -D "$CONF" -c "$CONF/middle-sing-box.json"
sleep 1
for p in "${PIDS[@]}"; do
  kill -0 "$p" >/dev/null 2>&1 || { echo 'MAX outer chain failed to start' >&2; exit 1; }
done

if [[ ${HOMEVPN_SOCKS:-false} != true ]]; then
  python3 "$SCRIPT_DIR/runtime-config.py" patch-kernel-dns "$ROOT" "$CFG"
fi
sudo "$QUICK" up "$CFG"
BASE_UP=1

(
  cd "$CONF"
  exec sudo rosenpass exchange-config rosenpass.toml
) >>"$RUN/$MODE.log" 2>&1 &
RP_PID=$!
PIDS+=("$RP_PID")
python3 "$SCRIPT_DIR/runtime-pids.py" record "$ROOT" "$MODE" "$RP_PID"
add_bg sudo bash "$SCRIPT_DIR/rosenpass-key-watch.sh" "$ROSENPASS_TOOL" "$ROSENPASS_INTERFACE" "$ROSENPASS_WG_PEER" "$RP_KEY"

if [[ ${HOMEVPN_SOCKS:-false} == true ]]; then
  PROXY="$RUN/$MODE-local-socks.json"
  if [[ $BASE_KIND == wg ]]; then SOCKS_HOST=10.77.0.1; else SOCKS_HOST=10.78.0.1; fi
  python3 "$SCRIPT_DIR/runtime-config.py" local-socks "$ROOT" "$PROXY" "$SOCKS_HOST" "${HOMEVPN_SOCKS_PORT:-1080}"
  add_bg sudo sing-box run -c "$PROXY"
else
  if command -v router-vpn-dns >/dev/null 2>&1; then
    DNS_BIN=$(command -v router-vpn-dns)
  elif [[ -x "$ROOT/router-vpn-dns" ]]; then
    DNS_BIN="$ROOT/router-vpn-dns"
  else
    echo 'router-vpn-dns is missing; reinstall current client bundle' >&2
    exit 1
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
