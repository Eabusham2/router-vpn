#!/usr/bin/env bash
set -euo pipefail
MODE=${1:?mode}
CONF=${2:?profile directory}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
RUN="$ROOT/run"
ENDPOINT=${HOMEVPN_ENDPOINT:?Choose a router backend in the app first}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 "$SCRIPT_DIR/runtime-pids.py" init "$ROOT" "$MODE"

# shellcheck disable=SC1090
source "$CONF/rosenpass.env"
RP_PORT=${ROSENPASS_PORT:-51822}
RP_KEY="$CONF/${ROSENPASS_KEY_OUT:-rosenpass.psk}"
# shellcheck disable=SC2046
eval "$(python3 "$SCRIPT_DIR/dns-policy.py" env)"
export HOMEVPN_DNS_MODE HOMEVPN_DNS_PROTOCOL HOMEVPN_DNS_HOST HOMEVPN_DNS_PORT HOMEVPN_DNS_SERVER_NAME HOMEVPN_DNS_PATH

# Standard PQ owns the public Rosenpass endpoint explicitly. Generic profile
# staging deliberately leaves rosenpass.toml alone because MAX uses a private
# Rosenpass-over-base-tunnel endpoint instead.
python3 "$SCRIPT_DIR/runtime-config.py" patch-rosenpass "$ROOT" "$CONF/rosenpass.toml" "$ENDPOINT" "$RP_PORT"

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
  python3 "$SCRIPT_DIR/runtime-config.py" patch-kernel-dns "$ROOT" "$CFG"
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
  python3 "$SCRIPT_DIR/runtime-pids.py" record "$ROOT" "$MODE" "$DNS_PID"
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
python3 "$SCRIPT_DIR/runtime-pids.py" record "$ROOT" "$MODE" "$RP_PID"

sudo bash "$SCRIPT_DIR/rosenpass-key-watch.sh" \
  "$ROSENPASS_TOOL" "$ROSENPASS_INTERFACE" "$ROSENPASS_WG_PEER" "$RP_KEY" \
  >>"$RUN/$MODE.log" 2>&1 &
WATCH_PID=$!
python3 "$SCRIPT_DIR/runtime-pids.py" record "$ROOT" "$MODE" "$WATCH_PID"

if [[ ${HOMEVPN_SOCKS:-false} == true ]]; then
  command -v sing-box >/dev/null 2>&1 || { echo 'sing-box is required for SOCKS5-only mode' >&2; exit 1; }
  PROXY="$RUN/$MODE-local-socks.json"
  python3 "$SCRIPT_DIR/runtime-config.py" local-socks "$ROOT" "$PROXY" "${HOMEVPN_SOCKS_HOST:-10.77.0.1}" "${HOMEVPN_SOCKS_PORT:-1080}"
  sudo sing-box run -c "$PROXY" >>"$RUN/$MODE.log" 2>&1 &
  SOCKS_PID=$!
  python3 "$SCRIPT_DIR/runtime-pids.py" record "$ROOT" "$MODE" "$SOCKS_PID"
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
