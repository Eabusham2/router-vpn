#!/usr/bin/env bash
set -euo pipefail
ENTRY_ID=${1:?entry id}
EXIT_ID=${2:?exit id}
ENTRY_BASE=${3:?wg or awg}
EXIT_MODE=${4:?shadowsocks or hysteria2}
POLICY_ID=${5:?control/policy profile id}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RUN="$ROOT/run/multihop"
HOMEVPN_ROOT="$ROOT" python3 "$SCRIPT_DIR/cleanup-private-runtime.py" "$RUN"
mkdir -p "$RUN"
python3 "$SCRIPT_DIR/multihop.py" build "$ENTRY_ID" "$EXIT_ID" "$ENTRY_BASE" "$EXIT_MODE" "$RUN" >/dev/null
# shellcheck disable=SC1090
. "$RUN/runtime.env"

ENTRY_UP=0
EXIT_PID=''
cleanup(){
  status=$?
  trap - EXIT INT TERM HUP
  if [[ -n ${EXIT_PID:-} ]]; then sudo kill "$EXIT_PID" >/dev/null 2>&1 || true; wait "$EXIT_PID" >/dev/null 2>&1 || true; fi
  if (( ENTRY_UP )); then sudo "$QUICK_TOOL" down "$ENTRY_CONF" >/dev/null 2>&1 || true; fi
  HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$ENTRY_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_ID" HOMEVPN_ENDPOINT="$ENTRY_ENDPOINT" \
    python3 "$SCRIPT_DIR/kill-switch.py" release >/dev/null 2>&1 || true
  HOMEVPN_ROOT="$ROOT" python3 "$SCRIPT_DIR/cleanup-private-runtime.py" "$RUN" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT INT TERM HUP

# The strict firewall follows policy from the selected control profile, but the
# only public exception is the physical entry endpoint. The exit endpoint is
# dialed by entry SOCKS and never appears as an OS/firewall exception.
HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$ENTRY_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_ID" HOMEVPN_ENDPOINT="$ENTRY_ENDPOINT" \
  python3 "$SCRIPT_DIR/kill-switch.py" apply

sudo "$QUICK_TOOL" up "$ENTRY_CONF"
ENTRY_UP=1

# Prove the private entry SOCKS listener is reachable through the split tunnel
# before installing the exit full TUN. This is reachability, not final success.
python3 - "$ENTRY_SOCKS_HOST" "$ENTRY_SOCKS_PORT" <<'PY'
import socket,sys,time
host=sys.argv[1];port=int(sys.argv[2]);last=None
for _ in range(30):
    try:
        s=socket.create_connection((host,port),timeout=.35);s.close();raise SystemExit(0)
    except OSError as exc:
        last=exc;time.sleep(.1)
raise SystemExit(f'entry private SOCKS5 is not reachable through the entry tunnel: {last}')
PY

# Apply the EXIT node's selected DNS policy inside the exit sing-box engine.
# DNS therefore follows proxy -> entry-hop and does not use entry-node DNS.
HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$EXIT_ID" HOMEVPN_ENDPOINT="$EXIT_ENDPOINT" \
  python3 "$SCRIPT_DIR/dns-policy.py" patch-sing "$EXIT_CONFIG"

sing-box check -D "$EXIT_DIR" -c "$EXIT_CONFIG" >/dev/null
sudo sing-box run -D "$EXIT_DIR" -c "$EXIT_CONFIG" &
EXIT_PID=$!
wait "$EXIT_PID"
