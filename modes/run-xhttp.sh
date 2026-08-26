#!/usr/bin/env bash
set -euo pipefail
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/profile-id.sh"
PROFILE_ID=$(homevpn_profile_id)
ENDPOINT=${HOMEVPN_ENDPOINT:?Choose a router backend first}
RUN="$ROOT/run"
MODE=reality-xhttp

# XHTTP can be entered directly or from run-mode; always establish the same
# validated private staging boundary here instead of copying generated state.
CONF=$(python3 "$SCRIPT_DIR/prepare-runtime-profile.py" "$ROOT" "$PROFILE_ID" "$MODE" "$ENDPOINT")
python3 "$SCRIPT_DIR/runtime-pids.py" init "$ROOT" "$MODE"
export HOMEVPN_MODE="$MODE"
export HOMEVPN_MTU=${HOMEVPN_MTU:-1320}
python3 "$SCRIPT_DIR/mtu-policy.py" apply "$CONF"
HOMEVPN_PROFILE_ID="$PROFILE_ID" "$SCRIPT_DIR/check-mode.sh" "$MODE" >/dev/null
HOMEVPN_PROFILE_ID="$PROFILE_ID" python3 "$SCRIPT_DIR/dns-policy.py" patch-sing "$CONF/sing-box.json"
xray run -test -c "$CONF/xray.json" >/dev/null
sing-box check -D "$CONF" -c "$CONF/sing-box.json" >/dev/null

sudo xray run -c "$CONF/xray.json" >>"$RUN/$MODE.log" 2>&1 &
XPID=$!
python3 "$SCRIPT_DIR/runtime-pids.py" record "$ROOT" "$MODE" "$XPID"
sleep 1
kill -0 "$XPID" >/dev/null 2>&1 || { echo 'XHTTP Xray outer process failed to start' >&2; exit 1; }

CFG="$CONF/sing-box.json"
if [[ ${HOMEVPN_SOCKS:-false} == true || ${HOMEVPN_JUMBO:-false} == true ]]; then
  TMP="$RUN/$MODE-sing-box.json"
  variant=jumbo
  [[ ${HOMEVPN_SOCKS:-false} == true ]] && variant=socks
  python3 "$SCRIPT_DIR/runtime-config.py" sing-variant "$ROOT" "$CFG" "$TMP" "$variant"
  CFG="$TMP"
fi
sing-box check -D "$CONF" -c "$CFG" >/dev/null
exec sudo sing-box run -D "$CONF" -c "$CFG"
