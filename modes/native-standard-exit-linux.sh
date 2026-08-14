#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-}
RUNTIME_DIR=${2:-}
ENDPOINT=${3:-}
TUNNEL_ALIAS=${4:-router-vpn}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
PROFILE_ID=${HOMEVPN_PROFILE_ID:-}
POLICY_PROFILE_ID=${HOMEVPN_POLICY_PROFILE_ID:-$PROFILE_ID}

[[ "$ACTION" == "check" || "$ACTION" == "up" || "$ACTION" == "down" ]] || { echo 'usage: native-standard-exit-linux.sh check|up|down RUNTIME_DIR ENDPOINT [TUNNEL_ALIAS]' >&2; exit 2; }
[[ -n "$RUNTIME_DIR" && -n "$PROFILE_ID" && -n "$POLICY_PROFILE_ID" && -n "$ENDPOINT" ]] || { echo 'standard exit runtime, entry profile, policy profile and endpoint are required' >&2; exit 2; }

ROOT=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$ROOT")
RUNTIME_DIR=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$RUNTIME_DIR")
RUN_ROOT=$(python3 -c 'import os,sys; print(os.path.realpath(os.path.join(sys.argv[1],"run")))' "$ROOT")
case "$RUNTIME_DIR/" in "$RUN_ROOT"/*) ;; *) echo 'refusing standard exit runtime outside HOMEVPN_ROOT/run' >&2; exit 2;; esac

CONFIG="$RUNTIME_DIR/sing-box.json"
PID_FILE="$RUNTIME_DIR/native-standard-exit.pid"
KILL_SWITCH="$ROOT/modes/kill-switch-platform.py"
[[ -f "$KILL_SWITCH" ]] || KILL_SWITCH="$(dirname "$0")/kill-switch-platform.py"
SING_BOX=$(command -v sing-box || true)
[[ -f "$CONFIG" ]] || { echo 'prepared standard exit sing-box.json is missing' >&2; exit 1; }
[[ -f "$KILL_SWITCH" ]] || { echo 'Linux kill-switch dispatcher is missing' >&2; exit 1; }
[[ -n "$SING_BOX" && -x "$SING_BOX" ]] || { echo 'sing-box is required for Linux standard exit' >&2; exit 1; }
[[ "$TUNNEL_ALIAS" == "router-vpn" ]] || { echo 'Linux strict kill switch permits only the owned router-vpn TUN alias' >&2; exit 1; }

stop_owned() {
  if [[ -f "$PID_FILE" ]]; then
    pid=$(cat "$PID_FILE" 2>/dev/null || true)
    if [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 1 )); then
      kill -INT "$pid" 2>/dev/null || true
      for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
      kill -TERM "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
  fi
}
release_guard() {
  HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$ENDPOINT" python3 "$KILL_SWITCH" release >/dev/null 2>&1 || true
}
cleanup() { trap - EXIT INT TERM HUP; stop_owned; release_guard; }
trap cleanup EXIT INT TERM HUP

if [[ "$ACTION" == "down" ]]; then cleanup; exit 0; fi
"$SING_BOX" check -D "$RUNTIME_DIR" -c "$CONFIG" >/dev/null
if [[ "$ACTION" == "check" ]]; then echo 'native Linux standard exit graph ready'; trap - EXIT INT TERM HUP; exit 0; fi

# Install fail-closed nftables policy before the full-device TUN starts. Only
# loopback, the physical Router VPN entry endpoint and the owned router-vpn TUN
# are permitted by the existing Linux policy.
HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$ENDPOINT" python3 "$KILL_SWITCH" apply
stop_owned
"$SING_BOX" run -D "$RUNTIME_DIR" -c "$CONFIG" &
child=$!
printf '%s\n' "$child" > "$PID_FILE"
sleep 0.5
if ! kill -0 "$child" 2>/dev/null; then wait "$child" || true; echo 'sing-box exited during Linux standard-exit startup' >&2; exit 1; fi
wait "$child"
status=$?
if (( status != 0 )); then echo "sing-box standard exit exited with code $status" >&2; exit "$status"; fi
