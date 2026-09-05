#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-}
RUNTIME_DIR=${2:-}
ENDPOINT=${3:-}
TUNNEL_ALIAS=${4:-router-vpn}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROFILE_ID=${HOMEVPN_PROFILE_ID:-}
POLICY_PROFILE_ID=${HOMEVPN_POLICY_PROFILE_ID:-$PROFILE_ID}

[[ "$ACTION" == "check" || "$ACTION" == "up" || "$ACTION" == "down" ]] || { echo 'usage: native-standard-exit-linux.sh check|up|down RUNTIME_DIR ENDPOINT [TUNNEL_ALIAS]' >&2; exit 2; }
[[ -n "$RUNTIME_DIR" && -n "$PROFILE_ID" && -n "$POLICY_PROFILE_ID" && -n "$ENDPOINT" ]] || { echo 'standard exit runtime, entry profile, policy profile and endpoint are required' >&2; exit 2; }

RUNTIME_DIR=$(HOMEVPN_ROOT="$ROOT" python3 "$SCRIPT_DIR/cleanup-private-runtime.py" verify-dir "$RUNTIME_DIR") || {
  echo 'refusing unsafe native Linux standard-exit runtime directory' >&2
  exit 2
}

CONFIG="$RUNTIME_DIR/sing-box.json"
PID_REGISTRY="$SCRIPT_DIR/runtime-pids.py"
PID_MODE=native-standard-exit-linux
KILL_SWITCH="$SCRIPT_DIR/kill-switch-platform.py"
SING_BOX=$(command -v sing-box || true)
[[ -f "$CONFIG" && ! -L "$CONFIG" ]] || { echo 'prepared standard exit sing-box.json is missing or unsafe' >&2; exit 1; }
[[ -f "$KILL_SWITCH" && ! -L "$KILL_SWITCH" ]] || { echo 'Linux kill-switch dispatcher is missing or unsafe' >&2; exit 1; }
[[ -f "$PID_REGISTRY" && ! -L "$PID_REGISTRY" ]] || { echo 'verified Router VPN PID registry is missing or unsafe' >&2; exit 1; }
[[ -n "$SING_BOX" && -x "$SING_BOX" ]] || { echo 'sing-box is required for Linux standard exit' >&2; exit 1; }
[[ "$TUNNEL_ALIAS" == "router-vpn" ]] || { echo 'Linux strict kill switch permits only the owned router-vpn TUN alias' >&2; exit 1; }

stop_owned() {
  local pid
  while IFS= read -r pid; do
    [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 1 )) || continue
    kill -INT "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done < <(python3 "$PID_REGISTRY" verified-mode "$ROOT" "$PID_MODE" 2>/dev/null || true)
  python3 "$PID_REGISTRY" init "$ROOT" "$PID_MODE" >/dev/null 2>&1 || true
}
release_guard() {
  HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$ENDPOINT" python3 "$KILL_SWITCH" release >/dev/null 2>&1 || true
}
cleanup() {
  status=$?
  trap - EXIT INT TERM HUP
  stop_owned
  # Unexpected child/wrapper failure must not release on-connect/always policy.
  # The Go controller owns normal Disconnect and releases only after teardown;
  # AUTO/SMART/watchdog failure can therefore hold protection without a gap.
  HOMEVPN_ROOT="$ROOT" python3 "$SCRIPT_DIR/cleanup-private-runtime.py" "$RUNTIME_DIR" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT INT TERM HUP

if [[ "$ACTION" == "down" ]]; then release_guard; cleanup; fi
"$SING_BOX" check -D "$RUNTIME_DIR" -c "$CONFIG" >/dev/null
if [[ "$ACTION" == "check" ]]; then echo 'native Linux standard exit graph ready'; trap - EXIT INT TERM HUP; exit 0; fi

# Install fail-closed nftables policy before the full-device TUN starts. Only
# loopback, the physical Router VPN entry endpoint and the owned router-vpn TUN
# are permitted by the existing Linux policy.
HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$ENDPOINT" python3 "$KILL_SWITCH" apply
stop_owned
"$SING_BOX" run -D "$RUNTIME_DIR" -c "$CONFIG" &
child=$!
if ! python3 "$PID_REGISTRY" record "$ROOT" "$PID_MODE" "$child"; then
  kill -TERM "$child" 2>/dev/null || true
  wait "$child" 2>/dev/null || true
  child=''
  echo 'could not prove ownership of native Linux standard-exit process' >&2
  exit 1
fi
sleep 0.5
if ! kill -0 "$child" 2>/dev/null; then wait "$child" || true; echo 'sing-box exited during Linux standard-exit startup' >&2; exit 1; fi
wait "$child"
status=$?
if (( status != 0 )); then echo "sing-box standard exit exited with code $status" >&2; exit "$status"; fi
