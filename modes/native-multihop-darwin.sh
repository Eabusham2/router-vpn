#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-}
RUNTIME_DIR=${2:-}
ENDPOINT=${3:-}
TUNNEL_ALIAS=${4:-router-vpn-multihop}

ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
PROFILE_ID=${HOMEVPN_PROFILE_ID:-}
POLICY_PROFILE_ID=${HOMEVPN_POLICY_PROFILE_ID:-$PROFILE_ID}

[[ "$ACTION" == "check" || "$ACTION" == "up" || "$ACTION" == "down" ]] || { echo 'usage: native-multihop-darwin.sh check|up|down RUNTIME_DIR ENDPOINT [TUNNEL_ALIAS]' >&2; exit 2; }
[[ -n "$RUNTIME_DIR" ]] || { echo 'multihop runtime directory is required' >&2; exit 2; }
[[ -n "$PROFILE_ID" && -n "$POLICY_PROFILE_ID" ]] || { echo 'HOMEVPN_PROFILE_ID and HOMEVPN_POLICY_PROFILE_ID are required' >&2; exit 2; }

ROOT=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$ROOT")
RUNTIME_DIR=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$RUNTIME_DIR")
RUN_ROOT=$(python3 -c 'import os,sys; print(os.path.realpath(os.path.join(sys.argv[1],"run")))' "$ROOT")
case "$RUNTIME_DIR/" in
  "$RUN_ROOT"/*) ;;
  *) echo 'refusing multihop runtime outside HOMEVPN_ROOT/run' >&2; exit 2;;
esac

CONFIG="$RUNTIME_DIR/sing-box.json"
PID_REGISTRY="$ROOT/modes/runtime-pids.py"
PID_MODE=native-multihop-darwin
KILL_SWITCH="$ROOT/modes/kill-switch-platform.py"
SING_BOX=$(command -v sing-box || true)

[[ -f "$CONFIG" ]] || { echo 'prepared multihop sing-box.json is missing' >&2; exit 1; }
[[ -x "$KILL_SWITCH" || -f "$KILL_SWITCH" ]] || { echo 'macOS kill-switch dispatcher is missing' >&2; exit 1; }
[[ -f "$PID_REGISTRY" && ! -L "$PID_REGISTRY" ]] || { echo 'verified Router VPN PID registry is missing or unsafe' >&2; exit 1; }
[[ -n "$SING_BOX" && -x "$SING_BOX" ]] || { echo 'sing-box is required for native macOS multihop' >&2; exit 1; }

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
  # Empty the owned registry atomically. If the registry path itself is unsafe,
  # the helper refuses it; cleanup never guesses a process from raw PID text.
  python3 "$PID_REGISTRY" init "$ROOT" "$PID_MODE" >/dev/null 2>&1 || true
}

release_guard() {
  HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$ENDPOINT" \
    python3 "$KILL_SWITCH" release >/dev/null 2>&1 || true
}

cleanup() {
  trap - EXIT INT TERM HUP
  stop_owned
  release_guard
  HOMEVPN_ROOT="$ROOT" python3 "$ROOT/modes/cleanup-private-runtime.py" "$RUNTIME_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM HUP

if [[ "$ACTION" == "down" ]]; then
  cleanup
  exit 0
fi

"$SING_BOX" check -D "$RUNTIME_DIR" -c "$CONFIG" >/dev/null

# The scoped PF policy is installed before the full-device TUN starts. Its
# watcher only promotes a newly-created utun that owns the public route, so a
# failed or partial startup remains fail-closed instead of leaking cleartext.
HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$ENDPOINT" \
  python3 "$KILL_SWITCH" apply

if [[ "$ACTION" == "check" ]]; then
  release_guard
  trap - EXIT INT TERM HUP
  HOMEVPN_ROOT="$ROOT" python3 "$ROOT/modes/cleanup-private-runtime.py" "$RUNTIME_DIR" >/dev/null 2>&1 || true
  echo 'native macOS multihop graph ready'
  exit 0
fi

stop_owned
"$SING_BOX" run -D "$RUNTIME_DIR" -c "$CONFIG" &
child=$!
if ! python3 "$PID_REGISTRY" record "$ROOT" "$PID_MODE" "$child"; then
  kill -TERM "$child" 2>/dev/null || true
  wait "$child" 2>/dev/null || true
  child=''
  echo 'could not prove ownership of native macOS multihop process' >&2
  exit 1
fi

sleep 0.5
if ! kill -0 "$child" 2>/dev/null; then
  wait "$child" || true
  echo 'sing-box exited during native macOS multihop startup' >&2
  exit 1
fi

wait "$child"
status=$?
if (( status != 0 )); then
  echo "sing-box multihop exited with code $status" >&2
  exit "$status"
fi
