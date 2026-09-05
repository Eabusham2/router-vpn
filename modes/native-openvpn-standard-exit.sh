#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-}
RUNTIME_DIR=${2:-}
ENDPOINT=${3:-}
OPENVPN_BIN=${4:-}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROFILE_ID=${HOMEVPN_PROFILE_ID:-}
POLICY_PROFILE_ID=${HOMEVPN_POLICY_PROFILE_ID:-$PROFILE_ID}

[[ "$ACTION" == "check" || "$ACTION" == "up" || "$ACTION" == "down" ]] || { echo 'usage: native-openvpn-standard-exit.sh check|up|down RUNTIME_DIR ENDPOINT OPENVPN_BIN' >&2; exit 2; }
[[ -n "$RUNTIME_DIR" && -n "$ENDPOINT" && -n "$OPENVPN_BIN" ]] || { echo 'runtime directory, endpoint and OpenVPN binary are required' >&2; exit 2; }
[[ -n "$PROFILE_ID" && -n "$POLICY_PROFILE_ID" ]] || { echo 'HOMEVPN_PROFILE_ID and HOMEVPN_POLICY_PROFILE_ID are required' >&2; exit 2; }

RUNTIME_DIR=$(HOMEVPN_ROOT="$ROOT" python3 "$SCRIPT_DIR/cleanup-private-runtime.py" verify-dir "$RUNTIME_DIR") || {
  echo 'refusing unsafe native OpenVPN runtime directory' >&2
  exit 2
}

CONFIG="$RUNTIME_DIR/client.ovpn"
BRIDGE_CONFIG="$RUNTIME_DIR/entry-bridge.json"
PID_REGISTRY="$SCRIPT_DIR/runtime-pids.py"
PID_MODE_OPENVPN=native-openvpn-standard-exit
PID_MODE_BRIDGE=native-openvpn-entry-bridge
KILL_SWITCH="$SCRIPT_DIR/kill-switch-platform.py"
[[ -f "$CONFIG" && ! -L "$CONFIG" ]] || { echo 'prepared OpenVPN client.ovpn is missing or unsafe' >&2; exit 1; }
[[ -f "$KILL_SWITCH" && ! -L "$KILL_SWITCH" ]] || { echo 'Router VPN platform kill switch is missing or unsafe' >&2; exit 1; }
[[ -f "$PID_REGISTRY" && ! -L "$PID_REGISTRY" ]] || { echo 'verified Router VPN PID registry is missing or unsafe' >&2; exit 1; }
[[ -x "$OPENVPN_BIN" ]] || { echo 'OpenVPN runtime is missing/not executable' >&2; exit 1; }
"$OPENVPN_BIN" --version | head -n1 | grep -Eq '^OpenVPN 2\.7\.' || { echo 'Router VPN requires OpenVPN 2.7.x for custom exits' >&2; exit 1; }

SINGBOX=''
if [[ -e "$BRIDGE_CONFIG" ]]; then
  [[ -f "$BRIDGE_CONFIG" && ! -L "$BRIDGE_CONFIG" ]] || { echo 'OpenVPN entry bridge config is unsafe' >&2; exit 1; }
  SINGBOX=$(command -v sing-box || true)
  [[ -n "$SINGBOX" ]] || { echo 'sing-box is required for Router VPN -> OpenVPN hopping' >&2; exit 1; }
  "$SINGBOX" check -D "$RUNTIME_DIR" -c "$BRIDGE_CONFIG" >/dev/null
fi

root_prefix=()
if [[ $(id -u) -ne 0 ]]; then
  SUDO=$(command -v sudo || true)
  [[ -n "$SUDO" ]] || { echo 'root privileges are required for native OpenVPN TUN' >&2; exit 1; }
  root_prefix=("$SUDO" -n)
fi

kill_pid() {
  local pid=${1:-}
  [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 1 )) || return 0
  kill -INT "$pid" 2>/dev/null || "${root_prefix[@]}" kill -INT "$pid" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    kill -0 "$pid" 2>/dev/null || "${root_prefix[@]}" kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.1
  done
  kill -TERM "$pid" 2>/dev/null || "${root_prefix[@]}" kill -TERM "$pid" 2>/dev/null || true
}

stop_mode() {
  local mode=$1 pid
  while IFS= read -r pid; do
    kill_pid "$pid"
  done < <(python3 "$PID_REGISTRY" verified-mode "$ROOT" "$mode" 2>/dev/null || true)
  python3 "$PID_REGISTRY" init "$ROOT" "$mode" >/dev/null 2>&1 || true
}

stop_owned() {
  stop_mode "$PID_MODE_OPENVPN"
  stop_mode "$PID_MODE_BRIDGE"
}

release_guard() {
  HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$ENDPOINT" \
    python3 "$KILL_SWITCH" release >/dev/null 2>&1 || true
}

cleanup() {
  status=$?
  trap - EXIT INT TERM HUP
  stop_owned
  # Runtime failure remains protected. Normal controller Disconnect releases
  # after teardown; transitions/watchdog failure may intentionally hold policy.
  HOMEVPN_ROOT="$ROOT" python3 "$SCRIPT_DIR/cleanup-private-runtime.py" "$RUNTIME_DIR" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT INT TERM HUP

if [[ "$ACTION" == "down" ]]; then release_guard; cleanup; fi

# Apply strict policy before either the Router VPN entry bridge or final
# OpenVPN TUN can emit traffic. For a hop, ENDPOINT is the physical Router VPN
# entry endpoint; the external OpenVPN server is reachable only inside entry-wg.
HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$ENDPOINT" \
  python3 "$KILL_SWITCH" apply

if [[ "$ACTION" == "check" ]]; then
  release_guard
  trap - EXIT INT TERM HUP
  echo 'native OpenVPN standard-exit policy ready'
  exit 0
fi

stop_owned
BRIDGE_PID=''
if [[ -f "$BRIDGE_CONFIG" ]]; then
  "$SINGBOX" run -D "$RUNTIME_DIR" -c "$BRIDGE_CONFIG" &
  BRIDGE_PID=$!
  if ! python3 "$PID_REGISTRY" record "$ROOT" "$PID_MODE_BRIDGE" "$BRIDGE_PID"; then
    kill_pid "$BRIDGE_PID"
    wait "$BRIDGE_PID" 2>/dev/null || true
    BRIDGE_PID=''
    echo 'could not prove ownership of OpenVPN entry bridge process' >&2
    exit 1
  fi
  python3 - <<'PY'
import socket,time
last=None
for _ in range(50):
    try:
        s=socket.create_connection(('127.0.0.1',1100),timeout=.15);s.close();raise SystemExit(0)
    except OSError as exc:
        last=exc;time.sleep(.1)
raise SystemExit(f'Router VPN OpenVPN entry bridge did not become ready: {last}')
PY
fi

"${root_prefix[@]}" "$OPENVPN_BIN" --config "$CONFIG" &
child=$!
# Give sudo/OpenVPN one bounded moment to settle on its stable command identity
# before recording the shell child. A process that vanishes here is never owned.
sleep 0.1
if ! kill -0 "$child" 2>/dev/null && ! "${root_prefix[@]}" kill -0 "$child" 2>/dev/null; then
  wait "$child" || true
  echo 'OpenVPN exited during native standard-exit startup' >&2
  exit 1
fi
if ! python3 "$PID_REGISTRY" record "$ROOT" "$PID_MODE_OPENVPN" "$child"; then
  kill_pid "$child"
  wait "$child" 2>/dev/null || true
  child=''
  echo 'could not prove ownership of native OpenVPN process' >&2
  exit 1
fi
sleep 0.4
if ! kill -0 "$child" 2>/dev/null && ! "${root_prefix[@]}" kill -0 "$child" 2>/dev/null; then
  wait "$child" || true
  echo 'OpenVPN exited during native standard-exit startup' >&2
  exit 1
fi

# macOS kill-switch promotion is handled by kill-switch-platform.py's watcher
# once the newly-created OpenVPN utun owns the public route. Linux's strict
# nftables policy already allows only the owned router-vpn TUN plus the physical
# endpoint exception.
while kill -0 "$child" 2>/dev/null || "${root_prefix[@]}" kill -0 "$child" 2>/dev/null; do
  if [[ -n "$BRIDGE_PID" ]] && ! kill -0 "$BRIDGE_PID" 2>/dev/null; then
    echo 'Router VPN entry bridge exited while OpenVPN hop was active' >&2
    exit 1
  fi
  sleep 0.25
done
wait "$child"
status=$?
if (( status != 0 )); then echo "OpenVPN standard exit exited with code $status" >&2; exit "$status"; fi
