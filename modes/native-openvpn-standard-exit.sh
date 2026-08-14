#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-}
RUNTIME_DIR=${2:-}
ENDPOINT=${3:-}
OPENVPN_BIN=${4:-}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
PROFILE_ID=${HOMEVPN_PROFILE_ID:-}
POLICY_PROFILE_ID=${HOMEVPN_POLICY_PROFILE_ID:-$PROFILE_ID}

[[ "$ACTION" == "check" || "$ACTION" == "up" || "$ACTION" == "down" ]] || { echo 'usage: native-openvpn-standard-exit.sh check|up|down RUNTIME_DIR ENDPOINT OPENVPN_BIN' >&2; exit 2; }
[[ -n "$RUNTIME_DIR" && -n "$ENDPOINT" && -n "$OPENVPN_BIN" ]] || { echo 'runtime directory, endpoint and OpenVPN binary are required' >&2; exit 2; }
[[ -n "$PROFILE_ID" && -n "$POLICY_PROFILE_ID" ]] || { echo 'HOMEVPN_PROFILE_ID and HOMEVPN_POLICY_PROFILE_ID are required' >&2; exit 2; }

ROOT=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$ROOT")
RUNTIME_DIR=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$RUNTIME_DIR")
RUN_ROOT=$(python3 -c 'import os,sys; print(os.path.realpath(os.path.join(sys.argv[1],"run")))' "$ROOT")
case "$RUNTIME_DIR/" in "$RUN_ROOT"/*) ;; *) echo 'refusing OpenVPN runtime outside HOMEVPN_ROOT/run' >&2; exit 2;; esac

CONFIG="$RUNTIME_DIR/client.ovpn"
PID_FILE="$RUNTIME_DIR/openvpn.pid"
KILL_SWITCH="$ROOT/modes/kill-switch-platform.py"
[[ -f "$CONFIG" ]] || { echo 'prepared OpenVPN client.ovpn is missing' >&2; exit 1; }
[[ -f "$KILL_SWITCH" ]] || { echo 'Router VPN platform kill switch is missing' >&2; exit 1; }
[[ -x "$OPENVPN_BIN" ]] || { echo 'OpenVPN runtime is missing/not executable' >&2; exit 1; }
"$OPENVPN_BIN" --version | head -n1 | grep -Eq '^OpenVPN 2\.7\.' || { echo 'Router VPN requires OpenVPN 2.7.x for custom exits' >&2; exit 1; }

root_prefix=()
if [[ $(id -u) -ne 0 ]]; then
  SUDO=$(command -v sudo || true)
  [[ -n "$SUDO" ]] || { echo 'root privileges are required for native OpenVPN TUN' >&2; exit 1; }
  root_prefix=("$SUDO" -n)
fi

stop_owned() {
  if [[ -f "$PID_FILE" ]]; then
    pid=$(cat "$PID_FILE" 2>/dev/null || true)
    if [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 1 )); then
      "${root_prefix[@]}" kill -INT "$pid" 2>/dev/null || true
      for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        "${root_prefix[@]}" kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
      "${root_prefix[@]}" kill -TERM "$pid" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
  fi
}

release_guard() {
  HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$ENDPOINT" \
    python3 "$KILL_SWITCH" release >/dev/null 2>&1 || true
}

cleanup() {
  status=$?
  trap - EXIT INT TERM HUP
  stop_owned
  release_guard
  rm -rf "$RUNTIME_DIR" 2>/dev/null || true
  exit "$status"
}
trap cleanup EXIT INT TERM HUP

if [[ "$ACTION" == "down" ]]; then cleanup; fi

# Apply the Router VPN policy before OpenVPN creates any full-tunnel route.
# Linux permits only the owned router-vpn TUN; macOS begins with only the
# literal external endpoint and promotes the newly-created routed utun.
HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$ENDPOINT" \
  python3 "$KILL_SWITCH" apply

if [[ "$ACTION" == "check" ]]; then
  release_guard
  trap - EXIT INT TERM HUP
  echo 'native OpenVPN standard-exit policy ready'
  exit 0
fi

stop_owned
"${root_prefix[@]}" "$OPENVPN_BIN" --config "$CONFIG" &
child=$!
printf '%s\n' "$child" > "$PID_FILE"
sleep 0.5
if ! "${root_prefix[@]}" kill -0 "$child" 2>/dev/null; then
  wait "$child" || true
  echo 'OpenVPN exited during native standard-exit startup' >&2
  exit 1
fi
wait "$child"
status=$?
if (( status != 0 )); then echo "OpenVPN standard exit exited with code $status" >&2; exit "$status"; fi
