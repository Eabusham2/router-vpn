#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-}
RUNTIME_DIR=${2:-}
BRIDGE_ENDPOINT=${3:-}
SOCKS_PORT=${4:-}
TOR_BIN=${5:-}
SING_BOX_BIN=${6:-}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROFILE_ID=${HOMEVPN_PROFILE_ID:-}
POLICY_PROFILE_ID=${HOMEVPN_POLICY_PROFILE_ID:-$PROFILE_ID}

[[ "$ACTION" == "check" || "$ACTION" == "up" || "$ACTION" == "down" ]] || { echo 'usage: native-tor-bridge.sh check|up|down RUNTIME_DIR BRIDGE_IP SOCKS_PORT TOR_BIN SING_BOX_BIN' >&2; exit 2; }
[[ -n "$RUNTIME_DIR" && -n "$PROFILE_ID" && -n "$POLICY_PROFILE_ID" && -n "$BRIDGE_ENDPOINT" ]] || { echo 'Tor bridge runtime/profile/bridge endpoint are required' >&2; exit 2; }
[[ "$SOCKS_PORT" =~ ^[0-9]+$ ]] && (( SOCKS_PORT >= 1024 && SOCKS_PORT <= 65535 )) || { echo 'invalid Tor SOCKS port' >&2; exit 2; }

RUNTIME_DIR=$(HOMEVPN_ROOT="$ROOT" python3 "$SCRIPT_DIR/cleanup-private-runtime.py" verify-dir "$RUNTIME_DIR") || {
  echo 'refusing unsafe Tor bridge runtime directory' >&2
  exit 2
}
TORRC="$RUNTIME_DIR/torrc"
CONFIG="$RUNTIME_DIR/sing-box.json"
TOR_LOG="$RUNTIME_DIR/tor.log"
PID_REGISTRY="$SCRIPT_DIR/runtime-pids.py"
PID_MODE=native-tor-bridge
KILL_SWITCH="$SCRIPT_DIR/kill-switch-platform.py"

[[ -f "$TORRC" && ! -L "$TORRC" && -f "$CONFIG" && ! -L "$CONFIG" ]] || { echo 'prepared Tor bridge runtime files are missing or unsafe' >&2; exit 1; }
[[ -f "$KILL_SWITCH" && ! -L "$KILL_SWITCH" && -f "$PID_REGISTRY" && ! -L "$PID_REGISTRY" ]] || { echo 'Tor bridge safety helpers are missing or unsafe' >&2; exit 1; }
[[ -n "$TOR_BIN" && -x "$TOR_BIN" && -n "$SING_BOX_BIN" && -x "$SING_BOX_BIN" ]] || { echo 'trusted tor and sing-box binaries are required' >&2; exit 1; }
[[ "$(command -v tor 2>/dev/null || true)" == "$TOR_BIN" ]] || { echo 'Tor binary changed after capability proof' >&2; exit 1; }
[[ "$(command -v sing-box 2>/dev/null || true)" == "$SING_BOX_BIN" ]] || { echo 'sing-box binary changed after capability proof' >&2; exit 1; }

stop_owned() {
  local pid
  while IFS= read -r pid; do
    [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 1 )) || continue
    kill -INT "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done < <(python3 "$PID_REGISTRY" verified-mode "$ROOT" "$PID_MODE" 2>/dev/null || true)
  python3 "$PID_REGISTRY" init "$ROOT" "$PID_MODE" >/dev/null 2>&1 || true
}

release_guard() {
  HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$BRIDGE_ENDPOINT" \
    python3 "$KILL_SWITCH" release >/dev/null 2>&1 || true
}

cleanup() {
  status=$?
  trap - EXIT INT TERM HUP
  stop_owned
  release_guard
  HOMEVPN_ROOT="$ROOT" python3 "$SCRIPT_DIR/cleanup-private-runtime.py" "$RUNTIME_DIR" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT INT TERM HUP

if [[ "$ACTION" == "down" ]]; then cleanup; fi
"$TOR_BIN" --version >/dev/null
"$SING_BOX_BIN" check -D "$RUNTIME_DIR" -c "$CONFIG" >/dev/null
if [[ "$ACTION" == "check" ]]; then
  echo 'native Tor bridge graph ready'
  trap - EXIT INT TERM HUP
  exit 0
fi

# The bridge relay is a literal public IP and is the only pre-tunnel WAN
# exception. Tor/obfs4 therefore cannot fall back to ordinary direct Internet.
HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$BRIDGE_ENDPOINT" \
  python3 "$KILL_SWITCH" apply
stop_owned
: > "$TOR_LOG"
chmod 600 "$TOR_LOG"
"$TOR_BIN" -f "$TORRC" --RunAsDaemon 0 &
tor_pid=$!
if ! python3 "$PID_REGISTRY" record "$ROOT" "$PID_MODE" "$tor_pid"; then
  kill -TERM "$tor_pid" 2>/dev/null || true
  wait "$tor_pid" 2>/dev/null || true
  echo 'could not prove ownership of Tor process' >&2
  exit 1
fi

# Tor process start is not connectivity. Require bootstrap 100% and the owned
# local SOCKS listener before the full-device TUN can start.
bootstrapped=0
for _ in $(seq 1 180); do
  kill -0 "$tor_pid" 2>/dev/null || { wait "$tor_pid" || true; echo 'Tor exited before bridge bootstrap completed' >&2; exit 1; }
  if grep -Fq 'Bootstrapped 100%' "$TOR_LOG" 2>/dev/null; then bootstrapped=1; break; fi
  sleep 0.5
done
(( bootstrapped == 1 )) || { echo 'Tor bridge did not reach Bootstrapped 100% within 90 seconds' >&2; exit 1; }

python3 - "$SOCKS_PORT" <<'PY'
import socket,sys,time
port=int(sys.argv[1]);last=None
for _ in range(20):
    try:
        s=socket.create_connection(("127.0.0.1",port),timeout=.25);s.close();raise SystemExit(0)
    except OSError as exc:
        last=exc;time.sleep(.1)
raise SystemExit(f"Tor SOCKS listener is unavailable after bootstrap: {last}")
PY

"$SING_BOX_BIN" run -D "$RUNTIME_DIR" -c "$CONFIG" &
sing_pid=$!
if ! python3 "$PID_REGISTRY" record "$ROOT" "$PID_MODE" "$sing_pid"; then
  kill -TERM "$sing_pid" 2>/dev/null || true
  wait "$sing_pid" 2>/dev/null || true
  echo 'could not prove ownership of Tor full-device sing-box process' >&2
  exit 1
fi
sleep 0.5
kill -0 "$sing_pid" 2>/dev/null || { wait "$sing_pid" || true; echo 'Tor full-device sing-box exited during startup' >&2; exit 1; }

# Keep the wrapper alive only while both owned children remain alive. Losing Tor
# or the TUN is a hard runtime failure; cleanup tears down the other child and
# releases/reasserts kill-switch policy through the normal ownership path.
while :; do
  if ! kill -0 "$tor_pid" 2>/dev/null; then
    wait "$tor_pid" || true
    echo 'Tor bridge process exited; tearing down full-device path' >&2
    exit 1
  fi
  if ! kill -0 "$sing_pid" 2>/dev/null; then
    wait "$sing_pid" || true
    echo 'Tor full-device sing-box process exited' >&2
    exit 1
  fi
  sleep 0.5
done
