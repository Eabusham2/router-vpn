#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-}
RUNTIME_DIR=${2:-}
ENDPOINT=${3:-}
TUNNEL_ALIAS=${4:-router-vpn-multihop}

ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROFILE_ID=${HOMEVPN_PROFILE_ID:-}
POLICY_PROFILE_ID=${HOMEVPN_POLICY_PROFILE_ID:-$PROFILE_ID}

[[ "$ACTION" == "check" || "$ACTION" == "up" || "$ACTION" == "down" ]] || { echo 'usage: native-multihop-darwin.sh check|up|down RUNTIME_DIR ENDPOINT [TUNNEL_ALIAS]' >&2; exit 2; }
[[ -n "$RUNTIME_DIR" ]] || { echo 'multihop runtime directory is required' >&2; exit 2; }
[[ -n "$PROFILE_ID" && -n "$POLICY_PROFILE_ID" ]] || { echo 'HOMEVPN_PROFILE_ID and HOMEVPN_POLICY_PROFILE_ID are required' >&2; exit 2; }

RUNTIME_DIR=$(HOMEVPN_ROOT="$ROOT" python3 "$SCRIPT_DIR/cleanup-private-runtime.py" verify-dir "$RUNTIME_DIR") || {
  echo 'refusing unsafe native macOS multihop runtime directory' >&2
  exit 2
}

CONFIG="$RUNTIME_DIR/sing-box.json"
PID_REGISTRY="$SCRIPT_DIR/runtime-pids.py"
PID_MODE=native-multihop-darwin
KILL_SWITCH="$SCRIPT_DIR/kill-switch-platform.py"
OWNER_HELPER="$SCRIPT_DIR/native-wrapper-owner.py"
CHILD_TOKEN=''
EXTERNAL_SESSION=${HOMEVPN_EXTERNAL_SESSION:-}
if [[ -n "$EXTERNAL_SESSION" ]]; then
  [[ ${HOMEVPN_STANDARD_ENGINE:-} == native && "$EXTERNAL_SESSION" =~ ^[a-f0-9]{32}$ ]] || { echo 'Invalid captured external native owner' >&2; exit 1; }
  if [[ "$ACTION" == down ]]; then exit 0; fi
elif [[ -n ${HOMEVPN_NODE_SESSION:-} ]]; then
  [[ ${HOMEVPN_STANDARD_ENGINE:-} == native && "$HOMEVPN_NODE_SESSION" =~ ^[a-f0-9]{32}$ && ${HOMEVPN_NODE_CONFIG_SHA256:-} =~ ^[a-f0-9]{64}$ ]] || { echo 'Invalid captured Router node owner' >&2; exit 1; }
  if [[ "$ACTION" == down ]]; then exit 0; fi
fi

[[ -f "$CONFIG" && ! -L "$CONFIG" ]] || { echo 'prepared multihop sing-box.json is missing or unsafe' >&2; exit 1; }
[[ -f "$KILL_SWITCH" && ! -L "$KILL_SWITCH" ]] || { echo 'macOS kill-switch dispatcher is missing or unsafe' >&2; exit 1; }
[[ -f "$PID_REGISTRY" && ! -L "$PID_REGISTRY" ]] || { echo 'verified Router VPN PID registry is missing or unsafe' >&2; exit 1; }
[[ -f "$OWNER_HELPER" && ! -L "$OWNER_HELPER" ]] || { echo 'native child ownership helper is missing or unsafe' >&2; exit 1; }

stop_owned() {
  [[ -n "$CHILD_TOKEN" ]] || return 0
  python3 "$OWNER_HELPER" stop "$CHILD_TOKEN"
}
stop_legacy_down() {
  local captured tokens
  tokens=$(python3 "$OWNER_HELPER" recorded "$ROOT" "$PID_MODE") || return 1
  while IFS= read -r captured; do
    [[ -n "$captured" ]] || continue
    python3 "$OWNER_HELPER" stop "$captured" || return 1
  done <<< "$tokens"
}

release_guard() {
  HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$ENDPOINT" \
    python3 "$KILL_SWITCH" release >/dev/null 2>&1 || true
}

cleanup() {
  status=$?
  trap - EXIT INT TERM HUP
  stop_owned || status=1
  # Unexpected runtime exit remains fail-closed. Normal app Disconnect releases
  # centrally after teardown; AUTO/SMART/watchdog failure can hold protection.
  # A retired wrapper never deletes whichever directory is currently at its
  # old pathname. Explicit controller teardown owns workspace retirement.
  exit "$status"
}

if [[ "$ACTION" == "down" ]]; then
  stop_legacy_down
  if [[ ${HOMEVPN_KILLSWITCH_HOLD:-0} != 1 ]]; then release_guard; fi
  HOMEVPN_ROOT="$ROOT" python3 "$SCRIPT_DIR/cleanup-private-runtime.py" "$RUNTIME_DIR"
  exit 0
fi

[[ -f "$SCRIPT_DIR/select-standard-engine.sh" && ! -L "$SCRIPT_DIR/select-standard-engine.sh" ]] || { echo 'Owned engine selector is missing' >&2; exit 1; }
source "$SCRIPT_DIR/select-standard-engine.sh"
SING_BOX=$(router_vpn_standard_engine) || { echo 'The selected standard-node engine is unavailable' >&2; exit 1; }
[[ -n "$SING_BOX" && -x "$SING_BOX" ]] || { echo 'sing-box is required for native macOS multihop' >&2; exit 1; }
"$SING_BOX" check -D "$RUNTIME_DIR" -c "$CONFIG" >/dev/null
if [[ "$ACTION" == "check" ]]; then echo 'native macOS multihop graph ready'; exit 0; fi
trap cleanup EXIT INT TERM HUP

# The scoped PF policy is installed before the full-device TUN starts. Its
# watcher only promotes a newly-created utun that owns the public route, so a
# failed or partial startup remains fail-closed instead of leaking cleartext.
HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$ENDPOINT" \
  python3 "$KILL_SWITCH" apply

python3 "$OWNER_HELPER" prune "$ROOT" "$PID_MODE"
if [[ -n ${HOMEVPN_EXTERNAL_SESSION:-} ]]; then
  [[ ${HOMEVPN_STANDARD_ENGINE:-} == native && "$HOMEVPN_EXTERNAL_SESSION" =~ ^[a-f0-9]{32}$ ]] || { echo 'Invalid captured external native owner' >&2; exit 1; }
  "$SING_BOX" routervpn-external --runtime-dir "$RUNTIME_DIR" --session "$HOMEVPN_EXTERNAL_SESSION" &
elif [[ -n ${HOMEVPN_NODE_SESSION:-} ]]; then
  [[ ${HOMEVPN_STANDARD_ENGINE:-} == native && "$HOMEVPN_NODE_SESSION" =~ ^[a-f0-9]{32}$ && ${HOMEVPN_NODE_CONFIG_SHA256:-} =~ ^[a-f0-9]{64}$ ]] || { echo 'Invalid captured Router node TUN owner' >&2; exit 1; }
  "$SING_BOX" routervpn-node --runtime-dir "$RUNTIME_DIR" --session "$HOMEVPN_NODE_SESSION" --config-sha256 "$HOMEVPN_NODE_CONFIG_SHA256" &
else
  "$SING_BOX" run -D "$RUNTIME_DIR" -c "$CONFIG" &
fi
child=$!
CHILD_TOKEN=$(python3 "$OWNER_HELPER" capture "$child") || { echo 'could not capture native macOS child identity' >&2; exit 1; }
if ! python3 "$PID_REGISTRY" record "$ROOT" "$PID_MODE" "$child"; then
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
