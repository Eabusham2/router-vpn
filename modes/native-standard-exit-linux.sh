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
OWNER_HELPER="$SCRIPT_DIR/native-wrapper-owner.py"
CHILD_TOKEN=''
EXTERNAL_SESSION=${HOMEVPN_EXTERNAL_SESSION:-}
if [[ -n "$EXTERNAL_SESSION" ]]; then
  [[ ${HOMEVPN_STANDARD_ENGINE:-} == native && "$EXTERNAL_SESSION" =~ ^[a-f0-9]{32}$ ]] || { echo 'Invalid captured external native owner' >&2; exit 1; }
  # The controller has already required the native lease-close acknowledgement.
  # Its pinned directory/process owner performs final cleanup, including retries.
  if [[ "$ACTION" == down ]]; then exit 0; fi
fi
[[ -f "$CONFIG" && ! -L "$CONFIG" ]] || { echo 'prepared standard exit sing-box.json is missing or unsafe' >&2; exit 1; }
[[ -f "$KILL_SWITCH" && ! -L "$KILL_SWITCH" ]] || { echo 'Linux kill-switch dispatcher is missing or unsafe' >&2; exit 1; }
[[ -f "$PID_REGISTRY" && ! -L "$PID_REGISTRY" ]] || { echo 'verified Router VPN PID registry is missing or unsafe' >&2; exit 1; }
[[ -f "$OWNER_HELPER" && ! -L "$OWNER_HELPER" ]] || { echo 'native child ownership helper is missing or unsafe' >&2; exit 1; }
[[ "$TUNNEL_ALIAS" == "router-vpn" ]] || { echo 'Linux strict kill switch permits only the owned router-vpn TUN alias' >&2; exit 1; }

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
  HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$ENDPOINT" python3 "$KILL_SWITCH" release >/dev/null 2>&1 || true
}
cleanup() {
  status=$?
  trap - EXIT INT TERM HUP
  stop_owned || status=1
  # Unexpected child/wrapper failure must not release on-connect/always policy.
  # The Go controller owns normal Disconnect and releases only after teardown;
  # AUTO/SMART/watchdog failure can therefore hold protection without a gap.
  # Never delete from an asynchronous wrapper trap: the path may now belong to
  # a replacement. Explicit controller teardown owns private workspace cleanup.
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
[[ -n "$SING_BOX" && -x "$SING_BOX" ]] || { echo 'sing-box is required for Linux standard exit' >&2; exit 1; }
"$SING_BOX" check -D "$RUNTIME_DIR" -c "$CONFIG" >/dev/null
if [[ "$ACTION" == "check" ]]; then echo 'native Linux standard exit graph ready'; exit 0; fi
trap cleanup EXIT INT TERM HUP

# Install fail-closed nftables policy before the full-device TUN starts. Only
# loopback, the physical Router VPN entry endpoint and the owned router-vpn TUN
# are permitted by the existing Linux policy.
HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$ENDPOINT" python3 "$KILL_SWITCH" apply
python3 "$OWNER_HELPER" prune "$ROOT" "$PID_MODE"
if [[ -n ${HOMEVPN_EXTERNAL_SESSION:-} ]]; then
  [[ ${HOMEVPN_STANDARD_ENGINE:-} == native && "$HOMEVPN_EXTERNAL_SESSION" =~ ^[a-f0-9]{32}$ ]] || { echo 'Invalid captured external native owner' >&2; exit 1; }
  "$SING_BOX" routervpn-external --runtime-dir "$RUNTIME_DIR" --session "$HOMEVPN_EXTERNAL_SESSION" &
else
  "$SING_BOX" run -D "$RUNTIME_DIR" -c "$CONFIG" &
fi
child=$!
CHILD_TOKEN=$(python3 "$OWNER_HELPER" capture "$child") || { echo 'could not capture native Linux child identity' >&2; exit 1; }
if ! python3 "$PID_REGISTRY" record "$ROOT" "$PID_MODE" "$child"; then
  echo 'could not prove ownership of native Linux standard-exit process' >&2
  exit 1
fi
sleep 0.5
if ! kill -0 "$child" 2>/dev/null; then wait "$child" || true; echo 'sing-box exited during Linux standard-exit startup' >&2; exit 1; fi
wait "$child"
status=$?
if (( status != 0 )); then echo "sing-box standard exit exited with code $status" >&2; exit "$status"; fi
