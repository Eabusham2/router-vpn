#!/usr/bin/env bash
set -u
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PID_REGISTRY="$SCRIPT_DIR/runtime-pids.py"
CLEANUP_RC=0

for i in wg0 awg0 wg awg router-vpn; do
  sudo wg-quick down "$i" >/dev/null 2>&1 || true
  sudo awg-quick down "$i" >/dev/null 2>&1 || true
  sudo ip link del "$i" >/dev/null 2>&1 || true
done

verified_pids() {
  local out
  if ! out=$(python3 "$PID_REGISTRY" verified "$ROOT" 2>/dev/null); then
    echo 'Router VPN verified PID registry could not be read safely; retaining ownership metadata.' >&2
    return 1
  fi
  printf '%s\n' "$out"
}

wait_for_owned_exit() {
  local remaining delay=${1:-1}
  sleep "$delay"
  if ! remaining=$(verified_pids); then
    return 2
  fi
  [[ -z "$remaining" ]] && return 0
  return 1
}

# Never turn raw/reused PID text or a command-line substring into kill input.
# Every long-lived Router VPN child (including DNS helpers) is registered with
# process-start + command identity by its launcher. The registry is retained
# until freshly verified owned children are actually gone, so failed cleanup can
# be retried without losing the only safe process-ownership evidence.
if [[ -f "$PID_REGISTRY" && ! -L "$PID_REGISTRY" ]]; then
  if PIDS=$(verified_pids); then
    while IFS= read -r pid; do
      [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 1 )) || continue
      sudo kill -TERM "$pid" >/dev/null 2>&1 || true
    done <<< "$PIDS"

    wait_for_owned_exit 1
    WAIT_RC=$?
    if (( WAIT_RC == 1 )); then
      if PIDS=$(verified_pids); then
        while IFS= read -r pid; do
          [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 1 )) || continue
          sudo kill -KILL "$pid" >/dev/null 2>&1 || true
        done <<< "$PIDS"
        wait_for_owned_exit 0.5
        WAIT_RC=$?
      else
        WAIT_RC=2
      fi
    fi

    if (( WAIT_RC == 0 )); then
      if ! python3 "$PID_REGISTRY" clear "$ROOT" >/dev/null 2>&1; then
        echo 'Router VPN children exited but PID ownership registry could not be cleared safely.' >&2
        CLEANUP_RC=1
      fi
    else
      echo 'Router VPN verified child cleanup is incomplete; retaining PID ownership registry for recovery.' >&2
      CLEANUP_RC=1
    fi
  else
    CLEANUP_RC=1
  fi
else
  echo 'Router VPN verified PID registry helper is unavailable; refusing broad process-name cleanup.' >&2
  CLEANUP_RC=1
fi

# Manual/final disconnect releases on-connect protection only after all owned
# tunnel processes/interfaces are asked to stop. During AUTO/SMART/fallback
# recovery the caller sets HOMEVPN_KILLSWITCH_HOLD=1 so the fail-closed firewall
# remains installed between candidates. 'always' policy intentionally remains
# active either way.
if [[ ${HOMEVPN_KILLSWITCH_HOLD:-0} != 1 ]]; then
  python3 "$SCRIPT_DIR/kill-switch.py" release >/dev/null 2>&1 || true
else
  echo 'Router VPN transition cleanup complete; strict kill switch remains held.' >&2
fi
exit "$CLEANUP_RC"
