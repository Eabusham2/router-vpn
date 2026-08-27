#!/usr/bin/env bash
set -u
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PID_REGISTRY="$SCRIPT_DIR/runtime-pids.py"

for i in wg0 awg0 wg awg router-vpn; do
  sudo wg-quick down "$i" >/dev/null 2>&1 || true
  sudo awg-quick down "$i" >/dev/null 2>&1 || true
  sudo ip link del "$i" >/dev/null 2>&1 || true
done

# Never turn raw/reused PID text or a command-line substring into kill input.
# Every long-lived Router VPN child (including DNS helpers) is registered with
# process-start + command identity by its launcher. A malformed/redirected
# registry is skipped rather than guessed.
if [[ -f "$PID_REGISTRY" && ! -L "$PID_REGISTRY" ]]; then
  while IFS= read -r pid; do
    [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 1 )) || continue
    sudo kill -TERM "$pid" >/dev/null 2>&1 || true
  done < <(python3 "$PID_REGISTRY" verified "$ROOT" 2>/dev/null || true)
  python3 "$PID_REGISTRY" clear "$ROOT" >/dev/null 2>&1 || true
else
  echo 'Router VPN verified PID registry is unavailable; refusing broad process-name cleanup.' >&2
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
exit 0
