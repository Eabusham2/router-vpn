#!/usr/bin/env bash
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Platform-generated profile trees are disposable and contain private imported
# node credentials. Remove them through the same ownership/identity-safe helper
# used by native launchers before/after central mode cleanup.
python3 "$SCRIPT_DIR/cleanup-private-runtime.py" --root "${HOMEVPN_ROOT:-/opt/router-vpn-client}" --all >/dev/null 2>&1 || true

bash "$SCRIPT_DIR/stop-mode.sh"
STOP_RC=$?
if (( STOP_RC != 0 )); then
  echo 'Router VPN platform teardown is incomplete; strict platform kill switch remains held for recovery.' >&2
  exit "$STOP_RC"
fi

if [[ ${HOMEVPN_KILLSWITCH_HOLD:-0} != 1 ]]; then
  if ! python3 "$SCRIPT_DIR/kill-switch-platform.py" release >/dev/null 2>&1; then
    echo 'Router VPN runtime stopped but platform kill-switch release failed; protection remains fail-closed.' >&2
    exit 1
  fi
else
  echo 'Router VPN platform transition cleanup complete; strict kill switch remains held.' >&2
fi
exit 0
