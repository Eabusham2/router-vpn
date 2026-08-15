#!/usr/bin/env bash
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# Preserve the established tunnel/process cleanup exactly. Its Linux-only
# kill-switch release is intentionally tolerant on Darwin; the platform release
# below is authoritative there and preserves an 'always' policy fail-closed.
bash "$SCRIPT_DIR/stop-mode.sh"
STOP_RC=$?
# AUTO/SMART/logical fallback transitions must not release an on-connect policy
# between candidates. Manual/final disconnect leaves HOLD unset and therefore
# performs the authoritative platform release as before.
if [[ ${HOMEVPN_KILLSWITCH_HOLD:-0} != 1 ]]; then
  python3 "$SCRIPT_DIR/kill-switch-platform.py" release >/dev/null 2>&1 || true
fi
exit "$STOP_RC"
