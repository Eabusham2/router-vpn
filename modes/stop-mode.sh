#!/usr/bin/env bash
set -u
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
RUN="$ROOT/run"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for i in wg0 awg0 wg awg router-vpn; do
  sudo wg-quick down "$i" >/dev/null 2>&1 || true
  sudo awg-quick down "$i" >/dev/null 2>&1 || true
  sudo ip link del "$i" >/dev/null 2>&1 || true
done
if [[ -d "$RUN" ]]; then
  while IFS= read -r pid; do [[ -n "$pid" ]] && sudo kill "$pid" >/dev/null 2>&1 || true; done < <(cat "$RUN"/*.pids 2>/dev/null || true)
  rm -f "$RUN"/*.pids
fi
sudo pkill -f 'xray run.*router-vpn-client/generated' >/dev/null 2>&1 || true
sudo pkill -f 'sing-box run.*router-vpn-client/generated' >/dev/null 2>&1 || true
sudo pkill -f 'sing-box run.*router-vpn-client/run' >/dev/null 2>&1 || true
sudo pkill -f 'rosenpass exchange-config.*router-vpn-client/generated' >/dev/null 2>&1 || true
sudo pkill -f 'router-vpn-dns.*127.0.0.1:53' >/dev/null 2>&1 || true
# Manual/final disconnect releases on-connect protection only after all tunnel
# processes/interfaces are down. During AUTO/SMART/fallback recovery the caller
# sets HOMEVPN_KILLSWITCH_HOLD=1 so the fail-closed firewall remains installed
# between candidates. 'always' policy intentionally remains active either way.
if [[ ${HOMEVPN_KILLSWITCH_HOLD:-0} != 1 ]]; then
  python3 "$SCRIPT_DIR/kill-switch.py" release >/dev/null 2>&1 || true
else
  echo 'Router VPN transition cleanup complete; strict kill switch remains held.' >&2
fi
exit 0
