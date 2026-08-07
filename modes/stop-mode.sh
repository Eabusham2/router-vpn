#!/usr/bin/env bash
set -u
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
RUN="$ROOT/run"
for i in wg0 awg0 wg awg; do
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
exit 0
