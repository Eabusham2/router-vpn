#!/usr/bin/env bash
set -euo pipefail

BASE=${BASE:-/opt/router-vpn}
WAN_INTERFACE=${WAN_INTERFACE:-eth0}
LAN_CIDR=${LAN_CIDR:-192.168.50.0/24}
ADGUARD4=${ADGUARD4:-192.168.50.133}
ENDPOINT=${ENDPOINT:-}
CONFIG_ENDPOINT=${ENDPOINT:-router.invalid}
WG_PORT=${WG_PORT:-51820}
AWG_PORT=${AWG_PORT:-585}
REALITY_PORT=${REALITY_PORT:-443}
HY2_PORT=${HY2_PORT:-8443}
SS_PORT=${SS_PORT:-8388}
XRAY_PQ_PORT=${XRAY_PQ_PORT:-10443}
XHTTP_PORT=${XHTTP_PORT:-11443}
REALITY_TARGET=${REALITY_TARGET:-www.microsoft.com:443}

for required in \
  "$BASE/config/router-agent.json" \
  "$BASE/config/socks5.json" \
  "$BASE/client-bundle/routers.json" \
  "$BASE/client-bundle/modes.json"; do
  [[ -s "$required" ]] || { echo "Base initialization missing $required" >&2; exit 1; }
done

# The base initializer temporarily writes credentials because older init code expects
# a users array. Remove it before SOCKS5 starts so apps only need tunnel IP + port.
python3 - "$BASE" "$ADGUARD4" <<'PY'
from pathlib import Path
import json,sys
base=Path(sys.argv[1]); dns=sys.argv[2]

socks_path=base/'config'/'socks5.json'
socks=json.load(open(socks_path))
for inbound in socks.get('inbounds',[]):
    if inbound.get('type')=='socks':
        inbound.pop('users',None)
for server in socks.get('dns',{}).get('servers',[]):
    if isinstance(server,dict) and server.get('tag')=='home-dns':
        server['server']=dns
socks_path.write_text(json.dumps(socks,indent=2)+'\n')

routers_path=base/'client-bundle'/'routers.json'
routers=json.load(open(routers_path))
for profile in routers.get('profiles',[]):
    profile['socks_host']=profile.get('socks_host') or dns
    profile['socks_port']=int(profile.get('socks_port') or 1080)
    profile['socks_username']=''
    profile['socks_password']=''
routers_path.write_text(json.dumps(routers,indent=2)+'\n')
PY

# Generate every compatible combined profile. Failure of an experimental upstream
# engine disables that profile instead of breaking the basic WireGuard services.
if ! python3 /src/server/scripts/generate-stack-profiles.py "$BASE"; then
  echo 'Warning: dual-transport profiles were not generated.' >&2
fi
if ! bash /src/server/scripts/generate-advanced-profiles.sh \
  "$BASE" "$CONFIG_ENDPOINT" "$ADGUARD4" "$WG_PORT" "$AWG_PORT" \
  "$SS_PORT" "$HY2_PORT" "$XHTTP_PORT" "$REALITY_TARGET"; then
  echo 'Warning: advanced MAX profiles failed validation and remain unavailable.' >&2
  for mode in max-tls-wg max-tls-awg max-quic-wg max-quic-awg; do
    rm -f "$BASE/client-bundle/generated/$mode/chain.env"
  done
fi

TOKEN=$(python3 - "$BASE/config/router-agent.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1])).get('token',''))
PY
)

cat >"$BASE/client-bundle/CREDENTIALS.txt" <<TXT
Endpoint: ${ENDPOINT:-CHOOSE_IN_APP}
WireGuard UDP: $WG_PORT
AmneziaWG UDP: $AWG_PORT
REALITY/Vision TCP: $REALITY_PORT
Hysteria2/QUIC UDP: $HY2_PORT
Shadowsocks TCP/UDP: $SS_PORT
PQ REALITY TCP: $XRAY_PQ_PORT
XHTTP/FinalMask TCP: $XHTTP_PORT
SOCKS5 after VPN connects: $ADGUARD4:1080
SOCKS5 authentication: none
Router API token: $TOKEN
TXT

python3 /src/server/scripts/create-bundle-json.py \
  "$BASE" "$ENDPOINT" "$TOKEN" "http://$ADGUARD4:8787" "$ADGUARD4" "" ""

rm -f "$BASE/downloads/router-vpn-client-bundle.zip" "$BASE/router-vpn-client-bundle.zip"
(
  cd "$BASE/client-bundle"
  zip -qr "$BASE/downloads/router-vpn-client-bundle.zip" .
)
cp "$BASE/downloads/router-vpn-client-bundle.zip" "$BASE/router-vpn-client-bundle.zip"

export WG_PORT AWG_PORT REALITY_PORT HY2_PORT SS_PORT XRAY_PQ_PORT XHTTP_PORT
bash /src/server/scripts/apply-runtime.sh "$WAN_INTERFACE" "$LAN_CIDR"
touch "$BASE/.finalized"

echo 'Finalization complete: advanced profiles generated where supported; SOCKS5 uses IP and port only.'
