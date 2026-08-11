#!/usr/bin/env bash
set -euo pipefail

BASE=${BASE:-/opt/router-vpn}
WAN_INTERFACE=${WAN_INTERFACE:-eth0}
LAN_CIDR=${LAN_CIDR:-192.168.50.0/24}
ADGUARD4=${ADGUARD4:-192.168.50.133}
ENDPOINT=${ENDPOINT:-}
WG_PORT=${WG_PORT:-51820}
AWG_PORT=${AWG_PORT:-585}
ROSENPASS_PORT=${ROSENPASS_PORT:-51822}
REALITY_PORT=${REALITY_PORT:-443}
HY2_PORT=${HY2_PORT:-8443}
SS_PORT=${SS_PORT:-8388}
XRAY_PQ_PORT=${XRAY_PQ_PORT:-10443}
XHTTP_PORT=${XHTTP_PORT:-11443}
SS_V2RAY_PORT=${SS_V2RAY_PORT:-12443}
NAIVE_PORT=${NAIVE_PORT:-13443}
OVERTLS_PORT=${OVERTLS_PORT:-14443}
OVERTLS_INTERNAL_PORT=${OVERTLS_INTERNAL_PORT:-14444}
SSR_PORT=${SSR_PORT:-15443}
REALITY_TARGET=${REALITY_TARGET:-www.microsoft.com:443}

for required in \
  "$BASE/config/router-agent.json" \
  "$BASE/config/socks5.json" \
  "$BASE/client-bundle/routers.json" \
  "$BASE/client-bundle/modes.json"; do
  [[ -s "$required" ]] || { echo "Base initialization missing $required" >&2; exit 1; }
done

bash /src/server/finalize/sync-client-runtime.sh "$BASE"
eval "$(python3 /src/server/finalize/detect-settings.py "$BASE")"
CONFIG_ENDPOINT=${ENDPOINT:-router.invalid}

python3 - "$BASE" "$ADGUARD4" <<'PY'
from pathlib import Path
import json,sys
base=Path(sys.argv[1]); dns=sys.argv[2]
socks_path=base/'config'/'socks5.json'
socks=json.load(open(socks_path))
for inbound in socks.get('inbounds',[]):
    if inbound.get('type')=='socks': inbound.pop('users',None)
for server in socks.get('dns',{}).get('servers',[]):
    if isinstance(server,dict) and server.get('tag')=='home-dns': server['server']=dns
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

if ! bash /src/server/scripts/ensure-rosenpass.sh "$BASE" "$CONFIG_ENDPOINT" "$ROSENPASS_PORT"; then
  echo 'Warning: Rosenpass PQ profiles were not generated; WG-PQ/AWG-PQ remain unavailable.' >&2
  rm -rf "$BASE/config/rosenpass"
  rm -f \
    "$BASE/client-bundle/generated/wg-pq/rosenpass.toml" \
    "$BASE/client-bundle/generated/wg-pq/rosenpass.env" \
    "$BASE/client-bundle/generated/wg-pq/rosenpass-client-public" \
    "$BASE/client-bundle/generated/wg-pq/rosenpass-client-secret" \
    "$BASE/client-bundle/generated/wg-pq/rosenpass-server-public" \
    "$BASE/client-bundle/generated/awg2-pq/rosenpass.toml" \
    "$BASE/client-bundle/generated/awg2-pq/rosenpass.env" \
    "$BASE/client-bundle/generated/awg2-pq/rosenpass-client-public" \
    "$BASE/client-bundle/generated/awg2-pq/rosenpass-client-secret" \
    "$BASE/client-bundle/generated/awg2-pq/rosenpass-server-public"
fi

bash /src/server/scripts/generate-transports.sh \
  "$BASE" "$CONFIG_ENDPOINT" "$ADGUARD4" "$REALITY_PORT" "$HY2_PORT" "$SS_PORT" "$REALITY_TARGET"
bash /src/server/scripts/generate-xray-pq.sh \
  "$BASE" "$CONFIG_ENDPOINT" "$ADGUARD4" "$XRAY_PQ_PORT" "$REALITY_TARGET" "$REALITY_PORT"

if ! python3 /src/server/scripts/generate-stack-profiles.py "$BASE"; then
  echo 'Warning: dual-transport profiles were not generated.' >&2
  rm -rf "$BASE/client-bundle/generated/split" "$BASE/client-bundle/generated/max"
fi
if ! bash /src/server/scripts/generate-advanced-profiles.sh \
  "$BASE" "$CONFIG_ENDPOINT" "$ADGUARD4" "$WG_PORT" "$AWG_PORT" \
  "$SS_PORT" "$HY2_PORT" "$XHTTP_PORT" "$REALITY_TARGET"; then
  echo 'Warning: advanced MAX and XHTTP profiles failed validation and remain unavailable.' >&2
  rm -rf \
    "$BASE/client-bundle/generated/max-tls-wg" \
    "$BASE/client-bundle/generated/max-tls-awg" \
    "$BASE/client-bundle/generated/max-quic-wg" \
    "$BASE/client-bundle/generated/max-quic-awg" \
    "$BASE/client-bundle/generated/reality-xhttp"
  rm -f "$BASE/config/xray/advanced-secrets.json"
else
  if ! python3 /src/server/scripts/enhance-max-pq.py "$BASE"; then
    echo 'Warning: MAX branches could not be enhanced with live Rosenpass PQ; disabling MAX instead of silently downgrading.' >&2
    rm -rf \
      "$BASE/client-bundle/generated/max-tls-wg" \
      "$BASE/client-bundle/generated/max-tls-awg" \
      "$BASE/client-bundle/generated/max-quic-wg" \
      "$BASE/client-bundle/generated/max-quic-awg"
  fi
  if ! python3 /src/server/scripts/wrap-xhttp-tun.py "$BASE" "$ADGUARD4"; then
    echo 'Warning: XHTTP outer profile is valid but its full-tunnel wrapper failed validation; disabling XHTTP mode only.' >&2
    rm -rf "$BASE/client-bundle/generated/reality-xhttp"
  fi
fi

export SS_V2RAY_PORT NAIVE_PORT
if ! bash /src/server/scripts/generate-tls-alternates.sh "$BASE" "$CONFIG_ENDPOINT" "$ADGUARD4"; then
  echo 'Warning: automatic TLS alternate profiles were not generated.' >&2
  rm -rf \
    "$BASE/config/tls" \
    "$BASE/client-bundle/generated/ss-v2ray" \
    "$BASE/client-bundle/generated/naive-h2" \
    "$BASE/client-bundle/generated/naive-h3"
fi

# Auxiliary compatibility methods are kept outside the 20-mode AUTO catalog.
# OverTLS uses Caddy TLS on the public port and plaintext only on loopback.
export OVERTLS_INTERNAL_PORT
if [[ -s "$BASE/config/tls/settings.env" ]]; then
  python3 /src/server/scripts/generate-aux-proxies.py \
    "$BASE" "$CONFIG_ENDPOINT" "$OVERTLS_PORT" "$SSR_PORT"
else
  echo 'TLS settings unavailable; disabling OverTLS/SSR compatibility bundle assets.' >&2
  rm -rf "$BASE/config/aux" "$BASE/client-bundle/generated/overtls" "$BASE/client-bundle/generated/shadowsocksr"
fi

if ! python3 /src/server/scripts/benchmark-dns.py "$BASE" >/dev/null; then
  echo 'Warning: public DNS benchmark failed; using bundle fallback until next upgrade/redeploy.' >&2
  rm -f "$BASE/config/dns-fastest.json"
fi

# This is a required user-facing product feature: fail finalization if private
# setup QR/URL generation breaks instead of silently shipping a half-working UI.
python3 /src/server/scripts/generate-setup-assets.py "$BASE" "$CONFIG_ENDPOINT" "$ADGUARD4"
[[ -s "$BASE/client-bundle/setup-assets.json" ]]
[[ -s "$BASE/client-bundle/router-vpn-device-setup.html" ]]

TOKEN=$(python3 - "$BASE/config/router-agent.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1])).get('token',''))
PY
)
DNS_FASTEST=$(python3 - "$BASE/config/dns-fastest.json" <<'PY'
import json,sys
try:
    x=json.load(open(sys.argv[1])).get('winner',{})
    name=x.get('name','public DNS fallback'); addr=x.get('address','1.1.1.1'); lat=x.get('latency_ms')
    print(f"{name}: {addr}" + (f" ({float(lat):.2f} ms DNS query)" if lat is not None else ""))
except Exception:
    print('public DNS fallback: 1.1.1.1')
PY
)
TLS_INFO=$(python3 - "$BASE/config/tls/generated.json" <<'PY'
import json,sys
try:
    x=json.load(open(sys.argv[1])); print(x.get('tls_name','unavailable'))
except Exception:
    print('unavailable')
PY
)

cat >"$BASE/client-bundle/CREDENTIALS.txt" <<TXT
Endpoint: ${ENDPOINT:-CHOOSE_IN_APP}
WireGuard UDP: $WG_PORT
AmneziaWG UDP: $AWG_PORT
Rosenpass PQ UDP: $ROSENPASS_PORT
REALITY/Vision TCP: $REALITY_PORT
Hysteria2/QUIC UDP: $HY2_PORT
Shadowsocks TCP/UDP: $SS_PORT
PQ REALITY TCP: $XRAY_PQ_PORT
XHTTP/FinalMask TCP: $XHTTP_PORT
SS + V2Ray TLS TCP: $SS_V2RAY_PORT
Naive HTTPS TCP/UDP: $NAIVE_PORT
SOCKS5 + TLS / OverTLS TCP: $OVERTLS_PORT
ShadowsocksR legacy TCP/UDP: $SSR_PORT
Automatic TLS hostname: $TLS_INFO
Certificate challenge external TCP: 80 -> AI Board TCP 18080
Fastest public DNS at home: $DNS_FASTEST
Default DNS policy: fastest (changeable to Home AdGuard, custom, DoT, DoH, DoH3, or rescue in client)
SOCKS5 after VPN connects: $ADGUARD4:1080
SOCKS5 authentication: none
Private Device Setup WebGUI (home LAN only): http://$ADGUARD4:8786/router-vpn-device-setup.html
Router API token: $TOKEN
TXT

python3 /src/server/scripts/create-bundle-json.py \
  "$BASE" "$ENDPOINT" "$TOKEN" "http://$ADGUARD4:8787" "$ADGUARD4" "" ""

mkdir -p "$BASE/client-bundle/router"
cp /src/router/asus-merlin-router-vpn-forwards.sh "$BASE/client-bundle/router/"
chmod 0755 "$BASE/client-bundle/router/asus-merlin-router-vpn-forwards.sh"

# Keep only the lightweight Setup Center/static metadata on disk. All ZIPs,
# including the full private bundle, are created by the broker per request.
bash /src/server/scripts/publish-downloads.sh "$BASE"
rm -f "$BASE/router-vpn-client-bundle.zip"

export WG_PORT AWG_PORT ROSENPASS_PORT REALITY_PORT HY2_PORT SS_PORT XRAY_PQ_PORT XHTTP_PORT SS_V2RAY_PORT NAIVE_PORT OVERTLS_PORT SSR_PORT
bash /src/server/scripts/apply-runtime.sh "$WAN_INTERFACE" "$LAN_CIDR"
touch "$BASE/.finalized"

echo 'Finalization complete: current transport/PQ/TLS profiles and ephemeral setup assets generated; auxiliary OverTLS/SSR remain separate from AUTO.'
