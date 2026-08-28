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
PRIVATE_WRITE=/src/server/scripts/atomic-private-write.py
PRIVATE_BATCH=/src/server/scripts/atomic-private-batch.py
PRIVATE_DIR=/src/server/scripts/private-directory.py
VERIFIED_READ=/src/server/scripts/verified-regular-read.py

for dir in \
  "$BASE" "$BASE/config" "$BASE/config/xray" "$BASE/config/transports" \
  "$BASE/client-bundle" "$BASE/client-bundle/generated" "$BASE/client-bundle/router" "$BASE/downloads"; do
  python3 "$PRIVATE_DIR" "$dir"
done
for required in "$BASE/config/router-agent.json" "$BASE/config/socks5.json" "$BASE/client-bundle/routers.json"; do
  python3 "$VERIFIED_READ" --private "$required" >/dev/null || { echo "Existing installation missing/unsafe private state $required" >&2; exit 1; }
done

bash /src/server/finalize/sync-client-runtime.sh "$BASE"
# current-entrypoint may have auto-detected a fresh public IP, and an explicit
# ENDPOINT from Portainer must also win. detect-settings is only fallback state.
REQUESTED_ENDPOINT=${ENDPOINT:-}
eval "$(python3 /src/server/finalize/detect-settings.py "$BASE")"
if [[ -n "$REQUESTED_ENDPOINT" ]]; then
  ENDPOINT=$REQUESTED_ENDPOINT
fi
CONFIG_ENDPOINT=${ENDPOINT:-router.invalid}

# Keep only the raw WG/AWG peer endpoints in sync. Do not use the legacy broad
# endpoint rewriter here: JSON DNS, localhost SOCKS, and internal chain servers
# must remain untouched.
if [[ $CONFIG_ENDPOINT != router.invalid ]]; then
  python3 /src/server/finalize/sync-endpoint.py "$BASE" "$CONFIG_ENDPOINT"
fi

# Keep the tunnel-only SOCKS endpoint simple: IP + port, no credentials. Stage
# both metadata files first, then adopt them as one private transaction.
META_TMP=$(mktemp -d "$BASE/config/.upgrade-meta.XXXXXX")
trap 'rm -rf "${META_TMP:-}"' EXIT
python3 - "$BASE" "$ADGUARD4" "$META_TMP" <<'PY'
from pathlib import Path
import json,os,stat,sys
base=Path(sys.argv[1]); dns=sys.argv[2]; out=Path(sys.argv[3])

def read_private_json(path: Path):
    info=path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink private JSON input: {path}")
    if info.st_size <= 0 or info.st_size > (32 << 20):
        raise RuntimeError(f"private JSON input is empty/oversized: {path}")
    return json.loads(path.read_text(encoding='utf-8'))

def stage(name: str, value):
    path=out/name
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    os.chmod(path,0o600)

socks_path=base/'config'/'socks5.json'
socks=read_private_json(socks_path)
for inbound in socks.get('inbounds',[]):
    if inbound.get('type')=='socks': inbound.pop('users',None)
for server in socks.get('dns',{}).get('servers',[]):
    if isinstance(server,dict) and server.get('tag')=='home-dns': server['server']=dns
stage('socks5.json',socks)

routers_path=base/'client-bundle'/'routers.json'
routers=read_private_json(routers_path)
for profile in routers.get('profiles',[]):
    profile['socks_host']=profile.get('socks_host') or dns
    profile['socks_port']=int(profile.get('socks_port') or 1080)
    profile['socks_username']=''
    profile['socks_password']=''
    profile.setdefault('base_tunnel','wg')
    profile.setdefault('dns_mode','home')
stage('routers.json',routers)
PY
python3 "$PRIVATE_BATCH" \
  "$BASE/config/socks5.json=$META_TMP/socks5.json" \
  "$BASE/client-bundle/routers.json=$META_TMP/routers.json"
rm -rf "$META_TMP"
META_TMP=
trap - EXIT

if ! bash /src/server/scripts/ensure-rosenpass.sh "$BASE" "$CONFIG_ENDPOINT" "$ROSENPASS_PORT"; then
  echo 'Warning: Rosenpass profiles are unavailable; PQ WG/AWG and MAX modes will stay disabled rather than silently downgrade.' >&2
fi

bash /src/server/finalize/ensure-profile-engines.sh \
  "$BASE" "$CONFIG_ENDPOINT" "$ADGUARD4" "$WG_PORT" "$AWG_PORT" \
  "$REALITY_PORT" "$HY2_PORT" "$SS_PORT" "$XRAY_PQ_PORT" "$XHTTP_PORT" \
  "$SS_V2RAY_PORT" "$NAIVE_PORT" "$REALITY_TARGET"

# Keep auxiliary compatibility secrets stable across normal upgrades. These are
# outside the 20-mode AUTO ladder and never replace the modern transports.
export OVERTLS_INTERNAL_PORT
if [[ -s "$BASE/config/tls/settings.env" ]]; then
  python3 /src/server/scripts/generate-aux-proxies.py \
    "$BASE" "$CONFIG_ENDPOINT" "$OVERTLS_PORT" "$SSR_PORT"
else
  echo 'Warning: TLS settings unavailable; OverTLS/SSR compatibility methods remain disabled.' >&2
  rm -rf "$BASE/config/aux" "$BASE/client-bundle/generated/overtls" "$BASE/client-bundle/generated/shadowsocksr"
fi

if ! python3 /src/server/scripts/benchmark-dns.py "$BASE" >/dev/null; then
  echo 'Warning: DNS benchmark failed; preserving the prior/fallback DNS selection.' >&2
fi

# The Setup Center/QRs are a required user-facing feature. Existing installations
# must receive them too, so fail rather than silently ship an incomplete UI.
python3 /src/server/scripts/generate-setup-assets.py "$BASE" "$CONFIG_ENDPOINT" "$ADGUARD4"
[[ -s "$BASE/client-bundle/setup-assets.json" ]]
[[ -s "$BASE/client-bundle/router-vpn-device-setup.html" ]]

TOKEN=$(python3 - "$BASE/config/router-agent.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1])).get('token',''))
PY
)
TLS_INFO=$(python3 - "$BASE/config/tls/generated.json" <<'PY'
import json,sys
try: print(json.load(open(sys.argv[1])).get('tls_name','unavailable'))
except Exception: print('unavailable')
PY
)
DNS_FASTEST=$(python3 - "$BASE/config/dns-fastest.json" <<'PY'
import json,sys
try:
    w=json.load(open(sys.argv[1])).get('winner',{})
    name=w.get('name','Fastest public DNS'); host=w.get('address','1.1.1.1'); lat=w.get('latency_ms')
    print(f"{name}: {host}" + (f" ({float(lat):.2f} ms DNS query)" if lat is not None else ""))
except Exception: print('public DNS fallback: 1.1.1.1')
PY
)

python3 "$PRIVATE_WRITE" "$BASE/client-bundle/CREDENTIALS.txt" <<TXT
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
Default DNS policy: Home AdGuard (changeable to fastest public, common/custom DNS, DoT, DoH, DoH3, or rescue in client)
SOCKS5 after VPN connects: $ADGUARD4:1080
SOCKS5 authentication: none
Private Setup Center (home LAN only): http://$ADGUARD4:8786/
Router API token: $TOKEN
TXT

python3 /src/server/scripts/create-bundle-json.py \
  "$BASE" "$ENDPOINT" "$TOKEN" "http://$ADGUARD4:8787" "$ADGUARD4" "" ""

# Refresh the bundled Merlin helper too, so existing users get any new listener
# rules without reconstructing them manually.
mkdir -p "$BASE/client-bundle/router"
cp /src/router/asus-merlin-router-vpn-forwards.sh "$BASE/client-bundle/router/"
chmod 0755 "$BASE/client-bundle/router/asus-merlin-router-vpn-forwards.sh"

# Publish only lightweight static Setup Center files. Large packages, including
# the private full bundle, are built by the download broker only when requested.
bash /src/server/scripts/publish-downloads.sh "$BASE"
# Remove a legacy root-level bundle left by older releases; client-bundle remains
# the canonical source used for ephemeral on-demand generation.
rm -f "$BASE/router-vpn-client-bundle.zip"

export WG_PORT AWG_PORT ROSENPASS_PORT REALITY_PORT HY2_PORT SS_PORT XRAY_PQ_PORT XHTTP_PORT SS_V2RAY_PORT NAIVE_PORT OVERTLS_PORT SSR_PORT
bash /src/server/scripts/apply-runtime.sh "$WAN_INTERFACE" "$LAN_CIDR"
printf 'finalized\n' | python3 "$PRIVATE_WRITE" "$BASE/.finalized"
echo 'Credential-preserving upgrade finalization complete with Setup Center, ephemeral downloads, and auxiliary compatibility profiles.'
