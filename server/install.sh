#!/usr/bin/env bash
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo 'Run with sudo: sudo ./server/install.sh'; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'Docker is required.'; exit 1; }
docker compose version >/dev/null 2>&1 || { echo 'Docker Compose v2 is required.'; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo 'Python 3 is required to verify the exact-SHA production compose.'; exit 1; }

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PRIVATE_WRITE="$ROOT_DIR/server/scripts/atomic-private-write.py"
[[ -f "$PRIVATE_WRITE" && ! -L "$PRIVATE_WRITE" ]] || { echo 'Private state publisher is missing or unsafe.' >&2; exit 1; }
COMPOSE=${ROUTER_VPN_PRODUCTION_COMPOSE:-}
[[ -n "$COMPOSE" ]] || { echo 'ROUTER_VPN_PRODUCTION_COMPOSE must point to a generated exact-SHA production compose; the tracked baseline is not a release.' >&2; exit 2; }
[[ -f "$COMPOSE" ]] || { echo "Production release compose not found: $COMPOSE" >&2; exit 2; }
RELEASE_SHA=$(python3 "$ROOT_DIR/server/scripts/verify-production-compose.py" "$COMPOSE") || exit $?
INSTALL=/opt/router-vpn
ENV_FILE="$INSTALL/.env"
DEFAULT_WAN=$(ip -4 route show default 2>/dev/null | awk 'NR==1{print $5}')
DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
DEFAULT_IP=${DEFAULT_IP:-192.168.50.133}

detect_public_ipv4() {
  python3 - <<'PY'
import ipaddress, urllib.request
sources=[
 ('https://1.1.1.1/cdn-cgi/trace','trace'),
 ('https://checkip.amazonaws.com','plain'),
 ('https://icanhazip.com','plain'),
 ('https://api.ipify.org','plain'),
]
for url,kind in sources:
    try:
        req=urllib.request.Request(url,headers={'User-Agent':'router-vpn/1'})
        body=urllib.request.urlopen(req,timeout=4).read().decode().strip()
        value=next((x[3:].strip() for x in body.splitlines() if x.startswith('ip=')),'') if kind=='trace' else (body.splitlines()[0].strip() if body else '')
        ip=ipaddress.ip_address(value)
        if ip.version==4 and ip.is_global:
            print(value); raise SystemExit(0)
    except Exception:
        pass
raise SystemExit(1)
PY
}
DEFAULT_PUBLIC=$(detect_public_ipv4 || true)

prompt(){ local variable=$1 text=$2 default=$3 value; read -r -p "$text [$default]: " value; printf -v "$variable" '%s' "${value:-$default}"; }
prompt WAN_INTERFACE 'AI Board network interface' "${DEFAULT_WAN:-eth0}"
prompt LAN_CIDR 'Home LAN IPv4 subnet' '192.168.50.0/24'
prompt LAN_CIDR6 'Home/local IPv6 subnet policy' 'fd00::/8'
prompt ADGUARD4 'AI Board / AdGuard IPv4 address' "$DEFAULT_IP"
prompt ENDPOINT 'Router public IP or hostname (blank is allowed)' "$DEFAULT_PUBLIC"
prompt WG_PORT 'Raw WireGuard UDP port' '51820'
prompt AWG_PORT 'AmneziaWG UDP port' '585'
prompt ROSENPASS_PORT 'Rosenpass PQ UDP port' '51822'
prompt REALITY_PORT 'REALITY/Vision TCP port' '443'
prompt HY2_PORT 'Hysteria2/QUIC UDP port' '8443'
prompt SS_PORT 'Shadowsocks TCP and UDP port' '8388'
prompt XRAY_PQ_PORT 'PQ REALITY TCP port' '10443'
prompt XHTTP_PORT 'XHTTP/FinalMask TCP port' '11443'
prompt SS_V2RAY_PORT 'Shadowsocks + V2Ray TLS TCP port' '12443'
prompt NAIVE_PORT 'Naive HTTPS TCP and UDP port' '13443'
prompt OVERTLS_PORT 'SOCKS5 + TLS / OverTLS public TCP port' '14443'
prompt OVERTLS_INTERNAL_PORT 'OverTLS loopback backend TCP port' '14444'
prompt SSR_PORT 'ShadowsocksR legacy TCP and UDP port' '15443'
prompt ROUTER_VPN_TLS_NAME 'Optional custom TLS hostname; blank auto-selects one when possible' ''
prompt REALITY_TARGET 'REALITY camouflage target host:port' 'www.microsoft.com:443'

umask 077
python3 "$PRIVATE_WRITE" "$ENV_FILE" <<ENV
WAN_INTERFACE=$WAN_INTERFACE
LAN_CIDR=$LAN_CIDR
LAN_CIDR6=$LAN_CIDR6
ADGUARD4=$ADGUARD4
ENDPOINT=$ENDPOINT
WG_PORT=$WG_PORT
AWG_PORT=$AWG_PORT
ROSENPASS_PORT=$ROSENPASS_PORT
REALITY_PORT=$REALITY_PORT
HY2_PORT=$HY2_PORT
SS_PORT=$SS_PORT
XRAY_PQ_PORT=$XRAY_PQ_PORT
XHTTP_PORT=$XHTTP_PORT
SS_V2RAY_PORT=$SS_V2RAY_PORT
NAIVE_PORT=$NAIVE_PORT
OVERTLS_PORT=$OVERTLS_PORT
OVERTLS_INTERNAL_PORT=$OVERTLS_INTERNAL_PORT
SSR_PORT=$SSR_PORT
ROUTER_VPN_TLS_NAME=$ROUTER_VPN_TLS_NAME
REALITY_TARGET=$REALITY_TARGET
ENV

echo "Starting Router VPN release $RELEASE_SHA from exact published images..."
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" up -d --remove-orphans

for container in router-vpn-init router-vpn-finalize; do
  docker wait "$container" >/dev/null 2>&1 || true
  code=$(docker inspect -f '{{.State.ExitCode}}' "$container" 2>/dev/null || echo 1)
  if [[ $code != 0 ]]; then
    echo "$container failed with exit code $code" >&2
    docker logs "$container" >&2 || true
    exit "$code"
  fi
done

test -s "$INSTALL/downloads/index.html" || { echo 'Setup Center index was not generated.' >&2; exit 1; }
test -s "$INSTALL/client-bundle/router-vpn-bundle.json" || { echo 'Canonical private router bundle was not generated.' >&2; exit 1; }
test ! -e "$INSTALL/downloads/router-vpn-bundle.json" || { echo 'Install leaked private router-vpn-bundle.json into public Setup Center downloads.' >&2; exit 1; }
test ! -e "$INSTALL/downloads/router-vpn-client-bundle.zip" || { echo 'Install leaked a cached private node-link ZIP into public Setup Center downloads.' >&2; exit 1; }

if command -v curl >/dev/null 2>&1; then
  for _ in $(seq 1 30); do
    curl -fsS http://127.0.0.1:8786/healthz >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fsS http://127.0.0.1:8786/healthz >/dev/null || { echo 'Setup Center broker health check failed.' >&2; exit 1; }
fi

echo
echo "Router VPN $RELEASE_SHA installed."
echo "Setup Center: http://$ADGUARD4:8786/"
echo 'Server services use the verified generated exact-SHA production compose.'
echo 'Client downloads use exact-SHA GitHub artifacts first and compile only the requested supported desktop/Portable package on this host if that artifact is unavailable.'
echo 'Private node material remains outside public downloads and is linked only through authenticated on-demand bundle/pairing flows.'
echo 'Use the Setup Center ASUS helper for persistent forwarding; do not expose 8786 to WAN.'
echo 'Public listeners include OverTLS 14443/TCP and legacy SSR 15443/TCP+UDP when enabled.'
echo 'Never WAN-forward 1080, 8786, 8787, 14444, 9443, SSH, Portainer, or AdGuard admin.'
