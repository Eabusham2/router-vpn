#!/usr/bin/env bash
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo 'Run with sudo: sudo ./server/install.sh'; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'Docker is required.'; exit 1; }
docker compose version >/dev/null 2>&1 || { echo 'Docker Compose v2 is required.'; exit 1; }

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE="$ROOT_DIR/server/portainer-compose.yaml"
INSTALL=/opt/router-vpn
ENV_FILE="$INSTALL/.env"
DEFAULT_WAN=$(ip -4 route show default 2>/dev/null | awk 'NR==1{print $5}')
DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
DEFAULT_IP=${DEFAULT_IP:-192.168.50.133}

detect_public_ipv4() {
  python3 - <<'PY'
import ipaddress
import urllib.request

sources = [
    ("https://1.1.1.1/cdn-cgi/trace", "trace"),
    ("https://checkip.amazonaws.com", "plain"),
    ("https://icanhazip.com", "plain"),
    ("https://api.ipify.org", "plain"),
]

for url, kind in sources:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "router-vpn/1"})
        body = urllib.request.urlopen(req, timeout=4).read().decode().strip()
        if kind == "trace":
            value = next((line[3:].strip() for line in body.splitlines() if line.startswith("ip=")), "")
        else:
            value = body.splitlines()[0].strip() if body else ""
        ip = ipaddress.ip_address(value)
        if ip.version == 4 and ip.is_global:
            print(value)
            raise SystemExit(0)
    except Exception:
        continue
raise SystemExit(1)
PY
}

DEFAULT_PUBLIC=$(detect_public_ipv4 || true)

prompt(){
  local variable=$1 text=$2 default=$3 value
  read -r -p "$text [$default]: " value
  printf -v "$variable" '%s' "${value:-$default}"
}

prompt WAN_INTERFACE 'AI Board network interface' "${DEFAULT_WAN:-eth0}"
prompt LAN_CIDR 'Home LAN IPv4 subnet' '192.168.50.0/24'
prompt ADGUARD4 'AI Board / AdGuard IPv4 address' "$DEFAULT_IP"
prompt ENDPOINT 'Router public IP or hostname' "$DEFAULT_PUBLIC"
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
prompt ROUTER_VPN_TLS_NAME 'Optional custom TLS hostname; blank auto-uses public IPv4 via sslip.io' ''
prompt REALITY_TARGET 'REALITY camouflage target host:port' 'www.microsoft.com:443'

mkdir -p "$INSTALL"
umask 077
cat >"$ENV_FILE" <<ENV
WAN_INTERFACE=$WAN_INTERFACE
LAN_CIDR=$LAN_CIDR
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
ROUTER_VPN_TLS_NAME=$ROUTER_VPN_TLS_NAME
REALITY_TARGET=$REALITY_TARGET
ENV
chmod 600 "$ENV_FILE"

echo 'Building and starting Router VPN...'
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" up -d --build

for container in router-vpn-init router-vpn-finalize; do
  if docker inspect "$container" >/dev/null 2>&1; then
    docker wait "$container" >/dev/null 2>&1 || true
    code=$(docker inspect -f '{{.State.ExitCode}}' "$container")
    if [[ $code != 0 ]]; then
      echo "$container failed with exit code $code" >&2
      docker logs "$container" >&2 || true
      exit "$code"
    fi
  fi
done

docker compose --env-file "$ENV_FILE" -f "$COMPOSE" up -d

test -s "$INSTALL/downloads/router-vpn-client-bundle.zip" || {
  echo 'Client bundle was not generated. Check router-vpn-finalize logs.' >&2
  exit 1
}

echo
echo 'Router VPN installed.'
echo
echo 'Create these ASUS WAN port forwards to the AI Board:'
printf '  TCP 80 -> %s:18080  (automatic TLS certificate/renewal)\n' "$ADGUARD4"
printf '  UDP %s -> %s:%s  (WireGuard)\n' "$WG_PORT" "$ADGUARD4" "$WG_PORT"
printf '  UDP %s -> %s:%s  (AmneziaWG)\n' "$AWG_PORT" "$ADGUARD4" "$AWG_PORT"
printf '  UDP %s -> %s:%s  (Rosenpass PQ)\n' "$ROSENPASS_PORT" "$ADGUARD4" "$ROSENPASS_PORT"
printf '  TCP %s -> %s:%s  (REALITY/Vision)\n' "$REALITY_PORT" "$ADGUARD4" "$REALITY_PORT"
printf '  UDP %s -> %s:%s  (Hysteria2/QUIC)\n' "$HY2_PORT" "$ADGUARD4" "$HY2_PORT"
printf '  TCP+UDP %s -> %s:%s  (Shadowsocks)\n' "$SS_PORT" "$ADGUARD4" "$SS_PORT"
printf '  TCP %s -> %s:%s  (PQ REALITY)\n' "$XRAY_PQ_PORT" "$ADGUARD4" "$XRAY_PQ_PORT"
printf '  TCP %s -> %s:%s  (XHTTP/FinalMask)\n' "$XHTTP_PORT" "$ADGUARD4" "$XHTTP_PORT"
printf '  TCP %s -> %s:%s  (Shadowsocks + V2Ray TLS)\n' "$SS_V2RAY_PORT" "$ADGUARD4" "$SS_V2RAY_PORT"
printf '  TCP+UDP %s -> %s:%s  (Naive HTTPS H2/H3)\n' "$NAIVE_PORT" "$ADGUARD4" "$NAIVE_PORT"
echo
echo 'Do NOT forward TCP 1080, 8786, 8787, Portainer, SSH, or AdGuard admin.'
echo
echo "Download the private client bundle on your home LAN:"
echo "  http://$ADGUARD4:8786/router-vpn-client-bundle.zip"
echo
echo 'SOCKS5 after a VPN tunnel connects:'
echo "  $ADGUARD4:1080"
echo '  authentication: none'
echo
echo 'Diagnostics:'
echo "  sudo $INSTALL/source/server/scripts/doctor.sh"
