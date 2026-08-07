#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo: sudo ./server/upgrade.sh'; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'Docker is required.'; exit 1; }
docker compose version >/dev/null 2>&1 || { echo 'Docker Compose v2 is required.'; exit 1; }

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE="$ROOT_DIR/server/portainer-compose.yaml"
ENV_FILE=/opt/router-vpn/.env
[[ -s "$ENV_FILE" ]] || { echo 'No existing Router VPN install found at /opt/router-vpn/.env'; exit 1; }

echo 'Building current router images...'
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" build

echo 'Migrating profiles without rotating already-current credentials...'
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" run --rm --no-deps \
  --entrypoint /bin/bash finalize /src/server/finalize/upgrade-safe.sh

echo 'Restarting long-lived Router VPN services...'
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" up -d --no-deps \
  router-agent wireguard awg2 rosenpass transports xray-pq naive ss-v2ray bundle-web socks5

BUNDLE=/opt/router-vpn/downloads/router-vpn-client-bundle.zip
[[ -s "$BUNDLE" ]] || { echo 'Upgrade completed but client bundle is missing.' >&2; exit 1; }

echo
echo 'Upgrade complete.'
echo 'Your current profile-engine credentials are preserved after the one-time migration.'
echo 'If this upgrade introduced the new profile-engine version, re-download/import the private client bundle once.'
echo 'Future upgrades with the same profile-engine version keep those credentials stable.'
