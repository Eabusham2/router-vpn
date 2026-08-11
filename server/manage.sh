#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo: sudo bash server/manage.sh'; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'Docker is required.'; exit 1; }
docker compose version >/dev/null 2>&1 || { echo 'Docker Compose v2 is required.'; exit 1; }
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE="$ROOT_DIR/server/portainer-compose.yaml"
ENV_FILE=/opt/router-vpn/.env

if [[ ! -s "$ENV_FILE" || ! -s /opt/router-vpn/.initialized ]]; then
  echo 'First Router VPN installation...'
  bash "$ROOT_DIR/server/install.sh"
  # Current fresh installs already generated the current profiles. Adopt those exact
  # credentials as the stable version before the user downloads the first bundle.
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE" run --rm --no-deps \
    --entrypoint /bin/bash finalize /src/server/finalize/adopt-current-markers.sh
  echo
  echo 'Initial profile credentials locked for future upgrades.'
  exit 0
fi

echo 'Updating Router VPN without rotating current profile credentials...'
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" build
# Pull image-only services when upstream has a newer compatible image. Failure to
# contact a registry does not destroy the existing installation.
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" pull --ignore-buildable \
  transports xray-pq bundle-web socks5 >/dev/null 2>&1 || true

docker compose --env-file "$ENV_FILE" -f "$COMPOSE" run --rm --no-deps \
  --entrypoint /bin/bash finalize -lc \
  'bash /src/server/finalize/adopt-current-markers.sh; exec bash /src/server/finalize/upgrade-safe.sh'

docker compose --env-file "$ENV_FILE" -f "$COMPOSE" up -d --remove-orphans --no-deps \
  router-agent wireguard awg2 rosenpass transports xray-pq naive ss-v2ray bundle-web socks5

# Clean only stale Router VPN containers/images. Never prune named volumes,
# unrelated projects, or the global Docker build cache.
bash "$ROOT_DIR/server/scripts/cleanup-router-vpn-docker.sh"

echo
echo 'Router VPN is current.'
echo 'Existing current-version profile credentials were preserved.'
echo 'If a one-time profile-engine migration occurred, re-download/import the private client bundle once.'
