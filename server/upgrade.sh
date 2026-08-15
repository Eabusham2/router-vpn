#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo: sudo ./server/upgrade.sh'; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'Docker is required.'; exit 1; }
docker compose version >/dev/null 2>&1 || { echo 'Docker Compose v2 is required.'; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo 'Python 3 is required to verify the exact-SHA production compose.'; exit 1; }

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE=${ROUTER_VPN_PRODUCTION_COMPOSE:-}
[[ -n "$COMPOSE" ]] || { echo 'ROUTER_VPN_PRODUCTION_COMPOSE must point to a generated exact-SHA production compose; the tracked baseline is not a release.' >&2; exit 2; }
[[ -f "$COMPOSE" ]] || { echo "Production release compose not found: $COMPOSE" >&2; exit 2; }
RELEASE_SHA=$(python3 "$ROOT_DIR/server/scripts/verify-production-compose.py" "$COMPOSE") || exit $?
ENV_FILE=/opt/router-vpn/.env
[[ -s "$ENV_FILE" ]] || { echo 'No existing Router VPN install found at /opt/router-vpn/.env'; exit 1; }

echo "Refreshing Router VPN release $RELEASE_SHA from exact published images..."
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" up -d --force-recreate init finalize-current
for container in router-vpn-init router-vpn-finalize; do
  docker wait "$container" >/dev/null 2>&1 || true
  code=$(docker inspect -f '{{.State.ExitCode}}' "$container" 2>/dev/null || echo 1)
  if [[ $code != 0 ]]; then
    echo "$container failed with exit code $code" >&2
    docker logs "$container" >&2 || true
    exit "$code"
  fi
done

echo 'Refreshing long-running services...'
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" up -d --remove-orphans

test -s /opt/router-vpn/downloads/index.html || { echo 'Upgrade completed but Setup Center index is missing.' >&2; exit 1; }
test -s /opt/router-vpn/downloads/router-vpn-bundle.json || { echo 'Upgrade completed but the private router bundle is missing.' >&2; exit 1; }

if command -v curl >/dev/null 2>&1; then
  for _ in $(seq 1 30); do
    curl -fsS http://127.0.0.1:8786/healthz >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fsS http://127.0.0.1:8786/healthz >/dev/null || { echo 'Setup Center broker health check failed.' >&2; exit 1; }
fi

bash "$ROOT_DIR/server/scripts/cleanup-router-vpn-docker.sh"
echo
echo "Upgrade to Router VPN $RELEASE_SHA complete."
echo 'Server services remain exact-image-only and were launched from the verified generated release compose.'
echo 'Current-version profile credentials were preserved by the finalizer migration path.'
echo 'Large client packages remain on-demand/ephemeral: GitHub artifact first, requested-package local build second.'
