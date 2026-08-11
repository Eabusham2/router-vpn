#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Run as root: sudo bash server/scripts/cleanup-router-vpn-docker.sh'; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'Docker is required.' >&2; exit 1; }

# This cleanup is intentionally scoped to Router VPN. It does NOT run docker
# system prune, volume prune, builder prune, or touch unrelated containers.
KEEP_CONTAINERS=' router-vpn-init router-vpn-finalize router-vpn-agent router-vpn-wireguard router-vpn-awg2 router-vpn-rosenpass router-vpn-transports router-vpn-xray router-vpn-naive router-vpn-ss-v2ray router-vpn-aux router-vpn-bundle-web router-vpn-socks5 '

before=$(docker system df 2>/dev/null || true)
echo '=== Router VPN Docker cleanup ==='

echo 'Removing stopped Router VPN containers that are not part of the current stack...'
while IFS= read -r id; do
  [[ -n "$id" ]] || continue
  name=$(docker inspect -f '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##')
  running=$(docker inspect -f '{{.State.Running}}' "$id" 2>/dev/null || echo true)
  [[ "$running" == false ]] || continue
  case "$KEEP_CONTAINERS" in
    *" $name "*) ;;
    *) docker rm "$id" >/dev/null && echo "removed container: $name" ;;
  esac
done < <(docker ps -aq --filter 'name=router-vpn-' 2>/dev/null)

# Collect image content IDs referenced by ANY container, including stopped ones.
declare -A USED=()
while IFS= read -r cid; do
  [[ -n "$cid" ]] || continue
  iid=$(docker inspect -f '{{.Image}}' "$cid" 2>/dev/null || true)
  [[ -n "$iid" ]] && USED["$iid"]=1
done < <(docker ps -aq 2>/dev/null)

echo 'Removing old Router VPN images that are not referenced by any container...'
declare -A SEEN=()
while read -r repo iid; do
  [[ -n "${repo:-}" && -n "${iid:-}" ]] || continue
  case "$repo" in
    ghcr.io/eabusham2/router-vpn-*|router-vpn-*) ;;
    *) continue ;;
  esac
  [[ -z "${SEEN[$iid]:-}" ]] || continue
  SEEN["$iid"]=1
  [[ -z "${USED[$iid]:-}" ]] || continue
  if docker image rm "$iid" >/dev/null 2>&1; then
    echo "removed unused Router VPN image: $repo ($iid)"
  fi
done < <(docker image ls --no-trunc --format '{{.Repository}} {{.ID}}' 2>/dev/null)

echo
echo '=== Docker usage before ==='
printf '%s\n' "$before"
echo '=== Docker usage after ==='
docker system df || true

echo 'Done. Named volumes, unrelated images/containers, and Docker build cache were not touched.'
