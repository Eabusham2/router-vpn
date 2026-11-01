#!/usr/bin/env bash
set -euo pipefail
fixture=${1:?built Setup Center native-import fixture is required}
mode=${2:-shadowsocks}
setup_options=()
case "$mode" in
  shadowsocks) ;;
  socks|hysteria) setup_options=(--cap-add NET_ADMIN --cap-add NET_BIND_SERVICE --dns 127.0.0.55) ;;
  *) echo 'Unknown Setup Center interoperability mode' >&2; exit 2 ;;
esac
transport=ghcr.io/sagernet/sing-box:v1.13.12
workspace=$(mktemp -d)
source_container=''
owned=''
cleanup() {
  if [[ -n $owned ]]; then docker rm --force "$owned" >/dev/null 2>&1 || true; fi
  if [[ -n $source_container ]]; then docker rm --force "$source_container" >/dev/null 2>&1 || true; fi
  rm -rf "$workspace"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
source_container=$(docker create --platform linux/arm64 "$transport")
docker cp "$source_container:/usr/local/bin/sing-box" "$workspace/sing-box"
test -f "$workspace/sing-box" && test ! -L "$workspace/sing-box"
production_hash=$(sha256sum "$workspace/sing-box")
production_hash=${production_hash%% *}
[[ $production_hash =~ ^[a-f0-9]{64}$ ]]
docker rm "$source_container" >/dev/null
source_container=''
owned=$(docker create --init --network none --platform linux/arm64 \
  --cap-drop ALL "${setup_options[@]}" --security-opt no-new-privileges --pids-limit 256 \
  --memory 768m --cpus 2 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=128m \
  --env ROUTERVPN_REQUIRE_PRODUCTION_HASHES=1 --env "ROUTERVPN_SINGBOX_SHA256=$production_hash" "$fixture")
timeout --signal=TERM --kill-after=10 240 docker start --attach "$owned"
test "$(docker inspect --format '{{.State.ExitCode}}' "$owned")" = 0
docker rm "$owned" >/dev/null
owned=''
