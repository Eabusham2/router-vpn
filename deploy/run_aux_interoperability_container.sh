#!/usr/bin/env bash
# Run only an owned, disconnected test container and compare its servers with
# the exact finalized production images built by this workflow.
set -euo pipefail
aux=${1:?built production auxiliary image is required}
fixture=${2:?built auxiliary interoperability image is required}
naive=${3:-}
mode=${4:-payload}
setup_caps=(--cap-add NET_ADMIN)
case "$mode" in
  payload|import) ;;
  dns) setup_caps+=(--cap-add NET_BIND_SERVICE) ;;
  *) echo 'Unknown auxiliary fixture mode' >&2; exit 2 ;;
esac

binary_hash() {
  local result value
  result=$(docker run --rm --network none --platform linux/arm64 --cap-drop ALL \
    --security-opt no-new-privileges --read-only --entrypoint sha256sum "$1" "$2")
  value=${result%% *}
  [[ $value =~ ^[a-f0-9]{64}$ ]] || { echo 'Invalid production binary checksum' >&2; return 1; }
  printf '%s' "$value"
}

ssr_hash=$(binary_hash "$aux" /usr/local/bin/ssr-server)
overtls_hash=$(binary_hash "$aux" /usr/local/bin/overtls-bin)
caddy_hash=''
if [[ -n $naive ]]; then
  caddy_hash=$(binary_hash "$naive" /usr/bin/caddy)
fi

owned=''
cleanup() {
  if [[ -n $owned ]]; then
    docker rm --force "$owned" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# NET_ADMIN is used only to assign TEST-NET-1 to this isolated loopback. The
# DNS setup additionally binds owned resolver sockets on port 53. The entry
# point drops every effective/permitted/inheritable capability, and the driver
# verifies that state before launching any protocol process.
owned=$(docker create --init --network none --platform linux/arm64 \
  --cap-drop ALL "${setup_caps[@]}" --security-opt no-new-privileges --pids-limit 256 \
  --memory 768m --cpus 2 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --env ROUTERVPN_REQUIRE_PRODUCTION_HASHES=1 \
  --env "ROUTERVPN_SSR_SERVER_SHA256=$ssr_hash" \
  --env "ROUTERVPN_OVERTLS_SERVER_SHA256=$overtls_hash" \
  --env "ROUTERVPN_CADDY_SHA256=$caddy_hash" "$fixture")
timeout --signal=TERM --kill-after=10 240 docker start --attach "$owned"
test "$(docker inspect --format '{{.State.ExitCode}}' "$owned")" = 0
docker rm "$owned" >/dev/null
owned=''
