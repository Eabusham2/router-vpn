#!/usr/bin/env bash
# Real nested encryption evidence supplements host graph and device validation.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VENDOR=${1:?prepared pinned mobile core}
[[ $(git -C "$VENDOR" rev-parse HEAD) == 1ac1a339cb1223e9c70eae14c44411c75033c02d ]]
[[ -x "${ROUTER_VPN_XRAY_TEST_BINARY:?verified Xray fixture required}" ]]
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
(cd "$ROOT" && go build -o "$WORK/whitening-fixture" ./cmd/start-layer-relay)
export ROUTER_VPN_WHITENING_TEST_BINARY="$WORK/whitening-fixture"
# The physical-mapping constructors must never enter an ordinary application.
(cd "$VENDOR" && go list -f '{{join .GoFiles "\n"}}' ./protocol/shadowsocks ./protocol/routervpnwhitening) >"$WORK/shipping-files"
if grep -Fxq 'routervpn_start_layer_fixture.go' "$WORK/shipping-files"; then
  echo 'test-only socket mapper entered the shipping build' >&2
  exit 1
fi
for tags in with_quic,with_wireguard,with_gvisor,routervpn_start_layer_integration with_quic,with_wireguard,with_gvisor,with_low_memory,routervpn_start_layer_integration; do
  (cd "$VENDOR" && go test -race -ldflags=-checklinkname=0 -tags "$tags" -count=1 -timeout=180s -v ./protocol/routervpnxray -run '^TestNativeXrayStartLayer')
done
