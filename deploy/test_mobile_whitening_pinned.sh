#!/usr/bin/env bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VENDOR=${1:?prepared pinned sing-box checkout}
[[ $(git -C "$VENDOR" rev-parse HEAD) == 1ac1a339cb1223e9c70eae14c44411c75033c02d ]]
python3 "$ROOT/deploy/prepare-mobile-buffers.py" "$VENDOR"
FIXTURE_DIR=$(mktemp -d)
trap 'rm -rf "$FIXTURE_DIR"' EXIT
(cd "$ROOT" && go build -o "$FIXTURE_DIR/start-layer-relay" ./cmd/start-layer-relay)
(cd "$VENDOR" && go build -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor -o "$FIXTURE_DIR/sing-fixture" ./cmd/sing-box)
export ROUTER_VPN_SING_TEST_BINARY="$FIXTURE_DIR/sing-fixture"
export ROUTER_VPN_WHITENING_TEST_BINARY="$FIXTURE_DIR/start-layer-relay"
(cd "$VENDOR" && go test -race -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor -count=1 -timeout=90s -v ./protocol/routervpnwhitening ./experimental/libbox/routervpn/startwhitening)
# Apple binds Libbox with with_low_memory. Exercise the actual constrained
# build too; a default-only test would hide its former 8 KiB UDP truncation.
(cd "$VENDOR" && go test -race -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor,with_low_memory -count=1 -timeout=90s ./protocol/routervpnwhitening)
