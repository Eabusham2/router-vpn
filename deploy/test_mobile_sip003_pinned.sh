#!/usr/bin/env bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VENDOR=${1:?prepared exact sing-box source required}
[[ $(git -C "$VENDOR" rev-parse HEAD) == 1ac1a339cb1223e9c70eae14c44411c75033c02d ]]
# The same mobile buffers/socket protection used in shipping Libbox remain on.
python3 "$ROOT/deploy/prepare-mobile-buffers.py" "$VENDOR"
FIXTURE_DIR=$(mktemp -d)
trap 'rm -rf "$FIXTURE_DIR"' EXIT
PLUGIN="$FIXTURE_DIR/v2ray-plugin-source"
git init "$PLUGIN"
git -C "$PLUGIN" remote add origin https://github.com/shadowsocks/v2ray-plugin.git
git -C "$PLUGIN" fetch --depth=1 origin e9af1cdd2549d528deb20a4ab8d61c5fbe51f306
git -C "$PLUGIN" checkout --detach FETCH_HEAD
[[ $(git -C "$PLUGIN" rev-parse HEAD) == e9af1cdd2549d528deb20a4ab8d61c5fbe51f306 ]]
(cd "$PLUGIN" && go mod download && go mod verify && go build -mod=readonly -ldflags=-checklinkname=0 -o "$FIXTURE_DIR/v2ray-plugin-fixture" .)
(cd "$VENDOR" && go build -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor -o "$FIXTURE_DIR/sing-fixture" ./cmd/sing-box)
export ROUTER_VPN_SING_TEST_BINARY="$FIXTURE_DIR/sing-fixture"
export ROUTER_VPN_V2RAY_TEST_BINARY="$FIXTURE_DIR/v2ray-plugin-fixture"
(cd "$VENDOR" && go test -race -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor -count=1 -timeout=120s -v ./protocol/routervpnsip003test)
(cd "$VENDOR" && go test -race -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor,with_low_memory -count=1 -timeout=120s ./protocol/routervpnsip003test)
