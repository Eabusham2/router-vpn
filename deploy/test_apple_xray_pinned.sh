#!/usr/bin/env bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VENDOR=${1:?prepared pinned sing-box checkout}
XRAY=${2:?prepared pinned Xray checkout}
[[ $(git -C "$VENDOR" rev-parse HEAD) == 1ac1a339cb1223e9c70eae14c44411c75033c02d ]]
[[ $(git -C "$XRAY" rev-parse HEAD) == 50231eaff98ccc31b5cbd247a721c16e97fe5ec1 ]]
export GOTOOLCHAIN=go1.26.3+auto
FIXTURE_DIR=$(mktemp -d)
trap 'rm -rf "$FIXTURE_DIR"' EXIT
# A separate server process avoids replacing the native client's globally
# registered system dialer. This executable is a CI fixture, not an app helper.
(cd "$XRAY" && go build -ldflags=-checklinkname=0 -o "$FIXTURE_DIR/xray-fixture" ./main)
export ROUTER_VPN_XRAY_TEST_BINARY="$FIXTURE_DIR/xray-fixture"
(
 cd "$VENDOR"
 go test -race -count=1 ./experimental/libbox/routervpn/applexray
 go test -race -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor -count=1 -timeout=180s -v ./protocol/routervpnxray
 go test -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor ./experimental/libbox -run 'TestRouterXray' -count=1
)
