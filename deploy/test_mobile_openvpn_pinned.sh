#!/usr/bin/env bash
# Run the real mobile compiler and core, including a loopback TLS data-path test.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VENDOR=${1:?Pass the exact checked-out mobile sing-box source directory}
PIN=1ac1a339cb1223e9c70eae14c44411c75033c02d
[[ $(git -C "$VENDOR" rev-parse HEAD) == "$PIN" ]] || { echo 'Mobile OpenVPN core pin mismatch' >&2; exit 1; }
# Xcode's iPhone SDK must not contaminate this host-only executable test.
if [[ $(uname -s) == Darwin ]]; then
  export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
  unset IPHONEOS_DEPLOYMENT_TARGET TVOS_DEPLOYMENT_TARGET WATCHOS_DEPLOYMENT_TARGET XROS_DEPLOYMENT_TARGET
fi
export GOTOOLCHAIN=go1.26.3
unset GOOS GOARCH CC CXX CGO_CFLAGS CGO_LDFLAGS
TEST="$VENDOR/experimental/libbox/routervpn_openvpn_native_test.go"
trap 'rm -f "$TEST"' EXIT
install -m 0644 "$ROOT/mobile/routervpn_openvpn_native_test.go.tmpl" "$TEST"
install -m 0644 "$ROOT/mobile/routervpn_openvpn.go" "$VENDOR/experimental/libbox/routervpn_openvpn.go"
cd "$VENDOR"
go test -count=1 -timeout=120s -tags with_openvpn,with_wireguard,with_quic,with_gvisor ./experimental/libbox -run '^TestRouterOpenVPNNative' -v
