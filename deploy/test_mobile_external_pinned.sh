#!/usr/bin/env bash
# Execute the native Box/configuration boundary before building either package.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VENDOR=${1:?Pass the prepared exact native source}
PIN=1ac1a339cb1223e9c70eae14c44411c75033c02d
[[ $(git -C "$VENDOR" rev-parse HEAD) == "$PIN" ]] || { echo 'External native core pin mismatch' >&2; exit 1; }
if [[ $(uname -s) == Darwin ]]; then
  export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
  unset IPHONEOS_DEPLOYMENT_TARGET TVOS_DEPLOYMENT_TARGET WATCHOS_DEPLOYMENT_TARGET XROS_DEPLOYMENT_TARGET
fi
export GOTOOLCHAIN=go1.26.3
unset GOOS GOARCH CC CXX CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_LDFLAGS
python3 "$ROOT/deploy/prepare-mobile-external-policy.py" "$VENDOR"
cd "$VENDOR"
go test -race -count=1 -timeout=90s -ldflags=-checklinkname=0 -tags with_wireguard,with_quic,with_gvisor . -run '^TestRouterVPNExternal'
go test -race -count=1 -timeout=90s ./experimental/libbox/routervpn/mobilemultihop -run '^TestExternal'
go test -count=1 -ldflags=-checklinkname=0 -tags with_wireguard,with_quic,with_gvisor ./experimental/libbox -run '^TestRouterExternal'
