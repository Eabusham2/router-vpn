#!/usr/bin/env bash
# Validate both actual composed graphs with the EXACT shipped Libbox core.
# This invokes `check`, never `run`: no tunnel, node traffic, or live secrets.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VENDOR="$ROOT/ios/RouterVPN/.deps/sing-box-apple"
PIN=1086ab2563320e0da0c23b3a491d8dfa0939dff4
[[ $(uname -s) == Darwin ]] || { echo 'Native Libbox parser gate requires macOS'; exit 1; }
[[ $(git -C "$VENDOR" rev-parse HEAD) == "$PIN" ]] || { echo 'Libbox core pin mismatch'; exit 1; }
# Xcode invokes this from an iphoneos build phase. The graph fixtures and
# parser are HOST executables, so they must not inherit the iPhone sysroot.
# This script runs in its own process; the enclosing IPA build keeps its SDK.
export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
[[ -d "$SDKROOT" ]] || { echo 'macOS host SDK is unavailable'; exit 1; }
unset IPHONEOS_DEPLOYMENT_TARGET TVOS_DEPLOYMENT_TARGET WATCHOS_DEPLOYMENT_TARGET XROS_DEPLOYMENT_TARGET
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
python3 "$ROOT/deploy/test_ios_multihop_graph.py" --fixture-dir "$WORK/fixtures"
(
  cd "$VENDOR"
  export GOTOOLCHAIN=go1.26.3
  export GOOS=darwin
  export GOARCH=$(go env GOHOSTARCH)
  export CGO_ENABLED=0
  go build -trimpath -tags with_wireguard,with_quic,with_gvisor -o "$WORK/sing-box" ./cmd/sing-box
)
for graph in "$WORK"/fixtures/*.json; do
  "$WORK/sing-box" check -c "$graph"
done
echo 'Pinned Libbox accepts both owned multihop graphs (configuration proof only, not device traffic proof)'
