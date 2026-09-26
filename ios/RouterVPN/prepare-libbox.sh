#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERSION=1.14.1
COMMIT=1ac1a339cb1223e9c70eae14c44411c75033c02d
XRAY_COMMIT=50231eaff98ccc31b5cbd247a721c16e97fe5ec1
XRAY_VERSION=v1.260327.1-0.20260711155151-50231eaff98c
GO_TOOLCHAIN=go1.26.3
GOMOBILE_VERSION=0.1.12
DEPS="$ROOT/.deps"
VENDOR="$DEPS/sing-box-apple"
XRAY_VENDOR="$DEPS/xray-core-apple"
XRAY_LICENSE_OUT="$DEPS/xray-core-LICENSE.txt"
FRAMEWORK="$DEPS/Libbox.xcframework"
STAMP="$DEPS/Libbox.xcframework.pin"
LICENSE_OUT="$DEPS/libbox-LICENSE.txt"
BRIDGE_SOURCE="$ROOT/../../mobile/routervpn_openvpn.go"
BRIDGE_STAMP="$DEPS/Libbox.routervpn-openvpn.sha256"
BRIDGE_SHA=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$BRIDGE_SOURCE")
MULTIHOP_SHA=$(python3 "$ROOT/../../deploy/prepare-mobile-multihop.py" --digest)
BRIDGE_SHA=$(python3 -c 'import hashlib,sys;print(hashlib.sha256((sys.argv[1]+"+"+sys.argv[2]).encode()).hexdigest())' "$BRIDGE_SHA" "$MULTIHOP_SHA")
XRAY_BRIDGE_SHA=$(python3 "$ROOT/../../deploy/prepare-apple-xray.py" --digest)
BRIDGE_SHA=$(python3 -c 'import hashlib,sys;print(hashlib.sha256((sys.argv[1]+"+"+sys.argv[2]).encode()).hexdigest())' "$BRIDGE_SHA" "$XRAY_BRIDGE_SHA")
EXPECTED_STAMP="$VERSION+$COMMIT+$GO_TOOLCHAIN+$GOMOBILE_VERSION+ios,iossimulator"

verify_framework() {
  test -d "$FRAMEWORK"
  test -f "$FRAMEWORK/Info.plist"
  /usr/libexec/PlistBuddy -c 'Print :AvailableLibraries' "$FRAMEWORK/Info.plist" >/dev/null
  python3 - "$FRAMEWORK/Info.plist" <<'PY'
import plistlib,sys
p=plistlib.load(open(sys.argv[1],'rb'))
libs=p.get('AvailableLibraries',[])
plats={(x.get('SupportedPlatform'),x.get('SupportedPlatformVariant','')) for x in libs}
assert ('ios','') in plats, plats
assert ('ios','simulator') in plats, plats
for x in libs:
    if x.get('SupportedPlatform')!='ios': continue
    ident=x['LibraryIdentifier']
    path=x.get('LibraryPath') or 'Libbox.framework'
    # XCFramework may expose framework path or a static library. Require a
    # real payload under every iOS slice; module/header details are checked by
    # Xcode when Router VPN links it.
    import os
    assert os.path.exists(os.path.join(sys.argv[1].rsplit('/',1)[0],ident,path)), (ident,path)
print('Libbox XCFramework iOS + simulator slices OK')
PY
  test -s "$LICENSE_OUT"
  test -s "$XRAY_LICENSE_OUT"
  test -f "$BRIDGE_STAMP"
  test "$(tr -d '\r\n' < "$BRIDGE_STAMP")" = "$BRIDGE_SHA"
  # Inspect generated headers, not a marker copied into our own Swift source.
  python3 - "$FRAMEWORK" <<'PYHEAD'
from pathlib import Path
import sys
headers=list(Path(sys.argv[1]).rglob('Libbox.objc.h'))
assert headers, 'Libbox generated headers missing'
for header in headers:
    assert 'LibboxRouterOpenVPNEndpoint' in header.read_text(), str(header)
    assert 'LibboxNewRouterMultihop' in header.read_text(), str(header)
    assert 'LibboxRouterCompileXrayProfile' in header.read_text(), str(header)
    assert 'LibboxRouterCompileSIP003Profile' in header.read_text(), str(header)
    assert 'LibboxRouterXrayRevision' in header.read_text(), str(header)
    assert 'LibboxRouterResolveXrayProfile' in header.read_text(), str(header)
PYHEAD
  test -f "$STAMP"
  test "$(tr -d '\r\n' < "$STAMP")" = "$EXPECTED_STAMP"
}

if [[ -d "$FRAMEWORK" && -f "$STAMP" && $(tr -d '\r\n' < "$STAMP") == "$EXPECTED_STAMP" && -f "$BRIDGE_STAMP" && $(tr -d '\r\n' < "$BRIDGE_STAMP") == "$BRIDGE_SHA" ]]; then
  verify_framework
  echo "Pinned Apple Libbox already prepared: sing-box $VERSION ($COMMIT)"
  exit 0
fi

[[ $(uname -s) == Darwin ]] || { echo 'Apple Libbox must be built on macOS with Xcode installed' >&2; exit 1; }
command -v git >/dev/null || { echo 'git is required' >&2; exit 1; }
command -v go >/dev/null || { echo 'Go is required' >&2; exit 1; }
command -v xcodebuild >/dev/null || { echo 'Xcode is required' >&2; exit 1; }

export GOTOOLCHAIN="$GO_TOOLCHAIN+auto"
GO_BIN_DIR="$(go env GOPATH)/bin"
mkdir -p "$GO_BIN_DIR" "$DEPS"
echo "Installing pinned SagerNet gomobile $GOMOBILE_VERSION under $GO_TOOLCHAIN..."
GOBIN="$GO_BIN_DIR" go install "github.com/sagernet/gomobile/cmd/gomobile@v$GOMOBILE_VERSION"
GOBIN="$GO_BIN_DIR" go install "github.com/sagernet/gomobile/cmd/gobind@v$GOMOBILE_VERSION"
export PATH="$GO_BIN_DIR:$PATH"
command -v gomobile >/dev/null
command -v gobind >/dev/null

rm -rf "$VENDOR" "$FRAMEWORK" "$STAMP" "$LICENSE_OUT"
for attempt in 1 2 3; do
  echo "Fetching pinned sing-box $VERSION at $COMMIT (attempt $attempt/3)..."
  rm -rf "$VENDOR"
  if git clone --filter=blob:none --no-checkout https://github.com/SagerNet/sing-box.git "$VENDOR" && \
     git -C "$VENDOR" fetch --depth 1 origin "$COMMIT" && \
     git -C "$VENDOR" checkout --detach FETCH_HEAD; then
    break
  fi
  [[ $attempt -lt 3 ]] || { echo 'Unable to fetch pinned sing-box source' >&2; exit 1; }
  sleep $((attempt*3))
done
ACTUAL=$(git -C "$VENDOR" rev-parse HEAD)
[[ "$ACTUAL" == "$COMMIT" ]] || { echo "sing-box pin mismatch: $ACTUAL" >&2; exit 1; }
grep -Fxq 'go 1.25.5' "$VENDOR/go.mod" || { echo 'pinned sing-box Go module version changed unexpectedly' >&2; exit 1; }
grep -Fq 'case "apple":' "$VENDOR/cmd/internal/build_libbox/main.go"
grep -Fq 'bindTarget = "ios,iossimulator,tvos,tvossimulator,macos"' "$VENDOR/cmd/internal/build_libbox/main.go"
grep -Fq 'with_wireguard' "$VENDOR/cmd/internal/build_libbox/main.go"
# Both native targets must contain the real OpenVPN endpoint, not a UI stub.
grep -Fq 'with_openvpn' "$VENDOR/cmd/internal/build_libbox/main.go"
install -m 0644 "$BRIDGE_SOURCE" "$VENDOR/experimental/libbox/routervpn_openvpn.go"
python3 "$ROOT/../../deploy/prepare-mobile-multihop.py" "$VENDOR"
for attempt in 1 2 3; do
  rm -rf "$XRAY_VENDOR"
  if git clone --filter=blob:none --no-checkout https://github.com/XTLS/Xray-core.git "$XRAY_VENDOR" && \
     git -C "$XRAY_VENDOR" fetch --depth 1 origin "$XRAY_COMMIT" && \
     git -C "$XRAY_VENDOR" checkout --detach FETCH_HEAD; then break; fi
  [[ $attempt -lt 3 ]] || { echo 'Unable to fetch pinned Apple Xray core' >&2; exit 1; }
  sleep $((attempt*3))
done
[[ $(git -C "$XRAY_VENDOR" rev-parse HEAD) == "$XRAY_COMMIT" ]]
python3 "$ROOT/../../deploy/prepare-apple-xray.py" "$VENDOR" "$XRAY_VENDOR"


git -C "$VENDOR" tag -f "v$VERSION" "$COMMIT" >/dev/null
(
  cd "$VENDOR"
  go mod edit -go=1.26.3
  go mod edit -require="github.com/xtls/xray-core@$XRAY_VERSION"
  go mod edit -replace="github.com/xtls/xray-core=$XRAY_VENDOR"
  go mod tidy
  [[ $(go list -m -f '{{.Version}}' github.com/xtls/xray-core) == "$XRAY_VERSION" ]]
  bash "$ROOT/../../deploy/test_apple_xray_pinned.sh" "$VENDOR" "$XRAY_VENDOR"
  bash "$ROOT/../../deploy/test_mobile_whitening_pinned.sh" "$VENDOR"
  bash "$ROOT/../../deploy/test_mobile_sip003_pinned.sh" "$VENDOR"
  go test ./experimental/libbox/routervpn/...
  go test -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor ./experimental/libbox -run TestRouterMultihop -count=1
  GOFLAGS="-ldflags=-checklinkname=0" go run ./cmd/internal/build_libbox -target apple -platform ios,iossimulator
)
SOURCE="$VENDOR/Libbox.xcframework"
[[ -d "$SOURCE" ]] || { echo 'Pinned Apple libbox build did not produce Libbox.xcframework' >&2; exit 1; }
mv "$SOURCE" "$FRAMEWORK"
install -m 0644 "$VENDOR/LICENSE" "$LICENSE_OUT"
install -m 0644 "$XRAY_VENDOR/LICENSE" "$XRAY_LICENSE_OUT"
printf '%s\n' "$EXPECTED_STAMP" > "$STAMP"
printf '%s\n' "$BRIDGE_SHA" > "$BRIDGE_STAMP"
verify_framework
echo "Built pinned Apple Libbox: sing-box $VERSION ($COMMIT), iOS + iOS Simulator"
