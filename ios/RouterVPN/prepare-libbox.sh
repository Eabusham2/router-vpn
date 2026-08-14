#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERSION=1.13.12
COMMIT=1086ab2563320e0da0c23b3a491d8dfa0939dff4
GO_TOOLCHAIN=go1.26.3
GOMOBILE_VERSION=0.1.12
DEPS="$ROOT/.deps"
VENDOR="$DEPS/sing-box-apple"
FRAMEWORK="$DEPS/Libbox.xcframework"
STAMP="$DEPS/Libbox.xcframework.pin"
LICENSE_OUT="$DEPS/libbox-LICENSE.txt"
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
  test -f "$STAMP"
  test "$(tr -d '\r\n' < "$STAMP")" = "$EXPECTED_STAMP"
}

if [[ -d "$FRAMEWORK" && -f "$STAMP" && $(tr -d '\r\n' < "$STAMP") == "$EXPECTED_STAMP" ]]; then
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
grep -Fxq 'go 1.24.7' "$VENDOR/go.mod" || { echo 'pinned sing-box Go module version changed unexpectedly' >&2; exit 1; }
grep -Fq 'case "apple":' "$VENDOR/cmd/internal/build_libbox/main.go"
grep -Fq 'bindTarget = "ios,iossimulator,tvos,tvossimulator,macos"' "$VENDOR/cmd/internal/build_libbox/main.go"
grep -Fq 'with_wireguard' "$VENDOR/cmd/internal/build_libbox/main.go"
# The exact 1.13.12 pin must not be silently described as OpenVPN-capable.
if grep -Fq 'with_openvpn' "$VENDOR/cmd/internal/build_libbox/main.go"; then
  echo 'Pinned Apple libbox unexpectedly enabled OpenVPN; review custom-exit capability contract before continuing' >&2
  exit 1
fi

git -C "$VENDOR" tag -f "v$VERSION" "$COMMIT" >/dev/null
(
  cd "$VENDOR"
  go run ./cmd/internal/build_libbox -target apple -platform ios,iossimulator
)
SOURCE="$VENDOR/Libbox.xcframework"
[[ -d "$SOURCE" ]] || { echo 'Pinned Apple libbox build did not produce Libbox.xcframework' >&2; exit 1; }
mv "$SOURCE" "$FRAMEWORK"
install -m 0644 "$VENDOR/LICENSE" "$LICENSE_OUT"
printf '%s\n' "$EXPECTED_STAMP" > "$STAMP"
verify_framework
echo "Built pinned Apple Libbox: sing-box $VERSION ($COMMIT), iOS + iOS Simulator"
