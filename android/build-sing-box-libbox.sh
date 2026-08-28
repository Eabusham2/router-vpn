#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERSION=1.13.12
COMMIT=1086ab2563320e0da0c23b3a491d8dfa0939dff4
LIBXRAY_COMMIT=294fb37343205b9b0cb7b7b1b423d3d4b60d9998
XRAY_CORE_VERSION=v1.260327.1-0.20260711155151-50231eaff98c
GO_TOOLCHAIN=go1.26.3
GO_MOD_VERSION=${GO_TOOLCHAIN#go}
[[ "$GO_MOD_VERSION" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || { echo "invalid Go module directive version: $GO_MOD_VERSION" >&2; exit 1; }
NDK_VERSION=28.0.13004108
GOMOBILE_VERSION=0.1.12
VENDOR="$ROOT/.vendor/sing-box"
XRAY_VENDOR="$ROOT/.vendor/libXray-combined"
LIBDIR="$ROOT/app/libs"
AAR="$LIBDIR/libbox.aar"
STAMP="$LIBDIR/libbox.commit"
LICENSE_OUT="$LIBDIR/libbox-LICENSE.txt"
XRAY_LICENSE_OUT="$LIBDIR/libxray-LICENSE.txt"
EXPECTED_STAMP="$COMMIT+$LIBXRAY_COMMIT+$XRAY_CORE_VERSION+$GO_TOOLCHAIN"

verify_aar() {
  test -s "$AAR"
  unzip -tq "$AAR" >/dev/null

  local tmp classes aar_list class_list api_list
  tmp=$(mktemp -d)
  classes="$tmp/classes.jar"
  aar_list="$tmp/aar.list"
  class_list="$tmp/classes.list"
  api_list="$tmp/libbox.javap"
  trap 'rm -rf "$tmp"' RETURN

  # Avoid producer | grep -q under pipefail: grep may exit as soon as it finds
  # the wanted member, SIGPIPE the producer, and turn a proven match into a
  # false-negative verification failure.
  unzip -Z1 "$AAR" >"$aar_list"
  grep -Fxq 'classes.jar' "$aar_list" || {
    echo 'combined libbox AAR is missing classes.jar' >&2
    return 1
  }
  for abi in armeabi-v7a arm64-v8a x86 x86_64; do
    grep -Fxq "jni/$abi/libbox.so" "$aar_list" || {
      echo "combined libbox AAR is missing jni/$abi/libbox.so" >&2
      return 1
    }
  done

  unzip -p "$AAR" classes.jar >"$classes"
  # The JDK jar tool may emit CRLF even on a Linux runner. Normalize its
  # complete listing before exact-line checks so a present class cannot become
  # a false negative because of a trailing carriage return.
  jar tf "$classes" >"$class_list.raw"
  tr -d '\r' <"$class_list.raw" >"$class_list"
  grep -Fxq 'io/nekohasekai/libbox/RouterXrayDialerController.class' "$class_list" || {
    echo 'combined libbox AAR is missing RouterXrayDialerController' >&2
    return 1
  }
  # Prove the generated Java binding is the expected socket-protection
  # interface rather than accepting a same-named class by filename alone.
  javap -classpath "$classes" io.nekohasekai.libbox.RouterXrayDialerController >"$tmp/router-xray-controller.javap"
  grep -Fq 'boolean protectFd(long);' "$tmp/router-xray-controller.javap" || {
    echo 'combined libbox AAR RouterXrayDialerController has the wrong API' >&2
    return 1
  }

  javap -classpath "$classes" io.nekohasekai.libbox.Libbox >"$api_list"
  for symbol in     routerXrayInvoke     routerXrayRegisterDialerController     routerXraySetDNS     routerXrayResetDNS     routerXrayBridgeRevision; do
    grep -Fq "$symbol" "$api_list" || {
      echo "combined libbox AAR is missing $symbol bridge" >&2
      return 1
    }
  done

  [[ $(grep -c '^go/Seq.class$' "$class_list") == 1 ]] || {
    echo 'combined libbox AAR must contain exactly one gomobile go.Seq runtime class' >&2
    return 1
  }
  if grep -Eq '^jni/[^/]+/libgojni\.so$' "$aar_list"; then
    echo 'combined SagerNet libbox AAR unexpectedly contains a second generic libgojni.so' >&2
    return 1
  fi
  rm -rf "$tmp"
  trap - RETURN
}

if [[ -s "$AAR" && -f "$STAMP" && $(tr -d '\r\n' <"$STAMP") == "$EXPECTED_STAMP" ]]; then
  verify_aar
  printf 'Pinned combined Android Go runtime already built: sing-box %s + libXray %s\n' "$VERSION" "$LIBXRAY_COMMIT"
  exit 0
fi

command -v git >/dev/null || { echo 'git is required to build the pinned Android Go runtime' >&2; exit 1; }
command -v go >/dev/null || { echo 'Go with toolchain download support is required' >&2; exit 1; }
command -v java >/dev/null || { echo 'Java 17 is required to validate the combined AAR' >&2; exit 1; }
command -v javap >/dev/null || { echo 'javap is required to validate the combined AAR API' >&2; exit 1; }
command -v jar >/dev/null || { echo 'JDK jar tool is required to inspect the combined AAR classes' >&2; exit 1; }

SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
SDKMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
if [[ -z "$SDK_ROOT" || ! -x "$SDKMANAGER" ]]; then
  echo 'Android sdkmanager was not found under ANDROID_HOME/ANDROID_SDK_ROOT' >&2
  exit 1
fi

yes | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true
"$SDKMANAGER" "ndk;$NDK_VERSION" >/dev/null
export ANDROID_NDK_HOME="$SDK_ROOT/ndk/$NDK_VERSION"
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
# The combined binary must satisfy libXray's pinned Go 1.26.3 module while
# preserving sing-box at its immutable source commit. Do not use ambient Go.
export GOTOOLCHAIN="$GO_TOOLCHAIN+auto"
# Keep public-module integrity verification enabled. Hosted runners occasionally
# see transient HTTP/2 failures from proxy/sumdb infrastructure; retry the exact
# same verified command instead of disabling GOSUMDB or accepting unverified
# module bytes.
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
export GOSUMDB="${GOSUMDB:-sum.golang.org}"
go_retry() {
  local attempt
  for attempt in 1 2 3; do
    if go "$@"; then
      return 0
    fi
    echo "Go command failed transiently: go $* (attempt $attempt/3)" >&2
    (( attempt < 3 )) && sleep $((attempt * 4))
  done
  echo "Go command failed after 3 verified attempts: go $*" >&2
  return 1
}

GO_BIN_DIR="$(go env GOPATH)/bin"
mkdir -p "$GO_BIN_DIR"
echo "Installing pinned SagerNet gomobile toolchain v$GOMOBILE_VERSION under $GO_TOOLCHAIN..."
GOBIN="$GO_BIN_DIR" go_retry install "github.com/sagernet/gomobile/cmd/gomobile@v$GOMOBILE_VERSION"
GOBIN="$GO_BIN_DIR" go_retry install "github.com/sagernet/gomobile/cmd/gobind@v$GOMOBILE_VERSION"
[[ -x "$GO_BIN_DIR/gomobile" && -x "$GO_BIN_DIR/gobind" ]] || { echo 'Pinned gomobile/gobind installation failed' >&2; exit 1; }
export PATH="$GO_BIN_DIR:$PATH"

rm -rf "$VENDOR" "$XRAY_VENDOR"
mkdir -p "$(dirname "$VENDOR")" "$LIBDIR"

clone_exact() {
  local url=$1 dest=$2 commit=$3 label=$4
  local ok=0
  for attempt in 1 2 3; do
    echo "Fetching $label at pinned commit $commit (attempt $attempt/3)..."
    rm -rf "$dest"
    if git clone --filter=blob:none --no-checkout "$url" "$dest" && \
       git -C "$dest" fetch --depth 1 origin "$commit" && \
       git -C "$dest" checkout --detach FETCH_HEAD; then
      ok=1
      break
    fi
    sleep $((attempt * 3))
  done
  [[ $ok == 1 ]] || { echo "Unable to fetch pinned $label source after 3 attempts" >&2; exit 1; }
  local actual
  actual=$(git -C "$dest" rev-parse HEAD)
  [[ "$actual" == "$commit" ]] || { echo "$label source commit mismatch: expected $commit got $actual" >&2; exit 1; }
}

clone_exact https://github.com/SagerNet/sing-box.git "$VENDOR" "$COMMIT" "sing-box $VERSION"
clone_exact https://github.com/XTLS/libXray.git "$XRAY_VENDOR" "$LIBXRAY_COMMIT" "libXray"

grep -Fq "github.com/xtls/xray-core $XRAY_CORE_VERSION" "$XRAY_VENDOR/go.mod" || {
  echo 'Pinned libXray no longer references the expected Xray-core v26.7.11 pseudo-version' >&2
  exit 1
}

git -C "$VENDOR" tag -f "v$VERSION" "$COMMIT" >/dev/null
install -m 0644 "$ROOT/routervpn_xray_bridge.go" "$VENDOR/experimental/libbox/routervpn_xray_bridge.go"

(
  cd "$VENDOR"
  # A local replace makes the immutable libXray checkout part of the one bound
  # libbox package. v0.0.0 is only a syntactic module requirement; the exact
  # source is the verified replacement above. The temporary module checkout is
  # deliberately lifted to libXray's required Go version, then tidied so Go's
  # MVS graph is explicit before any compile. Repository go.mod/go.sum files are
  # never changed by this disposable build workspace.
  go mod edit -go="$GO_MOD_VERSION"
  go mod edit -require=github.com/xtls/libxray@v0.0.0
  go mod edit -replace="github.com/xtls/libxray=$XRAY_VENDOR"
  go_retry mod tidy
  resolved=$(go_retry list -m -f '{{.Version}}' github.com/xtls/xray-core)
  [[ "$resolved" == "$XRAY_CORE_VERSION" ]] || {
    echo "combined module resolved unexpected Xray-core: $resolved" >&2
    exit 1
  }
  grep -Fq "github.com/xtls/libxray v0.0.0" go.mod || {
    echo 'combined module lost the pinned local libXray requirement' >&2
    exit 1
  }
  grep -Fq "replace github.com/xtls/libxray => $XRAY_VENDOR" go.mod || {
    echo 'combined module lost the exact local libXray replacement' >&2
    exit 1
  }
  gofmt -w experimental/libbox/routervpn_xray_bridge.go
  go_retry test ./experimental/libbox
  go_retry run ./cmd/internal/build_libbox -target android
)

SOURCE_AAR="$VENDOR/libbox.aar"
[[ -s "$SOURCE_AAR" ]] || { echo 'Pinned combined build did not produce libbox.aar' >&2; exit 1; }
install -m 0644 "$SOURCE_AAR" "$AAR"
install -m 0644 "$VENDOR/LICENSE" "$LICENSE_OUT"
install -m 0644 "$XRAY_VENDOR/LICENSE" "$XRAY_LICENSE_OUT"
printf '%s\n' "$EXPECTED_STAMP" >"$STAMP"
verify_aar
printf 'Built one pinned Android Go runtime: sing-box %s (%s) + libXray %s / Xray-core %s\n' "$VERSION" "$COMMIT" "$LIBXRAY_COMMIT" "$XRAY_CORE_VERSION"
