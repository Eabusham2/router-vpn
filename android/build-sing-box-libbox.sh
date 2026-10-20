#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERSION=1.14.1
COMMIT=1ac1a339cb1223e9c70eae14c44411c75033c02d
LIBXRAY_COMMIT=294fb37343205b9b0cb7b7b1b423d3d4b60d9998
XRAY_CORE_VERSION=v1.260327.1-0.20260711155151-50231eaff98c
GO_TOOLCHAIN=go1.26.3
GO_MOD_VERSION=${GO_TOOLCHAIN#go}
[[ "$GO_MOD_VERSION" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || { echo "invalid Go module directive version: $GO_MOD_VERSION" >&2; exit 1; }
NDK_VERSION=28.0.13004108
GOMOBILE_VERSION=0.1.12
VENDOR="$ROOT/.vendor/sing-box"
XRAY_VENDOR="$ROOT/.vendor/libXray-combined"
XRAY_CORE_VENDOR="$ROOT/.vendor/xray-core-shared"
XRAY_POLICY_SHA=$(python3 "$ROOT/../deploy/prepare-xray-runtime.py" --digest)
NATIVE_XRAY_SHA=$(python3 "$ROOT/../deploy/prepare-apple-xray.py" --digest)
LIBDIR="$ROOT/app/libs"
AAR="$LIBDIR/libbox.aar"
STAMP="$LIBDIR/libbox.commit"
LICENSE_OUT="$LIBDIR/libbox-LICENSE.txt"
XRAY_LICENSE_OUT="$LIBDIR/libxray-LICENSE.txt"
AMNEZIA_LICENSE_OUT="$LIBDIR/native-amneziawg-LICENSE.txt"
TOR_PACKAGE="$LIBDIR/tor-native"
TOR_NOTICES="$LIBDIR/tor-notices"
TOR_SOURCE_CACHE="$ROOT/.vendor/tor-sources"
# Select the shared pinned NDK before either the Tor C package or Libbox is
# built. Hosted runners may export a different default ANDROID_NDK_HOME.
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
TOR_SOURCE_SHA=$(python3 "$ROOT/../deploy/prepare-mobile-tor.py" --digest)
python3 "$ROOT/../deploy/build-mobile-tor-package.py" --platform android --output "$TOR_PACKAGE" --source-cache "$TOR_SOURCE_CACHE" --ndk "$ANDROID_NDK_HOME"
python3 "$ROOT/../deploy/stage-mobile-tor-notices.py" --package "$TOR_PACKAGE" --output "$TOR_NOTICES"
OPENVPN_SOURCE="$ROOT/../mobile/routervpn_openvpn.go"
OPENVPN_STAMP="$LIBDIR/libbox.openvpn.sha256"
OPENVPN_SHA=$(python3 "$ROOT/../deploy/prepare-mobile-openvpn.py" --digest)
MULTIHOP_SHA=$(python3 "$ROOT/../deploy/prepare-mobile-multihop.py" --digest)
OPENVPN_SHA=$(python3 -c 'import hashlib,sys;print(hashlib.sha256((sys.argv[1]+"+"+sys.argv[2]).encode()).hexdigest())' "$OPENVPN_SHA" "$MULTIHOP_SHA")
OPENVPN_SHA=$(python3 -c 'import hashlib,sys;print(hashlib.sha256((sys.argv[1]+"+"+sys.argv[2]).encode()).hexdigest())' "$OPENVPN_SHA" "$TOR_SOURCE_SHA")
# Native graph evidence is tied to the actual Java builder/policy inputs, not
# only the Go core. Changing a host graph invalidates the cached AAR proof.
ANDROID_GRAPH_SHA=$(python3 "$ROOT/../deploy/test_android_multihop_pinned.py" --digest)
OPENVPN_SHA=$(python3 -c 'import hashlib,sys;print(hashlib.sha256((sys.argv[1]+"+"+sys.argv[2]).encode()).hexdigest())' "$OPENVPN_SHA" "$ANDROID_GRAPH_SHA")
ANDROID_TOR_GRAPH_SHA=$(python3 "$ROOT/../deploy/test_android_tor_pinned.py" --digest)
OPENVPN_SHA=$(python3 -c 'import hashlib,sys;print(hashlib.sha256((sys.argv[1]+"+"+sys.argv[2]).encode()).hexdigest())' "$OPENVPN_SHA" "$ANDROID_TOR_GRAPH_SHA")
APPLE_TOR_GRAPH_SHA=$(python3 "$ROOT/../deploy/test_ios_tor_pinned.py" --digest)
OPENVPN_SHA=$(python3 -c 'import hashlib,sys;print(hashlib.sha256((sys.argv[1]+"+"+sys.argv[2]).encode()).hexdigest())' "$OPENVPN_SHA" "$APPLE_TOR_GRAPH_SHA")
EXPECTED_STAMP="$COMMIT+$LIBXRAY_COMMIT+$XRAY_CORE_VERSION+$GO_TOOLCHAIN+$XRAY_POLICY_SHA+$NATIVE_XRAY_SHA"

verify_aar() {
  test -s "$AAR"
  test -s "$AMNEZIA_LICENSE_OUT"
  python3 "$ROOT/../deploy/verify-mobile-tor-link.py" --native-package "$TOR_PACKAGE" --android-aar "$AAR"
  python3 "$ROOT/../deploy/stage-mobile-tor-notices.py" --package "$TOR_PACKAGE" --output "$TOR_NOTICES" --verify
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
  for symbol in routerCompileExternalPolicy routerExternalCreateProof; do
    grep -Fq "$symbol(" "$api_list" || { echo "combined libbox AAR is missing external policy API $symbol" >&2; return 1; }
  done
  javap -classpath "$classes" io.nekohasekai.libbox.RouterExternalProofRequest >"$tmp/router-external-proof.javap"
  for signature in 'java.lang.String run() throws java.lang.Exception;' 'void cancel();' 'boolean healthy();'; do
    grep -Fq "$signature" "$tmp/router-external-proof.javap" || {
      echo 'combined libbox AAR external proof request has the wrong owned-lifecycle API' >&2; return 1
    }
  done
  for symbol in routerTorNativeABI routerTorNativeVersion routerTorSourceNotices routerCompileTorProfile routerTorSetStateDirectory routerTorCreateProof routerTorCreateProofWithPredecessor routerStrategyDNSProof routerStrategyCloseService; do
    grep -Fq "$symbol(" "$api_list" || { echo "combined libbox AAR is missing native Tor API $symbol" >&2; return 1; }
  done
  for symbol in routerCheckMAXProfile routerCreateMAXProfileRequest routerCompileMAXProfile; do
    grep -Fq "$symbol(" "$api_list" || { echo "combined libbox AAR is missing owned MAX API $symbol" >&2; return 1; }
  done
  javap -classpath "$classes" io.nekohasekai.libbox.RouterMAXEndpointResolver >"$tmp/router-max-resolver.javap"
  for signature in 'java.lang.String ownerID();' 'boolean current();' 'java.lang.String lookup(java.lang.String) throws java.lang.Exception;' 'void cancel();'; do
    grep -Fq "$signature" "$tmp/router-max-resolver.javap" || {
      echo 'combined libbox AAR MAX resolver has the wrong captured-owner API' >&2; return 1
    }
  done
  javap -classpath "$classes" io.nekohasekai.libbox.RouterMAXProfileRequest >"$tmp/router-max-request.javap"
  for signature in 'java.lang.String sourceSHA256();' 'java.lang.String run() throws java.lang.Exception;' 'boolean healthy();' 'void cancel();' 'void close();'; do
    grep -Fq "$signature" "$tmp/router-max-request.javap" || {
      echo 'combined libbox AAR MAX request has the wrong cancellation/drain API' >&2; return 1
    }
  done
  javap -classpath "$classes" io.nekohasekai.libbox.RouterTorProofRequest >"$tmp/router-tor-proof.javap"
  for signature in 'java.lang.String run() throws java.lang.Exception;' 'void cancel();' 'boolean healthy();'; do
    grep -Fq "$signature" "$tmp/router-tor-proof.javap" || {
      echo 'combined libbox AAR RouterTorProofRequest has the wrong captured-owner API' >&2
      return 1
    }
  done
  for symbol in     newRouterMTU     routerMTUPhysicalPath     routerReadMTUInterface     routerApplyPerformancePolicy     routerStartPerformance     routerPerformanceFailure     routerInvalidatePerformance     routerPerformanceStatus     routerCompileProxyEntry     routerMultihopMTUProfile     routerCompileAmneziaProfile     routerAmneziaExitConfig     routerCompileWireGuardProfile     routerWireGuardExitConfig     routerApplyMultihopMTUPolicy     routerApplyMultihopLANPolicy     newRouterHopMeasurement     routerCompileSIP003Profile     routerComposeSIP003StartLayer     routerCheckXrayProfile     routerCompileXrayProfile     routerResolveXrayProfile     routerComposeXrayStartLayer     routerResolveXrayStartLayerProfile     routerApplyNativeXrayDevicePolicy     newRouterMultihop     newRouterMultihopWithEntryStartLayer     newRouterMultihopWithStartLayers     routerCompileMultihopStartLayers     routerCompileMultihopEntryStartLayer     routerOpenVPNEndpoint     routerXrayInvoke     routerXrayRegisterDialerController     routerXraySetDNS     routerXrayResetDNS     routerXrayBridgeRevision; do
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

if [[ -s "$AAR" && -f "$STAMP" && $(tr -d '\r\n' <"$STAMP") == "$EXPECTED_STAMP" && -f "$OPENVPN_STAMP" && $(tr -d '\r\n' <"$OPENVPN_STAMP") == "$OPENVPN_SHA" ]]; then
  verify_aar
  printf 'Pinned combined Android Go runtime already built: sing-box %s + libXray %s\n' "$VERSION" "$LIBXRAY_COMMIT"
  exit 0
fi

command -v git >/dev/null || { echo 'git is required to build the pinned Android Go runtime' >&2; exit 1; }
command -v go >/dev/null || { echo 'Go with toolchain download support is required' >&2; exit 1; }
command -v java >/dev/null || { echo 'Java 17 is required to validate the combined AAR' >&2; exit 1; }
command -v javap >/dev/null || { echo 'javap is required to validate the combined AAR API' >&2; exit 1; }
command -v jar >/dev/null || { echo 'JDK jar tool is required to inspect the combined AAR classes' >&2; exit 1; }

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
python3 "$ROOT/../deploy/test_mobile_tor_loader.py" --go "$(command -v go)"
python3 "$ROOT/../deploy/test_mobile_tor_package_policy.py" --source-cache "$TOR_SOURCE_CACHE"
python3 "$ROOT/../deploy/test_mobile_tor_packaged_link.py" --native-package "$TOR_PACKAGE"

rm -rf "$VENDOR" "$XRAY_VENDOR" "$XRAY_CORE_VENDOR"
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
clone_exact https://github.com/XTLS/Xray-core.git "$XRAY_CORE_VENDOR" 50231eaff98ccc31b5cbd247a721c16e97fe5ec1 "Xray-core"
python3 "$ROOT/../deploy/prepare-xray-runtime.py" "$XRAY_CORE_VENDOR"
# Context-scoped native Xray shares this Go runtime without replacing legacy
# Android VpnService socket protection or constructing a second system VPN.
python3 "$ROOT/../deploy/prepare-apple-xray.py" "$VENDOR" "$XRAY_CORE_VENDOR"

grep -Fq "github.com/xtls/xray-core $XRAY_CORE_VERSION" "$XRAY_VENDOR/go.mod" || {
  echo 'Pinned libXray no longer references the expected Xray-core v26.7.11 pseudo-version' >&2
  exit 1
}

git -C "$VENDOR" tag -f "v$VERSION" "$COMMIT" >/dev/null
install -m 0644 "$ROOT/routervpn_xray_bridge.go" "$VENDOR/experimental/libbox/routervpn_xray_bridge.go"
# Same Go runtime and protected socket path as every other mobile Libbox mode.
grep -Fq 'with_openvpn' "$VENDOR/cmd/internal/build_libbox/main.go"
python3 "$ROOT/../deploy/prepare-mobile-openvpn.py" "$VENDOR"
python3 "$ROOT/../deploy/prepare-mobile-multihop.py" "$VENDOR"
python3 "$ROOT/../deploy/test_retained_strategy_preparation.py" "$VENDOR"
python3 "$ROOT/../deploy/prepare-mobile-tor.py" "$VENDOR" --go "$(command -v go)"

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
  go mod edit -replace="github.com/xtls/xray-core=$XRAY_CORE_VENDOR"
  go_retry mod tidy
  core_dir=$(go_retry list -m -f '{{.Dir}}' github.com/xtls/xray-core)
  [[ "$core_dir" == "$XRAY_CORE_VENDOR" ]] || { echo 'combined engine lost its prepared Xray source' >&2; exit 1; }
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
  go_retry test ./experimental/libbox/routervpn/...
  go_retry test -race ./adapter/inbound -run TestRouterVPN -count=1
  go_retry test -race ./route -run '^TestRouterVPNStrategyInterface' -count=1 -timeout=90s
  go_retry test -ldflags=-checklinkname=0 -tags with_quic,with_wireguard,with_gvisor ./experimental/libbox -run 'TestRouter(Multihop|NativeWireGuard|NativeAmnezia|NativePerformance|NativeBaseStartLayer|NativeSIP003StartLayer|MTU)' -count=1
  go_retry test -race -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor ./protocol/routervpnamnezia -count=1
  go_retry test -race -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor ./transport/wireguard -run TestRouterVPNClientBind -count=1
  go_retry test -race -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor ./service/routervpnperformance ./experimental/libbox/routervpn/mobileperf -count=1 -timeout=120s
  python3 "$ROOT/../deploy/prepare-mobile-amnezia.py" --verify-dependency "$VENDOR"
  go_retry test -ldflags=-checklinkname=0 -tags with_quic,with_wireguard,with_gvisor ./experimental/libbox
  bash "$ROOT/../deploy/test_mobile_openvpn_pinned.sh" "$VENDOR"
  bash "$ROOT/../deploy/test_mobile_external_pinned.sh" "$VENDOR"
  bash "$ROOT/../deploy/test_apple_xray_pinned.sh" "$VENDOR" "$XRAY_CORE_VENDOR"
  bash "$ROOT/../deploy/test_mobile_whitening_pinned.sh" "$VENDOR"
  bash "$ROOT/../deploy/test_mobile_sip003_pinned.sh" "$VENDOR"
  python3 "$ROOT/../deploy/test_android_multihop_pinned.py" "$VENDOR"
  # This Linux gate runs real pinned Tor, the shipping Cgo owner and actual PT
  # workers in the same prepared Libbox module before cross-platform linkage.
  if [[ $(uname -s) == Linux ]]; then
    TOR_HOST_PACKAGE="$ROOT/.vendor/tor-host-test"
    python3 "$ROOT/../deploy/build-mobile-tor-package.py" --platform host-test --output "$TOR_HOST_PACKAGE" --source-cache "$TOR_SOURCE_CACHE"
    python3 "$ROOT/../deploy/test_mobile_tor_package_runtime.py" --package "$TOR_HOST_PACKAGE" --go "$(command -v go)"
    TOR_GATE_PARENT=$(mktemp -d "$ROOT/.vendor/tor-outbound-proof.XXXXXX")
    python3 "$ROOT/../deploy/test-mobile-tor-outbound.py" --go "$(command -v go)" --vendor "$VENDOR" --native-package "$TOR_HOST_PACKAGE" --output "$TOR_GATE_PARENT/evidence"
    python3 "$ROOT/../deploy/test_android_tor_pinned.py" "$VENDOR" --native-package "$TOR_HOST_PACKAGE" --go "$(command -v go)"
    # Run the shipping Swift profile compiler against these same real engines.
    # Linux CI includes Swift; this must not use the unavailable macOS C stub.
    python3 "$ROOT/../deploy/test_ios_tor_pinned.py" --vendor "$VENDOR" --native-package "$TOR_HOST_PACKAGE" --go "$(command -v go)" --output "$TOR_GATE_PARENT/apple-graphs"
    python3 "$ROOT/../deploy/test_mobile_external_graphs.py" --vendor "$VENDOR" --platform android --native-package "$TOR_HOST_PACKAGE" --go "$(command -v go)"
    python3 "$ROOT/../deploy/test_mobile_external_graphs.py" --vendor "$VENDOR" --platform ios --native-package "$TOR_HOST_PACKAGE" --go "$(command -v go)"
  fi
  # Install only the verified C dependency into the existing Go module after
  # host graph gates, before the sole gomobile build of the combined runtime.
  python3 "$ROOT/../deploy/prepare-mobile-torpack.py" "$VENDOR" --native-package "$TOR_PACKAGE"
  go_retry run ./cmd/internal/build_libbox -target android
)

SOURCE_AAR="$VENDOR/libbox.aar"
[[ -s "$SOURCE_AAR" ]] || { echo 'Pinned combined build did not produce libbox.aar' >&2; exit 1; }
install -m 0644 "$SOURCE_AAR" "$AAR"
install -m 0644 "$VENDOR/LICENSE" "$LICENSE_OUT"
install -m 0644 "$XRAY_VENDOR/LICENSE" "$XRAY_LICENSE_OUT"
install -m 0644 "$VENDOR/routervpn-amnezia-LICENSE.txt" "$AMNEZIA_LICENSE_OUT"
printf '%s\n' "$EXPECTED_STAMP" >"$STAMP"
printf '%s\n' "$OPENVPN_SHA" > "$OPENVPN_STAMP"
verify_aar
printf 'Built one pinned Android Go runtime: sing-box %s (%s) + libXray %s / Xray-core %s\n' "$VERSION" "$COMMIT" "$LIBXRAY_COMMIT" "$XRAY_CORE_VERSION"
