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
EXPECTED_STAMP="$COMMIT+$LIBXRAY_COMMIT+$XRAY_CORE_VERSION+$GO_TOOLCHAIN+$XRAY_POLICY_SHA+$NATIVE_XRAY_SHA"

require_typed_candidate_prefix_api() {
  local api_list="$1" signature
  for signature in 'io.nekohasekai.libbox.RouterNodeChainCandidatePreparation newRouterNodeChainSOCKSCandidatePreparation(java.lang.String, int, java.lang.String) throws java.lang.Exception;' 'io.nekohasekai.libbox.RouterNodeChainCandidatePreparation newRouterNodeChainCONNECTCandidatePreparation(java.lang.String, int, java.lang.String) throws java.lang.Exception;'; do
    grep -Fq "$signature" "$api_list" || {
      echo "combined libbox AAR is missing typed packet-prefix API: $signature" >&2; return 1
    }
  done
}

require_typed_connected_candidate_api() {
  local api_list="$1" socks_list="$2" connect_list="$3" family owner_list signature
  for family in SOCKS CONNECT; do
    for signature in "io.nekohasekai.libbox.RouterNodeChain${family}CandidateMeasurement routerNodeChain${family}NewCandidateMeasurement(io.nekohasekai.libbox.RouterNodeChain${family}, io.nekohasekai.libbox.CommandServer, int, java.lang.String, io.nekohasekai.libbox.RouterNodeChainCandidateCatalog) throws java.lang.Exception;"; do
      grep -Fq "$signature" "$api_list" || {
        echo "combined libbox AAR is missing connected typed candidate API: $signature" >&2; return 1
      }
    done
    if [[ "$family" == SOCKS ]]; then owner_list="$socks_list"; else owner_list="$connect_list"; fi
    for signature in 'void prepare() throws java.lang.Exception;' 'java.lang.String metadata();' 'java.lang.String metadataPage(int);' 'java.lang.String captureSHA256();' 'void start(java.lang.String, java.lang.String) throws java.lang.Exception;' 'void cancel(java.lang.String);' 'void drain(java.lang.String) throws java.lang.Exception;' 'java.lang.String statusJSON();' 'void networkChanged();' 'void close() throws java.lang.Exception;'; do
      grep -Fq "$signature" "$owner_list" || {
        echo "combined libbox AAR is missing the original $family candidate handle API: $signature" >&2; return 1
      }
    done
  done
}

require_ordinary_candidate_reservation_api() {
  local api_list="$1" owner_list="$2" signature
  signature='io.nekohasekai.libbox.RouterNodeChainCandidateMeasurement routerNodeChainNewCandidateMeasurement(io.nekohasekai.libbox.RouterNodeChain, io.nekohasekai.libbox.CommandServer, int, java.lang.String, io.nekohasekai.libbox.RouterNodeChainCandidateCatalog) throws java.lang.Exception;'
  grep -Fq "$signature" "$api_list" || {
    echo 'combined libbox AAR is missing the ordinary candidate reservation factory' >&2; return 1
  }
  for signature in 'java.lang.String routerNodeChainFilterPublicCandidateInventory(java.lang.String, int, java.lang.String) throws java.lang.Exception;' 'java.lang.String routerNodeChainCandidatePrefixMeasurement(io.nekohasekai.libbox.RouterNodeChain, int);' 'boolean routerNodeChainCandidateInputSupportedForMeasurement(java.lang.String, java.lang.String);' 'java.lang.String routerNodeChainCandidatePrefixProof(io.nekohasekai.libbox.RouterNodeChain, int);'; do
    grep -Fq "$signature" "$api_list" || {
      echo "combined libbox AAR is missing the candidate prefix measurement API: $signature" >&2; return 1
    }
  done
  if grep -Fq 'routerNodeChainCloseCandidateMeasurement(' "$api_list"; then
    echo 'combined libbox AAR exposes unsafe ordinary candidate owner-key cleanup' >&2; return 1
  fi
  for signature in 'void prepare() throws java.lang.Exception;' 'java.lang.String metadata();' 'java.lang.String metadataPage(int);' 'java.lang.String captureSHA256();' 'void start(java.lang.String, java.lang.String) throws java.lang.Exception;' 'void cancel(java.lang.String);' 'void drain(java.lang.String) throws java.lang.Exception;' 'java.lang.String statusJSON();' 'void networkChanged();' 'void close() throws java.lang.Exception;'; do
    grep -Fq "$signature" "$owner_list" || {
      echo "combined libbox AAR is missing the original ordinary candidate handle API: $signature" >&2; return 1
    }
  done
}

require_execution_entry_candidate_api() {
  local api_list="$1" owner_list="$2" signature
  signature='io.nekohasekai.libbox.RouterNodeChainExecutionCandidateMeasurement routerNodeChainExecutionNewCandidateMeasurement(io.nekohasekai.libbox.RouterNodeChainExecution, io.nekohasekai.libbox.CommandServer, int, java.lang.String, io.nekohasekai.libbox.RouterNodeChainCandidateCatalog) throws java.lang.Exception;'
  grep -Fq "$signature" "$api_list" || {
    echo 'combined libbox AAR is missing the execution entry candidate reservation factory' >&2; return 1
  }
  if grep -Fq 'routerNodeChainExecutionCloseCandidateMeasurement(' "$api_list"; then
    echo 'combined libbox AAR exposes unsafe execution entry candidate owner-key cleanup' >&2; return 1
  fi
  for signature in 'void prepare() throws java.lang.Exception;' 'java.lang.String metadata();' 'java.lang.String metadataPage(int);' 'java.lang.String captureSHA256();' 'void start(java.lang.String, java.lang.String) throws java.lang.Exception;' 'void cancel(java.lang.String);' 'void drain(java.lang.String) throws java.lang.Exception;' 'java.lang.String statusJSON();' 'void networkChanged();' 'void close() throws java.lang.Exception;'; do
    grep -Fq "$signature" "$owner_list" || {
      echo "combined libbox AAR is missing the original execution entry candidate handle API: $signature" >&2; return 1
    }
  done
}

verify_aar() {
  test -s "$AAR"
  test -s "$AMNEZIA_LICENSE_OUT"
  python3 "$ROOT/../deploy/verify-mobile-tor-link.py" --native-package "$TOR_PACKAGE" --android-aar "$AAR" --ndk "$ANDROID_NDK_HOME"
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
  grep -Fq 'io.nekohasekai.libbox.RouterNodeChainCandidatePreparation newRouterNodeChainCandidatePreparation(java.lang.String, int, java.lang.String) throws java.lang.Exception;' "$api_list" || {
    echo 'combined libbox AAR is missing the original prefix preparation factory' >&2; return 1
  }
  grep -Fq 'io.nekohasekai.libbox.RouterNodeChainCandidatePreparation routerNodeChainCandidatePreparationLaunch(java.lang.String) throws java.lang.Exception;' "$api_list" || {
    echo 'combined libbox AAR is missing the strict private prefix launch parser' >&2; return 1
  }
  require_typed_candidate_prefix_api "$api_list" || return 1
  javap -classpath "$classes" io.nekohasekai.libbox.RouterNodeChainSOCKSCandidateMeasurement >"$tmp/router-node-chain-socks-candidate.javap"
  javap -classpath "$classes" io.nekohasekai.libbox.RouterNodeChainCONNECTCandidateMeasurement >"$tmp/router-node-chain-connect-candidate.javap"
  require_typed_connected_candidate_api "$api_list" "$tmp/router-node-chain-socks-candidate.javap" "$tmp/router-node-chain-connect-candidate.javap" || return 1
  javap -classpath "$classes" io.nekohasekai.libbox.RouterNodeChainCandidateMeasurement >"$tmp/router-node-chain-candidate.javap"
  require_ordinary_candidate_reservation_api "$api_list" "$tmp/router-node-chain-candidate.javap" || return 1
  javap -classpath "$classes" io.nekohasekai.libbox.RouterNodeChainExecutionCandidateMeasurement >"$tmp/router-node-chain-execution-candidate.javap"
  require_execution_entry_candidate_api "$api_list" "$tmp/router-node-chain-execution-candidate.javap" || return 1
  grep -Fq 'java.lang.String routerNodeChainImportedOpenVPNMemberInput(java.lang.String, java.lang.String) throws java.lang.Exception;' "$api_list" || {
    echo 'combined libbox AAR is missing the exact original OpenVPN middle constructor API' >&2; return 1
  }
  javap -classpath "$classes" io.nekohasekai.libbox.RouterNodeChainCandidatePreparation >"$tmp/router-node-chain-candidate-preparation.javap"
  for signature in 'void bindNative(io.nekohasekai.libbox.CommandServer) throws java.lang.Exception;' 'boolean nativeClosed();' 'void run(io.nekohasekai.libbox.CommandServer, io.nekohasekai.libbox.RouterNodeChainCandidateCatalog) throws java.lang.Exception;' 'java.lang.String config();' 'java.lang.String launchInput();' 'java.lang.String sourceSHA256();' 'java.lang.String configSHA256();' 'java.lang.String originalSourceSHA256();' 'java.lang.String captureSHA256();' 'java.lang.String metadata();' 'java.lang.String metadataPage(int);' 'java.lang.String progressJSON();' 'boolean healthy();' 'void start(java.lang.String, java.lang.String) throws java.lang.Exception;' 'void cancel(java.lang.String);' 'void drain(java.lang.String) throws java.lang.Exception;' 'java.lang.String statusJSON();' 'void networkChanged();' 'void close() throws java.lang.Exception;'; do
    grep -Fq "$signature" "$tmp/router-node-chain-candidate-preparation.javap" || {
      echo 'combined libbox AAR prefix preparation has the wrong retained-owner API' >&2; return 1
    }
  done
  # CONNECT is a separate schema-four owner; an ordinary graph API cannot
  # satisfy its generated Java construction, MTU or close-receipt contract.
  for signature in 'io.nekohasekai.libbox.RouterNodeChainCONNECT newRouterNodeChainCONNECT(java.lang.String) throws java.lang.Exception;' 'java.lang.String routerNodeChainImportedCONNECTMemberInput(java.lang.String, java.lang.String) throws java.lang.Exception;' 'io.nekohasekai.libbox.CommandServer routerNodeChainCONNECTNewCommandServer(io.nekohasekai.libbox.RouterNodeChainCONNECT, io.nekohasekai.libbox.CommandServerHandler, io.nekohasekai.libbox.PlatformInterface) throws java.lang.Exception;' 'io.nekohasekai.libbox.RouterHopMeasurement routerNodeChainCONNECTNewHopMeasurement(io.nekohasekai.libbox.RouterNodeChainCONNECT, io.nekohasekai.libbox.CommandServer) throws java.lang.Exception;' 'io.nekohasekai.libbox.RouterMTU routerNodeChainCONNECTNewMTU(io.nekohasekai.libbox.RouterNodeChainCONNECT, io.nekohasekai.libbox.CommandServer, io.nekohasekai.libbox.RouterMTUPlatform) throws java.lang.Exception;'; do
    grep -Fq "$signature" "$api_list" || { echo "combined libbox AAR is missing typed CONNECT API: $signature" >&2; return 1; }
  done
  javap -classpath "$classes" io.nekohasekai.libbox.RouterNodeChainCONNECT >"$tmp/router-node-chain-connect.javap"
  for signature in 'io.nekohasekai.libbox.CommandServer newCommandServer(io.nekohasekai.libbox.CommandServerHandler, io.nekohasekai.libbox.PlatformInterface) throws java.lang.Exception;' 'java.lang.String source() throws java.lang.Exception;' 'java.lang.String config() throws java.lang.Exception;' 'java.lang.String sourceSHA256();' 'java.lang.String configSHA256();' 'java.lang.String metadata();' 'java.lang.String mtuProfile();' 'java.lang.String progressJSON();' 'void bindNative(io.nekohasekai.libbox.CommandServer) throws java.lang.Exception;' 'void run(io.nekohasekai.libbox.CommandServer) throws java.lang.Exception;' 'boolean healthy();' 'boolean nativeClosed();' 'boolean retainsServerCleanup(io.nekohasekai.libbox.CommandServer);' 'void networkChanged();' 'void close() throws java.lang.Exception;'; do
    grep -Fq "$signature" "$tmp/router-node-chain-connect.javap" || { echo "combined libbox AAR is missing captured CONNECT owner API: $signature" >&2; return 1; }
  done
  for symbol in newRouterNodeChainExecution routerNodeChainExecutionFromLaunch newRouterNodeChainExecutionLaunch newRouterNodeChainExecutionRestore; do
    grep -Fq "$symbol(" "$api_list" || { echo "combined libbox AAR is missing ordered execution API $symbol" >&2; return 1; }
  done
  for signature in 'io.nekohasekai.libbox.RouterNodeChainExecution newRouterNodeChainCONNECTExecution(java.lang.String, java.lang.String) throws java.lang.Exception;' 'io.nekohasekai.libbox.RouterNodeChainExecution newRouterNodeChainCONNECTExecutionLaunch(java.lang.String) throws java.lang.Exception;' 'io.nekohasekai.libbox.RouterNodeChainExecution routerNodeChainCONNECTExecutionFromLast(java.lang.String, java.lang.String, java.lang.String) throws java.lang.Exception;'; do
    grep -Fq "$signature" "$api_list" || { echo "combined libbox AAR is missing typed CONNECT execution API: $signature" >&2; return 1; }
  done
  for signature in 'io.nekohasekai.libbox.RouterNodeChainExecution newRouterNodeChainSOCKSExecution(java.lang.String, java.lang.String) throws java.lang.Exception;' 'io.nekohasekai.libbox.RouterNodeChainExecution newRouterNodeChainSOCKSExecutionLaunch(java.lang.String) throws java.lang.Exception;' 'io.nekohasekai.libbox.RouterNodeChainExecution routerNodeChainSOCKSExecutionFromLast(java.lang.String, java.lang.String, java.lang.String) throws java.lang.Exception;' 'io.nekohasekai.libbox.CommandServer routerNodeChainSOCKSExecutionNewCommandServer(io.nekohasekai.libbox.RouterNodeChainExecution, io.nekohasekai.libbox.CommandServerHandler, io.nekohasekai.libbox.PlatformInterface) throws java.lang.Exception;'; do
    grep -Fq "$signature" "$api_list" || { echo "combined libbox AAR is missing typed SOCKS execution API: $signature" >&2; return 1; }
  done
  for signature in 'io.nekohasekai.libbox.RouterNodeChainExecution routerNodeChainOpenVPNExecutionFromLaunch(java.lang.String, java.lang.String) throws java.lang.Exception;' 'io.nekohasekai.libbox.RouterNodeChainExecution newRouterNodeChainOpenVPNExecutionLaunch(java.lang.String) throws java.lang.Exception;' 'io.nekohasekai.libbox.RouterNodeChainExecution routerNodeChainOpenVPNExecutionFromLast(java.lang.String, java.lang.String, java.lang.String) throws java.lang.Exception;' 'io.nekohasekai.libbox.CommandServer routerNodeChainOpenVPNExecutionNewCommandServer(io.nekohasekai.libbox.RouterNodeChainExecution, io.nekohasekai.libbox.CommandServerHandler, io.nekohasekai.libbox.PlatformInterface) throws java.lang.Exception;'; do
    grep -Fq "$signature" "$api_list" || { echo "combined libbox AAR is missing typed OpenVPN execution API: $signature" >&2; return 1; }
  done
  javap -classpath "$classes" io.nekohasekai.libbox.RouterNodeChainExecution >"$tmp/router-node-chain-execution.javap"
  for signature in 'int extendedOriginalNodeCount();' 'int extendedOriginalStatusLimit();' 'io.nekohasekai.libbox.CommandServer newCommandServer(io.nekohasekai.libbox.CommandServerHandler, io.nekohasekai.libbox.PlatformInterface) throws java.lang.Exception;' 'void bindNative(io.nekohasekai.libbox.CommandServer) throws java.lang.Exception;' 'void run(io.nekohasekai.libbox.CommandServer) throws java.lang.Exception;' 'boolean healthy();' 'java.lang.String execution();' 'void close() throws java.lang.Exception;' 'boolean nativeClosed();' 'boolean retainsServerCleanup(io.nekohasekai.libbox.CommandServer);' 'java.lang.String launchInput() throws java.lang.Exception;'; do
    grep -Fq "$signature" "$tmp/router-node-chain-execution.javap" || {
      echo 'combined libbox AAR ordered execution has the wrong original-owner API' >&2; return 1
    }
  done
  for symbol in routerCompileExternalPolicy routerValidateExternalTransport routerValidateExternalDNS routerPrepareExternalExecutionCapture routerValidateExternalResponseProbe routerExternalCreateProof routerExternalCreateHopMeasurement routerTorCreateHopMeasurement routerExternalCreateDNSMeasurement routerTorCreateDNSMeasurement newRouterExternalMTU; do
    grep -Fq "$symbol(" "$api_list" || { echo "combined libbox AAR is missing external policy API $symbol" >&2; return 1; }
  done
  grep -Fq 'io.nekohasekai.libbox.RouterMTU newRouterExternalMTU(io.nekohasekai.libbox.CommandServer, io.nekohasekai.libbox.RouterMTUPlatform, io.nekohasekai.libbox.RouterExternalProofRequest, java.lang.String, java.lang.String) throws java.lang.Exception;' "$api_list" || {
    echo 'combined libbox AAR external MTU factory has the wrong retained-proof API' >&2; return 1
  }
  javap -classpath "$classes" io.nekohasekai.libbox.RouterHopMeasurement >"$tmp/router-hop-measurement.javap"
  grep -Fq 'void drain(java.lang.String) throws java.lang.Exception;' "$tmp/router-hop-measurement.javap" || {
    echo 'combined libbox AAR measurement owner lacks synchronous request drain' >&2; return 1
  }
  javap -classpath "$classes" io.nekohasekai.libbox.RouterDNSMeasurement >"$tmp/router-dns-measurement.javap"
  for signature in 'void start(java.lang.String, java.lang.String) throws java.lang.Exception;' 'void cancel(java.lang.String);' 'void drain(java.lang.String) throws java.lang.Exception;' 'java.lang.String statusJSON();' 'void close() throws java.lang.Exception;' 'void networkChanged();'; do
    grep -Fq "$signature" "$tmp/router-dns-measurement.javap" || {
      echo 'combined libbox AAR DNS measurement owner has the wrong retained-lifecycle API' >&2; return 1
    }
  done
  javap -classpath "$classes" io.nekohasekai.libbox.RouterExternalProofRequest >"$tmp/router-external-proof.javap"
  for signature in 'java.lang.String run() throws java.lang.Exception;' 'java.lang.String execution();' 'void cancel();' 'void close() throws java.lang.Exception;' 'boolean healthy();'; do
    grep -Fq "$signature" "$tmp/router-external-proof.javap" || {
      echo 'combined libbox AAR external proof request has the wrong owned-lifecycle API' >&2; return 1
    }
  done
  for symbol in routerTorNativeABI routerTorNativeVersion routerTorSourceNotices routerCompileTorProfile routerValidateTorProfile routerCompileTorProfileWithPredecessor routerCompileTorProfileWithExternalPredecessor routerTorPaddingSource routerTorSetStateDirectory routerTorCreateProof routerTorCreateProofWithPredecessor routerTorNewCompare routerStrategyDNSProof routerStrategyCloseService; do
    grep -Fq "$symbol(" "$api_list" || { echo "combined libbox AAR is missing native Tor API $symbol" >&2; return 1; }
  done
  javap -classpath "$classes" io.nekohasekai.libbox.RouterTorCompare >"$tmp/router-tor-compare.javap"
  for signature in 'void run() throws java.lang.Exception;' 'java.lang.String execution();' 'java.lang.String resultJSON();' 'void keep() throws java.lang.Exception;' 'void cancel();' 'void close() throws java.lang.Exception;'; do
    grep -Fq "$signature" "$tmp/router-tor-compare.javap" || {
      echo 'combined libbox AAR Tor comparison has the wrong transfer/drain API' >&2; return 1
    }
  done
  javap -classpath "$classes" io.nekohasekai.libbox.RouterTorCompareHost >"$tmp/router-tor-compare-host.javap"
  for signature in 'boolean current();' 'io.nekohasekai.libbox.RouterTorCompareCandidate newCandidate(java.lang.String, java.lang.String);' 'void progress(java.lang.String, java.lang.String);'; do
    grep -Fq "$signature" "$tmp/router-tor-compare-host.javap" || {
      echo 'combined libbox AAR Tor comparison has the wrong captured-host API' >&2; return 1
    }
  done
  javap -classpath "$classes" io.nekohasekai.libbox.RouterTorCompareCandidate >"$tmp/router-tor-compare-candidate.javap"
  for signature in 'boolean current();' 'void start() throws java.lang.Exception;' 'io.nekohasekai.libbox.CommandServer server();' 'io.nekohasekai.libbox.RouterTorProofRequest proof();' 'void cancel();' 'void close() throws java.lang.Exception;'; do
    grep -Fq "$signature" "$tmp/router-tor-compare-candidate.javap" || {
      echo 'combined libbox AAR Tor comparison has the wrong native-candidate API' >&2; return 1
    }
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
  for signature in 'java.lang.String run() throws java.lang.Exception;' 'java.lang.String paddingStatusJSON() throws java.lang.Exception;' 'void cancel();' 'boolean healthy();'; do
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

rm -rf "$VENDOR" "$XRAY_VENDOR" "$XRAY_CORE_VENDOR"
mkdir -p "$(dirname "$VENDOR")" "$LIBDIR"

python3 "$ROOT/../deploy/fetch_mobile_pinned_git.py" https://github.com/SagerNet/sing-box.git "$COMMIT" "$VENDOR"
python3 "$ROOT/../deploy/fetch_mobile_pinned_git.py" https://github.com/XTLS/libXray.git "$LIBXRAY_COMMIT" "$XRAY_VENDOR"
python3 "$ROOT/../deploy/fetch_mobile_pinned_git.py" https://github.com/XTLS/Xray-core.git 50231eaff98ccc31b5cbd247a721c16e97fe5ec1 "$XRAY_CORE_VENDOR"
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
  python3 "$ROOT/../deploy/prepare-mobile-amnezia.py" --verify-dependency "$VENDOR"
  # This Linux gate runs real pinned Tor, the shipping Cgo owner and actual PT
  # workers in the same prepared Libbox module before cross-platform linkage.
  if [[ $(uname -s) == Linux ]]; then
    TOR_HOST_PACKAGE="$ROOT/.vendor/tor-host-test"
    python3 "$ROOT/../deploy/build-mobile-tor-package.py" --platform host-test --output "$TOR_HOST_PACKAGE" --source-cache "$TOR_SOURCE_CACHE"
    TOR_GATE_PARENT=$(mktemp -d "$ROOT/.vendor/tor-outbound-proof.XXXXXX")
    # Run the shipping Swift profile compiler against these same real engines.
    # Linux CI includes Swift; this must not use the unavailable macOS C stub.
  fi
  # Install only the verified C dependency into the existing Go module after
  # host graph gates, before the sole gomobile build of the combined runtime.
  python3 "$ROOT/../deploy/prepare-mobile-torpack.py" "$VENDOR" --native-package "$TOR_PACKAGE"
  # Recheck the actual Android-only Xray import after every host preparation.
  # Host tests cannot detect a lowered Go directive on that platform-only edge.
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
