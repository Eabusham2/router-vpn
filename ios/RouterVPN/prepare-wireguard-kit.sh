#!/bin/sh
set -eu

PIN="9d5ee60edefa95b933a738dd7cda671dd18021fc"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
DEPS="$ROOT/.deps"
WG="$DEPS/wireguard-apple"
REMOTE="https://github.com/amnezia-vpn/amneziawg-apple"

mkdir -p "$DEPS"
if [ ! -d "$WG/.git" ]; then
  TMP="$DEPS/wireguard-apple.tmp.$$"
  rm -rf "$TMP"
  git clone --filter=blob:none --no-checkout "$REMOTE" "$TMP"
  git -C "$TMP" fetch --depth=1 origin "$PIN"
  git -C "$TMP" checkout --detach "$PIN"
  rm -rf "$WG"
  mv "$TMP" "$WG"
else
  git -C "$WG" remote set-url origin "$REMOTE"
  git -C "$WG" fetch --depth=1 origin "$PIN"
  git -C "$WG" checkout --detach "$PIN"
  git -C "$WG" reset --hard "$PIN"
  git -C "$WG" clean -fdx
fi
ACTUAL="$(git -C "$WG" rev-parse HEAD)"
[ "$ACTUAL" = "$PIN" ] || { echo "AmneziaWG WireGuardKit checkout mismatch: expected $PIN, got $ACTUAL" >&2; exit 1; }
MANIFEST="$WG/Package.swift"
HEADER="$WG/Sources/WireGuardKitC/WireGuardKitC.h"
INTERFACE="$WG/Sources/WireGuardKit/InterfaceConfiguration.swift"
GOMOD="$WG/Sources/WireGuardKitGo/go.mod"
[ -f "$MANIFEST" ] && [ -f "$HEADER" ] && [ -f "$INTERFACE" ] && [ -f "$GOMOD" ] || { echo "Pinned Apple AmneziaWG sources are incomplete" >&2; exit 1; }
[ "$(sed -n '1p' "$MANIFEST")" = '// swift-tools-version:5.5' ] || { echo "Unexpected pinned AmneziaWG WireGuardKit manifest header" >&2; exit 1; }
grep -Fq '#include <sys/types.h>' "$HEADER" || { echo "Pinned WireGuardKitC sys/types.h contract missing" >&2; exit 1; }
grep -Fq 'public var junkPacketCount: UInt16?' "$INTERFACE" || { echo "Pinned Apple engine lacks AmneziaWG Jc support" >&2; exit 1; }
grep -Fq 'public var initPacketMagicHeader: String?' "$INTERFACE" || { echo "Pinned Apple engine lacks AmneziaWG H1 support" >&2; exit 1; }
grep -Fq 'github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260814' "$GOMOD" || { echo "Pinned AmneziaWG Go backend changed" >&2; exit 1; }
STATUS="$(git -C "$WG" status --porcelain)"
[ -z "$STATUS" ] || { echo "Pinned AmneziaWG WireGuardKit checkout is unexpectedly modified:" >&2; printf '%s\n' "$STATUS" >&2; exit 1; }
printf '%s\n' "$PIN" > "$DEPS/wireguard-apple.pin"
echo "Prepared clean pinned Apple WireGuardKit/AmneziaWG engine $PIN."
