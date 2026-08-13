#!/bin/sh
set -eu

PIN="2fec12a6e1f6e3460b6ee483aa00ad29cddadab1"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
DEPS="$ROOT/.deps"
WG="$DEPS/wireguard-apple"
REMOTE="https://github.com/WireGuard/wireguard-apple"

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
[ "$ACTUAL" = "$PIN" ] || {
  echo "WireGuardKit checkout mismatch: expected $PIN, got $ACTUAL" >&2
  exit 1
}

MANIFEST="$WG/Package.swift"
HEADER="$WG/Sources/WireGuardKitC/WireGuardKitC.h"
[ -f "$MANIFEST" ] || { echo "WireGuardKit Package.swift missing" >&2; exit 1; }
[ -f "$HEADER" ] || { echo "WireGuardKitC.h missing" >&2; exit 1; }
FIRST="$(sed -n '1p' "$MANIFEST")"
[ "$FIRST" = '// swift-tools-version:5.3' ] || {
  echo "Unexpected pinned WireGuardKit manifest header: $FIRST" >&2
  exit 1
}
grep -Fq '#include "key.h"' "$HEADER" || { echo "Unexpected pinned WireGuardKitC header" >&2; exit 1; }
if grep -Fq '#include <sys/types.h>' "$HEADER"; then
  echo "Pinned WireGuardKitC header unexpectedly already contains sys/types.h" >&2
  exit 1
fi

# Compatibility patches are deliberately tiny and applied only after exact-SHA verification:
# 1) upstream declares Swift tools 5.3 while using PackageDescription 5.5 platform constants;
# 2) Xcode 16.4 modular C import requires BSD u_int*/u_char declarations before use.
TMP_MANIFEST="$MANIFEST.routervpn.tmp"
{
  printf '%s\n' '// swift-tools-version:5.5'
  sed '1d' "$MANIFEST"
} > "$TMP_MANIFEST"
mv "$TMP_MANIFEST" "$MANIFEST"

TMP_HEADER="$HEADER.routervpn.tmp"
awk '
  !done && $0 == "#include \"key.h\"" {
    print "#include <sys/types.h>"
    print ""
    done=1
  }
  { print }
  END { if (!done) exit 7 }
' "$HEADER" > "$TMP_HEADER"
mv "$TMP_HEADER" "$HEADER"

[ "$(sed -n '1p' "$MANIFEST")" = '// swift-tools-version:5.5' ] || exit 1
grep -Fq '#include <sys/types.h>' "$HEADER" || exit 1
[ "$(git -C "$WG" rev-parse HEAD)" = "$PIN" ] || exit 1

# Fail if anything besides the two audited compatibility edits changed.
STATUS="$(git -C "$WG" status --porcelain)"
EXPECTED=" M Package.swift
 M Sources/WireGuardKitC/WireGuardKitC.h"
[ "$STATUS" = "$EXPECTED" ] || {
  echo "Unexpected WireGuardKit working tree changes:" >&2
  printf '%s\n' "$STATUS" >&2
  exit 1
}

printf '%s\n' "$PIN" > "$DEPS/wireguard-apple.pin"
echo "Prepared WireGuardKit $PIN with audited Xcode compatibility patches."
