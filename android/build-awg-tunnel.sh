#!/usr/bin/env bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERSION=2.0.0
COMMIT=4116c836241f737badb99dcd4e990600d46e4c65
VENDOR="$ROOT/.vendor/amneziawg-android"
LIBDIR="$ROOT/app/libs"
AAR="$LIBDIR/amneziawg-tunnel.aar"
STAMP="$LIBDIR/amneziawg-tunnel.commit"
LICENSE_OUT="$LIBDIR/amneziawg-tunnel-LICENSE.txt"

verify_aar(){
  unzip -tq "$AAR" >/dev/null
  unzip -l "$AAR" | grep -q 'jni/.*/libawg-go.so' || { echo 'AmneziaWG AAR is missing namespaced libawg-go.so' >&2; return 1; }
  if unzip -l "$AAR" | grep -Eq 'jni/.*/libwg(-go|-quick)?\.so'; then
    echo 'AmneziaWG AAR still contains a libwg*.so name that can collide with the official WireGuard AAR' >&2
    return 1
  fi
}
if [[ -s "$AAR" && -f "$STAMP" && $(tr -d '\r\n' <"$STAMP") == "$COMMIT" ]]; then
  verify_aar
  printf 'Pinned namespaced AmneziaWG Android tunnel already built: %s (%s)\n' "$VERSION" "$COMMIT"
  exit 0
fi

rm -rf "$VENDOR"
mkdir -p "$(dirname "$VENDOR")" "$LIBDIR"
git clone --filter=blob:none --no-checkout https://github.com/amnezia-vpn/amneziawg-android "$VENDOR"
git -C "$VENDOR" fetch --depth 1 origin "$COMMIT"
git -C "$VENDOR" checkout --detach FETCH_HEAD
ACTUAL=$(git -C "$VENDOR" rev-parse HEAD)
[[ "$ACTUAL" == "$COMMIT" ]] || { echo "AmneziaWG Android source commit mismatch: $ACTUAL" >&2; exit 1; }
# Upstream records exact amneziawg-tools and elf-cleaner gitlinks. Follow those
# commits, never a moving submodule branch.
git -C "$VENDOR" submodule update --init --recursive

# WireGuard Android and AmneziaWG Android both use libwg*.so names upstream.
# Router VPN embeds both engines in one APK, so choosing one duplicate with
# Gradle pickFirst would silently make one backend execute the wrong binary.
# Namespace only the pinned AWG build before compiling its AAR.
python3 - "$VENDOR" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
cmake=root/'tunnel/tools/CMakeLists.txt'
make=root/'tunnel/tools/libwg-go/Makefile'
backend=root/'tunnel/src/main/java/org/amnezia/awg/backend/GoBackend.java'
for path in (cmake,make,backend):
    text=path.read_text()
    if path == cmake:
        text=text.replace('libwg-quick.so','libawg-quick.so').replace('libwg-go.so','libawg-go.so').replace('libwg.so','libawg.so')
    elif path == make:
        text=text.replace('libwg-go.so','libawg-go.so')
    else:
        old='SharedLibraryLoader.loadSharedLibrary(context, "wg-go")'
        if old not in text: raise SystemExit('AWG GoBackend loader marker changed upstream')
        text=text.replace(old,'SharedLibraryLoader.loadSharedLibrary(context, "awg-go")')
    path.write_text(text)
PY

grep -q 'libawg-go.so' "$VENDOR/tunnel/tools/CMakeLists.txt"
grep -q 'soname=libawg-go.so' "$VENDOR/tunnel/tools/libwg-go/Makefile"
grep -q 'loadSharedLibrary(context, "awg-go")' "$VENDOR/tunnel/src/main/java/org/amnezia/awg/backend/GoBackend.java"
(
  cd "$VENDOR"
  ./gradlew --no-daemon --stacktrace :tunnel:assembleRelease
)
SOURCE_AAR="$VENDOR/tunnel/build/outputs/aar/tunnel-release.aar"
[[ -s "$SOURCE_AAR" ]] || { echo 'Pinned AmneziaWG tunnel build did not produce tunnel-release.aar' >&2; exit 1; }
install -m 0644 "$SOURCE_AAR" "$AAR"
install -m 0644 "$VENDOR/LICENSE" "$LICENSE_OUT"
printf '%s\n' "$COMMIT" >"$STAMP"
verify_aar
printf 'Built pinned namespaced AmneziaWG Android tunnel %s at %s\n' "$VERSION" "$COMMIT"
