#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SRC="$ROOT/client/macos/RouterVPNMacProduct.swift"
MENU_SRC="$ROOT/client/macos/RouterVPNMenuBar.m"
OUT=${1:?usage: build-native-app.sh OUT_DIR [amd64|arm64]}
ARCH=${2:-arm64}
case "$ARCH" in
  amd64) TARGET=x86_64-apple-macosx13.0; CLANG_ARCH=x86_64 ;;
  arm64) TARGET=arm64-apple-macosx13.0; CLANG_ARCH=arm64 ;;
  *) echo "Unsupported macOS app architecture: $ARCH" >&2; exit 2 ;;
esac

SDK=$(xcrun --sdk macosx --show-sdk-path)
APP="$OUT/RouterVPN.app"
BIN="$APP/Contents/MacOS/RouterVPN"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$OUT"
BUILD_WORK=$(mktemp -d "${TMPDIR:-/tmp}/router-vpn-macos-build.XXXXXX")
trap 'rm -rf "$BUILD_WORK"' EXIT
MENU_OBJ="$BUILD_WORK/RouterVPNMenuBar.o"

# Native menu-bar integration is compiled into the same AppKit executable. It
# exposes Open, Emergency Stop and Quit without a browser or separate daemon.
xcrun clang \
  -fobjc-arc \
  -fblocks \
  -fmodules \
  -isysroot "$SDK" \
  -mmacosx-version-min=13.0 \
  -arch "$CLANG_ARCH" \
  -c "$MENU_SRC" \
  -o "$MENU_OBJ"

xcrun swiftc \
  -O \
  -sdk "$SDK" \
  -target "$TARGET" \
  -framework AppKit \
  -framework Foundation \
  -framework MapKit \
  "$SRC" \
  "$MENU_OBJ" \
  -o "$BIN"
chmod 755 "$BIN"

# Build the normal macOS application icon from the same deterministic Router VPN
# icon source used by Windows/Linux. No opaque binary source asset is committed.
ICON_WORK="$BUILD_WORK/icon"
mkdir -p "$ICON_WORK"
python3 "$ROOT/deploy/materialize-desktop-icons.py" --png "$ICON_WORK/router-vpn-1024.png" --ico "$ICON_WORK/router-vpn.ico"
ICONSET="$ICON_WORK/RouterVPN.iconset"
mkdir -p "$ICONSET"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$ICON_WORK/router-vpn-1024.png" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
  retina=$((size * 2))
  sips -z "$retina" "$retina" "$ICON_WORK/router-vpn-1024.png" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/RouterVPN.icns"
[[ -s "$APP/Contents/Resources/RouterVPN.icns" ]]

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>RouterVPN</string>
  <key>CFBundleIdentifier</key><string>com.eabusham.routervpn.macos</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>Router VPN</string>
  <key>CFBundleDisplayName</key><string>Router VPN</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleIconFile</key><string>RouterVPN</string>
  <key>CFBundleShortVersionString</key><string>0.9.0</string>
  <key>CFBundleVersion</key><string>9</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
</dict></plist>
PLIST

plutil -lint "$APP/Contents/Info.plist" >/dev/null
[[ "$(plutil -extract CFBundleIconFile raw -o - "$APP/Contents/Info.plist")" == "RouterVPN" ]]
file "$BIN"
case "$ARCH" in
  amd64) file "$BIN" | grep -Eq 'x86_64|Mach-O 64-bit executable x86_64' ;;
  arm64) file "$BIN" | grep -Eq 'arm64|Mach-O 64-bit executable arm64' ;;
esac

# A Router VPN desktop app must be native UI, not a hidden website/WebView wrapper.
! grep -Eq 'import[[:space:]]+WebKit|WKWebView|SFSafariViewController' "$SRC"
grep -Fq 'NSWindow(' "$SRC"
grep -Fq 'NSTabViewController' "$SRC"
grep -Fq 'import MapKit' "$SRC"
grep -Fq 'MKMapView' "$SRC"
grep -Fq 'http://127.0.0.1:8788' "$SRC"
grep -Fq '/api/connect-logical' "$SRC"
grep -Fq '/api/session/events' "$SRC"
grep -Fq '/api/multihop/status' "$SRC"
grep -Fq '/api/multihop/connect' "$SRC"
grep -Fq '/api/external-profile/import' "$SRC"
grep -Fq '/api/external-profile/connect' "$SRC"
grep -Fq 'entry_id' "$SRC"
grep -Fq 'externalEntryPopup' "$SRC"
grep -Fq '/api/mtu/retest' "$SRC"
grep -Fq 'Retest MTU' "$SRC"
grep -Fq 'effective_mtu_mbps' "$SRC"
grep -Fq '/api/emergency-stop' "$SRC"
grep -Fq 'NSStatusBar' "$MENU_SRC"
grep -Fq 'Open Router VPN' "$MENU_SRC"
grep -Fq 'Emergency Stop' "$MENU_SRC"
grep -Fq 'Quit Router VPN' "$MENU_SRC"
strings "$BIN" | grep -Fq 'RouterVPNMenuBarBootstrap'
! otool -L "$BIN" | grep -q '/WebKit.framework/'

if [[ "$(uname -m)" == arm64 && "$ARCH" == arm64 ]] || [[ "$(uname -m)" == x86_64 && "$ARCH" == amd64 ]]; then
  "$BIN" --self-test
fi

echo "Built native RouterVPN.app with menu-bar integration for $ARCH at $APP"
