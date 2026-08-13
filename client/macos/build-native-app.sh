#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SRC="$ROOT/client/macos/RouterVPNMacProduct.swift"
OUT=${1:?usage: build-native-app.sh OUT_DIR [amd64|arm64]}
ARCH=${2:-arm64}
case "$ARCH" in
  amd64) TARGET=x86_64-apple-macosx13.0 ;;
  arm64) TARGET=arm64-apple-macosx13.0 ;;
  *) echo "Unsupported macOS app architecture: $ARCH" >&2; exit 2 ;;
esac

SDK=$(xcrun --sdk macosx --show-sdk-path)
APP="$OUT/RouterVPN.app"
BIN="$APP/Contents/MacOS/RouterVPN"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

xcrun swiftc \
  -O \
  -sdk "$SDK" \
  -target "$TARGET" \
  -framework AppKit \
  -framework Foundation \
  -framework MapKit \
  "$SRC" \
  -o "$BIN"
chmod 755 "$BIN"

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
  <key>CFBundleShortVersionString</key><string>0.9.0</string>
  <key>CFBundleVersion</key><string>9</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
</dict></plist>
PLIST

plutil -lint "$APP/Contents/Info.plist" >/dev/null
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
grep -Fq '/api/emergency-stop' "$SRC"
! otool -L "$BIN" | grep -q '/WebKit.framework/'

if [[ "$(uname -m)" == arm64 && "$ARCH" == arm64 ]] || [[ "$(uname -m)" == x86_64 && "$ARCH" == amd64 ]]; then
  "$BIN" --self-test
fi

echo "Built native RouterVPN.app for $ARCH at $APP"
