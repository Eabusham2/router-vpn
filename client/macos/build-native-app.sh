#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SRC="$ROOT/client/macos/RouterVPNMacProduct.swift"
UNIFIED_SRC="$ROOT/client/macos/RouterVPNMacUnifiedShell.swift"
TELEMETRY_SRC="$ROOT/client/macos/RouterVPNMacTelemetry.swift"
GLOBE_SRC="$ROOT/client/macos/RouterVPNMacGlobeChrome.swift"
ONBOARDING_SRC="$ROOT/client/macos/RouterVPNProductOnboarding.swift"
HOME_SRC="$ROOT/client/macos/RouterVPNHomeSummary.swift"
SETTINGS_SRC="$ROOT/client/macos/RouterVPNProfileSettings.swift"
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
# Swift permits top-level executable statements across a multi-file target only
# when the executable translation unit is named main.swift.
ADAPTIVE_SRC="$BUILD_WORK/main.swift"

python3 - "$SRC" "$ADAPTIVE_SRC" <<'PY'
from pathlib import Path
import sys
src, out = map(Path, sys.argv[1:3])
text = src.read_text(encoding="utf-8")
changes = (
    ('NSRect(x: 0, y: 0, width: 1180, height: 780)', 'NSRect(x: 0, y: 0, width: 1050, height: 720)'),
    ('window.minSize = NSSize(width: 980, height: 650)', 'window.minSize = NSSize(width: 720, height: 520)'),
    ('tabs.view.heightAnchor.constraint(greaterThanOrEqualToConstant: 540)', 'tabs.view.heightAnchor.constraint(greaterThanOrEqualToConstant: 360)'),
    ('split.setPosition(650, ofDividerAt: 0)', 'split.setPosition(430, ofDividerAt: 0)'),
    (
        'super.init(window: window); buildUI(); refreshAll(); timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refreshLive() }',
        'super.init(window: window); buildUnifiedUI(); installUnifiedTelemetryUI(); installUnifiedMapChrome(); refreshAll(); refreshUnifiedModeMenu(); refreshUnifiedChrome(); refreshUnifiedTelemetry(); timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refreshLive(); self?.refreshUnifiedChrome(); self?.refreshUnifiedTelemetry() }',
    ),
    (
        'let r = NSStackView(); r.orientation = .horizontal; r.spacing = 8; r.addArrangedSubview(button("AUTO Connect", #selector(autoConnect))); r.addArrangedSubview(button("Connect Selected", #selector(connectSelected))); r.addArrangedSubview(button("Disconnect", #selector(disconnect))); r.addArrangedSubview(button("Refresh", #selector(refreshAction))); s.addArrangedSubview(r)',
        'let strategyRow = NSStackView(); strategyRow.orientation = .horizontal; strategyRow.spacing = 8; strategyRow.addArrangedSubview(button("AUTO", #selector(autoConnect))); strategyRow.addArrangedSubview(button("SMART AUTO", #selector(smartAutoConnect))); strategyRow.addArrangedSubview(button("CUSTOM", #selector(customConnect))); strategyRow.addArrangedSubview(button("Connect Selected", #selector(connectSelected))); s.addArrangedSubview(strategyRow); let actionRow = NSStackView(); actionRow.orientation = .horizontal; actionRow.spacing = 8; actionRow.addArrangedSubview(button("Disconnect", #selector(disconnect))); actionRow.addArrangedSubview(button("Prove actual exit", #selector(proveActualHomeExit))); actionRow.addArrangedSubview(button("Emergency Disconnect", #selector(emergencyDisconnectHome))); actionRow.addArrangedSubview(button("Refresh", #selector(refreshAction))); s.addArrangedSubview(actionRow)',
    ),
    (
        '@objc func autoConnect() { asyncAction { String(data: try self.api.request("/api/auto", method: "POST", body: [:], timeout: 150), encoding: .utf8) ?? "AUTO connected" } }',
        '''@objc func autoConnect() { asyncAction { String(data: try self.api.request("/api/strategy/auto", method: "POST", body: [:], timeout: 180), encoding: .utf8) ?? "AUTO connected" } }
    @objc func smartAutoConnect() { asyncAction { String(data: try self.api.request("/api/strategy/smart-auto", method: "POST", body: [:], timeout: 240), encoding: .utf8) ?? "SMART AUTO connected" } }
    @objc func customConnect() { openUnifiedCustomBuilder() }''',
    ),
    (
        'func refreshLive() { refreshStatus(); refreshSessionEvents() }',
        'func refreshLive() { refreshStatus(); refreshHomeSummary(); refreshSessionEvents(); refreshUnifiedChrome(); refreshUnifiedTelemetry() }',
    ),
    (
        'let row = NSStackView(); row.orientation = .horizontal; row.addArrangedSubview(button("Connect real multihop", #selector(connectMultihop))); row.addArrangedSubview(button("Refresh multihop readiness", #selector(refreshAdvancedAction))); row.addArrangedSubview(button("Retest MTU", #selector(retestMTU))); row.addArrangedSubview(button("Emergency stop", #selector(emergencyStop))); s.addArrangedSubview(row);',
        'let row = NSStackView(); row.orientation = .horizontal; row.addArrangedSubview(button("Edit profile settings", #selector(editProfileSettings))); row.addArrangedSubview(button("Connect real multihop", #selector(connectMultihop))); row.addArrangedSubview(button("Refresh multihop readiness", #selector(refreshAdvancedAction))); row.addArrangedSubview(button("Retest MTU", #selector(retestMTU))); row.addArrangedSubview(button("Emergency stop", #selector(emergencyStop))); s.addArrangedSubview(row);',
    ),
    (
        'let row = NSStackView(); row.orientation = .horizontal; row.addArrangedSubview(button("Pair/add node", #selector(pairNode)));',
        'let row = NSStackView(); row.orientation = .horizontal; row.addArrangedSubview(button("Run onboarding", #selector(runProductOnboarding))); row.addArrangedSubview(button("Pair/add node", #selector(pairNode)));',
    ),
    (
        'let w = ProductWindowController(api: api); wc = w; w.showWindow(nil); w.window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)',
        'let w = ProductWindowController(api: api); wc = w; w.showWindow(nil); w.window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true); RouterVPNProductOnboarding.shared.presentIfNeeded(parent: w.window)',
    ),
)
for old, new in changes:
    if text.count(old) != 1:
        raise SystemExit(f"macOS adaptive/unified strategy/settings/onboarding contract drifted before: {old}")
    text = text.replace(old, new, 1)
for marker in (
    'window.minSize = NSSize(width: 720, height: 520)',
    'buildUnifiedUI(); installUnifiedTelemetryUI(); installUnifiedMapChrome(); refreshAll(); refreshUnifiedModeMenu(); refreshUnifiedChrome(); refreshUnifiedTelemetry()',
    '/api/strategy/auto', '/api/strategy/smart-auto',
    'customConnect() { openUnifiedCustomBuilder() }',
    'refreshHomeSummary()',
    'button("Edit profile settings", #selector(editProfileSettings))',
    'button("Run onboarding", #selector(runProductOnboarding))',
    'RouterVPNProductOnboarding.shared.presentIfNeeded(parent: w.window)',
):
    if marker not in text:
        raise SystemExit(f"macOS shipping marker missing: {marker}")
out.write_text(text, encoding="utf-8")
PY

xcrun clang -fobjc-arc -fblocks -fmodules -isysroot "$SDK" -mmacosx-version-min=13.0 -arch "$CLANG_ARCH" -c "$MENU_SRC" -o "$MENU_OBJ"

xcrun swiftc -O -sdk "$SDK" -target "$TARGET" -framework AppKit -framework Foundation -framework MapKit \
  "$ADAPTIVE_SRC" "$UNIFIED_SRC" "$TELEMETRY_SRC" "$GLOBE_SRC" "$ONBOARDING_SRC" "$HOME_SRC" "$SETTINGS_SRC" "$MENU_OBJ" -o "$BIN"
chmod 755 "$BIN"

ICON_WORK="$BUILD_WORK/icon"; mkdir -p "$ICON_WORK"
python3 "$ROOT/deploy/materialize-desktop-icons.py" --png "$ICON_WORK/router-vpn-1024.png" --ico "$ICON_WORK/router-vpn.ico"
ICONSET="$ICON_WORK/RouterVPN.iconset"; mkdir -p "$ICONSET"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$ICON_WORK/router-vpn-1024.png" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
  retina=$((size * 2)); sips -z "$retina" "$retina" "$ICON_WORK/router-vpn-1024.png" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/RouterVPN.icns"
[[ -s "$APP/Contents/Resources/RouterVPN.icns" ]]

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string><key>CFBundleExecutable</key><string>RouterVPN</string>
  <key>CFBundleIdentifier</key><string>com.eabusham.routervpn.macos</string><key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>Router VPN</string><key>CFBundleDisplayName</key><string>Router VPN</string>
  <key>CFBundlePackageType</key><string>APPL</string><key>CFBundleIconFile</key><string>RouterVPN</string>
  <key>CFBundleShortVersionString</key><string>0.9.0</string><key>CFBundleVersion</key><string>14</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string><key>NSHighResolutionCapable</key><true/><key>NSPrincipalClass</key><string>NSApplication</string>
</dict></plist>
PLIST
plutil -lint "$APP/Contents/Info.plist" >/dev/null
[[ "$(plutil -extract CFBundleIconFile raw -o - "$APP/Contents/Info.plist")" == "RouterVPN" ]]
file "$BIN"
case "$ARCH" in amd64) file "$BIN" | grep -Eq 'x86_64|Mach-O 64-bit executable x86_64';; arm64) file "$BIN" | grep -Eq 'arm64|Mach-O 64-bit executable arm64';; esac

! grep -Eq 'import[[:space:]]+WebKit|WKWebView|SFSafariViewController' "$SRC" "$UNIFIED_SRC" "$TELEMETRY_SRC" "$GLOBE_SRC" "$ONBOARDING_SRC" "$HOME_SRC" "$SETTINGS_SRC"
for marker in 'NSWindow(' 'import MapKit' 'MKMapView' 'http://127.0.0.1:8788' '/api/connect-logical' '/api/session/events' '/api/multihop/status' '/api/multihop/connect' '/api/external-profile/import' '/api/external-profile/connect' 'entry_id' 'externalEntryPopup' '/api/mtu/retest' 'Retest MTU' 'effective_mtu_mbps' '/api/emergency-stop'; do grep -Fq "$marker" "$SRC"; done
for marker in 'buildUnifiedUI' 'unified-sheet' 'unified-connect' 'SMART AUTO — recommended' 'AUTO — first proven path' 'New CUSTOM preset…' 'CUSTOM preset builder' 'Kill switch' 'Multihop' 'Open settings' 'Mode' 'DNS' 'systemBlue' 'systemOrange' 'systemPink' 'real coordinates'; do grep -Fq "$marker" "$UNIFIED_SRC"; done
for marker in 'installUnifiedTelemetryUI' 'unified-fastest-node' 'unified-live-latency' 'unified-multihop-latency' '/api/profile/fastest' '/api/connection/live-latency' '/api/multihop/live-latency' '/api/forwarding/master' 'Forward ON' 'Forward OFF' 'toggleUnifiedForwardingMaster' 'Performance' 'Throughput + Auto MTU'; do grep -Fq "$marker" "$TELEMETRY_SRC"; done
for marker in 'installUnifiedMapChrome' 'ROUTER VPN • LIVE ROUTE' 'Only linked real coordinates' 'no IP geolocation or fabricated device pin' 'map.mapType = .mutedStandard' 'Timer.scheduledTimer(withTimeInterval: 0.05' '/api/multihop/status' '/api/multihop/live-latency' 'PATH %.1f ms'; do grep -Fq "$marker" "$GLOBE_SRC"; done
for marker in 'buildUnifiedUI(); installUnifiedTelemetryUI(); installUnifiedMapChrome(); refreshAll(); refreshUnifiedModeMenu(); refreshUnifiedChrome(); refreshUnifiedTelemetry()' '/api/strategy/auto' '/api/strategy/smart-auto' 'openUnifiedCustomBuilder()' 'refreshHomeSummary()' 'button("Edit profile settings", #selector(editProfileSettings))' 'button("Run onboarding", #selector(runProductOnboarding))' 'RouterVPNProductOnboarding.shared.presentIfNeeded(parent: w.window)'; do grep -Fq "$marker" "$ADAPTIVE_SRC"; done
for marker in 'RouterVPNProductOnboardingDoneV2' 'Add or link a node' 'router-vpn-bundle.json' 'AUTO' 'WireGuard' 'AmneziaWG' 'DNS' 'LAN Off' 'MTU/Jumbo' 'kill-switch' 'Multihop' 'forwarding' 'permissions' 'Disconnect' 'private identity/path proof' 'Public exit' 'Diagnostics' 'Emergency stop' 'Setup Center Full Guide' 'Run onboarding'; do grep -Fq "$marker" "$ONBOARDING_SRC"; done
for marker in '/api/home-summary' '/api/home-summary/prove-exit' 'actualExitStatus == "proved"' 'Node latency' 'LAN access' 'Kill switch' 'Effective MTU' 'Warnings'; do grep -Fq "$marker" "$HOME_SRC"; done
for marker in '/api/profile/settings' 'Allow home LAN access' 'Always / strict' 'AmneziaWG' 'Auto measured' 'DAITA-like' 'Jumbo TUN' 'SOCKS5' 'startup' 'auto-connect'; do grep -Fiq "$marker" "$SETTINGS_SRC"; done
grep -Fq 'NSStatusBar' "$MENU_SRC"; grep -Fq 'Open Router VPN' "$MENU_SRC"; grep -Fq 'Emergency Stop' "$MENU_SRC"; grep -Fq 'Quit Router VPN' "$MENU_SRC"
strings "$BIN" | grep -Fq 'RouterVPNMenuBarBootstrap'; ! otool -L "$BIN" | grep -q '/WebKit.framework/'

if [[ "$(uname -m)" == arm64 && "$ARCH" == arm64 ]] || [[ "$(uname -m)" == x86_64 && "$ARCH" == amd64 ]]; then "$BIN" --self-test; fi

echo "Built native RouterVPN.app with map-first unified shell, animated VPN route chrome, fastest-node connect, live path/multihop telemetry, real forwarding master, truthful SMART/AUTO/CUSTOM, editable profile settings, menu bar and persistent onboarding for $ARCH at $APP"
