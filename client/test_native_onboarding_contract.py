#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(name: str, source: str, markers: tuple[str, ...]) -> None:
    lower = source.lower()
    for marker in markers:
        assert marker.lower() in lower, f"{name} shipping onboarding missing {marker!r}"


def require_any(name: str, source: str, label: str, variants: tuple[str, ...]) -> None:
    lower = source.lower()
    assert any(value.lower() in lower for value in variants), f"{name} shipping onboarding missing semantic {label!r}: {variants!r}"


def block(source: str, start: str, end: str) -> str:
    a = source.find(start)
    b = source.find(end, a + len(start)) if a >= 0 else -1
    assert a >= 0 and b > a, f"cannot isolate source block {start!r} -> {end!r}"
    return source[a:b]


# Watch the sources/package seams that the current product actually ships.
# Unified map-first shells may own drill-in controls while onboarding remains a
# separate persisted lifecycle. Legacy prototype files are never used as proof.
win = read("client/RouterVPN-Windows-App.ps1")
win_unified = read("client/RouterVPN-Windows-UnifiedShell.ps1")
win_telemetry = read("client/RouterVPN-Windows-Telemetry.ps1")
win_product = read("client/RouterVPN-Windows-Product-v2.ps1")
mac_onboarding = read("client/macos/RouterVPNProductOnboarding.swift")
mac_build = read("client/macos/build-native-app.sh")
mac_telemetry = read("client/macos/RouterVPNMacTelemetry.swift")
mac_globe = read("client/macos/RouterVPNMacGlobeChrome.swift")
linux_onboarding = read("client/linux/routervpn-product-onboarding-v6.inc")
linux_build = read("client/linux/build-native-app.sh")
linux_telemetry = read("client/linux/routervpn-telemetry-v9.inc")
linux_globe = read("client/linux/routervpn-globe-v10.inc")
android_onboarding = read("android/app/src/main/java/com/eabusham/routervpn/AndroidProductOnboarding.java")
android_product = read("android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java")
ios_onboarding = read("ios/RouterVPN/App/ProductOnboardingView.swift")
ios_root = read("ios/RouterVPN/App/ProductRootView.swift")
ios_unified = read("ios/RouterVPN/App/IOSUnifiedProductView.swift")
ios_location = read("ios/RouterVPN/App/IOSUserLocationOverlay.swift")
ios_project = read("ios/RouterVPN/project.yml")

# Windows v3 keeps the full wizard, but latest product policy starts the shipping
# map immediately. Normal startup reaches the onboarding entry point only as a
# deliberate no-op; Help force-opens the real persisted wizard on demand.
require("Windows onboarding v3", win, (
    "windows-onboarding-v3.json", ".routervpn-state", "Get-OnboardingState",
    "Save-OnboardingState", "Show-RouterVPNProductOnboarding",
    "Close and resume later", "app onboarding is separate from Setup Center",
    "SMART AUTO is the default mode", "AUTO", "WireGuard", "AmneziaWG",
    "DNS", "LAN", "MTU", "Jumbo", "Multihop", "forwarding", "permissions",
    "Disconnect", "selected-node private path proof", "public exit",
    "Setup Center Full Guide", "Emergency stop",
    "normal startup must never open a modal", "Show-RouterVPNProductOnboarding -Force",
))
require_any("Windows onboarding v3", win, "kill switch", ("kill switch", "kill-switch"))
require("Windows unified shipping shell", win_unified + win_product + win_telemetry, (
    "UnifiedShell", "UnifiedMapCanvas", "UnifiedConnectButton", "UnifiedKillSwitch",
    "SMART AUTO", "CUSTOM", "/api/strategy/auto", "/api/strategy/smart-auto",
    "/api/strategy/custom", "/api/connect-logical", "/api/multihop/connect",
    "/api/profile/select", "/api/profile/latency", "/api/dns/retest",
    "/api/emergency-stop",
))
require("Windows globe + forwarding", win_telemetry, (
    "ROUTER VPN GLOBE", "GlobeXY", "SelectUnifiedMapNode", "TickUnifiedMapAnimation",
    "UnifiedMapAnimationTimer", "entry", "exit", "external", "selected",
    "PATH {0:N1} ms", "latency_trimmed_mean_ms", "latency_median_ms",
    "Only real stored coordinates", "/api/forwarding/master", "Forward ON", "Forward OFF",
    "ToggleUnifiedForwardingMaster", "Real path speed", "Routed hop speeds",
))
assert "OpenUnifiedDetail 5" not in win_telemetry, "Windows Forward side control regressed to a detail-page shortcut"
assert "device location is never fabricated" in win_telemetry
assert "if($SelfTest)" in win
assert "if(-not$Force){return}" in win, "Windows normal launch can still enter blocking onboarding"
assert re.search(r"Show-RouterVPNProductOnboarding\s+-Force", win), "Windows Help does not force-open the real full onboarding wizard"
assert re.search(r"else\s*\{\s*Show-RouterVPNProductOnboarding\s*;\s*&\s*\$ProductScript\b", win), "Windows map-first product launch seam disappeared"

# macOS keeps the full modal wizard only for explicit Help/rerun. The automatic
# first-launch entry point records a map-first hint state and must never call
# runModal before the daily AppKit map is usable.
shared_topics = (
    "pairing", "router-vpn-bundle.json", "AUTO", "WireGuard", "DNS",
    "LAN Off", "MTU", "Jumbo", "Multihop", "forwarding",
    "permissions", "Disconnect", "private identity/path proof", "Public",
    "Diagnostics", "Setup Center Full Guide",
)
require("macOS", mac_onboarding, shared_topics + (
    "AmneziaWG", "Emergency stop", "RouterVPNProductOnboardingDoneV2",
    "RouterVPNProductOnboardingStepV2", "Close & resume later",
    "presentIfNeeded", "runProductOnboarding", "mapFirstHintKey",
    "first launch never blocks", "Help → Run onboarding",
    "app onboarding is separate from Setup Center onboarding",
))
require_any("macOS", mac_onboarding, "kill switch", ("kill switch", "kill-switch"))
mac_auto = block(mac_onboarding, "func presentIfNeeded(parent: NSWindow?)", "func present(force: Bool")
assert "runModal" not in mac_auto and "NSAlert()" not in mac_auto, "macOS automatic first launch still opens modal onboarding over the map"
require("macOS build", mac_build, (
    "RouterVPNProductOnboarding.swift", "Run onboarding",
    "RouterVPNProductOnboarding.shared.presentIfNeeded(parent: w.window)",
    "RouterVPNProductOnboardingDoneV2",
))
assert '"$ONBOARDING_SRC"' in mac_build
require("macOS forwarding master", mac_telemetry, (
    "unified-forward-master", "/api/forwarding/master", "Forward ON", "Forward OFF",
    "toggleUnifiedForwardingMaster", "refreshUnifiedForwardingMaster",
    "Forwarding master did not reach the requested state", "Real server forwarding master",
))
assert 'action: #selector(openUnifiedForwarding)' not in mac_telemetry, "macOS Forward side control regressed to forwarding-page navigation"
require("macOS VPN route chrome", mac_globe, (
    "installUnifiedMapChrome", "ROUTER VPN • LIVE ROUTE", "Only linked real coordinates",
    "no IP geolocation or fabricated device pin", "map.mapType = .mutedStandard",
    "/api/multihop/status", "/api/multihop/live-latency", "PATH %.1f ms",
    "Timer.scheduledTimer(withTimeInterval: 0.05", "chrome.advance()",
))
assert "RouterVPNMacGlobeChrome.swift" in mac_build
assert '"$GLOBE_SRC"' in mac_build
assert "installUnifiedMapChrome()" in mac_build

# Linux keeps the complete native GTK assistant for explicit Help → Run Tutorial,
# but the canonical builder removes the legacy automatic call after showing the
# map-first window and fails closed if that source seam drifts.
require("Linux", linux_onboarding, shared_topics + (
    "AmneziaWG", "Emergency stop", "Run Tutorial",
    "app onboarding is separate from Setup Center onboarding",
))
require_any("Linux", linux_onboarding, "kill switch", ("kill switch", "kill-switch"))
require("Linux build", linux_build, (
    "routervpn-product-onboarding-v6.inc", "onboarding_read_step_v6",
    "onboarding_write_step_v6", "gtk_assistant_set_current_page",
    "gtk_assistant_get_current_page", "Run Tutorial",
    "Map-first startup: onboarding is explicit from Help -> Run Tutorial.",
    "Linux shipping build still auto-opens blocking onboarding over the map",
))
assert 'show_onboarding_v5(&app, FALSE);' in linux_build, "Linux builder no longer checks/removes the legacy automatic onboarding seam"
assert "text.replace(auto_onboarding" in linux_build, "Linux builder does not remove automatic modal onboarding from the shipping source"
assert 'gcc -O2 -Wall -Wextra -Werror' in linux_build
require("Linux forwarding master", linux_telemetry, (
    "/api/forwarding/master", "Forward ON", "Forward OFF", "linux_telemetry_forward_v9",
    "linux_telemetry_read_forward_v9", "linux_telemetry_set_forward_label_v9",
    "Forwarding master response did not verify the requested state",
))
assert "linux_unified_show_detail_v8(t->base,5)" not in linux_telemetry, "Linux Forward side control regressed to a detail-page shortcut"
assert "Forward shortcut" not in linux_telemetry, "Linux telemetry still describes forwarding as a shortcut"
require("Linux VPN globe", linux_globe, (
    "LinuxGlobeV10", "ROUTER VPN GLOBE", "linux_globe_draw_v10", "linux_globe_click_v10",
    "routervpn_flat_map_v9", "entry blue", "exit orange", "external pink",
    "animated packet", "PATH %.1f ms", "device location is not fabricated",
    "/api/multihop/live-latency",
))
assert "routervpn-globe-v10.inc" in linux_build
assert "linux_install_globe_v10(&app);" in linux_build
assert "#define draw_map routervpn_flat_map_v9" in linux_build

# Android ProductActivity is the actual map-first dashboard. First launch may
# show one non-blocking hint, but the full AlertDialog is opt-in from Help.
require("Android", android_onboarding, shared_topics + (
    "AmneziaWG", "Emergency stop", "VpnService", "Always-on VPN",
    "Block connections without VPN", "routervpn_product_onboarding_v2",
    "Close & resume later", "showIfNeeded", "map_first_hint_shown",
    "Toast.makeText", "app onboarding is separate from Setup Center onboarding",
))
require_any("Android", android_onboarding, "kill switch", ("kill switch", "kill-switch"))
require("Android product", android_product, (
    "AndroidProductOnboarding.showIfNeeded(this)", "Run onboarding again",
))
assert "show(activity, false)" not in android_onboarding, "Android first launch still opens a blocking onboarding AlertDialog"
assert re.search(r"AndroidProductOnboarding\.show\(this\s*,\s*true\)", android_product), "Android Help is not wired to force-rerun product onboarding"

# iOS/iPadOS now delegates the daily surface from ProductRootView into the
# unified map-first view. Automatic first launch only leaves a non-blocking
# message; Setup Guide explicitly presents RouterVPNProductOnboardingView.
require("iOS/iPadOS", ios_onboarding, (
    "pairing", "router-vpn-bundle.json", "AUTO", "WireGuard", "DNS",
    "LAN Off", "MTU/Jumbo", "Multihop", "forwarding",
    "VPN permission", "Network Extension", "Local Network permission",
    "Disconnect", "private identity/path proof", "public VPN exit",
    "Diagnostics", "Setup Center Full Guide", "unsigned IPA", "TestFlight",
    "App Store", "sideload", "provisioning", "PacketTunnel",
    "RouterVPNProductOnboardingDoneV2", "RouterVPNProductOnboardingStepV2",
    "Close & resume later", "app onboarding is separate from Setup Center onboarding",
))
require_any("iOS/iPadOS", ios_onboarding, "kill switch", ("kill switch", "kill-switch"))
require("iOS/iPadOS unified product", ios_root + ios_unified, (
    "IOSUnifiedProductView", "RouterVPNProductOnboardingView",
    "RouterVPNProductOnboardingDoneV2", "Setup Guide", "SMART AUTO",
    "CUSTOM", "Connect", "Disconnect", "DNS", "Kill switch", "Multihop",
    "Setup is ready. Open Setup guide from the expanded control sheet when needed.",
))
require("iOS opt-in real user location", ios_root + ios_location + ios_project, (
    "IOSUserLocationControl", "requestFromUserTap", "requestedByUser",
    "requestWhenInUseAuthorization", "requestLocation()", "horizontalAccuracy",
    "age: abs(location.timestamp.timeIntervalSinceNow)", "sample.age <= 30", "CLLocationCoordinate2DIsValid",
    "map.showsUserLocation = true", ".systemGreen", "no automatic request",
    "no IP geolocation", "INFOPLIST_KEY_NSLocationWhenInUseUsageDescription",
    "when you explicitly tap the location button", "never inferred from your IP address",
))
assert "IOSUnifiedProductView()" in ios_root and "IOSUserLocationControl()" in ios_unified, "iOS real-location control is not wired through the shipping unified product view"
assert "startUpdatingLocation" not in ios_location, "iOS location must remain a user-triggered one-shot rather than automatic background tracking"
assert "CLGeocoder" not in ios_location and "ipify" not in ios_location.lower(), "iOS user location must not use geocoding/IP-derived placement"

print("Shipping native app onboarding contract: PASS")
