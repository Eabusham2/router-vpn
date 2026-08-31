#!/usr/bin/env python3
"""Authoritative shipping-source audit for the unified native map-first UI.

This gate captures the user-facing Router VPN redesign across Windows, macOS,
Linux, Android, and iOS/iPadOS. It deliberately checks the real shipping
composition seams rather than accepting documentation, mockups, legacy tabs,
or a browser wrapper as product evidence.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ERRORS: list[str] = []


def read(path: str) -> str:
    p = ROOT / path
    if not p.is_file():
        ERRORS.append(f"missing shipping source: {path}")
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def combined(paths: tuple[str, ...]) -> str:
    return "\n".join(read(path) for path in paths)


def require(label: str, paths: tuple[str, ...], *markers: str) -> None:
    body = combined(paths)
    for marker in markers:
        if marker not in body:
            ERRORS.append(f"{label}: missing {marker!r}")


def require_order(label: str, paths: tuple[str, ...], *markers: str) -> None:
    body = combined(paths)
    cursor = -1
    for marker in markers:
        pos = body.find(marker, cursor + 1)
        if pos < 0:
            ERRORS.append(f"{label}: missing ordered marker {marker!r}")
            return
        if pos <= cursor:
            ERRORS.append(f"{label}: control order regressed at {marker!r}")
            return
        cursor = pos


def forbid(label: str, paths: tuple[str, ...], *markers: str) -> None:
    body = combined(paths).lower()
    for marker in markers:
        if marker.lower() in body:
            ERRORS.append(f"{label}: forbidden browser/retired surface {marker!r}")


# Shared controller and profile truth behind the native controls.
require(
    "shared map-first controller contract",
    (
        "cmd/client/telemetry.go",
        "cmd/client/telemetry_hops.go",
        "cmd/client/profile_settings.go",
        "cmd/client/connection_profiles.go",
        "cmd/client/connection_profile_setup.go",
        "cmd/client/forwarding_master.go",
        "cmd/client/mtu_retest.go",
    ),
    "/api/profile/fastest",
    "/api/connection/live-latency",
    "/api/connection/speed-test",
    "/api/multihop/live-latency",
    "/api/multihop/speed-test",
    "/api/forwarding/master",
    "/api/mtu/retest",
    "/api/connection-profile/setup/save",
    "/api/connection-profile/setup/load",
    "/api/connection-profile/setup/update",
    "/api/connection-profile/setup/delete",
)

# Windows: launcher composes the hardened WPF unified shell + telemetry into the
# real product source. Legacy tabs stay hidden behind drill-in details.
windows = (
    "client/RouterVPN-Windows-App.ps1",
    "client/RouterVPN-Windows-UnifiedShell.ps1",
    "client/RouterVPN-Windows-Telemetry.ps1",
    "client/RouterVPN-Windows-ProfileSettings.ps1",
)
require(
    "Windows native map-first UI",
    windows,
    "Add / manage nodes",
    "UnifiedMapCanvas",
    "UnifiedFastestNode",
    "UnifiedConnectButton",
    "UnifiedLiveLatency",
    "UnifiedKillSwitch",
    "UnifiedForwardButton",
    "UnifiedMultihop",
    "UnifiedSettingsButton",
    "UnifiedModeCombo",
    "UnifiedDnsCombo",
    "SMART AUTO — recommended",
    "AUTO — first proven path",
    "New CUSTOM preset",
    "Only real stored coordinates",
    "TickUnifiedMapAnimation",
    "Real path speed",
    "Routed hop speeds",
    "ProfileAdd",
    "ProfileLoad",
    "ProfileUpdate",
    "ProfileDelete",
    "Require encrypted AUTO candidates",
    "Require obfuscation for AUTO candidates",
    "IPv6 On",
    "Auto measured MTU",
    "DAITA-like traffic padding",
    "Jumbo TUN",
    "LegacyDetailTabs\" Visibility=\"Collapsed",
)
require_order(
    "Windows bottom control sheet order",
    ("client/RouterVPN-Windows-UnifiedShell.ps1",),
    'Text="Multihop"',
    'Text="Settings"',
    'Text="Mode"',
    'Text="DNS"',
)
windows_telemetry = read("client/RouterVPN-Windows-Telemetry.ps1")
try:
    windows_choices = windows_telemetry.split(
        "function RefreshUnifiedFastestChoices", 1
    )[1].split("function RefreshUnifiedForwardingMaster", 1)[0]
    windows_selector = windows_telemetry.split(
        "(Control 'UnifiedFastestNode').Add_SelectionChanged", 1
    )[1].split("(Control 'UnifiedForwardButton').Add_Click", 1)[0]
except IndexError:
    ERRORS.append("Windows node selector: shipping event/function seam is missing")
else:
    for marker in ("$Store.selected_id", "SelectedValue=$Preferred"):
        if marker not in windows_choices:
            ERRORS.append(
                f"Windows node selector: refresh must preserve selected node ({marker!r})"
            )
    if "UnifiedConnect" in windows_selector:
        ERRORS.append(
            "Windows node selector: choosing Fastest/a node must not auto-connect; Connect is a separate control"
        )
    if "SelectedValue='fastest'" in windows_selector:
        ERRORS.append(
            "Windows node selector: selection event must not reset the visible target to Fastest"
        )
    for marker in (
        "Assert-RouterVPNMutationIdle 'selecting a Router VPN node'",
        "'/api/profile/fastest'",
        "'/api/profile/select'",
        "RefreshUnifiedTelemetry",
    ):
        if marker not in windows_selector:
            ERRORS.append(f"Windows node selector: missing {marker!r}")
forbid(
    "Windows native shell",
    windows,
    "WebView2",
    "msedge.exe",
    "electron",
    "Start-Process http://127.0.0.1:8788",
)

# macOS: the AppKit/MapKit product composes unified chrome, route animation,
# telemetry, settings, and whole-connection profile CRUD at build time.
macos = (
    "client/macos/build-native-app.sh",
    "client/macos/RouterVPNMacUnifiedShell.swift",
    "client/macos/RouterVPNMacTelemetry.swift",
    "client/macos/RouterVPNMacGlobeChrome.swift",
    "client/macos/RouterVPNProfileSettings.swift",
    "client/macos/RouterVPNConnectionProfiles.swift",
)
require(
    "macOS native map-first UI",
    macos,
    "Add / manage nodes",
    "unified-fastest-node",
    "unified-connect",
    "unified-live-latency",
    "Forward",
    "Multihop",
    "Open settings",
    "Mode",
    "DNS",
    "SMART AUTO — recommended",
    "AUTO — first proven path",
    "New CUSTOM preset…",
    "real-coordinate",
    "packet",
    "Real path speed",
    "Routed hop speeds",
    "Add current",
    "Load",
    "Update",
    "Delete",
    "Require encrypted AUTO candidates",
    "Require obfuscation for AUTO candidates",
    "IPv6 On",
    "Auto MTU",
    "DAITA-like",
    "Jumbo",
)
require_order(
    "macOS bottom control sheet order",
    ("client/macos/RouterVPNMacUnifiedShell.swift",),
    'checkboxWithTitle: "Multihop"',
    'unifiedLabeledRow(title: "Settings")',
    'unifiedLabeledRow(title: "Mode")',
    'unifiedLabeledRow(title: "DNS")',
)
forbid(
    "macOS native shell",
    (
        "client/macos/RouterVPNMacUnifiedShell.swift",
        "client/macos/RouterVPNMacTelemetry.swift",
        "client/macos/RouterVPNMacGlobeChrome.swift",
        "client/macos/RouterVPNProfileSettings.swift",
        "client/macos/RouterVPNConnectionProfiles.swift",
    ),
    "import WebKit", "WKWebView", "SFSafariViewController", "Electron",
)

# Linux: the canonical GTK builder must compile the unified shell, globe,
# telemetry, profile settings, AUTO requirements, and v11 profile manager.
linux = (
    "client/linux/build-native-app.sh",
    "client/linux/routervpn-unified-shell-v8.inc",
    "client/linux/routervpn-telemetry-v9.inc",
    "client/linux/routervpn-globe-v10.inc",
    "client/linux/routervpn-profile-settings-v1.inc",
    "client/linux/routervpn-auto-requirements-v11.inc",
    "client/linux/routervpn-connection-profiles-v10.inc",
    "client/linux/routervpn-connection-profiles-v11.inc",
)
require(
    "Linux native map-first UI",
    linux,
    "Add / manage nodes",
    "Fastest",
    "Connect",
    "Disconnect",
    "Kill switch",
    "Forward",
    "Multihop",
    "Open settings",
    "Mode",
    "DNS",
    "SMART AUTO — recommended",
    "AUTO — first proven path",
    "New CUSTOM preset…",
    "real stored coordinates",
    "animated packet",
    "Real path speed",
    "Routed hop speeds",
    "Add current",
    "Load",
    "Update",
    "Delete",
    "Require encrypted AUTO candidates",
    "Require obfuscation for AUTO candidates",
    "IPv6 On",
    "Auto MTU",
    "DAITA-like",
    "Jumbo",
    'routervpn-connection-profiles-v11.inc',
    'routervpn-auto-requirements-v11.inc',
)
require_order(
    "Linux bottom control dock order",
    ("client/linux/routervpn-unified-shell-v8.inc",),
    'new_with_label("Multihop")',
    'linux_unified_row_v8("Settings"',
    'linux_unified_row_v8("Mode"',
    'linux_unified_row_v8("DNS"',
)
forbid(
    "Linux native shell",
    (
        "client/linux/routervpn-unified-shell-v8.inc",
        "client/linux/routervpn-telemetry-v9.inc",
        "client/linux/routervpn-globe-v10.inc",
        "client/linux/routervpn-profile-settings-v1.inc",
        "client/linux/routervpn-auto-requirements-v11.inc",
        "client/linux/routervpn-connection-profiles-v11.inc",
    ),
    "WebKit", "WebView", "chromium", "electron", "xdg-open",
)

# Android: ProductActivity is the actual native VpnService dashboard. Location
# is opt-in and map data must remain real, not IP-derived.
android = (
    "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
    "android/app/src/main/java/com/eabusham/routervpn/RouterVpnNodeMapView.java",
    "android/app/src/main/java/com/eabusham/routervpn/AndroidTelemetry.java",
    "android/app/src/main/java/com/eabusham/routervpn/AndroidForwardingMaster.java",
    "android/app/src/main/java/com/eabusham/routervpn/AndroidProfileSettingsDialog.java",
    "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfilesDialog.java",
)
require(
    "Android native map-first UI",
    android,
    "Add / manage nodes",
    "⚡ Fastest",
    "Connect",
    "Disconnect",
    "Kill switch",
    "Forward ON",
    "Forward OFF",
    "Multihop",
    "Settings",
    "Mode",
    "DNS",
    "SMART AUTO — recommended",
    "AUTO — first proven path",
    "New CUSTOM preset",
    "LOCATE ME",
    "Only real coordinates",
    "System.currentTimeMillis()%1800L",
    "Real current VPN path speed",
    "Routed multihop speeds",
    "Add / Load / Update / Delete",
    "Require encrypted AUTO candidates",
    "Require obfuscation for AUTO candidates",
    "IPv6 On",
    "Auto MTU",
    "DAITA-like",
    "Jumbo",
)
require_order(
    "Android control sheet order",
    ("android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",),
    'setText("Multihop")',
    'controlRow("Settings")',
    'controlRow("Mode")',
    'controlRow("DNS")',
)
forbid("Android native shell", android, "android.webkit.WebView", 'loadUrl("http://127.0.0.1:8788")')

# iOS/iPadOS: SwiftUI/MapKit owns the map-first product. Unsupported forwarding
# and desktop-equivalent multihop remain explicit/unavailable rather than fake.
ios = (
    "ios/RouterVPN/App/ProductRootView.swift",
    "ios/RouterVPN/App/IOSUnifiedProductView.swift",
    "ios/RouterVPN/App/IOSUnifiedTelemetry.swift",
    "ios/RouterVPN/App/IOSProfileSettingsView.swift",
    "ios/RouterVPN/App/IOSConnectionProfilesView.swift",
    "ios/RouterVPN/App/NodeManagerSheet.swift",
    "ios/RouterVPN/App/IOSUserLocationOverlay.swift",
)
require(
    "iOS/iPadOS native map-first UI",
    ios,
    "Add / manage nodes",
    "Fastest node or choose node",
    "Connect",
    "Disconnect",
    "Kill switch",
    "Master port forwarding",
    "keep this unavailable rather than showing a fake switch",
    "Multihop",
    "Settings",
    "Mode",
    "DNS",
    "SMART AUTO",
    "AUTO",
    "New CUSTOM preset…",
    "real coordinates",
    "packet",
    "Add / Load / Update / Delete",
    "Require encrypted",
    "Require obfuscation",
    "IPv6 On",
    "Auto MTU",
    "DAITA-like",
    "Jumbo",
    "When-In-Use permission",
    "no IP geolocation",
)
require_order(
    "iOS swipe-up control sheet order",
    ("ios/RouterVPN/App/IOSUnifiedProductView.swift",),
    'title: "Multihop"',
    'title: "Settings"',
    'title: "Mode"',
    'Label("DNS"',
)
forbid("iOS/iPadOS native shell", ios, "WKWebView", "SFSafariViewController", "Electron")

if ERRORS:
    print("NATIVE MAP-FIRST UI AUDIT: FAIL")
    for error in ERRORS:
        print(" - " + error)
    raise SystemExit(1)

print("NATIVE MAP-FIRST UI AUDIT: PASS")
