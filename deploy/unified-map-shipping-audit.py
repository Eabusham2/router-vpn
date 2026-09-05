#!/usr/bin/env python3
"""Prove the unified map control center is in each real shipping entrypoint."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(path: str) -> str:
    target = ROOT / path
    if not target.is_file():
        errors.append(f"missing shipping source: {path}")
        return ""
    return target.read_text(encoding="utf-8", errors="replace")


def need(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing shipping marker {marker!r}")


def forbid(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker in body:
            errors.append(f"{path}: forbidden shipping marker {marker!r}")


contract = json.loads(read("client/unified-control-center-v2.json") or "{}")
if contract.get("default_surface") != "map":
    errors.append("unified product no longer starts on the map")
if contract.get("bottom_sheet_order") != ["connection", "multihop", "settings", "mode", "dns"]:
    errors.append("unified swipe-up control order drifted")
for key, expected in {
    "mode": "smart-auto",
    "selected_node_count": 1,
    "ipv6": True,
    "mtu_policy": "auto",
    "auto_require_encrypted": False,
    "auto_require_obfuscation": False,
}.items():
    if contract.get("defaults", {}).get(key) != expected:
        errors.append(f"canonical default {key} drifted")
for key in ("color_coded_roles", "animated_packet", "node_rtt_labels", "hop_lines"):
    if contract.get("map", {}).get(key) is not True:
        errors.append(f"canonical map behavior {key} is not enabled")
for key in ("live_pairwise_rtt", "live_per_hop_rtt", "live_total_rtt", "per_hop_speed_tests", "end_to_end_speed_test"):
    if contract.get("multihop", {}).get(key) is not True:
        errors.append(f"canonical multihop behavior {key} is not enabled")
if contract.get("capability_gating", {}).get("unsupported_controls_are_disabled_with_reason") is not True:
    errors.append("unsupported platform controls are no longer required to fail closed with a reason")

# iPhone/iPad: Xcode compiles the complete App directory, ProductRootView opens
# the unified map directly, and the real unified screen owns all requested controls.
need(
    "ios/RouterVPN/project.yml",
    "sources:\n      - App",
    'TARGETED_DEVICE_FAMILY: "1,2"',
    'SWIFT_VERSION: "6.0"',
)
need("ios/RouterVPN/App/RouterVPNApp.swift", "ProductRootView()", ".environmentObject(model)")
need("ios/RouterVPN/App/ProductRootView.swift", "IOSUnifiedProductView()")
need(
    "ios/RouterVPN/App/IOSUnifiedProductView.swift",
    "IOSUnifiedMap",
    "IOSUserLocationControl()",
    "controlSheet(height:",
    "Test & select fastest",
    "connectionButtonTitle",
    'title: "Add / manage nodes"',
    'title: "Multihop"',
    'title: "Profiles & bridges"',
    'title: "Settings"',
    'title: "Mode"',
    'Label("DNS"',
    "IOSUnifiedCustomBuilder",
    "IOSConnectionProfilesView",
    "IOSUnifiedPerformanceView",
    "Run real current VPN path speed",
    "Auto-MTU optimizer result",
    "Require encrypted",
    "Require obfuscation",
    "IPv6",
    "Jumbo TUN",
    "DAITA-like",
    "systemBlue",
    "systemOrange",
    "systemPink",
    "startPacketAnimation",
)
forbid("ios/RouterVPN/App/IOSUnifiedProductView.swift", "Test & connect fastest", "private func connectFastest")

# Android: ProductActivity is the only launcher; the old engine console is
# disabled so the unified map/controller owns the process-visible product.
need(
    "android/app/src/main/AndroidManifest.xml",
    'android:name=".ProductActivity"',
    'android.intent.category.LAUNCHER',
    'android:name=".MainActivity" android:exported="false" android:enabled="false"',
)
need(
    "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
    "RouterVpnNodeMapView",
    'smallButton("⚡ Fastest ▾")',
    "Use Connect separately",
    'primaryButton("Connect")',
    'killSwitch.setContentDescription("Kill switch")',
    'forwardButton=smallButton("Forward")',
    'multihopToggle.setText("Multihop")',
    'controlRow("Settings")',
    'controlRow("Mode")',
    'controlRow("DNS")',
    'smallButton("Performance")',
    'smallButton("Profiles")',
    'setContentDescription("Add, load, update or delete a whole non-secret connection profile")',
    'smallButton("Add Router")',
    'smallButton("Add custom")',
    "showCustomBuilder",
    '"custom:new"',
    "showViaEntryExitPicker",
    "live via-entry multihop candidate RTT",
    "currentPathMs",
)

# Windows: the packaged launcher copies the native client tree, starts the WPF
# app, then composes unified-shell and telemetry transforms into Product-v2.
need(
    "deploy/package-builds.sh",
    'cp -a "$ROOT/client" "$dir/client"',
    "RouterVPN-Windows-App.ps1",
    "normal native Windows Router VPN app",
)
need(
    "client/RouterVPN-Windows-App.ps1",
    "RouterVPN-Windows-UnifiedShell.ps1",
    "Add-RouterVPNUnifiedWindowsShell",
    "RouterVPN-Windows-Telemetry.ps1",
    "Add-RouterVPNTelemetryWindowsShell",
    "UnifiedConnectButton",
    "UnifiedFastestNode",
    "UnifiedLiveLatency",
    "UnifiedForwardButton",
    "UnifiedKillSwitch",
    "UnifiedMultihopLatency",
    "UnifiedPerformanceButton",
    "New CUSTOM preset",
)
need(
    "client/RouterVPN-Windows-Telemetry.ps1",
    "Real path speed",
    "Routed hop speeds",
    "/api/multihop/speed-test",
    "UnifiedPerformanceButton",
)
need(
    "client/RouterVPN-Windows-UnifiedShell.ps1",
    'Name="UnifiedMapCanvas"',
    'Name="UnifiedConnectButton" Content="Connect"',
    'Name="UnifiedMultihop"',
    'Text="Settings"',
    'Text="Mode"',
    'Text="DNS"',
    "ShowUnifiedCustomBuilder",
    "/api/strategy/smart-auto",
    "/api/strategy/auto",
    "/api/strategy/custom",
)
forbid("client/RouterVPN-Windows-App.ps1", "msedge.exe", "chrome.exe", "--app=")

# macOS: the native compiler command includes hardened unified UI, telemetry,
# Speed Lab, globe, whole-profile CRUD, onboarding and settings sources.
need(
    "client/macos/build-native-app.sh",
    "RouterVPNMacUnifiedShell.swift",
    "RouterVPNMacTelemetry.swift",
    "RouterVPNMacSpeedLab.swift",
    "RouterVPNMacGlobeChrome.swift",
    "RouterVPNConnectionProfiles.swift",
    "RouterVPNConnectionProfileChrome.swift",
    "RouterVPNProfileSettings.swift",
    '"$HARDENED_UNIFIED_SRC" "$TELEMETRY_SRC" "$SPEED_LAB_SRC" "$GLOBE_SRC" "$PROFILE_SRC"',
    "buildUnifiedUI(); installUnifiedTelemetryUI(); installUnifiedSpeedLabUI(); installUnifiedMapChrome(); installUnifiedConnectionProfileChrome()",
)
need(
    "client/macos/RouterVPNMacUnifiedShell.swift",
    "CUSTOM preset builder",
    "New preset",
    "Delete",
    "Save & Connect",
    "buildUnifiedUI()",
    'NSUserInterfaceItemIdentifier("unified-sheet")',
    "Add / manage nodes",
    "SMART AUTO",
    "AUTO",
    "Multihop",
    "Open settings",
    "DNS",
    "real coordinates",
)
forbid("client/macos/RouterVPNMacUnifiedShell.swift", "WKWebView", "SFSafariViewController")

# Linux: the strict native builder physically composes the unified sheet,
# telemetry, globe, profiles/settings and AUTO requirements before -Werror.
need(
    "client/linux/build-native-app.sh",
    "routervpn-auto-requirements-v11.inc",
    "routervpn-unified-shell-v8.inc",
    "routervpn-telemetry-v9.inc",
    "routervpn-globe-v10.inc",
    "linux_install_telemetry_v9(&app)",
    "linux_install_globe_v10(&app)",
    "gcc -O2 -Wall -Wextra -Werror",
)
need(
    "client/linux/routervpn-unified-shell-v8.inc",
    '"SMART AUTO — recommended"',
    '"AUTO — first proven path"',
    '"New CUSTOM preset…"',
    '"CUSTOM preset builder"',
    '"Multihop"',
    '"Settings"',
    '"Mode"',
    '"DNS"',
    "/api/mtu/retest",
    "Add / manage nodes",
)

# Setup Center/onboarding may never cover the map controls. It is an explicit,
# dismissible overlay with bounded viewport dimensions and disabled background
# pointer capture when hidden.
need(
    "server/scripts/setup_center_ux_patch.py",
    "Unified Map Control Center non-blocking overlay contract",
    "pointer-events:none!important",
    "max-height:calc(100dvh - 24px)",
    "aria-label=\"Hide download progress\"",
)

if errors:
    print("UNIFIED MAP SHIPPING AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)
print("UNIFIED MAP SHIPPING AUDIT: PASS")
