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


# Watch the sources/package seams that the current product actually ships.
# Unified map-first shells may own drill-in controls while onboarding remains a
# separate persisted lifecycle. Legacy prototype files are never used as proof.
win = read("client/RouterVPN-Windows-App.ps1")
win_unified = read("client/RouterVPN-Windows-UnifiedShell.ps1")
win_product = read("client/RouterVPN-Windows-Product-v2.ps1")
mac_onboarding = read("client/macos/RouterVPNProductOnboarding.swift")
mac_build = read("client/macos/build-native-app.sh")
linux_onboarding = read("client/linux/routervpn-product-onboarding-v6.inc")
linux_build = read("client/linux/build-native-app.sh")
android_onboarding = read("android/app/src/main/java/com/eabusham/routervpn/AndroidProductOnboarding.java")
android_product = read("android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java")
ios_onboarding = read("ios/RouterVPN/App/ProductOnboardingView.swift")
ios_root = read("ios/RouterVPN/App/ProductRootView.swift")
ios_unified = read("ios/RouterVPN/App/IOSUnifiedProductView.swift")

# Windows v3 owns first-launch/resume in the launcher and the map-first daily
# controls in the unified shell. Require the real current lifecycle rather than
# dead v2 function names or duplicated endpoint strings in the wrapper.
require("Windows onboarding v3", win, (
    "windows-onboarding-v3.json", ".routervpn-state", "Get-OnboardingState",
    "Save-OnboardingState", "Show-RouterVPNProductOnboarding",
    "Close and resume later", "app onboarding is separate from Setup Center",
    "SMART AUTO is the default mode", "AUTO", "WireGuard", "AmneziaWG",
    "DNS", "LAN", "MTU", "Jumbo", "Multihop", "forwarding", "permissions",
    "Disconnect", "selected-node private path proof", "public exit",
    "Setup Center Full Guide", "Emergency stop",
))
require_any("Windows onboarding v3", win, "kill switch", ("kill switch", "kill-switch"))
require("Windows unified shipping shell", win_unified + win_product, (
    "UnifiedShell", "UnifiedMapCanvas", "UnifiedConnectButton", "UnifiedKillSwitch",
    "SMART AUTO", "CUSTOM", "/api/strategy/auto", "/api/strategy/smart-auto",
    "/api/strategy/custom", "/api/connect-logical", "/api/multihop/connect",
    "/api/profile/select", "/api/profile/latency", "/api/dns/retest",
    "/api/emergency-stop",
))
assert "if($SelfTest)" in win
assert re.search(r"else\s*\{\s*Show-RouterVPNProductOnboarding\s*;\s*&\s*\$ProductScript\b", win), "Windows first-run onboarding is not wired before the shipping product"

# macOS shipping build compiles the onboarding source into RouterVPN.app and
# exact-wires both first launch and rerun into the AppKit product.
shared_topics = (
    "pairing", "router-vpn-bundle.json", "AUTO", "WireGuard", "DNS",
    "LAN Off", "MTU", "Jumbo", "Multihop", "forwarding",
    "permissions", "Disconnect", "private identity/path proof", "Public",
    "Diagnostics", "Setup Center Full Guide",
)
require("macOS", mac_onboarding, shared_topics + (
    "AmneziaWG", "Emergency stop", "RouterVPNProductOnboardingDoneV2",
    "RouterVPNProductOnboardingStepV2", "Close & resume later",
    "presentIfNeeded", "runProductOnboarding",
    "app onboarding is separate from Setup Center onboarding",
))
require_any("macOS", mac_onboarding, "kill switch", ("kill switch", "kill-switch"))
require("macOS build", mac_build, (
    "RouterVPNProductOnboarding.swift", "Run onboarding",
    "RouterVPNProductOnboarding.shared.presentIfNeeded(parent: w.window)",
    "RouterVPNProductOnboardingDoneV2",
))
assert '"$ONBOARDING_SRC"' in mac_build

# Linux retains the native GTK assistant but ships the complete v6 content and
# a guarded build seam that persists/resumes its current page.
require("Linux", linux_onboarding, shared_topics + (
    "AmneziaWG", "Emergency stop", "Run Tutorial",
    "app onboarding is separate from Setup Center onboarding",
))
require_any("Linux", linux_onboarding, "kill switch", ("kill switch", "kill-switch"))
require("Linux build", linux_build, (
    "routervpn-product-onboarding-v6.inc", "onboarding_read_step_v6",
    "onboarding_write_step_v6", "gtk_assistant_set_current_page",
    "gtk_assistant_get_current_page", "Run Tutorial",
))
assert 'gcc -O2 -Wall -Wextra -Werror' in linux_build

# Android ProductActivity is the actual map-first dashboard. First launch and
# Help both route to the persisted SharedPreferences onboarding flow.
require("Android", android_onboarding, shared_topics + (
    "AmneziaWG", "Emergency stop", "VpnService", "Always-on VPN",
    "Block connections without VPN", "routervpn_product_onboarding_v2",
    "Close & resume later", "showIfNeeded",
    "app onboarding is separate from Setup Center onboarding",
))
require_any("Android", android_onboarding, "kill switch", ("kill switch", "kill-switch"))
require("Android product", android_product, (
    "AndroidProductOnboarding.showIfNeeded(this)", "Run onboarding again",
))
assert re.search(r"AndroidProductOnboarding\.show\(this\s*,\s*true\)", android_product), "Android Help is not wired to force-rerun product onboarding"

# iOS/iPadOS now delegates the daily surface from ProductRootView into the
# unified map-first view. Audit that composed shipping seam instead of requiring
# old floating-button labels to remain duplicated in ProductRootView.
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
))

print("Shipping native app onboarding contract: PASS")
