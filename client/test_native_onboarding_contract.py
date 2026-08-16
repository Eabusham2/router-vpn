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


# This audit intentionally watches the sources/package seams that the current
# product actually ships. Legacy desktop prototype files are not evidence that
# the packaged native product still owns the required onboarding lifecycle.
win = read("client/RouterVPN-Windows-App.ps1")
mac_onboarding = read("client/macos/RouterVPNProductOnboarding.swift")
mac_build = read("client/macos/build-native-app.sh")
linux_onboarding = read("client/linux/routervpn-product-onboarding-v6.inc")
linux_build = read("client/linux/build-native-app.sh")
android_onboarding = read("android/app/src/main/java/com/eabusham/routervpn/AndroidProductOnboarding.java")
android_product = read("android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java")
ios_onboarding = read("ios/RouterVPN/App/ProductOnboardingView.swift")
ios_product = read("ios/RouterVPN/App/ProductRootView.swift")

shared_topics = (
    "pairing", "router-vpn-bundle.json", "AUTO", "WireGuard", "DNS",
    "LAN Off", "MTU", "Jumbo", "Multihop", "forwarding",
    "permissions", "Disconnect", "private identity/path proof", "Public",
    "Diagnostics", "Setup Center Full Guide",
)

# Windows shipping wrapper owns the lifecycle and rewires the actual Product-v2
# Help button into the same persisted first-run tutorial.
require("Windows", win, shared_topics + (
    "AmneziaWG", "Emergency stop", "windows-onboarding-v2.json",
    ".routervpn-state", "Close and resume later", "Show-RouterVPNProductOnboarding",
    "Save-RouterVPNOnboardingState", "Show-RouterVPNProductOnboarding -Force",
    "app onboarding is separate from Setup Center onboarding",
))
require_any("Windows", win, "kill switch", ("kill switch", "kill-switch"))
assert "if ($SelfTest)" in win
assert re.search(r"else\s*\{\s*Show-RouterVPNProductOnboarding\s*;\s*&\s*\$ProductScript\b", win), "Windows first-run onboarding is not wired before the shipping product"
assert "TutorialPattern" in win and "Run onboarding" in win

# macOS shipping build compiles the onboarding source into RouterVPN.app and
# exact-wires both first launch and Help rerun into the AppKit product.
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

# Android ProductActivity is the actual dashboard. First launch and Help both
# route to the persisted SharedPreferences onboarding flow.
require("Android", android_onboarding, shared_topics + (
    "AmneziaWG", "Emergency stop", "VpnService", "Always-on VPN",
    "Block connections without VPN", "routervpn_product_onboarding_v2",
    "Close & resume later", "showIfNeeded",
    "app onboarding is separate from Setup Center onboarding",
))
require_any("Android", android_onboarding, "kill switch", ("kill switch", "kill-switch"))
require("Android product", android_product, (
    "AndroidProductOnboarding.showIfNeeded(this)",
    "Run onboarding again", "AndroidProductOnboarding.show(this, true)",
))

# iOS/iPadOS needs the shared app contract plus explicit Apple distribution and
# Network Extension truth. Unsupported AWG/desktop parity must remain stated,
# not faked green just to satisfy a shared-wording test.
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
require("iOS/iPadOS product", ios_product, (
    "Setup Guide", "RouterVPNProductOnboardingView",
    "RouterVPNProductOnboardingDoneV2", ".onAppear",
))

print("Shipping native app onboarding contract: PASS")
