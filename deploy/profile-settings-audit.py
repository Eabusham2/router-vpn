#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(path: str) -> str:
    p = ROOT / path
    try:
        return p.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{path}: unreadable: {exc}")
        return ""


def require(path: str, *markers: str) -> str:
    body = read(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing settings marker {marker!r}")
    return body


api = require(
    "cmd/client/profile_settings.go",
    "/api/profile/settings",
    "disconnect or let the active AUTO/SMART/CUSTOM transition finish before changing Router VPN profile settings",
    "profileSettingsBusy", '"auto:"', '"smart-auto:"', '"smart:"', '"custom:"',
    "external exits own their protocol settings", "NormalizeRouterProfile", "syncProfileOptionStateLocked",
    "HomeLANAccess", "KillSwitchPolicy", "IPv6Mode", "BaseTunnel", "BaseFallback",
    "MTUPolicy", "ManualMTU", "DAITAEnabled", "JumboTUN", "SocksEnabled",
)
for forbidden in ("APIToken =", "NodeProofID =", "RouterAPI =", "Endpoint =", "DNSHost =", "PrivateKey"):
    if forbidden in api:
        errors.append(f"cmd/client/profile_settings.go mutates protected/non-policy field: {forbidden}")
require(
    "cmd/client/profile_settings_test.go",
    "TestProfileSettingsV2MutateOnlyAllowedPolicyFields", "TestProfileSettingsV2Validation",
    "TestProfileSettingsV2DefaultAndAutoMTUClearManualValue", "APIToken", "NodeProofID", "EffectiveMTUPathKey",
)
require("internal/common/types.go", 'json:"daita_enabled,omitempty"', 'json:"jumbo_tun,omitempty"', 'json:"socks_enabled,omitempty"')
require("cmd/client/mtu_retest.go", "registerProfileSettingsRoute(h, a)", "registerStrategyRoutes(h, a)")

# Windows shipping wrapper owns the button and only invokes the narrow helper.
require(
    "client/RouterVPN-Windows-ProfileSettings.ps1", "/api/profile/settings", "Allow home LAN access",
    "Always / strict", "AmneziaWG", "Auto measured", "DAITA-like", "Jumbo TUN", "SOCKS5",
    "never POST redacted /api/profile",
)
require(
    "client/RouterVPN-Windows-App.ps1", "RouterVPN-Windows-ProfileSettings.ps1", "ProfileSettingsButton",
    "Edit profile settings", "Show-RouterVPNProfileSettingsDialog", "/api/profile/settings",
    "/api/strategy/auto", "/api/strategy/smart-auto", "/api/strategy/custom",
)

# macOS build must compile the settings module and expose it from Advanced.
require(
    "client/macos/RouterVPNProfileSettings.swift", "/api/profile/settings", "Allow home LAN access",
    "Always / strict", "AmneziaWG", "Auto measured", "DAITA-like", "Jumbo TUN", "SOCKS5",
    "no redacted full-profile POST",
)
require(
    "client/macos/build-native-app.sh", "SETTINGS_SRC", 'button(\"Edit profile settings\", #selector(editProfileSettings))',
    '"$SETTINGS_SRC"', "/api/profile/settings", "/api/strategy/auto", "/api/strategy/smart-auto", "/api/strategy/custom",
)

# Linux shipping build compiles the GTK editor into v5 Advanced.
require(
    "client/linux/routervpn-profile-settings-v1.inc", "/api/profile/settings", "Allow home LAN access",
    "Always / strict", "AmneziaWG", "Auto measured", "DAITA-like", "Jumbo TUN", "SOCKS5",
    "never redacted full-profile POST",
)
require(
    "client/linux/build-native-app.sh", "SETTINGS_INC", '#include \"routervpn-profile-settings-v1.inc\"',
    "Edit profile settings", "G_CALLBACK(on_profile_settings_v7)", "gcc -O2 -Wall -Wextra -Werror",
)
require(
    "client/linux/routervpn-home-summary-v1.inc",
    "/api/strategy/auto", "/api/strategy/smart-auto", "/api/strategy/custom", "GtkFlowBox",
)

# Android edits only the selected private bundle and Advanced must open it.
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidProfileSettingsDialog.java",
    "home_lan_access", "kill_switch_policy", "ipv6_mode", "base_tunnel", "base_fallback",
    "mtu_policy", "manual_mtu", "daita_enabled", "jumbo_tun", "socks_enabled",
    "External exits own their protocol settings", "store.importBundle",
)
android_product = require(
    "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
    "AndroidProfileSettingsDialog.show", "showAdvanced", "LinearLayout.VERTICAL",
)
if "AndroidProfileSettingsDialog.show(this,nodeStore,this::refreshHomeState)" not in android_product.replace(" ", ""):
    errors.append("Android ProductActivity Advanced is not wired to refresh Home after settings save")

# Apple exposes only settings carried by the current PacketTunnel profile and
# explicitly omits unsupported Jumbo/DAITA/SOCKS rather than fake-enabling them.
require(
    "ios/RouterVPN/App/IOSProfileSettingsView.swift", "Allow home LAN access", "Always / strict",
    "AmneziaWG stays unavailable on iOS", "MTU policy", "Manual MTU", "Jumbo TUN is intentionally not exposed",
    "model.importBundle", "Disconnect before changing profile settings",
)
ios_home = require("ios/RouterVPN/App/IOSHomeSummaryView.swift", "IOSProfileSettingsView", "Advanced Settings")
if "Cached profile.publicIP is never used as live proof" not in ios_home:
    errors.append("iOS Home lost its live-exit trust-boundary marker while settings were wired")

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN safe cross-platform profile settings audit: PASS")
