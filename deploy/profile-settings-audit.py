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


def require_combined(label: str, paths: tuple[str, ...], *markers: str) -> str:
    bodies = [(path, read(path)) for path in paths]
    combined = "\n".join(body for _, body in bodies)
    for marker in markers:
        if marker not in combined:
            errors.append(f"{label}: missing composed settings marker {marker!r} across {', '.join(paths)}")
    return combined


api = require(
    "cmd/client/profile_settings.go",
    "/api/profile/settings",
    "disconnect or let the active AUTO/SMART/CUSTOM transition finish before changing Router VPN profile settings",
    "profileSettingsBusy", '"auto:"', '"smart-auto:"', '"smart:"', '"custom:"',
    "external exits own their protocol settings", "NormalizeRouterProfile", "syncProfileOptionStateLocked",
    "HomeLANAccess", "KillSwitchPolicy", "IPv6Mode", "BaseTunnel", "BaseFallback",
    "AutoRequireEncrypted", "AutoRequireObfuscation",
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
require(
    "cmd/client/strategy_requirements.go",
    "modeMeetsAutoRequirements", "modeHasEncryptedTransport", "modeHasObfuscation",
    "AutoRequireEncrypted", "AutoRequireObfuscation",
)
require(
    "internal/common/types.go",
    'json:"auto_require_encrypted,omitempty"', 'json:"auto_require_obfuscation,omitempty"',
    'json:"daita_enabled,omitempty"', 'json:"jumbo_tun,omitempty"', 'json:"socks_enabled,omitempty"',
)
require("cmd/client/mtu_retest.go", "registerProfileSettingsRoute(h, a)", "registerStrategyRoutes(h, a)")

# Windows is a composed native WPF product: launcher + unified daily shell +
# narrow settings helper. The migration audit follows that real shipping seam
# instead of requiring the old tab/button names to remain duplicated.
require(
    "client/RouterVPN-Windows-ProfileSettings.ps1", "/api/profile/settings", "Allow home LAN access",
    "Always / strict", "AmneziaWG", "Auto measured", "DAITA-like", "Jumbo TUN", "SOCKS5",
    "never POST redacted /api/profile",
)
require_combined(
    "Windows unified product",
    ("client/RouterVPN-Windows-App.ps1", "client/RouterVPN-Windows-UnifiedShell.ps1", "client/RouterVPN-Windows-ProfileSettings.ps1"),
    "RouterVPN-Windows-ProfileSettings.ps1", "Show-RouterVPNProfileSettingsDialog", "/api/profile/settings",
    "/api/strategy/auto", "/api/strategy/smart-auto", "/api/strategy/custom",
    "UnifiedSettingsButton", "UnifiedKillSwitch", "UnifiedMtuButton",
)

# macOS build compiles both settings and unified shell. Strategy endpoints live
# in the unified shell while the build owns the compile/package seam.
require(
    "client/macos/RouterVPNProfileSettings.swift", "/api/profile/settings", "Allow home LAN access",
    "Always / strict", "AmneziaWG", "Auto measured", "DAITA-like", "Jumbo TUN", "SOCKS5",
    "no redacted full-profile POST",
)
require_combined(
    "macOS unified product",
    ("client/macos/build-native-app.sh", "client/macos/RouterVPNMacUnifiedShell.swift", "client/macos/RouterVPNProfileSettings.swift"),
    "SETTINGS_SRC", "UNIFIED_SRC", '"$SETTINGS_SRC"', '"$UNIFIED_SRC"',
    "editProfileSettings", "/api/profile/settings", "/api/strategy/auto", "/api/strategy/smart-auto", "/api/strategy/custom",
)

# Linux shipping build compiles the settings editor plus the unified v8 shell.
require(
    "client/linux/routervpn-profile-settings-v1.inc", "/api/profile/settings", "Allow home LAN access",
    "Always / strict", "AmneziaWG", "Auto measured", "DAITA-like", "Jumbo TUN", "SOCKS5",
    "never redacted full-profile POST",
)
require(
    "client/linux/build-native-app.sh", "SETTINGS_INC", '#include \"routervpn-profile-settings-v1.inc\"',
    "G_CALLBACK(on_profile_settings_v7)", "gcc -O2 -Wall -Wextra -Werror",
)
require_combined(
    "Linux unified product",
    ("client/linux/routervpn-unified-shell-v8.inc", "client/linux/routervpn-home-summary-v1.inc"),
    "/api/profile/settings", "/api/strategy/auto", "/api/strategy/smart-auto", "/api/strategy/custom",
    "linux_unified_settings_v8", "Kill switch", "MTU Retest",
)

# Android edits only the selected private bundle. Current map-first ProductActivity
# opens showSettings() and refreshes the complete unified surface after a save.
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidProfileSettingsDialog.java",
    "home_lan_access", "kill_switch_policy", "ipv6_mode", "base_tunnel", "base_fallback",
    "auto_require_encrypted", "auto_require_obfuscation", "Require encrypted", "Require obfuscation",
    "mtu_policy", "manual_mtu", "daita_enabled", "jumbo_tun", "socks_enabled",
    "External exits own their protocol settings", "store.importBundle",
)
android_product = require(
    "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
    "AndroidProfileSettingsDialog.show", "showSettings", "LinearLayout.VERTICAL",
)
compact_android = android_product.replace(" ", "").replace("\n", "")
if "AndroidProfileSettingsDialog.show(this,nodeStore,this::refreshAll)" not in compact_android:
    errors.append("Android ProductActivity Settings is not wired to refresh the unified surface after save")
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java",
    "auto_require_encrypted", "auto_require_obfuscation", "applyAutoRequirements",
    "AUTO/SMART filters only",
)

# Apple exposes only settings carried by the current PacketTunnel profile and
# explicitly omits unsupported Jumbo/DAITA/SOCKS rather than fake-enabling them.
# iOS must also accept current profile schema v4 and enforce the shared AUTO
# encryption/obfuscation classifications before initial and SMART attempts.
require(
    "ios/RouterVPN/App/Models.swift",
    "profileSchemaVersion: 4", "profileSchemaVersion <= 4",
    "autoRequireEncrypted", 'autoRequireEncrypted = "auto_require_encrypted"',
    "autoRequireObfuscation", 'autoRequireObfuscation = "auto_require_obfuscation"',
)
require(
    "ios/RouterVPN/App/IOSProfileSettingsView.swift", "Allow home LAN access", "Always / strict",
    "AmneziaWG stays unavailable on iOS", "MTU policy", "Fixed / manual", "Jumbo TUN is intentionally not exposed",
    "Require encrypted AUTO candidates", "Require obfuscation for AUTO candidates",
    "autoRequireEncrypted", "autoRequireObfuscation", "model.importBundle",
    "Disconnect before changing profile settings",
)
require(
    "ios/RouterVPN/App/IOSStrategySupport.swift",
    "autoRequirementFailure", "encryptedLayers", "obfuscationLayers",
    "profile.autoRequireEncrypted", "profile.autoRequireObfuscation",
    "SMART AUTO •", "skipping simplification",
)
require(
    "ios/RouterVPN/App/RouterVPNModel.swift",
    "IOSStrategyCatalog.autoRequirementFailure", "AUTO failed closed: no iOS-runnable candidate satisfies the saved requirements",
)
ios_home = require("ios/RouterVPN/App/IOSHomeSummaryView.swift", "IOSProfileSettingsView", "Advanced Settings")
if "Cached profile.publicIP is never used as live proof" not in ios_home:
    errors.append("iOS Home lost its live-exit trust-boundary marker while settings were wired")

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN safe cross-platform profile settings audit: PASS")
