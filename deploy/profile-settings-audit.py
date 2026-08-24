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
require(
    "cmd/client/mtu_retest.go", "registerProfileSettingsRoute(h, a)", "registerStrategyRoutes(h, a)",
    "registerConnectionProfileRoutes(h, a)",
)

connection_profiles = require(
    "cmd/client/connection_profiles.go",
    "/api/connection-profiles", "/api/connection-profile/save", "/api/connection-profile/update",
    "/api/connection-profile/load", "/api/connection-profile/delete",
    "connection-profiles.json", "0o600", "profileSettingsBusy", "saved multihop profile references",
    "connect separately so the selected platform can establish and prove the requested dataplane",
    "snapshotConnectionPreferences", "CustomLayers", "DNSMode", "MultihopEntryID", "MultihopExitID",
)
for forbidden_field in (
    "APIToken string", "PrivateKey string", "PresharedKey string", "SocksUsername string",
    "SocksPassword string", "External *common.ExternalNodeConfig",
):
    if forbidden_field in connection_profiles:
        errors.append(f"connection profile persistence unexpectedly declares secret-bearing field: {forbidden_field}")
require(
    "cmd/client/connection_profiles_test.go",
    "TestConnectionProfileStoreRoundTripIsPrivateAndSecretFree",
    "TestSnapshotConnectionPreferencesNeverCopiesNodeCredentials",
    "TestConnectionProfileInputNormalization", "TOP-SECRET-API-TOKEN", "private-password", "0o600",
)

win_settings = require(
    "client/RouterVPN-Windows-ProfileSettings.ps1", "/api/profile/settings", "Allow home LAN access",
    "Always / strict", "AmneziaWG", "Auto measured", "DAITA-like", "Jumbo TUN", "SOCKS5",
    "Require encrypted AUTO candidates", "Require obfuscation for AUTO candidates",
    "Connection profiles", "Add profile", "Load", "Update", "Delete",
    "/api/connection-profiles", "/api/connection-profile/setup/save", "/api/connection-profile/setup/update",
    "/api/connection-profile/setup/load", "/api/connection-profile/setup/delete",
    "windows-selected-mode-v1.txt", "windows-custom-presets-v1.json", "never duplicate node secrets",
)
for forbidden in ("APIToken", "PrivateKey", "PresharedKey", "socks_password"):
    if forbidden in win_settings:
        errors.append(f"Windows connection profile UI should not serialize private node field marker: {forbidden}")
require_combined(
    "Windows unified product",
    ("client/RouterVPN-Windows-App.ps1", "client/RouterVPN-Windows-UnifiedShell.ps1", "client/RouterVPN-Windows-ProfileSettings.ps1"),
    "RouterVPN-Windows-ProfileSettings.ps1", "Show-RouterVPNProfileSettingsDialog", "/api/profile/settings",
    "/api/strategy/auto", "/api/strategy/smart-auto", "/api/strategy/custom",
    "UnifiedSettingsButton", "UnifiedSettingsSummary", "AUTO requirements=", "auto_require_encrypted", "auto_require_obfuscation",
    "UnifiedKillSwitch", "UnifiedMtuButton", "/api/connection-profile/setup/load",
)

mac_settings = require(
    "client/macos/RouterVPNProfileSettings.swift", "/api/profile/settings", "Allow home LAN access",
    "Always / strict", "AmneziaWG", "Auto measured", "DAITA-like", "Jumbo TUN", "SOCKS5",
    "Require encrypted AUTO candidates", "Require obfuscation for AUTO candidates",
    "Connection profiles", "MacConnectionProfileControls", "Add", "Load", "Update", "Delete",
    "/api/connection-profiles", "/api/connection-profile/save", "/api/connection-profile/update",
    "/api/connection-profile/load", "/api/connection-profile/delete",
    "routervpn.unified.selected-mode.v1", "routervpn.unified.custom-presets.v1", "never duplicates node secrets",
)
for forbidden in ("apiToken", "privateKey", "presharedKey", "socksPassword"):
    if forbidden in mac_settings:
        errors.append(f"macOS connection profile UI should not serialize private node field marker: {forbidden}")
require_combined(
    "macOS unified product",
    ("client/macos/build-native-app.sh", "client/macos/RouterVPNMacUnifiedShell.swift", "client/macos/RouterVPNProfileSettings.swift"),
    "SETTINGS_SRC", "UNIFIED_SRC", '"$SETTINGS_SRC"', '"$UNIFIED_SRC"',
    "editProfileSettings", "/api/profile/settings", "/api/strategy/auto", "/api/strategy/smart-auto", "/api/strategy/custom",
    "unified-auto-requirements", "AUTO requirements: Off", "auto_require_encrypted", "auto_require_obfuscation",
    "/api/connection-profile/load",
)

require(
    "client/linux/routervpn-profile-settings-v1.inc", "/api/profile/settings", "Allow home LAN access",
    "Always / strict", "AmneziaWG", "Auto measured", "DAITA-like", "Jumbo TUN", "SOCKS5",
    "never redacted full-profile POST",
)
linux_profiles = require(
    "client/linux/routervpn-connection-profiles-v10.inc",
    "LinuxConnectionProfilesV10", "Add profile", "Load", "Update", "Delete", "Refresh",
    "/api/connection-profiles", "/api/connection-profile/save", "/api/connection-profile/update",
    "/api/connection-profile/load", "/api/connection-profile/delete",
    "linux_unified_selected_mode_v8", "linux_unified_custom_layers_for_mode_v8",
    "linux_unified_store_mode_v8", "never duplicate node secrets or credentials",
    "linux_connection_profiles_button_v10",
)
for forbidden in ("api_token", "private_key", "preshared_key", "socks_password"):
    if forbidden in linux_profiles:
        errors.append(f"Linux connection profile UI should not serialize private node field marker: {forbidden}")
require(
    "client/linux/routervpn-telemetry-v9.inc", '#include "routervpn-connection-profiles-v10.inc"',
    'linux_telemetry_button_v9("Profiles",G_CALLBACK(linux_connection_profiles_v10),t)',
    "linux_telemetry_button_v9",
)
require(
    "client/linux/build-native-app.sh", "SETTINGS_INC", '#include \"routervpn-profile-settings-v1.inc\"',
    "G_CALLBACK(on_profile_settings_v7)", "gcc -O2 -Wall -Wextra -Werror",
)
require_combined(
    "Linux unified product",
    ("client/linux/routervpn-unified-shell-v8.inc", "client/linux/routervpn-home-summary-v1.inc", "client/linux/routervpn-telemetry-v9.inc", "client/linux/routervpn-connection-profiles-v10.inc"),
    "/api/profile/settings", "/api/strategy/auto", "/api/strategy/smart-auto", "/api/strategy/custom",
    "linux_unified_settings_v8", "linux_unified_auto_requirements_v8", "AUTO requirements", "on_linux_auto_requirements_v11",
    "Kill switch", "MTU Retest", "/api/connection-profile/load",
)

android_settings = require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidProfileSettingsDialog.java",
    "home_lan_access", "kill_switch_policy", "ipv6_mode", "base_tunnel", "base_fallback",
    "auto_require_encrypted", "auto_require_obfuscation", "Require encrypted AUTO candidates", "Require obfuscation for AUTO candidates",
    "mtu_policy", "manual_mtu", "daita_enabled", "jumbo_tun", "socks_enabled",
    "External exits own their protocol settings", "store.importBundle",
    "Connection profiles — Add / Load / Update / Delete", "AndroidConnectionProfilesDialog.show",
)
android_store = require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java",
    "connection-profiles-v1.json", "MAX_PROFILES=64", "POLICY_KEYS", "requireIdle",
    "home_lan_access", "kill_switch_policy", "ipv6_mode", "auto_require_encrypted", "auto_require_obfuscation",
    "mtu_policy", "dns_mode", "dns_protocol", "multihop_enabled", "multihop_entry_id", "multihop_exit_id",
    "node_kind", "node_id", "custom_layers", "Connection profile contains non-whitelisted node data",
)
for forbidden in ('"api_token"', '"private_key"', '"preshared_key"', '"socks_password"', '"password"', '"secret"'):
    if forbidden in android_store:
        errors.append(f"Android connection profile store contains forbidden secret field literal: {forbidden}")
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfilesDialog.java",
    "Add", "Load", "Update", "Delete", "Refresh", "AndroidConnectionProfileStore",
    "never copied into these profiles", "Connect still has to establish and prove the real VPN path",
)
android_product = require(
    "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
    "AndroidProfileSettingsDialog.show", "showSettings", "LinearLayout.VERTICAL",
    "AUTO requirements: Off", "auto_require_encrypted", "auto_require_obfuscation",
)
compact_android = android_product.replace(" ", "").replace("\n", "")
if "AndroidProfileSettingsDialog.show(this,nodeStore,this::refreshAll)" not in compact_android:
    errors.append("Android ProductActivity Settings is not wired to refresh the unified surface after save")
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java",
    "auto_require_encrypted", "auto_require_obfuscation", "applyAutoRequirements",
    "collect(bundle,true,custom==null)", "applyAutoRequirements&&profile!=null",
)

require(
    "ios/RouterVPN/App/Models.swift",
    "profileSchemaVersion: 4", "profileSchemaVersion <= 4",
    "autoRequireEncrypted", 'autoRequireEncrypted = "auto_require_encrypted"',
    "autoRequireObfuscation", 'autoRequireObfuscation = "auto_require_obfuscation"',
)
ios_settings = require(
    "ios/RouterVPN/App/IOSProfileSettingsView.swift", "Allow home LAN access", "Always / strict",
    "AmneziaWG stays unavailable on iOS", "MTU policy", "Fixed / manual", "Jumbo TUN is intentionally not exposed",
    "Require encrypted AUTO candidates", "Require obfuscation for AUTO candidates",
    "autoRequireEncrypted", "autoRequireObfuscation", "model.importBundle",
    "profileMutationBlocked", ".disabled(model.profileMutationBlocked)",
    "guard !model.profileMutationBlocked else", "Disconnect or let the active VPN transition finish before changing profile settings.",
    "Connection profiles", "IOSConnectionProfilesView",
)
ios_profiles = require(
    "ios/RouterVPN/App/IOSConnectionProfilesView.swift",
    "IOSConnectionProfileStore", "IOSConnectionSafePreferences", "Add", "Load", "Update", "Delete",
    "routervpn.connection-profiles.v1", "routervpn.unified.mode.v1", "routervpn.unified.custom-presets.v1",
    "dnsMode", "dnsProtocol", "multihopEnabled", "multihopEntryID", "multihopExitID",
    "Current iOS does not execute full desktop multihop", "rejected at Add/Update time",
    "Connect remains a separate action", "No RouterProfile/API token/private key/external secret payload",
)
for forbidden in ("apiToken", "privateKey", "presharedKey", "socksPassword", "ExternalNodeConfig"):
    if forbidden in ios_profiles:
        errors.append(f"iOS connection profile store unexpectedly references secret-bearing model field/type: {forbidden}")
require(
    "ios/RouterVPN/App/IOSUnifiedProductView.swift",
    "Require encrypted AUTO candidates", "Require obfuscation for AUTO candidates",
    "Both AUTO requirements are Off by default", "profile-shared requirements",
)
require(
    "ios/RouterVPN/App/IOSStrategySupport.swift",
    "autoRequirementFailure", "encryptedLayers", "obfuscationLayers",
    "profile.autoRequireEncrypted", "profile.autoRequireObfuscation", "SMART AUTO •", "skipping simplification",
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
