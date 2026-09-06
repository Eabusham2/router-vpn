#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(path: str, *markers: str) -> None:
    body = (ROOT / path).read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in body]
    if missing:
        raise SystemExit(f"{path}: missing native AUTO-requirements UI markers: {missing}")


require(
    "client/RouterVPN-Windows-ProfileSettings.ps1",
    "Require encrypted AUTO candidates",
    "Require obfuscation for AUTO candidates",
    "Both are Off by default",
    "AUTO encryption/obfuscation requirements",
    "AUTO Encrypted+Obfuscation",
    "AUTO Obfuscation",
    "AUTO Encrypted",
    "AUTO Off",
    "AUTO n/a",
    "Test-RouterVPNConnectionProfileBusy",
    "Disconnect Router VPN or let the active transition finish",
    "$settingsSave.IsEnabled=$false",
    "VPN became active or began transitioning before settings save",
)
require(
    "client/RouterVPN-Windows-UnifiedShell.ps1",
    "UnifiedSettingsSummary",
    "AUTO requirements=",
    "auto_require_encrypted",
    "auto_require_obfuscation",
)
require(
    "client/macos/RouterVPNProfileSettings.swift",
    "Require encrypted AUTO candidates",
    "Require obfuscation for AUTO candidates",
    "Both AUTO requirements are Off by default",
    "AUTO encryption/obfuscation requirements",
    "AUTO Encrypted+Obfuscation",
    "AUTO Obfuscation",
    "AUTO Encrypted",
    "AUTO Off",
    "AUTO n/a",
    "macMutationBusy",
    "syncMutationState()",
    "alert.buttons.first?.isEnabled = false",
    "VPN became active or began transitioning before settings save",
)
require(
    "client/macos/RouterVPNMacUnifiedShell.swift",
    "unified-auto-requirements",
    "AUTO requirements: Off",
    "auto_require_encrypted",
    "auto_require_obfuscation",
)
require(
    "client/linux/routervpn-auto-requirements-v11.inc",
    "Require encrypted AUTO candidates",
    "Require obfuscation for AUTO candidates",
    "auto_require_encrypted",
    "auto_require_obfuscation",
)
require(
    "client/linux/routervpn-profile-settings-v1.inc",
    "/api/profile/settings",
    "Save for next connection",
    "on_profile_settings_v7",
)
require(
    "client/linux/apply-session-mutation-v1.py",
    "routervpn-profile-settings-v1.inc",
    "gtk_dialog_get_widget_for_response",
    "Connected/transitioning: settings are read-only.",
    'routervpn_require_mutation_idle(app, "saving persistent node settings")',
)
require(
    "client/linux/build-native-app.sh",
    'SETTINGS_INC="$ROOT/client/linux/routervpn-profile-settings-v1.inc"',
    'SESSION_MUTATION="$ROOT/client/linux/apply-session-mutation.py"',
    'START_LAYER_SETTINGS="$ROOT/client/linux/apply-start-layer-settings.py"',
    'MUTATION_SETTINGS="$BUILD_DIR/routervpn-profile-settings-session.inc"',
    'HARDENED_SETTINGS="$BUILD_DIR/routervpn-profile-settings-v1.inc"',
    '"$SETTINGS_INC" "$MUTATION_SETTINGS"',
    'python3 "$START_LAYER_SETTINGS" "$MUTATION_SETTINGS" "$HARDENED_SETTINGS"',
)
if "routervpn-profile-settings-v2.inc" in (ROOT / "client/linux/build-native-app.sh").read_text(encoding="utf-8"):
    raise SystemExit("Linux shipping builder must not compose the superseded profile-settings-v2 source")
require(
    "client/linux/routervpn-unified-shell-v8.inc",
    "linux_unified_auto_requirements_v8",
    "AUTO requirements",
    "settings_summary",
    "AUTO requirements: Off • Off by default • SMART never simplifies below enabled requirements",
    "auto_require_encrypted",
    "auto_require_obfuscation",
)
require(
    "client/linux/routervpn-connection-profiles-v11.inc",
    "AUTO encryption/obfuscation requirements",
    "Load never connects automatically",
    "AUTO Encrypted+Obfuscation",
    "AUTO Obfuscation",
    "AUTO Encrypted",
    "AUTO Off",
    "AUTO n/a",
    "auto_require_encrypted",
    "auto_require_obfuscation",
    "linux_profile_mutation_busy_v11",
    "gtk_dialog_get_widget_for_response",
    "Disconnect Router VPN or let the active transition finish",
)
# Android no longer enumerates a fragile list of known STARTING/STOPPING labels.
# Mutation is allowed only in explicit stable idle states; every unknown/future
# phase and every non-DOWN engine state fails closed. This covers STARTING,
# STOPPING, reconnecting and new runtime phases without an audit-only string.
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidVpnMutationGuard.java",
    "hasOwnedVpnTransport",
    "AndroidHomeStateStore.snapshot",
    "orchestrator.isRunning()",
    "multihop.isActiveOrTransitioning()",
    "standardExit.isActiveOrTransitioning()",
    "phaseBusy(home.connected, phase)",
    'return !("off".equals(phase) || "disconnected".equals(phase) || "failed".equals(phase));',
    "tunnelBusy(e.wireGuard.getState())",
    "tunnelBusy(e.amneziaWG.getState())",
    "runtimeBusy(e.singBox.getState())",
    "runtimeBusy(e.xray.getState())",
    'return !("DOWN".equals(normalized) || "FAILED".equals(normalized) || "REVOKED".equals(normalized));',
    "return true;",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidProfileSettingsDialog.java",
    "Require encrypted AUTO candidates",
    "Require obfuscation for AUTO candidates",
    "Both filters are Off by default",
    "AndroidVpnMutationGuard.isBusy(activity)",
    "VPN became active or began transitioning while settings were open",
    "before settings commit",
    "Loading a profile never counts as runtime proof",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
    "autoRequirementsHint",
    "AUTO requirements: Off",
    "SMART never simplifies below enabled requirements",
    "auto_require_encrypted",
    "auto_require_obfuscation",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfilesDialog.java",
    "AUTO encryption/obfuscation requirements",
    "Connect still has to establish and prove the real VPN path",
    "AndroidVpnMutationGuard.isBusy(activity)",
    "active transition finish before Add / Load / Update / Delete",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java",
    "autoRequirementsSummary",
    "AUTO Encrypted+Obfuscation",
    "AUTO Obfuscation",
    "AUTO Encrypted",
    "AUTO Off",
    "AUTO n/a",
    "auto_require_encrypted",
    "auto_require_obfuscation",
    "AndroidVpnMutationGuard.isBusy(context)",
)
require(
    "ios/RouterVPN/App/RouterVPNModel.swift",
    "tunnelTransitioning",
    "profileMutationBlocked",
    "Disconnecting…",
    "status == .connecting || status == .disconnecting || status == .reasserting",
)
require(
    "ios/RouterVPN/App/IOSProfileSettingsView.swift",
    "Require encrypted AUTO candidates",
    "Require obfuscation for AUTO candidates",
    "AUTO fails closed instead of silently relaxing them",
    ".disabled(model.profileMutationBlocked)",
    "active VPN transition finish before editing persistent tunnel policy",
    "guard !model.profileMutationBlocked",
)
require(
    "ios/RouterVPN/App/IOSUnifiedProductView.swift",
    "settingsSummary",
    "AUTO Encrypted+Obfuscation",
    "AUTO Obfuscation",
    "AUTO Encrypted",
    "AUTO Off",
    "Require encrypted AUTO candidates",
    "Require obfuscation for AUTO candidates",
)
require(
    "ios/RouterVPN/App/IOSConnectionProfilesView.swift",
    "autoRequirementsSummary",
    "AUTO Encrypted+Obfuscation",
    "AUTO Off",
    "AUTO encryption/obfuscation requirements",
    "model.profileMutationBlocked",
    "delete(model: RouterVPNModel",
    "active VPN transition finish",
)

print("Native AUTO/SMART requirements UI parity audit: PASS")
