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
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidProfileSettingsDialog.java",
    "Require encrypted AUTO candidates",
    "Require obfuscation for AUTO candidates",
    "Both filters are Off by default",
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
)
require(
    "ios/RouterVPN/App/IOSProfileSettingsView.swift",
    "Require encrypted AUTO candidates",
    "Require obfuscation for AUTO candidates",
    "AUTO fails closed instead of silently relaxing them",
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
)

print("Native AUTO/SMART requirements UI parity audit: PASS")
