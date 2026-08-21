#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{path}: unreadable: {exc}")
        return ""


def require(body: str, label: str, *markers: str) -> None:
    for marker in markers:
        if marker not in body:
            errors.append(f"{label}: missing {marker!r}")


telemetry = read("client/linux/routervpn-telemetry-v9.inc")
compat = read("client/linux/routervpn-connection-profiles-v10.inc")
full = read("client/linux/routervpn-connection-profiles-v11.inc")
build = read("client/linux/build-native-app.sh")
profiles = read("cmd/client/connection_profiles.go")
setup = read("cmd/client/connection_profile_setup.go")

# The current shipping composition is build -> telemetry-v9 -> v10 compatibility
# seam -> v11. Prove every link so an orphaned v11 source file cannot be called
# shipped merely because it exists in the repository.
require(telemetry, "Linux telemetry shipping seam",
        '#include "routervpn-connection-profiles-v10.inc"',
        'linux_telemetry_button_v9("Profiles",G_CALLBACK(linux_connection_profiles_v10),t)')
require(compat, "Linux profile compatibility seam",
        '#include "routervpn-connection-profiles-v11.inc"',
        "linux_profile_manager_v11(NULL, telemetry->base)",
        "linux_connection_profiles_v11_install_reference_v10")
if "api_request(" in compat:
    errors.append("Linux v10 compatibility seam must not implement a second/stale profile API client")
require(build, "Linux native shipping build",
        'TELEMETRY_INC="$ROOT/client/linux/routervpn-telemetry-v9.inc"',
        '#include "routervpn-telemetry-v9.inc"',
        "linux_install_telemetry_v9(&app);",
        "gcc -O2 -Wall -Wextra -Werror")

# v11 is the whole-connection manager. It must use the setup routes that stage
# exact multihop graph identity while Connect remains a separate action.
require(full, "Linux full connection profile manager v11",
        "Full non-secret connection profile CRUD",
        "/api/connection-profile/setup/save",
        "/api/connection-profile/setup/update",
        "/api/connection-profile/setup/load",
        "/api/connection-profile/setup/delete",
        "multihop_enabled",
        "multihop_entry_id",
        "multihop_exit_id",
        "multihop_exit_mode",
        "Save/restore exact multihop graph",
        "Connect remains separate")

# The setup route intentionally sends only UI-owned mode/CUSTOM/multihop fields;
# the underlying controller save snapshots the remaining current node settings.
# Guard that full snapshot so DNS/kill-switch/IPv6/MTU/AUTO/base settings cannot
# silently disappear from Linux profiles.
require(profiles, "Shared connection profile snapshot",
        "snapshotConnectionPreferences",
        "HomeLANAccess", "KillSwitchPolicy", "IPv6Mode",
        "AutoRequireEncrypted", "AutoRequireObfuscation",
        "BaseTunnel", "BaseFallback", "MTUPolicy", "ManualMTU",
        "DAITAEnabled", "JumboTUN", "SocksEnabled",
        "DNSMode", "DNSProtocol", "DNSHost", "DNSPort",
        "DNSServerName", "DNSPath",
        "MultihopEnabled", "MultihopEntryID", "MultihopExitID",
        "CustomLayers", "0o600")
require(setup, "Whole-connection setup routes",
        "/api/connection-profile/setup/save",
        "/api/connection-profile/setup/update",
        "/api/connection-profile/setup/load",
        "/api/connection-profile/setup/delete",
        "a.saveConnectionProfile(recorder, innerReq)",
        "a.updateConnectionProfile(recorder, innerReq)",
        "persistConnectionProfileStore(a, store)",
        "persistConnectionProfileSetupMeta(a, meta)",
        "connection setup snapshot failed and was rolled back")

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN Linux full connection-profile shipping audit: PASS")
