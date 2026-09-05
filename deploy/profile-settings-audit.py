#!/usr/bin/env python3
"""Current profile/settings audit layered over the frozen v1 contract."""
from pathlib import Path

HERE = Path(__file__).resolve().parent
V1 = HERE / "profile-settings-audit-v1.py"
source = V1.read_text(encoding="utf-8")

old_mac_routes = '''    "/api/connection-profiles", "/api/connection-profile/save", "/api/connection-profile/update",\n    "/api/connection-profile/load", "/api/connection-profile/delete",\n'''
new_mac_routes = '''    "/api/connection-profiles", "/api/connection-profile/setup/save", "/api/connection-profile/setup/update",\n    "/api/connection-profile/setup/load", "/api/connection-profile/setup/delete",\n'''
if source.count(old_mac_routes) != 1:
    raise SystemExit("profile audit overlay failed: v1 macOS CRUD predicate changed")
source = source.replace(old_mac_routes, new_mac_routes, 1)

old_mac_composed = '''    "unified-auto-requirements", "AUTO requirements: Off", "auto_require_encrypted", "auto_require_obfuscation",\n    "/api/connection-profile/load",\n'''
new_mac_composed = '''    "unified-auto-requirements", "AUTO requirements: Off", "auto_require_encrypted", "auto_require_obfuscation",\n    "/api/connection-profile/setup/load", "exact multihop graph restored",\n'''
if source.count(old_mac_composed) != 1:
    raise SystemExit("profile audit overlay failed: v1 macOS unified predicate changed")
source = source.replace(old_mac_composed, new_mac_composed, 1)

old_android = '''    "connection-profiles-v1.json", "MAX_PROFILES=64", "POLICY_KEYS", "requireIdle",\n'''
new_android = '''    "SCHEMA_VERSION=4", "connection-profiles-v4.json", "connection-profiles-v1.json", "MAX_PROFILES=64", "POLICY_KEYS", "requireIdle",\n'''
if source.count(old_android) != 1:
    raise SystemExit("profile audit overlay failed: v1 Android schema predicate changed")
source = source.replace(old_android, new_android, 1)

old_ios = '''    "IOSConnectionProfileStore", "IOSConnectionSafePreferences", "Add", "Load", "Update", "Delete",\n'''
new_ios = '''    "IOSConnectionProfileStore", "IOSConnectionSafePreferences", "iosConnectionProfilesSchemaVersion = 4", "IOSConnectionProfileEnvelope", "Add", "Load", "Update", "Delete",\n'''
if source.count(old_ios) != 1:
    raise SystemExit("profile audit overlay failed: v1 iOS schema predicate changed")
source = source.replace(old_ios, new_ios, 1)

exec(compile(source, str(V1), "exec"), {"__name__": "__main__", "__file__": str(V1)})
