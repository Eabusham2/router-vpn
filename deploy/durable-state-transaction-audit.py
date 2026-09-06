#!/usr/bin/env python3
"""Authoritative durable-state audit layered over the v1 contract.

The v1 file preserves the broad router-agent/update-controller/server publication
matrix. During the flattening transition this wrapper accepts either the old v1
predicates or the current predicates, so every direct-main intermediate head
remains executable without weakening the durability checks.
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
V1 = HERE / "durable-state-transaction-audit-v1.py"
source = V1.read_text(encoding="utf-8")

old_android = '    "AndroidPrivateFileStore.read(file, MAX_STORE)",\n'
new_android = '''    "SCHEMA_VERSION=4",\n    'FILE_NAME="connection-profiles-v4.json", LEGACY_FILE_NAME="connection-profiles-v1.json"',\n    "AndroidPrivateFileStore.read(source, MAX_STORE)",\n    "AndroidPrivateFileStore.remove(legacyFile, MAX_STORE)",\n'''
if source.count(old_android) == 1:
    source = source.replace(old_android, new_android, 1)
elif all(marker in source for marker in (
    '    "SCHEMA_VERSION=4",',
    'FILE_NAME="connection-profiles-v4.json", LEGACY_FILE_NAME="connection-profiles-v1.json"',
    '    "AndroidPrivateFileStore.read(source, MAX_STORE)",',
    '    "AndroidPrivateFileStore.remove(legacyFile, MAX_STORE)",',
)):
    pass
else:
    raise SystemExit("durable audit overlay failed: Android profile predicate is unknown")

old_android_test = 'run_test("android/test_android_connection_profile_store_contract.py")\n'
new_android_test = 'run_test("android/test_android_connection_profiles_contract.py")\n'
if source.count(old_android_test) == 1:
    source = source.replace(old_android_test, new_android_test, 1)
elif source.count(new_android_test) == 1:
    pass
else:
    raise SystemExit("durable audit overlay failed: Android profile test hook is unknown")

old_mtu = 'require("cmd/client/mtu_retest.go", "mtuRetestSnapshot", "rollbackMTULiveResult", "restoreMTUMeasurementFields")\n'
new_mtu = '''require(\n    "cmd/client/mtu_retest.go",\n    "mtuRetestSnapshot",\n    "captureMTULiveSnapshot",\n    "validateMTUMeasurementAgainstLiveSnapshot",\n    "failMTURetestWithLiveRollback",\n    "restoreMTULiveSnapshot",\n    "restoreMTUMeasurementFields",\n)\n'''
if source.count(old_mtu) == 1:
    source = source.replace(old_mtu, new_mtu, 1)
elif all(marker in source for marker in (
    '    "mtuRetestSnapshot",',
    '    "captureMTULiveSnapshot",',
    '    "validateMTUMeasurementAgainstLiveSnapshot",',
    '    "failMTURetestWithLiveRollback",',
    '    "restoreMTULiveSnapshot",',
    '    "restoreMTUMeasurementFields",',
)):
    pass
else:
    raise SystemExit("durable audit overlay failed: MTU predicate is unknown")

# Central stop-mode ownership was strengthened from the old non-strict
# `verified` command to verified-strict plus fail-closed registry retention.
# Keep the broad v1 matrix, but account for the current stronger vocabulary
# rather than weakening runtime/test code to satisfy stale literal markers.
old_stop_verified = '    \'verified "$ROOT"\',\n'
new_stop_verified = '    \'verified-strict "$ROOT"\',\n'
if source.count(old_stop_verified) == 1:
    source = source.replace(old_stop_verified, new_stop_verified, 1)
elif source.count(new_stop_verified) == 1:
    pass
else:
    raise SystemExit("durable audit overlay failed: stop-mode PID verification predicate is unknown")

old_stop_test = '    "legacy/raw PID registry",\n'
new_stop_test = '    "strict failure must not guess at process ownership",\n'
if source.count(old_stop_test) == 1:
    source = source.replace(old_stop_test, new_stop_test, 1)
elif source.count(new_stop_test) == 1:
    pass
else:
    raise SystemExit("durable audit overlay failed: stop-mode PID ownership test predicate is unknown")

exec(compile(source, str(V1), "exec"), {"__name__": "__main__", "__file__": str(V1)})
