#!/usr/bin/env python3
"""Authoritative durable-state audit layered over the frozen v1 contract.

v1 preserves the broad router-agent/update-controller/server publication safety
matrix. This wrapper updates only source predicates whose implementation became
strictly stronger after that baseline: Android connection-profile schema-v4
migration, the canonical Android profile safety contract, and controller-owned
MTU live rollback.
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
V1 = HERE / "durable-state-transaction-audit-v1.py"
source = V1.read_text(encoding="utf-8")

old_android = '    "AndroidPrivateFileStore.read(file, MAX_STORE)",\n'
new_android = '''    "SCHEMA_VERSION=4",\n    'FILE_NAME="connection-profiles-v4.json", LEGACY_FILE_NAME="connection-profiles-v1.json"',\n    "AndroidPrivateFileStore.read(source, MAX_STORE)",\n    "AndroidPrivateFileStore.remove(legacyFile, MAX_STORE)",\n'''
if source.count(old_android) != 1:
    raise SystemExit("durable audit overlay failed: v1 Android profile predicate changed")
source = source.replace(old_android, new_android, 1)

old_android_test = 'run_test("android/test_android_connection_profile_store_contract.py")\n'
new_android_test = 'run_test("android/test_android_connection_profiles_contract.py")\n'
if source.count(old_android_test) != 1:
    raise SystemExit("durable audit overlay failed: v1 Android profile test hook changed")
source = source.replace(old_android_test, new_android_test, 1)

old_mtu = 'require("cmd/client/mtu_retest.go", "mtuRetestSnapshot", "rollbackMTULiveResult", "restoreMTUMeasurementFields")\n'
new_mtu = '''require(\n    "cmd/client/mtu_retest.go",\n    "mtuRetestSnapshot",\n    "captureMTULiveSnapshot",\n    "validateMTUMeasurementAgainstLiveSnapshot",\n    "failMTURetestWithLiveRollback",\n    "restoreMTULiveSnapshot",\n    "restoreMTUMeasurementFields",\n)\n'''
if source.count(old_mtu) != 1:
    raise SystemExit("durable audit overlay failed: v1 MTU predicate changed")
source = source.replace(old_mtu, new_mtu, 1)

exec(compile(source, str(V1), "exec"), {"__name__": "__main__", "__file__": str(V1)})
