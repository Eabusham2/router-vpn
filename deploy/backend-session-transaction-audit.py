#!/usr/bin/env python3
"""Current backend transaction audit layered over the frozen v1 contract."""
from pathlib import Path

HERE = Path(__file__).resolve().parent
V1 = HERE / "backend-session-transaction-audit-v1.py"
source = V1.read_text(encoding="utf-8")

old_extras = '''    "cmd/client/extras.go": (\n        "captureAsyncMeasurementSession", "sameAsyncMeasurementSession", "stateAtStart := mtuStateSnapshotToken(a.state)",\n        "VPN session/path changed while public-exit lookup was running", "VPN session/path changed while DNS Retest was running",\n        "previousStore := cloneRouterProfileStore(a.profiles)", "a.rollbackProfilesLocked(previousStore)",\n    ),\n'''
new_extras = '''    "cmd/client/extras.go": (\n        "captureAsyncMeasurementSession", "sameAsyncMeasurementSession", "activeAsyncMeasurementProfile",\n        "validateAsyncMeasurementProfile", "asyncMeasurementProfileToken",\n        "VPN session/path changed while live proof was running",\n        "active VPN node/mode/base/path changed while live proof was running",\n        "active VPN profile or policy changed while live proof was running",\n        "active VPN path or policy changed before public-exit persistence",\n        "active node/path or DNS policy changed before DNS Retest persistence",\n        "previousStore := cloneRouterProfileStore(a.profiles)", "a.rollbackProfilesLocked(previousStore)",\n    ),\n'''
if source.count(old_extras) != 1:
    raise SystemExit("backend transaction overlay failed: v1 async-measurement predicate changed")
source = source.replace(old_extras, new_extras, 1)

old_mtu = '''    "cmd/client/mtu_retest.go": (\n        "previous := *x", "*x = previous", "durable rollback was incomplete",\n        "restoreMTUMeasurementFields", "rollbackMTULiveResult",\n    ),\n'''
new_mtu = '''    "cmd/client/mtu_retest.go": (\n        "captureMTULiveSnapshot", "validateMTUMeasurementAgainstLiveSnapshot",\n        "failMTURetestWithLiveRollback", "restoreMTULiveSnapshot",\n        "restoreMTUMeasurementFields", "rollback was incomplete",\n    ),\n'''
if source.count(old_mtu) != 1:
    raise SystemExit("backend transaction overlay failed: v1 MTU predicate changed")
source = source.replace(old_mtu, new_mtu, 1)

old_mtu_test = '''require(\n    "cmd/client/mtu_retest_test.go",\n    "TestMTURetestPersistenceFailureRollsBackLiveAndInMemoryResult",\n    "did not roll back the live interface",\n)'''
new_mtu_test = '''require(\n    "cmd/client/mtu_retest_test.go",\n    "TestMTURetestPersistenceFailureRollsBackLiveAndInMemoryResult",\n    "MTU persistence failure is no longer wired to exact live-MTU rollback",\n)'''
if source.count(old_mtu_test) != 1:
    raise SystemExit("backend transaction overlay failed: v1 MTU rollback-test predicate changed")
source = source.replace(old_mtu_test, new_mtu_test, 1)

exec(compile(source, str(V1), "exec"), {"__name__": "__main__", "__file__": str(V1)})
