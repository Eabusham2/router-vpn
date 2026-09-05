#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent
JAVA = ROOT / "app" / "src" / "main" / "java" / "com" / "eabusham" / "routervpn"


def read(name: str) -> str:
    path = JAVA / name
    assert path.is_file(), f"missing {path}"
    return path.read_text(encoding="utf-8", errors="replace")


registry = read("AndroidRuntimeRegistry.java")
reconciler = read("AndroidProcessStateReconciler.java")
home = read("AndroidHomeStateStore.java")
layered = read("LayeredVpnService.java")
xray = read("XrayVpnService.java")

# Reconciliation must happen before a controller/multihop object can restore
# process-owned state from SharedPreferences.
reconcile_at = registry.index("AndroidProcessStateReconciler.reconcile(app);")
for marker in (
    "new NativeWireGuardController(app)",
    "new NativeAmneziaWGController(app)",
    "new NativeSingBoxController(app)",
    "new NativeXrayController(app)",
    "new AndroidMultihopRuntime(app, singBox)",
    "new AndroidStandardExitRuntime(app, singBox)",
):
    assert reconcile_at < registry.index(marker), f"startup reconciliation occurs after {marker}"

for marker in (
    "previous process-owned VPN/path proof was invalidated",
    '"connecting".equals(phase)',
    '"connected".equals(phase)',
    '"stopping".equals(phase)',
    '"UP".equals(state)',
    '"STARTING".equals(state)',
    '"STOPPING".equals(state)',
    'putString(stateKey, "FAILED")',
    "AndroidHomeStateStore.advancePathGeneration(app)",
    "AndroidHomeStateStore.failed(app, RESTART_REASON)",
):
    assert marker in reconciler, f"restart reconciler missing {marker}"

# A stale path generation/Connected bit is not enough to survive a new process.
for marker in ('putString("path_proof", "passed")', 'putBoolean("connected", true)', "advancePathGeneration"):
    assert marker in home, f"home state contract missing {marker}"

# This cold-start invalidation is valid because neither process-owned VpnService
# asks Android to resurrect it after process death.
assert layered.count("Service.START_NOT_STICKY") >= 2, "LayeredVpnService became sticky; revisit restart reconciliation"
assert xray.count("Service.START_NOT_STICKY") >= 2, "XrayVpnService became sticky; revisit restart reconciliation"

print("Android cold-process restart invalidates stale Connected/service state before runtime restore: OK")
