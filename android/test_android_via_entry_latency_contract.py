#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


probe = read("android/app/src/main/java/com/eabusham/routervpn/AndroidViaEntryLatencyProbe.java")
telemetry = read("android/app/src/main/java/com/eabusham/routervpn/AndroidTelemetry.java")
product = read("android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java")

for marker in (
    "wireGuard.connect(entry.file",
    "state != Tunnel.State.UP",
    "telemetry.measureNodesViaCurrentPath(entry.id",
    "wireGuard.disconnect",
    "Temporary entry did not fully disconnect; candidate results discarded.",
    "AtomicBoolean",
    "runtime.multihop.isActiveOrTransitioning()",
):
    assert marker in probe, f"probe missing {marker!r}"

for marker in (
    "measureNodesViaCurrentPath",
    '"raw-tunnel".equals(before.logicalMode)',
    '"wg".equals(before.actualBase)',
    "String session=before.sessionId",
    "long generation=before.pathGeneration",
    "session.equals(now.sessionId)",
    "now.pathGeneration!=generation",
    "all results discarded",
):
    assert marker in telemetry, f"telemetry missing {marker!r}"

# Via-entry measurements must not pollute the normal direct-node cache.
method = telemetry.split("void measureNodesViaCurrentPath", 1)[1].split("void currentPath", 1)[0]
assert "cache(" not in method, "via-entry RTT must never overwrite direct-node RTT cache"

for marker in (
    "PREPARE_VIA_ENTRY_RTT",
    "VpnService.prepare(this)",
    "prepareViaEntryExitMeasurement",
    "runPendingViaEntryProbe",
    "showViaEntryExitPicker",
    "Router VPN will then briefly establish and prove this entry",
    "Values are not saved as direct-node RTTs.",
    "unavailable",
    "STATE_PROBE_ENTRY",
    "STATE_PROBE_CANDIDATES",
):
    assert marker in product, f"product missing {marker!r}"

# The picker must not fabricate X→Y values from direct cached RTTs.
picker = product.split("private void showViaEntryExitPicker", 1)[1].split("private void clearPendingProbe", 1)[0]
assert "cachedMedian" not in picker, "via-entry picker must not substitute direct cached RTT"
assert "medianMs" in picker, "via-entry picker must display measured via-entry median"

print("Android via-entry multihop latency source contract OK")
