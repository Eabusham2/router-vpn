#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


probe = read("android/app/src/main/java/com/eabusham/routervpn/AndroidViaEntryLatencyProbe.java")
meter = read("android/app/src/main/java/com/eabusham/routervpn/AndroidViaEntryPathMeter.java")
telemetry = read("android/app/src/main/java/com/eabusham/routervpn/AndroidTelemetry.java")
product = read("android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java")

for marker in (
    "wireGuard.connectManaged(entry.file",
    "state != Tunnel.State.UP",
    "AndroidViaEntryPathMeter.measure(entry, wireGuard",
    "wireGuard.disconnectManaged",
    "Temporary entry did not fully disconnect; candidate results discarded.",
    "AtomicBoolean",
    "AndroidVpnMutationGuard.isBusy(context)",
):
    assert marker in probe, f"probe missing {marker!r}"

for marker in (
    "AndroidPathProbe.prove(entry.file, 8000)",
    "wireGuard.getState() != Tunnel.State.UP",
    "before candidate RTT measurement",
    "after candidate RTT measurement",
    "all results discarded",
    "Collections.sort(out",
    "probeNode(node, count)",
):
    assert marker in meter, f"managed via-entry meter missing {marker!r}"

# Temporary X→Y/X→Z results never enter the direct-node telemetry cache and do
# not rely on a spoofed Home raw-tunnel session.
assert "cache(" not in meter, "via-entry RTT must never overwrite direct-node RTT cache"
assert "AndroidHomeStateStore" not in meter, "temporary via-entry meter must not publish/read normal Home session state"
assert "telemetry.measureNodesViaCurrentPath" not in probe, "probe still relies on old Home-state via-entry telemetry"
assert "wireGuard.connect(entry.file" not in probe
assert "wireGuard.disconnect(" not in probe

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

# The old telemetry method may remain temporarily for source compatibility, but
# the shipping via-entry flow is forbidden from calling it.
assert "measureNodesViaCurrentPath" in telemetry

print("Android managed via-entry multihop latency source contract OK")
