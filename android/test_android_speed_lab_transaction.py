#!/usr/bin/env python3
"""Keep temporary Speed Lab restoration and captured-cleanup gates wired."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
controller = (JAVA / "AndroidSpeedLabController.java").read_text()
unified = (JAVA / "AndroidUnifiedConnectionController.java").read_text()
for marker in ("connection.captureRestorePoint()", "stopAndDrain(original.home.sessionId", "connection.restoreCaptured(original,idle", "connection.restoredCurrent(original,restoredOwner[0])", "meter.cancel()", "nativeHopMeter.cancel()", "connection.stopCaptured(home,topology", "AndroidMTUMeasurementGate.release(lease)"):
    assert marker in controller, "Temporary test lost its actual owner: " + marker
assert "connection.disconnect(" not in controller, "Temporary cleanup can stop an unrelated session"
for marker in ("Explicit/test-only node connection that never mutates AndroidNodeStore.activeId()", "void connectNode(AndroidNodeStore.Node node", "validateRestorePoint(point)", "orchestrator.restoreCaptured(point.node.file,point.home.runtimeMode", "disconnectAndDrainCaptured(session)"):
    assert marker in unified, "Exact original restoration is missing: " + marker
assert '"test_android_speed_lab_restore.py"' in (ROOT / "android/test_android_runtime_contract.py").read_text()
print("Android captured Speed Lab restoration gate: OK")
