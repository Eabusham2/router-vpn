#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
controller = (ROOT / "android/app/src/main/java/com/eabusham/routervpn/AndroidSpeedLabController.java").read_text(encoding="utf-8")
unified = (ROOT / "android/app/src/main/java/com/eabusham/routervpn/AndroidUnifiedConnectionController.java").read_text(encoding="utf-8")

for marker in (
    "boolean temporaryRuntimeRequested=false;",
    "temporaryRuntimeRequested=true;",
    'if(!ok){complete(callback,true,null,new IllegalStateException(message));return;}',
    "if(temporaryRuntimeRequested)complete(callback,true,null,error);else finish(callback,null,error);",
    'Temporary setup/measurement failed. Restoring the disconnected state…',
    "connection.disconnect",
    "Temporary Android path cleanup failed:",
):
    assert marker in controller, f"Android Speed Lab temporary rollback lost {marker!r}"

assert 'if(!ok){finish(callback,null,new IllegalStateException(message));return;}' not in controller, \
    "failed temporary Android setup can still bypass cleanup"

# The explicit Router-node test path must remain non-persistent; temporary Speed
# Lab may connect any stored node without replacing AndroidNodeStore.activeId().
for marker in (
    "Explicit/test-only node connection that never mutates AndroidNodeStore.activeId()",
    "void connectNode(AndroidNodeStore.Node node",
):
    assert marker in unified, f"Android test-only node ownership lost {marker!r}"

print("android Speed Lab temporary transaction contract: OK")
