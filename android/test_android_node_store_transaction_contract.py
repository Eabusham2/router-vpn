#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStore.java").read_text(encoding="utf-8")
for marker in (
    "byte[] previousNode = snapshotOptional(target)",
    "restoreFile(target, previousNode)",
    "byte[] previousActiveBundle = snapshotOptional(activeBundle)",
    "rollbackSelection(activeBundle, previousActiveBundle, previousId)",
    "preferences().edit().putString(ACTIVE_ID, id).commit()",
    "preferences().edit().remove(ACTIVE_ID).commit()",
    "AndroidPrivateFileStore.remove(activeBundle, MAX_BUNDLE)",
    "failed and rollback was incomplete",
    "AndroidVpnMutationGuard.isBusy(context)",
    "active transition/temporary VPN operation finish before selecting another node",
    "live node identity and proof must remain immutable for the session",
):
    assert marker in source, f"Android node transaction lost {marker}"
assert ".apply()" not in source, "Android node identity transaction still uses asynchronous SharedPreferences.apply"
assert "engines.wireGuard.getState" not in source, "Android node store revived a partial hand-written runtime guard"
assert "engines.amneziaWG.getState" not in source, "Android node store revived a partial hand-written runtime guard"
remove_start = source.index("    synchronized void remove(String id)")
remove_end = source.index("    String activeId()", remove_start)
remove = source[remove_start:remove_end]
assert "previousNode" in remove and "previousActiveBundle" in remove and "previousId" in remove
print("Android node import/select/delete transaction + canonical busy guard contract: PASS")
