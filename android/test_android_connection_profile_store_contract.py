#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java").read_text(encoding="utf-8")
for marker in (
    "SCHEMA_VERSION=4",
    'FILE_NAME="connection-profiles-v4.json", LEGACY_FILE_NAME="connection-profiles-v1.json"',
    "AndroidPrivateFileStore.read(source, MAX_STORE)",
    "AndroidPrivateFileStore.write(file, raw, MAX_STORE)",
    "AndroidPrivateFileStore.remove(legacyFile, MAX_STORE)",
    "Could not persist the loaded connection profile; prior Router node state was restored.",
    "nodes.importBundle(originalBundle)",
):
    assert marker in source, f"Android connection-profile store lost {marker}"
for forbidden in ("Os.rename(", "FileOutputStream", "requirePrivateRegularFile", ".delete()"):
    assert forbidden not in source, f"Android connection-profile store retains private-write bypass: {forbidden}"
print("Android connection-profile v4 shared private-store contract: PASS")
