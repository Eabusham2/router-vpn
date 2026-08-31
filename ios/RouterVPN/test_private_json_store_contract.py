#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / "ios/RouterVPN/App/IOSPrivateJSONStore.swift").read_text(encoding="utf-8")
start = source.index("    static func write(_ data: Data")
end = source.index("    static func remove", start)
write = source[start:end]
for marker in (
    ".posixPermissions: NSNumber(value: Int16(0o600))",
    "try handle.synchronize()",
    "try manager.setAttributes(attributes, ofItemAtPath: temporary.path)",
    "manager.replaceItemAt(destination, withItemAt: temporary",
    "manager.moveItem(at: temporary, to: destination)",
    "The verified temporary file already owns the required protection",
):
    assert marker in write, f"iOS private store lost atomic-adoption marker: {marker}"
post = write.split("        adopted = true", 1)[1]
assert "setAttributes(attributes, ofItemAtPath: destination.path)" not in post, "iOS private store performs fallible metadata work after commit"
assert "removeItem(at: destination)" not in write, "iOS private store deletes authoritative state before replacement"
print("iOS private JSON atomic adoption contract: PASS")
