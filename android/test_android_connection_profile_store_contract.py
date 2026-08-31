#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java").read_text(encoding="utf-8")
start = source.index("    private void writeRows(JSONArray rows) throws Exception {")
end = source.index("    private static void requirePrivateRegularFile", start)
write_rows = source[start:end]
for marker in (
    "tmp.createNewFile()",
    "Os.chmod(tmp.getAbsolutePath(), 0600)",
    "out.getFD().sync()",
    "requirePrivateRegularFile(tmp)",
    "Os.rename(tmp.getAbsolutePath(), file.getAbsolutePath())",
    "Rename preserves that inode and mode",
):
    assert marker in write_rows, f"Android profile store lost private atomic-write marker: {marker}"
rename_tail = write_rows.split("Os.rename(tmp.getAbsolutePath(), file.getAbsolutePath())", 1)[1]
assert "Os.chmod(file.getAbsolutePath(), 0600)" not in rename_tail, "Android profile store performs fallible chmod after commit"
assert "requirePrivateRegularFile(file)" not in rename_tail, "Android profile store performs fallible validation after commit"
assert ".delete()" not in write_rows.split("Os.rename", 1)[0], "Android profile store deletes authoritative state before replacement"
print("Android connection-profile atomic adoption contract: PASS")
