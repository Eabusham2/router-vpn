#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
helper = (base / "AndroidPrivateFileStore.java").read_text(encoding="utf-8")
node = (base / "AndroidNodeStore.java").read_text(encoding="utf-8")
exits = (base / "AndroidStandardExitStore.java").read_text(encoding="utf-8")
for marker in (
    "Os.lstat",
    "Os.fstat",
    "st_dev",
    "st_ino",
    "temporary.createNewFile()",
    "Os.chmod(temporary.getAbsolutePath(), 0600)",
    "out.getFD().sync()",
    "requireTargetUnchanged",
    "Os.rename(temporary.getAbsolutePath(), target.getAbsolutePath())",
    "perform a fallible chmod/stat after commit",
):
    assert marker in helper, f"Android private-file primitive lost {marker}"
writer = helper[helper.index("    static void write("):helper.index("    static void remove(")]
rename_tail = writer.split("Os.rename(temporary.getAbsolutePath(), target.getAbsolutePath())", 1)[1]
assert "Os.chmod(target.getAbsolutePath()" not in rename_tail
assert "target.delete()" not in helper
for body, label in ((node, "node store"), (exits, "custom-exit store")):
    assert "AndroidPrivateFileStore.write" in body, f"{label} is not using shared private writer"
    assert "AndroidPrivateFileStore.read" in body, f"{label} is not using verified private reader"
    assert "renameTo(" not in body, f"{label} still uses Java renameTo"
    assert "&& !target.delete()" not in body and "&&!storeFile.delete()" not in body, f"{label} deletes authoritative state before replacement"
assert 'new File(parent, "." + target.getName() + ".tmp")' not in node
print("Android shared private-file store contract: PASS")
