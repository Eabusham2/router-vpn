#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REL = "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java"
PATH = ROOT / REL


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, text=True, check=check)


def commit(message: str) -> None:
    run("git", "add", "--", REL)
    status = run("git", "diff", "--cached", "--quiet", check=False)
    if status.returncode == 0:
        return
    if status.returncode != 1:
        raise SystemExit(f"git diff failed: {status.returncode}")
    run("git", "commit", "-m", message)


def replace_once_or_verify(text: str, old: str, new: str, label: str) -> str:
    old_count = text.count(old)
    new_count = text.count(new)
    if old_count == 1 and new_count == 0:
        return text.replace(old, new, 1)
    if old_count == 0 and new_count == 1:
        return text
    raise SystemExit(f"{label} drift: old={old_count} new={new_count}")


def atomic_store() -> None:
    text = PATH.read_text(encoding="utf-8")
    text = replace_once_or_verify(
        text,
        "import android.content.SharedPreferences;\n",
        "import android.content.SharedPreferences;\nimport android.system.Os;\nimport android.system.OsConstants;\nimport android.system.StructStat;\n",
        "Android private-store imports",
    )
    text = replace_once_or_verify(
        text,
        '''        if (!file.exists()) return new JSONArray();
        if (!file.isFile() || file.length() <= 0 || file.length() > MAX_STORE) {
            throw new IllegalStateException("Connection profile store is invalid or too large.");
        }
''',
        '''        if (!file.exists()) return new JSONArray();
        requirePrivateRegularFile(file);
        if (file.length() <= 0 || file.length() > MAX_STORE) {
            throw new IllegalStateException("Connection profile store is invalid or too large.");
        }
''',
        "Android profile read boundary",
    )

    old_write = re.compile(
        r"    private void writeRows\(JSONArray rows\)throws Exception\{.*?\}\n\n"
        r"(?=    private List<String> customLayers)",
        re.DOTALL,
    )
    new_write = '''    private void writeRows(JSONArray rows) throws Exception {
        byte[] raw = (new JSONObject()
                .put("schema_version", SCHEMA_VERSION)
                .put("profiles", rows)
                .toString(2) + "\\n").getBytes(StandardCharsets.UTF_8);
        if (raw.length > MAX_STORE) throw new IllegalStateException("Connection profile store exceeds safety limit.");

        File parent = file.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs())) {
            throw new IllegalStateException("Connection profile directory is unavailable.");
        }
        File tmp = new File(parent, ".connection-profiles-" + randomHex(12) + ".tmp");
        boolean adopted = false;
        try {
            if (!tmp.createNewFile()) throw new IllegalStateException("Cannot create private profile temporary file.");
            Os.chmod(tmp.getAbsolutePath(), 0600);
            try (FileOutputStream out = new FileOutputStream(tmp, false)) {
                out.write(raw);
                out.flush();
                out.getFD().sync();
            }
            requirePrivateRegularFile(tmp);
            if (file.exists()) requirePrivateRegularFile(file);
            // POSIX rename is atomic and replaces the old same-filesystem file.
            // Never delete the authoritative store before the replacement exists.
            Os.rename(tmp.getAbsolutePath(), file.getAbsolutePath());
            adopted = true;
            Os.chmod(file.getAbsolutePath(), 0600);
            requirePrivateRegularFile(file);
        } finally {
            if (!adopted && tmp.exists() && !tmp.delete()) tmp.deleteOnExit();
        }
    }

    private static void requirePrivateRegularFile(File target) throws Exception {
        StructStat stat = Os.lstat(target.getAbsolutePath());
        int kind = stat.st_mode & OsConstants.S_IFMT;
        if (kind != OsConstants.S_IFREG) {
            throw new IllegalStateException("Connection profile state is not a regular file.");
        }
        if ((stat.st_mode & 0077) != 0) {
            throw new IllegalStateException("Connection profile state permissions are not private.");
        }
    }

'''
    old_count = len(old_write.findall(text))
    new_count = text.count("private static void requirePrivateRegularFile")
    if old_count == 1 and new_count == 0:
        text = old_write.sub(new_write, text, count=1)
    elif old_count == 0 and new_count == 1:
        pass
    else:
        raise SystemExit(f"Android profile writer drift: old={old_count} new={new_count}")

    PATH.write_text(text, encoding="utf-8")
    commit("Make Android profile storage atomic and private [skip ci]")


def transactional_load() -> None:
    text = PATH.read_text(encoding="utf-8")
    text = replace_once_or_verify(
        text,
        "        byte[] updatedBundle=null;\n",
        "        byte[] originalBundle=null,updatedBundle=null;\n",
        "Android profile rollback snapshot declaration",
    )
    text = replace_once_or_verify(
        text,
        '''            AndroidNodeStore.Node selected=findNode(nodeId);if(selected==null)throw new IllegalStateException("Saved Router node is no longer linked.");
            JSONObject bundle=readBundle(selected.file),profile=selectedProfile(bundle);if(profile==null)throw new IllegalStateException("Saved Router node bundle has no selected profile.");
''',
        '''            AndroidNodeStore.Node selected=findNode(nodeId);if(selected==null)throw new IllegalStateException("Saved Router node is no longer linked.");
            originalBundle=readLimited(selected.file,AndroidNodeStore.MAX_BUNDLE);
            JSONObject bundle=new JSONObject(new String(originalBundle,StandardCharsets.UTF_8)),profile=selectedProfile(bundle);if(profile==null)throw new IllegalStateException("Saved Router node bundle has no selected profile.");
''',
        "Android profile rollback snapshot",
    )
    text = replace_once_or_verify(
        text,
        '''        if(preparedCustom!=null)edit.putString(CUSTOM_KEY,preparedCustom);
        edit.apply();
        return toRecord(row);
''',
        '''        if(preparedCustom!=null)edit.putString(CUSTOM_KEY,preparedCustom);
        if(!edit.commit()){
            String rollbackDetail="";
            if(originalBundle!=null){
                try{AndroidNodeStore.Node restored=nodes.importBundle(originalBundle);if(!nodeId.equals(restored.id))throw new IllegalStateException("restored node identity changed");}
                catch(Exception rollbackError){rollbackDetail=" Rollback also failed: "+rollbackError.getMessage();}
            }
            throw new IllegalStateException("Could not persist the loaded connection profile; prior Router node state was restored."+rollbackDetail);
        }
        return toRecord(row);
''',
        "Android synchronous profile adoption",
    )
    PATH.write_text(text, encoding="utf-8")
    commit("Rollback Android profile load on preference failure [skip ci]")


def cleanup() -> None:
    paths = [
        ".github/workflows/one-shot-android-profile-transactions.yml",
        ".github/scripts/apply-android-profile-transactions.py",
    ]
    for rel in paths:
        path = ROOT / rel
        if path.exists():
            path.unlink()
    run("git", "add", "-A", "--", *paths)
    status = run("git", "diff", "--cached", "--quiet", check=False)
    if status.returncode == 1:
        run("git", "commit", "-m", "Remove completed Android profile automation [skip ci]")


def main() -> int:
    atomic_store()
    transactional_load()
    run("git", "diff", "--check")
    cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
