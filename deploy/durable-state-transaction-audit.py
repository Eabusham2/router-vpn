#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def text(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing required durable-state source: {rel}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def require(rel: str, *markers: str) -> None:
    source = text(rel)
    for marker in markers:
        if marker not in source:
            errors.append(f"{rel}: missing durable-state marker {marker!r}")


def forbid(rel: str, *markers: str) -> None:
    source = text(rel)
    for marker in markers:
        if marker in source:
            errors.append(f"{rel}: forbidden durability regression marker {marker!r}")


def require_absent(rel: str) -> None:
    if (ROOT / rel).exists():
        errors.append(f"obsolete unsafe path must stay removed: {rel}")


def run_test(rel: str) -> None:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing durable-state behavior test: {rel}")
        return
    proc = subprocess.run([sys.executable, str(path)], cwd=ROOT, text=True, capture_output=True)
    if proc.returncode != 0:
        output = (proc.stdout + "\n" + proc.stderr).strip()
        errors.append(f"{rel}: behavior test failed: {output[-4000:]}")


# Client-side authoritative state: bounded private regular files, random
# same-directory temps, fsync-before-rename, and no post-rename false failure.
require(
    "cmd/client/private_store.go",
    "hardenPrivateRegular",
    "readPrivateRegular",
    "validatePrivateParent",
    "os.SameFile(opened, current)",
    "os.CreateTemp",
    "tmp.Sync()",
    "os.Rename(tmpPath, path)",
    "atomicWritePrivateTargetUnchanged",
)
require(
    "cmd/client/main.go",
    "beginMutationOperation",
    "previousProfiles := cloneRouterProfileStore",
    "a.rollbackProfilesLocked(previousProfiles)",
    "atomicWritePrivate(a.cfg.ProfilesFile",
)
require("cmd/client/connection_profiles.go", "readPrivateRegular", "atomicWritePrivate")
require("cmd/client/connection_profile_setup.go", "readPrivateRegular", "atomicWritePrivate")
require("cmd/client/strategy_modes.go", "readPrivateRegular", "atomicWritePrivate")
require("cmd/client/standard_exits.go", "readPrivateRegular", "atomicWritePrivate")
require("cmd/client/standard_exits_test.go", "TestStandardExitStoreRejectsSymlinkParent", "TestStandardExitStoreAtomicWriterLeavesNoTempFiles")
require("cmd/client/router_profile_transaction_test.go", "RollsRAMBackWhenPersistenceFails", "CompetingMutation")
require("cmd/client/private_store_test.go", "RejectsSymlinkTargets", "RejectsSymlinkParent", "RejectsOversizedRead", "TargetReplacementBeforeAdoption")

# Android linked-node and custom-exit stores contain private profile/credential
# data and therefore share one verified-inode, bounded, 0600, same-directory
# atomic publication primitive. They may never delete the authoritative target
# before adopting its replacement.
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidPrivateFileStore.java",
    "Os.fstat",
    "st_dev",
    "st_ino",
    "out.getFD().sync()",
    "requireTargetUnchanged",
    "Os.rename(temporary.getAbsolutePath(), target.getAbsolutePath())",
    "perform a fallible chmod/stat after commit",
)
forbid(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStore.java",
    "target.delete()",
    "renameTo(target)",
)
forbid(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java",
    "storeFile.delete()",
    "renameTo(storeFile)",
)
run_test("android/test_android_private_file_store_contract.py")

# iOS whole-connection/profile metadata is app-private authoritative state.
# The verified temporary file is flushed and atomically adopted; the operation
# must not throw after replacement merely to reapply metadata already owned by
# the adopted inode.
require(
    "ios/RouterVPN/App/IOSPrivateJSONStore.swift",
    "try handle.synchronize()",
    "try manager.setAttributes(attributes, ofItemAtPath: temporary.path)",
    "manager.replaceItemAt(destination, withItemAt: temporary",
    "manager.moveItem(at: temporary, to: destination)",
    "The verified temporary file already owns the required protection",
)
forbid(
    "ios/RouterVPN/App/IOSPrivateJSONStore.swift",
    "try manager.setAttributes(attributes, ofItemAtPath: destination.path)",
)
run_test("ios/RouterVPN/test_private_json_store_contract.py")
run_test("ios/RouterVPN/test_connection_profile_store_fail_closed.py")

# Android whole-connection profiles share the same verified-inode primitive as
# linked nodes/exits and retain node-policy rollback when preference persistence
# fails. No bespoke delete/rename writer may bypass that contract.
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java",
    "SCHEMA_VERSION=4",
    'FILE_NAME="connection-profiles-v4.json", LEGACY_FILE_NAME="connection-profiles-v1.json"',
    "AndroidPrivateFileStore.read(source, MAX_STORE)",
    "AndroidPrivateFileStore.remove(legacyFile, MAX_STORE)",
    "AndroidPrivateFileStore.write(file, raw, MAX_STORE)",
    "nodes.importBundle(originalBundle)",
)
forbid(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java",
    "Os.rename(",
    "FileOutputStream",
    "requirePrivateRegularFile",
)
run_test("android/test_android_connection_profiles_contract.py")
run_test("android/test_android_node_store_transaction_contract.py")

# MTU adoption remains a two-phase live/session transaction and persistence
# failure must restore the live interface/in-memory state. Runtime-profile MTU
# edits are disposable pre-connect state, but still reject path redirection and
# restore earlier files if a later adoption fails.
require(
    "cmd/client/mtu_retest.go",
    "mtuRetestSnapshot",
    "captureMTULiveSnapshot",
    "validateMTUMeasurementAgainstLiveSnapshot",
    "failMTURetestWithLiveRollback",
    "restoreMTULiveSnapshot",
    "restoreMTUMeasurementFields",
)
require("cmd/client/mtu_retest_test.go", "stale", "rollback")
require(
    "modes/prepare-runtime-profile.py",
    "runtime profile file changed during open",
    "runtime profile source contains symlink",
    "os.rename(dest, backup)",
    "os.rename(stage, dest)",
)
require(
    "modes/test_prepare_runtime_profile.py",
    "runtime profile staging followed a source symlink",
    "runtime staging followed a symlink run directory",
    "failed runtime tree adoption did not restore prior tree",
    "run-combined.sh",
)
require("modes/run-combined.sh", "prepare-runtime-profile.py", "runtime-pids.py")
forbid("modes/run-combined.sh", 'cp -a "$SOURCE" "$CONF"', "for p in root.glob('*.json')")

# Background process ownership is recovery state too. Every launcher that starts
# long-lived children must use the verified PID registry (PID + process-start
# + command identity) rather than trusting reusable raw numeric PID files.
require(
    "modes/runtime-pids.py",
    "process_start",
    "first_start = process_start(pid)",
    "second_start = process_start(pid)",
    "current_command == expected_command",
    "first_start == second_start",
    "chunks: list[bytes] = []",
    "def verified_mode",
    "command_sha256",
    "runtime PID registry changed during open",
    "runtime PID target changed before adoption",
)
require(
    "modes/test_runtime²È="25Ñ•}Á…É•¹Ğˆ°(€€€€‰½Ì¹Á…Ñ ¹Í…µ•ÍÑ…Ğ¡½Á•¹•°ÕÉÉ•¹Ğ¤ˆ°(€€€€‰µÕÍĞ‰”µ½‘”€ÀØÀÀˆ°(€€€€‰…Ñ½µ¥ŒµÁÉ¥Ù…Ñ”µ‰…Ñ ¹Áäˆ°(€€€€‰½¹™±¥ÑÌİ¥Ñ ]¥É•Õ…ÉÍ•ÉÙ•È¥‘•¹Ñ¥Ñäˆ°(¤)É•ÅÕ¥É” (€€€€‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ñ•ÍÑ}¹½‘•}ÁÉ½½™}ÁÉ¥Ù…Ñ•}ÍÑ…Ñ”¹Áäˆ°(€€€€‰‰É½…É½ÕÑ•Èµ…•¹Ğ¥‘•¹Ñ¥ÑäÍÑ…Ñ”İ…Ì…•ÁÑ•ˆ°(€€€€‰Íåµ±¥¹­A…É•¹Ğˆ°(€€€€‰]¥É•Õ…É¥‘•¹Ñ¥ÑäÍ½ÕÉ”É•Á±…•µ•¹ĞÉ…”İ…Ì…•ÁÑ•ˆ°(¤)É•ÅÕ¥É” (€€€€‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½ÁÉ•Í•ÉÙ”µ•¹•É…Ñ•µÍÑ…Ñ”¹Áäˆ°(€€€€‰}•¹ÍÕÉ•}ÁÉ¥Ù…Ñ•}Á…É•¹Ğˆ°(€€€€‰µÕÍĞ‰”µ½‘”€ÀØÀÀˆ°(€€€€‰½Ì¹Á…Ñ ¹Í…µ•ÍÑ…Ğ¡½Á•¹•°ÕÉÉ•¹Ğ¤ˆ°(€€€€‰É•™ÕÍ¥¹œ¹½¸µÉ•Õ±…È½Íåµ±¥¹¬ˆ°(€€€€‰½ÉÉÕÁĞ)M=8ˆ°(€€€€‰•áÁ•Ñ••á…Ñ±ä½¹”ÁÉ•Í•ÉÙ•ˆ°(¤)É•ÅÕ¥É” (€€€€‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ñ•ÍÑ}ÁÉ•Í•ÉÙ•}•¹•É…Ñ•‘}ÍÑ…Ñ”¹Áäˆ°(€€€€‰½ÉÉÕÁĞÁÉ•Í•ÉÙ•ÑÉ…¹ÍÁ½ÉĞÍÑ…Ñ”ˆ°(€€€€‰…µ‰¥Õ½ÕÌÁÉ•Í•ÉÙ•Q1LÉ•‘•¹Ñ¥…±Ìˆ°(€€€€‰Íåµ±¥¹¬ÁÉ•Í•ÉÙ•ÑÉ…¹ÍÁ½ÉĞÍÑ…Ñ”ˆ°(€€€€‰Íåµ±¥¹¬Á…É•¹Ğ™½ÈÁÉ•Í•ÉÙ•ÑÉ…¹ÍÁ½ÉĞÍÑ…Ñ”İ…Ì…•ÁÑ•ˆ°(€€€€‰‰É½…µÁ•Éµ¥ÍÍ¥½¸ÁÉ•Í•ÉÙ•É•‘•¹Ñ¥…°ÍÑ…Ñ”İ…Ì…•ÁÑ•ˆ°(€€€€‰ÁÉ•Í•ÉÙ•É•‘•¹Ñ¥…°™¥±”É•Á±…•µ•¹ĞÉ…”İ…Ì…•ÁÑ•ˆ°(¤)É•ÅÕ¥É” ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½•¹•É…Ñ”µÑÉ…¹ÍÁ½ÉÑÌ¹Í ˆ°€‰É•™ÕÍ¥¹œÍ¥±•¹Ğˆ°€‰AI%YQ}	Q ˆ°€‰ÁÉ¥Ù…Ñ”‰…Ñ ¡•±Á•Èˆ¤)É•ÅÕ¥É” ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½•¹•É…Ñ”µáÉ…äµÁÄ¹Í ˆ°€‰É•™ÕÍ¥¹œÍ¥±•¹Ğˆ°€‰Y…±¥‘…Ñ”Ñ¡”½µÁ±•Ñ”…¹‘¥‘…Ñ”•¹•É…Ñ¥½¸ˆ°€‰AI%YQ}	Q ˆ¤)É•ÅÕ¥É” ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½•¹•É…Ñ”µÑ±Ìµ…±Ñ•É¹…Ñ•Ì¹Í ˆ°€‰É•™ÕÍ¥¹œÍ¥±•¹Ğˆ°€‰Y…±¥‘…Ñ”•Ù•Éä…¹‘¥‘…Ñ”ˆ°€‰AI%YQ}	Q ˆ¤)É•ÅÕ¥É” ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½•¹•É…Ñ”µ…ÕàµÁÉ½á¥•Ì¹Áäˆ°€‰É•™ÕÍ¥¹œÍ¥±•¹ĞÉ•‘•¹Ñ¥…°É½Ñ…Ñ¥½¸ˆ°€‰…Ñ½µ¥ŒµÁÉ¥Ù…Ñ”µ‰…Ñ ¹Áäˆ¤)É•ÅÕ¥É” ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½•¹•É…Ñ”µÉ½Í•¹Á…ÍÌ¹Í ˆ°€‰I•™ÕÍ¥¹œÑ¼½Ù•ÉİÉ¥Ñ”•á¥ÍÑ¥¹œI½Í•¹Á…ÍÌ¥‘•¹Ñ¥Ñäˆ°€‰AI%YQ}	Q ˆ¤)É•ÅÕ¥É” ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½•¹ÍÕÉ”µÉ½Í•¹Á…ÍÌ¹Í ˆ°€‰MQQ}!1AHˆ°€ÁÉ½‰”€ˆ‘	Mˆ€ˆ°€É•™É•Í €ˆ‘	Mˆ€ˆ‘9A=%9Pˆ€ˆ‘IA}A=IPˆœ¤)É•ÅÕ¥É” ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½É½Í•¹Á…ÍÌµÁÉ¥Ù…Ñ”µÍÑ…Ñ”¹Áäˆ°€‰Á…ÉÑ¥…°½Õ¹Í…™”ˆ°€‰…Ñ½µ¥ŒµÁÉ¥Ù…Ñ”µ‰…Ñ ¹Áäˆ°€‰É•™ÕÍ¥¹œÍ¥±•¹Ğ­•äÉ½Ñ…Ñ¥½¸ˆ¤)É•ÅÕ¥É” ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½•¹•É…Ñ”µ…‘Ù…¹•µÁÉ½™¥±•Ì¹Í ˆ°€‰É•™ÕÍ¥¹œÍ¥±•¹ĞI1%QdÉ•‘•¹Ñ¥…°É½Ñ…Ñ¥½¸ˆ°€‰Y…±¥‘…Ñ”Ñ¡”•¹Ñ¥É”…¹‘¥‘…Ñ”ÑÉ•”ˆ°€‰AI%YQ}	Q ˆ¤)É•ÅÕ¥É” ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½•¹¡…¹”µµ…àµÁÄ¹Áäˆ°€‰…Ñ½µ¥ŒµÁÉ¥Ù…Ñ”µ‰…Ñ ¹Áäˆ°€‰½¹”ÁÉ¥Ù…Ñ”ÑÉ…¹Í…Ñ¥½¸ˆ¤)É•ÅÕ¥É” ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½İÉ…Àµá¡ÑÑÀµÑÕ¸¹Áäˆ°€‰‰•™½É”…Ñ½µ¥Œ…‘½ÁÑ¥½¸ˆ°€‰…Ñ½µ¥ŒµÁÉ¥Ù…Ñ”µİÉ¥Ñ”¹Áäˆ¤)É•ÅÕ¥É” ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½•¹•É…Ñ”µÍÑ…¬µÁÉ½™¥±•Ì¹Áäˆ°€‰…Ñ½µ¥ŒµÁÉ¥Ù…Ñ”µ‰…Ñ ¹Áäˆ°€‰ÍÑ…¬µÁÉ½™¥±•Ì´ˆ¤)™½É‰¥ ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½•¹•É…Ñ”µÑÉ…¹ÍÁ½ÉÑÌ¹Í ˆ°€‰ÁÉ•Í•ÉÙ”µ•¹•É…Ñ•µÍÑ…Ñ”¹ÁäÑÉ…¹ÍÁ½ÉÑÌpˆ‘	Mpˆ€Èø½‘•Ø½¹Õ±°ñğÑÉÕ”ˆ¤)™½É‰¥ ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½•¹•É…Ñ”µáÉ…äµÁÄ¹Í ˆ°€‰ÁÉ•Í•ÉÙ”µ•¹•É…Ñ•µÍÑ…Ñ”¹ÁäáÉ…äpˆ‘	Mpˆ€Èø½‘•Ø½¹Õ±°ñğÑÉÕ”ˆ¤)™½É‰¥ ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½•¹•É…Ñ”µÑ±Ìµ…±Ñ•É¹…Ñ•Ì¹Í ˆ°€‰ÁÉ•Í•ÉÙ”µ•¹•É…Ñ•µÍÑ…Ñ”¹ÁäÑ±Ìpˆ‘	Mpˆ€Èø½‘•Ø½¹Õ±°ñğÑÉÕ”ˆ¤)™½É‰¥ ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½•¹•É…Ñ”µ…‘Ù…¹•µÁÉ½™¥±•Ì¹Í ˆ°€‰ÁÉ•Í•ÉÙ”µ•¹•É…Ñ•µÍÑ…Ñ”¹Áä…‘Ù…¹•pˆ‘	Mpˆ€Èø½‘•Ø½¹Õ±°ñğÑÉÕ”ˆ¤((ŒÉ•Í ¥¹¥Ğ°™¥¹…±¥é…Ñ¥½¸°…¹ÕÁÉ…‘”Á…Ñ¡ÌÁÕ‰±¥Í É•‘•¹Ñ¥…°µ‰•…É¥¹œÍÑ…Ñ”(ŒÑ¡É½Õ Ñ¡”Í…µ”¡•±Á•ÉÌ°Ù…±¥‘…Ñ”Ñ¡”½µÁ±•Ñ”ÁÉ¥Ù…Ñ”ÍÑ…Ñ”ÑÉ•”‰•™½É”…¹ä(Œ±•…¹ÕÀ½µÕÑ…Ñ¥½¸°…¹½¹±äµ…É¬½µÁ±•Ñ¥½¸…™Ñ•ÈÉÕ¹Ñ¥µ”…ÁÁ±¥…Ñ¥½¸¸)É•ÅÕ¥É” (€€€€‰Í•ÉÙ•È½¥¹¥Ğ½¹½¹¥¹Ñ•É…Ñ¥Ù”¹Í ˆ°(€€€€‰…Ñ½µ¥ŒµÁÉ¥Ù…Ñ”µİÉ¥Ñ”¹Áäˆ°(€€€€‰AI%YQ}%Hô½ÍÉŒ½Í•ÉÙ•È½ÍÉ¥ÁÑÌ½ÁÉ¥Ù…Ñ”µ‘¥É•Ñ½Éä¹Áäˆ°(€€€€‰YI%%}Iô½ÍÉŒ½Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ù•É¥™¥•µÉ•Õ±…ÈµÉ•…¹Áäˆ°(€€€€ÁåÑ¡½¸Ì€ˆ‘AI%YQ}%Hˆ€ˆ‘‘¥Èˆœ°(€€€€ÁåÑ¡½¸Ì€ˆ‘YI%%}Iˆ€´µÁÉ¥Ù…Ñ”€ˆ‘	M¼¹¥¹¥Ñ¥…±¥é•ˆœ°(€€€€‰É•™ÕÍ¥¹œÉ•‘•¹Ñ¥…°É••¹•É…Ñ¥½¸ˆ°(€€€€‰I9Q%1L¹ÑáĞˆ°(€€€€ˆ¹¥¹¥Ñ¥…±¥é•ˆ°(¤)É•ÅÕ¥É” (€€€€‰Í•ÉÙ•È½™¥¹…±¥é”½™¥¹…±¥é”¹Í ˆ°(€€€€‰…Ñ½µ¥ŒµÁÉ¥Ù…Ñ”µİÉ¥Ñ”¹Áäˆ°(€€€€‰…Ñ½µ¥ŒµÁÉ¥Ù…Ñ”µ‰…Ñ ¹Áäˆ°(€€€€‰AI%YQ}%Hô½ÍÉŒ½Í•ÉÙ•È½ÍÉ¥ÁÑÌ½ÁÉ¥Ù…Ñ”µ‘¥É•Ñ½Éä¹Áäˆ°(€€€€‰YI%%}Iô½ÍÉŒ½Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ù•É¥™¥•µÉ•Õ±…ÈµÉ•…¹Áäˆ°(€€€€ÁåÑ¡½¸Ì€ˆ‘AI%YQ}%Hˆ€ˆ‘‘¥Èˆœ°(€€€€ÁåÑ¡½¸Ì€ˆ‘YI%%}Iˆ€´µÁÉ¥Ù…Ñ”€ˆ‘É•ÅÕ¥É•ˆœ°(€€€€‰I9Q%1L¹ÑáĞˆ°(€€€€ˆ¹™¥¹…±¥é•ˆ°(¤)É•ÅÕ¥É” (€€€€‰Í•ÉÙ•È½™¥¹…±¥é”½ÕÁÉ…‘”µÍ…™”¹Í ˆ°(€€€€‰…Ñ½µ¥ŒµÁÉ¥Ù…Ñ”µİÉ¥Ñ”¹Áäˆ°(€€€€‰…Ñ½µ¥ŒµÁÉ¥Ù…Ñ”µ‰…Ñ ¹Áäˆ°(€€€€‰AI%YQ}%Hô½ÍÉŒ½Í•ÉÙ•È½ÍÉ¥ÁÑÌ½ÁÉ¥Ù…Ñ”µ‘¥É•Ñ½Éä¹Áäˆ°(€€€€‰YI%%}Iô½ÍÉŒ½Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ù•É¥™¥•µÉ•Õ±…ÈµÉ•…¹Áäˆ°(€€€€ÁåÑ¡½¸Ì€ˆ‘AI%YQ}%Hˆ€ˆ‘‘¥Èˆœ°(€€€ÁåÑ¡½¸Ì€ˆ‘YI%%}Iˆ€´µÁÉ¥Ù…Ñ”€ˆ‘É•ÅÕ¥É•ˆœ°(€€€€‰I9Q%1L¹ÑáĞˆ°(€€€€ˆ¹™¥¹…±¥é•ˆ°(¤)™½É‰¥ ‰Í•ÉÙ•È½™¥¹…±¥é”½™¥¹…±¥é”¹Í ˆ°€…Ğ€øˆ‘	M½±¥•¹Ğµ‰Õ¹‘±”½I9Q%1L¹ÑáĞˆœ°€Ñ½Õ €ˆ‘	M¼¹™¥¹…±¥é•ˆœ¤)™½É‰¥ ‰Í•ÉÙ•È½™¥¹…±¥é”½ÕÁÉ…‘”µÍ…™”¹Í ˆ°€…Ğ€øˆ‘	M½±¥•¹Ğµ‰Õ¹‘±”½I9Q%1L¹ÑáĞˆœ°€Ñ½Õ €ˆ‘	M¼¹™¥¹…±¥é•ˆœ¤()¥¹¥Ñ}‰½‘ä€ôÑ•áĞ ‰Í•ÉÙ•È½¥¹¥Ğ½¹½¹¥¹Ñ•É…Ñ¥Ù”¹Í ˆ¤)¥¹¥Ñ}‘¥È€ô¥¹¥Ñ}‰½‘ä¹™¥¹ ÁåÑ¡½¸Ì€ˆ‘AI%YQ}%Hˆ€ˆ‘‘¥Èˆœ¤)¥¹¥Ñ}ÁÕÉ”€ô¥¹¥Ñ}‰½‘ä¹™¥¹ É´€µ˜€ˆ‘	M½‘½İ¹±½…‘Ì½É½ÕÑ•ÈµÙÁ¸µ±¥•¹Ğµ‰Õ¹‘±”¹é¥Àˆœ¤)¥¹¥Ñ}…ÁÁ±ä€ô¥¹¥Ñ}‰½‘ä¹É™¥¹ œ½ÍÉŒ½Í•ÉÙ•È½ÍÉ¥ÁÑÌ½…ÁÁ±äµÉÕ¹Ñ¥µ”¹Í €ˆ‘]9}%9QIˆ€ˆ‘19}%Hˆœ¤)¥¹¥Ñ}µ…É­•È€ô¥¹¥Ñ}‰½‘ä¹É™¥¹ ÁÉ¥¹Ñ˜p¥¹¥Ñ¥…±¥é•‘qq¹pœğÁåÑ¡½¸Ì€ˆ‘AI%YQ}]I%Qˆ€ˆ‘	M¼¹¥¹¥Ñ¥…±¥é•ˆœ¤)¥˜µ¥¸¡¥¹¥Ñ}‘¥È°¥¹¥Ñ}ÁÕÉ”°¥¹¥Ñ}…ÁÁ±ä°¥¹¥Ñ}µ…É­•È¤€ğ€À½È¥¹¥Ñ}‘¥È€ø¥¹¥Ñ}ÁÕÉ”½È¥¹¥Ñ}…ÁÁ±ä€ø¥¹¥Ñ}µ…É­•Èè(€€€•ÉÉ½ÉÌ¹…ÁÁ•¹ ‰Í•ÉÙ•È½¥¹¥Ğ½¹½¹¥¹Ñ•É…Ñ¥Ù”¹Í èÁÉ¥Ù…Ñ”µ‘¥É•Ñ½Éä½¥¹¥Ñ¥…±¥é…Ñ¥½¸½É‘•É¥¹œÉ•É•ÍÍ•ˆ¤()™½ÈÉ•°°™¥ÉÍÑ}µÕÑ…Ñ¥½¸¥¸€ (€€€€ ‰Í•ÉÙ•È½™¥¹…±¥é”½™¥¹…±¥é”¹Í ˆ°€‰…Í €½ÍÉŒ½Í•ÉÙ•È½™¥¹…±¥é”½Íå¹Œµ±¥•¹ĞµÉÕ¹Ñ¥µ”¹Í €ˆ‘	Mˆœ¤°(€€€€ ‰Í•ÉÙ•È½™¥¹…±¥é”½ÕÁÉ…‘”µÍ…™”¹Í ˆ°€‰…Í €½ÍÉŒ½Í•ÉÙ•È½™¥¹…±¥é”½Íå¹Œµ±¥•¹ĞµÉÕ¹Ñ¥µ”¹Í €ˆ‘	Mˆœ¤(¤è(€€€‰½‘ä€ôÑ•áĞ¡É•°¤(€€€ÁÉ¥Ù…Ñ•}‘¥É}Á½Ì€ô‰½‘ä¹™¥¹ ÁåÑ¡½¸Ì€ˆ‘AI%YQ}%Hˆ€ˆ‘‘¥Èˆœ¤(€€€µÕÑ…Ñ¥½¹}Á½Ì€ô‰½‘ä¹™¥¹¡™¥ÉÍÑ}µÕÑ…Ñ¥½¸¤(€€€…ÁÁ±å}Á½Ì€ô‰½‘ä¹É™¥¹ ‰…Í €½ÍÉŒ½Í•ÉÙ•È½ÍÉ¥ÁÑÌ½…ÁÁ±äµÉÕ¹Ñ¥µ”¹Í €ˆ‘]9}%9QIˆ€ˆ‘19}%Hˆœ¤(€€€™¥¹…±¥é•‘}Á½Ì€ô‰½‘ä¹É™¥¹ ÁÉ¥¹Ñ˜p™¥¹…±¥é•‘qq¹pœğÁåÑ¡½¸Ì€ˆ‘AI%YQ}]I%Qˆ€ˆ‘	M¼¹™¥¹…±¥é•ˆœ¤(€€€¥˜µ¥¸¡ÁÉ¥Ù…Ñ•}‘¥É}Á½Ì°µÕÑ…Ñ¥½¹}Á½Ì°…ÁÁ±å}Á½Ì°™¥¹…±¥é•‘}Á½Ì¤€ğ€Àè(€€€€€€€•ÉÉ½ÉÌ¹…ÁÁ•¹¡˜‰íÉ•±ôè™¥¹…±¥é…Ñ¥½¸½É‘•É¥¹œµ…É­•ÉÌ…É”¥¹½µÁ±•Ñ”ˆ¤(€€€•±Í”è(€€€€€€€¥˜ÁÉ¥Ù…Ñ•}‘¥É}Á½Ì€øµÕÑ…Ñ¥½¹}Á½Ìè(€€€€€€€€€€€•ÉÉ½ÉÌ¹…ÁÁ•¹¡˜‰íÉ•±ôèÁÉ¥Ù…Ñ”µ‘¥É•Ñ½ÉäÙ…±¥‘…Ñ¥½¸¡…ÁÁ•¹Ì…™Ñ•ÈÍÑ…Ñ”µÕÑ…Ñ¥½¸‰•¥¹Ìˆ¤(€€€€€€€¥˜…ÁÁ±å}Á½Ì€ø™¥¹…±¥é•‘}Á½Ìè(€€€€€€€€€€€•ÉÉ½ÉÌ¹…ÁÁ•¹¡˜‰íÉ•±ôè™¥¹…±¥é•µ…É­•È¥ÌÁÕ‰±¥Í¡•‰•™½É”ÉÕ¹Ñ¥µ”…ÁÁ±¥…Ñ¥½¸ÍÕ••‘Ìˆ¤((ŒM•ÑÕÀ…ÍÍ•ÑÌ…É”‘•É¥Ù•ÁÉ¥Ù…Ñ”ÁÉ•Í•¹Ñ…Ñ¥½¸‘…Ñ„½¹Ñ…¥¹¥¹œ¥µÁ½ÉĞÁ…å±½…‘Ì°(Œ¹½ĞÍÑ…‰±”¥‘•¹Ñ¥Ñä½È…Ñ¥Ù”Á½±¥ä¸Q¡•ä…É”‘•±¥‰•É…Ñ•±ä•á±Õ‘•™É½´Ñ¡”(Œ…ÕÑ¡½É¥Ñ…Ñ¥Ù”µÍÑ…Ñ”ÑÉ…¹Í…Ñ¥½¸Í•Ğì™…¥±ÕÉ”…‰½ÉÑÌ™¥¹…±¥é…Ñ¥½¸…¹Ñ¡•ä…É”(ŒÉ••¹•É…Ñ•™É½´Ñ¡”…±É•…‘äµÑÉ…¹Í…Ñ¥½¹…°ÁÉ¥Ù…Ñ”Í½ÕÉ”‰Õ¹‘±”¸)É•ÅÕ¥É” ‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½•¹•É…Ñ”µÍ•ÑÕÀµ…ÍÍ•ÑÌ¹Áäˆ°€‰ÁÉ¥Ù…Ñ”É½ÕÑ•ÈÉ•‘•¹Ñ¥…±Ìˆ°€¡µ½ Á¼ØÀÀ¤œ¤((Œá•ÕÑ”Ñ¡”™½ÕÍ•AåÑ¡½¸‰•¡…Ù¥½È½¹ÑÉ…ÑÌ™É½´Ñ¡”…ÕÑ¡½É¥Ñ…Ñ¥Ù”…Ñ”¸)™½ÈÑ•ÍĞ¥¸€ (€€€€‰Í•ÉÙ•È½™¥¹…±¥é”½Ñ•ÍÑ}Íå¹}•¹‘Á½¥¹Ğ¹Áäˆ°(€€€€‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ñ•ÍÑ}…Ñ½µ¥}ÁÉ¥Ù…Ñ•}ÁÕ‰±¥…Ñ¥½¸¹Áäˆ°(€€€€‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ñ•ÍÑ}‘¹Í}‰•¹¡µ…É­}Á•ÉÍ¥ÍÑ•¹”¹Áäˆ°(€€€€‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ñ•ÍÑ}Í•ÑÕÁ}…ÕÑ ¹Áäˆ°(€€€€‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ñ•ÍÑ}¹½‘•}ÁÉ½½™}ÁÉ¥Ù…Ñ•}ÍÑ…Ñ”¹Áäˆ°(€€€€‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ñ•ÍÑ}½¹™¥ÕÉ•}Á½ÉÑ…¥¹•É}ÕÁ‘…Ñ”¹Áäˆ°(€€€€‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ñ•ÍÑ}ÁÉ•Í•ÉÙ•}•¹•É…Ñ•‘}ÍÑ…Ñ”¹Áäˆ°(€€€€‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ñ•ÍÑ}É•…Ñ•}‰Õ¹‘±•}ÑÉ…¹Í…Ñ¥½¸¹Áäˆ°(€€€€‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ñ•ÍÑ}Í•ÑÕÁ}•¹•É…Ñ¥½¹}ÑÉ…¹Í…Ñ¥½¸¹Áäˆ°(€€€€‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ñ•ÍÑ}¥¹ÍÑ…±±}ÍÑ…Ñ”¹Áäˆ°(€€€€‰Í•ÉÙ•È½ÍÉ¥ÁÑÌ½Ñ•ÍÑ}Ù•É¥™¥•‘}É•Õ±…É}É•…¹Áäˆ°(€€€€‰µ½‘•Ì½Ñ•ÍÑ}ÉÕ¹Ñ¥µ•}Á¥‘Ì¹Áäˆ°(€€€€‰µ½‘•Ì½Ñ•ÍÑ}ÍÑ½Á}µ½‘•}Á¥‘}½İ¹•ÉÍ¡¥À¹Áäˆ°(€€€€‰µ½‘•Ì½Ñ•ÍÑ}ÉÕ¹Ñ¥µ•}½¹™¥œ¹Áäˆ°(€€€€‰µ½‘•Ì½Ñ•ÍÑ}ÁÉ•Á…É•}ÉÕ¹Ñ¥µ•}ÁÉ½™¥±”¹Áäˆ°(¤è(€€€ÉÕ¹}Ñ•ÍĞ¡Ñ•ÍĞ¤()¥˜•ÉÉ½ÉÌè(€€€ÁÉ¥¹Ğ ‰ÕÉ…‰±”µÍÑ…Ñ”ÑÉ…¹Í…Ñ¥½¸…Õ‘¥Ğè%0ˆ°™¥±”õÍåÌ¹ÍÑ‘•ÉÈ¤(€€€™½È•ÉÉ½È¥¸•ÉÉ½ÉÌè(€€€€€€€ÁÉ¥¹Ğ¡˜ˆ€´í•ÉÉ½Éôˆ°™¥±”õÍåÌ¹ÍÑ‘•ÉÈ¤(€€€É…¥Í”MåÍÑ•µá¥Ğ Ä¤()ÁÉ¥¹Ğ ‰ÕÉ…‰±”µÍÑ…Ñ”ÑÉ…¹Í…Ñ¥½¸…Õ‘¥ĞèAMLˆ¤(