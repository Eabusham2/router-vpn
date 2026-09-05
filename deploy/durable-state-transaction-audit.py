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

# Android whole-connection profiles use schema v4 but can migrate the exact
# known legacy v1 file. Reads therefore intentionally go through the selected
# source (v4 or legacy) while canonical writes always target the verified v4
# file. Legacy cleanup must also use the shared private-file primitive.
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java",
    "SCHEMA_VERSION=4",
    'FILE_NAME="connection-profiles-v4.json", LEGACY_FILE_NAME="connection-profiles-v1.json"',
    "AndroidPrivateFileStore.read(source, MAX_STORE)",
    "AndroidPrivateFileStore.write(file, raw, MAX_STORE)",
    "AndroidPrivateFileStore.remove(legacyFile, MAX_STORE)",
    "nodes.importBundle(originalBundle)",
)
forbid(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java",
    "Os.rename(",
    "FileOutputStream",
    "requirePrivateRegularFile",
)
run_test("android/test_android_connection_profile_store_contract.py")
run_test("android/test_android_node_store_transaction_contract.py")

# MTU adoption remains a two-phase live/session transaction. The controller now
# captures the exact live interface/family/original MTU before helper mutation
# and owns rollback itself, so timeout/cancellation can recover even if the
# helper process was killed before its own exception handler ran.
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
    "modes/test_runtime_pids.py",
    "wrong-start-token",
    "wrong_command",
    "verified_mode",
    "native-multihop-darwin.sh",
    "runtime PID registry followed a symlink target",
    "run-combined.sh",
    "Legacy plain numeric PID files are intentionally untrusted.",
    "Regular-file reads may legally return short chunks.",
    "PID reused between the first birth-token check",
    "short_read_records",
    "replacement-start-token",
)
for rel in ("modes/run-mode.sh", "modes/run-max.sh", "modes/run-pq.sh", "modes/run-xhttp.sh", "modes/run-combined.sh"):
    require(rel, 'runtime-pids.py" init', 'runtime-pids.py" record')
    forbid(rel, ': >"$RUN/$MODE.pids"', 'echo $! >>"$RUN/$MODE.pids"')

require(
    "modes/native-multihop-darwin.sh",
    'verified-mode "$ROOT" "$PID_MODE"',
    'record "$ROOT" "$PID_MODE" "$child"',
    "could not prove ownership of native macOS multihop process",
)
forbid("modes/native-multihop-darwin.sh", "native-multihop.pid", "PID_FILE")

require(
    "modes/stop-mode.sh",
    'verified "$ROOT"',
    'clear "$ROOT"',
    "refusing broad process-name cleanup",
)
forbid("modes/stop-mode.sh", 'cat "$RUN"/*.pids', "pkill -f")
require(
    "modes/test_stop_mode_pid_ownership.py",
    "legacy/raw PID registry",
    "kill_calls ==",
    "Verified central stop-mode PID ownership tests: OK",
)

# Per-session runtime config adoption must bind the exact target identity:
# a foreign regular file appearing/replacing the target after staging is not
# Router VPN state and must never be overwritten.
require(
    "modes/runtime-config.py",
    "runtime config target appeared before adoption",
    "runtime config target identity changed before adoption",
    "os.path.samestat(current, target)",
)
require(
    "modes/test_runtime_config.py",
    "runtime config replacement race was accepted",
    "foreign-replacement",
)

# Persistent Linux kill-switch state is authoritative recovery policy. Corrupt or
# redirected state must fail closed instead of being interpreted as "off".
require(
    "modes/kill-switch.py",
    "_private_regular_bytes",
    "cannot safely read persistent kill-switch state",
    "write_state",
    "remove_state",
    "kill-switch state target changed before adoption",
)
require(
    "modes/test_kill_switch.py",
    "router-vpn-killswitch-state-safety-",
    "router-vpn-killswitch-parent-safety-",
    "router-vpn-killswitch-remove-identity-",
    "router-vpn-killswitch-forceoff-swap-",
    "force-off",
)

# Windows strict kill-switch rollback state is equally authoritative. Its state
# tree must reject reparse redirects and use flushed random staging + atomic
# replacement; corrupt-state force-off is explicit local recovery.
require(
    "client/windows-kill-switch.ps1",
    "Assert-NoReparseAncestors",
    "Assert-SafeStateLeaf",
    "[IO.File]::Replace",
    "[Guid]::NewGuid().ToString('N')",
    "$stream.Flush($true)",
    "Remove-State -ForceRecovery",
    "emergency outbound-Allow recovery",
)
forbid(
    "client/windows-kill-switch.ps1",
    '$tmp = "$path.tmp"',
    "Move-Item -LiteralPath $tmp -Destination $path -Force",
)
require(
    "client/test-windows-kill-switch.ps1",
    "corrupt persistent Windows kill-switch state did not fail closed",
    "predictable Windows kill-switch state temp path returned",
    "Windows kill-switch plan/rollback/private-state contract: OK",
)

# Elevated Windows native helpers consume the controller-owned private node store
# through one read-only reparse-safe helper; they may never persist routers.json.
require(
    "client/Private-RouterVPN-State.ps1",
    "Assert-RouterVPNNoReparseAncestors",
    "Resolve-RouterVPNPrivateChild",
    "[IO.FileShare]::Read",
    "Get-RouterVPNProfileStore",
    "Get-RouterVPNSelectedProfile",
    "exposes no profile-store writer",
)
require(
    "client/test-private-router-vpn-state.ps1",
    "missing selected profile silently fell back",
    "corrupt profile store did not fail closed",
    "symlink profile store was accepted",
)
for rel in ("client/native-windows-mode.ps1", "client/native-wireguard-windows.ps1", "client/Optimize-RouterVPN-MTU.ps1"):
    require(rel, "Private-RouterVPN-State.ps1", "Get-RouterVPNSelectedProfile")
for rel in ("client/native-windows-mode.ps1", "client/native-wireguard-windows.ps1"):
    require(rel, "Assert-RouterVPNNoReparseAncestors")

# Native Windows runtime children use verified process records (PID + process
# start identity + executable path), never reusable raw numeric PID files.
require(
    "client/native-windows-mode.ps1",
    "native-windows-mode.process.json",
    "xray.process.json",
    "Write-RouterVPNProcessRecord",
    "Test-RouterVPNRecordedProcess",
    "Stop-RouterVPNRecordedProcess",
)
forbid(
    "client/native-windows-mode.ps1",
    "children.pids",
    "Stop-PidFile",
    "Set-Content -Encoding ASCII -LiteralPath $PidFile",
)
require(
    "client/native-wireguard-windows.ps1",
    "router-vpn-dns.process.json",
    "Write-RouterVPNProcessRecord",
    "Stop-RouterVPNRecordedProcess",
)
forbid(
    "client/native-wireguard-windows.ps1",
    "router-vpn-dns.pid",
    "Stop-Process -Id $pidValue",
)

# The Windows tray holds only an in-memory identity for the WPF UI process, but
# it must bind PID + start time + executable before any restore/close/fallback
# stop action. A recycled PID is treated as the UI having exited.
require(
    "client/RouterVPN-Windows-Tray.ps1",
    "Get-RouterVPNProcessIdentity",
    "start_time_utc_ticks",
    "executable_path",
    "Stop-Process -InputObject $ownedUi",
)
forbid(
    "client/RouterVPN-Windows-Tray.ps1",
    "Stop-Process -Id $UiPid",
)
for rel in (
    "client/native-windows-mode.ps1",
    "client/native-wireguard-windows.ps1",
    "client/Optimize-RouterVPN-MTU.ps1",
):
    forbid(rel, "Get-Content -Raw -LiteralPath $storePath", "foreach($item in @($store.profiles)){if($item)")
require(
    "client/Optimize-RouterVPN-MTU.ps1",
    "Resolve-RouterVPNPrivateChild",
    "Generated MTU path profile contains a reparse point.",
)
require(
    "client/Optimize-RouterVPN-MTU.ps1",
    "durable_adoption=$false",
    "Router VPN Go controller /api/mtu/retest",
)
forbid(
    "client/Optimize-RouterVPN-MTU.ps1",
    "durable_adoption=$true",
)

# Router-agent privileged state uses the same fail-closed private regular-file
# primitive, including strict 0600 and same-directory atomic rename.
require(
    "cmd/router-agent/private_state.go",
    "readPrivateState",
    "writePrivateState",
    "removePrivateState",
    "ensurePrivateStateParent",
    "state parent contains symlink",
    "state file is symlink",
    "os.SameFile",
    "os.CreateTemp",
    "tmp.Sync()",
    "os.Rename(tmpPath, path)",
)
require(
    "cmd/router-agent/private_state_test.go",
    "RejectsSymlinkParent",
    "RejectsWorldReadableState",
    "RejectsSymlinkState",
    "RejectsOversizedState",
    "TargetChangedBeforeRemove",
)

# Forwarding-extension ownership state is transactional: a failed live apply or
# failed save restores prior metadata/live intent rather than reporting partial
# success; stale-owner cleanup snapshots RAM and rolls it back when persistence
# fails.
require(
    "cmd/router-agent/admin_forward_extension.go",
    "captureForwardingSnapshotLocked",
    "restoreForwardingSnapshotLocked",
    "rollbackForwardingSnapshotLocked",
    "saveForwardingState()",
    "applyForwardingState()",
    "cleanupExpiredForwardingLocked",
    "pruneForwardingLocked",
    "cleanupExpired",
)
require(
    "cmd/router-agent/forwarding_transaction_test.go",
    "TestForwardingFailureRollsBackMetadataAndLiveIntent",
    "TestForwardingPersistenceFailureDoesNotChangeLiveRules",
    "TestForwardingExpirationPersistenceFailureRestoresMemory",
)

# Protected DMZ uses the same serialized state owner; enable/disable and periodic
# reassertion restore old intent/live rules after failure.
require(
    "cmd/router-agent/admin_protected_dmz.go",
    "dmzMu.Lock()",
    "snapshotProtectedDMZLocked",
    "rollbackProtectedDMZLocked",
    "saveProtectedDMZState()",
    "applyProtectedDMZ()",
    "reassertProtectedDMZOnce",
)
require(
    "cmd/router-agent/protected_dmz_transaction_test.go",
    "TestProtectedDMZApplyFailureRollsBackState",
    "TestProtectedDMZPersistenceFailureKeepsOldLiveRules",
)

# Exact-SHA updater recovery: status and previous compose snapshots are private;
# persistence is a hard boundary; rollback proves the previous stack healthy;
# interrupted applying/rolling-back/finalizing states reconcile after restart.
require(
    "cmd/updater/main.go",
    "writeStatusAtomic",
    "saveRollbackSnapshot",
    "loadRollbackSnapshot",
    "restorePreviousStack",
    "reconcileOnStartup",
    "rolling-back",
    "terminalStatus",
    "verifyExpectedContainers",
    "healthCheck",
    "composeSHA",
)
require(
    "cmd/updater/main_test.go",
    "TestUpdaterRecoveryRejects",
    "TestUpdaterRecoveryAcceptsPrivateRegularFile",
)
forbid("cmd/updater/main.go", 'Prune: true', '"Prune":true')

# Endpoint synchronization is one staged transaction across the narrow owned
# WG/AWG endpoint fields + home Router VPN profile endpoint. The obsolete broad
# recursive rewriter must stay gone.
require_absent("server/scripts/update-endpoint.sh")
require(
    "server/finalize/sync-endpoint.py",
    "stage_changes",
    "adopt_changes",
    "restore_adopted",
    "assert_owned_path",
    'profile.get("id") == "home"',
    'profile.get("node_kind") == "router-vpn"',
    'wg/server.conf',
    'awg2/awg0.conf',
)
run_test("server/finalize/test-sync-endpoint.py")

# DNS benchmark is measurement-only durable state. It must not mutate the user's
# current node DNS policy in routers.json. Fresh bundle generation may consume
# this measured result as a default.
require(
    "server/scripts/benchmark-dns.py",
    "atomic_write_private_json",
    "/opt/router-vpn/config/dns-benchmark.json",
)
forbid("server/scripts/benchmark-dns.py", "routers.json")

# Security-sensitive generated publication must go through staged private
# adoption, including Setup token, router-agent token/config, node proof,
# transports, private bundle/client JSON, and preserved upgrade credentials.
require(
    "server/scripts/private-file.py",
    "atomic_write_private",
    "atomic_copy_private",
    "atomic_write_private_batch",
    "atomic_copy_private_batch",
    "unlink_owned_private",
    "adopted_inodes",
    "rollback_adopted",
    "temporary file parent changed during open",
)
run_test("server/scripts/test_private_file_batch.py")
run_test("server/scripts/test_private_file_parent_safety.py")
require("server/scripts/setup-token.py", "private-file.py", "atomic_write_private")
require("server/router-agent/run.sh", "private-file.py", "atomic_write_private")
require("server/init/node-proof-identity.py", "private-file.py", "atomic_write_private")
require("server/init/gen-socks5.py", "private-file.py", "atomic_write_private_batch")
require("server/init/gen-transports.sh", "private-file.py", "atomic_write_private_batch")
require("server/init/gen-xray.sh", "private-file.py", "atomic_write_private_batch")
require("server/init/gen-naive.sh", "private-file.py", "atomic_write_private_batch")
require("server/init/gen-ss-v2ray.sh", "private-file.py", "atomic_write_private_batch")
require("server/init/gen-over-tls.sh", "private-file.py", "atomic_write_private_batch")
require("server/init/gen-ssr.sh", "private-file.py", "atomic_write_private_batch")
require("server/init/gen-awg.sh", "private-file.py", "atomic_write_private_batch")
require("server/finalize/gen-client.sh", "private-file.py", "atomic_write_private_batch")
require("server/finalize/router-vpn-bundle.sh", "private-file.py", "atomic_write_private_batch")
require("server/init/init-current.sh", "private-file.py", "atomic_write_private_batch")
require("server/finalize/finalize-current.sh", "private-file.py", "atomic_write_private_batch")
require("server/upgrade.sh", "private-file.py", "atomic_write_private_batch")

# Preserved upgrade state is validated as a private regular file before reuse;
# corrupt preserved security identities fail closed rather than silently rotating
# linked clients or server identity.
require(
    "server/init/init-current.sh",
    "fail rather than rotating it silently",
    "private-file.py",
    "router-agent-token",
)
require(
    "server/finalize/finalize-current.sh",
    "copy-private-batch",
    "CREDENTIALS.txt",
    "client.json",
    "routers.json",
)
require("server/upgrade.sh", "copy-private-batch", "previous", "CREDENTIALS.txt", "client.json", "routers.json")

# Generated transport/Xray/TLS configuration is published through transaction
# batch adoption; disposable validation artifacts stay private temp state and
# are never authoritative.
for rel in (
    "server/init/gen-transports.sh",
    "server/init/gen-xray.sh",
    "server/init/gen-naive.sh",
    "server/init/gen-ss-v2ray.sh",
    "server/init/gen-over-tls.sh",
    "server/init/gen-ssr.sh",
):
    forbid(rel, "cat > /opt/router-vpn/config", "cp $WORKDIR")

if errors:
    print("Durable-state transaction audit: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)
print("Durable-state transaction audit: PASS")
