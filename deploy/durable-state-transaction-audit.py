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
require("cmd/client/private_store_test.go", "RejectsSymlinkTargets", "RejectsSymlinkParent", "RejectsOversizedRead")

# MTU adoption remains a two-phase live/session transaction and persistence
# failure must restore the live interface/in-memory state. Runtime-profile MTU
# edits are disposable pre-connect state, but still reject path redirection and
# restore earlier files if a later adoption fails.
require("cmd/client/mtu_retest.go", "mtuRetestSnapshot", "rollbackMTULiveResult", "restoreMTUMeasurementFields")
require("cmd/client/mtu_retest_test.go", "stale", "rollback")

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
require(
    "client/Optimize-RouterVPN-MTU.ps1",
    "durable_adoption=$false",
    "Router VPN Go controller /api/mtu/retest",
)
forbid(
    "client/Optimize-RouterVPN-MTU.ps1",
    "function Persist-Winner",
    ".mtu.tmp",
    "Move-Item -LiteralPath $tmp -Destination $Ctx.Path -Force",
)

# macOS PF uses the same hardened private state store. Poisoned-state force-off
# may clear only Router VPN's scoped anchor; without the persisted reference
# token it must never guess at global PF ownership.
require(
    "modes/kill-switch-platform.py",
    "_linux.remove_state(root",
    "_darwin._clear_anchor(check=False)",
    "persisted PF reference token was unreadable",
    "global PF enablement was left untouched",
)
forbid("modes/kill-switch-platform.py", "_linux.state_path(root).unlink")
require(
    "deploy/test_macos_killswitch_contract.py",
    "_linux.remove_state(root",
    "global PF enablement was left untouched",
)
require(
    "modes/mtu-policy.py",
    "_runtime_regular_bytes",
    "os.path.samestat(opened, current)",
    "MTU runtime profile adoption failed; prior runtime profile restored",
    "_load_measurement_cache",
)
require(
    "modes/test_mtu_policy.py",
    "test_runtime_profile_symlink_is_never_followed",
    "test_runtime_profile_late_adoption_failure_rolls_back",
    "test_symlink_cache_is_never_followed",
)

# Router-agent privileged state must fail closed on symlink/broad permissions and
# transactionally coordinate durable state with live firewall/DMZ changes.
require(
    "cmd/router-agent/private_state.go",
    "validatePrivilegedStateFile",
    "validatePrivilegedStateParent",
    "os.SameFile",
    "os.CreateTemp",
    "tmp.Sync()",
    "atomicWritePrivilegedState",
)
require(
    "cmd/router-agent/admin_forwarding_extension.go",
    "dmzMu",
    "cloneAdminForwardingExtensionState",
    "rollbackProtectedDMZLocked",
    "protectedDMZTransactionError",
    "readPrivilegedState",
)
require(
    "cmd/router-agent/admin_mutations.go",
    "adminMutationFailure",
    "rollback incomplete",
    "atomicWritePrivilegedState",
)
require("cmd/router-agent/admin_server_control.go", "readPrivilegedState", "atomicWritePrivilegedState")
require("cmd/router-agent/private_state_test.go", "RejectsSymlink", "RejectsSymlinkParent", "RejectsOversizedRead")
require("cmd/router-agent/admin_forwarding_extension_test.go", "LiveApplyFailureRestoresDurableAndRAMState")
require("cmd/router-agent/admin_rollback_test.go", "ReportsIncompleteRollback")

# Exact-SHA updater recovery state is a hard transaction boundary. The previous
# exact compose must survive process restart until success or proven rollback.
require("cmd/update-controller/private_state.go", "validateUpdaterPrivateFile", "validateUpdaterPrivateParent", "os.SameFile", "atomicWriteUpdaterPrivate")
require(
    "cmd/update-controller/recovery.go",
    "rollbackComposePath",
    "saveRollbackCompose",
    "unexpectedly exists after update transaction started",
    "loadRollbackCompose",
    "restorePreviousStack",
    "rollbackAfterDeploymentFailure",
    "rolling-back",
    "reconcileRecovery",
)
require(
    "cmd/update-controller/main.go",
    "cannot safely clear stale rollback snapshot before update",
    "saveRollbackCompose(previous, from)",
    "rollbackAfterDeploymentFailure",
    "completeRecoveredUpdate",
    "exact_compose_verified",
)
require(
    "cmd/update-controller/recovery_test.go",
    "RollbackComposeSnapshotIsPrivateAndExact",
    "ClearRollbackComposeUnsafeStaleSnapshotBlocksNewTransaction",
    "SaveRollbackComposeRefusesUnexpectedExistingSnapshotAfterTransactionStart",
    "InterruptedPreDeploymentApplying",
)
require("cmd/update-controller/private_state_test.go", "RejectsBroadPermissions", "RejectsSymlink", "RejectsSymlinkParent", "RejectsOversizedRead")

# Endpoint synchronization owns only explicit raw WG/AWG endpoint fields + the
# owned home Router VPN profile and adopts all changed files as one transaction.
# Its independent publisher must reject symlink parents and re-prove open-file
# identity before reading an owned authoritative target.
require(
    "server/finalize/sync-endpoint.py",
    "ensure_owned_parent",
    "os.path.samestat(opened, current)",
    "build_changes",
    "stage_private",
    "apply_transaction",
    "restore_changes",
    'profile.get("id")',
    '"home"',
)
require(
    "server/finalize/test_sync_endpoint.py",
    "late_adoption_failure",
    "symlink_owned_target",
    "symlink_owned_parent",
    "identity_change_during_open",
)
require_absent("server/scripts/update-endpoint.sh")

# DNS benchmark is measurement-only; fresh bundle generation may consume the
# result, but benchmark execution may never own current routers.json policy.
require("server/scripts/benchmark-dns.py", "measurement_only", "write_private_atomic")
forbid("server/scripts/benchmark-dns.py", 'BASE / "client-bundle" / "routers.json"', "routers_path =")
require("server/scripts/test_dns_benchmark_persistence.py", "DNS benchmark code regained routers.json ownership")

# Generic private publishers reject symlink leaf targets and symlinked immediate
# parents, then adopt 0600 files through random same-directory fsynced temps.
require("server/scripts/atomic-private-write.py", "ensure_private_parent", "mkstemp", "os.fsync", "os.replace", "0o600")
require("server/scripts/atomic-private-batch.py", "ensure_private_parent", "restore", "adopt", "rollback was incomplete", "os.replace")
require(
    "server/scripts/test_atomic_private_publication.py",
    "fail_second_adoption",
    "prior state restored",
    "single-file private publisher accepted a symlink parent",
    "batch private publisher accepted a symlink parent",
)
require("server/scripts/create-bundle-json.py", "write_private_json", '"client.json"', '"routers.json"', '"router-vpn-bundle.json"')

# Stable identity/credential generators must preserve valid existing state,
# reject corrupt preserved state, validate candidates before adoption, and batch
# related identity files together. Reads are also strict: no symlink parent/leaf,
# no broad permissions, and no validate-then-replace race.
require(
    "server/scripts/ensure-setup-auth.py",
    "ensure_private_config_dir",
    "read_preserved_token",
    "os.path.samestat(opened, current)",
    "os.fchmod(fd, PRIVATE_MODE)",
    "refusing silent rotation",
    "atomic-private-write.py",
)
require(
    "server/scripts/test_setup_auth.py",
    "corrupt preserved Setup Center token was silently rotated",
    "symlink Setup Center token",
    "symlink Setup Center config parent was accepted",
    "Setup Center token replacement race was accepted",
)
require(
    "server/scripts/ensure-node-proof.py",
    "ensure_private_parent",
    "os.path.samestat(opened, current)",
    "must be mode 0600",
    "atomic-private-batch.py",
    "conflicts with WireGuard server identity",
)
require(
    "server/scripts/test_node_proof_private_state.py",
    "broad router-agent identity state was accepted",
    "symlink parent for WireGuard identity source was accepted",
    "WireGuard identity source replacement race was accepted",
)
require(
    "server/scripts/preserve-generated-state.py",
    "_ensure_private_parent",
    "must be mode 0600",
    "os.path.samestat(opened, current)",
    "refusing non-regular/symlink",
    "corrupt JSON",
    "expected exactly one preserved",
)
require(
    "server/scripts/test_preserve_generated_state.py",
    "corrupt preserved transport state",
    "ambiguous preserved TLS credentials",
    "symlink preserved transport state",
    "symlink parent for preserved transport state was accepted",
    "broad-permission preserved credential state was accepted",
    "preserved credential file replacement race was accepted",
)
require("server/scripts/generate-transports.sh", "refusing silent", "PRIVATE_BATCH", "private batch helper")
require("server/scripts/generate-xray-pq.sh", "refusing silent", "Validate the complete candidate generation", "PRIVATE_BATCH")
require("server/scripts/generate-tls-alternates.sh", "refusing silent", "Validate every candidate", "PRIVATE_BATCH")
require("server/scripts/generate-aux-proxies.py", "refusing silent credential rotation", "atomic-private-batch.py")
require("server/scripts/generate-rosenpass.sh", "Refusing to overwrite existing Rosenpass identity", "PRIVATE_BATCH")
require("server/scripts/ensure-rosenpass.sh", "partial/unsafe", "PRIVATE_BATCH")
require("server/scripts/generate-advanced-profiles.sh", "refusing silent REALITY credential rotation", "Validate the entire candidate tree", "PRIVATE_BATCH")
require("server/scripts/enhance-max-pq.py", "atomic-private-batch.py", "one private transaction")
require("server/scripts/wrap-xhttp-tun.py", "before atomic adoption", "atomic-private-write.py")
require("server/scripts/generate-stack-profiles.py", "atomic-private-batch.py", "stack-profiles-")
forbid("server/scripts/generate-transports.sh", "preserve-generated-state.py transports \"$BASE\" 2>/dev/null || true")
forbid("server/scripts/generate-xray-pq.sh", "preserve-generated-state.py xray \"$BASE\" 2>/dev/null || true")
forbid("server/scripts/generate-tls-alternates.sh", "preserve-generated-state.py tls \"$BASE\" 2>/dev/null || true")
forbid("server/scripts/generate-advanced-profiles.sh", "preserve-generated-state.py advanced \"$BASE\" 2>/dev/null || true")

# Fresh init, finalization, and upgrade paths publish credential-bearing state
# through the same helpers and only mark completion after runtime application.
require("server/init/noninteractive.sh", "atomic-private-write.py", "CREDENTIALS.txt", ".initialized")
require("server/finalize/finalize.sh", "atomic-private-write.py", "atomic-private-batch.py", "CREDENTIALS.txt", ".finalized")
require("server/finalize/upgrade-safe.sh", "atomic-private-write.py", "atomic-private-batch.py", "CREDENTIALS.txt", ".finalized")
forbid("server/finalize/finalize.sh", 'cat >"$BASE/client-bundle/CREDENTIALS.txt"', 'touch "$BASE/.finalized"')
forbid("server/finalize/upgrade-safe.sh", 'cat >"$BASE/client-bundle/CREDENTIALS.txt"', 'touch "$BASE/.finalized"')

# Setup assets are derived private presentation data containing import payloads,
# not stable identity or active policy. They are deliberately excluded from the
# authoritative-state transaction set; failure aborts finalization and they are
# regenerated from the already-transactional private source bundle.
require("server/scripts/generate-setup-assets.py", "private router credentials", 'chmod(0o600)')

# Execute the focused Python behavior contracts from the authoritative gate.
for test in (
    "server/finalize/test_sync_endpoint.py",
    "server/scripts/test_atomic_private_publication.py",
    "server/scripts/test_dns_benchmark_persistence.py",
    "server/scripts/test_setup_auth.py",
    "server/scripts/test_node_proof_private_state.py",
    "server/scripts/test_preserve_generated_state.py",
):
    run_test(test)

if errors:
    print("Durable-state transaction audit: FAIL", file=sys.stderr)
    for error in errors:
        print(f" - {error}", file=sys.stderr)
    raise SystemExit(1)

print("Durable-state transaction audit: PASS")
