#!/usr/bin/env python3
"""Execute the direct Node process adapter on the actual Windows kernel.

The whole shipping cmd/client package supplies the tested adapter. Its native
fixture launches only an exact copied test image, proves actual entry and exit,
and joins its retained child Job before releasing image ancestry. The shared
tests additionally exercise failed joins, concurrent cancellation and bounded
command authority. This is not a complete authenticated-package launch or a
sing-box dataplane test; those remain separate required composition gates.
The application restart cases use real admission/settings/private-store code
with explicit process/BFE/journal-I/O models. Native journal retirement/adoption
and actual BFE observation are verified by their separate Windows gates.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "windows_node_process_toolchain", ROOT / "deploy/test_desktop_windows_identity.py")
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
TAG = "routervpn_controller_windows_native"
NATIVE_TESTS = (
    "TestWindowsOwnedNodeProcessActualRetirement",
    "TestWindowsOwnedNodeProcessRejectsMissingController",
    "TestWindowsPrivateStoreWriteThroughReplace",
    "TestWindowsPrivateStoreWriteThroughFailureAndRetry",
    "TestWindowsPrivateStoreWriteThroughFlags",
    "TestWindowsPrivateStoreRejectsInvalidReplacement",
)
SHARED_TESTS = (
    "TestDesktopNodeProcessArguments",
    "TestDesktopNodeProcessFailedJoinRetainsPinsAndExactWait",
    "TestDesktopNodeProcessConcurrentCloseJoinsAndHonorsCancellation",
    "TestDesktopNodeProcessCancelledWaitDoesNotManufactureExit",
    "TestDesktopNodeProcessControllerReplacementAndPartialOwner",
    "TestDesktopNodeProcessPinReleaseRetriesAfterJoinedChild",
    "TestDesktopNodeJournalCapturedPreparedPrecedesPermission",
    "TestDesktopNodeJournalCapturedPreparedRejectsChangedOwners",
    "TestDesktopNodeJournalSettlementRequiresJoinedExactOutcome",
    "TestDesktopNodeJournalSettlementRetriesExactFailedFlush",
    "TestDesktopNodeJournalAbortedIntentKeepsProvedPredecessor",
    "TestDesktopNodeJournalDoesNotUseCallbackFreeRemoval",
    "TestDesktopNodeJournalReceiptlessChildUsesOnlyRecordedOutcome",
    "TestDesktopNodeJournalEmptyReleaseRetainsFailedNativeClose",
    "TestDesktopNodeJournalReleaseOrdersDurabilityAndPreservesAlways",
    "TestDesktopNodeJournalReleaseRetriesExactIntentFlush",
    "TestDesktopNodeJournalReleaseRetriesAfterNativeRemoval",
    "TestDesktopNodeJournalReleaseRetriesPartialNativeOwner",
    "TestDesktopNodeJournalReleaseRetainsArmedOwnerAndIntent",
    "TestDesktopNodeJournalReleaseRejectsUncapturedState",
    "TestDesktopNodeJournalReleaseRejectsReplacementDuringRetry",
    "TestDesktopNodeJournalReleaseRejectsSubstitutedNativeBarrier",
    "TestDesktopNodeJournalReleaseRequiresActualBarrierAcknowledgment",
    "TestDesktopNodeJournalReleaseKeepsSeparateOffGate",
    "TestDesktopNodeJournalReleaseJoinsLateNativeBarrier",
    "TestDesktopNodeJournalOffOrdersRemovalSaveAndSettlement",
    "TestDesktopNodeJournalOffRetainsIntentUntilProfileSave",
    "TestDesktopNodeJournalOffSavedResultRetryKeepsTokenAndOwner",
    "TestDesktopNodeJournalOffSavedReadbackRetainsExactOwner",
    "TestDesktopNodeJournalOffRejectsReplacementRevision",
    "TestDesktopNodeJournalOffRejectsUncapturedDurability",
    "TestDesktopNodeJournalOffRejectsSubstitutedBarrier",
    "TestDesktopNodeJournalOffRetriesNativeAndIntentFailures",
    "TestDesktopNodeJournalOffDoesNotPublishBeforeNativeProof",
    "TestDesktopNodeJournalOffHTTPReportsActualSavedPendingResult",
    "TestDesktopNodeJournalOffJoinsLateNativeBarrier",
    "TestDesktopNodeRecoveryRetainsAlwaysBeforeSuccessor",
    "TestDesktopNodeRecoveryPendingOffOriginalAndSavedResult",
    "TestDesktopNodeRecoveryOffRetriesActualSavedResult",
    "TestDesktopNodeRecoveryRejectsUnprovedReceiptAndChangedProfile",
    "TestDesktopNodeRecoveryAdmissionRetriesAndHTTPPendingOff",
    "TestDesktopNodeRecoveryEmptyStartupClosesStore",
    "TestDesktopNodeRecoveryTerminalShutdownPreservesUnknownPolicy",
    "TestDesktopNodeRecoveryCancellationKeepsReplacement",
    "TestDesktopNodeRecoveryRequiresJoinedInitializationBeforeBegin",
    "TestDesktopNodeRecoveryPartialOpenAndNativeCloseRemainOwned",
    "TestDesktopNodeRecoveryUncertainResultCannotBeReplaced",
    "TestDesktopNodeRecoveryHTTPDoesNotReuseUnknownOwnerToken",
    "TestDesktopNodeRecoveryAdmissionCancellation",
    "TestDesktopNodeRecoveryOldCompletionKeepsNewOperation",
    "TestDesktopOwnedNodeHealthUsesSealedSourceAfterSavedBundleChanges",
    "TestDesktopOwnedNodeHealthRejectsWrongOrRetiredProof",
    "TestDesktopOwnedNodeHealthRejectsUncapturedProfileBeforeNetwork",
    "TestDesktopNodeInitialStartupDoesNotCreateJournal",
    "TestDesktopNodeInitialSourceCreatesBeforeCapturedAttempt",
    "TestDesktopNodeInitialSourceRejectsUnmaterializedJournal",
    "TestDesktopNodeInitialStartupRejectsMissingAndForeignState",
    "TestDesktopNodeInitialAbsenceRequiresCurrentJoinedOwner",
    "TestDesktopNodeInitialCloseRetryReopensExactNamespace",
    "TestDesktopNodeInitialCreateRetryRetainsPartialOwner",
    "TestDesktopNodeInitialCreateCancellationRetainsWrittenJournal",
    "TestDesktopNodeInitialCancelledStartCannotAuthorizeReadOnlyCreate",
)
REQUIRED = (*NATIVE_TESTS, *SHARED_TESTS)
ARGUMENT_CASES = (
    "interpreter", "another-directory", "missing-source", "duplicate-source",
    "credential-flag", "upper-session", "short-session", "invalid-config",
    "upper-transfer", "zero-mtu", "low-mtu", "large-mtu", "noncanonical-mtu",
    "flag-injection",
)
EXPECTED = (*REQUIRED, *(SHARED_TESTS[0] + "/" + case for case in ARGUMENT_CASES),
            "TestWindowsPrivateStoreWriteThroughReplace/unicode",
            "TestWindowsPrivateStoreWriteThroughReplace/long-portable-path")
REQUIRED_SOURCES = (
    "cmd/client/desktop_node_process.go",
    "cmd/client/desktop_node_process_other.go",
    "cmd/client/desktop_node_process_test.go",
    "cmd/client/desktop_node_process_windows.go",
    "cmd/client/desktop_node_process_windows_native_test.go",
    "cmd/client/desktop_node_journal.go", "cmd/client/desktop_node_journal_test.go",
    "cmd/client/desktop_node_journal_windows.go",
    "cmd/client/desktop_node_journal_release.go", "cmd/client/desktop_node_journal_release_test.go",
    "cmd/client/desktop_node_protection.go", "cmd/client/desktop_node_protection_windows.go",
    "cmd/client/desktop_node_protection_off.go", "cmd/client/desktop_node_protection_off_test.go",
    "cmd/client/desktop_node_journal_off.go", "cmd/client/desktop_node_journal_off_test.go",
    "cmd/client/desktop_node_recovery.go", "cmd/client/desktop_node_recovery_windows.go",
    "cmd/client/desktop_node_recovery_other.go", "cmd/client/desktop_node_recovery_test.go",
    "cmd/client/desktop_node_recovery_initial.go", "cmd/client/desktop_node_recovery_initial_test.go",
    "cmd/client/desktop_node_owned.go",
    "cmd/client/desktop_node_health.go", "cmd/client/desktop_node_health_test.go",
    "cmd/client/desktop_node_startup.go", "cmd/client/desktop_node_startup_test.go",
    "cmd/client/node_proof.go", "cmd/client/speed_lab_transaction.go",
    "cmd/client/controller_shutdown.go", "cmd/client/operation_guard.go",
    "cmd/client/profile_protection.go", "cmd/client/profile_protection_owned.go", "cmd/client/profile_protection_owned_test.go",
    "cmd/client/controller_privilege_windows.go",
    "cmd/client/private_runtime_permissions_windows.go",
    "cmd/client/private_store.go", "cmd/client/private_store_replace_windows.go",
    "cmd/client/private_store_replace_other.go", "cmd/client/private_store_replace_windows_test.go",
    "cmd/client/bundled_native.go", "cmd/client/bundled_amnezia.go",
    "cmd/client/main.go", "cmd/client/ui.html", "cmd/client/logical_ui.js",
    "internal/windowscontroller/gui_windows.go",
    "internal/windowscontroller/process_windows.go",
    "internal/windowscontroller/launch_windows.go",
    "go.mod", "deploy/test_desktop_windows_identity.py",
    "deploy/test_windows_node_process.py", "deploy/test_windows_node_process_runner.py",
    ".github/workflows/windows-controller-contract.yml",
)


def sources():
    paths = set([*ROOT.glob("cmd/client/*.go"), *ROOT.glob("internal/**/*.go"),
                 *ROOT.glob("go.sum"), *(ROOT / name for name in REQUIRED_SOURCES)])
    records = {}
    for path in sorted(paths):
        if path.is_symlink() or not path.is_file():
            raise ValueError("Native Node process gate lost its actual regular source: " + str(path))
        records[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def test_line(output, result, test):
    return re.search(r"(?m)^[ \t]*--- " + result + ": " + re.escape(test) + r" \(", output) is not None


def invalid_execution(output):
    return any(marker in output for marker in (
        "--- SKIP:", "DATA RACE", "panic:", "fatal error:", "[build failed]"))


def check_baseline(status, output):
    if (status or invalid_execution(output) or "--- FAIL:" in output or
            any(not test_line(output, "PASS", name) for name in EXPECTED)):
        raise ValueError("Native Node process gate did not execute every required ownership case:\n" + output[-32768:])


def report_baseline(status, output):
    # Windows redirected Python output can default to cp1252 while the native
    # fixture emits UTF-8 private paths. Keep their exact spelling visible;
    # a console encoding error must not hide the actual native exit status.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    check_baseline(status, output)


def check_rejection(name, test, witness, status, output):
    if (not status or invalid_execution(output) or witness not in output or
            not test_line(output, "FAIL", test)):
        raise ValueError("Node process negative control missed its intended boundary: " + name + "\n" + output[-16384:])


def mutants():
    filename = "cmd/client/desktop_node_process.go"
    original = (ROOT / filename).read_text(encoding="utf-8")
    journal_file = "cmd/client/desktop_node_journal.go"
    journal = (ROOT / journal_file).read_text(encoding="utf-8")
    release_file = "cmd/client/desktop_node_journal_release.go"
    release = (ROOT / release_file).read_text(encoding="utf-8")
    private_file = "cmd/client/private_store_replace_windows.go"
    private = (ROOT / private_file).read_text(encoding="utf-8")
    off_file = "cmd/client/desktop_node_journal_off.go"
    off = (ROOT / off_file).read_text(encoding="utf-8")
    off_capture_file = "cmd/client/desktop_node_protection_off.go"
    off_capture = (ROOT / off_capture_file).read_text(encoding="utf-8")
    profile_file = "cmd/client/profile_protection_owned.go"
    profile = (ROOT / profile_file).read_text(encoding="utf-8")
    recovery_file = "cmd/client/desktop_node_recovery.go"
    recovery = (ROOT / recovery_file).read_text(encoding="utf-8")
    protection_file = "cmd/client/desktop_node_protection.go"
    protection = (ROOT / protection_file).read_text(encoding="utf-8")
    operation_file = "cmd/client/operation_guard.go"
    operation = (ROOT / operation_file).read_text(encoding="utf-8")
    health_file = "cmd/client/desktop_node_health.go"
    health = (ROOT / health_file).read_text(encoding="utf-8")
    startup_file = "cmd/client/desktop_node_startup.go"
    startup = (ROOT / startup_file).read_text(encoding="utf-8")
    initial_file = "cmd/client/desktop_node_recovery_initial.go"
    initial = (ROOT / initial_file).read_text(encoding="utf-8")
    owned_file = "cmd/client/desktop_node_owned.go"
    owned = (ROOT / owned_file).read_text(encoding="utf-8")
    once = NATIVE.replace_once
    alive = NATIVE.function_mutant(original, "func (owner *desktopNodeProcessOwner) Alive()",
        "\tif err := owner.controller(); err != nil {\n\t\treturn err\n\t}\n", "")
    alive = NATIVE.function_mutant(alive, "func (owner *desktopNodeProcessOwner) Alive()",
                                  "return owner.controller()", "return nil")
    return (
        (filename, "retired-controller-authority", NATIVE_TESTS[0],
         "retired controller still authorized the native child", alive),
        (filename, "failed-child-join-acknowledgment", SHARED_TESTS[1],
         "failed native join released a retained image or exit owner",
         once(original, "\t\tif err := owner.child.Close(ctx); err != nil {\n\t\t\treturn err\n\t\t}",
              "\t\tif err := owner.child.Close(ctx); err != nil {\n\t\t\treturn nil\n\t\t}")),
        (filename, "duplicate-command-authority", SHARED_TESTS[0] + "/duplicate-source",
         "native Node launch accepted substituted or incomplete authority",
         once(original, 'if _, exists := values[name]; exists || value == ""',
              'if _, exists := values[name]; false && exists || value == ""')),
        (journal_file, "uncaptured-durable-target", "TestDesktopNodeJournalCapturedPreparedPrecedesPermission",
         "native admission did not capture its independently proved durable target before permission",
         once(journal, "return s.provePreparedLocked(ctx, attempt, *record.Committed.Target, current)", "return nil")),
        (journal_file, "orphaned-empty-journal", "TestDesktopNodeJournalEmptyReleaseRetainsFailedNativeClose",
         "failed journal close released its exact owner",
         once(journal, "\tif err := s.journal.Close(); err != nil {\n\t\treturn err\n\t}\n", "")),
        (journal_file, "ignored-settlement-flush", "TestDesktopNodeJournalSettlementRetriesExactFailedFlush",
         "failed journal settlement discarded its exact attempt",
         once(journal, "if err != nil || wantErr != nil || gotErr != nil || written.Incomplete || !bytes.Equal(want, got) {",
              "if false && (err != nil || wantErr != nil || gotErr != nil || written.Incomplete || !bytes.Equal(want, got)) {")),
        (release_file, "release-before-durable-intent", "TestDesktopNodeJournalReleaseOrdersDurabilityAndPreservesAlways/on-connect",
         "native removal preceded its exact durable intent",
         once(release, "\tif err := writeDesktopNodeJournalReleaseRecord(ctx, r.store, r.head, r.intent); err != nil {\n\t\treturn err\n\t}\n", "")),
        (release_file, "release-without-settlement", "TestDesktopNodeJournalReleaseOrdersDurabilityAndPreservesAlways/on-connect",
         "durable release did not finish its captured transaction",
         once(release, "\t\t\tif err := writeDesktopNodeJournalReleaseRecord(ctx, r.store, r.intent, r.settlement); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n", "")),
        (release_file, "release-accepts-off-callback", "TestDesktopNodeJournalReleaseRejectsSubstitutedNativeBarrier/off",
         "substituted native callback gained durable removal permission",
         once(release, 'change.Action != "release" || change.Previous == nil', 'false || change.Previous == nil')),
        (private_file, "private-publication-without-write-through", "TestWindowsPrivateStoreWriteThroughFlags",
         "private replacement omitted write-through or permitted deferred/cross-volume publication",
         once(private, "windowsPrivateReplaceExisting|windowsPrivateWriteThrough", "windowsPrivateReplaceExisting")),
        (private_file, "private-publication-overwrites-retained-file", "TestWindowsPrivateStoreWriteThroughReplace",
         "private replacement modified the old file instead of promoting its new private file",
         once(private, "return replaceWindowsPrivateStoreFile(source, target, moveWindowsPrivateStoreFile)",
              "body, err := os.ReadFile(source); if err != nil { return err }; if err := os.WriteFile(target, body, 0600); err != nil { return err }; return os.Remove(source)")),
        (off_file, "off-before-durable-intent", "TestDesktopNodeJournalOffOrdersRemovalSaveAndSettlement/always",
         "explicit Off removed protection before its durable intent",
         once(off, "\t\tif err := writeDesktopNodeJournalReleaseRecord(ctx, j.store, j.head, j.intent); err != nil {\n\t\t\treturn err\n\t\t}\n", "")),
        (off_file, "off-accepts-normal-release", "TestDesktopNodeJournalOffRejectsSubstitutedBarrier/release",
         "substituted explicit Off callback reached persistence or completion",
         once(off, 'change.Action != "off" ||', 'false ||')),
        (profile_file, "off-accepts-replaced-profile-store", "TestDesktopNodeJournalOffSavedReadbackRetainsExactOwner/store-bytes",
         "saved Off accepted a replacement private profile store",
         NATIVE.function_mutant(profile, "func (a *app) persistCapturedProtectionOff(",
                               "!bytes.Equal(raw, append(want, '\\n'))", "false && !bytes.Equal(raw, append(want, '\\n'))")),
        (off_capture_file, "off-loses-saved-result-revision", "TestDesktopNodeJournalOffSavedResultRetryKeepsTokenAndOwner/settlement",
         "saved-result retry did not finish captured Off",
         once(off_capture, "if capture.profileWritten.Load() {", "if false && capture.profileWritten.Load() {")),
        (protection_file, "successor-without-startup-recovery", "TestDesktopNodeRecoveryRequiresJoinedInitializationBeforeBegin/not-initialized",
         "native successor entered before checked startup recovery joined",
         once(protection, "s.backend.bootstrap != nil && (s.recovery == nil || !s.recovery.ready || s.journal == nil) ||", "")),
        (recovery_file, "adoption-with-lost-native-proof", "TestDesktopNodeRecoveryRejectsUnprovedReceiptAndChangedProfile/durable-with-error",
         "unproved recovery or changed accepted profile reached native removal or saved settlement",
         once(recovery, '\t\tif err != nil {\n\t\t\treturn errors.Join(err, errors.New("native startup recovery has not joined its process and BFE proof"))\n\t\t}',
              '\t\tif false && err != nil {\n\t\t\treturn errors.Join(err, errors.New("native startup recovery has not joined its process and BFE proof"))\n\t\t}')),
        (recovery_file, "adoption-forgets-captured-profile", "TestDesktopNodeRecoveryRetainsAlwaysBeforeSuccessor",
         "startup did not adopt the exact joined Always owner independently of today's selected profile",
         once(recovery, "true, copyDesktopNodeProtectionTarget(state.Target), state.ProfileRevision", 'true, copyDesktopNodeProtectionTarget(state.Target), ""')),
        (recovery_file, "adoption-replaces-uncertain-receipt", "TestDesktopNodeRecoveryUncertainResultCannotBeReplaced/changed-request",
         "uncertain restart result was replaced or reused without a current exact native receipt",
         once(recovery, "r.result != nil && !sameDesktopNodeJournalSelection(r.result.Selection, copy)", "false")),
        (profile_file, "recovered-off-ignores-private-readback", "TestDesktopNodeRecoveryRejectsUnprovedReceiptAndChangedProfile/private-store-mismatch",
         "unproved recovery or changed accepted profile reached native removal or saved settlement",
         NATIVE.function_mutant(profile, "func (a *app) captureRecoveredOffProfile(",
                               "!bytes.Equal(raw, append(want, '\\n'))", "false && !bytes.Equal(raw, append(want, '\\n'))")),
        (recovery_file, "adoption-before-native-close", "TestDesktopNodeRecoveryPartialOpenAndNativeCloseRemainOwned/native-close",
         "native recovery cleanup failure admitted a successor owner",
         once(recovery, "\t\tif err := r.owner.Close(ctx); err != nil {\n\t\t\treturn err\n\t\t}\n", "")),
        (recovery_file, "terminal-recovery-drops-open-store", "TestDesktopNodeRecoveryTerminalShutdownPreservesUnknownPolicy/partial-open",
         "terminal recovery dropped its slot before joining the original protected store",
         NATIVE.function_mutant(recovery, "func (a *app) closeTerminalDesktopNodeRecovery(",
                               "\t\tif err := slot.journal.Close(); err != nil {\n\t\t\treturn true, err\n\t\t}\n", "")),
        (operation_file, "disconnect-leaves-admission-recovery-running", "TestDesktopNodeRecoveryAdmissionCancellation/cancel-operation",
         "admission recovery ignored captured cancellation or installed a connection owner",
         once(operation, "\ta.cancelDesktopNodeRecovery()\n", "")),
        (startup_file, "owned-proof-reopens-current-bundle", "TestDesktopOwnedNodeHealthUsesSealedSourceAfterSavedBundleChanges/missing",
         "owned proof reread a replacement bundle or skipped its current captured path",
         once(startup, "if launch != nil && launch.ownedNode != nil {", "if false && launch != nil && launch.ownedNode != nil {")),
        (health_file, "owned-proof-accepts-wrong-node", "TestDesktopOwnedNodeHealthRejectsWrongOrRetiredProof/wrong-node",
         "wrong or retired native HTTP proof was accepted",
         once(health, "return validateCapturedNodeProof(node, body)", "return nil")),
        (health_file, "owned-proof-skips-retirement-recheck", "TestDesktopOwnedNodeHealthRejectsWrongOrRetiredProof/generation",
         "wrong or retired native HTTP proof was accepted",
         once(health, "\tif ownershipErr := current(); ownershipErr != nil {\n\t\treturn 0, errors.Join(err, ownershipErr)\n\t}\n", "")),
        (health_file, "owned-proof-skips-native-target-readback", "TestDesktopOwnedNodeHealthRejectsWrongOrRetiredProof/target",
         "wrong or retired native HTTP proof was accepted",
         once(health, "\t\tif err := slot.backend.prepared(parent, *target); err != nil {\n\t\t\treturn err\n\t\t}\n", "")),
        (owned_file, "source-skips-durable-journal-materialization", "TestDesktopNodeInitialSourceCreatesBeforeCapturedAttempt",
         "protected source captured an attempt before materializing its rechecked durable journal",
         once(owned, "\tif err := a.ensureDesktopNodeJournalForStart(ctx, slot); err != nil {\n\t\treturn err\n\t}\n", "")),
        (initial_file, "initial-absence-ignores-native-close", "TestDesktopNodeInitialAbsenceRequiresCurrentJoinedOwner/close-failure",
         "cancelled, replaced or unjoined absence admitted durable source creation",
         once(initial, "\tr.absenceClosing = true\n\tif err := s.journal.Close(); err != nil {\n\t\treturn false, err\n\t}\n",
              "\tr.absenceClosing = true\n\t_ = s.journal.Close()\n")),
        (initial_file, "initial-absence-ignores-post-join-cancellation", "TestDesktopNodeInitialAbsenceRequiresCurrentJoinedOwner/cancel-after-close",
         "cancelled, replaced or unjoined absence admitted durable source creation",
         once(initial, "\ts.journal, r.opened, r.absenceClosing = nil, false, false\n\tif err := check(); err != nil {\n\t\treturn false, err\n\t}\n",
              "\ts.journal, r.opened, r.absenceClosing = nil, false, false\n")),
        (protection_file, "initial-absence-authorizes-unrecorded-attempt", "TestDesktopNodeInitialStartupDoesNotCreateJournal",
         "read-only startup absence authorized a source without a durable journal",
         once(protection, "!s.recovery.ready || s.journal == nil", "!s.recovery.ready")),
        (initial_file, "initial-absence-creates-for-read-only-recovery", "TestDesktopNodeInitialCancelledStartCannotAuthorizeReadOnlyCreate",
         "cancelled source start lent creation authority to later read-only startup",
         once(initial, "if !requireJournal {", "if false && !requireJournal {")),
    )


def execute(go="go", *, env=None):
    if platform.system() != "Windows":
        raise ValueError("Native Node process proof requires actual Windows execution")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Native Node process proof requires its actual elevated primary host")
    before = sources()
    changes = mutants()
    compiler, captured, architecture = NATIVE.selected_compiler(
        go, ROOT, dict(os.environ if env is None else env))
    race = ["-race"] if architecture == "amd64" else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    build = [compiler, "test", "-c", "-mod=readonly", "-gcflags=all=-d=checkptr=2", "-tags=" + TAG, *race]
    package = "./cmd/client"
    with tempfile.TemporaryDirectory(prefix="routervpn-windows-node-process-") as directory:
        workspace = Path(directory)
        binary = workspace / "node-process.test.exe"
        status, output = NATIVE.run([*build, "-o", binary, package], cwd=ROOT, env=captured, timeout=240)
        if status:
            raise ValueError("Actual Windows Node process fixture did not compile:\n" + output[-32768:])
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        expression = "^(" + "|".join(REQUIRED) + ")$"
        status, output = NATIVE.run(
            [binary, "-test.run=" + expression, "-test.count=1", "-test.timeout=120s", "-test.v"],
            cwd=ROOT / "cmd/client", env=captured, timeout=135)
        report_baseline(status, output)
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Native Node process fixture changed during execution")
        for filename, name, test, witness, replacement in changes:
            changed = workspace / (name + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = workspace / (name + ".json")
            overlay.write_text(json.dumps({"Replace": {str(ROOT / filename): str(changed)}}), encoding="utf-8")
            candidate = workspace / (name + ".test.exe")
            status, output = NATIVE.run(
                [*build, "-overlay=" + str(overlay), "-o", candidate, package],
                cwd=ROOT, env=captured, timeout=240)
            if status:
                raise ValueError("Node process mutant failed to compile: " + name + "\n" + output[-8192:])
            candidate_digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            expression = "/".join("^" + re.escape(part) + "$" for part in test.split("/"))
            status, output = NATIVE.run(
                [candidate, "-test.run=" + expression, "-test.count=1", "-test.timeout=60s", "-test.v"],
                cwd=ROOT / "cmd/client", env=captured, timeout=75)
            check_rejection(name, test, witness, status, output)
            if hashlib.sha256(candidate.read_bytes()).hexdigest() != candidate_digest:
                raise ValueError("Native Node process mutant changed during execution: " + name)
            print("Node process negative control rejected: " + name, flush=True)
            candidate.unlink()
        if sources() != before:
            raise ValueError("Native Node process source changed during the gate")
        print(json.dumps({"schema": 1, "host": "windows/" + architecture,
                          "native_process_cases": len(NATIVE_TESTS), "shared_ownership_cases": len(SHARED_TESTS),
                          "command_rejection_cases": len(ARGUMENT_CASES), "negative_controls": len(changes),
                          "actual_child_fixture_sha256": digest, "source_files": len(before),
                          "source_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
                          "authenticated_package_launch": "separate-required-composition-gate",
                          "sing_box_dataplane": "separate-required-composition-gate"}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    execute(parser.parse_args().go)
