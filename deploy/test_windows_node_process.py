#!/usr/bin/env python3
"""Execute the direct Node process adapter on the actual Windows kernel.

The whole shipping cmd/client package supplies the tested adapter. Its native
fixture launches only an exact copied test image, proves actual entry and exit,
and joins its retained child Job before releasing image ancestry. The shared
tests additionally exercise failed joins, concurrent cancellation and bounded
command authority. This is not a complete authenticated-package launch or a
sing-box dataplane test; those remain separate required composition gates.
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
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        check_baseline(status, output)
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
