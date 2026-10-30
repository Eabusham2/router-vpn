#!/usr/bin/env python3
"""Prove exact native WFP succession/retirement on the actual Windows kernel.

Only the actual test executable receives these filters. No legacy Firewall
profile, device route or foreign account is changed. Native direction reversal
does not by itself establish application adoption, node proof or device use.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("windows_transfer_identity", ROOT / "deploy/test_desktop_windows_identity.py")
IDENTITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IDENTITY)
REQUIRED = tuple("TestDesktopWindowsProtectionTransfer" + suffix for suffix in (
    "BothDirections", "RejectsChangedTarget", "RetirementRejectsReplacement", "RejectsAdditionalPermit", "JoinedOutcome"))
PURE = ("TestDesktopWindowsProtectionTargetRejectsSubstitution", "TestDesktopWindowsProtectionTargetCapturesBeforeNativeWait",
        "TestDesktopProtectionTransferRecordRoundTrip", "TestDesktopProtectionTransferRecordRejectsChangedFields",
        "TestDesktopProtectionTransferRecordStrictEncoding", "TestDesktopProtectionRetirementRecordExactOutcomes")
COMMIT_REQUIRED = tuple("TestDesktopWindowsProtectionCommitNative" + suffix for suffix in (
    "RequiresBarrier", "Successor", "SuccessorAbort", "RejectsExtraCandidate", "Retirement", "RetirementRetry"))
COMMIT_PURE = tuple("TestDesktopWindowsProtectionCommit" + suffix for suffix in (
    "Validation", "CopiesTargets", "Cancellation", "JoinsCallback"))
COMMIT_SUBCASES = {
    COMMIT_REQUIRED[1]: ("initial", "retained"),
    COMMIT_REQUIRED[2]: ("persist-failure", "late-cancellation", "foreign-predecessor"),
    COMMIT_REQUIRED[4]: ("release-on-connect", "preserve-always", "explicit-off"),
    COMMIT_REQUIRED[5]: ("persist-failure", "late-cancellation"),
}


def mutants(target):
    transfer = (target / "desktop_socket_windows_transfer.go").read_text(encoding="utf-8")
    baseline = (target / "desktop_socket_windows_baseline.go").read_text(encoding="utf-8")
    record = (target / "desktop_protection_transfer_record.go").read_text(encoding="utf-8")
    commit = (target / "desktop_socket_windows_commit.go").read_text(encoding="utf-8")
    barrier = (target / "desktop_socket_protection_commit.go").read_text(encoding="utf-8")
    return (
        ("other-predecessor", "desktop_socket_windows_transfer.go", REQUIRED[1],
         "changed native predecessor acquired replacement authority",
         IDENTITY.replace_once(transfer,
            "actual == nil || !expected.target.matches(actual.capture, actual.options.KillSwitchPolicy, actual.metadata)",
            "actual == nil")),
        ("initial-adoption", "desktop_socket_windows_transfer.go", REQUIRED[1],
         "changed native predecessor acquired replacement authority",
         IDENTITY.replace_once(transfer, "if actual != nil {", "if false && actual != nil {")),
        ("retained-live-owner", "desktop_socket_windows_transfer.go", REQUIRED[0],
         "live native predecessor was mistaken for joined retained protection",
         IDENTITY.replace_once(transfer, "err != nil || lock != nil", "err != nil || (lock != nil && false)")),
        ("old-target-retirement", "desktop_socket_windows_baseline.go", REQUIRED[2],
         "old target acquired authority over a replacement baseline",
         IDENTITY.replace_once(baseline, "if expected != nil {", "if false && expected != nil {")),
        ("transfer-extra-permit", "desktop_socket_windows_transfer.go", REQUIRED[3],
         "exact retained target accepted an extra native permit",
         IDENTITY.replace_once(transfer,
            "if err := engine.AssertComplete(actual.sublayer, actual.baseline); err != nil {",
            "if err := error(nil); err != nil {")),
        ("unverified-retired-outcome", "desktop_socket_windows_transfer.go", REQUIRED[4],
         "stale partial outcome adopted a replacement native baseline",
         IDENTITY.replace_once(transfer,
            "if err := readDesktopWindowsProtectionExpectation(ctx, target, p.fixtureScope); err != nil {",
            "if err := error(nil); err != nil {")),
        ("noncanonical-private-transfer", "desktop_protection_transfer_record.go", PURE[4],
         "noncanonical transfer input was admitted",
         IDENTITY.replace_once(record,
            "canonical, err := CanonicalDesktopProtectionTransferRecord(record)\n\tif err != nil || !bytes.Equal(raw, canonical)",
            "canonical, err := CanonicalDesktopProtectionTransferRecord(record)\n\tif err != nil || (!bytes.Equal(raw, canonical) && false)")),
        ("retired-other-source", "desktop_protection_transfer_record.go", PURE[5],
         "retirement receipt adopted an uncaptured protection outcome",
         IDENTITY.replace_once(record,
            "r.Target.Capture.SourceSHA256 != expected.SourceSHA256",
            "(r.Target.Capture.SourceSHA256 != expected.SourceSHA256 && false)")),
        ("successor-without-intent", "desktop_socket_windows_baseline.go", COMMIT_REQUIRED[1],
         "BFE successor committed without its exact normalized intent",
         IDENTITY.replace_once(baseline, "err = p.completeSuccessorCommitBarrier(old)", "err = nil")),
        ("retirement-without-intent", "desktop_socket_windows_baseline.go", COMMIT_REQUIRED[4],
         "BFE retirement lost its original policy or durable intent",
         IDENTITY.replace_once(baseline, "err := p.completeRemovalCommitBarrier(ctx)", "err := error(nil)")),
        ("candidate-extra-rule", "desktop_socket_windows_commit.go", COMMIT_REQUIRED[3],
         "incomplete candidate rules acquired durable commit acknowledgment",
         IDENTITY.function_mutant(commit, "func (p *DesktopWindowsSocketPolicy) completeSuccessorCommitBarrier(",
            "if err := p.baselineEngine.AssertComplete(actual.sublayer, actual.baseline); err != nil {",
            "if err := error(nil); err != nil {")),
        ("original-always-intent", "desktop_socket_windows_commit.go", COMMIT_REQUIRED[4],
         "BFE retirement lost its original policy or durable intent",
         IDENTITY.replace_once(commit,
            "previous := desktopWindowsProtectionTarget(actual.capture, actual.options.KillSwitchPolicy, actual.metadata)",
            "previous := desktopWindowsProtectionTarget(actual.capture, p.options.KillSwitchPolicy, actual.metadata)")),
        ("missing-required-callback", "desktop_socket_windows_commit.go", COMMIT_REQUIRED[0],
         "durable successor admitted a missing persistence callback",
         IDENTITY.function_mutant(commit, "func NewDesktopWindowsSocketPolicySuccessorWithBarrier(",
            "if barrier == nil {", "if false && barrier == nil {")),
        ("failed-durable-ack", "desktop_socket_protection_commit.go", COMMIT_PURE[2],
         "commit lost its actual persistence failure",
         IDENTITY.replace_once(barrier, "return errors.Join(err, ctx.Err())", "_ = err; return ctx.Err()")),
        ("late-cancelled-ack", "desktop_socket_protection_commit.go", COMMIT_PURE[2],
         "late cancellation was converted into commit authority",
         IDENTITY.replace_once(barrier, "return errors.Join(err, ctx.Err())", "return err")),
        ("mutable-native-commit", "desktop_socket_protection_commit.go", COMMIT_PURE[1],
         "durable callback mutated retained native commit targets",
         IDENTITY.replace_once(barrier, "barrier(ctx, cloneDesktopWindowsProtectionCommit(change))", "barrier(ctx, change)")),
    )


def execute(source=ROOT, go="go", *, env=None, bootstrap_only=False):
    if platform.system() != "Windows" or not IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Exact WFP transfer requires an actual elevated Windows host")
    source, target, package, before = IDENTITY.checked_sources(source)
    for name in ("desktop_socket_protection_target.go", "desktop_socket_protection_target_test.go",
                 "desktop_socket_windows_transfer.go", "desktop_socket_windows_transfer_test.go",
                 "desktop_protection_transfer_record.go", "desktop_protection_transfer_record_test.go",
                 "desktop_socket_protection_commit.go", "desktop_socket_protection_commit_test.go",
                 "desktop_socket_windows_commit.go", "desktop_socket_windows_commit_test.go",
                 "desktop_socket_windows_baseline.go", "desktop_socket_windows_policy.go"):
        if name not in before:
            raise ValueError("Exact WFP transfer lost shipping source: " + name)
    compiler, captured, architecture = IDENTITY.selected_compiler(go, source, dict(os.environ if env is None else env))
    race = ["-race"] if architecture == "amd64" and not bootstrap_only else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    build = [compiler, "test", "-c", "-mod=readonly", "-tags=routervpn_windows_wfp", *race]
    with tempfile.TemporaryDirectory(prefix="routervpn-exact-wfp-transfer-") as temporary:
        workspace = Path(temporary)
        binary = workspace / "transfer.test.exe"
        status, output = IDENTITY.run([*build, "-o", binary, package], cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError("Exact native transfer did not compile:\n" + output[-32768:])
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        status, output = IDENTITY.run([binary, "-test.run=^TestDesktop(WindowsProtection|ProtectionTransferRecord|ProtectionRetirementRecord)", "-test.count=1", "-test.timeout=120s", "-test.v"],
                                      cwd=source, env=captured, timeout=135)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if status or any("--- PASS: " + test + " (" not in output for test in (*REQUIRED, *PURE, *COMMIT_REQUIRED, *COMMIT_PURE)) or any(value in output for value in ("--- SKIP:", "DATA RACE")):
            raise ValueError("Exact native transfer omitted a required kernel/ownership case")
        for test, cases in COMMIT_SUBCASES.items():
            if any("--- PASS: " + test + "/" + case + " (" not in output for case in cases):
                raise ValueError("Native commit barrier omitted its actual case: " + test)
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Exact native transfer executable changed during execution")
        for label, filename, test, witness, changed in mutants(target):
            path = workspace / (label + ".go")
            path.write_bytes(changed.encode())
            overlay = workspace / (label + ".json")
            overlay.write_text(json.dumps({"Replace": {str(target / filename): str(path)}}), encoding="utf-8")
            candidate = workspace / (label + ".test.exe")
            status, output = IDENTITY.run([*build, "-overlay=" + str(overlay), "-o", candidate, package], cwd=source, env=captured, timeout=600)
            if status:
                raise ValueError("Exact transfer mutation failed to compile: " + label + "\n" + output[-16384:])
            status, output = IDENTITY.run([candidate, "-test.run=^" + test + "$", "-test.count=1", "-test.timeout=45s", "-test.v"],
                                          cwd=source, env=captured, timeout=55)
            if status == 0 or "--- FAIL: " + test + " (" not in output or witness not in output or any(value in output for value in ("--- SKIP:", "DATA RACE", "panic: test timed out")):
                raise ValueError("Exact transfer mutation missed its actual defect: " + label + "\n" + output[-16384:])
            print("Rejected exact native transfer production mutant: " + label, flush=True)
    if IDENTITY.checked_sources(source)[3] != before:
        raise ValueError("Exact WFP transfer source changed during native execution")
    print("Exact BFE succession and reversal, retained target identity, Always preservation, joined partial outcomes, canonical private receipts, precommit durable-barrier ordering/cancellation and sixteen production mutations passed. Actual journal persistence, application host adoption and encrypted-peer composition remain separate requirements.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?", default=ROOT)
    parser.add_argument("--go", default="go")
    parser.add_argument("--bootstrap-only", action="store_true", help="execute the actual kernel without claiming race instrumentation")
    args = parser.parse_args()
    execute(args.source, args.go, bootstrap_only=args.bootstrap_only)
