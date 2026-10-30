#!/usr/bin/env python3
"""Prove retained protection preparation against the actual Windows kernel.

The fixture uses a fresh private directory for each case. It creates no Firewall
rule, changes no profile, and never opens the production recovery directory.
Native files, security descriptors, process tokens and deletion handles remain
real; metadata-only comparisons are never accepted as native owner authority.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "windows_protection_native_toolchain", ROOT / "deploy/test_desktop_windows_identity.py")
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
TARGET = ROOT / "internal/windowsprotection"
PACKAGE = "./internal/windowsprotection"
REQUIRED = (
    "TestWindowsProtectionOwnerRecordRoundTrip",
    "TestWindowsProtectionOwnerRecordInvalidFields",
    "TestWindowsProtectionOwnerRecordStrictEncoding",
    "TestWindowsProtectionOwnerRecordSID",
    "TestWindowsProtectionOwnerRecordDigest",
    "TestWindowsProtectionPreparedOwnerActualLifecycle",
    "TestWindowsProtectionPreparedOwnerPinsNamespaceAndFile",
    "TestWindowsProtectionPreparedOwnerPreservesRecoveryRecord",
    "TestWindowsProtectionPreparedOwnerRejectsChangedIdentity",
    "TestWindowsProtectionPreparedOwnerRejectsChangedRecord",
    "TestWindowsProtectionPreparedOwnerCancellationAndConcurrentDiscard",
    "TestWindowsProtectionPreparedOwnerDiscardRetriesSameHandle",
    "TestWindowsProtectionPreparedOwnerRejectsUntrustedOrExistingState",
    "TestWindowsProtectionCapturedObjectsRejectHardlinks",
    "TestWindowsProtectionCapturedAncestorsRejectRename",
)
REQUIRED_SUBCASES = {
    REQUIRED[6]: ("record-write", "record-delete", "record-rename", "root-rename", "parent-rename"),
    REQUIRED[8]: ("session", "source", "config", "network", "generation"),
    REQUIRED[12]: ("foreign-owner", "broad-write", "inherited", "legacy-record", "unknown-journal",
                   "foreign-lock", "linked-parent"),
}


def sources():
    expected = {"record.go", "record_test.go", "owner_windows.go", "owner_windows_test.go",
                "path_windows.go", "security_windows.go"}
    owned = sorted(TARGET.glob("*.go"))
    if {path.name for path in owned} != expected:
        raise ValueError("Windows protection owner source/test closure changed")
    controller = sorted((ROOT / "internal/windowscontroller").glob("*.go"))
    if not {"process_windows.go", "identity_windows.go", "machine_directories_windows.go"}.issubset(
            path.name for path in controller):
        raise ValueError("Windows protection owner lost its shipping native identity dependency")
    paths = owned + controller + [ROOT / "go.mod", Path(__file__).resolve(),
                                  ROOT / "deploy/test_desktop_windows_identity.py",
                                  ROOT / "deploy/prepare-desktop-external.py"]
    result = {}
    for path in paths:
        if not path.is_file() or any(part.is_symlink() for part in (path, *path.parents) if part != ROOT.parent):
            raise ValueError("Windows protection owner source is not its regular captured file")
        result[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def mutants():
    read = lambda name: (TARGET / name).read_text(encoding="utf-8")
    once, function = NATIVE.replace_once, NATIVE.function_mutant
    owner, path, security = read("owner_windows.go"), read("path_windows.go"), read("security_windows.go")
    changed_bytes = once(owner, "read > OwnerRecordLimit || !bytes.Equal(buffer[:read], owner.body)",
                         "read > OwnerRecordLimit || false && !bytes.Equal(buffer[:read], owner.body)")
    changed_bytes = once(changed_bytes, "if err != nil || actual != owner.record {",
                         "if err != nil || false && actual != owner.record {")
    return (
        ("security_windows.go", "native-security-readback", REQUIRED[12],
         "an existing or untrusted protection owner was adopted",
         function(security, "func verifyProtectionSecurity(", "return security.verify(directory)", "return nil")),
        ("owner_windows.go", "captured-connection", REQUIRED[8],
         "another captured connection acquired the native preparation",
         once(owner, "if capture != owner.record.Capture {", "if false {")),
        ("path_windows.go", "retained-file-identity", REQUIRED[8],
         "another retained file identity acquired the native preparation",
         once(path,
              "return expected.VolumeSerialNumber == actual.VolumeSerialNumber && expected.FileIndexHigh == actual.FileIndexHigh &&\n\t\texpected.FileIndexLow == actual.FileIndexLow && expected.NumberOfLinks == actual.NumberOfLinks",
              "return true")),
        ("path_windows.go", "single-record-link", REQUIRED[13],
         "multiply linked recovery record acquired native file authority",
         once(path, " || !directory && actual.NumberOfLinks != 1", "")),
        ("owner_windows.go", "immutable-owner-record", REQUIRED[9],
         "changed immutable owner bytes were accepted", changed_bytes),
        ("owner_windows.go", "joined-discard-retry", REQUIRED[11],
         "retried native discard did not independently prove absence",
         once(owner, "if owner.discarded {", "if owner.discarded || owner.discarding {")),
        ("owner_windows.go", "durable-close-record", REQUIRED[7],
         "Close discarded or changed the durable owner record",
         function(owner, "func (owner *PreparedOwner) Close()", "return owner.closeLocked()",
                  "return errors.Join(owner.deleteCreatedRecord(), owner.closeLocked())")),
        ("path_windows.go", "retained-ancestor-sharing", REQUIRED[14],
         "captured protection ancestry allowed a namespace replacement",
         function(path, "func pinProtectionDirectory(", "syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE)",
                  "syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE)")),
        ("path_windows.go", "metadata-only-ancestor", REQUIRED[14],
         "captured protection ancestry allowed a namespace replacement",
         function(path, "func pinProtectionDirectory(",
                  "syscall.FILE_LIST_DIRECTORY|protectionReadAttributes|protectionReadControl",
                  "protectionReadAttributes|protectionReadControl")),
    )


def execute(go="go"):
    if platform.system() != "Windows" or not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Protection owner proof requires an actual elevated Windows host")
    before = sources()
    compiler, captured, architecture = NATIVE.selected_compiler(go, ROOT, dict(os.environ))
    race = ["-race"] if architecture == "amd64" else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    build = [compiler, "test", "-c", "-mod=readonly", "-tags=routervpn_windows_protection_native",
             "-gcflags=all=-d=checkptr=2", *race]
    with tempfile.TemporaryDirectory(prefix="routervpn-windows-protection-owner-") as directory:
        workspace = Path(directory)
        binary = workspace / "owner.test.exe"
        status, output = NATIVE.run([*build, "-o", binary, PACKAGE], cwd=ROOT, env=captured, timeout=240)
        if status:
            raise ValueError("Native protection owner baseline failed to compile:\n" + output[-32768:])
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        status, output = NATIVE.run([binary, "-test.run=^TestWindowsProtection", "-test.count=1",
                                     "-test.timeout=90s", "-test.v"], cwd=ROOT, env=captured, timeout=105)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if (status or "--- SKIP:" in output or "DATA RACE" in output or
                any("--- PASS: " + test + " (" not in output for test in REQUIRED)):
            raise ValueError("Protection owner baseline did not execute every native ownership case")
        for test, names in REQUIRED_SUBCASES.items():
            if any("--- PASS: " + test + "/" + name + " (" not in output for name in names):
                raise ValueError("Protection owner baseline omitted a real negative ownership case: " + test)
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Native protection owner binary changed during execution")
        changes = mutants()
        for filename, name, test, witness, replacement in changes:
            changed = workspace / (name + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = workspace / (name + ".json")
            overlay.write_text(json.dumps({"Replace": {str(TARGET / filename): str(changed)}}), encoding="utf-8")
            candidate = workspace / (name + ".test.exe")
            status, output = NATIVE.run([*build, "-overlay=" + str(overlay), "-o", candidate, PACKAGE],
                                        cwd=ROOT, env=captured, timeout=120)
            if status:
                raise ValueError("Protection owner mutant failed to compile: " + name + "\n" + output[-16384:])
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            status, output = NATIVE.run([candidate, "-test.run=^" + test + "$", "-test.count=1",
                                         "-test.timeout=30s", "-test.v"], cwd=ROOT, env=captured, timeout=45)
            if (status == 0 or "--- FAIL: " + test + " (" not in output or witness not in output or
                    "--- SKIP:" in output or "panic:" in output or "DATA RACE" in output):
                raise ValueError("Protection owner mutant missed its exact broken behavior: " + name +
                                 "\n" + output[-16384:])
            if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
                raise ValueError("Protection owner mutant changed during execution: " + name)
            print("Rejected production Windows protection owner mutant:", name, flush=True)
        if sources() != before:
            raise ValueError("Protection owner shipping sources changed during the actual native gate")
    print("Native protection preparation passed five strict-record groups, ten native ownership groups, "
          "seven existing/untrusted-state cases and nine production negative controls. "
          "Firewall mutation, transfer, recovery and ordinary-path activation remain separate requirements.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    execute(parser.parse_args().go)
