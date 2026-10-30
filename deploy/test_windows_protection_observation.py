#!/usr/bin/env python3
"""Verify durable recovery callbacks inside actual retained BFE read snapshots.

All kernel fixtures are scoped to the exact test executable. This gate proves
read-only snapshot and callback lifetime, not application restart adoption or
physical device acceptance. Missing Windows capability is a failure.
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
SPEC = importlib.util.spec_from_file_location("observation_identity", ROOT / "deploy/test_desktop_windows_identity.py")
IDENTITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IDENTITY)
PREFIX = "TestDesktopWindowsProtectionObservation"
PURE = tuple(PREFIX + suffix for suffix in (
    "CapturedOutcomes", "RejectsInvalidRequest", "RetainsFailures", "CancelsBeforeAcknowledgement",
    "CloseJoinsCallback", "SerializesRequests", "RetainsLostSnapshot"))
NATIVE = tuple(PREFIX + "Native" + suffix for suffix in (
    "Outcomes", "RejectsChangedOutcome", "RejectsAdditionalPermit", "HeldReadOnlySnapshot", "RejectsLostSnapshot"))
REQUIRED_SUBCASES = {
    NATIVE[0]: ("absence", "retained"),
    NATIVE[1]: ("absence", "session", "source", "network", "policy", "metadata"),
    PURE[2]: ("partial-open", "read", "uncaptured-index", "callback", "cleanup"),
    PURE[6]: ("acknowledged", "uncertain-write"),
}
SOURCES = ("desktop_socket_protection_observation.go", "desktop_socket_protection_observation_test.go",
           "desktop_socket_windows_observation.go", "desktop_socket_windows_observation_test.go")


def mutants(target):
    native = (target / SOURCES[2]).read_text(encoding="utf-8")
    owner = (target / SOURCES[0]).read_text(encoding="utf-8")
    return (
        ("live-owner", SOURCES[2], NATIVE[0], "native observation adopted a still-live session",
         IDENTITY.replace_once(native, "err != nil || lock != nil", "err != nil || false && lock != nil")),
        ("extra-permit", SOURCES[2], NATIVE[2], "native observation acknowledged an extra retained permit",
         IDENTITY.replace_once(native, "if err := n.engine.AssertComplete(actual.sublayer, actual.baseline); err != nil {", "if err := error(nil); err != nil {")),
        ("unrecorded-outcome", SOURCES[2], NATIVE[1], "native observation adopted an unrecorded baseline",
         IDENTITY.replace_once(native, "candidate.verify(actual) == nil", "candidate != nil")),
        ("write-transaction", SOURCES[2], NATIVE[3], "native observation callback did not retain a read-only transaction",
         IDENTITY.replace_once(native, "n.engine.api.begin.Call(uintptr(n.engine.handle), 1)", "n.engine.api.begin.Call(uintptr(n.engine.handle), 0)")),
        ("early-snapshot-close", SOURCES[0], PURE[0], "acknowledgement escaped the exact live observation",
         IDENTITY.replace_once(owner, "\tcallbackErr := o.callback(request, matched)", "\tif err := o.closeNative(); err != nil { return err }\n\tcallbackErr := o.callback(request, matched)")),
        ("forget-partial-owner", SOURCES[0], PURE[2], "failed observation lost its partial native owner",
         IDENTITY.replace_once(owner, "if err := o.native.close(); err != nil {\n\t\treturn err", "if err := o.native.close(); err != nil {\n\t\to.native = nil\n\t\treturn err")),
        ("repeat-durable-ack", SOURCES[0], PURE[0], "successful acknowledgement was replayed or cleanup ran before it",
         IDENTITY.replace_once(owner, "\t\to.acked = true", "\t\to.acked = false")),
        ("normalize-lost-snapshot", SOURCES[2], NATIVE[4], "native lost snapshot acquired durable adoption",
         IDENTITY.function_mutant(native, "func (n *desktopWindowsProtectionNativeObservation) finishSnapshot(",
                                 "return desktopWFPError(\"finish acknowledged recovery snapshot\", status)",
                                 "if uint32(status) == 0x8032000d || uint32(status) == 0x8032000f { return nil }; return desktopWFPError(\"finish acknowledged recovery snapshot\", status)")),
    )


def execute(source=ROOT, go="go", *, env=None, bootstrap_only=False):
    if platform.system() != "Windows" or not IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Protection observation requires an actual elevated Windows host")
    source, target, package, before = IDENTITY.checked_sources(source)
    if any(name not in before for name in SOURCES):
        raise ValueError("Protection observation lost its exact source/test closure")
    compiler, captured, architecture = IDENTITY.selected_compiler(go, source, dict(os.environ if env is None else env))
    race = ["-race"] if architecture == "amd64" and not bootstrap_only else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    build = [compiler, "test", "-c", "-mod=readonly", "-tags=routervpn_windows_wfp", *race]
    with tempfile.TemporaryDirectory(prefix="routervpn-native-observation-") as temporary:
        workspace = Path(temporary)
        binary = workspace / "observation.test.exe"
        status, output = IDENTITY.run([*build, "-o", binary, package], cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError("Exact observation did not compile:\n" + output[-32768:])
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        status, output = IDENTITY.run([binary, "-test.run=^" + PREFIX, "-test.count=1", "-test.timeout=60s", "-test.v"], cwd=source, env=captured, timeout=75)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if status or any("--- PASS: " + test + " (" not in output for test in (*PURE, *NATIVE)) or any(value in output for value in ("--- SKIP:", "DATA RACE")):
            raise ValueError("Exact observation omitted a required native/lifecycle case")
        for test, cases in REQUIRED_SUBCASES.items():
            if any("--- PASS: " + test + "/" + case + " (" not in output for case in cases):
                raise ValueError("Exact observation omitted a captured outcome/failure: " + test)
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Observation executable changed during native execution")
        for label, filename, test, witness, changed in mutants(target):
            path = workspace / (label + ".go")
            path.write_bytes(changed.encode())
            overlay = workspace / (label + ".json")
            overlay.write_text(json.dumps({"Replace": {str(target / filename): str(path)}}), encoding="utf-8")
            candidate = workspace / (label + ".test.exe")
            status, output = IDENTITY.run([*build, "-overlay=" + str(overlay), "-o", candidate, package], cwd=source, env=captured, timeout=600)
            if status:
                raise ValueError("Observation mutation did not compile: " + label + "\n" + output[-16384:])
            status, output = IDENTITY.run([candidate, "-test.run=^" + test + "$", "-test.count=1", "-test.timeout=30s", "-test.v"], cwd=source, env=captured, timeout=40)
            if status == 0 or "--- FAIL: " + test + " (" not in output or witness not in output or any(value in output for value in ("--- SKIP:", "DATA RACE", "panic: test timed out")):
                raise ValueError("Observation mutation missed its intended defect: " + label + "\n" + output[-16384:])
            print("Rejected exact observation production mutant: " + label, flush=True)
    if IDENTITY.checked_sources(source)[3] != before:
        raise ValueError("Observation shipping source changed during native proof")
    print("Actual read-only BFE snapshot, exact outcomes, live-owner/extra-rule rejection, synchronous callback/cancellation joins, partial cleanup retries, retained snapshot-loss failure and eight production mutations passed. Journal restart adoption and public runtime activation remain separate requirements.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?", default=ROOT)
    parser.add_argument("--go", default="go")
    parser.add_argument("--bootstrap-only", action="store_true", help="execute the actual kernel without claiming race instrumentation")
    args = parser.parse_args()
    execute(args.source, args.go, bootstrap_only=args.bootstrap_only)
