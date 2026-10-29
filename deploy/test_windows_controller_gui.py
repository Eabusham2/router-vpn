#!/usr/bin/env python3
"""Execute GUI child ownership and binary pipes on the actual Windows kernel.

Only newly owned fixture processes, unnamed objects and private temporary files
are used. The child is the exact compiled test image, not a simulated process.
This gate proves launcher primitives; C# GUI composition, standard-user UAC and
cross-account acceptance remain separate mandatory product evidence.
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
PACKAGE = ROOT / "internal/windowscontroller"
SPEC = importlib.util.spec_from_file_location(
    "gui_native_toolchain", ROOT / "deploy/test_desktop_windows_identity.py")
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)

REQUIRED = (
    "TestWindowsControllerGUIParentRightsAndHandleIsolation",
    "TestWindowsControllerGUIOriginalUserAndPeer",
    "TestWindowsControllerGUIOldCleanupPreservesReplacement",
    "TestWindowsControllerGUICancelledCleanupRetainsOwner",
    "TestWindowsControllerGUIRetirementRevokesBeforeBlockedCleanup",
    "TestWindowsControllerGUIJobCloseFailureCanRetry",
    "TestWindowsControllerGUICancelledLaunchRunsNothing",
    "TestWindowsControllerGUIRejectsChangedImageBeforeResume",
    "TestWindowsControllerGUIJobRetiresDescendants",
    "TestWindowsControllerGUIOwnerDeathRetiresOnlyOwnedTree",
    "TestWindowsControllerGUIEnvironmentIsExact",
    "TestWindowsControllerStreamActualBinaryChunks",
    "TestWindowsControllerStreamBoundsAndCancellation",
    "TestWindowsControllerStreamCloseJoinsBorrowedWriter",
    "TestWindowsControllerGUIRejectedTerminationJoinsExactProcess",
)


def sources():
    expected = {"api_windows.go", "identity_windows.go", "launch_windows.go",
                "pipe_windows.go", "process_windows.go", "gui_windows.go", "stream_windows.go",
                "fixture_windows_test.go", "foundation_windows_test.go", "capture_windows_test.go",
                "restricted_worker_windows_test.go", "gui_windows_test.go", "stream_windows_test.go"}
    paths = sorted(PACKAGE.glob("*.go"))
    if PACKAGE.is_symlink() or {path.name for path in paths} != expected:
        raise ValueError("Native GUI source/test closure changed")
    paths.extend(ROOT / name for name in ("go.mod", "deploy/test_desktop_windows_identity.py",
                                         "deploy/test_windows_controller_gui.py"))
    checksum = ROOT / "go.sum"
    if checksum.exists() or checksum.is_symlink():
        paths.append(checksum)
    records = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Native GUI proof requires exact regular source: " + str(path))
        records[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def mutants():
    gui = (PACKAGE / "gui_windows.go").read_text(encoding="utf-8")
    pipe = (PACKAGE / "pipe_windows.go").read_text(encoding="utf-8")
    once = NATIVE.replace_once
    original = "actual.Primary || actual.SID != want.SID || actual.AuthenticationID != want.AuthenticationID || actual.SessionID != want.SessionID || actual.Elevated != want.Elevated || actual.Administrator != want.Administrator"
    return (
        ("gui_windows.go", "excess-parent-rights", REQUIRED[0],
         "native GUI inherited excess parent authority",
         once(gui, "&parent, 0x00100000|0x1000, true, 0)", "&parent, 0x001fffff, true, 0)")),
        ("gui_windows.go", "unrelated-inheritable-object", REQUIRED[0],
         "native GUI inherited an unrelated inheritable kernel object",
         once(gui, "\t\tok, _, callErr = api.update.Call(uintptr(list)",
              "\t\tif attribute.kind == 0x00020002 { continue }\n\t\tok, _, callErr = api.update.Call(uintptr(list)")),
        ("gui_windows.go", "captured-original-logon", REQUIRED[1],
         "native GUI admitted a pipe writer outside its captured original logon identity",
         once(gui, "if " + original + " {", "if false && (" + original + ") {")),
        ("gui_windows.go", "retired-gui-admission", REQUIRED[4],
         "retiring GUI admitted a live pipe while cleanup was still blocked",
         once(once(gui, " || child.retiring.Load()", ""),
              "if child.retiring.Load() {", "if false {")),
        ("gui_windows.go", "final-job-close-retry", REQUIRED[5],
         "GUI could not retire its retained Job after an actual final-close failure",
         once(gui, "if child.process != nil && !child.processClosed {\n\t\t// A partial/ambiguous",
              "if child.process != nil {\n\t\t// A partial/ambiguous")),
        ("gui_windows.go", "cancelled-gui-builder", REQUIRED[6],
         "cancelled GUI launch admitted a new native owner or builder",
         once(gui, "\tif err := ctx.Err(); err != nil {\n\t\treturn nil, err\n\t}",
              "\t// Broken: cancelled launches enter a new owner.")),
        ("gui_windows.go", "suspended-image-readback", REQUIRED[7],
         "native GUI resumed a different actual image than its pinned capture",
         once(gui, "\tif err := child.process.VerifyImage(image); err != nil {\n\t\treturn child, err\n\t}",
              "\t// Broken: the suspended actual image is not compared.")),
        ("gui_windows.go", "launcher-death-job", REQUIRED[9],
         "GUI launcher death left its owned GUI tree alive",
         once(gui, "limits := jobLimits{Flags: 0x2000", "limits := jobLimits{Flags: 0")),
        ("gui_windows.go", "ambiguous-gui-environment", REQUIRED[10],
         "native GUI accepted ambiguous or unbounded environment input",
         once(gui, "\t\tif _, exists := entries[key]; exists {\n\t\t\treturn nil, errors.New(\"native GUI environment repeats a Windows variable\")\n\t\t}",
              "\t\t// Broken: aliases overwrite captured Windows variables.")),
        ("pipe_windows.go", "binary-entered-writer-join", REQUIRED[13],
         "binary channel closed its native handle before the captured borrow joined",
         NATIVE.function_mutant(pipe, "func (p *Pipe) Close()", "p.operations.Wait()",
                                "/* broken: no entered binary I/O join */")),
        ("gui_windows.go", "termination-error-before-join", REQUIRED[14],
         "GUI termination error bypassed the exact live process wait",
         once(gui, "func joinGUIProcessTermination(ctx context.Context, process *Process, terminateErr error) error {",
              "func joinGUIProcessTermination(ctx context.Context, process *Process, terminateErr error) error {\n\tif terminateErr != nil { return terminateErr }")),
        ("gui_windows.go", "termination-error-lost-on-cancel", REQUIRED[14],
         "bounded GUI join discarded cancellation or its actual termination failure",
         NATIVE.function_mutant(gui, "func joinGUIProcessTermination(",
                                "return errors.Join(terminateErr, err)", "return err")),
    )


def execute(go="go"):
    if platform.system() != "Windows":
        raise ValueError("GUI process/handle proof requires actual Windows execution")
    before = sources()
    compiler, environment, architecture = NATIVE.selected_compiler(go, ROOT, dict(os.environ))
    race = ["-race"] if architecture == "amd64" else []
    environment["CGO_ENABLED"] = "1" if race else "0"
    with tempfile.TemporaryDirectory(prefix="routervpn-gui-native-") as directory:
        owned = Path(directory)
        build = [compiler, "test", "-c", "-mod=readonly", *race]
        baseline = owned / "gui.test.exe"
        status, output = NATIVE.run([*build, "-o", baseline, "./internal/windowscontroller"], cwd=ROOT, env=environment)
        if status:
            raise ValueError("Native GUI compilation failed:\n" + output[-16384:])
        identity = hashlib.sha256(baseline.read_bytes()).hexdigest()
        selector = "^(" + "|".join(REQUIRED) + ")$"
        status, output = NATIVE.run([baseline, "-test.run=" + selector, "-test.count=1", "-test.timeout=180s", "-test.v"],
                                    cwd=ROOT, env=environment, timeout=195)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if (status or "--- SKIP:" in output or "DATA RACE" in output or
                any("--- PASS: " + name + " (" not in output for name in REQUIRED)):
            raise ValueError("Native GUI did not execute every actual process/pipe boundary")
        if hashlib.sha256(baseline.read_bytes()).hexdigest() != identity:
            raise ValueError("Native GUI test image changed during its proof")
        for filename, name, test, witness, replacement in mutants():
            changed = owned / (name + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = owned / (name + ".json")
            overlay.write_text(json.dumps({"Replace": {str(PACKAGE / filename): str(changed)}}), encoding="utf-8")
            candidate = owned / (name + ".test.exe")
            status, output = NATIVE.run([*build, "-overlay=" + str(overlay), "-o", candidate,
                                        "./internal/windowscontroller"], cwd=ROOT, env=environment)
            if status:
                raise ValueError("Native GUI mutant did not compile: " + name + "\n" + output[-8192:])
            status, output = NATIVE.run([candidate, "-test.run=^" + test + "$", "-test.count=1", "-test.timeout=45s", "-test.v"],
                                        cwd=ROOT, env=environment, timeout=60)
            if (status == 0 or witness not in output or "--- FAIL: " + test + " (" not in output or
                    "--- SKIP:" in output or "panic: test timed out" in output or "DATA RACE" in output):
                raise ValueError("Native GUI mutant did not reach its exact semantic rejection: " + name + "\n" + output[-16384:])
            print("Rejected production native GUI mutant:", name, flush=True)
        if sources() != before:
            raise ValueError("Native GUI sources changed during execution")
    print("Native GUI ownership passed fifteen actual kernel process/pipe cases and twelve compiled production negative controls; C# application and cross-account UAC composition remain separate.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    execute(parser.parse_args().go)
