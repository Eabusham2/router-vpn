#!/usr/bin/env python3
"""Execute Windows controller process/IPC ownership against the native kernel.

No launcher is admitted by a source marker. This gate executes the actual
Windows package, including private pipes, exact process tokens and image files,
joined overlapped I/O, ShellExecuteEx and kill-on-close Job descendants. Every
negative control changes compiled production code and must reach its specific
failure witness; a compile error, timeout or skipped capability is no proof.
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
    "windows_controller_native_toolchain", ROOT / "deploy/test_desktop_windows_identity.py")
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
TARGET = ROOT / "internal/windowscontroller"
REQUIRED = (
    "TestWindowsControllerFoundationActualTokenAndABI",
    "TestWindowsControllerFoundationSingleLocalPipe",
    "TestWindowsControllerFoundationActualPeerAndPrivateFrames",
    "TestWindowsControllerFoundationRejectWrongProcessAndImage",
    "TestWindowsControllerFoundationRejectImpersonatingPipe",
    "TestWindowsControllerFoundationCancelledAcceptAndRead",
    "TestWindowsControllerFoundationCloseJoinsEnteredOperation",
    "TestWindowsControllerFoundationCloseJoinsPendingKernelRead",
    "TestWindowsControllerFoundationPinnedImageRejectsReplacement",
    "TestWindowsControllerFoundationRejectHardlinkAndReparse",
    "TestWindowsControllerFoundationFramesAreBounded",
    "TestWindowsControllerFoundationProcessCloseJoinsBorrow",
    "TestWindowsControllerFoundationProcessDeathOwnsDescendants",
    "TestWindowsControllerFoundationRejectCancelledUAC",
    "TestWindowsControllerFoundationLateLaunchKeepsOwner",
    "TestWindowsControllerFoundationActualElevatedLaunch",
    "TestWindowsControllerFoundationReadFrameLeavesLifetimeByte",
    "TestWindowsControllerFoundationRetainsGrantedLaunchHandle",
    "TestWindowsControllerFoundationCapturedVolumeSurvivesDriveRebind",
    "TestWindowsControllerFoundationRejectRemoteVolumeNames",
    "TestWindowsControllerFoundationPinnedPackageCode",
    "TestWindowsControllerFoundationPinnedPackageCodeRejectsAliases",
    "TestWindowsControllerFoundationSuspendedLaunchRejectsReplacement",
    "TestWindowsControllerFoundationSuspendedLaunchRejectsMissingCallback",
    "TestWindowsControllerFoundationSuspendedLaunchCancellation",
    "TestWindowsControllerFoundationSuspendedLaunchThreadOwner",
    "TestWindowsControllerFoundationSuspendedLaunchCreationCount",
    "TestWindowsControllerFoundationSuspendedCallbackRefusal",
)


def sources():
    expected = {"api_windows.go", "identity_windows.go", "launch_windows.go",
                "pipe_windows.go", "process_windows.go", "gui_windows.go", "stream_windows.go",
                "code_file_windows.go", "code_file_windows_test.go",
                "process_profile_windows.go", "process_profile_windows_test.go",
                "system_image_windows.go", "system_image_windows_test.go",
                "system_image_policy.go", "system_image_policy_test.go",
                "machine_directories_windows.go", "machine_directories_windows_test.go",
                "fixture_windows_test.go", "foundation_windows_test.go", "capture_windows_test.go",
                "suspended_launch_windows.go", "suspended_launch_windows_test.go",
                "restricted_worker_windows_test.go", "gui_windows_test.go", "stream_windows_test.go"}
    paths = sorted(TARGET.glob("*.go"))
    if {path.name for path in paths} != expected:
        raise ValueError("Windows controller native source/test closure changed")
    if TARGET.is_symlink() or any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError("Windows controller native source must be regular captured files")
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def mutants():
    read = lambda name: (TARGET / name).read_text(encoding="utf-8")
    once = NATIVE.replace_once
    function = NATIVE.function_mutant
    pipe = read("pipe_windows.go")
    process = read("process_windows.go")
    identity = read("identity_windows.go")
    launch = read("launch_windows.go")
    suspended = read("suspended_launch_windows.go")
    return (
        ("pipe_windows.go", "retained-pid", REQUIRED[3],
         "same executable with a different retained PID acquired the private channel",
         once(once(pipe, "if peer.Process.PID() != expected.PID() {", "if false {"),
              "if pid != expected.PID() {", "if false {")),
        ("process_windows.go", "actual-image-file", REQUIRED[3],
         "different file with identical executable bytes acquired the private channel",
         once(process,
              "want.VolumeSerialNumber != got.VolumeSerialNumber || want.FileIndexHigh != got.FileIndexHigh || want.FileIndexLow != got.FileIndexLow",
              "got.NumberOfLinks == 0")),
        ("identity_windows.go", "identification-only", REQUIRED[4],
         "a client granting impersonation acquired the identification-only boundary",
         once(identity, "captured.Primary || level != 1", "captured.Primary || level < 1")),
        ("pipe_windows.go", "entered-pipe-join", REQUIRED[6],
         "Close returned before the entered pipe operation joined",
         function(pipe, "func (p *Pipe) Close()", "p.operations.Wait()", "/* broken: no entered I/O join */")),
        ("process_windows.go", "entered-process-join", REQUIRED[11],
         "process reference closed before its entered read joined",
         function(process, "func (p *Process) Close()", "p.operations.Wait()", "/* broken: no entered process read join */")),
        ("process_windows.go", "image-write-sharing", REQUIRED[8],
         "pinned image allowed a concurrent writer",
         once(process, "access, share, flags = syscall.GENERIC_READ, syscall.FILE_SHARE_READ, 0x00200000",
              "access, share, flags = syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, 0x00200000")),
        ("process_windows.go", "image-hardlink", REQUIRED[9],
         "hardlinked executable was admitted as one owned image",
         once(process, "info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 || info.NumberOfLinks != 1",
              "info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0")),
        ("process_windows.go", "image-reparse", REQUIRED[9],
         "reparse executable was admitted as the captured image",
         once(process, "info.FileAttributes&0x400 != 0 || (!last", "(!last")),
        ("launch_windows.go", "job-owner-death", REQUIRED[12],
         "controller process death left its owned descendant alive",
         once(launch, "jobLimits{Flags: 0x2000", "jobLimits{Flags: 0")),
        ("launch_windows.go", "late-uac-owner", REQUIRED[14],
         "late native launch was hidden behind cancellation without its owner",
         once(launch, "done <- result{process, ctx.Err()}",
              "if ctx.Err() != nil { _ = process.Close(); process = nil }; done <- result{process, ctx.Err()}")),
        ("pipe_windows.go", "reopened-admin-process", REQUIRED[17],
         "retained launch handle was rejected by a fresh process DACL",
         once(pipe, "process, err = expected.retain()", "process, err = OpenProcess(pid)")),
        ("process_windows.go", "mutable-launch-drive", REQUIRED[18],
         "retargeted DOS drive replaced the retained executable",
         once(process, "image.path = canonical", "image.path = path")),
        ("process_windows.go", "package-code-write-sharing", REQUIRED[20],
         "retained package code allowed another writer",
         once(process, "access, share, flags = syscall.GENERIC_READ, syscall.FILE_SHARE_READ, 0x00200000",
              "access, share, flags = syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, 0x00200000")),
        ("process_windows.go", "package-code-launch-capability", REQUIRED[20],
         "a non-executable code pin acquired a process launch capability",
         once(process, 'err != nil || !strings.EqualFold(filepath.Ext(clean), ".exe")',
              'err != nil || false')),
        ("suspended_launch_windows.go", "suspended-image-before-resume", REQUIRED[22],
         "replacement image was admitted before its captured pre-resume proof",
         once(suspended,
              'return errors.New("suspended Shell process mapped a different captured native image path")',
              'return nil')),
        ("suspended_launch_windows.go", "suspended-creation-site", REQUIRED[23],
         "a missing Shell creation callback admitted its child",
         once(suspended, 'if err := site.prove(); err != nil {',
              'if err := site.prove(); false && err != nil {')),
        ("suspended_launch_windows.go", "suspended-cancelled-owner", REQUIRED[24],
         "cancelled suspended launch lost its original caller",
         function(once(suspended, 'if launchErr != nil {',
                       'if launchErr != nil && !errors.Is(launchErr, context.Canceled) {'),
                  'func resumeSuspendedShellThread(', 'if err := ctx.Err(); err != nil {',
                  'if err := ctx.Err(); false && err != nil {')),
        ("suspended_launch_windows.go", "suspended-thread-owner", REQUIRED[25],
         "a foreign retained thread was considered for Shell resume",
         once(suspended, 'if thread == 0 || pid != uintptr(process.PID()) {',
              'if thread == 0 || false && pid != uintptr(process.PID()) {')),
        ("suspended_launch_windows.go", "suspended-original-count", REQUIRED[26],
         "a changed initial suspension count was admitted for Shell resume",
         once(suspended, 'if uint32(previous) != 1 {',
              'if false && uint32(previous) != 1 {')),
        ("suspended_launch_windows.go", "suspended-callback-refusal", REQUIRED[27],
         "cancelled Shell callback lost its local admission refusal",
         once(suspended, 'if site.ctx.Err() != nil {',
              'if false && site.ctx.Err() != nil {')),
        ("suspended_launch_windows.go", "suspended-cancel-before-suspension", REQUIRED[27],
         "cancelled Shell callback omitted its actual creation suspension",
         once(suspended, 'if site.calls.Add(1) != 1 || inputs == nil {',
              'if site.ctx.Err() != nil {\n\t\tsite.calls.Add(1)\n\t\treturn reject(0x800704c7)\n\t}\n\tif site.calls.Add(1) != 1 || inputs == nil {')),
    )


def execute(go="go", *, env=None):
    if platform.system() != "Windows":
        raise ValueError("Controller ownership proof requires actual Windows execution")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Controller ownership gate requires its actual elevated native test host")
    before = sources()
    compiler, captured, architecture = NATIVE.selected_compiler(
        go, ROOT, dict(os.environ if env is None else env))
    race = ["-race"] if architecture == "amd64" else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    package = "./internal/windowscontroller"
    with tempfile.TemporaryDirectory(prefix="routervpn-controller-native-") as directory:
        workspace = Path(directory)
        binary = workspace / "controller.test.exe"
        build = [compiler, "test", "-c", "-mod=readonly", *race]
        status, output = NATIVE.run([*build, "-o", binary, package], cwd=ROOT, env=captured)
        if status:
            raise ValueError("Windows controller native compilation failed:\n" + output[-32768:])
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        status, output = NATIVE.run(
            [binary, "-test.run=^TestWindowsControllerFoundation", "-test.count=1",
             "-test.timeout=120s", "-test.v"], cwd=ROOT, env=captured, timeout=135)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if (status or "--- SKIP:" in output or "DATA RACE" in output or
                any("--- PASS: " + name + " (" not in output for name in REQUIRED)):
            raise ValueError("Windows controller did not execute every native ownership boundary")
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Windows controller test binary changed during execution")
        for filename, name, test, witness, replacement in mutants():
            changed = workspace / (name + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = workspace / (name + ".json")
            overlay.write_text(json.dumps({"Replace": {str(TARGET / filename): str(changed)}}), encoding="utf-8")
            candidate = workspace / (name + ".test.exe")
            status, output = NATIVE.run(
                [*build, "-overlay=" + str(overlay), "-o", candidate, package], cwd=ROOT, env=captured)
            if status:
                raise ValueError("Windows controller mutant failed to compile: " + name + "\n" + output[-8192:])
            status, output = NATIVE.run(
                [candidate, "-test.run=^" + test + "$", "-test.count=1", "-test.timeout=35s", "-test.v"],
                cwd=ROOT, env=captured, timeout=45)
            if (status == 0 or "--- FAIL: " + test + " (" not in output or witness not in output or
                    "--- SKIP:" in output or "panic: test timed out" in output or "DATA RACE" in output):
                raise ValueError("Windows controller mutant did not reach its exact rejection: " + name + "\n" + output[-16384:])
            print("Rejected production Windows controller mutant:", name, flush=True)
        if sources() != before:
            raise ValueError("Windows controller source changed during its native proof")
    print(f"Windows controller foundation passed {len(REQUIRED)} actual process/IPC/lifetime/package-code cases and {len(mutants())} compiled production negative controls; launcher composition remains a separate gate.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    execute(parser.parse_args().go)
