#!/usr/bin/env python3
"""Execute the real C# public GUI channel against the Go native owner and TLS.

The C# library is compiled by Windows PowerShell 5.1, referenced by a fresh
Framework process executable, and launched by the actual original-user GUI
Job/handle implementation. This gate does not use the C# Stream test seam or
substitute source markers for process, pipe, token, cancellation or TLS proof.
Shipping WPF/Tray composition and cross-account UAC remain separate gates.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "internal/windowsuibridge"
SPEC = importlib.util.spec_from_file_location(
    "windows_gui_bridge_native", ROOT / "deploy/test_desktop_windows_identity.py")
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)

REQUIRED = (
    "TestWindowsUIBridgeActualCSharpAndPinnedTLS",
    "TestWindowsUIBridgeActualCancellationAndDrain",
    "TestWindowsUIBridgeRetiredGUIRevokesPendingHTTP",
    "TestWindowsUIBridgeOneGUIClosePreservesOther",
    "TestWindowsUIBridgeWrongChildNeverForwards",
    "TestWindowsUIBridgeWrongParentHandleSendsNoHello",
    "TestWindowsUIBridgeWrongTLSPinSendsNoBearer",
    "TestWindowsUIBridgeWrongServerSendsNoHello",
)


def sources():
    expected = {"bridge_windows.go", "bridge_windows_test.go"}
    paths = sorted(PACKAGE.glob("*.go"))
    if PACKAGE.is_symlink() or {path.name for path in paths} != expected:
        raise ValueError("Native GUI composition source closure changed")
    for name in ("internal/windowscontroller", "internal/controllerbridge", "internal/controllertransport"):
        directory = ROOT / name
        if directory.is_symlink():
            raise ValueError("Native GUI composition dependency was replaced")
        paths.extend(directory.glob("*.go"))
    paths.extend(ROOT / name for name in (
        "go.mod", "client/RouterVPN-Windows-ControllerTransport.cs",
        "client/test-windows-controller-transport.ps1",
        "deploy/fixtures/windows-controller-transport/bridge_process.cs",
        "deploy/fixtures/windows-controller-transport/compile_bridge.ps1",
        "deploy/test_windows_gui_bridge.py", "deploy/test_desktop_windows_identity.py"))
    records = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Native GUI composition requires captured regular source: " + str(path))
        records[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def mutants():
    source = (PACKAGE / "bridge_windows.go").read_text(encoding="utf-8")
    return (
        ("captured-child", REQUIRED[4], "unproved peer acquired the C# channel",
         NATIVE.replace_once(source, "peer, err := child.VerifyPeer(pipe, image)", "peer, err := pipe.Peer()")),
        ("retired-child-request", REQUIRED[2],
         "retired GUI forwarded a new request using another owner's shared TLS client",
         NATIVE.replace_once(source,
             "\tif err := forward.child.Alive(); err != nil {\n\t\treturn controllertransport.Response{}, err\n\t}",
             "\t// Broken: retired GUI reuses the shared controller.")),
        ("exact-ready-frame", REQUIRED[0], "The captured native UI channel received an invalid frame.",
         NATIVE.replace_once(source, 'const ready = "RouterVPN-UI-Bridge-Ready-v1\\n"',
                                   'const ready = "RouterVPN-UI-Bridge-Ready-v0\\n"')),
    )


def compile_fixture(directory, shell, captured, source=None, platform_target="anycpu"):
    directory.mkdir()
    library = directory / "RouterVPN.ControllerTransport.dll"
    executable = directory / "RouterVPN.GuiBridgeFixture.exe"
    arguments = [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                 ROOT / "client/test-windows-controller-transport.ps1", "-CompileAssembly", library]
    if source is not None:
        arguments += ["-Source", source]
    status, output = NATIVE.run(arguments, cwd=ROOT, env=captured, timeout=90)
    if status or "PASS controller GUI transport production DLL compilation" not in output:
        raise ValueError("Actual Framework GUI library compilation failed:\n" + output[-16384:])
    status, output = NATIVE.run(
        [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
         ROOT / "deploy/fixtures/windows-controller-transport/compile_bridge.ps1",
         "-Assembly", library, "-Fixture", ROOT / "deploy/fixtures/windows-controller-transport/bridge_process.cs",
         "-Output", executable, "-Platform", platform_target], cwd=ROOT, env=captured, timeout=90)
    if status or "PASS actual Framework GUI process compilation" not in output:
        raise ValueError("Actual Framework GUI process compilation failed:\n" + output[-16384:])
    return executable, {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in (library, executable)}


def diagnose_managed_creation(workspace, shell, captured, architecture, build, package, executable):
    """Bounded failure-only controls; never replace the required baseline.

    Keep the actual private creation-time Job, handle allowlist, suspended image
    readback and C# public channel unchanged. Compare native64 PE metadata with
    the same AnyCPU source, then the same retained volume's normalized Win32
    spelling. No mutable DOS drive or unowned running process is introduced.
    """
    if architecture != "amd64":
        print("Managed creation PE diagnostic is limited to the actual AMD64 Framework compiler", flush=True)
        return
    native_image, _ = compile_fixture(workspace / "diagnostic-native64", shell, captured,
                                      platform_target="x64")
    path = ROOT / "internal/windowscontroller/gui_windows.go"
    source = path.read_text(encoding="utf-8")
    needle = ('\tapplication, _ := syscall.UTF16PtrFromString(image.path)\n'
              '\tcommand, _ := syscall.UTF16FromString(syscall.EscapeArg(image.path) + " " + strings.Join(quoted, " "))')
    replacement = ('\t// Diagnostic only: the same retained volume identity, with Win32 normalization.\n'
                   '\tlaunchPath := `\\\\.\\` + image.path[len(`\\\\?\\`):]\n'
                   '\tapplication, _ := syscall.UTF16PtrFromString(launchPath)\n'
                   '\tcommand, _ := syscall.UTF16FromString(syscall.EscapeArg(launchPath) + " " + strings.Join(quoted, " "))')
    changed = workspace / "diagnostic-volume-spelling.go"
    changed.write_text(NATIVE.replace_once(source, needle, replacement), encoding="utf-8")
    overlay = workspace / "diagnostic-volume-spelling.json"
    overlay.write_text(json.dumps({"Replace": {str(path): str(changed)}}), encoding="utf-8")
    for name, image, flags in (
            ("native64-canonical-volume", native_image, []),
            ("anycpu-normalized-volume", executable, ["-overlay=" + str(overlay)]),
            ("native64-normalized-volume", native_image, ["-overlay=" + str(overlay)])):
        binary = workspace / ("diagnostic-" + name + ".test.exe")
        status, output = NATIVE.run([*build, *flags, "-o", binary, package], cwd=ROOT, env=captured, timeout=180)
        if status:
            raise ValueError("Managed creation diagnostic did not compile: " + name + "\n" + output[-8192:])
        variant = dict(captured, ROUTERVPN_GUI_BRIDGE_FIXTURE=str(image))
        status, output = NATIVE.run([binary, "-test.run=^" + REQUIRED[0] + "$", "-test.count=1",
                                    "-test.timeout=35s", "-test.v"], cwd=ROOT, env=variant, timeout=45)
        print("Managed creation diagnostic:", name, "exit", status, flush=True)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)


def execute(go="go", shell="powershell.exe"):
    if platform.system() != "Windows":
        raise ValueError("Actual native GUI composition requires Windows execution")
    before = sources()
    compiler, captured, architecture = NATIVE.selected_compiler(go, ROOT, dict(os.environ))
    resolved = shutil.which(shell)
    if resolved is None or not Path(resolved).is_absolute():
        raise ValueError("Native GUI composition requires an actual selected Framework shell")
    shell = str(Path(resolved).resolve())
    race = ["-race"] if architecture == "amd64" else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    package = "./internal/windowsuibridge"
    with tempfile.TemporaryDirectory(prefix="routervpn-gui-composition-") as directory:
        workspace = Path(directory)
        executable, artifacts = compile_fixture(workspace / "baseline", shell, captured)
        captured["ROUTERVPN_GUI_BRIDGE_FIXTURE"] = str(executable)
        binary = workspace / "bridge.test.exe"
        build = [compiler, "test", "-c", "-mod=readonly", *race]
        status, output = NATIVE.run([*build, "-o", binary, package], cwd=ROOT, env=captured, timeout=180)
        if status:
            raise ValueError("Actual Go GUI composition did not compile:\n" + output[-16384:])
        artifacts[str(binary)] = hashlib.sha256(binary.read_bytes()).hexdigest()
        status, output = NATIVE.run([binary, "-test.run=^TestWindowsUIBridge", "-test.count=1",
                                    "-test.timeout=120s", "-test.v"], cwd=ROOT, env=captured, timeout=135)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if (status or "--- SKIP:" in output or "DATA RACE" in output or
                any("--- PASS: " + name + " (" not in output for name in REQUIRED)):
            if "original-user GUI suspended CreateProcess: The parameter is incorrect." in output:
                diagnose_managed_creation(workspace, shell, captured, architecture, build, package, executable)
            raise ValueError("Native C# GUI composition did not execute every actual boundary")
        for name, test, witness, replacement in mutants():
            changed = workspace / (name + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = workspace / (name + ".json")
            overlay.write_text(json.dumps({"Replace": {str(PACKAGE / "bridge_windows.go"): str(changed)}}), encoding="utf-8")
            mutant = workspace / (name + ".test.exe")
            status, output = NATIVE.run([*build, "-overlay=" + str(overlay), "-o", mutant, package], cwd=ROOT, env=captured)
            if status:
                raise ValueError("GUI composition mutant did not compile: " + name + "\n" + output[-8192:])
            status, output = NATIVE.run([mutant, "-test.run=^" + test + "$", "-test.count=1",
                                        "-test.timeout=45s", "-test.v"], cwd=ROOT, env=captured, timeout=55)
            if (status == 0 or "--- FAIL: " + test + " (" not in output or witness not in output or
                    "--- SKIP:" in output or "panic: test timed out" in output or "DATA RACE" in output):
                raise ValueError("Native GUI composition mutant missed its actual rejection: " + name + "\n" + output[-16384:])
            print("Rejected compiled native GUI composition mutant:", name, flush=True)
        changed = workspace / "unproved-server.cs"
        changed.write_text(NATIVE.replace_once(
            (ROOT / "client/RouterVPN-Windows-ControllerTransport.cs").read_text(encoding="utf-8"),
            "!Native.GetNamedPipeServerProcessId(pipe, out server) || server != pid",
            "!Native.GetNamedPipeServerProcessId(pipe, out server)"), encoding="utf-8")
        candidate, _ = compile_fixture(workspace / "wrong-server", shell, captured, changed)
        variant = dict(captured, ROUTERVPN_GUI_BRIDGE_FIXTURE=str(candidate))
        test = REQUIRED[7]
        status, output = NATIVE.run([binary, "-test.run=^" + test + "$", "-test.count=1",
                                    "-test.timeout=45s", "-test.v"], cwd=ROOT, env=variant, timeout=55)
        if (status == 0 or "--- FAIL: " + test + " (" not in output or
                "C# disclosed handshake bytes before authenticating its actual parent server" not in output or
                "--- SKIP:" in output or "panic: test timed out" in output or "DATA RACE" in output):
            raise ValueError("C# server-PID mutant missed its actual no-disclosure boundary:\n" + output[-16384:])
        print("Rejected compiled native C# server-PID mutant", flush=True)
        for path, digest in artifacts.items():
            if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
                raise ValueError("Native GUI composition artifact changed while executing")
        if sources() != before:
            raise ValueError("Native GUI composition source changed during execution")
    print("Native GUI composition passed eight actual C#/Go process-pipe-TLS cases and four compiled production negative controls; shipping WPF/Tray and cross-account UAC remain separate.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--shell", default="powershell.exe")
    args = parser.parse_args()
    execute(args.go, args.shell)
