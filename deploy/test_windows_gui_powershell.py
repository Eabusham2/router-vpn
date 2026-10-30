#!/usr/bin/env python3
"""Execute the shipping PS adapter through actual Windows GUI ownership and TLS.

The selected PowerShell process compiles the packaged C# transport, proves its
inherited parent against the actual pipe server, and forwards exact JSON/import
requests through Go's retained controller TLS client. No fake Stream is used.
WPF rendering and cross-account UAC remain separate native product gates.
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
SPEC = importlib.util.spec_from_file_location(
    "windows_gui_powershell_native", ROOT / "deploy/test_desktop_windows_identity.py")
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
REQUIRED = (
    "TestWindowsUIBridgePowerShellActualRequests",
    "TestWindowsUIBridgePowerShellCancellation",
    "TestWindowsUIBridgePowerShellWrongParent",
    "TestWindowsUIBridgePowerShellWrongPin",
)
CODE = (
    "client/RouterVPN-Windows-ControllerTransport.psm1",
    "client/RouterVPN-Windows-ControllerTransport.cs",
    "deploy/fixtures/windows-controller-transport/bridge_process.ps1",
)


def sources():
    paths = [ROOT / name for name in (*CODE, "go.mod", "deploy/test_windows_gui_powershell.py",
                                    "deploy/test_desktop_windows_identity.py")]
    for name in ("windowsuibridge", "windowscontroller", "controllerbridge", "controllertransport"):
        directory = ROOT / "internal" / name
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("PowerShell native composition dependency was replaced")
        paths.extend(directory.glob("*.go"))
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError("PowerShell native composition requires regular captured sources")
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def execute(go="go", shell="powershell.exe"):
    if platform.system() != "Windows":
        raise ValueError("Actual PowerShell process/pipe proof requires Windows execution")
    before = sources()
    compiler, environment, architecture = NATIVE.selected_compiler(go, ROOT, dict(os.environ))
    resolved = shutil.which(shell)
    if resolved is None or not Path(resolved).is_absolute():
        raise ValueError("The selected real PowerShell executable is unavailable")
    shell = str(Path(resolved).resolve())
    status, output = NATIVE.run(
        [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
         "@{edition=$PSVersionTable.PSEdition;major=$PSVersionTable.PSVersion.Major;minor=$PSVersionTable.PSVersion.Minor;path=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName}|ConvertTo-Json -Compress"],
        cwd=ROOT, env=environment, timeout=30)
    if status:
        raise ValueError("Actual PowerShell identity probe failed:\n" + output[-8192:])
    identity = json.loads(output)
    edition = identity.get("edition")
    if (edition == "Desktop" and (identity.get("major"), identity.get("minor")) != (5, 1) or
            edition == "Core" and identity.get("major", 0) < 7 or edition not in ("Desktop", "Core") or
            os.path.normcase(os.path.abspath(identity.get("path", ""))) != os.path.normcase(shell)):
        raise ValueError("Selected PowerShell differs from its actual executable/runtime identity")
    shell_hash = hashlib.sha256(Path(shell).read_bytes()).hexdigest()
    environment.update(ROUTERVPN_GUI_POWERSHELL=shell, ROUTERVPN_GUI_POWERSHELL_KIND=edition,
                       ROUTERVPN_GUI_POWERSHELL_ROOT=str(ROOT))
    race = ["-race"] if architecture == "amd64" else []
    environment["CGO_ENABLED"] = "1" if race else "0"
    with tempfile.TemporaryDirectory(prefix="routervpn-powershell-native-") as directory:
        owned = Path(directory)
        binary = owned / "powershell-bridge.test.exe"
        status, output = NATIVE.run(
            [compiler, "test", "-c", "-mod=readonly", *race, "-o", binary, "./internal/windowsuibridge"],
            cwd=ROOT, env=environment, timeout=180)
        if status:
            raise ValueError("Actual PowerShell bridge fixture did not compile:\n" + output[-16384:])
        binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
        selector = "^(" + "|".join(REQUIRED) + ")$"
        status, output = NATIVE.run([binary, "-test.run=" + selector, "-test.count=1", "-test.timeout=180s", "-test.v"],
                                   cwd=ROOT, env=environment, timeout=195)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if (status or "--- SKIP:" in output or "DATA RACE" in output or
                any("--- PASS: " + name + " (" not in output for name in REQUIRED)):
            raise ValueError("Actual PowerShell did not execute every native adapter boundary")
        # Exercise the same native executable against an isolated copy with one
        # actual production defect. The fixture's HTTP spy must catch fallback;
        # compile/launch failures and arbitrary nonzero exits are not evidence.
        variant = owned / "ordinary-http-defect"
        for name in CODE:
            target = variant / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
        adapter = variant / CODE[0]
        adapter.write_text(NATIVE.replace_once(adapter.read_text(encoding="utf-8"),
            "$Response=$Client.SendAsync($Request,[Threading.CancellationToken]::None).GetAwaiter().GetResult()",
            "return Invoke-RestMethod -Uri $Uri -Method $Method -TimeoutSec $TimeoutSec"), encoding="utf-8")
        changed = dict(environment, ROUTERVPN_GUI_POWERSHELL_ROOT=str(variant))
        status, output = NATIVE.run([binary, "-test.run=^" + REQUIRED[0] + "$", "-test.count=1", "-test.timeout=60s", "-test.v"],
                                   cwd=ROOT, env=changed, timeout=75)
        if (status == 0 or "--- FAIL: " + REQUIRED[0] + " (" not in output or
                "CONTROL owned PowerShell used ordinary HTTP" not in output or "--- SKIP:" in output or
                "panic: test timed out" in output or "DATA RACE" in output):
            raise ValueError("Actual PowerShell fallback defect missed its exact rejection:\n" + output[-16384:])
        print("Rejected executable native PowerShell ordinary-HTTP fallback defect", flush=True)
        if hashlib.sha256(binary.read_bytes()).hexdigest() != binary_hash or hashlib.sha256(Path(shell).read_bytes()).hexdigest() != shell_hash:
            raise ValueError("Actual PowerShell or native bridge fixture changed during execution")
    if sources() != before:
        raise ValueError("Actual PowerShell source closure changed during execution")
    print("Actual", edition, "PowerShell passed four native Go/pipe/TLS cases and an executable adapter fallback defect; WPF and cross-account UAC acceptance remain separate.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--shell", default="powershell.exe")
    args = parser.parse_args()
    execute(args.go, args.shell)
