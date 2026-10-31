#!/usr/bin/env python3
"""Observe the first owned Windows UI launch in its own disposable native job.

This is an instrumented diagnostic, not shipping-source acceptance. The normal
Session job remains independent and unchanged. Only blank fixture copies receive
fixed timing markers; no user logs, credentials, arguments or environment are
recorded. No retry, warm-up, startup deadline or authentication bypass is added.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import stat
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("windows_cold_session", ROOT / "deploy/test_windows_app_session.py")
SESSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SESSION)
NATIVE = SESSION.NATIVE
PREFIX = "[RouterVPN-UI-startup]"


def marker(label):
    if not label or any(ch not in "abcdefghijklmnopqrstuvwxyz-" for ch in label):
        raise ValueError("UI startup marker is not a fixed public stage")
    return "[Console]::Error.WriteLine('" + PREFIX + " " + label + " ticks=' + [DateTime]::UtcNow.Ticks)"


def lookup_observers():
    # Both hooks are public in the Windows PowerShell 5.1 reference API.
    # They bracket normal command discovery, including module auto-loading.
    # Observe the original Add-Type lookup; do not pre-load or resolve it.
    # https://learn.microsoft.com/dotnet/api/system.management.automation.commandinvocationintrinsics.precommandlookupaction
    # https://learn.microsoft.com/dotnet/api/system.management.automation.commandinvocationintrinsics.postcommandlookupaction
    before = r"""    $RouterVPNDiagnosticInvocation=$null
    $RouterVPNDiagnosticCaptured=$false
    try{
        $RouterVPNDiagnosticInvocation=$ExecutionContext.InvokeCommand
        $RouterVPNDiagnosticPre=$RouterVPNDiagnosticInvocation.PreCommandLookupAction
        $RouterVPNDiagnosticPost=$RouterVPNDiagnosticInvocation.PostCommandLookupAction
        if($null-ne$RouterVPNDiagnosticPre-or$null-ne$RouterVPNDiagnosticPost){throw 'Existing lookup observers remain untouched.'}
        $RouterVPNDiagnosticCaptured=$true
        $RouterVPNDiagnosticInvocation.PreCommandLookupAction=[System.EventHandler[System.Management.Automation.CommandLookupEventArgs]]{
            param($Sender,$Lookup)
            try{if($Sender-ceq'Add-Type'-or$Sender-ceq'Microsoft.PowerShell.Utility\Add-Type'){
                PRE_MARKER
            }}catch{}
        }
        $RouterVPNDiagnosticInvocation.PostCommandLookupAction=[System.EventHandler[System.Management.Automation.CommandLookupEventArgs]]{
            param($Sender,$Lookup)
            try{if($Sender-ceq'Add-Type'-or$Sender-ceq'Microsoft.PowerShell.Utility\Add-Type'){
                POST_MARKER
            }}catch{}
        }
    }catch{try{
        UNAVAILABLE_MARKER
    }catch{}}
    try{
"""
    after = """    }finally{
        if($RouterVPNDiagnosticCaptured){
            try{$RouterVPNDiagnosticInvocation.PreCommandLookupAction=$RouterVPNDiagnosticPre}catch{try{
                RESTORE_MARKER
            }catch{}}
            try{$RouterVPNDiagnosticInvocation.PostCommandLookupAction=$RouterVPNDiagnosticPost}catch{try{
                RESTORE_MARKER
            }catch{}}
        }
    }
"""
    before = before.replace('PRE_MARKER', marker('framework-command-lookup-begin'))
    before = before.replace('POST_MARKER', marker('framework-command-lookup-complete'))
    before = before.replace('UNAVAILABLE_MARKER', marker('framework-command-observers-unavailable'))
    after = after.replace('RESTORE_MARKER', marker('framework-command-observers-restore-failed'))
    return before, after


def instrumented_scripts():
    result = {}
    for role in ("App", "Tray"):
        path = "client/RouterVPN-Windows-" + role + ".ps1"
        source = (ROOT / path).read_bytes().decode("utf-8")
        preference = "$ErrorActionPreference='Stop'" if role == "App" else "$ErrorActionPreference = 'Stop'"
        source = NATIVE.replace_once(source, preference, preference + "\n" + marker(role.lower() + "-script-entered"))
        boundary = "    Import-Module ([IO.Path]::Combine($PSScriptRoot,'RouterVPN-Windows-ControllerTransport.psm1')) -Global -ErrorAction Stop"
        source = NATIVE.replace_once(source, boundary,
            "    " + marker(role.lower() + "-module-begin") + "\n" + boundary + "\n    " + marker(role.lower() + "-module-complete"))
        result[path] = source.encode("utf-8")
    path = "client/RouterVPN-Windows-ControllerTransport.psm1"
    source = (ROOT / path).read_bytes().decode("utf-8")
    source = NATIVE.replace_once(source, "Set-StrictMode -Version 2", marker("module-entered") + "\nSet-StrictMode -Version 2")
    boundaries = (
        ("    param([string]$ControllerPipe,[long]$ControllerParentHandle)", "initialize-entered", False),
        ("    Microsoft.PowerShell.Utility\\Add-Type -AssemblyName System.Net.Http", "framework-http", True),
        ("        Add-Type @Compile", "transport-compile", True),
        ("    $script:ControllerChannel=[RouterVPN.ControllerUI.ControllerChannel]::ConnectAsync($ControllerPipe,$ControllerParentHandle,10000,[Threading.CancellationToken]::None).GetAwaiter().GetResult()", "pipe-connect", True),
    )
    # The second Http assembly load belongs to request clients, after startup.
    # Restrict all edits to the exact initializer, retaining its complete code.
    start = source.index("function Initialize-RouterVPNControllerTransport {")
    end = source.index("\nfunction Get-RouterVPNControllerDataRoot {", start)
    initialize = source[start:end]
    for boundary, label, around in boundaries:
        indent = boundary[:len(boundary) - len(boundary.lstrip())]
        replacement = boundary + "\n" + indent + marker(label if not around else label + "-complete")
        if around:
            replacement = indent + marker(label + "-begin") + "\n" + replacement
        if label == "framework-http":
            before_lookup, after_lookup = lookup_observers()
            replacement = before_lookup + replacement + "\n" + after_lookup.rstrip("\n")
        initialize = NATIVE.replace_once(initialize, boundary, replacement)
    result[path] = (source[:start] + initialize + source[end:]).encode("utf-8")
    return result


def read_traces(root):
    traces = sorted(root.glob(".routervpn-gui-trace-*.log"))
    if not 1 <= len(traces) <= 3:
        raise ValueError("First-launch diagnostic did not retain its bounded child traces")
    for index, path in enumerate(traces):
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                getattr(info, "st_file_attributes", 0) & 0x400):
            raise ValueError("First-launch trace is not its exclusive regular file")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError("First-launch trace changed before bounded read")
            stream.seek(max(0, opened.st_size - 16384))
            text = stream.read(16384).decode("utf-8", errors="replace")
        print("First-launch owned blank-fixture child " + str(index) + " stdout/stderr (bounded):\n" + text, flush=True)


def execute(go="go", *, env=None):
    if platform.system() != "Windows" or not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("First-launch UI diagnostics require an actual elevated Windows test host")
    before = SESSION.sources()
    compiler, captured, architecture = NATIVE.selected_compiler(go, ROOT, dict(os.environ if env is None else env))
    race = ["-race"] if architecture == "amd64" else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    scripts = instrumented_scripts()
    with tempfile.TemporaryDirectory(prefix="routervpn-first-ui-launch-") as directory:
        workspace = Path(directory)
        shipping = workspace / "shipping-client.exe"
        status, output = NATIVE.run([compiler, "build", "-mod=readonly", "-o", shipping, "./cmd/client"],
                                   cwd=ROOT, env=captured, timeout=240)
        if status:
            raise ValueError("First-launch diagnostic shipping controller did not compile:\n" + output[-16384:])
        overlay_source = workspace / "gui_windows.go"
        overlay_source.write_bytes(SESSION.gui_diagnostic_overlay().encode("utf-8"))
        overlay = workspace / "gui-overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(ROOT / "internal/windowscontroller/gui_windows.go"): str(overlay_source)}}), encoding="utf-8")
        fixture = workspace / "first-session.test.exe"
        status, output = NATIVE.run([compiler, "test", "-c", "-mod=readonly", "-tags=" + SESSION.TAG,
                                    *race, "-overlay=" + str(overlay), "-o", fixture, "./internal/windowsapp"],
                                   cwd=ROOT, env=captured, timeout=240)
        if status:
            raise ValueError("First-launch diagnostic Session did not compile:\n" + output[-16384:])
        digests = {"shipping": hashlib.sha256(shipping.read_bytes()).hexdigest(),
                   "fixture": hashlib.sha256(fixture.read_bytes()).hexdigest()}
        root, launcher = SESSION.layout(workspace, fixture, shipping, "installed-selftest", captured)
        for relative, content in scripts.items():
            (root / relative).write_bytes(content)
        print(json.dumps({"diagnostic_only": True, "first_attempt": True, "launch_time_ns": time.time_ns(),
                          "host": "windows/" + architecture, "executables": digests,
                          "gui_overlay_sha256": hashlib.sha256(overlay_source.read_bytes()).hexdigest(),
                          "instrumented_scripts": {name: hashlib.sha256(raw).hexdigest() for name, raw in scripts.items()}}, sort_keys=True), flush=True)
        status, output = NATIVE.run([launcher, "-test.run=^" + SESSION.TEST + "$", "-test.count=1", "-test.timeout=180s",
                                    "-test.v", root, "installed-selftest"], cwd=root, env=captured, timeout=195)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        read_traces(root)
        if (SESSION.sources() != before or hashlib.sha256(shipping.read_bytes()).hexdigest() != digests["shipping"] or
                hashlib.sha256(fixture.read_bytes()).hexdigest() != digests["fixture"] or
                hashlib.sha256(launcher.read_bytes()).hexdigest() != digests["fixture"]):
            raise ValueError("First-launch diagnostic source or retained executable changed")
        print("Instrumented first-launch result only; the independent exact-source Session gate remains required.", flush=True)
        if status or "--- PASS: " + SESSION.TEST + " (" not in output or any(value in output for value in ("--- SKIP:", "DATA RACE")):
            raise ValueError("First instrumented UI launch failed; see its original attempt stage timings")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    execute(parser.parse_args().go)
