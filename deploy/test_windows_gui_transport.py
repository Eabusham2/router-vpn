#!/usr/bin/env python3
"""Run the real C# UI pipe transport under the selected PowerShell/.NET runtime.

The private-stream cases prove framing/lifecycle, and the local named-pipe case
uses actual OS IPC. Windows parent/child authentication and native OVERLAPPED
ownership additionally require the real launcher composition gate; this suite
does not substitute a fake identity for that separate native evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "client/RouterVPN-Windows-ControllerTransport.cs"
HARNESS = ROOT / "client/test-windows-controller-transport.ps1"
FIXTURE = ROOT / "deploy/fixtures/windows-controller-transport/transport_tests.cs"
CASES = (
    "golden", "concurrent", "cancel-frame", "widget-dispose", "close-join",
    "targets", "large-import", "budgets", "responses", "terminals",
    "sync-context", "peer-revocation", "real-pipe",
    "publication-revocation", "captured-deadline",
    "admission-close", "native-dispatch-failure",
)


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise RuntimeError("C# rejection boundary missing or duplicated: " + old)
    return source.replace(old, new, 1)


def execute(command: list[str], expected: str | None = None) -> str:
    result = subprocess.run(command, text=True, encoding="utf-8", errors="replace",
                            capture_output=True, timeout=90)
    output = result.stdout + result.stderr
    if expected is not None:
        if result.returncode == 0 or expected not in output:
            raise RuntimeError("C# defect did not fail its own assertion: " + expected + "\n" + output)
    elif result.returncode:
        raise RuntimeError(output)
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shell", default="pwsh")
    parser.add_argument("--shipping-only", action="store_true")
    args = parser.parse_args()
    command = [args.shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-File", str(HARNESS), "-Root", str(ROOT)]
    output = execute(command)
    required = CASES + (("native-overlapped",) if os.name == "nt" else ())
    for case in required:
        if output.count("PASS controller GUI transport " + case + "\n") != 1:
            raise RuntimeError("Actual C# case missing or repeated: " + case + "\n" + output)
    if f"PASS controller GUI transport total={len(required)}" not in output:
        raise RuntimeError("C# transport suite did not complete all mandatory cases\n" + output)
    print(output.strip(), flush=True)
    with tempfile.TemporaryDirectory(prefix="routervpn-ui-assembly-") as temp:
        library = Path(temp) / "RouterVPN.ControllerTransport.dll"
        compiled = execute(command + ["-CompileAssembly", str(library)])
        loaded = execute(command + ["-LoadAssembly", str(library)])
        if "PASS controller GUI transport production DLL compilation" not in compiled or "PASS controller GUI transport compiled DLL load" not in loaded:
            raise RuntimeError("The exact production C# DLL did not compile and load independently")
        print(compiled.strip(), flush=True)
        print(loaded.strip(), flush=True)
    for path in (SOURCE, HARNESS, FIXTURE):
        print("Exact source SHA256 " + str(path.relative_to(ROOT)) + " " + hashlib.sha256(path.read_bytes()).hexdigest(), flush=True)
    if args.shipping_only:
        return
    source = SOURCE.read_text(encoding="utf-8")
    mutations = [
        ("skipped-id", "concurrent", "state.ID = ++lastID;", "state.ID = (lastID += 2);",
         "CONTROL serialized request IDs were reused or reordered"),
        ("large-import-cap", "large-import", "? MaxImport : MaxBody;", "? MaxBody : MaxBody;",
         "CONTROL 32MiB import was rejected before transmission"),
        ("encoded-path", "targets", "path.IndexOf('%') >= 0 || ", "",
         "CONTROL invalid target/body escaped before rejection"),
        ("pending-budget", "budgets", "requests.Count >= MaxPending || ", "",
         "CONTROL pending limit was exceeded"),
        ("aggregate-budget", "budgets", "reserved > MaxReserved - state.Reserved", "false",
         "CONTROL aggregate byte budget was exceeded"),
        ("shared-owner-dispose", "widget-dispose", "if (disposing && Interlocked.Exchange(ref retired, 1) == 0) disposed.Cancel();",
         "if (disposing && Interlocked.Exchange(ref retired, 1) == 0) { disposed.Cancel(); channel.Dispose(); }",
         "CONTROL widget disposal closed the common channel"),
        ("request-cancel-frame", "cancel-frame",
         "frame.CancelAfter(frameTimeout);\n                    // After ID commitment the frame uses ONLY channel lifetime,",
         "state.Cancellation.Token.Register(delegate { frame.Cancel(); });\n                    frame.CancelAfter(frameTimeout);\n                    // After ID commitment the frame uses ONLY channel lifetime,",
         "CONTROL request cancellation corrupted a committed frame"),
        ("revoked-publication", "publication-revocation", "return !closing && !state.Released", "return !state.Released",
         "CONTROL revoked channel published a held response"),
        ("extended-deadline", "captured-deadline", "state.Timeout - elapsed * (1000.0 / Stopwatch.Frequency)", "(double)state.Timeout",
         "CONTROL writer serialization extended the captured request deadline"),
        ("unowned-admission", "admission-close",
         "state.Registration = state.Cancellation.Token.Register(delegate { CancelRequest(state); });\n                    writes++;",
         "state.Registration = state.Cancellation.Token.Register(delegate { CancelRequest(state); });",
         "CONTROL close released an admitted request before writer dispatch joined"),
        ("stranded-native-dispatch", "native-dispatch-failure",
         "// Synchronous scheduling failure installed no delegate\n                    // finally and submitted no IRP. Retire its admitted count.\n                    FinishOperation();",
         "// Deliberately omit the rejected scheduler ownership retirement.",
         "CONTROL native scheduler rejection retained an unowned operation"),
    ]
    with tempfile.TemporaryDirectory(prefix="routervpn-ui-transport-") as temp:
        for name, case, old, new, rejected in mutations:
            variant = replace_once(source, old, new)
            path = Path(temp) / (name + ".cs")
            path.write_text(variant, encoding="utf-8")
            execute(command + ["-Source", str(path), "-Case", case], expected=rejected)
            print("Rejected executable C# defect: " + name, flush=True)
    print(f"C# GUI pipe transport: {len(required)} actual cases and {len(mutations)} rejected production defects", flush=True)


if __name__ == "__main__":
    main()
