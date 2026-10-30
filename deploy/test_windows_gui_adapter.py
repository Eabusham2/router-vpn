#!/usr/bin/env python3
"""Execute the shipping PowerShell adapter over the C# authenticated-stream seam.

Only this fixture can inject the assembly-private test stream. Production calls
compile the packaged C# source and authenticate the real inherited parent/pipe.
The separate native PowerShell gate verifies that public Windows composition.
"""
from pathlib import Path
import argparse
import hashlib
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "client/RouterVPN-Windows-ControllerTransport.psm1"
HARNESS = ROOT / "client/test-windows-controller-adapter.ps1"


def execute(shell, adapter, case, witness=None, root=ROOT):
    result = subprocess.run(
        [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(HARNESS), "-Root", str(root), "-Adapter", str(adapter), "-Case", case],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", timeout=60, check=False)
    if witness is not None:
        if result.returncode == 0 or witness not in result.stdout:
            raise ValueError("PowerShell adapter defect missed its semantic rejection:\n" + result.stdout)
    elif result.returncode or result.stdout.count("PASS controller PowerShell adapter " + case + " checks=") != 1:
        raise ValueError("PowerShell adapter did not execute its actual " + case + " case:\n" + result.stdout)
    return result.stdout.strip()


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError("PowerShell adapter defect lost its production boundary")
    return source.replace(before, after, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shell", default="pwsh")
    args = parser.parse_args()
    paths = [ADAPTER, HARNESS, ROOT / "client/RouterVPN-Windows-ControllerTransport.cs",
             ROOT / "client/RouterVPN-Windows-HomeSummary.ps1",
             ROOT / "client/RouterVPN-Windows-App.ps1", ROOT / "client/RouterVPN-Windows-Tray.ps1",
             ROOT / "deploy/fixtures/windows-controller-transport/transport_tests.cs",
             ROOT / "deploy/fixtures/windows-controller-transport/adapter_tests.cs"]
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError("PowerShell adapter requires exact regular source")
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    for case in ("startup", "requests", "handoff", "bounds"):
        print(execute(args.shell, ADAPTER, case), flush=True)
    source = ADAPTER.read_text(encoding="utf-8")
    variants = (
        ("failed-handoff-reset", "handoff", "CONTROL failed native handoff reset to legacy",
         replace_once(source, "    if($script:ControllerMode-cne'legacy'){\n        if($script:ControllerMode-cne'owned'-or$null-eq$script:ControllerChannel){throw 'The captured native controller channel is closed or unavailable.'}\n        if($Supplied",
                      "    if($false){\n        if($script:ControllerMode-cne'owned'-or$null-eq$script:ControllerChannel){throw 'The captured native controller channel is closed or unavailable.'}\n        if($Supplied")),
        ("raw-import-reencoding", "requests", "CONTROL raw import changed its exact captured bytes",
         replace_once(source, "if($Body-is[byte[]]){$Bytes=$Body}",
                      "if($Body-is[byte[]]){$Bytes=[Text.Encoding]::UTF8.GetBytes([Text.Encoding]::UTF8.GetString($Body))}")),
        ("ordinary-http-fallback", "requests", "CONTROL sync JSON did not use the captured channel",
         replace_once(source,
                      "$Response=$Client.SendAsync($Request,[Threading.CancellationToken]::None).GetAwaiter().GetResult()",
                      "return Invoke-RestMethod -Uri $Uri -Method $Method -TimeoutSec $TimeoutSec")),
        ("failed-http-status", "requests", "CONTROL failed HTTP status became successful JSON",
         replace_once(source, "if(-not$Response.IsSuccessStatusCode){", "if($false){")),
        ("retired-owner-reset", "requests", "CONTROL closed owner created another client",
         replace_once(source, "$script:ControllerMode='closed'", "$script:ControllerMode='legacy'")),
    )
    with tempfile.TemporaryDirectory(prefix="routervpn-ui-adapter-") as directory:
        staged = Path(directory) / "client"
        staged.mkdir()
        guards = (
            ("provider-lookup", "-not(Test-Path -LiteralPath Function:\\New-RouterVPNControllerClient)",
             "CONTROL startup lookup invoked a provider cmdlet"),
            ("command-discovery", "-not(Get-Command New-RouterVPNControllerClient -ErrorAction SilentlyContinue)",
             "CONTROL startup lookup searched commands"),
        )
        for role in ("App", "Tray"):
            for name, changed, witness in guards:
                for candidate in ("App", "Tray"):
                    filename = "RouterVPN-Windows-" + candidate + ".ps1"
                    raw = (ROOT / "client" / filename).read_text(encoding="utf-8")
                    if candidate == role:
                        raw = replace_once(raw, "$null-eq${function:New-RouterVPNControllerClient}", changed)
                    (staged / filename).write_text(raw, encoding="utf-8")
                execute(args.shell, ADAPTER, "startup", witness, root=Path(directory))
                print("Rejected executable PowerShell startup defect:", role, name, flush=True)
        for name, case, witness, changed in variants:
            target = Path(directory) / (name + ".psm1")
            target.write_text(changed, encoding="utf-8")
            execute(args.shell, target, case, witness)
            print("Rejected executable PowerShell adapter defect:", name, flush=True)
    if any(hashlib.sha256(path.read_bytes()).hexdigest() != digest for path, digest in before.items()):
        raise ValueError("PowerShell adapter source changed during execution")
    print("PowerShell adapter passed direct loaded-function startup, real requests, cancellation, raw imports, ownership and response bounds; four startup and five transport defects were rejected. Native Windows authentication remains a separate gate.", flush=True)


if __name__ == "__main__":
    main()
