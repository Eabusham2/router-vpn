#!/usr/bin/env python3
"""Run actual legacy recovery dispatch and reject its unsafe recovery defects."""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "client/windows-kill-switch.ps1"
TEST = ROOT / "client/test-windows-legacy-protection-recovery.ps1"


def once(source, before, after):
    if source.count(before) != 1:
        raise ValueError("Legacy recovery defect control lost its exact source boundary")
    return source.replace(before, after, 1)


def execute(shell):
    executable = shutil.which(shell)
    if not executable:
        raise ValueError("Legacy recovery verification requires the actual selected PowerShell")
    closure = [SOURCE, TEST, ROOT / "client/Private-RouterVPN-State.ps1",
               ROOT / "client/Private-RouterVPN-Protection.ps1"]
    captured = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in closure}
    command = [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
               "Bypass", "-File", str(TEST)]
    baseline = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=180)
    print(baseline.stdout, end="", flush=True)
    if baseline.returncode or "32 actual child dispatches and 242 assertions" not in baseline.stdout:
        raise ValueError("The complete shipping legacy recovery fixture did not pass")
    source = SOURCE.read_text(encoding="utf-8")
    guessed = once(
        source,
        "      throw ('Windows kill-switch recovery was not proved; preserve the rollback record and existing firewall policy. '+$_.Exception.Message)",
        "      foreach ($name in @('Domain','Private','Public')) { Set-NetFirewallProfile -Name $name -DefaultOutboundAction Allow }\n"
        "      Remove-State",
    )
    invalid = once(source, "  Assert-RollbackState $value\n", "")
    invalid = once(invalid, "  Assert-RollbackState $state\n", "")
    premature = once(source, "  $actual=@(Firewall-Profiles)\n",
                     "  Remove-State\n  $actual=@(Firewall-Profiles)\n")
    controls = (
        ("guessed-global-allow", "corrupt-json", "Unexpected recovery verdict for corrupt-json", guessed),
        ("incomplete-authority", "missing-profile", "Unexpected recovery verdict for missing-profile", invalid),
        ("premature-record-deletion", "profile-readback", "Recovery discarded its rollback record: profile-readback", premature),
    )
    with tempfile.TemporaryDirectory(prefix="routervpn-legacy-recovery-defects-") as directory:
        for name, case, witness, body in controls:
            path = Path(directory) / (name + ".ps1")
            path.write_text(body, encoding="utf-8")
            result = subprocess.run([*command, "-Source", str(path), "-OnlyCase", case],
                                    cwd=ROOT, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=45)
            if result.returncode == 0 or witness not in result.stdout:
                raise ValueError("Legacy recovery defect did not fail at its intended assertion: "
                                 + name + "\n" + result.stdout[-16384:])
            print("Rejected shipping legacy recovery defect:", name, flush=True)
    if {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in closure} != captured:
        raise ValueError("Legacy recovery source changed while its actual fixture was running")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shell", default="pwsh")
    args = parser.parse_args()
    execute(args.shell)
