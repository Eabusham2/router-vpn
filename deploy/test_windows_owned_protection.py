#!/usr/bin/env python3
"""Execute the shipping Windows protection adapter and its exact defect controls."""
from pathlib import Path
import argparse
import hashlib
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "client/Private-RouterVPN-Protection.ps1"
TEST = ROOT / "client/test-windows-owned-protection.ps1"


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("Owned Windows protection control lost its exact source seam")
    return text.replace(before, after, 1)


def execute(shell="pwsh", go="go"):
    shell = shutil.which(shell)
    go = shutil.which(go)
    if not shell or not go:
        raise ValueError("Owned Windows protection requires actual PowerShell and the selected Go compiler")
    closure = [HELPER, TEST, ROOT / "client/Private-RouterVPN-State.ps1"]
    captured = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in closure}
    source = HELPER.read_text(encoding="utf-8")
    command = [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-File", str(TEST), "-Go", go]
    baseline = subprocess.run(command, cwd=ROOT, env=dict(os.environ), text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    print(baseline.stdout, end="", flush=True)
    if baseline.returncode or "owned Windows protection assertions:" not in baseline.stdout:
        raise ValueError("Shipping Windows protection adapter did not execute its complete real fixture")
    mutants = (
        ("ordinary-release-removes-always", "Normal release changed Always",
         replace_once(source, "-Operation release\n", "-Operation force-off\n")),
        ("legacy-owner-takeover", "Native preparation adopted a live legacy rule",
         replace_once(source, "if ($legacy.active) {\n    throw 'An existing Router VPN",
                      "if ($false) {\n    throw 'An existing Router VPN")),
        ("captured-session-noop", "Captured session used the unprivileged no-op escape",
         replace_once(source, ",'HOMEVPN_NODE_SESSION'", "")),
    )
    with tempfile.TemporaryDirectory(prefix="routervpn-protection-defects-") as directory:
        for label, witness, body in mutants:
            path = Path(directory) / (label + ".ps1")
            path.write_text(body, encoding="utf-8")
            candidate = subprocess.run([*command, "-Source", str(path)], cwd=ROOT, env=dict(os.environ),
                                       text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            if candidate.returncode == 0 or witness not in candidate.stdout:
                raise ValueError("Protection defect control missed its named failure: " + label + "\n" + candidate.stdout[-16384:])
            print("Rejected shipping Windows protection defect:", label, flush=True)
    if {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in closure} != captured:
        raise ValueError("Shipping Windows protection source changed during execution")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shell", default="pwsh")
    parser.add_argument("--go", default="go")
    arguments = parser.parse_args()
    execute(arguments.shell, arguments.go)
