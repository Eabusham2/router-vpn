#!/usr/bin/env python3
"""Run the final composed Windows Performance callbacks and causal controls."""
import argparse
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "close-cancel": "Window close did not cancel while retaining original request",
    "closed-result": "Closed dialog adopted a late callback",
    "foreign-cancel": "Old window close cancelled a replacement request",
    "draft-hops": "Hop test borrowed draft node IDs",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shell", default="pwsh")
    args = parser.parse_args()
    shell = shutil.which(args.shell)
    if not shell:
        raise SystemExit(f"Required PowerShell is unavailable: {args.shell}")
    command = [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
               str(ROOT / "client/test-windows-performance.ps1"), "-Root", str(ROOT)]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=90)
    if result.returncode or "Composed Windows Advanced Performance: PASS" not in result.stdout:
        raise SystemExit(result.stdout or "Composed Performance fixture did not pass")
    print(result.stdout.strip())
    for mutant, diagnostic in EXPECTED.items():
        result = subprocess.run(command + ["-Mutant", mutant], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
        if result.returncode == 0 or ("WINDOWS_PERFORMANCE_ASSERT: " + diagnostic) not in result.stdout:
            raise SystemExit(f"Causal control {mutant} did not reject its defect:\n{result.stdout}")
        print(f"PASS causal control: {mutant}")
    print("Exact shipping composition and four ownership/selection causal controls passed.")


if __name__ == "__main__":
    main()
