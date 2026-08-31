#!/usr/bin/env python3
"""Exact-head source/shipping gate for the recovered native UI update."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"

# Ordered from focused semantic/unit contracts into platform composition and
# shared state-ownership contracts. Every gate runs even after an earlier one
# fails so the final report contains the complete exact-head blocker set.
GATES = (
    "recovered-native-ui-contract-test.py",
    "recovered-native-ui-contract-audit.py",
    "recovered-map-first-ui-contract-audit-test.py",
    "recovered-map-first-ui-contract-audit.py",
    "native-map-first-ui-audit.py",
    "setup-center-responsive-ui-audit.py",
    "native-session-mutation-audit.py",
    "windows-session-mutation-audit.py",
    "macos-session-mutation-audit.py",
    "linux-session-mutation-audit.py",
    "android-session-mutation-audit.py",
    "ios-session-mutation-audit.py",
    "endpoint-sync-ownership-audit.py",
    "product-parity-audit.py",
    "profile-settings-audit.py",
    "backend-session-transaction-audit.py",
    "durable-state-transaction-audit.py",
)


def run_gate(name: str) -> tuple[int, str]:
    path = DEPLOY / name
    if not path.is_file():
        return 127, f"missing mandatory gate: deploy/{name}"
    try:
        completed = subprocess.run(
            [sys.executable, str(path)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=600,
        )
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + (exc.stderr or "")
        return 124, f"deploy/{name} timed out\n{output.rstrip()}"
    return completed.returncode, completed.stdout.rstrip()


def main() -> int:
    failed: list[str] = []
    for gate in GATES:
        print(f"=== deploy/{gate} ===")
        code, output = run_gate(gate)
        if output:
            print(output)
        if code:
            failed.append(f"deploy/{gate} ({code})")

    if failed:
        print("RECOVERED NATIVE UI EXACT-HEAD GATE: FAIL")
        for item in failed:
            print(f" - {item}")
        return 1

    print("RECOVERED NATIVE UI EXACT-HEAD GATE: PASS")
    print("Native compilation, built artifacts, rendered UX, selected-path proof, and physical release remain separate gates.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
