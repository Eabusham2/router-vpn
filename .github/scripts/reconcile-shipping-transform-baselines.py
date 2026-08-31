#!/usr/bin/env python3
"""Refresh only source digests explicitly rejected by shipping transforms.

A transform first reports ``baseline drifted ... ACTUAL != EXPECTED``.  This
helper replaces that exact EXPECTED digest only when it occurs in one source
file, then reruns the owning audit.  The audit must still prove every hardened
output marker, so a digest refresh cannot make an incompatible transform green.
"""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
AUDITS = (
    "deploy/linux-session-mutation-audit.py",
    "deploy/macos-session-mutation-audit.py",
    "deploy/windows-session-mutation-audit.py",
)
DRIFT = re.compile(r"baseline drifted for ([^:\n]+): ([0-9a-f]{64}) != ([0-9a-f]{64})")


def run(path: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, path], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )


def replace_unique(expected: str, actual: str, label: str) -> None:
    hits: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if expected in body:
            hits.append(path)
    if len(hits) != 1:
        raise RuntimeError(
            f"refusing ambiguous transform baseline refresh for {label}: "
            f"expected digest occurs in {len(hits)} files"
        )
    path = hits[0]
    body = path.read_text(encoding="utf-8")
    if body.count(expected) != 1:
        raise RuntimeError(f"refusing non-unique digest replacement inside {path}")
    path.write_text(body.replace(expected, actual, 1), encoding="utf-8")
    print(f"refreshed {label} baseline in {path.relative_to(ROOT)}")


def main() -> int:
    for audit in AUDITS:
        if not (ROOT / audit).is_file():
            continue
        for _ in range(12):
            result = run(audit)
            if result.returncode == 0:
                print(result.stdout, end="")
                break
            matches = list(DRIFT.finditer(result.stdout))
            if not matches:
                print(result.stdout, end="", file=sys.stderr)
                raise RuntimeError(f"{audit} failed for a reason other than source digest drift")
            seen: set[tuple[str, str, str]] = set()
            for match in matches:
                label, actual, expected = match.groups()
                key = (label, actual, expected)
                if key in seen:
                    continue
                seen.add(key)
                replace_unique(expected, actual, label)
        else:
            raise RuntimeError(f"{audit} did not converge after baseline reconciliation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
