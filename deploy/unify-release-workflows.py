#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RC = ROOT / ".github/workflows/release-candidate.yml"
BUILD_ALL = ROOT / ".github/workflows/build-all.yml"


def patch_release_candidate() -> bool:
    text = RC.read_text(encoding="utf-8")
    if "\n  workflow_call:\n" in text:
        return False
    marker = "on:\n  workflow_dispatch:\n"
    if marker not in text:
        raise RuntimeError("release-candidate workflow trigger block changed unexpectedly")
    text = text.replace(marker, "on:\n  workflow_call:\n  workflow_dispatch:\n", 1)
    RC.write_text(text, encoding="utf-8")
    return True


def patch_build_all() -> bool:
    desired = '''name: Build all Router VPN release gates\n\non:\n  workflow_dispatch:\n  push:\n    branches: [main]\n    paths:\n      - '.github/workflows/build-all.yml'\n      - '.github/workflows/release-candidate.yml'\n\npermissions:\n  contents: read\n\nconcurrency:\n  group: build-all-${{ github.ref }}\n  cancel-in-progress: true\n\njobs:\n  release-candidate:\n    name: Authoritative one-SHA native release matrix\n    uses: ./.github/workflows/release-candidate.yml\n    secrets: inherit\n'''
    current = BUILD_ALL.read_text(encoding="utf-8") if BUILD_ALL.exists() else ""
    if current == desired:
        return False
    BUILD_ALL.write_text(desired, encoding="utf-8")
    return True


def main() -> int:
    changed = []
    if patch_release_candidate(): changed.append("release-candidate.yml")
    if patch_build_all(): changed.append("build-all.yml")
    print("release workflow unifier changed:", ", ".join(changed) if changed else "nothing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
