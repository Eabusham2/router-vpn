#!/usr/bin/env python3
"""Fail closed on duplicated/truncated GitHub Actions workflow source."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing workflow: {rel}")
        return ""
    return path.read_text(encoding="utf-8")


def exactly(rel: str, marker: str, count: int = 1) -> None:
    body = read(rel)
    actual = body.count(marker)
    if actual != count:
        errors.append(f"{rel}: {marker!r} count={actual}, expected={count}")


client = ".github/workflows/client-apps-ci.yml"
aux = ".github/workflows/aux-proxies-ci.yml"

for marker in (
    "\n  desktop-unix:\n",
    "\n  windows-portable-smoke:\n",
    "\n  android:\n",
    "\n  ios-native:\n",
    "name: Client apps cross-platform CI",
    "Verify logical catalog ships on desktop/Unix packages",
):
    exactly(client, marker)

for marker in (
    "Validate formerly grey combined and MAX modes",
    "Build auxiliary proxy ARM64 image",
    "Smoke-test generated OverTLS and SSR services",
):
    exactly(aux, marker)

# These exact standalone shell-variable fragments were left behind when a text
# replacement accidentally expanded JavaScript's special replacement sequence
# `$'` and duplicated the suffix of the workflow. They are never valid YAML
# steps on their own.
for rel in (client, aux):
    body = read(rel)
    for number, line in enumerate(body.splitlines(), 1):
        stripped = line.strip()
        if stripped in {'"$list"', '"$portable_members"', '"$bundle_members"'}:
            errors.append(f"{rel}:{number}: dangling corruption fragment {stripped}")
        if "      - uses:" in line and not line.lstrip().startswith("- uses:"):
            errors.append(f"{rel}:{number}: action step was spliced into another line")
    if body.count("\njobs:\n") != 1:
        errors.append(f"{rel}: jobs root count must be exactly one")

if errors:
    print("Workflow source integrity audit: FAIL", file=sys.stderr)
    for error in errors:
        print(f" - {error}", file=sys.stderr)
    raise SystemExit(1)

print("Workflow source integrity audit: PASS")
