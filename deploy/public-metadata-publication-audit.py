#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing publication boundary source: {rel}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


reader = read("server/scripts/verified-regular-read.py")
test = read("server/scripts/test_verified_regular_read.py")
publish = read("server/scripts/publish-downloads.sh")

for marker in (
    "validate_parent_chain",
    "O_NOFOLLOW",
    "st_dev",
    "st_ino",
    "refusing non-regular/symlink public metadata source",
    "MAX_BYTES",
):
    if marker not in reader:
        errors.append(f"verified public reader missing {marker!r}")

for marker in (
    "accepted symlink leaf",
    "followed symlink ancestor",
    "accepted oversized input",
    "0o755",
    "0o644",
):
    if marker not in test:
        errors.append(f"verified public reader test missing {marker!r}")

for marker in (
    "VERIFIED_READ=/src/server/scripts/verified-regular-read.py",
    'stage_public "$BUNDLE/router/asus-merlin-router-vpn-forwards.sh"',
    'stage_public "$BUNDLE/modes.json"',
    'stage_public "$BUNDLE/logical-modes.json"',
    'stage_private "$BUNDLE/router-vpn-device-setup.html"',
    'stage_private "$BUNDLE/setup-assets.json"',
    'python3 "$PRIVATE_BATCH" "${publish[@]}"',
):
    if marker not in publish:
        errors.append(f"publish-downloads lost publication boundary marker {marker!r}")

# Private/import-bearing Setup Center material must never be fed to the broader
# regular-file reader merely because it is eventually served as metadata.
for forbidden in (
    'stage_public "$BUNDLE/router-vpn-device-setup.html"',
    'stage_public "$BUNDLE/setup-assets.json"',
    'stage_public "$BUNDLE/router-vpn-bundle.json"',
    'stage_public "$BUNDLE/CREDENTIALS.txt"',
):
    if forbidden in publish:
        errors.append(f"private Setup/node material crossed public-reader boundary: {forbidden}")

# Conversely the executable helper/catalog sources intentionally keep normal
# source-tree permissions and must not force a weakening of the strict private
# batch source-mode contract.
if 'private source must be mode 0600' not in read("server/scripts/atomic-private-batch.py"):
    errors.append("strict private batch 0600 source rule disappeared")

proc = subprocess.run(
    [sys.executable, str(ROOT / "server/scripts/test_verified_regular_read.py")],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
if proc.returncode != 0:
    errors.append("verified public metadata behavior test failed: " + (proc.stdout + proc.stderr)[-3000:])

if errors:
    print("Public/private metadata publication audit: FAIL", file=sys.stderr)
    for error in errors:
        print(" - " + error, file=sys.stderr)
    raise SystemExit(1)

print("Public/private metadata publication audit: PASS")
