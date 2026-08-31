#!/usr/bin/env python3
"""Authoritative audit for the newest surviving Router VPN contract.

Detailed platform behavior is delegated to the existing shipping/session/
durability audits. This gate prevents later work from reviving requirements the
user superseded: branch/PR patch flows, tab-first daily UI, immediate successful
download deletion, fake cross-platform parity, moving-main artifacts, or custom
XOR-style packet ciphers.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing {rel}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def need(rel: str, *markers: str) -> None:
    body = read(rel)
    for marker in markers:
        if marker not in body:
            errors.append(f"{rel}: missing {marker!r}")


def forbid(rel: str, *markers: str) -> None:
    body = read(rel).lower()
    for marker in markers:
        if marker.lower() in body:
            errors.append(f"{rel}: forbidden {marker!r}")


need(
    "docs/REQUIREMENTS-RECONCILED.md",
    "Development changes land directly on `main`",
    "map-first",
    "30 minutes from READY",
    "Do not invent XOR",
    "Unsupported platform functionality remains disabled/unavailable",
    "immutable exact-SHA GitHub Release asset",
    "ASUS household safety",
)
need(
    "client/unified-control-center-v2.json",
    '"default_surface"',
    '"map"',
    '"smart-auto"',
    '"selected_node_count"',
    '"authenticated_encryption"',
    '"tor"',
)
forbid(
    "client/unified-control-center-v2.json",
    '"xor"',
    '"homemade_cipher"',
    '"custom_cipher"',
)
need(
    "server/scripts/download_jobs.py",
    "JOB_TTL_SECONDS = 30 * 60",
    'RETAINED = {"ready", "delivered", "delivery-interrupted"}',
    "retention_deadline_epoch=time.time() + PACKAGE_RETENTION_SECONDS",
    "temporary package retained for repeat download until its 30-minute deadline",
    "cleanup-pending",
)
need(
    "deploy/setup-center-download-retention-audit.py",
    "GitHub-first and 30-minute Setup Center download contract",
    "immutable exact-SHA GitHub Release",
    "matching exact-SHA GitHub Actions",
    "bounded requested local desktop/Portable build",
)
need(
    "server/scripts/setup_center_ux_patch.py",
    "pointer-events:none!important",
    "Temporary package deletes in",
    "Download again",
    "Delete now",
    "expires_in_seconds",
)
need(
    "deploy/materialize-production-compose.py",
    "GENERATED exact-SHA Router VPN production compose",
    "server/portainer-current.yaml",
    "--sha",
    "CUSTOM_IMAGES",
    "ROUTER_VPN_GITHUB_SHA",
)
for rel in ("deploy/package-macos-native.sh", "deploy/package-linux-native.sh"):
    need(rel, "server/scripts/source_provenance.py", '--sha "$SOURCE_SHA"')

transient = [
    *sorted((ROOT / ".github/workflows").glob("direct-main-*.yml")),
    *sorted((ROOT / ".github/workflows").glob("one-shot-*.yml")),
]
if transient:
    errors.append(
        "transient source-mutating workflows remain: "
        + ", ".join(str(path.relative_to(ROOT)) for path in transient)
    )

for child in (
    "deploy/unified-map-shipping-audit.py",
    "deploy/native-session-mutation-audit.py",
    "deploy/setup-center-download-retention-audit.py",
    "deploy/durable-state-transaction-audit.py",
):
    path = ROOT / child
    if not path.is_file():
        errors.append(f"missing delegated audit {child}")
        continue
    result = subprocess.run(
        [sys.executable, str(path)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        errors.append(f"{child}: {result.stdout.strip()}")

if errors:
    print("RECONCILED PROJECT CONTRACT AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)

print("RECONCILED PROJECT CONTRACT AUDIT: PASS")
