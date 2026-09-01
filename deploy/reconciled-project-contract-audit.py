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
import json
import subprocess
import sys
import tempfile

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
contract_text = read("client/unified-control-center-v2.json")
try:
    contract = json.loads(contract_text)
except json.JSONDecodeError as exc:
    errors.append(f"client/unified-control-center-v2.json: invalid JSON: {exc}")
    contract = {}

if contract.get("default_surface") != "map":
    errors.append("client/unified-control-center-v2.json: default surface must be map")
defaults = contract.get("defaults", {})
if defaults.get("mode") != "smart-auto":
    errors.append("client/unified-control-center-v2.json: SMART AUTO must remain the default")
if defaults.get("selected_node_count") != 1:
    errors.append("client/unified-control-center-v2.json: exactly one node must be selected by default")
if defaults.get("authenticated_transport") is not True:
    errors.append("client/unified-control-center-v2.json: authenticated transport must be enabled")
node_types = {item.get("id") for item in contract.get("node_types", []) if isinstance(item, dict)}
outer_bridges = set(contract.get("secure_transport", {}).get("outer_bridges", []))
if "tor-bridge" not in node_types or "tor-ntor-v3" not in outer_bridges:
    errors.append("client/unified-control-center-v2.json: Tor bridge contract is incomplete")
secure = contract.get("secure_transport", {})
if secure.get("mandatory") is not True or secure.get("custom_crypto_allowed") is not False:
    errors.append("client/unified-control-center-v2.json: vetted authenticated encryption must be mandatory")
forbid(
    "client/unified-control-center-v2.json",
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
    "_exact_release.install",
    "build_github_package",
    '"router-local-generic-build"',
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
# Native packages must publish source provenance; resolve_sha() intentionally
# accepts the exact workflow GITHUB_SHA so every packaging path need not carry a
# redundant local SOURCE_SHA shell variable.
for rel in ("deploy/package-macos-native.sh", "deploy/package-linux-native.sh"):
    need(rel, "server/scripts/source_provenance.py")

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
    "deploy/auto-update-audit.py",
):
    path = ROOT / child
    if not path.is_file():
        errors.append(f"missing delegated audit {child}")
        continue
    try:
        with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as output:
            result = subprocess.run(
                [sys.executable, str(path)], cwd=ROOT, text=True,
                stdout=output, stderr=subprocess.STDOUT, timeout=600,
            )
            output.seek(0)
            child_output = output.read().strip()
    except subprocess.TimeoutExpired:
        errors.append(f"{child}: timed out after 600 seconds")
        continue
    if result.returncode != 0:
        errors.append(f"{child}: {child_output}")

if errors:
    print("RECONCILED PROJECT CONTRACT AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)

print("RECONCILED PROJECT CONTRACT AUDIT: PASS")
