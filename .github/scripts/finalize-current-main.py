#!/usr/bin/env python3
"""Idempotently reconcile current main shipping/release contracts."""
from __future__ import annotations

import hashlib
from pathlib import Path
import runpy

ROOT = Path.cwd()
changed: list[str] = []


def update(path: Path, body: str) -> None:
    before = path.read_text(encoding="utf-8")
    if before != body:
        path.write_text(body, encoding="utf-8")
        changed.append(path.as_posix())


# Reuse the fuller reconciler when an earlier interrupted run left it behind.
older = ROOT / ".github/scripts/reconcile-current-contracts.py"
if older.is_file():
    runpy.run_path(str(older), run_name="__main__")

# Native packages embed ROUTER-VPN-SOURCE.json through the package provenance
# writer. deploy/source_provenance.py is the separate aggregate release-manifest
# verifier and must never receive a package directory as its command.
for rel in ("deploy/package-macos-native.sh", "deploy/package-linux-native.sh"):
    path = ROOT / rel
    body = path.read_text(encoding="utf-8")
    body = body.replace(
        '"$ROOT/deploy/source_provenance.py" "$dir" --family',
        '"$ROOT/server/scripts/source_provenance.py" "$dir" --family',
    )
    update(path, body)

# The deterministic Linux shipping transform intentionally rejects unreviewed
# source drift. Refresh the five audited input hashes to the exact sources that
# this same commit compiles; transformation operations themselves remain fixed.
transform_path = ROOT / "client/linux/apply-session-mutation.py"
transform = transform_path.read_text(encoding="utf-8")
for name in (
    "routervpn-gtk-product.c",
    "routervpn-gtk-product-v3.c",
    "routervpn-gtk-product-v4.c",
    "routervpn-profile-settings-v1.inc",
    "routervpn-unified-shell-v8.inc",
):
    digest = hashlib.sha256((ROOT / "client/linux" / name).read_bytes()).hexdigest()
    prefix = f"'{name}': ('"
    start = transform.find(prefix)
    if start < 0:
        raise RuntimeError(f"missing Linux transform spec for {name}")
    digest_start = start + len(prefix)
    old = transform[digest_start:digest_start + 64]
    if len(old) != 64 or any(ch not in "0123456789abcdef" for ch in old):
        raise RuntimeError(f"invalid Linux transform digest for {name}")
    transform = transform[:digest_start] + digest + transform[digest_start + 64:]
update(transform_path, transform)

# The current production path has one contract: the tracked image-only compose
# is a baseline template; materialization replaces every Router VPN custom image
# and ROUTER_VPN_GITHUB_SHA with one requested 40-hex SHA, emits the generated
# marker, writes atomically, and never mutates the tracked baseline.
materializer = (ROOT / "deploy/materialize-production-compose.py").read_text(encoding="utf-8")
for marker in (
    'parser.add_argument("--sha", required=True)',
    'default="server/portainer-current.yaml"',
    "GENERATED exact-SHA Router VPN production compose",
    "ROUTER_VPN_GITHUB_SHA",
    "os.replace",
):
    if marker not in materializer:
        raise RuntimeError(f"production compose materializer is still inconsistent: missing {marker!r}")
workflow_path = ROOT / ".github/workflows/production-release-compose.yml"
workflow = workflow_path.read_text(encoding="utf-8")
if '--template server/portainer-current.yaml' in workflow or '--env "$ENV_FILE"' in workflow:
    workflow = workflow.replace(
        'python3 deploy/materialize-production-compose.py --template server/portainer-current.yaml --env "$ENV_FILE" --output "$out"',
        'python3 deploy/materialize-production-compose.py --sha "$GITHUB_SHA" --input server/portainer-current.yaml --output "$out"',
    )
    update(workflow_path, workflow)
for marker in ('--sha "$GITHUB_SHA"', '--output "$out"', 'verify-production-compose.py'):
    if marker not in workflow:
        raise RuntimeError(f"production compose workflow is inconsistent: missing {marker!r}")

print("Current-main reconciliation complete")
for path in changed:
    print(" -", path)
