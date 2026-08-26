#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []

PYTHON_FILES = (
    "deploy/private-store-path-audit.py",
    "deploy/runtime-state-ownership-audit.py",
    "deploy/profile-persistence-error-audit.py",
    "deploy/durable-state-transaction-audit.py",
    "server/finalize/sync-endpoint.py",
    "server/finalize/test_sync_endpoint.py",
    "server/scripts/atomic-private-write.py",
    "server/scripts/atomic-private-batch.py",
    "server/scripts/test_atomic_private_publication.py",
    "server/scripts/verified-regular-read.py",
    "server/scripts/test_verified_regular_read.py",
    "server/scripts/benchmark-dns.py",
    "server/scripts/test_dns_benchmark_persistence.py",
    "server/scripts/create-bundle-json.py",
    "server/scripts/ensure-setup-auth.py",
    "server/scripts/test_setup_auth.py",
    "server/scripts/ensure-node-proof.py",
    "server/scripts/test_node_proof_private_state.py",
    "server/scripts/preserve-generated-state.py",
    "server/scripts/test_preserve_generated_state.py",
    "server/scripts/generate-aux-proxies.py",
    "server/scripts/enhance-max-pq.py",
    "server/scripts/wrap-xhttp-tun.py",
    "server/scripts/generate-stack-profiles.py",
    "modes/mtu-policy.py",
    "modes/mtu-policy-platform.py",
    "modes/test_mtu_policy.py",
    "modes/dns-policy.py",
    "modes/multihop.py",
    "modes/orchestrate.py",
)

SHELL_FILES = (
    "server/init/noninteractive.sh",
    "server/finalize/finalize.sh",
    "server/finalize/upgrade-safe.sh",
    "server/scripts/generate-transports.sh",
    "server/scripts/generate-xray-pq.sh",
    "server/scripts/generate-tls-alternates.sh",
    "server/scripts/generate-rosenpass.sh",
    "server/scripts/ensure-rosenpass.sh",
    "server/scripts/generate-advanced-profiles.sh",
    "server/scripts/publish-downloads.sh",
    "modes/run-mode.sh",
    "modes/run-all.sh",
)


def require_file(rel: str) -> Path | None:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing durability source for syntax gate: {rel}")
        return None
    return path


for rel in PYTHON_FILES:
    path = require_file(rel)
    if path is None:
        continue
    try:
        source = path.read_text(encoding="utf-8")
        compile(source, rel, "exec")
    except Exception as exc:
        errors.append(f"{rel}: Python parse failed: {exc}")

for rel in SHELL_FILES:
    path = require_file(rel)
    if path is None:
        continue
    proc = subprocess.run(["bash", "-n", str(path)], cwd=ROOT, text=True, capture_output=True)
    if proc.returncode != 0:
        detail = (proc.stdout + "\n" + proc.stderr).strip()
        errors.append(f"{rel}: bash -n failed: {detail[-3000:]}")

# Go files are compiled by the release candidate's authoritative `go test ./...`.
# Keep that stronger compiler/type gate instead of attempting a source-text Go
# parser here.

if errors:
    print("Durable-state syntax audit: FAIL", file=sys.stderr)
    for error in errors:
        print(f" - {error}", file=sys.stderr)
    raise SystemExit(1)

print(f"Durable-state syntax audit: PASS ({len(PYTHON_FILES)} Python + {len(SHELL_FILES)} shell files)")
