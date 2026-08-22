#!/usr/bin/env python3
"""Protect the authoritative Router VPN release chain from workflow drift."""
from pathlib import Path
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
def read(rel: str) -> str:
    path = ROOT / rel
    assert path.is_file(), f"missing release workflow: {rel}"
    return path.read_text(encoding="utf-8")

build = read(".github/workflows/build-all.yml")
rc = read(".github/workflows/release-candidate.yml")
preflight = read(".github/workflows/arm64-portainer-preflight.yml")
publish = read(".github/workflows/publish-arm64-images.yml")
compose = read(".github/workflows/production-release-compose.yml")

for rel, body, concurrency in (
    ("release-candidate.yml", rc, "group: release-candidate-${{ github.ref }}-${{ github.sha }}"),
    ("arm64-portainer-preflight.yml", preflight, "group: arm64-portainer-${{ github.ref }}-${{ github.sha }}"),
    ("publish-arm64-images.yml", publish, "group: publish-arm64-portainer-${{ github.ref }}-${{ github.sha }}"),
    ("production-release-compose.yml", compose, "group: production-release-compose-${{ github.ref }}-${{ github.sha }}"),
):
    assert "workflow_call:" in body, f"{rel} cannot participate in authoritative Build all chain"
    assert concurrency in body, f"{rel} can be canceled by a different release SHA"
    assert "cancel-in-progress: true" in body, f"{rel} does not collapse duplicate same-SHA runs"

for marker in (
    "packages: write",
    "uses: ./.github/workflows/release-candidate.yml",
    "uses: ./.github/workflows/arm64-portainer-preflight.yml",
    "needs: [release-candidate, portainer-preflight]",
    "uses: ./.github/workflows/publish-arm64-images.yml",
    "needs: [publish-arm64-images]",
    "uses: ./.github/workflows/production-release-compose.yml",
):
    assert marker in build, f"Build all lost release-order marker: {marker}"

for marker in (
    "platforms: linux/arm64",
    "push: true",
    "ghcr.io/eabusham2/${{ matrix.image }}:${{ github.sha }}",
    "org.opencontainers.image.revision=${{ github.sha }}",
):
    assert marker in publish, f"image publication lost exact-SHA marker: {marker}"

for marker in (
    'python3 deploy/materialize-production-compose.py --sha "$GITHUB_SHA" --output "$out"',
    'python3 server/scripts/verify-production-compose.py "$out"',
    'sha256sum -c "$(basename "$out").sha256"',
    "name: RouterVPN-production-compose-${{ github.sha }}",
):
    assert marker in compose, f"production compose workflow lost verification marker: {marker}"

assert "server/portainer-current.yaml" not in build, "Build all must not expose tracked baseline as deployable production compose"
assert "RouterVPN-Portainer-${GITHUB_SHA}.yaml" in compose, "production compose artifact is not exact-SHA named"

# These source-level destructive/security and historical runtime boundaries must
# travel with exact release orchestration instead of living as orphan scripts.
for audit in (
    "deploy/docker-cleanup-safety-audit.py",
    "deploy/private-bundle-boundary-audit.py",
    "deploy/historical-regression-audit.py",
):
    subprocess.run([sys.executable, str(ROOT / audit)], cwd=ROOT, check=True)

# The recovered scorer owns requirements that landed after the original weighted
# 88/12 model (macOS PF, desktop multihop parity, selected-DNS proof, current
# native information architecture). Build-all/RC must not be able to bypass
# those gates merely because weighted-release-audit.yml is a separate workflow.
recovered_proc = subprocess.run(
    [sys.executable, str(ROOT / "deploy" / "recovered-release-audit-v4.py")],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=True,
)
recovered = json.loads(recovered_proc.stdout)
assert recovered.get("source_weight") == 88.0, recovered
assert recovered.get("manual_live_weight") == 12.0, recovered
assert recovered.get("source_earned") == 88.0, (
    "recovered source requirements are incomplete: "
    + ", ".join(
        g["name"] for g in recovered.get("recovered_gates", []) if not g.get("pass")
    )
)
assert not [
    g for g in recovered.get("legacy_gates", [])
    if g.get("kind") == "source" and not g.get("pass")
], "legacy source gate failed inside recovered release audit"

print("authoritative one-SHA release orchestration + complete recovered source/security audit: OK")
