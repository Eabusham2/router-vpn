#!/usr/bin/env python3
"""Protect the authoritative Router VPN release chain from workflow drift."""
from pathlib import Path
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

# These are source-level destructive/security boundaries that must travel with
# the exact release orchestration instead of living as orphan audit scripts.
for audit in (
    "deploy/docker-cleanup-safety-audit.py",
    "deploy/private-bundle-boundary-audit.py",
):
    subprocess.run([sys.executable, str(ROOT / audit)], cwd=ROOT, check=True)

print("authoritative one-SHA release orchestration + cleanup/private-bundle isolation audit: OK")
