#!/usr/bin/env python3
"""Protect the authoritative Router VPN release chain from workflow drift."""
from pathlib import Path

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

for rel, body in (
    ("release-candidate.yml", rc),
    ("arm64-portainer-preflight.yml", preflight),
    ("publish-arm64-images.yml", publish),
    ("production-release-compose.yml", compose),
):
    assert "workflow_call:" in body, f"{rel} cannot participate in authoritative Build all chain"

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

# Exact image publication must always include immutable commit tags. The moving
# arm64-main convenience tag may coexist, but production compose never uses it.
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

# The tracked file stays a baseline template. Only a generated file with the
# verifier header is deployable; never make Build all upload the tracked YAML.
assert "server/portainer-current.yaml" not in build, "Build all must not expose tracked baseline as deployable production compose"
assert "RouterVPN-Portainer-${GITHUB_SHA}.yaml" in compose, "production compose artifact is not exact-SHA named"

print("authoritative one-SHA release orchestration audit: OK")
