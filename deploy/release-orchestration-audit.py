#!/usr/bin/env python3
"""Protect the authoritative Router VPN release chain from workflow drift."""
from pathlib import Path
import json
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
def read(rel: str) -> str:
    path = ROOT / rel
    assert path.is_file(), f"missing release workflow: {rel}"
    return path.read_text(encoding="utf-8")

build = read(".github/workflows/build-all.yml")
snapshot = read(".github/workflows/source-snapshot.yml")
rc = read(".github/workflows/release-candidate.yml")
preflight = read(".github/workflows/arm64-portainer-preflight.yml")
publish = read(".github/workflows/publish-arm64-images.yml")
compose = read(".github/workflows/production-release-compose.yml")

assert "\n  push:\n    branches: [main]\n" in build, "Build all must be the automatic main-branch release orchestrator"
assert "group: build-all-${{ github.ref }}" in build, "Build all must cancel superseded main-branch release chains"
assert "cancel-in-progress: true" in build, "Build all must cancel superseded release chains"
updater = read("cmd/update-controller/main.go")
workflow_block_match = re.search(
    r"requiredReleaseWorkflows\s*=\s*\[\]string\{(?P<body>.*?)\n\s*\}",
    updater,
    re.S,
)
assert workflow_block_match, "update controller requiredReleaseWorkflows declaration is missing"
workflow_block = workflow_block_match.group("body")
assert workflow_block.count('"build-all.yml"') == 1, (
    "update controller must require exactly one successful exact-SHA Build-all caller proof"
)
for called in (
    "source-snapshot.yml",
    "release-candidate.yml",
    "arm64-portainer-preflight.yml",
    "publish-arm64-images.yml",
    "production-release-compose.yml",
):
    assert f'"{called}"' not in workflow_block, (
        f"called reusable workflow {called} was incorrectly restored as a standalone run requirement"
    )
assert "actions/workflows/build-all.yml/runs" in updater, (
    "update controller latest-verified discovery must query the Build-all caller workflow"
)
assert '"status": {"success"}' not in updater, (
    "update controller must not hide newer failed/pending Build-all reruns with a success-only query"
)
assert "latestSuccessfulWorkflowSHAs" in updater, (
    "update controller lost newest-meaningful per-SHA release candidate selection"
)
assert "actions/workflows/release-candidate.yml/runs" not in updater, (
    "update controller still queries reusable release-candidate as if it had an automatic standalone run"
)
for marker in (
    "func validGitHubRepo",
    "func validGitHubBranch",
    'validateGitHubEndpoint(endpoint, "api.github.com")',
    'validateGitHubEndpoint(endpoint, "raw.githubusercontent.com")',
    'githubAPIHeaders(req)',
    'githubBaseHeaders(req)',
    'req.Header.Del("Authorization")',
    'githubClient("raw.githubusercontent.com")',
    'Portainer redirects are forbidden',
):
    assert marker in updater, f"update controller lost network credential boundary: {marker}"
assert "githubHeaders(req)" not in updater, (
    "update controller revived one shared authenticated header path for API and raw GitHub origins"
)
for rel, body in (
    ("source-snapshot.yml", read(".github/workflows/source-snapshot.yml")),
    ("release-candidate.yml", rc),
    ("arm64-portainer-preflight.yml", preflight),
    ("publish-arm64-images.yml", publish),
    ("production-release-compose.yml", compose),
):
    assert "\n  push:\n" not in body, f"{rel} must not bypass Build-all ordering with an autonomous push trigger"

for rel, body, concurrency in (
    ("source-snapshot.yml", snapshot, "group: source-snapshot-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}"),
    ("release-candidate.yml", rc, "group: release-candidate-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}"),
    ("arm64-portainer-preflight.yml", preflight, "group: arm64-portainer-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}"),
    ("publish-arm64-images.yml", publish, "group: publish-arm64-portainer-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}"),
    ("production-release-compose.yml", compose, "group: production-release-compose-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}"),
):
    assert "workflow_call:" in body, f"{rel} cannot participate in authoritative Build all chain"
    assert concurrency in body, f"{rel} can cancel caller-owned exact-SHA evidence"
    assert "cancel-in-progress: true" in body, f"{rel} does not collapse duplicate same-SHA runs"

for marker in (
    'artifact_family\": \"exact-source-snapshot\"',
    '\"tree_sha\": tree',
    'sha256sum -c "$(basename "$archive").sha256"',
    'router-vpn-source-${{ github.sha }}.json',
):
    assert marker in snapshot, f"source snapshot lost exact identity marker: {marker}"

for marker in (
    "packages: write",
    "statuses: write",
    "uses: ./.github/workflows/source-snapshot.yml",
    "uses: ./.github/workflows/release-candidate.yml",
    "uses: ./.github/workflows/arm64-portainer-preflight.yml",
    "needs: [source-snapshot, release-candidate, portainer-preflight]",
    "uses: ./.github/workflows/publish-arm64-images.yml",
    "needs: [publish-arm64-images]",
    "uses: ./.github/workflows/production-release-compose.yml",
):
    assert marker in build, f"Build all lost release-order marker: {marker}"

assert "\n  push:\n" not in publish, "ARM64 publisher must not bypass Build-all ordering with an autonomous push trigger"
assert "validate-source:" in publish and "needs: validate-source" in publish, "ARM64 publication lost its whole-source validation prerequisite"
assert "go test ./cmd/update-controller -count=1" in publish, "ARM64 publication no longer compiles the updater before pushing images"
assert "python3 deploy/durable-state-syntax-audit.py" in publish, "ARM64 publication lost durability syntax preflight"
assert "python3 deploy/server-image-dependency-audit.py" in publish, "ARM64 publication lost server dependency pin preflight"

for marker in (
    "platforms: linux/arm64",
    "push: true",
    "Record exact source tree identity",
    "ghcr.io/eabusham2/${{ matrix.image }}:${{ github.sha }}",
    "org.opencontainers.image.revision=${{ github.sha }}",
    "org.opencontainers.image.source-tree=${{ env.SOURCE_TREE_SHA }}",
    "image: router-vpn-updater",
    "dockerfile: deploy/update-controller.Dockerfile",
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

# Exact-SHA release candidate must directly block on core behavioral/shipping contracts.
for marker in (
    "python3 deploy/historical-regression-audit.py",
    "python3 deploy/backend-session-transaction-audit.py",
    "python3 deploy/native-auto-requirements-ui-audit.py",
    "python3 deploy/native-artifact-workflow-parity-audit.py",
    "python3 deploy/workflow-structure-audit.py",
    "python3 deploy/reusable-workflow-concurrency-audit.py",
    "python3 deploy/workflow-evidence-pipeline-audit.py",
    "python3 deploy/server-image-dependency-audit.py",
    "python3 deploy/setup-center-publication-audit.py",
    "python3 deploy/production-install-state-audit.py",
    "python3 deploy/profile-readiness-marker-audit.py",
    "python3 deploy/test_source_provenance.py",
    "python3 deploy/release-orchestration-audit.py",
    "python3 modes/test_kill_switch.py",
    "python3 server/scripts/test_preserve_generated_state.py",
    "python3 deploy/test-release-candidate-provenance.py",
    'python3 deploy/verify-release-candidate-provenance.py dist/release-candidate --sha "$GITHUB_SHA"',
    "python3 modes/test_mtu_policy.py",
    "python3 modes/test_multihop.py",
    "python3 server/scripts/test_download_safety.py",
    "python3 server/scripts/test_setup_center_release.py",
    "python3 server/scripts/test_setup_center_update.py",
    "python3 server/scripts/test_setup_center_requirement_349.py",
    "python3 modes/test_smart_auto_rollback.py",
    "python3 deploy/daita-safety-audit.py",
    "python3 deploy/recovered-corrections-audit.py",
    "python3 deploy/recovered-requirements-1-264-audit.py",
    "python3 deploy/recovered-requirements-265-311-audit.py",
    "python3 deploy/recovered-addendum-312-356-audit.py",
    "python3 deploy/latest-a20-product-contract-audit.py",
    "python3 deploy/binding-edge-requirements-audit.py",
    "client\\test-windows-kill-switch.ps1",
    "client\\test-private-router-vpn-state.ps1",
    "python3 server/scripts/test_setup_center_ux_patch.py",
    "python3 server/scripts/test_setup_center_router_onboarding.py",
    "python3 android/test_android_connection_profiles_contract.py",
    "python3 android/test_android_via_entry_latency_contract.py",
):
    assert marker in rc, f"release candidate lost authoritative gate: {marker}"

# These source-level destructive/security, durable-state, credential-preservation,
# runtime-ownership, persistence-error, publication, and historical boundaries
# must travel with exact release orchestration instead of living as orphan scripts.
for audit in (
    "deploy/docker-cleanup-safety-audit.py",
    "deploy/private-bundle-boundary-audit.py",
    "deploy/historical-regression-audit.py",
    "deploy/binding-edge-requirements-audit.py",
    "deploy/private-store-path-audit.py",
    "deploy/runtime-state-ownership-audit.py",
    "deploy/native-auto-requirements-ui-audit.py",
    "deploy/native-artifact-workflow-parity-audit.py",
    "deploy/workflow-structure-audit.py",
    "deploy/reusable-workflow-concurrency-audit.py",
    "deploy/workflow-evidence-pipeline-audit.py",
    "deploy/server-image-dependency-audit.py",
    "deploy/test_source_provenance.py",
    "deploy/profile-persistence-error-audit.py",
    "deploy/standard-exit-private-runtime-audit.py",
    "deploy/portable-private-state-audit.py",
    "deploy/bundle-staging-durability-audit.py",
    "deploy/setup-center-publication-audit.py",
    "deploy/public-metadata-publication-audit.py",
    "deploy/durable-state-syntax-audit.py",
    "deploy/durable-state-transaction-audit.py",
    "deploy/workflow-source-integrity-audit.py",
    "deploy/macos-mutation-build-audit.py",
    "deploy/production-install-state-audit.py",
    "deploy/profile-readiness-marker-audit.py",
    "server/scripts/test_preserve_generated_state.py",
):
    subprocess.run([sys.executable, str(ROOT / audit)], cwd=ROOT, check=True)

# The recovered scorer owns requirements that landed after the original weighted
# 88/12 model (macOS PF, desktop multihop parity, selected-DNS proof, current
# native information architecture). Build-all/RC must not be able to bypass
# those gates merely because weighted-release-audit.yml is a separate workflow.
recovered_proc = subprocess.run(
    [sys.executable, str(ROOT / "deploy" / "recovered-release-audit-v3.py")],
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

print("authoritative one-SHA release orchestration + exact-source package provenance + public/private metadata publication + atomic Setup Center publication + bundle staging durability + Portable private bootstrap/state + standard-exit private runtimes + runtime/profile ownership + profile persistence error classification + private-store boundaries + durable-state syntax/transactions + upgrade preservation + complete recovered source/security audit: OK")
