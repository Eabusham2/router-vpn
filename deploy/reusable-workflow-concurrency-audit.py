#!/usr/bin/env python3
"""Require reusable release children to isolate caller-owned evidence runs."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    ".github/workflows/source-snapshot.yml": "  group: source-snapshot-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}",
    ".github/workflows/release-candidate.yml": "  group: release-candidate-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}",
    ".github/workflows/darwin-node-child-tun.yml": "  group: darwin-node-child-tun-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}",
    ".github/workflows/server-node-chain-encrypted.yml": "  group: server-node-chain-encrypted-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}",
    ".github/workflows/arm64-portainer-preflight.yml": "  group: arm64-portainer-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}",
    ".github/workflows/publish-arm64-images.yml": "  group: publish-arm64-portainer-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}",
    ".github/workflows/production-release-compose.yml": "  group: production-release-compose-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}",
}

CALL_ONLY = {
    ".github/workflows/darwin-node-host-tun.yml": "  group: darwin-node-host-tun-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}",
}
STANDALONE = {
    ".github/workflows/darwin-node-host-native.yml": "  group: darwin-node-host-native-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}",
}

for filename, expected in {**EXPECTED, **CALL_ONLY, **STANDALONE}.items():
    path = ROOT / filename
    assert path.is_file(), f"missing reusable release workflow: {filename}"
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines.count(expected) == 1, (
        f"{filename} must isolate each caller-owned exact-SHA evidence run"
    )
    if filename in STANDALONE:
        assert "  workflow_call:" not in lines, f"{filename} must remain the standalone producer wrapper"
    else:
        assert "  workflow_call:" in lines, f"{filename} lost workflow_call"
    if filename in CALL_ONLY:
        assert not any(line in lines for line in ("  workflow_dispatch:", "  push:", "  pull_request:")), (
            f"{filename} must consume its successful caller's current-run artifacts")
    else:
        assert "  workflow_dispatch:" in lines, f"{filename} lost workflow_dispatch"
    assert lines.count("  cancel-in-progress: true") == 1, (
        f"{filename} lost duplicate-run cancellation within one caller"
    )

print("Reusable release workflow concurrency audit: PASS")
