#!/usr/bin/env python3
"""Guard CI -> exact-SHA Release -> Setup Center -> local fallback delivery."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def text(path: str) -> str:
    target = ROOT / path
    if not target.is_file():
        errors.append(f"missing {path}")
        return ""
    return target.read_text(encoding="utf-8", errors="replace")


def need(path: str, *markers: str) -> None:
    body = text(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing {marker!r}")


def forbid(path: str, *markers: str) -> None:
    body = text(path)
    for marker in markers:
        if marker in body:
            errors.append(f"{path}: forbidden {marker!r}")


need(
    "server/scripts/native_artifact_policy.py",
    'EXACT_SHA_RELEASE_TAG_PREFIX = "router-vpn-sha-"',
    "EXACT_SHA_RELEASE_ASSETS",
    '"router-vpn-windows-amd64.zip": "RouterVPN-Windows-amd64.zip"',
    '"router-vpn-android.apk": "app-debug.apk"',
    '"router-vpn-ios.ipa": "RouterVPN-native-unsigned-resignable.ipa"',
)
need(
    "server/scripts/exact_sha_release_download.py",
    "exact-SHA GitHub Release asset",
    'headers["Accept"] = "application/octet-stream"',
    "target_commitish",
    "/git/ref/tags/",
    "github-release",
    "github-actions",
    "router-local-generic-build",
    "Mobile packages remain GitHub-only",
)
forbid("server/scripts/exact_sha_release_download.py", "/releases/latest", "latest.zip", "refs/heads/main")
need(
    "server/scripts/setup-center-product-server.py",
    "exact_sha_release_download.py",
    "_exact_release.install(_ai._core._broker)",
    "exact-SHA Release-first delivery",
    "one-package local fallback",
)
need(
    "deploy/materialize-exact-sha-release.py",
    "EXACT_SHA_RELEASE_ASSETS",
    "RouterVPN-RELEASE.json",
    "SHA256SUMS",
    "source_sha",
    "producer_workflow",
)
need(
    ".github/workflows/build-all.yml",
    "release-delivery-contracts:",
    "publish-exact-sha-release:",
    "RouterVPN-release-candidate-${{ github.sha }}",
    "materialize-exact-sha-release.py",
    'TAG="router-vpn-sha-${GITHUB_SHA}"',
    "gh release create",
    "gh release upload",
    "target_commitish",
    "RouterVPN-exact-sha-release-${{ github.sha }}",
)
forbid(".github/workflows/build-all.yml", "/releases/latest", "latest.zip")
build_all = text(".github/workflows/build-all.yml")
allowed_main_ref = "if: github.ref == 'refs/heads/main'"
for line in build_all.splitlines():
    if "refs/heads/main" in line and line.strip() != allowed_main_ref:
        errors.append(f".github/workflows/build-all.yml: moving-main reference outside the publish trigger: {line.strip()!r}")
need(
    "docs/EXACT-SHA-DOWNLOAD-DELIVERY.md",
    "GitHub Release",
    "GitHub Actions",
    "router-local",
    "temporary",
    "Android and iOS",
    "full exact source SHA",
)

# The immutable Release asset map must cover every stable native request. The
# older Actions policy remains the second source and must not silently diverge.
try:
    spec = importlib.util.spec_from_file_location(
        "router_vpn_native_artifact_policy_audited",
        ROOT / "server/scripts/native_artifact_policy.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load native artifact policy")
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    expected = set(policy.NATIVE_PACKAGE_ARTIFACTS) | set(policy.DIRECT_ARTIFACTS)
    actual = set(policy.EXACT_SHA_RELEASE_ASSETS)
    if expected != actual:
        errors.append(
            f"exact-SHA Release asset request map drifted: missing={sorted(expected-actual)} extra={sorted(actual-expected)}"
        )
    if len(set(policy.EXACT_SHA_RELEASE_ASSETS.values())) != 10:
        errors.append("exact-SHA Release should contain ten unique native package assets")
except Exception as exc:
    errors.append(f"cannot validate exact-SHA Release policy: {type(exc).__name__}: {exc}")

if errors:
    print("EXACT-SHA RELEASE PIPELINE AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)
print("EXACT-SHA RELEASE PIPELINE AUDIT: PASS")
