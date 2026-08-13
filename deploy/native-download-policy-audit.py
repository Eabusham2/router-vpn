#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def text(rel: str) -> str:
    p = ROOT / rel
    if not p.is_file():
        errors.append(f"missing {rel}")
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def need(rel: str, *markers: str) -> None:
    body = text(rel)
    for marker in markers:
        if marker not in body:
            errors.append(f"{rel}: missing native-download marker {marker!r}")


# The public/requested filenames are intentionally stable. CI-native packages
# replace the older controller-only desktop payload without changing the client
# facing download URL or leaking node data into the generic package.
package_names = (
    "RouterVPN-Windows-amd64.zip",
    "RouterVPN-Windows-arm64.zip",
    "RouterVPN-Portable-Windows-amd64.zip",
    "RouterVPN-Portable-Windows-arm64.zip",
    "RouterVPN-darwin-amd64.tar.gz",
    "RouterVPN-darwin-arm64.tar.gz",
    "RouterVPN-linux-amd64.tar.gz",
    "RouterVPN-linux-arm64.tar.gz",
)

for name in package_names:
    if name not in text("server/scripts/download-broker.py") and name.lower() not in text("server/scripts/download-broker.py").lower():
        errors.append(f"download broker has no requested-package mapping/reference for {name}")

need(
    ".github/workflows/release-candidate.yml",
    "RouterVPN-release-candidate-${{ github.sha }}",
    "RouterVPN-darwin-amd64.tar.gz",
    "RouterVPN-darwin-arm64.tar.gz",
    "RouterVPN-linux-${{ matrix.arch }}.tar.gz",
    "RouterVPN-Windows-$arch.zip",
    "retention-days: 1",
)
need(
    "deploy/package-macos-native.sh",
    "RouterVPN-darwin-amd64",
    "RouterVPN-darwin-arm64",
    "RouterVPN.app",
    "check-generic-package-secrets.py",
)
need(
    "deploy/package-linux-native.sh",
    'name="RouterVPN-linux-$ARCH"',
    "router-vpn-app",
    "check-generic-package-secrets.py",
)

broker = text("server/scripts/download-broker.py")
for marker in ("ROUTER_VPN_GITHUB_SHA", "artifact"):
    if marker.lower() not in broker.lower():
        errors.append(f"download broker missing same-SHA GitHub artifact concept: {marker}")
for forbidden in ("latest.zip", "/releases/latest", "refs/heads/main"):
    if forbidden in broker:
        errors.append(f"download broker contains floating artifact source {forbidden!r}")

builder = text("server/scripts/build-download-on-demand.py")
for marker in ("requested-generic-package-only", "LOCAL_BUILD_TIMEOUT", "compile_requested"):
    if marker not in builder:
        errors.append(f"router-local fallback contract missing {marker!r}")

# Generic packages must remain independent of private node linking.
scanner = text("deploy/check-generic-package-secrets.py")
for marker in ("generic package contains private bundle", "generic package contains linked router profiles", "package does not ship LICENSE"):
    if marker not in scanner:
        errors.append(f"generic package leak scanner missing {marker!r}")

if errors:
    print("NATIVE DOWNLOAD POLICY AUDIT: FAIL", file=sys.stderr)
    for err in errors:
        print(" - " + err, file=sys.stderr)
    raise SystemExit(1)
print("NATIVE DOWNLOAD POLICY AUDIT: PASS")
