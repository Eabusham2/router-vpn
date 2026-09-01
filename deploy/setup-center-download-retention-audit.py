#!/usr/bin/env python3
"""Authoritative GitHub-first and 30-minute Setup Center download contract."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(path: str) -> str:
    target = ROOT / path
    if not target.is_file():
        errors.append(f"missing {path}")
        return ""
    return target.read_text(encoding="utf-8", errors="replace")


def need(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing {marker!r}")


def forbid(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker in body:
            errors.append(f"{path}: forbidden {marker!r}")


need(
    "server/scripts/download_jobs.py",
    "JOB_TTL_SECONDS = 30 * 60",
    'RETAINED = {"ready", "delivered", "delivery-interrupted"}',
    "retention_deadline_epoch=time.time() + PACKAGE_RETENTION_SECONDS",
    'status not in RETAINED',
    "delivery_attempts",
    "temporary package retained for repeat download until its 30-minute deadline",
    "temporary package and build workspace deleted after 30 minutes",
    'job.update(status="cleaning", phase="cleanup", progress=100)',
    'status="cleanup-pending"',
)
forbid(
    "server/scripts/download_jobs.py",
    "JOB_TTL_SECONDS = 15 * 60",
    "download delivery was interrupted; temporary output was deleted",
)

# Every package route, including a raw/direct package URL, must use the same
# retained manager. Streaming must observe DELETE cancellation between chunks.
need(
    "server/scripts/setup-center-product-server.py",
    "def _dynamic(self, name: str)",
    "job = self.server.jobs.create(name)",
    "self._job_file(job_id)",
    "self.server.jobs.cancel_requested(job_id)",
    "X-Router-VPN-Retained-Until",
    "30-minute retained package retry",
)

# Normal delivery order is exact-SHA GitHub Release, then exact-SHA Actions,
# then one bounded supported local desktop/Portable build. Mobile stays exact-
# SHA GitHub-only and private node data remains a separate bundle.
need(
    "server/scripts/setup-center-product-server.py",
    "_exact_release.install(_ai._core._broker)",
    "one-package local fallback",
)
need(
    "server/scripts/download-broker.py",
    "build_github_package",
    "compiling requested generic package locally",
    '"router-local-generic-build"',
    "requires its same-SHA GitHub mobile artifact",
)
need(
    "server/scripts/build-download-on-demand.py",
    "assemble only the requested",
    "bounded Go build only for a missing supported Windows/Portable Go component",
    "GENERIC and secret-free",
)

need(
    "server/scripts/setup_center_ux_patch.py",
    "Temporary package deletes in",
    "Download again",
    "Delete now",
    "downloadExisting(active)",
    "retained_until",
    "expires_in_seconds",
    "same 30-minute retained job policy",
)

for test in (
    "server/scripts/test_download_jobs.py",
    "server/scripts/test_setup_center_ux_patch.py",
):
    proc = subprocess.run([sys.executable, str(ROOT / test)], cwd=ROOT,
                          text=True, capture_output=True)
    if proc.returncode != 0:
        errors.append(f"{test}: {proc.stdout}{proc.stderr}".strip())

if errors:
    print("SETUP CENTER DOWNLOAD RETENTION AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)

print("SETUP CENTER DOWNLOAD RETENTION AUDIT: PASS")
