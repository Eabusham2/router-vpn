#!/usr/bin/env python3
"""Prove endpoint synchronization remains narrow, private, and transactional."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SYNC = ROOT / "server/finalize/sync-endpoint.py"
TEST = ROOT / "server/finalize/test_sync_endpoint.py"
LEGACY = ROOT / "server/scripts/update-endpoint.sh"


def fail(message: str) -> None:
    raise SystemExit(f"endpoint sync ownership audit: {message}")


def require(body: str, *markers: str) -> None:
    missing = [marker for marker in markers if marker not in body]
    if missing:
        fail(f"missing source contract marker(s): {missing}")


if not SYNC.is_file() or not TEST.is_file():
    fail("missing endpoint synchronizer or transaction tests")
if LEGACY.exists():
    fail("obsolete broad endpoint rewriter returned")

body = SYNC.read_text(encoding="utf-8")
tests = TEST.read_text(encoding="utf-8")

require(
    body,
    'RAW_PROFILES = {',
    'ENDPOINT_LINE = re.compile(',
    'base / "client-bundle" / "generated" / mode / name',
    'profile.get("id")',
    '"home"',
    'profile.get("node_kind")',
    '"Router-vpn"',
    'multiple owned home Router VPN profiles',
    'stage_private',
    'os.fchmod(fd, PRIVATE_MODE)',
    'os.fsync(stream.fileno())',
    'os.replace(tmp, change.path)',
    'restore_changes(reversed(adopted))',
    'rollback was incomplete',
    'os.path.samestat(opened, current)',
    'refusing non-directory/symlink owned path component',
)
# The synchronizer may parse JSON, but it must never recursively walk arbitrary
# dictionaries or mutate generic server/address keys outside the explicit raw
# WG/AWG Endpoint line plus owned home-profile endpoint contract.
for forbidden in (
    'profile["server"] =',
    'profile["address"] =',
    'replace("router.invalid"',
    'os.walk(',
    'rglob(',
):
    if forbidden in body:
        fail(f"broad endpoint ownership pattern returned: {forbidden!r}")

require(
    tests,
    'test_owned_endpoint_update_is_atomic_private_and_narrow',
    'test_late_adoption_failure_restores_every_changed_file',
    'test_foreign_regular_replacement_before_adoption_is_preserved',
    'test_rollback_preserves_foreign_replacement_after_adoption',
    'test_symlink_owned_target_is_rejected_before_mutation',
    'test_symlink_owned_parent_is_rejected_before_mutation',
    'test_nested_symlink_owned_ancestor_is_rejected_before_mutation',
    'test_owned_file_identity_change_during_open_is_rejected',
    'test_owned_file_identity_change_during_read_is_rejected',
    'test_duplicate_owned_home_profiles_fail_closed',
)

subprocess.run([sys.executable, str(TEST)], cwd=ROOT, check=True)
print("Endpoint synchronization ownership audit: PASS")
