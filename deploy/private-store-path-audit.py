#!/usr/bin/env python3
"""Lock private authoritative stores to regular leaf + non-symlink parent paths."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def require(rel: str, *markers: str) -> None:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing {rel}")
        return
    body = path.read_text(encoding="utf-8", errors="replace")
    for marker in markers:
        if marker not in body:
            errors.append(f"{rel}: missing {marker!r}")


require(
    "cmd/client/private_store.go",
    "validatePrivateParent",
    "os.SameFile(opened, current)",
    "refusing non-directory/symlink private store parent",
)
require(
    "cmd/client/private_store_test.go",
    "TestPrivateStoreRejectsSymlinkParent",
    "symlink parent was accepted for private store write",
)
require(
    "cmd/router-agent/private_state.go",
    "validatePrivilegedStateParent",
    "os.SameFile(opened, current)",
    "refusing non-directory/symlink privileged state parent",
)
require(
    "cmd/router-agent/private_state_test.go",
    "TestPrivilegedStateRejectsSymlinkParent",
    "symlink privileged-state parent was accepted",
)
require(
    "cmd/update-controller/private_state.go",
    "validateUpdaterPrivateParent",
    "os.SameFile(opened, current)",
    "refusing non-directory/symlink private updater parent",
)
require(
    "cmd/update-controller/private_state_test.go",
    "TestUpdaterPrivateFileRejectsSymlinkParent",
    "symlink updater-state parent was accepted",
)
require(
    "server/scripts/atomic-private-write.py",
    "ensure_private_parent",
    "refusing non-directory/symlink private parent",
)
require(
    "server/scripts/atomic-private-batch.py",
    "ensure_private_parent",
    "refusing non-directory/symlink private parent",
)
require(
    "server/scripts/test_atomic_private_publication.py",
    "single-file private publisher accepted a symlink parent",
    "batch private publisher accepted a symlink parent",
)

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN private-store path boundary audit: PASS")
