#!/usr/bin/env python3
"""Lock private authoritative stores to regular leaves + symlink-free ancestor paths."""
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
    "validateAncestors",
    "os.SameFile(opened, current)",
    "path component",
)
require(
    "cmd/client/private_store_test.go",
    "TestPrivateStoreRejectsSymlinkParent",
    "TestPrivateStoreRejectsNestedSymlinkAncestor",
)
require(
    "cmd/router-agent/private_state.go",
    "validatePrivilegedStateParent",
    "validateAncestors",
    "os.SameFile(opened, current)",
    "path component",
)
require(
    "cmd/router-agent/private_state_test.go",
    "TestPrivilegedStateRejectsSymlinkParent",
    "TestPrivilegedStateRejectsNestedSymlinkAncestor",
)
require(
    "cmd/update-controller/private_state.go",
    "validateUpdaterPrivateParent",
    "validateAncestors",
    "os.SameFile(opened, current)",
    "path component",
)
require(
    "cmd/update-controller/private_state_test.go",
    "TestUpdaterPrivateFileRejectsSymlinkParent",
    "TestUpdaterPrivateFileRejectsNestedSymlinkAncestor",
)
require(
    "server/scripts/atomic-private-write.py",
    "_validate_existing_ancestors",
    "ensure_private_parent",
    "private path component",
)
require(
    "server/scripts/atomic-private-batch.py",
    "_validate_existing_ancestors",
    "ensure_private_parent",
    "changed during read",
)
require(
    "server/scripts/test_atomic_private_publication.py",
    "accepted a symlink parent",
    "accepted a nested symlink ancestor",
)
require(
    "server/scripts/rosenpass-private-state.py",
    "_validate_existing_ancestors",
    "changed during read",
    "path component",
)
require(
    "server/scripts/test_rosenpass_private_state.py",
    "nested Rosenpass symlink ancestor was accepted",
    "changed during open",
)

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN recursive private-store path boundary audit: PASS")
