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
    "cmd/client/bundle_staging.go",
    "canonicalBundleRoot",
    "validatePrivateParent",
    "client root must be a non-symlink directory",
    "ensurePrivateDirectoryNoSymlink",
)
require(
    "cmd/client/bundle_staging_path_test.go",
    "TestBundleOperationsRejectSymlinkedClientRoot",
    "TestBundleOperationsRejectNestedSymlinkAncestor",
    "TestStagedBundleImportRejectsExistingDestination",
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
    "server/scripts/ensure-setup-auth.py",
    "_validate_existing_ancestors",
    "changed during read",
    "Path(os.path.abspath(base))",
)
require(
    "server/scripts/test_setup_auth.py",
    "nested Setup Center symlink ancestor was accepted",
    "post-read replacement race was accepted",
)
require(
    "server/scripts/ensure-node-proof.py",
    "_validate_existing_ancestors",
    "changed during read",
    "path component",
)
require(
    "server/scripts/test_node_proof_private_state.py",
    "nested node-proof symlink ancestor was accepted",
    "router-agent replacement during node-proof read was accepted",
)
require(
    "server/scripts/preserve-generated-state.py",
    "_validate_existing_ancestors",
    "changed during read",
    "Path(os.path.abspath(sys.argv[2]))",
)
require(
    "server/scripts/test_preserve_generated_state.py",
    "nested preserved credential symlink ancestor was accepted",
    "preserved credential post-read replacement race was accepted",
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
require(
    "server/finalize/sync-endpoint.py",
    "_validate_owned_ancestors",
    "changed during read",
    "Path(os.path.abspath(base))",
)
require(
    "server/finalize/test_sync_endpoint.py",
    "test_nested_symlink_owned_ancestor_is_rejected_before_mutation",
    "test_owned_file_identity_change_during_read_is_rejected",
)

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN recursive private-store/import/identity path boundary audit: PASS")
