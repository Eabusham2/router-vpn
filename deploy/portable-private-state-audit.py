#!/usr/bin/env python3
"""Protect Router VPN Portable bootstrap/state from unsafe writes and path redirects."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing Portable private-state source: {rel}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def require(rel: str, *markers: str) -> None:
    body = read(rel)
    for marker in markers:
        if marker not in body:
            errors.append(f"{rel}: missing Portable private-state marker {marker!r}")


def forbid(rel: str, *markers: str) -> None:
    body = read(rel)
    for marker in markers:
        if marker in body:
            errors.append(f"{rel}: forbidden Portable state regression marker {marker!r}")


require(
    "cmd/portable-launcher/private_store.go",
    "validatePortableExistingAncestors",
    "rejectPortableSymlinksUnder",
    "validatePortablePrivateParent",
    "ensurePortablePrivateDir",
    "readPortablePrivate",
    "readPortablePackageFile",
    "os.SameFile(opened, current)",
    "os.CreateTemp",
    "tmp.Sync()",
    "atomicWritePortablePrivate",
    "atomicWritePortablePrivateTargetUnchanged",
    "identity changed before adoption",
    "copyPortablePrivate",
)
require(
    "cmd/portable-launcher/main.go",
    "ensurePortablePrivateDir(dataDir)",
    "ensurePortablePrivateDir(generatedDir)",
    "copyPortablePrivate",
    "readPortablePrivate",
    "atomicWritePortablePrivate",
    "existing Portable client.json is invalid; refusing silent reset",
    "writeRuntimeStatus",
)
forbid(
    "cmd/portable-launcher/main.go",
    'path+".tmp"',
    "os.WriteFile(tmp",
    "_ = os.WriteFile(path",
    "os.WriteFile(dst",
    "copyAlways(",
    "copyDefault(",
)
require(
    "cmd/portable-launcher/private_store_test.go",
    "TestPortablePrivateStoreRoundTrip",
    "TestPortablePrivateStoreRejectsSymlinkDataDirectory",
    "TestPortablePrivateStoreRejectsNestedSymlinkAncestor",
    "TestPortablePackageSourceRejectsSymlinkAncestor",
    "TestPortableRegularExistsRejectsRuntimeSymlinkAncestor",
    "TestPortablePrivateStoreRejectsTargetReplacementBeforeAdoption",
)
require(
    "cmd/portable-launcher/native_windows_catalog_test.go",
    "if _, _, err := prepareWindowsModeCatalog",
)

if errors:
    print("Router VPN Portable private-state audit: FAIL")
    for error in errors:
        print(" -", error)
    raise SystemExit(1)
print("Router VPN Portable private-state audit: PASS")
