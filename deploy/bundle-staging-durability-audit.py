#!/usr/bin/env python3
"""Require private imported bundle bytes to be durable before atomic adoption."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing bundle-staging durability source: {rel}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def require(rel: str, *markers: str) -> None:
    body = read(rel)
    for marker in markers:
        if marker not in body:
            errors.append(f"{rel}: missing bundle durability marker {marker!r}")


def forbid(rel: str, *markers: str) -> None:
    body = read(rel)
    for marker in markers:
        if marker in body:
            errors.append(f"{rel}: forbidden staging durability regression {marker!r}")


require(
    "cmd/client/bundle_staging.go",
    "writeStagedBundleFile",
    "os.O_EXCL",
    "file.Sync()",
    "syncBundleDirectory",
    "syncBundleDirectory(s.profileDir)",
    "sync staged profile before adoption",
    "os.Rename(s.profileDir, final)",
    "syncBundleDirectoryBestEffort(generated)",
    "Rename is the commit point",
)
forbid(
    "cmd/client/bundle_staging.go",
    "os.WriteFile(path, data, 0o600)",
)
require(
    "cmd/client/bundle_staging_test.go",
    "TestBundleStagingFailureLeavesNoGeneratedProfile",
    "TestBundleStagingCommitsAtomicallyWithPrivateModes",
    "TestBundleCommitRejectsGeneratedSymlinkSwapAfterStaging",
)
require(
    "cmd/client/main.go",
    "newStagedBundle(",
    ".writeProfiles(",
    ".commit(",
)

if errors:
    print("Router VPN bundle staging durability audit: FAIL")
    for error in errors:
        print(" -", error)
    raise SystemExit(1)
print("Router VPN bundle staging durability audit: PASS")
