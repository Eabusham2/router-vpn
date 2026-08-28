#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

SCHEMA_VERSION = 1
MANIFEST = "ROUTER-VPN-SOURCE.json"
MAX_MANIFEST = 64 << 10
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def normalize_sha(value: str) -> str:
    sha = str(value or "").strip().lower()
    if not SHA_RE.fullmatch(sha):
        raise RuntimeError("source provenance requires one full 40-character Git commit SHA")
    return sha


def resolve_sha(explicit: str = "", root: Path | None = None) -> str:
    values = (
        explicit,
        os.environ.get("ROUTER_VPN_SOURCE_SHA", ""),
        os.environ.get("GITHUB_SHA", ""),
        os.environ.get("ROUTER_VPN_GITHUB_SHA", ""),
    )
    for value in values:
        if str(value or "").strip():
            return normalize_sha(str(value))
    if root is not None:
        try:
            out = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).strip()
            return normalize_sha(out)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError):
            pass
    raise RuntimeError("source provenance SHA is unavailable; set GITHUB_SHA or ROUTER_VPN_GITHUB_SHA")


def validate_repo(value: str) -> str:
    repo = str(value or "").strip()
    if not repo or not REPO_RE.fullmatch(repo):
        raise RuntimeError("invalid source provenance repository")
    return repo


def resolve_repo(explicit: str = "") -> str:
    repo = str(
        explicit
        or os.environ.get("ROUTER_VPN_GITHUB_REPO", "")
        or os.environ.get("GITHUB_REPOSITORY", "")
        or "Eabusham2/router-vpn"
    ).strip()
    return validate_repo(repo)


def _regular_root(root: Path) -> Path:
    root = Path(os.path.abspath(root))
    info = root.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink source provenance root: {root}")
    return root


def _safe_existing(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink source provenance target: {path}")


def write_manifest(root: Path, sha: str, family: str, repo: str = "") -> Path:
    root = _regular_root(root)
    sha = normalize_sha(sha)
    repo = resolve_repo(repo)
    family = str(family or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", family):
        raise RuntimeError("invalid source provenance artifact family")
    path = root / MANIFEST
    _safe_existing(path)
    body = (json.dumps({
        "schema_version": SCHEMA_VERSION,
        "repository": repo,
        "source_sha": sha,
        "artifact_family": family,
    }, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, name = tempfile.mkstemp(prefix=f".{MANIFEST}.tmp-", dir=root)
    tmp = Path(name)
    committed = False
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o644)
        else:
            # Windows has no POSIX fchmod; provenance is public package metadata,
            # so chmod the already-created temp path instead.
            os.chmod(tmp, 0o644)
        stream = os.fdopen(fd, "wb", closefd=True)
        fd = -1
        with stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        # Re-prove the root and leaf immediately before adoption. A build path
        # redirected after staging must not receive a trusted provenance file.
        current_root = root.lstat()
        if stat.S_ISLNK(current_root.st_mode) or not stat.S_ISDIR(current_root.st_mode):
            raise RuntimeError("source provenance root changed before adoption")
        _safe_existing(path)
        os.replace(tmp, path)
        committed = True
        try:
            dfd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if not committed:
            tmp.unlink(missing_ok=True)
    return path


def _read_manifest_bytes(root: Path) -> bytes:
    root = _regular_root(root)
    path = root / MANIFEST
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError("source provenance manifest is not a regular file")
    if before.st_size <= 0 or before.st_size > MAX_MANIFEST:
        raise RuntimeError("source provenance manifest size is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(opened, current)
        ):
            raise RuntimeError("source provenance manifest changed during open")
        body = os.read(fd, MAX_MANIFEST + 1)
    finally:
        os.close(fd)
    if not body or len(body) > MAX_MANIFEST:
        raise RuntimeError("source provenance manifest size is invalid")
    return body


def read_manifest(root: Path) -> dict:
    try:
        data = json.loads(_read_manifest_bytes(root).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("source provenance manifest JSON is invalid") from exc
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("source provenance manifest schema is invalid")
    data["source_sha"] = normalize_sha(str(data.get("source_sha") or ""))
    data["repository"] = validate_repo(str(data.get("repository") or ""))
    family = str(data.get("artifact_family") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", family):
        raise RuntimeError("source provenance artifact family is invalid")
    data["artifact_family"] = family
    return data


def verify_manifest(root: Path, expected_sha: str, expected_family: str = "", expected_repo: str = "") -> dict:
    data = read_manifest(root)
    expected_sha = normalize_sha(expected_sha)
    if data["source_sha"] != expected_sha:
        raise RuntimeError(
            f"source provenance mismatch: package={data['source_sha']} expected={expected_sha}"
        )
    if expected_family and data.get("artifact_family") != expected_family:
        raise RuntimeError(
            f"source provenance family mismatch: package={data.get('artifact_family')} expected={expected_family}"
        )
    if expected_repo:
        repo = validate_repo(expected_repo)
        if data.get("repository") != repo:
            raise RuntimeError(
                f"source provenance repository mismatch: package={data.get('repository')} expected={repo}"
            )
    return data


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--sha", default="")
    ap.add_argument("--family", required=True)
    ap.add_argument("--repo", default="")
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args()
    root = Path(args.root)
    sha = resolve_sha(args.sha, root)
    if args.verify:
        verify_manifest(root, sha, args.family, args.repo)
    else:
        write_manifest(root, sha, args.family, args.repo)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
