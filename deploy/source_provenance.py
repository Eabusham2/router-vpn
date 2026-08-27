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


def resolve_repo(explicit: str = "") -> str:
    repo = str(explicit or os.environ.get("ROUTER_VPN_GITHUB_REPO", "") or os.environ.get("GITHUB_REPOSITORY", "") or "Eabusham2/router-vpn").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise RuntimeError("invalid source provenance repository")
    return repo


def _safe_existing(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink source provenance target: {path}")


def write_manifest(root: Path, sha: str, family: str, repo: str = "") -> Path:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("source provenance root is not a directory")
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
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
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
        if not committed:
            tmp.unlink(missing_ok=True)
    return path


def read_manifest(root: Path) -> dict:
    root = root.resolve(strict=True)
    path = root / MANIFEST
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("source provenance manifest is not a regular file")
    if info.st_size <= 0 or info.st_size > MAX_MANIFEST:
        raise RuntimeError("source provenance manifest size is invalid")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("source provenance manifest schema is invalid")
    data["source_sha"] = normalize_sha(str(data.get("source_sha") or ""))
    resolve_repo(str(data.get("repository") or ""))
    family = str(data.get("artifact_family") or "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", family):
        raise RuntimeError("source provenance artifact family is invalid")
    return data


def verify_manifest(root: Path, expected_sha: str, expected_family: str = "") -> dict:
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
        verify_manifest(root, sha, args.family)
    else:
        write_manifest(root, sha, args.family, args.repo)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
