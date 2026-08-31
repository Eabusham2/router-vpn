#!/usr/bin/env python3
"""Flatten one verified release-candidate artifact into exact-SHA Release assets."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "server/scripts/native_artifact_policy.py"
_spec = importlib.util.spec_from_file_location("router_vpn_native_artifact_policy", POLICY_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"cannot load {POLICY_PATH}")
_policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_policy)

CHUNK = 1024 * 1024
MAX_ASSET = 768 * 1024 * 1024


def _valid_sha(value: str) -> str:
    sha = value.strip().lower()
    if len(sha) != 40 or any(ch not in "0123456789abcdef" for ch in sha):
        raise ValueError("--sha must be one full 40-character commit SHA")
    return sha


def _verified_copy(source: Path, destination: Path) -> tuple[int, str]:
    before = source.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"release input is not a regular file: {source}")
    if before.st_size <= 0 or before.st_size > MAX_ASSET:
        raise RuntimeError(f"release input has an unsafe size: {source}")

    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    temp_fd, temp_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".part", dir=destination.parent
    )
    temp = Path(temp_name)
    digest = hashlib.sha256()
    total = 0
    adopted = False
    try:
        with os.fdopen(source_fd, "rb", closefd=True) as src, os.fdopen(temp_fd, "wb", closefd=True) as out:
            opened = os.fstat(src.fileno())
            current = source.lstat()
            if not os.path.samestat(before, opened) or not os.path.samestat(opened, current):
                raise RuntimeError(f"release input changed while opening: {source}")
            while True:
                block = src.read(CHUNK)
                if not block:
                    break
                total += len(block)
                if total > MAX_ASSET:
                    raise RuntimeError(f"release input exceeds safety limit: {source}")
                out.write(block)
                digest.update(block)
            out.flush()
            os.fsync(out.fileno())
            after = source.lstat()
            if not os.path.samestat(opened, after) or after.st_size != total:
                raise RuntimeError(f"release input changed during copy: {source}")
        if destination.exists():
            raise RuntimeError(f"release output already exists: {destination}")
        os.chmod(temp, 0o644)
        os.replace(temp, destination)
        adopted = True
        return total, digest.hexdigest()
    finally:
        if not adopted:
            temp.unlink(missing_ok=True)


def _atomic_text(path: Path, text: str) -> None:
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".part", dir=path.parent)
    temp = Path(name)
    adopted = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n", closefd=True) as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temp, 0o644)
        if path.exists():
            raise RuntimeError(f"release metadata output already exists: {path}")
        os.replace(temp, path)
        adopted = True
    finally:
        if not adopted:
            temp.unlink(missing_ok=True)


def materialize(input_root: Path, output_root: Path, source_sha: str, repository: str) -> dict:
    source_sha = _valid_sha(source_sha)
    if repository != "Eabusham2/router-vpn":
        raise ValueError("release repository identity mismatch")
    if not input_root.is_dir():
        raise ValueError("release-candidate input directory is missing")
    output_root.mkdir(parents=True, exist_ok=False)

    expected = sorted(set(_policy.EXACT_SHA_RELEASE_ASSETS.values()))
    if not expected:
        raise RuntimeError("exact-SHA release asset policy is empty")

    assets: list[dict[str, object]] = []
    for name in expected:
        matches = [path for path in input_root.rglob(name) if path.is_file()]
        if len(matches) != 1:
            raise RuntimeError(f"expected exactly one release-candidate file named {name}; found {len(matches)}")
        size, digest = _verified_copy(matches[0], output_root / name)
        assets.append({"name": name, "size": size, "sha256": digest})

    tag = f"{_policy.EXACT_SHA_RELEASE_TAG_PREFIX}{source_sha}"
    metadata = {
        "schema_version": 1,
        "repository": repository,
        "source_sha": source_sha,
        "tag": tag,
        "producer_workflow": "build-all.yml",
        "assets": assets,
    }
    metadata_text = json.dumps(metadata, sort_keys=True, indent=2) + "\n"
    _atomic_text(output_root / "RouterVPN-RELEASE.json", metadata_text)

    release_meta = output_root / "RouterVPN-RELEASE.json"
    meta_digest = hashlib.sha256(release_meta.read_bytes()).hexdigest()
    meta_size = release_meta.stat().st_size
    manifest_rows = [f"{item['sha256']}  {item['name']}" for item in assets]
    manifest_rows.append(f"{meta_digest}  {release_meta.name}")
    _atomic_text(output_root / "SHA256SUMS", "\n".join(manifest_rows) + "\n")
    metadata["assets"].append({"name": release_meta.name, "size": meta_size, "sha256": meta_digest})
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--repository", default="Eabusham2/router-vpn")
    args = parser.parse_args()
    metadata = materialize(args.input.resolve(), args.output.resolve(), args.sha, args.repository)
    print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
