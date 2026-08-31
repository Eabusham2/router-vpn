#!/usr/bin/env python3
"""Source-SHA and artifact provenance helpers for Router VPN release workflows."""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Iterable, Mapping

HEX64 = frozenset("0123456789abcdef")
MAX_FILE_BYTES = 512 << 20
PUBLIC_MODE = 0o644


def validate_sha(value: str, label: str) -> str:
    value = str(value or "").strip().lower()
    if len(value) != 64 or any(ch not in HEX64 for ch in value):
        raise RuntimeError(f"{label} is not a lowercase sha256 digest")
    return value


def validate_source_sha(value: str) -> str:
    value = str(value or "").strip().lower()
    if len(value) != 40 or any(ch not in HEX64 for ch in value):
        raise RuntimeError("source SHA is not a 40-character lowercase Git commit")
    return value


def _parent_snapshot(path: Path) -> os.stat_result:
    parent = path.parent
    info = parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing unsafe provenance parent: {parent}")
    return info


def _target_snapshot(path: Path) -> os.stat_result | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink provenance target: {path}")
    return info


def _require_target_state(path: Path, expected: os.stat_result | None) -> None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        current = None
    if expected is None:
        if current is not None:
            raise RuntimeError(f"provenance target appeared before adoption: {path}")
        return
    if current is None:
        raise RuntimeError(f"provenance target disappeared before adoption: {path}")
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or not os.path.samestat(expected, current)
    ):
        raise RuntimeError(f"provenance target identity changed before adoption: {path}")


def _read_regular_file(path: Path) -> bytes:
    path = Path(path)
    parent_before = _parent_snapshot(path)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink artifact: {path}")
    if info.st_size <= 0 or info.st_size > MAX_FILE_BYTES:
        raise RuntimeError(f"artifact is empty or exceeds {MAX_FILE_BYTES} bytes: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError(f"artifact changed during open: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1 << 20, MAX_FILE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise RuntimeError(f"artifact exceeds {MAX_FILE_BYTES} bytes: {path}")
        parent_after = _parent_snapshot(path)
        current = path.lstat()
        if (
            not os.path.samestat(parent_before, parent_after)
            or stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(opened, current)
        ):
            raise RuntimeError(f"artifact changed during read: {path}")
        body = b"".join(chunks)
    finally:
        os.close(fd)
    if not body:
        raise RuntimeError(f"artifact is empty: {path}")
    return body


def _sha256_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(_read_regular_file(path))


def _gunzip_sha256_bytes(body: bytes) -> str:
    digest = hashlib.sha256()
    total = 0
    with gzip.GzipFile(fileobj=io.BytesIO(body), mode="rb") as stream:
        while True:
            chunk = stream.read(min(1 << 20, MAX_FILE_BYTES + 1 - total))
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise RuntimeError("decompressed provenance artifact exceeds safety limit")
    if total <= 0:
        raise RuntimeError("decompressed provenance artifact is empty")
    return digest.hexdigest()


def _gunzip_sha256(path: Path) -> str:
    return _gunzip_sha256_bytes(_read_regular_file(path))


def _atomic_write(path: Path, body: bytes) -> None:
    path = Path(path)
    if not body or len(body) > MAX_FILE_BYTES:
        raise RuntimeError(f"provenance output is empty or oversized: {path}")
    parent_before = _parent_snapshot(path)
    target_before = _target_snapshot(path)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.provenance-", dir=path.parent)
    tmp = Path(name)
    adopted = False
    try:
        os.fchmod(fd, PUBLIC_MODE)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        staged = tmp.lstat()
        if (
            stat.S_ISLNK(staged.st_mode)
            or not stat.S_ISREG(staged.st_mode)
            or (os.name != "nt" and stat.S_IMODE(staged.st_mode) != PUBLIC_MODE)
        ):
            raise RuntimeError(f"staged provenance target is unsafe: {tmp}")

        parent_current = _parent_snapshot(path)
        if not os.path.samestat(parent_before, parent_current):
            raise RuntimeError(f"provenance parent changed before adoption: {path.parent}")
        _require_target_state(path, target_before)
        os.replace(tmp, path)
        adopted = True

        parent_after = _parent_snapshot(path)
        current = path.lstat()
        if (
            not os.path.samestat(parent_before, parent_after)
            or stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or (os.name != "nt" and stat.S_IMODE(current.st_mode) != PUBLIC_MODE)
            or not os.path.samestat(staged, current)
        ):
            raise RuntimeError(f"adopted provenance target identity changed before verification: {path}")
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if not adopted:
            tmp.unlink(missing_ok=True)


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    _atomic_write(Path(path), (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def copy_artifact(source: Path, destination: Path, expected_sha256: str) -> int:
    body = _read_regular_file(Path(source))
    actual = _sha256_bytes(body)
    expected = validate_sha(expected_sha256, f"expected digest for {source}")
    if actual != expected:
        raise RuntimeError(f"artifact digest changed before publication: {source}")
    _atomic_write(Path(destination), body)
    return len(body)


def build_file_record(
    *,
    source_sha: str,
    platform: str,
    source: Path,
    artifact_name: str,
    expected_binary_sha256: str,
    publish_path: Path | None = None,
) -> dict[str, Any]:
    source_sha = validate_source_sha(source_sha)
    source = Path(source)
    artifact_name = str(artifact_name or "").strip()
    if not artifact_name or Path(artifact_name).name != artifact_name:
        raise RuntimeError("artifact name must be one plain filename")

    # Hash, size, gzip-inner verification, and publication all consume this one
    # verified source snapshot. The source pathname is never reopened between
    # evidence generation and the bytes copied into the release artifact.
    body = _read_regular_file(source)
    artifact_sha = _sha256_bytes(body)
    expected_binary_sha = validate_sha(expected_binary_sha256, "expected binary digest")
    if source.name.endswith(".tar.gz"):
        actual_binary_sha = _gunzip_sha256_bytes(body)
        if actual_binary_sha != expected_binary_sha:
            raise RuntimeError(f"compressed artifact does not contain expected binary: {source}")
    elif artifact_sha != expected_binary_sha:
        raise RuntimeError(f"artifact does not match expected binary digest: {source}")

    if publish_path is not None:
        _atomic_write(Path(publish_path), body)

    return {
        "schema_version": 1,
        "source_sha": source_sha,
        "platform": str(platform),
        "artifact_name": artifact_name,
        "artifact_sha256": artifact_sha,
        "binary_sha256": expected_binary_sha,
        "size": len(body),
    }


def build_manifest(
    *,
    source_sha: str,
    source_ref: str,
    run_id: str,
    records: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    source_sha = validate_source_sha(source_sha)
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw in records:
        record = dict(raw)
        if validate_source_sha(str(record.get("source_sha") or "")) != source_sha:
            raise RuntimeError("provenance record source SHA does not match manifest source SHA")
        platform = str(record.get("platform") or "").strip()
        name = str(record.get("artifact_name") or "").strip()
        if not platform or not name:
            raise RuntimeError("provenance record is missing platform or artifact name")
        key = (platform, name)
        if key in seen:
            raise RuntimeError(f"duplicate provenance record for {platform}/{name}")
        seen.add(key)
        record["artifact_sha256"] = validate_sha(str(record.get("artifact_sha256") or ""), "artifact digest")
        record["binary_sha256"] = validate_sha(str(record.get("binary_sha256") or ""), "binary digest")
        normalized.append(record)
    if not normalized:
        raise RuntimeError("release manifest has no provenance records")
    return {
        "schema_version": 1,
        "source_sha": source_sha,
        "source_ref": str(source_ref or "").strip(),
        "run_id": str(run_id or "").strip(),
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "artifacts": sorted(normalized, key=lambda item: (item["platform"], item["artifact_name"])),
    }


def verify_manifest(
    manifest: Mapping[str, Any],
    *,
    expected_source_sha: str,
    required: Iterable[tuple[str, str]] = (),
) -> list[str]:
    errors: list[str] = []
    try:
        source_sha = validate_source_sha(str(manifest.get("source_sha") or ""))
    except RuntimeError as exc:
        return [str(exc)]
    expected = validate_source_sha(expected_source_sha)
    if source_sha != expected:
        errors.append(f"manifest source SHA {source_sha} does not match expected {expected}")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("manifest artifacts list is empty")
        artifacts = []
    present: set[tuple[str, str]] = set()
    for index, raw in enumerate(artifacts):
        if not isinstance(raw, Mapping):
            errors.append(f"artifact record {index} is not an object")
            continue
        platform = str(raw.get("platform") or "").strip()
        name = str(raw.get("artifact_name") or "").strip()
        present.add((platform, name))
        if str(raw.get("source_sha") or "").strip().lower() != expected:
            errors.append(f"artifact {platform}/{name} was not built from expected source SHA")
        for field in ("artifact_sha256", "binary_sha256"):
            try:
                validate_sha(str(raw.get(field) or ""), f"{platform}/{name} {field}")
            except RuntimeError as exc:
                errors.append(str(exc))
        try:
            if int(raw.get("size") or 0) <= 0:
                raise ValueError
        except (TypeError, ValueError):
            errors.append(f"artifact {platform}/{name} has invalid size")
    for platform, name in required:
        if (platform, name) not in present:
            errors.append(f"missing required provenance artifact {platform}/{name}")
    return errors


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(_read_regular_file(Path(path)).decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON root is not an object: {path}")
    return value


def _main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("manifest", type=Path)
    verify.add_argument("--source-sha", required=True)
    verify.add_argument("--require", action="append", default=[], metavar="PLATFORM/FILE")
    args = parser.parse_args()
    if args.command == "verify":
        required: list[tuple[str, str]] = []
        for value in args.require:
            if "/" not in value:
                raise RuntimeError("--require must use PLATFORM/FILE")
            required.append(tuple(value.split("/", 1)))
        errors = verify_manifest(load_json(args.manifest), expected_source_sha=args.source_sha, required=required)
        for error in errors:
            print(f"ERROR: {error}")
        return 1 if errors else 0
    return 2


if __name__ == "__main__":
    raise SystemExit(_main())
