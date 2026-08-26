#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
import stat
import sys
import tempfile

MAX_BYTES = 32 << 20


def _validate_existing_ancestors(parent: pathlib.Path) -> None:
    for current in (parent, *parent.parents):
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"refusing non-directory/symlink private path component: {current}")


def ensure_private_parent(path: pathlib.Path) -> pathlib.Path:
    path = pathlib.Path(os.path.abspath(path))
    parent = path.parent
    # Validate lexical ancestors before creation so a symlink in an earlier path
    # component cannot redirect MkdirAll-equivalent work outside the intended
    # private state tree. Then re-check after creation before any file adoption.
    _validate_existing_ancestors(parent)
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _validate_existing_ancestors(parent)
    return path


def atomic_private_write(path: pathlib.Path, body: bytes) -> None:
    if not body or len(body) > MAX_BYTES:
        raise RuntimeError(f"private output is empty or oversized: {path}")
    path = ensure_private_parent(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        info = None
    if info is not None and (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)):
        raise RuntimeError(f"refusing non-regular/symlink private target: {path}")

    fd, name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    tmp = pathlib.Path(name)
    committed = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        path = ensure_private_parent(path)
        os.replace(tmp, path)
        committed = True
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if not committed:
            tmp.unlink(missing_ok=True)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        raise SystemExit("usage: atomic-private-write.py OUTPUT_PATH")
    body = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise SystemExit("private output exceeds safety limit")
    try:
        atomic_private_write(pathlib.Path(argv[1]), body)
    except (OSError, RuntimeError) as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
