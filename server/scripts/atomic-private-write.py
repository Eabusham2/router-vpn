#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
import stat
import sys
import tempfile

MAX_BYTES = 32 << 20


def ensure_private_parent(path: pathlib.Path) -> None:
    parent = path.parent
    try:
        info = parent.lstat()
    except FileNotFoundError:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink private parent: {parent}")


def atomic_private_write(path: pathlib.Path, body: bytes) -> None:
    if not body or len(body) > MAX_BYTES:
        raise RuntimeError(f"private output is empty or oversized: {path}")
    ensure_private_parent(path)
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
