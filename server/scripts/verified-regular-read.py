#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
import stat
import sys

MAX_BYTES = 8 << 20


def parent_chain_snapshot(path: pathlib.Path) -> list[tuple[pathlib.Path, int, int]]:
    absolute = pathlib.Path(os.path.abspath(os.path.normpath(path)))
    parent = absolute.parent
    chain: list[pathlib.Path] = []
    current = parent
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    chain.reverse()

    snapshot: list[tuple[pathlib.Path, int, int]] = []
    for current in chain:
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"refusing non-directory/symlink source ancestor: {current}")
        snapshot.append((current, info.st_dev, info.st_ino))
    return snapshot


def verify_parent_chain(snapshot: list[tuple[pathlib.Path, int, int]]) -> None:
    for current, dev, ino in snapshot:
        info = current.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_dev != dev
            or info.st_ino != ino
        ):
            raise RuntimeError(f"verified source ancestor changed during read: {current}")


def validate_parent_chain(path: pathlib.Path) -> None:
    # Compatibility wrapper retained for callers/tests that only need a
    # one-point validation. Reads use the stronger snapshot + reproof below.
    parent_chain_snapshot(path)


def read_verified_regular(path: pathlib.Path, limit: int = MAX_BYTES, *, private: bool = False) -> bytes:
    path = pathlib.Path(os.path.abspath(os.path.normpath(path)))
    parent_snapshot = parent_chain_snapshot(path)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink public metadata source: {path}")
    if before.st_size <= 0 or before.st_size > limit:
        raise RuntimeError(f"verified source is empty/oversized: {path}")
    if private and stat.S_IMODE(before.st_mode) != 0o600:
        raise RuntimeError(
            f"private verified source must be mode 0600: {path} has {oct(stat.S_IMODE(before.st_mode))}"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        verify_parent_chain(parent_snapshot)
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or (private and stat.S_IMODE(opened.st_mode) != 0o600)
            or (private and stat.S_IMODE(current.st_mode) != 0o600)
        ):
            raise RuntimeError(f"verified source changed during open or violated private mode: {path}")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        body = b"".join(chunks)
        if not body or len(body) > limit:
            raise RuntimeError(f"verified source is empty/oversized: {path}")
        verify_parent_chain(parent_snapshot)
        final = path.lstat()
        if (
            stat.S_ISLNK(final.st_mode)
            or not stat.S_ISREG(final.st_mode)
            or (opened.st_dev, opened.st_ino) != (final.st_dev, final.st_ino)
        ):
            raise RuntimeError(f"verified source changed during read: {path}")
        return body
    finally:
        os.close(fd)


def main(argv: list[str]) -> int:
    private = False
    if len(argv) == 3 and argv[1] == "--private":
        private = True
        source = argv[2]
    elif len(argv) == 2:
        source = argv[1]
    else:
        raise SystemExit("usage: verified-regular-read.py [--private] SOURCE")
    try:
        body = read_verified_regular(pathlib.Path(source), private=private)
    except (OSError, RuntimeError) as exc:
        raise SystemExit(str(exc)) from exc
    sys.stdout.buffer.write(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
