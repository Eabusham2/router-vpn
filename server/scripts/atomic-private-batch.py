#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
import stat
import sys
import tempfile
from dataclasses import dataclass

MAX_BYTES = 32 << 20


@dataclass(frozen=True)
class Item:
    dest: pathlib.Path
    source: pathlib.Path
    before: bytes | None
    after: bytes


def read_regular(path: pathlib.Path, label: str) -> bytes:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink {label}: {path}")
    if info.st_size < 0 or info.st_size > MAX_BYTES:
        raise RuntimeError(f"{label} is oversized: {path}")
    body = path.read_bytes()
    if not body or len(body) > MAX_BYTES:
        raise RuntimeError(f"{label} is empty or oversized: {path}")
    return body


def existing_bytes(path: pathlib.Path) -> bytes | None:
    try:
        return read_regular(path, "private destination")
    except FileNotFoundError:
        return None


def stage(dest: pathlib.Path, body: bytes) -> pathlib.Path:
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=f".{dest.name}.batch-", dir=dest.parent)
    tmp = pathlib.Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        return tmp
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        tmp.unlink(missing_ok=True)
        raise


def fsync_dir(path: pathlib.Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def restore(items: list[Item]) -> list[str]:
    errors: list[str] = []
    for item in reversed(items):
        try:
            if item.before is None:
                item.dest.unlink(missing_ok=True)
                fsync_dir(item.dest.parent)
                continue
            tmp = stage(item.dest, item.before)
            try:
                os.replace(tmp, item.dest)
            finally:
                tmp.unlink(missing_ok=True)
            fsync_dir(item.dest.parent)
        except Exception as exc:
            errors.append(f"{item.dest}: {exc}")
    return errors


def adopt(items: list[Item]) -> None:
    staged: dict[pathlib.Path, pathlib.Path] = {}
    adopted: list[Item] = []
    try:
        for item in items:
            staged[item.dest] = stage(item.dest, item.after)
        for item in items:
            tmp = staged.pop(item.dest)
            os.replace(tmp, item.dest)
            adopted.append(item)
            fsync_dir(item.dest.parent)
    except Exception as exc:
        rollback_errors = restore(adopted)
        detail = f"private batch adoption failed; prior state restored: {exc}"
        if rollback_errors:
            detail = f"private batch adoption failed and rollback was incomplete: {exc}; " + "; ".join(rollback_errors)
        raise RuntimeError(detail) from exc
    finally:
        for tmp in staged.values():
            tmp.unlink(missing_ok=True)


def parse_item(arg: str) -> Item:
    if "=" not in arg:
        raise RuntimeError("batch entries must use DEST=SOURCE")
    dest_text, source_text = arg.split("=", 1)
    dest = pathlib.Path(dest_text)
    source = pathlib.Path(source_text)
    if not str(dest) or not str(source):
        raise RuntimeError("batch destination/source may not be empty")
    return Item(dest=dest, source=source, before=existing_bytes(dest), after=read_regular(source, "private source"))


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        raise SystemExit("usage: atomic-private-batch.py DEST=SOURCE [DEST=SOURCE ...]")
    try:
        items = [parse_item(arg) for arg in argv[1:]]
        destinations = [item.dest for item in items]
        if len(set(destinations)) != len(destinations):
            raise RuntimeError("duplicate private batch destination")
        adopt(items)
    except (OSError, RuntimeError) as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
