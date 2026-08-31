#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
import stat
import sys
import tempfile
from dataclasses import dataclass

MAX_BYTES = 32 << 20
PRIVATE_MODE = 0o600


@dataclass(frozen=True)
class Item:
    dest: pathlib.Path
    source: pathlib.Path | None
    before: bytes | None
    before_stat: os.stat_result | None
    after: bytes | None


def _validate_existing_ancestors(parent: pathlib.Path) -> None:
    for current in (parent, *parent.parents):
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"refusing non-directory/symlink private path component: {current}")


def ensure_private_parent(path: pathlib.Path, *, create: bool = True) -> None:
    parent = path.parent
    _validate_existing_ancestors(parent)
    try:
        info = parent.lstat()
    except FileNotFoundError:
        if not create:
            raise
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _validate_existing_ancestors(parent)
        info = parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink private parent: {parent}")
    _validate_existing_ancestors(parent)


def read_regular_snapshot(path: pathlib.Path, label: str) -> tuple[bytes, os.stat_result]:
    ensure_private_parent(path, create=False)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink {label}: {path}")
    if info.st_mode & 0o777 != PRIVATE_MODE:
        raise RuntimeError(f"{label} must be mode 0600: {path}")
    if info.st_size <= 0 or info.st_size > MAX_BYTES:
        raise RuntimeError(f"{label} is empty or oversized: {path}")

    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError(f"{label} changed during open: {path}")
        body = bytearray()
        while True:
            chunk = os.read(fd, min(64 * 1024, MAX_BYTES + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > MAX_BYTES:
                raise RuntimeError(f"{label} is oversized: {path}")
        ensure_private_parent(path, create=False)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError(f"{label} changed during read: {path}")
        if not body:
            raise RuntimeError(f"{label} is empty: {path}")
        return bytes(body), current
    finally:
        os.close(fd)


def read_regular(path: pathlib.Path, label: str) -> bytes:
    body, _ = read_regular_snapshot(path, label)
    return body


def existing_snapshot(path: pathlib.Path) -> tuple[bytes | None, os.stat_result | None]:
    try:
        return read_regular_snapshot(path, "private destination")
    except FileNotFoundError:
        return None, None


def require_destination_state(path: pathlib.Path, expected: os.stat_result | None, label: str) -> None:
    ensure_private_parent(path, create=False)
    try:
        current = path.lstat()
    except FileNotFoundError:
        current = None
    if expected is None:
        if current is not None:
            raise RuntimeError(f"{label} appeared before adoption: {path}")
        return
    if current is None:
        raise RuntimeError(f"{label} disappeared before adoption: {path}")
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or current.st_mode & 0o777 != PRIVATE_MODE
        or not os.path.samestat(expected, current)
    ):
        raise RuntimeError(f"{label} identity changed before adoption: {path}")


def stage(dest: pathlib.Path, body: bytes) -> pathlib.Path:
    ensure_private_parent(dest)
    fd, name = tempfile.mkstemp(prefix=f".{dest.name}.batch-", dir=dest.parent)
    tmp = pathlib.Path(name)
    try:
        os.fchmod(fd, PRIVATE_MODE)
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
        _validate_existing_ancestors(path)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"refusing non-directory/symlink private parent: {path}")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        # Some filesystems do not support directory fsync. The file itself was
        # already fsynced before rename, and a post-rename error would be a
        # false transaction failure because adoption has already occurred.
        pass


def restore(adopted: list[tuple[Item, os.stat_result | None]]) -> list[str]:
    errors: list[str] = []
    for item, adopted_stat in reversed(adopted):
        tmp: pathlib.Path | None = None
        try:
            # Rollback owns only the exact inode (or exact absence for a
            # deletion) that this transaction just adopted. If another actor
            # replaced/recreated the destination, report incomplete rollback
            # rather than overwriting foreign state.
            require_destination_state(item.dest, adopted_stat, "adopted private destination")
            if item.before is None:
                if adopted_stat is not None:
                    item.dest.unlink()
                fsync_dir(item.dest.parent)
                continue
            tmp = stage(item.dest, item.before)
            require_destination_state(item.dest, adopted_stat, "adopted private destination")
            os.replace(tmp, item.dest)
            tmp = None
            fsync_dir(item.dest.parent)
        except Exception as exc:
            errors.append(f"{item.dest}: {exc}")
        finally:
            if tmp is not None:
                tmp.unlink(missing_ok=True)
    return errors


def adopt(items: list[Item]) -> None:
    staged: dict[pathlib.Path, pathlib.Path] = {}
    adopted: list[tuple[Item, os.stat_result | None]] = []
    try:
        for item in items:
            if item.after is not None:
                staged[item.dest] = stage(item.dest, item.after)
        for item in items:
            require_destination_state(item.dest, item.before_stat, "private destination")
            if item.after is None:
                # Deletion owns the exact pre-transaction inode. Missing-at-
                # snapshot is a safe no-op; a foreign file that appears later
                # is never unlinked.
                if item.before_stat is not None:
                    item.dest.unlink()
                adopted.append((item, None))
                fsync_dir(item.dest.parent)
                continue

            # Bind ownership to the exact staged inode before rename. A foreign
            # actor can replace the destination immediately after os.replace;
            # recording a fresh lstat without this identity would make rollback
            # mistake that foreign inode for Router VPN state and overwrite it.
            tmp = staged[item.dest]
            staged_stat = tmp.lstat()
            if (
                stat.S_ISLNK(staged_stat.st_mode)
                or not stat.S_ISREG(staged_stat.st_mode)
                or staged_stat.st_mode & 0o777 != PRIVATE_MODE
            ):
                raise RuntimeError(f"staged private destination is unsafe: {tmp}")
            os.replace(tmp, item.dest)
            staged.pop(item.dest, None)

            # Register the expected staged identity before re-reading the
            # destination. If verification detects an immediate replacement,
            # rollback will refuse to touch the foreign inode and report the
            # transaction as incompletely recoverable.
            adopted.append((item, staged_stat))
            adopted_stat = item.dest.lstat()
            if (
                stat.S_ISLNK(adopted_stat.st_mode)
                or not stat.S_ISREG(adopted_stat.st_mode)
                or adopted_stat.st_mode & 0o777 != PRIVATE_MODE
                or not os.path.samestat(staged_stat, adopted_stat)
            ):
                raise RuntimeError(f"adopted private destination identity changed before verification: {item.dest}")
            adopted[-1] = (item, adopted_stat)
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
    ensure_private_parent(dest)
    before, before_stat = existing_snapshot(dest)
    return Item(
        dest=dest,
        source=source,
        before=before,
        before_stat=before_stat,
        after=read_regular(source, "private source"),
    )


def parse_delete(arg: str) -> Item:
    if not arg:
        raise RuntimeError("--delete requires a destination")
    dest = pathlib.Path(arg)
    ensure_private_parent(dest)
    before, before_stat = existing_snapshot(dest)
    return Item(dest=dest, source=None, before=before, before_stat=before_stat, after=None)


def parse_args(argv: list[str]) -> list[Item]:
    items: list[Item] = []
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg == "--delete":
            index += 1
            if index >= len(argv):
                raise RuntimeError("--delete requires a destination")
            items.append(parse_delete(argv[index]))
        elif arg.startswith("--"):
            raise RuntimeError(f"unknown private batch option: {arg}")
        else:
            items.append(parse_item(arg))
        index += 1
    if not items:
        raise RuntimeError("private batch requires at least one mutation")
    destinations = [item.dest for item in items]
    if len(set(destinations)) != len(destinations):
        raise RuntimeError("duplicate private batch destination")
    return items


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        raise SystemExit(
            "usage: atomic-private-batch.py DEST=SOURCE [DEST=SOURCE ...] "
            "[--delete DEST ...]"
        )
    try:
        adopt(parse_args(argv))
    except (OSError, RuntimeError) as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
