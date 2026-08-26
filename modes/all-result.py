#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import tempfile

ALLOWED = {"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"}
MAX_BYTES = 64


def trusted_target(root_text: str, target_text: str) -> tuple[Path, os.stat_result]:
    root_input = Path(root_text)
    root = root_input.resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("Router VPN root is not a directory")
    target_input = Path(target_text)
    if target_input.is_absolute():
        target = Path(os.path.abspath(target_input))
    else:
        # The controller's state/result paths are relative to HOMEVPN_ROOT, not
        # the shell process cwd. Resolve them against the explicit trusted root.
        target = Path(os.path.abspath(root_input / target_input)).resolve(strict=False)
    try:
        rel_parent = target.parent.relative_to(root)
    except ValueError as exc:
        raise RuntimeError("ALL result path must stay inside HOMEVPN_ROOT") from exc

    current = root
    for part in rel_parent.parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"refusing non-directory/symlink ALL result ancestor: {current}")
    parent_info = target.parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise RuntimeError(f"refusing unsafe ALL result parent: {target.parent}")
    return target, parent_info


def validate_existing(target: Path) -> None:
    try:
        info = target.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink ALL result target: {target}")
    if info.st_size < 0 or info.st_size > MAX_BYTES:
        raise RuntimeError(f"ALL result target exceeds safety limit: {target}")


def _sync_parent_best_effort(parent: Path) -> None:
    try:
        dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def prepare(root: str, target_text: str) -> None:
    target, parent_before = trusted_target(root, target_text)
    validate_existing(target)
    try:
        target.unlink()
    except FileNotFoundError:
        return
    target_now, parent_now = trusted_target(root, target_text)
    if target_now != target or not os.path.samestat(parent_before, parent_now):
        raise RuntimeError("ALL result parent changed during stale-result cleanup")
    _sync_parent_best_effort(target.parent)


def publish(root: str, target_text: str, value: str) -> None:
    value = value.strip()
    if value not in ALLOWED:
        raise RuntimeError(f"refusing unknown ALL runtime branch: {value!r}")
    body = (value + "\n").encode("ascii")
    target, parent_before = trusted_target(root, target_text)
    validate_existing(target)

    fd, name = tempfile.mkstemp(prefix=f".{target.name}.all-", dir=target.parent)
    tmp = Path(name)
    committed = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        target_now, parent_now = trusted_target(root, target_text)
        if target_now != target or not os.path.samestat(parent_before, parent_now):
            raise RuntimeError("ALL result parent changed before adoption")
        validate_existing(target)
        os.replace(tmp, target)
        committed = True
        _sync_parent_best_effort(target.parent)
    finally:
        if not committed:
            tmp.unlink(missing_ok=True)


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 4 and argv[1] == "prepare":
            prepare(argv[2], argv[3])
            return 0
        if len(argv) == 5 and argv[1] == "publish":
            publish(argv[2], argv[3], argv[4])
            return 0
        raise RuntimeError("usage: all-result.py prepare ROOT RESULT | publish ROOT RESULT BRANCH")
    except (OSError, RuntimeError) as exc:
        print(f"ALL result error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
