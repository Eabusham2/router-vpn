#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat
import sys
import tempfile

ALLOWED = {"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"}
MAX_BYTES = 64
PRIVATE_MODE = 0o600


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


def validate_existing(target: Path) -> os.stat_result | None:
    try:
        info = target.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink ALL result target: {target}")
    if info.st_size < 0 or info.st_size > MAX_BYTES:
        raise RuntimeError(f"ALL result target exceeds safety limit: {target}")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) != PRIVATE_MODE:
        raise RuntimeError(f"ALL result target must be private 0600: {target}")
    return info


def require_target_state(target: Path, expected: os.stat_result | None, label: str) -> None:
    try:
        current = target.lstat()
    except FileNotFoundError:
        current = None
    if expected is None:
        if current is not None:
            raise RuntimeError(f"{label} appeared before adoption: {target}")
        return
    if current is None:
        raise RuntimeError(f"{label} disappeared before adoption: {target}")
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or (os.name != "nt" and stat.S_IMODE(current.st_mode) != PRIVATE_MODE)
        or not os.path.samestat(expected, current)
    ):
        raise RuntimeError(f"{label} identity changed before adoption: {target}")


def require_parent_state(root: str, target_text: str, target: Path, expected: os.stat_result, label: str) -> None:
    target_now, parent_now = trusted_target(root, target_text)
    if target_now != target or not os.path.samestat(expected, parent_now):
        raise RuntimeError(f"{label} parent changed during transaction")


def _sync_parent_best_effort(parent: Path) -> None:
    try:
        dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def _owned_tombstone(target: Path) -> Path:
    for _ in range(16):
        candidate = target.parent / f".{target.name}.stale-{secrets.token_hex(16)}"
        if not candidate.exists() and not candidate.is_symlink():
            return candidate
    raise RuntimeError("could not allocate a private ALL result tombstone")


def prepare(root: str, target_text: str) -> None:
    target, parent_before = trusted_target(root, target_text)
    expected = validate_existing(target)
    require_parent_state(root, target_text, target, parent_before, "ALL result")
    require_target_state(target, expected, "ALL result target")
    if expected is None:
        return

    # Move the exact snapshotted inode to a random same-directory tombstone
    # before deleting it. If another actor replaced the target after the
    # snapshot, verification fails without unlinking the foreign bytes.
    tombstone = _owned_tombstone(target)
    os.rename(target, tombstone)
    try:
        moved = validate_existing(tombstone)
        if moved is None or not os.path.samestat(expected, moved):
            try:
                if validate_existing(target) is None:
                    os.rename(tombstone, target)
            except OSError:
                pass
            raise RuntimeError("ALL result target identity changed during stale-result cleanup")
        require_parent_state(root, target_text, target, parent_before, "ALL result")
        tombstone.unlink()
        _sync_parent_best_effort(target.parent)
    finally:
        # A verified stale Router VPN result may be removed. An unverified
        # foreign tombstone is intentionally retained rather than erased.
        try:
            moved = validate_existing(tombstone)
        except RuntimeError:
            moved = None
        if moved is not None and os.path.samestat(expected, moved):
            tombstone.unlink(missing_ok=True)


def publish(root: str, target_text: str, value: str) -> None:
    value = value.strip()
    if value not in ALLOWED:
        raise RuntimeError(f"refusing unknown ALL runtime branch: {value!r}")
    body = (value + "\n").encode("ascii")
    target, parent_before = trusted_target(root, target_text)
    expected = validate_existing(target)

    fd, name = tempfile.mkstemp(prefix=f".{target.name}.all-", dir=target.parent)
    tmp = Path(name)
    adopted = False
    try:
        os.fchmod(fd, PRIVATE_MODE)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        staged = tmp.lstat()
        if (
            stat.S_ISLNK(staged.st_mode)
            or not stat.S_ISREG(staged.st_mode)
            or (os.name != "nt" and stat.S_IMODE(staged.st_mode) != PRIVATE_MODE)
        ):
            raise RuntimeError(f"staged ALL result is unsafe: {tmp}")

        require_parent_state(root, target_text, target, parent_before, "ALL result")
        require_target_state(target, expected, "ALL result target")
        os.replace(tmp, target)
        adopted = True

        current = validate_existing(target)
        if current is None or not os.path.samestat(staged, current):
            raise RuntimeError("adopted ALL result identity changed before verification")
        require_parent_state(root, target_text, target, parent_before, "ALL result")
        _sync_parent_best_effort(target.parent)
    finally:
        if not adopted:
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
