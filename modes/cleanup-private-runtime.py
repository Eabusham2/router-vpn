#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat
import sys

ALLOWED_ROOTS = {"multihop", "native-multihop"}
DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def lexical(path_value: str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(path_value)))


def require_directory(path: Path, label: str) -> os.stat_result:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink {label}: {path}")
    return info


def open_directory(path: Path, expected: os.stat_result, label: str) -> int:
    fd = os.open(path, DIR_FLAGS)
    opened = os.fstat(fd)
    current = path.lstat()
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or not os.path.samestat(opened, current)
        or not os.path.samestat(expected, current)
    ):
        os.close(fd)
        raise RuntimeError(f"{label} changed during open: {path}")
    return fd


def remove_tree_at(parent_fd: int, name: str) -> None:
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        os.unlink(name, dir_fd=parent_fd)
        return

    fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    try:
        opened = os.fstat(fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or not os.path.samestat(opened, current)
            or not os.path.samestat(info, current)
        ):
            raise RuntimeError("private runtime quarantine changed during open")
        for entry in list(os.scandir(fd)):
            child = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(child.st_mode) and not stat.S_ISLNK(child.st_mode):
                remove_tree_at(fd, entry.name)
            else:
                os.unlink(entry.name, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent_fd)


def quarantine_name(run_fd: int) -> str:
    for _ in range(32):
        name = ".router-vpn-cleanup-" + secrets.token_hex(16)
        try:
            os.stat(name, dir_fd=run_fd, follow_symlinks=False)
        except FileNotFoundError:
            return name
    raise RuntimeError("could not reserve private runtime cleanup quarantine name")


def verify_directory(root_value: str, target_value: str) -> Path:
    root = lexical(root_value)
    require_directory(root, "Router VPN root")
    run_root = root / "run"
    run_info = require_directory(run_root, "Router VPN run directory")
    target = lexical(target_value)
    try:
        rel = target.relative_to(run_root)
    except ValueError as exc:
        raise RuntimeError("refusing runtime directory outside HOMEVPN_ROOT/run") from exc
    if not rel.parts or rel.parts[0] not in ALLOWED_ROOTS or len(rel.parts) > 2:
        raise RuntimeError("refusing unrelated/deep private runtime directory")

    run_fd = open_directory(run_root, run_info, "Router VPN run directory")
    parent_fd: int | None = None
    try:
        if len(rel.parts) == 1:
            parent_fd = run_fd
            leaf = rel.parts[0]
        else:
            parent_name, leaf = rel.parts
            parent_info = os.stat(parent_name, dir_fd=run_fd, follow_symlinks=False)
            if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
                raise RuntimeError("refusing non-directory/symlink private runtime parent")
            parent_fd = os.open(parent_name, DIR_FLAGS, dir_fd=run_fd)
            opened_parent = os.fstat(parent_fd)
            current_parent = os.stat(parent_name, dir_fd=run_fd, follow_symlinks=False)
            if (
                stat.S_ISLNK(current_parent.st_mode)
                or not stat.S_ISDIR(current_parent.st_mode)
                or not os.path.samestat(opened_parent, current_parent)
                or not os.path.samestat(parent_info, current_parent)
            ):
                raise RuntimeError("private runtime parent changed during open")

        info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("refusing non-directory/symlink private runtime directory")
        fd = os.open(leaf, DIR_FLAGS, dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if (
                stat.S_ISLNK(current.st_mode)
                or not stat.S_ISDIR(current.st_mode)
                or not os.path.samestat(opened, current)
                or not os.path.samestat(info, current)
            ):
                raise RuntimeError("private runtime directory changed during open")
        finally:
            os.close(fd)
        return target
    finally:
        if parent_fd is not None and parent_fd != run_fd:
            os.close(parent_fd)
        os.close(run_fd)


def cleanup(root_value: str, target_value: str) -> None:
    root = lexical(root_value)
    require_directory(root, "Router VPN root")
    run_root = root / "run"
    target = lexical(target_value)
    try:
        rel = target.relative_to(run_root)
    except ValueError as exc:
        raise RuntimeError("refusing cleanup outside HOMEVPN_ROOT/run") from exc
    if not rel.parts or rel.parts[0] not in ALLOWED_ROOTS:
        raise RuntimeError("refusing cleanup of unrelated runtime path")
    if len(rel.parts) > 2:
        raise RuntimeError("refusing unexpectedly deep runtime cleanup path")

    try:
        run_info = require_directory(run_root, "Router VPN run directory")
    except FileNotFoundError:
        # First launch may not have created run/ yet. With a lexically confined
        # target there is then nothing to clean.
        return
    run_fd = open_directory(run_root, run_info, "Router VPN run directory")
    parent_fd: int | None = None
    try:
        if len(rel.parts) == 1:
            parent_fd = run_fd
            leaf = rel.parts[0]
        else:
            parent_name, leaf = rel.parts
            parent_info = os.stat(parent_name, dir_fd=run_fd, follow_symlinks=False)
            if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
                raise RuntimeError("refusing non-directory/symlink private runtime parent")
            parent_fd = os.open(parent_name, DIR_FLAGS, dir_fd=run_fd)
            opened = os.fstat(parent_fd)
            current = os.stat(parent_name, dir_fd=run_fd, follow_symlinks=False)
            if (
                stat.S_ISLNK(current.st_mode)
                or not stat.S_ISDIR(current.st_mode)
                or not os.path.samestat(opened, current)
                or not os.path.samestat(parent_info, current)
            ):
                raise RuntimeError("private runtime parent changed during open")

        try:
            os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return

        quarantine = quarantine_name(run_fd)
        # Rename through already-open parent/run directory descriptors. A leaf
        # swap can therefore only change which object at this owned path is moved;
        # it cannot redirect the operation through a symlinked ancestor.
        os.rename(leaf, quarantine, src_dir_fd=parent_fd, dst_dir_fd=run_fd)
        try:
            remove_tree_at(run_fd, quarantine)
        except Exception as exc:
            raise RuntimeError(f"private runtime quarantined but cleanup failed: {exc}") from exc
    finally:
        if parent_fd is not None and parent_fd != run_fd:
            os.close(parent_fd)
        os.close(run_fd)


def main() -> int:
    root = os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client")
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "verify-dir":
            print(verify_directory(root, sys.argv[2]))
            return 0
        if len(sys.argv) != 2:
            print("usage: cleanup-private-runtime.py [verify-dir] RUNTIME_DIR", file=sys.stderr)
            return 2
        cleanup(root, sys.argv[1])
        return 0
    except Exception as exc:
        print(f"private runtime cleanup failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
