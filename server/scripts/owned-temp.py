#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import tempfile

MARKER_NAME = ".router-vpn-owned-temp"
MARKER_BODY = b"router-vpn-owned-temp-v1\n"
ALLOWED_PREFIXES = (
    "router-vpn-request-",
    "router-vpn-job-",
    "router-vpn-one-package-",
)


def _owned_uid(info: os.stat_result) -> bool:
    if os.name == "nt" or not hasattr(os, "geteuid"):
        return True
    return info.st_uid == os.geteuid()


def _valid_name(path: Path) -> bool:
    return any(path.name.startswith(prefix) for prefix in ALLOWED_PREFIXES)


def mark_owned_temp(path: Path) -> Path:
    path = Path(path)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink Router VPN temp root: {path}")
    if not _owned_uid(info):
        raise RuntimeError(f"Router VPN temp root is not owned by this process uid: {path}")
    if not _valid_name(path):
        raise RuntimeError(f"refusing unexpected Router VPN temp-root name: {path}")
    os.chmod(path, 0o700)
    marker = path / MARKER_NAME
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(marker, flags, 0o600)
    try:
        view = memoryview(MARKER_BODY)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        directory = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        pass
    return path


def create_owned_temp(prefix: str) -> Path:
    if prefix not in ALLOWED_PREFIXES:
        raise RuntimeError(f"unsupported Router VPN temp prefix: {prefix}")
    path = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        return mark_owned_temp(path)
    except Exception:
        shutil.rmtree(path, ignore_errors=True)
        raise


def is_owned_temp(path: Path) -> bool:
    path = Path(path)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return False
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISDIR(before.st_mode)
        or not _owned_uid(before)
        or not _valid_name(path)
        or (os.name != "nt" and stat.S_IMODE(before.st_mode) & 0o077)
    ):
        return False

    marker = path / MARKER_NAME
    try:
        marker_before = marker.lstat()
    except FileNotFoundError:
        return False
    if (
        stat.S_ISLNK(marker_before.st_mode)
        or not stat.S_ISREG(marker_before.st_mode)
        or not _owned_uid(marker_before)
        or (os.name != "nt" and stat.S_IMODE(marker_before.st_mode) != 0o600)
        or marker_before.st_size != len(MARKER_BODY)
    ):
        return False

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(marker, flags)
    except OSError:
        return False
    try:
        opened = os.fstat(fd)
        body = b""
        while len(body) <= len(MARKER_BODY):
            chunk = os.read(fd, len(MARKER_BODY) + 1 - len(body))
            if not chunk:
                break
            body += chunk
    finally:
        os.close(fd)
    try:
        marker_after = marker.lstat()
        after = path.lstat()
    except FileNotFoundError:
        return False
    return (
        body == MARKER_BODY
        and os.path.samestat(opened, marker_before)
        and os.path.samestat(opened, marker_after)
        and not stat.S_ISLNK(after.st_mode)
        and stat.S_ISDIR(after.st_mode)
        and os.path.samestat(before, after)
    )


def cleanup_owned_temp(path: Path) -> bool:
    path = Path(path)
    if not is_owned_temp(path):
        return False
    shutil.rmtree(path)
    return True
