#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import tempfile

MARKER_NAME = ".router-vpn-owned-temp"
MARKER_VERSION = 2
MARKER_PREFIX = b"router-vpn-owned-temp-v2\n"
MAX_MARKER_BYTES = 256
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


def _marker_body(pid: int) -> bytes:
    if pid <= 0:
        raise RuntimeError("invalid Router VPN temp owner pid")
    nonce = secrets.token_hex(24)
    return MARKER_PREFIX + f"pid={pid}\nnonce={nonce}\n".encode("ascii")


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
        body = _marker_body(os.getpid())
        view = memoryview(body)
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


def _owned_temp_identity(path: Path) -> tuple[int, str] | None:
    path = Path(path)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISDIR(before.st_mode)
        or not _owned_uid(before)
        or not _valid_name(path)
        or (os.name != "nt" and stat.S_IMODE(before.st_mode) & 0o077)
    ):
        return None

    marker = path / MARKER_NAME
    try:
        marker_before = marker.lstat()
    except FileNotFoundError:
        return None
    if (
        stat.S_ISLNK(marker_before.st_mode)
        or not stat.S_ISREG(marker_before.st_mode)
        or not _owned_uid(marker_before)
        or (os.name != "nt" and stat.S_IMODE(marker_before.st_mode) != 0o600)
        or marker_before.st_size <= len(MARKER_PREFIX)
        or marker_before.st_size > MAX_MARKER_BYTES
    ):
        return None

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(marker, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(fd)
        body = b""
        while len(body) <= MAX_MARKER_BYTES:
            chunk = os.read(fd, MAX_MARKER_BYTES + 1 - len(body))
            if not chunk:
                break
            body += chunk
    finally:
        os.close(fd)
    if len(body) > MAX_MARKER_BYTES:
        return None
    try:
        marker_after = marker.lstat()
        after = path.lstat()
    except FileNotFoundError:
        return None
    if not (
        os.path.samestat(opened, marker_before)
        and os.path.samestat(opened, marker_after)
        and not stat.S_ISLNK(after.st_mode)
        and stat.S_ISDIR(after.st_mode)
        and os.path.samestat(before, after)
    ):
        return None

    try:
        text = body.decode("ascii")
    except UnicodeDecodeError:
        return None
    lines = text.splitlines()
    if len(lines) != 3 or lines[0] != "router-vpn-owned-temp-v2":
        return None
    if not re.fullmatch(r"pid=[1-9][0-9]*", lines[1]):
        return None
    if not re.fullmatch(r"nonce=[0-9a-f]{48}", lines[2]):
        return None
    return int(lines[1][4:]), lines[2][6:]


def owned_temp_owner_pid(path: Path) -> int | None:
    identity = _owned_temp_identity(Path(path))
    return identity[0] if identity else None


def is_owned_temp(path: Path) -> bool:
    return _owned_temp_identity(Path(path)) is not None


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        # Unknown platform/process state is treated as live so cleanup fails
        # safe by leaking a temp directory instead of disrupting another owner.
        return True
    return True


def cleanup_owned_temp(path: Path) -> bool:
    path = Path(path)
    identity = _owned_temp_identity(path)
    if identity is None:
        return False
    owner_pid, _nonce = identity
    current_pid = os.getpid()
    if owner_pid != current_pid and _pid_alive(owner_pid):
        # A second Setup Center process must never erase another live broker's
        # active request/job/package workspace merely because the name matches.
        return False

    # Re-prove the exact marker/root immediately before destructive cleanup.
    if _owned_temp_identity(path) != identity:
        return False
    shutil.rmtree(path)
    return True
