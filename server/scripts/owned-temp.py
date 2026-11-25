#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import sys
import tempfile

MARKER_NAME = ".router-vpn-owned-temp"
MARKER_VERSION = 2
MARKER_PREFIX = b"router-vpn-owned-temp-v2\n"
MAX_MARKER_BYTES = 256
PACKAGE_CHUNK = 1024 * 1024
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


def mark_owned_temp(path: Path, *, capture_identity=False):
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
    if capture_identity:
        # The original root stat and the nonce just written belong to this allocation.
        nonce = body.decode("ascii").splitlines()[2][6:]
        return path, (os.getpid(), nonce, info.st_dev, info.st_ino)
    return path


def create_owned_temp(prefix: str, *, capture_identity=False):
    if prefix not in ALLOWED_PREFIXES:
        raise RuntimeError(f"unsupported Router VPN temp prefix: {prefix}")
    path = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        return mark_owned_temp(path, capture_identity=capture_identity)
    except Exception:
        shutil.rmtree(path, ignore_errors=True)
        raise


def owned_temp_identity(path: Path) -> tuple[int, str, int, int] | None:
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
    return int(lines[1][4:]), lines[2][6:], before.st_dev, before.st_ino


def package_file_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise RuntimeError("package output is not a nonempty regular file")
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def package_sha256(stream) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(PACKAGE_CHUNK):
        digest.update(chunk)
    return digest.hexdigest()


def verify_package_output(path: Path, identity, progress=None, digest=None):
    if package_file_identity(path.lstat()) != tuple(identity):
        raise RuntimeError("verified package changed before adoption")
    receive = getattr(progress, "verified_output", None)
    if receive is not None:
        if not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest):
            raise RuntimeError("package producer omitted its verified SHA-256")
        receive(path, identity, digest)


def workspace_child_environment(path: Path, progress):
    current = owned_temp_identity(path)
    if (current is None or current[0] != os.getpid() or
            current != getattr(progress, "work_identity", current)):
        raise RuntimeError("original broker workspace changed before worker start")
    return {**os.environ, "ROUTER_VPN_JOB_WORKSPACE_IDENTITY": json.dumps(current)}


def require_parent_workspace(path: Path):
    current = owned_temp_identity(path)
    expected = json.loads(os.environ.pop("ROUTER_VPN_JOB_WORKSPACE_IDENTITY", "null"))
    if current is None or current[0] != os.getppid() or list(current) != expected:
        raise RuntimeError("package worker lost its original parent broker workspace")


def owned_temp_owner_pid(path: Path) -> int | None:
    identity = owned_temp_identity(Path(path))
    return identity[0] if identity else None


def is_owned_temp(path: Path) -> bool:
    return owned_temp_identity(Path(path)) is not None


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


def cleanup_owned_temp(path: Path, expected=None) -> bool:
    path = Path(path)
    identity = owned_temp_identity(path)
    if identity is None or (expected is not None and identity != expected):
        return False
    owner_pid, nonce, _, _ = identity
    current_pid = os.getpid()
    if owner_pid != current_pid and _pid_alive(owner_pid):
        # A second Setup Center process must never erase another live broker's
        # active request/job/package workspace merely because the name matches.
        return False

    # Re-prove the exact marker/root immediately before destructive cleanup.
    if owned_temp_identity(path) != identity:
        return False
    if os.name == "posix" and shutil.rmtree.avoids_symlink_attacks and sys.version_info >= (3, 11):
        # Preserve the ownership marker while deleting potentially large trees.
        # A failed compiler-cache removal can then be retried by this process or
        # the broker's dead-owner recovery without authorizing a different root.
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            original = os.fstat(fd)
            if not os.path.samestat(original, path.lstat()) or owned_temp_identity(path) != identity:
                return False
            for name in os.listdir(fd):
                if name == MARKER_NAME:
                    continue
                try:
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        shutil.rmtree(name, dir_fd=fd)
                    else:
                        os.unlink(name, dir_fd=fd)
                except FileNotFoundError:
                    continue
            if not os.path.samestat(original, path.lstat()) or owned_temp_identity(path) != identity:
                return False
            os.unlink(MARKER_NAME, dir_fd=fd)
            try:
                os.rmdir(path)
            except OSError:
                # Write back the original identity only through the retained
                # directory fd. Never follow a replaced pathname or marker.
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                marker = os.open(MARKER_NAME, flags, 0o600, dir_fd=fd)
                with os.fdopen(marker, "wb") as target:
                    target.write(MARKER_PREFIX + f"pid={owner_pid}\nnonce={nonce}\n".encode("ascii"))
                raise
        finally:
            os.close(fd)
    else:
        shutil.rmtree(path)
    return True
