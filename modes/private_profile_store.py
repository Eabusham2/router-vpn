#!/usr/bin/env python3
"""Strict read-only access to controller-owned Router VPN profile state."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Any

MAX_PROFILE_STORE_BYTES = 4 << 20


def _validate_existing_ancestors(path: Path) -> None:
    current = path.parent
    while True:
        try:
            info = current.lstat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise RuntimeError(f"refusing non-directory/symlink private profile path component: {current}")
        parent = current.parent
        if parent == current:
            break
        current = parent


def private_root(raw: str) -> Path:
    root = Path(os.path.abspath(os.path.expanduser(raw)))
    _validate_existing_ancestors(root / ".profile-root-check")
    try:
        info = root.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"Router VPN private root is missing: {root}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"Router VPN private root is not a real directory: {root}")
    return root


def read_private_bytes(path: Path, limit: int = MAX_PROFILE_STORE_BYTES) -> bytes:
    if limit <= 0 or limit > MAX_PROFILE_STORE_BYTES:
        limit = MAX_PROFILE_STORE_BYTES
    _validate_existing_ancestors(path)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink private profile store: {path}")
    if before.st_size < 0 or before.st_size > limit:
        raise RuntimeError(f"private profile store exceeds safety limit: {path}")
    if os.name != "nt" and before.st_mode & 0o077:
        raise RuntimeError(f"private profile store must be mode 0600: {path}")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        current = path.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(opened, current)
        ):
            raise RuntimeError(f"private profile store changed during open: {path}")
        body = stream.read(limit + 1)
    if len(body) > limit:
        raise RuntimeError(f"private profile store exceeds safety limit: {path}")
    return body


def read_private_json(path: Path, limit: int = MAX_PROFILE_STORE_BYTES) -> Any:
    try:
        value = json.loads(read_private_bytes(path, limit).decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError) as exc:
        raise RuntimeError(f"cannot safely read private Router VPN state {path}: {exc}") from exc
    return value


def read_profile_store(root: Path) -> dict[str, Any]:
    value = read_private_json(root / "routers.json")
    if not isinstance(value, dict) or not isinstance(value.get("profiles"), list):
        raise RuntimeError("routers.json must contain a profile-store object")
    return value
