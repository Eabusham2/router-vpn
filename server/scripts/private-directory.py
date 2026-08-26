#!/usr/bin/env python3
"""Create/validate a private directory without following symlinked path components."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys


def validate_existing_ancestors(path: Path) -> None:
    current = path
    while True:
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise RuntimeError(f"refusing non-directory/symlink private directory path component: {current}")
        parent = current.parent
        if parent == current:
            break
        current = parent


def ensure_private_directory(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    validate_existing_ancestors(path)
    os.makedirs(path, mode=0o700, exist_ok=True)
    validate_existing_ancestors(path)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"private directory is not a real directory: {path}")
    os.chmod(path, 0o700)
    validate_existing_ancestors(path)
    return path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        raise SystemExit("usage: private-directory.py PATH")
    try:
        ensure_private_directory(Path(argv[1]))
    except (OSError, RuntimeError) as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
