#!/usr/bin/env python3
"""Create/preserve the Setup Center access token outside all client bundles."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

MIN_TOKEN_LEN = 32
MAX_TOKEN_BYTES = 4096
PRIVATE_MODE = 0o600


def ensure_private_config_dir(config: Path) -> None:
    try:
        info = config.lstat()
    except FileNotFoundError:
        config.mkdir(parents=True, exist_ok=False, mode=0o700)
        info = config.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink Setup Center config parent: {config}")


def read_preserved_token(path: Path) -> str:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink Setup Center token: {path}")
    if info.st_size <= 0 or info.st_size > MAX_TOKEN_BYTES:
        raise RuntimeError("existing Setup Center token is empty or oversized; refusing silent rotation")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError("existing Setup Center token changed during open; refusing silent rotation")

        # Older installs may predate the strict private-mode contract. Harden the
        # already-open verified inode, not the pathname, before consuming it.
        if opened.st_mode & 0o077:
            os.fchmod(fd, PRIVATE_MODE)
            opened = os.fstat(fd)
        if opened.st_mode & 0o777 != PRIVATE_MODE:
            raise RuntimeError("existing Setup Center token could not be hardened to mode 0600")

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024, MAX_TOKEN_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_TOKEN_BYTES:
                raise RuntimeError("existing Setup Center token is oversized; refusing silent rotation")
        try:
            token = b"".join(chunks).decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise RuntimeError("existing Setup Center token is not UTF-8; refusing silent rotation") from exc

        # Re-prove that the path still names the exact inode we consumed.
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError("existing Setup Center token changed during read; refusing silent rotation")
        if len(token) < MIN_TOKEN_LEN or any(ch.isspace() for ch in token):
            raise RuntimeError("existing Setup Center token is corrupt; refusing silent rotation")
        return token
    finally:
        os.close(fd)


def ensure_token(base: Path) -> Path:
    config = base / "config"
    ensure_private_config_dir(config)
    path = config / "setup-center.token"
    helper = Path(__file__).with_name("atomic-private-write.py")

    try:
        read_preserved_token(path)
        return path
    except FileNotFoundError:
        pass

    token = secrets.token_urlsafe(32)
    subprocess.run(
        [sys.executable, str(helper), str(path)],
        input=(token + "\n").encode("utf-8"),
        check=True,
    )
    # The private publisher is the commit point, but immediately re-read the
    # newly-created token through the same strict boundary before returning.
    if read_preserved_token(path) != token:
        raise RuntimeError("new Setup Center token failed post-publication verification")
    return path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base", nargs="?", default="/opt/router-vpn")
    args = ap.parse_args()
    try:
        path = ensure_token(Path(args.base).resolve())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        raise SystemExit(str(exc)) from exc
    # Never print the token itself: this helper is safe to call from init/finalizer
    # without leaking credentials into Docker/Portainer logs.
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
