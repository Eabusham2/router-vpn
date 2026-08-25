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


def ensure_token(base: Path) -> Path:
    config = base / "config"
    config.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = config / "setup-center.token"
    helper = Path(__file__).with_name("atomic-private-write.py")

    try:
        info = path.lstat()
    except FileNotFoundError:
        info = None

    if info is not None:
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"refusing non-regular/symlink Setup Center token: {path}")
        if info.st_size <= 0 or info.st_size > MAX_TOKEN_BYTES:
            raise RuntimeError("existing Setup Center token is empty or oversized; refusing silent rotation")
        # Older installs may predate the strict private-mode contract. Harden the
        # same regular file before reading it; never rotate a valid preserved token.
        if info.st_mode & 0o077:
            os.chmod(path, 0o600)
        token = path.read_text(encoding="utf-8").strip()
        if len(token) < MIN_TOKEN_LEN or any(ch.isspace() for ch in token):
            raise RuntimeError("existing Setup Center token is corrupt; refusing silent rotation")
        return path

    token = secrets.token_urlsafe(32)
    subprocess.run(
        [sys.executable, str(helper), str(path)],
        input=(token + "\n").encode("utf-8"),
        check=True,
    )
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
