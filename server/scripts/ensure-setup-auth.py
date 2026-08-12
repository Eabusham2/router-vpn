#!/usr/bin/env python3
"""Create/preserve the Setup Center access token outside all client bundles."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets


def ensure_token(base: Path) -> Path:
    config = base / "config"
    config.mkdir(parents=True, exist_ok=True)
    path = config / "setup-center.token"
    token = ""
    if path.is_file():
        token = path.read_text(encoding="utf-8").strip()
    if len(token) < 32:
        token = secrets.token_urlsafe(32)
        tmp = path.with_suffix(".token.tmp")
        tmp.write_text(token + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(path)
    os.chmod(path, 0o600)
    return path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base", nargs="?", default="/opt/router-vpn")
    args = ap.parse_args()
    path = ensure_token(Path(args.base).resolve())
    # Never print the token itself: this helper is safe to call from init/finalizer
    # without leaking credentials into Docker/Portainer logs.
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
