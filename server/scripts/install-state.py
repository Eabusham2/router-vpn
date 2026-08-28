#!/usr/bin/env python3
"""Classify Router VPN host install state without following redirected private files."""
from __future__ import annotations

from pathlib import Path
import runpy
import sys

HERE = Path(__file__).resolve().parent
reader = runpy.run_path(str(HERE / "verified-regular-read.py"))
read_verified_regular = reader["read_verified_regular"]


def lexical_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def classify(base: Path) -> str:
    base = Path(base)
    env_path = base / ".env"
    marker_path = base / ".initialized"
    env_exists = lexical_exists(env_path)
    marker_exists = lexical_exists(marker_path)
    if not env_exists and not marker_exists:
        return "absent"
    if not env_exists or not marker_exists:
        raise RuntimeError("partial Router VPN install state: .env and .initialized must exist together")

    env_body = read_verified_regular(env_path, 256 << 10, private=True)
    marker = read_verified_regular(marker_path, 4096, private=True).decode("utf-8", "strict").strip()
    if marker != "initialized":
        raise RuntimeError("invalid Router VPN initialization marker")

    try:
        env_text = env_body.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise RuntimeError("Router VPN .env is not UTF-8") from exc
    if "\x00" in env_text:
        raise RuntimeError("Router VPN .env contains NUL")
    required = ("WAN_INTERFACE=", "LAN_CIDR=", "ADGUARD4=")
    missing = [name for name in required if not any(line.startswith(name) for line in env_text.splitlines())]
    if missing:
        raise RuntimeError("Router VPN .env is missing required keys: " + ", ".join(missing))
    return "complete"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: install-state.py BASE", file=sys.stderr)
        return 2
    try:
        state = classify(Path(argv[1]))
    except (OSError, RuntimeError, UnicodeError) as exc:
        print(f"unsafe Router VPN install state: {exc}", file=sys.stderr)
        return 4
    if state == "absent":
        return 3
    print("complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
