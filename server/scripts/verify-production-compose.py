#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import stat
from pathlib import Path

SHA = r"[0-9a-f]{40}"
HEADER_RE = re.compile(rf"^# GENERATED exact-SHA Router VPN production compose: ({SHA})$", re.M)
BROKER_RE = re.compile(rf"(?m)^\s*ROUTER_VPN_GITHUB_SHA:\s*({SHA})\s*$")
IMAGE_RE = re.compile(rf"ghcr\.io/eabusham2/router-vpn-(init|agent|wireguard|awg2|rosenpass|naive|ss-v2ray|aux|updater):({SHA})")
EXPECTED = {
    "init": 3,
    "agent": 1,
    "wireguard": 1,
    "awg2": 1,
    "rosenpass": 1,
    "naive": 1,
    "ss-v2ray": 1,
    "aux": 1,
    "updater": 1,
}

MAX_COMPOSE_BYTES = 4 << 20


def _read_compose(path: Path) -> str:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        fail("production release compose is redirected or not a regular file")
    if before.st_size <= 0 or before.st_size > MAX_COMPOSE_BYTES:
        fail("production release compose size is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(before, opened)
            or not os.path.samestat(opened, current)
        ):
            fail("production release compose changed identity during open")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_COMPOSE_BYTES + 1)
    finally:
        os.close(fd)
    if not raw or len(raw) > MAX_COMPOSE_BYTES:
        fail("production release compose size is invalid")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("production release compose is not UTF-8") from exc


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def verify(path: Path) -> str:
    text = _read_compose(path)
    if re.search(r"(?m)^\s*build:\s*$", text):
        fail("production release compose contains build:")
    if re.search(r"(?m)^\s*context:\s*https?://", text):
        fail("production release compose contains a remote Git build context")
    if re.search(r"ghcr\.io/eabusham2/router-vpn-[^\s:]+:(?:latest|main|arm64-main)\b", text):
        fail("production release compose contains a moving Router VPN image tag")
    if "/var/run/docker.sock" in text:
        fail("production release compose must not grant Docker socket access")

    header = HEADER_RE.search(text)
    if not header:
        fail("not a generated exact-SHA Router VPN production compose")
    target = header.group(1)

    counts = {name: 0 for name in EXPECTED}
    shas: set[str] = set()
    for name, sha in IMAGE_RE.findall(text):
        counts[name] += 1
        shas.add(sha)
    if counts != EXPECTED:
        fail(f"unexpected Router VPN custom-image reference counts: {counts}")
    if shas != {target}:
        fail(f"Router VPN custom image SHAs do not equal generated release SHA {target}: {sorted(shas)}")

    brokers = BROKER_RE.findall(text)
    if brokers != [target]:
        fail(f"ROUTER_VPN_GITHUB_SHA does not equal generated release SHA {target}")
    if "ROUTER_VPN_UPDATE_LISTEN: 127.0.0.1:8793" not in text:
        fail("update controller is not pinned to loopback")
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify one generated exact-SHA Router VPN production compose.")
    parser.add_argument("compose")
    args = parser.parse_args()
    path = Path(args.compose)
    if not path.is_file():
        fail(f"production release compose not found: {path}")
    print(verify(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
