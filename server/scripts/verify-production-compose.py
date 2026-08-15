#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path

SHA = r"[0-9a-f]{40}"
HEADER_RE = re.compile(rf"^# GENERATED exact-SHA Router VPN production compose: ({SHA})$", re.M)
BROKER_RE = re.compile(rf"(?m)^\s*ROUTER_VPN_GITHUB_SHA:\s*({SHA})\s*$")
IMAGE_RE = re.compile(rf"ghcr\.io/eabusham2/router-vpn-(init|agent|wireguard|awg2|rosenpass|naive|ss-v2ray|aux):({SHA})")
EXPECTED = {
    "init": 3,
    "agent": 1,
    "wireguard": 1,
    "awg2": 1,
    "rosenpass": 1,
    "naive": 1,
    "ss-v2ray": 1,
    "aux": 1,
}


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def verify(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    if re.search(r"(?m)^\s*build:\s*$", text):
        fail("production release compose contains build:")
    if re.search(r"(?m)^\s*context:\s*https?://", text):
        fail("production release compose contains a remote Git build context")
    if re.search(r"ghcr\.io/eabusham2/router-vpn-[^\s:]+:(?:latest|main|arm64-main)\b", text):
        fail("production release compose contains a moving Router VPN image tag")

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
