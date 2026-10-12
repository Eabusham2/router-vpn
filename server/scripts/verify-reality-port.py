#!/usr/bin/env python3
"""Read-only gate: prove standard/PQ REALITY server and client ports match.

Existing credentials and marker files alone do not prove readiness when the
operator explicitly migrates REALITY off TCP 443. Do not print private data.
"""
from __future__ import annotations

import json
from pathlib import Path
import runpy
import sys


def main(args: list[str]) -> int:
    if len(args) != 4:
        raise ValueError("usage: verify-reality-port.py BASE STANDARD_PORT PQ_PORT")
    base = Path(args[1])
    standard, pq = int(args[2]), int(args[3])
    if not (1 <= standard <= 65535 and 1 <= pq <= 65535):
        raise ValueError("invalid REALITY listener port")
    verified_read = runpy.run_path(
        str(Path(__file__).with_name("verified-regular-read.py"))
    )["read_verified_regular"]

    def load(rel: str) -> dict:
        value = json.loads(verified_read(base / rel, private=True).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("expected JSON object: " + rel)
        return value

    inbounds = load("config/xray/server.json").get("inbounds") or []

    def inbound_port(tag: str) -> int:
        found = [item for item in inbounds
                 if isinstance(item, dict) and item.get("tag") == tag]
        if len(found) != 1:
            raise ValueError("expected exactly one inbound with tag " + tag)
        return found[0].get("port")

    def client_port(rel: str) -> int:
        outbounds = load(rel).get("outbounds") or []
        proxies = [item for item in outbounds
                   if isinstance(item, dict) and item.get("tag") == "proxy"]
        if len(proxies) != 1:
            raise ValueError("expected one outbound proxy in " + rel)
        nodes = (proxies[0].get("settings") or {}).get("vnext") or []
        if len(nodes) != 1 or not isinstance(nodes[0], dict):
            raise ValueError("malformed REALITY endpoint in " + rel)
        return nodes[0].get("port")

    actual = (
        inbound_port("reality-in"),
        inbound_port("pq-reality-in"),
        client_port("client-bundle/generated/reality-vision/xray.json"),
        client_port("client-bundle/generated/reality-pq-vision/xray.json"),
    )
    if actual != (standard, pq, standard, pq):
        raise ValueError(
            "REALITY server/client port drift; credential-preserving "
            "regeneration is required"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
        print("REALITY port readiness: " + str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
