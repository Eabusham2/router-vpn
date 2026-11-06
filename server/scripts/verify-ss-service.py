#!/usr/bin/env python3
"""Read-only upgrade gate for the configured SS service and original client.

An old readiness marker does not establish that this generation carries the
current capability declaration or requested public endpoint. A refusal sends
the finalizer through its existing credential-preserving transport generator.
This check does not establish live service readiness or advertise UoT support.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import runpy
import sys


def main(args: list[str]) -> int:
    if len(args) != 3 or not args[2]:
        raise ValueError("usage: verify-ss-service.py BASE ENDPOINT")
    base, endpoint = Path(args[1]), args[2]
    here = Path(__file__).resolve().parent
    read = runpy.run_path(str(here / "verified-regular-read.py"))["read_verified_regular"]
    capability = runpy.run_path(str(here / "ss_service_capability.py"))

    def private(rel: str) -> bytes:
        return read(base / rel, limit=4 << 20, private=True)

    server = private("config/transports/server.json")
    client = private("client-bundle/generated/shadowsocks/sing-box.json")
    declared = json.loads(private("config/transports/ss-service.json"))
    configured_image = capability["configured_service_image"](
        read(here.parent / "portainer-current.yaml", limit=4 << 20)
    )
    # Match generate-transports.sh's explicit override, including an empty
    # override falling back to the pinned default. Unsupported explicit images
    # can be internally current; capture() separately refuses to grant UoT.
    generator_image = os.environ.get("SING_BOX_IMAGE") or capability["IMAGE"]
    expected = capability["declaration"](server, client, generator_image, configured_image)
    if (not isinstance(declared, dict) or set(declared) != set(expected)
            or type(declared.get("schema")) is not int or declared != expected):
        raise ValueError("configured SS generation is stale")
    if capability["pair"](server, client)["server"] != endpoint:
        raise ValueError("configured SS endpoint is stale")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError):
        # Never echo private JSON, credential values, or decoder exception text.
        print("SS service readiness: current configured sources require regeneration.", file=sys.stderr)
        raise SystemExit(1)
