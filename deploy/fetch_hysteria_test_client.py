#!/usr/bin/env python3
"""Fetch a checksum-pinned, unchanged official Hysteria interoperability client."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import urllib.request

VERSION = "2.13.0"
COMMIT = "ca8fbd874fd6ca82413948de6dc5924405e103e1"
PINS = {
    "amd64": ("907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691", 62),
    "arm64": ("a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7", 183),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=tuple(PINS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    expected, machine = PINS[args.arch]
    url = ("https://github.com/HyNetworks/hysteria/releases/download/app/v" + VERSION
           + "/hysteria-linux-" + args.arch)
    with urllib.request.urlopen(url, timeout=60) as response:
        binary = response.read((32 << 20) + 1)
    if not 64 <= len(binary) <= 32 << 20 or hashlib.sha256(binary).hexdigest() != expected:
        raise RuntimeError("official Hysteria binary differs from its pinned SHA256")
    if binary[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", binary, 18)[0] != machine:
        raise RuntimeError("official Hysteria client has the wrong format/architecture")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as stream:
        stream.write(binary)
    args.output.chmod(0o755)
    receipt = {"schema": 1, "version": VERSION, "architecture": args.arch, "binary_url": url,
               "binary_sha256": expected, "release_tag_commit": COMMIT, "upstream_modified": False}
    with args.output.with_suffix(".json").open("x") as stream:
        json.dump(receipt, stream, sort_keys=True)
        stream.write("\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
