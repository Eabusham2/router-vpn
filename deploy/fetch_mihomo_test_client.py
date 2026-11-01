#!/usr/bin/env python3
"""Fetch one checksum-pinned, unchanged official client for the isolated gate."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import urllib.request

VERSION = "1.19.33"
PINS = {
    "amd64": ("mihomo-linux-amd64-v1-v1.19.33.gz", "8ec92e7b2fdc6b853ba00156bab7e4e965c8b0d843b8c4ac8ab98795f02ad524", 62),
    "arm64": ("mihomo-linux-arm64-v1.19.33.gz", "ba408b317080ee265c46cb923a50018c1b82cbd708551cdd46a1e3e307396187", 183),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=tuple(PINS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    name, expected, machine = PINS[args.arch]
    url = "https://github.com/MetaCubeX/mihomo/releases/download/v" + VERSION + "/" + name
    with urllib.request.urlopen(url, timeout=60) as response:
        raw = response.read((32 << 20) + 1)
    if len(raw) > 32 << 20 or hashlib.sha256(raw).hexdigest() != expected:
        raise RuntimeError("official client archive differs from its pinned SHA256")
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        binary = stream.read((96 << 20) + 1)
    if (not 64 <= len(binary) <= 96 << 20 or binary[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", binary, 18)[0] != machine):
        raise RuntimeError("official native client has the wrong format/architecture")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as stream:
        stream.write(binary)
    args.output.chmod(0o755)
    receipt = {"schema": 1, "version": VERSION, "architecture": args.arch, "archive_url": url,
               "archive_sha256": expected, "binary_sha256": hashlib.sha256(binary).hexdigest(),
               "release_tag_commit": "3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8", "upstream_modified": False}
    with args.output.with_suffix(".json").open("x") as stream:
        json.dump(receipt, stream, sort_keys=True)
        stream.write("\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
