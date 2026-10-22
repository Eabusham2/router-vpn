#!/usr/bin/env python3
"""Reproduce the bundled world outline from one pinned public-domain archive.

This build-time conversion does not install a shapefile/GIS dependency. It reads
only the Polygon records used by the pinned Natural Earth 110m land archive.
The native apps never download geography or infer a node/device coordinate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

SOURCE_URL = "https://naciscdn.org/naturalearth/110m/physical/ne_110m_land.zip"
ARCHIVE_SHA256 = "1926c621afd6ac67c3f36639bb1236134a48d82226dc675d3e3df53d02d2a3de"
ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "client/shared/map/routervpn-land-110m.json"


def convert(archive: Path) -> dict:
    raw = archive.read_bytes()
    if hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("Natural Earth source archive checksum mismatch")
    with zipfile.ZipFile(archive) as source:
        if source.read("ne_110m_land.VERSION.txt").decode().strip() != "4.1.0":
            raise ValueError("unexpected source version")
        if "WGS_1984" not in source.read("ne_110m_land.prj").decode():
            raise ValueError("source must use WGS84 coordinates")
        shape = source.read("ne_110m_land.shp")
    if struct.unpack_from(">i", shape)[0] != 9994 or struct.unpack_from("<ii", shape, 28) != (1000, 5):
        raise ValueError("expected a Polygon shapefile")
    if struct.unpack_from(">i", shape, 24)[0] * 2 != len(shape):
        raise ValueError("truncated shapefile")
    offset = 100
    rings: list[list[list[int]]] = []
    record_count = 0
    while offset < len(shape):
        record, words = struct.unpack_from(">ii", shape, offset)
        data = shape[offset + 8:offset + 8 + words * 2]
        offset += 8 + words * 2
        record_count += 1
        if record != record_count or len(data) != words * 2 or len(data) < 44:
            raise ValueError("invalid Polygon record")
        kind, = struct.unpack_from("<i", data)
        parts, points = struct.unpack_from("<ii", data, 36)
        if kind != 5 or not 0 < parts <= points <= 30_000 or len(data) != 44 + 4 * parts + 16 * points:
            raise ValueError("unexpected Polygon record shape")
        starts = list(struct.unpack_from(f"<{parts}i", data, 44)) + [points]
        if starts[0] != 0 or any(a >= b for a, b in zip(starts, starts[1:])):
            raise ValueError("invalid Polygon ring offsets")
        coordinates = []
        for i in range(points):
            lon, lat = struct.unpack_from("<dd", data, 44 + 4 * parts + 16 * i)
            if not -180.0000001 <= lon <= 180.0000001 or not -90.0000001 <= lat <= 90.0000001:
                raise ValueError("invalid WGS84 coordinate")
            coordinates.append([round(lon * 10_000), round(lat * 10_000)])
        for start, end in zip(starts, starts[1:]):
            ring = coordinates[start:end]
            if len(ring) < 4 or ring[0] != ring[-1]:
                raise ValueError("unclosed Polygon ring")
            rings.append(ring)
    if offset != len(shape):
        raise ValueError("trailing shapefile data")
    return {"schema": 1, "scale": 10_000, "source": "Natural Earth 110m land 4.1.0",
            "source_sha256": ARCHIVE_SHA256, "rings": rings}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help=f"local archive fetched from {SOURCE_URL}")
    parser.add_argument("--check", action="store_true", help="verify the committed asset without rewriting it")
    args = parser.parse_args()
    value = convert(args.archive)
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n"
    if args.check:
        if OUTPUT.read_text() != encoded:
            raise SystemExit("bundled land vectors differ from the pinned source conversion")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(encoded)
    print(f"VPN map land: {len(value['rings'])} rings / {sum(map(len, value['rings']))} points, {len(encoded)} bytes; pinned source verified")


if __name__ == "__main__":
    main()
