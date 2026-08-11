#!/usr/bin/env python3
"""Generate the PortableApps.com AppInfo icon set without binary source assets."""
from __future__ import annotations

import binascii
from pathlib import Path
import struct
import sys
import zlib


def chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)


def icon_png(size: int) -> bytes:
    rows = []
    cx = cy = (size - 1) / 2.0
    radius = size * 0.44
    inner = size * 0.30
    stroke = max(1.0, size * 0.055)
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            dx, dy = x - cx, y - cy
            d2 = dx * dx + dy * dy
            if d2 <= radius * radius:
                # Dark ring + bright center gives a legible VPN/node mark at 16px.
                if d2 >= (radius - stroke) ** 2:
                    rgba = (18, 48, 86, 255)
                else:
                    rgba = (36, 126, 214, 255)
                # White linked-node glyph: vertical stem and two connection bars.
                stem = abs(x - (cx - size * 0.12)) <= stroke * 0.62 and abs(y - cy) <= inner
                top = abs(y - (cy - inner * 0.48)) <= stroke * 0.58 and cx - size * 0.12 <= x <= cx + inner
                mid = abs(y - cy) <= stroke * 0.58 and cx - size * 0.12 <= x <= cx + inner * 0.78
                diag = abs((y - cy) - (x - cx) * 0.72) <= stroke * 0.70 and x >= cx and y >= cy - stroke
                if stem or top or mid or diag:
                    rgba = (255, 255, 255, 255)
            else:
                rgba = (0, 0, 0, 0)
            row.extend(rgba)
        rows.append(bytes(row))
    raw = b"".join(rows)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def ico(images: list[tuple[int, bytes]]) -> bytes:
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    directory = bytearray()
    payload = bytearray()
    for size, data in images:
        wh = 0 if size == 256 else size
        directory += struct.pack("<BBBBHHII", wh, wh, 0, 0, 1, 32, len(data), offset)
        payload += data
        offset += len(data)
    return header + bytes(directory) + bytes(payload)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: make-portableapps-icons.py APPINFO_DIR")
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    pngs = {size: icon_png(size) for size in (16, 32, 48, 75, 128, 256)}
    main_ico = ico([(s, pngs[s]) for s in (16, 32, 48, 256)])

    for suffix in ("", "1", "2"):
        (out / f"appicon{suffix}.ico").write_bytes(main_ico)
        for size in ((16, 32, 75, 128, 256) if suffix == "" else (16, 32)):
            (out / f"appicon{suffix}_{size}.png").write_bytes(pngs[size])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
