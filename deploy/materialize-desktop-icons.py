#!/usr/bin/env python3
"""Generate Router VPN desktop PNG/ICO icons using only the Python stdlib."""
from __future__ import annotations

import argparse
import binascii
import math
from pathlib import Path
import struct
import tempfile
import zlib

NAVY = (23, 71, 157, 255)
BLUE = (31, 91, 202, 255)
WHITE = (255, 255, 255, 245)
TRANSPARENT = (0, 0, 0, 0)


def put(buf: bytearray, size: int, x: int, y: int, color: tuple[int, int, int, int]) -> None:
    if 0 <= x < size and 0 <= y < size:
        i = (y * size + x) * 4
        buf[i:i + 4] = bytes(color)


def rounded_rect(buf: bytearray, size: int, x0: int, y0: int, x1: int, y1: int, radius: int, color: tuple[int, int, int, int]) -> None:
    r2 = radius * radius
    for y in range(y0, y1 + 1):
        for x in range(x0, x1 + 1):
            cx = x0 + radius if x < x0 + radius else x1 - radius if x > x1 - radius else x
            cy = y0 + radius if y < y0 + radius else y1 - radius if y > y1 - radius else y
            if (x - cx) * (x - cx) + (y - cy) * (y - cy) <= r2:
                put(buf, size, x, y, color)


def polygon(buf: bytearray, size: int, points: list[tuple[int, int]], color: tuple[int, int, int, int]) -> None:
    min_y = max(0, min(y for _, y in points))
    max_y = min(size - 1, max(y for _, y in points))
    for y in range(min_y, max_y + 1):
        xs: list[float] = []
        for i, (x1, y1) in enumerate(points):
            x2, y2 = points[(i + 1) % len(points)]
            if y1 == y2:
                continue
            if y >= min(y1, y2) and y < max(y1, y2):
                xs.append(x1 + (y - y1) * (x2 - x1) / (y2 - y1))
        xs.sort()
        for i in range(0, len(xs) - 1, 2):
            for x in range(max(0, math.ceil(xs[i])), min(size - 1, math.floor(xs[i + 1])) + 1):
                put(buf, size, x, y, color)


def disc(buf: bytearray, size: int, cx: int, cy: int, radius: int, color: tuple[int, int, int, int]) -> None:
    r2 = radius * radius
    for y in range(cy - radius, cy + radius + 1):
        for x in range(cx - radius, cx + radius + 1):
            if (x - cx) * (x - cx) + (y - cy) * (y - cy) <= r2:
                put(buf, size, x, y, color)


def thick_line(buf: bytearray, size: int, a: tuple[int, int], b: tuple[int, int], width: int, color: tuple[int, int, int, int]) -> None:
    x1, y1 = a
    x2, y2 = b
    steps = max(abs(x2 - x1), abs(y2 - y1), 1)
    radius = max(1, width // 2)
    for step in range(steps + 1):
        t = step / steps
        disc(buf, size, round(x1 + (x2 - x1) * t), round(y1 + (y2 - y1) * t), radius, color)


def icon_rgba(size: int) -> bytes:
    buf = bytearray(bytes(TRANSPARENT) * size * size)
    margin = round(size * 0.06)
    rounded_rect(buf, size, margin, margin, size - margin - 1, size - margin - 1, round(size * 0.22), NAVY)
    inner = round(size * 0.14)
    rounded_rect(buf, size, inner, inner, size - inner - 1, size - inner - 1, round(size * 0.17), BLUE)

    cx = size // 2
    top = round(size * 0.24)
    half = round(size * 0.20)
    height = round(size * 0.48)
    shield = [
        (cx, top),
        (cx + half, top + round(size * 0.07)),
        (cx + round(size * 0.184), top + round(height * 0.58)),
        (cx, top + height),
        (cx - round(size * 0.184), top + round(height * 0.58)),
        (cx - half, top + round(size * 0.07)),
    ]
    polygon(buf, size, shield, WHITE)

    nodes = [
        (cx, top + round(size * 0.18)),
        (cx - round(size * 0.115), top + round(size * 0.29)),
        (cx + round(size * 0.115), top + round(size * 0.29)),
        (cx, top + round(size * 0.41)),
    ]
    for left, right in ((0, 1), (0, 2), (1, 3), (2, 3), (1, 2)):
        thick_line(buf, size, nodes[left], nodes[right], max(2, round(size * 0.018)), BLUE)
    radius = max(2, round(size * 0.035))
    for x, y in nodes:
        disc(buf, size, x, y, radius, BLUE)
    return bytes(buf)


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)


def make_png(size: int) -> bytes:
    rgba = icon_rgba(size)
    raw = b"".join(b"\x00" + rgba[y * size * 4:(y + 1) * size * 4] for y in range(size))
    return b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)) + png_chunk(b"IDAT", zlib.compress(raw, 9)) + png_chunk(b"IEND", b"")


def make_ico() -> bytes:
    image = make_png(256)
    header = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", 0, 0, 0, 0, 1, 32, len(image), 22)
    return header + entry + image


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def validate(png: Path, ico: Path) -> None:
    p = png.read_bytes()
    i = ico.read_bytes()
    if not p.startswith(b"\x89PNG\r\n\x1a\n"):
        raise SystemExit("generated PNG signature is invalid")
    if len(p) < 4096:
        raise SystemExit("generated PNG is unexpectedly small")
    if i[:6] != b"\x00\x00\x01\x00\x01\x00" or i[22:30] != b"\x89PNG\r\n\x1a\n":
        raise SystemExit("generated ICO structure is invalid")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--png", type=Path)
    parser.add_argument("--ico", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        with tempfile.TemporaryDirectory(prefix="router-vpn-icons-") as td:
            png = Path(td) / "router-vpn.png"
            ico = Path(td) / "router-vpn.ico"
            write(png, make_png(1024))
            write(ico, make_ico())
            validate(png, ico)
        print("Router VPN desktop icon generator self-test: OK")
        return 0
    if not args.png or not args.ico:
        parser.error("--png and --ico are required unless --self-test is used")
    write(args.png, make_png(1024))
    write(args.ico, make_ico())
    validate(args.png, args.ico)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
