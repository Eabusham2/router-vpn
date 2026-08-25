#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socket
import stat
import statistics
import struct
import sys
import tempfile
import time
from pathlib import Path

BASE = Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/router-vpn")
OUT = BASE / "config" / "dns-fastest.json"
MAX_RESULT_BYTES = 1 << 20

# Common public recursive resolvers, including primary/secondary addresses and
# both address families where the provider publishes them. The benchmark runs
# from the home VPN node because that is where tunneled public DNS exits.
CANDIDATES = [
    ("Cloudflare IPv4", "1.1.1.1"),
    ("Cloudflare IPv4 secondary", "1.0.0.1"),
    ("Google IPv4", "8.8.8.8"),
    ("Google IPv4 secondary", "8.8.4.4"),
    ("Quad9 IPv4", "9.9.9.9"),
    ("Quad9 IPv4 secondary", "149.112.112.112"),
    ("AdGuard DNS IPv4", "94.140.14.14"),
    ("AdGuard DNS IPv4 secondary", "94.140.15.15"),
    ("Control D IPv4", "76.76.2.0"),
    ("Control D IPv4 secondary", "76.76.10.0"),
    ("OpenDNS IPv4", "208.67.222.222"),
    ("OpenDNS IPv4 secondary", "208.67.220.220"),
    ("Cloudflare IPv6", "2606:4700:4700::1111"),
    ("Cloudflare IPv6 secondary", "2606:4700:4700::1001"),
    ("Google IPv6", "2001:4860:4860::8888"),
    ("Google IPv6 secondary", "2001:4860:4860::8844"),
    ("Quad9 IPv6", "2620:fe::fe"),
    ("Quad9 IPv6 secondary", "2620:fe::9"),
    ("AdGuard DNS IPv6", "2a10:50c0::ad1:ff"),
    ("AdGuard DNS IPv6 secondary", "2a10:50c0::ad2:ff"),
]


def query_packet(name: str, qtype: int = 1) -> bytes:
    txid = int(time.time_ns()) & 0xFFFF
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    return header + labels + struct.pack("!HH", qtype, 1)


def probe(address: str, qtype: int) -> float | None:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    packet = query_packet("example.com", qtype)
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(1.25)
    target = (address, 53, 0, 0) if family == socket.AF_INET6 else (address, 53)
    started = time.perf_counter()
    try:
        sock.sendto(packet, target)
        data, _ = sock.recvfrom(4096)
        if len(data) < 12:
            return None
        rcode = data[3] & 0x0F
        if rcode not in (0, 3):
            return None
        return (time.perf_counter() - started) * 1000.0
    except OSError:
        return None
    finally:
        sock.close()


def write_private_atomic(path: Path, text: str) -> None:
    body = text.encode("utf-8")
    if not body or len(body) > MAX_RESULT_BYTES:
        raise RuntimeError("DNS benchmark result is empty or oversized")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        info = path.lstat()
    except FileNotFoundError:
        info = None
    if info is not None:
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"refusing non-regular/symlink DNS benchmark output: {path}")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    tmp = Path(name)
    committed = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        committed = True
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if not committed:
            tmp.unlink(missing_ok=True)


def main() -> int:
    results = []
    for name, address in CANDIDATES:
        samples = []
        # Five real DNS queries give a useful median while still keeping first-run
        # time bounded. Alternate A/AAAA so both record paths are exercised.
        for qtype in (1, 28, 1, 28, 1):
            value = probe(address, qtype)
            if value is not None:
                samples.append(value)
        if samples:
            samples.sort()
            latency = statistics.median(samples)
            results.append({
                "name": name,
                "address": address,
                "family": "ipv6" if ":" in address else "ipv4",
                "latency_ms": round(latency, 3),
                "samples": len(samples),
                "working": True,
            })
        else:
            results.append({
                "name": name,
                "address": address,
                "family": "ipv6" if ":" in address else "ipv4",
                "samples": 0,
                "working": False,
            })

    working = [r for r in results if r.get("working")]
    working.sort(key=lambda r: r["latency_ms"])
    if working:
        winner = working[0]
    else:
        # Home AdGuard remains the actual default policy. This fallback is only a
        # measured-default candidate for fresh bundle generation; benchmark runs
        # never rewrite an existing user's routers.json or active DNS policy.
        winner = {"name": "Cloudflare IPv4 fallback", "address": "1.1.1.1", "family": "ipv4", "latency_ms": None, "working": False}

    payload = {
        "policy": "fastest-public",
        "winner": winner,
        "results": results,
        "tested_from": "home-vpn-node",
        "test": "five real DNS A/AAAA UDP queries; median shown",
        "measurement_only": True,
    }
    write_private_atomic(OUT, json.dumps(payload, indent=2) + "\n")
    print(winner["address"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
