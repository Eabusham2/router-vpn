#!/usr/bin/env python3
from __future__ import annotations

import json
import socket
import statistics
import struct
import sys
import time
from pathlib import Path

BASE = Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/router-vpn")
OUT = BASE / "config" / "dns-fastest.json"

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
    # Home AdGuard is the default profile policy, so failure to benchmark public
    # resolvers must never make first boot unusable.
    winner = {"name": "Cloudflare IPv4 fallback", "address": "1.1.1.1", "family": "ipv4", "latency_ms": None, "working": False}

payload = {
    "policy": "fastest-public",
    "winner": winner,
    "results": results,
    "tested_from": "home-vpn-node",
    "test": "five real DNS A/AAAA UDP queries; median shown",
}
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(payload, indent=2) + "\n")
OUT.chmod(0o600)

# Desktop installers may copy routers.json directly instead of importing the JSON
# bundle. Keep the benchmark available there, but default actual DNS selection to
# the user's Home AdGuard resolver as requested.
routers_path = BASE / "client-bundle" / "routers.json"
if routers_path.is_file():
    try:
        routers = json.loads(routers_path.read_text())
        latency = winner.get("latency_ms")
        for profile in routers.get("profiles", []):
            profile.setdefault("dns_mode", "home")
            profile.setdefault("dns_protocol", "udp")
            home = profile.get("adguard_ipv4") or "10.77.0.1"
            profile["dns_host"] = home
            profile.setdefault("dns_port", 53)
            profile.setdefault("dns_server_name", "")
            profile.setdefault("dns_path", "/dns-query")
            profile["fastest_dns_host"] = winner["address"]
            profile["fastest_dns_name"] = winner["name"]
            profile["fastest_dns_latency_ms"] = float(latency) if latency is not None else 0.0
            profile["dns_results"] = results
        routers_path.write_text(json.dumps(routers, indent=2) + "\n")
        routers_path.chmod(0o600)
    except Exception as exc:
        print(f"warning: could not update routers.json DNS fields: {exc}", file=sys.stderr)

print(winner["address"])
