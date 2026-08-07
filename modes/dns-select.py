#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import random
import socket
import statistics
import struct
import sys
import time
from urllib.parse import urlparse

TEST_NAME = os.environ.get("HOMEVPN_DNS_TEST_NAME", "example.com")
MODE = os.environ.get("HOMEVPN_DNS_MODE", "fastest").strip().lower()
FAMILY = os.environ.get("HOMEVPN_DNS_FAMILY", "auto").strip().lower()
CUSTOM_ADDRESS = os.environ.get("HOMEVPN_DNS_ADDRESS", "").strip()
CUSTOM_PORT = os.environ.get("HOMEVPN_DNS_PORT", "").strip()
CUSTOM_PROTOCOL = os.environ.get("HOMEVPN_DNS_PROTOCOL", "udp").strip().lower()
DOH_URL = os.environ.get("HOMEVPN_DNS_DOH_URL", "").strip()
ADGUARD4 = os.environ.get("HOMEVPN_ADGUARD4", "").strip()
ADGUARD6 = os.environ.get("HOMEVPN_ADGUARD6", "").strip()

CANDIDATES = [
    ("Cloudflare IPv4", "1.1.1.1"),
    ("Google IPv4", "8.8.8.8"),
    ("Quad9 IPv4", "9.9.9.9"),
    ("Cloudflare IPv6", "2606:4700:4700::1111"),
    ("Google IPv6", "2001:4860:4860::8888"),
    ("Quad9 IPv6", "2620:fe::fe"),
]


def family_ok(address: str) -> bool:
    is_v6 = ":" in address
    if FAMILY in ("v4", "ipv4"):
        return not is_v6
    if FAMILY in ("v6", "ipv6"):
        return is_v6
    return True


def dns_query(name: str) -> tuple[int, bytes]:
    ident = random.randrange(0, 65536)
    header = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(x)]) + x.encode("ascii") for x in name.rstrip(".").split(".")) + b"\x00"
    return ident, header + labels + struct.pack("!HH", 1, 1)


def probe_udp(address: str, port: int = 53, timeout: float = 0.9) -> float | None:
    af = socket.AF_INET6 if ":" in address else socket.AF_INET
    samples: list[float] = []
    for _ in range(2):
        ident, payload = dns_query(TEST_NAME)
        s = socket.socket(af, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            t0 = time.perf_counter()
            s.sendto(payload, (address, port))
            data, _ = s.recvfrom(4096)
            elapsed = (time.perf_counter() - t0) * 1000
            if len(data) >= 12 and struct.unpack("!H", data[:2])[0] == ident:
                samples.append(elapsed)
        except OSError:
            pass
        finally:
            s.close()
    return statistics.median(samples) if samples else None


def fastest() -> tuple[str, str, float | None]:
    results: list[tuple[float, str, str]] = []
    for name, address in CANDIDATES:
        if not family_ok(address):
            continue
        latency = probe_udp(address)
        if latency is not None:
            results.append((latency, name, address))
    if results:
        latency, name, address = min(results)
        return name, address, latency
    # DNS may be blocked before the VPN exists. Keep a deterministic bootstrap;
    # the runtime will carry it through the tunnel once the mode is up.
    for name, address in CANDIDATES:
        if family_ok(address):
            return name + " fallback", address, None
    return "Cloudflare IPv4 fallback", "1.1.1.1", None


def home_address() -> str:
    if FAMILY in ("v6", "ipv6") and ADGUARD6:
        return ADGUARD6
    if FAMILY in ("v4", "ipv4") and ADGUARD4:
        return ADGUARD4
    return ADGUARD4 or ADGUARD6 or "10.77.0.1"


def parse_port(value: str, default: int) -> int:
    try:
        p = int(value)
        if 1 <= p <= 65535:
            return p
    except ValueError:
        pass
    return default


def dns_server(tag: str, protocol: str, address: str, port: int, *, path: str = "/dns-query", server_name: str = "", detour: bool = True) -> dict:
    protocol = protocol.lower()
    aliases = {"dot": "tls", "doh": "https", "doh3": "h3", "http3": "h3"}
    protocol = aliases.get(protocol, protocol)
    if protocol not in {"udp", "tcp", "tls", "https", "h3"}:
        raise SystemExit(f"unsupported DNS protocol: {protocol}")
    out: dict = {"type": protocol, "tag": tag, "server": address, "server_port": port}
    if detour:
        out["detour"] = "proxy"
    if protocol in {"https", "h3"}:
        out["path"] = path or "/dns-query"
    if protocol in {"tls", "https", "h3"}:
        out["tls"] = {"enabled": True}
        if server_name:
            out["tls"]["server_name"] = server_name
    return out


def main() -> int:
    selected_name = ""
    selected_latency = None

    if MODE in {"home", "adguard", "home-adguard"}:
        addr = home_address()
        server = dns_server("selected-dns", "udp", addr, parse_port(CUSTOM_PORT, 53), detour=False)
        selected_name = "Home AdGuard"
    elif MODE in {"rescue", "dns-rescue"}:
        # No bootstrap DNS lookup is needed: connect to Cloudflare by IP, but use
        # the proper TLS SNI/certificate name. Port can be changed if a network
        # permits HTTPS only on an alternate port supported by the chosen server.
        addr = "2606:4700:4700::1111" if FAMILY in {"v6", "ipv6"} else "1.1.1.1"
        server = dns_server("selected-dns", "https", addr, parse_port(CUSTOM_PORT, 443), path="/dns-query", server_name="cloudflare-dns.com")
        selected_name = "DNS Rescue DoH"
    elif MODE in {"doh", "https", "doh3", "h3"}:
        raw = DOH_URL or CUSTOM_ADDRESS or "https://cloudflare-dns.com/dns-query"
        if "://" not in raw:
            raw = "https://" + raw
        u = urlparse(raw)
        if not u.hostname:
            raise SystemExit("invalid DoH URL")
        proto = "h3" if MODE in {"doh3", "h3"} or u.scheme.lower() in {"h3", "http3"} else "https"
        default_port = 443
        port = parse_port(CUSTOM_PORT, u.port or default_port)
        # If a literal IP was supplied, no bootstrap resolver is needed. A named
        # server is valid too; sing-box resolves it using the bootstrap server.
        addr = u.hostname
        server = dns_server("selected-dns", proto, addr, port, path=u.path or "/dns-query", server_name=u.hostname)
        selected_name = f"Custom {'DoH3' if proto == 'h3' else 'DoH'}"
    elif MODE == "custom":
        if not CUSTOM_ADDRESS:
            raise SystemExit("custom DNS requires an address")
        proto = CUSTOM_PROTOCOL or "udp"
        defaults = {"udp": 53, "tcp": 53, "tls": 853, "dot": 853, "https": 443, "doh": 443, "h3": 443, "doh3": 443}
        port = parse_port(CUSTOM_PORT, defaults.get(proto, 53))
        addr = CUSTOM_ADDRESS.strip("[]")
        server_name = os.environ.get("HOMEVPN_DNS_SERVER_NAME", "").strip()
        path = os.environ.get("HOMEVPN_DNS_PATH", "/dns-query").strip() or "/dns-query"
        server = dns_server("selected-dns", proto, addr, port, path=path, server_name=server_name)
        selected_name = "Custom DNS"
    else:
        selected_name, addr, selected_latency = fastest()
        server = dns_server("selected-dns", "udp", addr, 53)

    # Bootstrap is only used to resolve a named encrypted resolver. It is itself
    # routed through the selected VPN outbound so local DNS filtering cannot see it.
    servers = []
    if server.get("type") in {"tls", "https", "h3"} and ":" not in str(server.get("server", "")):
        _, bootstrap_addr, _ = fastest()
        servers.append(dns_server("dns-bootstrap", "udp", bootstrap_addr, 53))
        server["domain_resolver"] = "dns-bootstrap"
    servers.append(server)

    result = {
        "mode": MODE,
        "family": FAMILY,
        "selected_name": selected_name,
        "selected_address": server.get("server"),
        "selected_port": server.get("server_port"),
        "selected_protocol": server.get("type"),
        "latency_ms": selected_latency,
        "servers": servers,
        "final": "selected-dns",
    }
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
