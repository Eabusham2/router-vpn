#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path

ROOT = Path(os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client"))
PROFILE_ID = os.environ.get("HOMEVPN_PROFILE_ID", "")

KNOWN_TLS_NAMES = {
    "1.1.1.1": "cloudflare-dns.com",
    "1.0.0.1": "cloudflare-dns.com",
    "2606:4700:4700::1111": "cloudflare-dns.com",
    "2606:4700:4700::1001": "cloudflare-dns.com",
    "8.8.8.8": "dns.google",
    "8.8.4.4": "dns.google",
    "2001:4860:4860::8888": "dns.google",
    "2001:4860:4860::8844": "dns.google",
    "9.9.9.9": "dns.quad9.net",
    "149.112.112.112": "dns.quad9.net",
    "2620:fe::fe": "dns.quad9.net",
}


def load_profile() -> dict:
    path = ROOT / "routers.json"
    try:
        store = json.loads(path.read_text())
    except Exception:
        return {}
    selected = PROFILE_ID or store.get("selected_id", "")
    profiles = store.get("profiles", [])
    for p in profiles:
        if p.get("id") == selected:
            return p
    return profiles[0] if profiles else {}


def infer_server_name(host: str, explicit: str) -> str:
    if explicit:
        return explicit
    if host in KNOWN_TLS_NAMES:
        return KNOWN_TLS_NAMES[host]
    # A hostname can normally authenticate itself. An arbitrary IP cannot, so leave
    # it blank and let validation/client UI explain that a TLS name is needed.
    if ":" not in host and any(c.isalpha() for c in host):
        return host
    return ""


def settings() -> dict:
    p = load_profile()
    mode = str(p.get("dns_mode") or "fastest").lower()
    fastest = str(p.get("fastest_dns_host") or "1.1.1.1")
    protocol = str(p.get("dns_protocol") or "udp").lower()
    host = str(p.get("dns_host") or fastest)
    port = int(p.get("dns_port") or 0)
    server_name = str(p.get("dns_server_name") or "")
    path = str(p.get("dns_path") or "/dns-query")

    if mode == "home":
        host = str(p.get("adguard_ipv4") or p.get("adguard_ipv6") or "10.77.0.1")
        protocol, port, server_name, path = "udp", 53, "", ""
    elif mode == "fastest":
        host, protocol, port, server_name, path = fastest, "udp", 53, "", ""
    elif mode == "doh":
        protocol = "https"
        port = port or 443
    elif mode == "dot":
        protocol = "tls"
        port = port or 853
    elif mode == "doh3":
        protocol = "h3"
        port = port or 443
    elif mode == "rescue":
        protocol = "rescue"
        host = host or fastest
        port = port or 443
    else:  # custom
        protocol = {"doh": "https", "dot": "tls", "doh3": "h3"}.get(protocol, protocol)
        if not port:
            port = 443 if protocol in ("https", "h3") else 853 if protocol == "tls" else 53

    server_name = infer_server_name(host, server_name)
    return {
        "mode": mode,
        "protocol": protocol,
        "host": host,
        "port": port,
        "server_name": server_name,
        "path": path or "/dns-query",
        "fastest_name": str(p.get("fastest_dns_name") or "Fastest public DNS"),
        "fastest_latency_ms": float(p.get("fastest_dns_latency_ms") or 0.0),
    }


def shell_env(s: dict) -> None:
    fields = {
        "HOMEVPN_DNS_MODE": s["mode"],
        "HOMEVPN_DNS_PROTOCOL": s["protocol"],
        "HOMEVPN_DNS_HOST": s["host"],
        "HOMEVPN_DNS_PORT": s["port"],
        "HOMEVPN_DNS_SERVER_NAME": s["server_name"],
        "HOMEVPN_DNS_PATH": s["path"],
    }
    for key, value in fields.items():
        print(f"{key}={shlex.quote(str(value))}")


def choose_detour(cfg: dict) -> str:
    tags = [x.get("tag") for x in cfg.get("outbounds", []) if isinstance(x, dict)]
    for candidate in ("proxy", "tcp-stack", "ss-hop", "outer"):
        if candidate in tags:
            return candidate
    return "direct"


def sing_server(s: dict, detour: str) -> dict:
    protocol = s["protocol"]
    # Rescue is deliberately conservative in sing-box: encrypted HTTPS on 443.
    # The raw WG/AWG helper performs the longer DoH -> DoT -> TCP -> UDP fallback.
    if protocol == "rescue":
        protocol = "https"
        if not s["server_name"]:
            s = dict(s)
            s["host"] = "1.1.1.1"
            s["server_name"] = "cloudflare-dns.com"
            s["port"] = 443
            s["path"] = "/dns-query"
    out = {
        "type": protocol,
        "tag": "selected-dns",
        "server": s["host"],
        "server_port": int(s["port"]),
        "detour": detour,
    }
    if protocol in ("tls", "https", "h3"):
        if not s["server_name"]:
            raise SystemExit("encrypted DNS requires a TLS server name; enter one in DNS settings")
        out["tls"] = {"enabled": True, "server_name": s["server_name"]}
    if protocol in ("https", "h3"):
        out["path"] = s["path"]
    if protocol not in ("udp", "tcp", "tls", "https", "h3"):
        raise SystemExit(f"unsupported DNS protocol: {protocol}")
    return out


def patch_sing(path: Path, s: dict) -> None:
    cfg = json.loads(path.read_text())
    detour = choose_detour(cfg)
    cfg["dns"] = {"servers": [sing_server(s, detour)], "final": "selected-dns"}
    route = cfg.setdefault("route", {})
    rules = route.setdefault("rules", [])
    if not any(isinstance(r, dict) and r.get("protocol") == "dns" for r in rules):
        rules.insert(0, {"protocol": "dns", "action": "hijack-dns"})
    path.write_text(json.dumps(cfg, indent=2) + "\n")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: dns-policy.py env | json | patch-sing CONFIG")
    s = settings()
    cmd = sys.argv[1]
    if cmd == "env":
        shell_env(s)
    elif cmd == "json":
        print(json.dumps(s, indent=2))
    elif cmd == "patch-sing":
        if len(sys.argv) != 3:
            raise SystemExit("patch-sing requires a config path")
        patch_sing(Path(sys.argv[2]), s)
    else:
        raise SystemExit(f"unknown command: {cmd}")


if __name__ == "__main__":
    main()
