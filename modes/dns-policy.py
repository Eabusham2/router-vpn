#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shlex
import stat
import sys
import tempfile
from pathlib import Path

from profile_id import validate_profile_id
from private_profile_store import private_root, read_profile_store

ROOT = private_root(os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client"))
PROFILE_ID = os.environ.get("HOMEVPN_PROFILE_ID", "").strip()
if PROFILE_ID:
    PROFILE_ID = validate_profile_id(PROFILE_ID, default="")

MAX_RUNTIME_CONFIG_BYTES = 8 << 20

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
    store = read_profile_store(ROOT)
    selected = PROFILE_ID or str(store.get("selected_id") or "").strip()
    if selected:
        selected = validate_profile_id(selected, default="")
    profiles = [p for p in store.get("profiles", []) if isinstance(p, dict)]
    for p in profiles:
        if p.get("id") == selected:
            return p
    if selected:
        raise RuntimeError(f"selected Router VPN profile {selected!r} is missing")
    if len(profiles) == 1:
        return profiles[0]
    raise RuntimeError("Router VPN DNS policy requires one selected profile")


def infer_server_name(host: str, explicit: str) -> str:
    if explicit:
        return explicit
    if host in KNOWN_TLS_NAMES:
        return KNOWN_TLS_NAMES[host]
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
    else:
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


def _read_runtime_json(path: Path) -> dict:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink runtime DNS config: {path}")
    if before.st_size < 0 or before.st_size > MAX_RUNTIME_CONFIG_BYTES:
        raise RuntimeError(f"runtime DNS config exceeds safety limit: {path}")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError(f"runtime DNS config changed during open: {path}")
        body = stream.read(MAX_RUNTIME_CONFIG_BYTES + 1)
    if len(body) > MAX_RUNTIME_CONFIG_BYTES:
        raise RuntimeError(f"runtime DNS config exceeds safety limit: {path}")
    value = json.loads(body)
    if not isinstance(value, dict):
        raise RuntimeError("runtime DNS config must be a JSON object")
    return value


def _atomic_private_runtime_json(path: Path, cfg: dict) -> None:
    body = (json.dumps(cfg, indent=2) + "\n").encode("utf-8")
    if not body or len(body) > MAX_RUNTIME_CONFIG_BYTES:
        raise RuntimeError(f"patched runtime DNS config is empty or oversized: {path}")
    parent = path.parent
    parent_before = parent.lstat()
    if stat.S_ISLNK(parent_before.st_mode) or not stat.S_ISDIR(parent_before.st_mode):
        raise RuntimeError(f"refusing unsafe runtime DNS config parent: {parent}")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.dns-", dir=parent)
    tmp = Path(name)
    committed = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        parent_current = parent.lstat()
        if stat.S_ISLNK(parent_current.st_mode) or not stat.S_ISDIR(parent_current.st_mode) or not os.path.samestat(parent_before, parent_current):
            raise RuntimeError(f"runtime DNS config parent changed during patch: {parent}")
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
            raise RuntimeError(f"runtime DNS config target changed before adoption: {path}")
        os.replace(tmp, path)
        committed = True
        try:
            dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if not committed:
            tmp.unlink(missing_ok=True)


def patch_sing(path: Path, s: dict) -> None:
    cfg = _read_runtime_json(path)
    detour = choose_detour(cfg)
    cfg["dns"] = {"servers": [sing_server(s, detour)], "final": "selected-dns"}
    route = cfg.setdefault("route", {})
    rules = route.setdefault("rules", [])
    if not any(isinstance(r, dict) and r.get("protocol") == "dns" for r in rules):
        rules.insert(0, {"protocol": "dns", "action": "hijack-dns"})
    _atomic_private_runtime_json(path, cfg)


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
