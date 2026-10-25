#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import stat
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from profile_id import validate_profile_id
from private_profile_store import private_root, read_profile_store

ROOT = Path(os.path.abspath(os.path.expanduser(os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client"))))
PROFILE_ID = os.environ.get("HOMEVPN_PROFILE_ID", "").strip()
if PROFILE_ID:
    PROFILE_ID = validate_profile_id(PROFILE_ID, default="")

MAX_RUNTIME_CONFIG_BYTES = 8 << 20
PRIVATE_MODE = 0o600

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
    store = read_profile_store(private_root(str(ROOT)))
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


def profile_text(profile: dict, key: str) -> str:
    value = profile.get(key)
    if value is None:
        return ""
    if not isinstance(value, str) or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise RuntimeError(f"invalid captured DNS field: {key}")
    return value


def home_settings(profile: dict) -> dict:
    kind = profile_text(profile, "node_kind").strip().lower() or "router-vpn"
    if kind != "router-vpn" or profile.get("external") is not None:
        raise RuntimeError("Home DNS requires the captured Router VPN node policy")
    addresses = []
    private_v4 = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    private_v6 = ipaddress.ip_network("fc00::/7")
    for key, version in (("adguard_ipv4", 4), ("adguard_ipv6", 6)):
        text = profile_text(profile, key)
        if not text:
            continue
        try:
            address = ipaddress.ip_address(text)
        except ValueError as error:
            raise RuntimeError("Home DNS requires this node's canonical private AdGuard addresses") from error
        private = any(address in network for network in private_v4) if version == 4 else address in private_v6
        if address.version != version or str(address) != text or "%" in text or not private:
            raise RuntimeError("Home DNS requires this node's canonical private AdGuard addresses")
        addresses.append(text)
    if not addresses:
        raise RuntimeError("Home AdGuard address is missing from this captured node")
    host = profile_text(profile, "dns_host").strip().strip("[]") or addresses[0]
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise RuntimeError("Home DNS requires this node's explicit private AdGuard address") from error
    host = str(address)
    if host not in addresses:
        raise RuntimeError("Home DNS belongs to a different node; select this node's saved AdGuard address")
    if address.version == 6 and profile_text(profile, "ipv6_mode").strip().lower() == "off":
        raise RuntimeError("The selected IPv6 Home resolver cannot be used while IPv6 is Off")
    protocol = profile_text(profile, "dns_protocol").strip().lower() or "udp"
    protocol = {"dot": "tls", "doh": "https", "doh3": "h3"}.get(protocol, protocol)
    if protocol not in ("udp", "tcp", "tls", "https", "h3"):
        raise RuntimeError("Home DNS transport must be UDP, TCP, DoT, DoH or DoH3")
    port = profile.get("dns_port")
    if port is None:
        port = 0
    if type(port) is not int or not 0 <= port <= 65535:
        raise RuntimeError("Home DNS port must be between 1 and 65535")
    port = port or (853 if protocol == "tls" else 443 if protocol in ("https", "h3") else 53)
    server_name, path = "", ""
    if protocol in ("tls", "https", "h3"):
        server_name = profile_text(profile, "dns_server_name").strip()
        try:
            ipaddress.ip_address(server_name)
        except ValueError:
            pass
        else:
            raise RuntimeError("Encrypted Home DNS requires its exact TLS certificate hostname")
        if len(server_name) > 253 or "." not in server_name or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in server_name.split(".")
        ):
            raise RuntimeError("Encrypted Home DNS requires its exact TLS certificate hostname")
    if protocol in ("https", "h3"):
        path = profile_text(profile, "dns_path").strip() or "/dns-query"
        parsed = urlsplit(path)
        if len(path.encode("utf-8")) > 2048 or not path.startswith("/") or path.startswith("//") or \
                any(ord(ch) <= 32 or ord(ch) == 127 or ch in "\\?#" for ch in path) or re.search(r"%(?![0-9A-Fa-f]{2})", path) or \
                parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            raise RuntimeError("Home DoH requires its exact local resolver path without a host, query or fragment")
    return {"mode": "home", "protocol": protocol, "host": host, "port": port, "server_name": server_name, "path": path}


def settings() -> dict:
    p = load_profile()
    mode = profile_text(p, "dns_mode").strip().lower() or "home"
    if mode == "home":
        selected = home_settings(p)
        selected.update(fastest_name=str(p.get("fastest_dns_name") or "Fastest public DNS"),
                        fastest_latency_ms=float(p.get("fastest_dns_latency_ms") or 0.0))
        return selected
    fastest = str(p.get("fastest_dns_host") or "1.1.1.1")
    protocol = str(p.get("dns_protocol") or "udp").lower()
    host = str(p.get("dns_host") or fastest)
    port = int(p.get("dns_port") or 0)
    server_name = str(p.get("dns_server_name") or "")
    path = str(p.get("dns_path") or "/dns-query")

    if mode == "fastest":
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


def _runtime_parent_snapshot(path: Path) -> os.stat_result:
    parent = path.parent
    info = parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing unsafe runtime DNS config parent: {parent}")
    return info


def _read_runtime_json_snapshot(path: Path) -> tuple[dict, os.stat_result, os.stat_result]:
    parent_before = _runtime_parent_snapshot(path)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink runtime DNS config: {path}")
    if before.st_size < 0 or before.st_size > MAX_RUNTIME_CONFIG_BYTES:
        raise RuntimeError(f"runtime DNS config exceeds safety limit: {path}")
    if os.name != "nt" and stat.S_IMODE(before.st_mode) != PRIVATE_MODE:
        raise RuntimeError(f"runtime DNS config must be private 0600: {path}")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError(f"runtime DNS config changed during open: {path}")
        body = stream.read(MAX_RUNTIME_CONFIG_BYTES + 1)
        after = path.lstat()
        parent_after = _runtime_parent_snapshot(path)
        if (
            stat.S_ISLNK(after.st_mode)
            or not stat.S_ISREG(after.st_mode)
            or not os.path.samestat(opened, after)
            or not os.path.samestat(parent_before, parent_after)
        ):
            raise RuntimeError(f"runtime DNS config changed during read: {path}")
    if len(body) > MAX_RUNTIME_CONFIG_BYTES:
        raise RuntimeError(f"runtime DNS config exceeds safety limit: {path}")
    value = json.loads(body)
    if not isinstance(value, dict):
        raise RuntimeError("runtime DNS config must be a JSON object")
    return value, after, parent_after


def _read_runtime_json(path: Path) -> dict:
    value, _, _ = _read_runtime_json_snapshot(path)
    return value


def _atomic_private_runtime_json(
    path: Path,
    cfg: dict,
    expected: os.stat_result,
    expected_parent: os.stat_result,
) -> None:
    body = (json.dumps(cfg, indent=2) + "\n").encode("utf-8")
    if not body or len(body) > MAX_RUNTIME_CONFIG_BYTES:
        raise RuntimeError(f"patched runtime DNS config is empty or oversized: {path}")
    parent = path.parent
    parent_before = _runtime_parent_snapshot(path)
    if not os.path.samestat(expected_parent, parent_before):
        raise RuntimeError(f"runtime DNS config parent changed before staging: {parent}")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.dns-", dir=parent)
    tmp = Path(name)
    committed = False
    try:
        os.fchmod(fd, PRIVATE_MODE)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        staged = tmp.lstat()
        if (
            stat.S_ISLNK(staged.st_mode)
            or not stat.S_ISREG(staged.st_mode)
            or (os.name != "nt" and stat.S_IMODE(staged.st_mode) != PRIVATE_MODE)
        ):
            raise RuntimeError(f"staged runtime DNS config is unsafe: {tmp}")

        parent_current = _runtime_parent_snapshot(path)
        if not os.path.samestat(parent_before, parent_current):
            raise RuntimeError(f"runtime DNS config parent changed during patch: {parent}")
        current = path.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(expected, current)
        ):
            raise RuntimeError(f"runtime DNS config target identity changed before adoption: {path}")
        os.replace(tmp, path)
        committed = True

        parent_after = _runtime_parent_snapshot(path)
        adopted = path.lstat()
        if (
            not os.path.samestat(parent_before, parent_after)
            or stat.S_ISLNK(adopted.st_mode)
            or not stat.S_ISREG(adopted.st_mode)
            or (os.name != "nt" and stat.S_IMODE(adopted.st_mode) != PRIVATE_MODE)
            or not os.path.samestat(staged, adopted)
        ):
            raise RuntimeError(f"adopted runtime DNS config identity changed before verification: {path}")
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
    cfg, expected, expected_parent = _read_runtime_json_snapshot(path)
    detour = choose_detour(cfg)
    if s["mode"] == "home":
        owned = [outbound for outbound in cfg.get("outbounds", [])
                 if isinstance(outbound, dict) and outbound.get("tag") == detour]
        kind = owned[0].get("type") if len(owned) == 1 else None
        if detour == "direct" or not isinstance(kind, str) or not kind.strip() or kind.strip().lower() in ("direct", "block", "dns"):
            raise RuntimeError("Home DNS requires an owned tunnel outbound; direct fallback is forbidden")
    cfg["dns"] = {"servers": [sing_server(s, detour)], "final": "selected-dns"}
    route = cfg.setdefault("route", {})
    rules = route.setdefault("rules", [])
    if not any(isinstance(r, dict) and r.get("protocol") == "dns" for r in rules):
        rules.insert(0, {"protocol": "dns", "action": "hijack-dns"})
    _atomic_private_runtime_json(path, cfg, expected, expected_parent)


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
