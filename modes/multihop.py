#!/usr/bin/env python3
"""Build a real two-node Router VPN multihop runtime.

Supported first dataplane:
  client -> WG/AWG split entry -> entry private SOCKS5 ->
  exit Shadowsocks/Hysteria2 -> exit node -> Internet

The entry split route is narrowed to the entry SOCKS host only, so overlapping
private Router VPN/LAN addresses on entry and exit cannot steal exit DNS/proof
traffic. The exit transport's `proxy` outbound has `detour=entry-hop`; the exit
public endpoint is therefore requested through entry SOCKS and never opened as
an OS/firewall exception.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import sys
import tempfile
from typing import Any

from profile_id import validate_profile_id
from private_profile_store import private_root, read_profile_store

SUPPORTED_EXIT = {"shadowsocks": "shadowsocks", "hysteria2": "hysteria2"}
PROOF_PORT = 1099
MAX_RUNTIME_FILE_BYTES = 8 << 20


def root_dir() -> Path:
    return private_root(os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client"))


def valid_id(value: str, label: str) -> str:
    try:
        return validate_profile_id(str(value or "").strip(), default="")
    except ValueError as exc:
        raise RuntimeError(f"invalid {label}") from exc


def safe_under(parent: Path, child: Path) -> Path:
    parent = parent.resolve()
    child = child.resolve()
    try:
        child.relative_to(parent)
    except ValueError as exc:
        raise RuntimeError(f"unsafe path outside {parent}") from exc
    return child


def read_store(root: Path) -> dict[str, Any]:
    return read_profile_store(root)


def profile(store: dict[str, Any], profile_id: str, role: str) -> dict[str, Any]:
    for item in store.get("profiles", []):
        if isinstance(item, dict) and item.get("id") == profile_id:
            return item
    raise RuntimeError(f"{role} node {profile_id!r} is not linked")


def literal_ip(value: str, label: str) -> ipaddress._BaseAddress:
    try:
        return ipaddress.ip_address(str(value or "").strip().strip("[]"))
    except ValueError as exc:
        raise RuntimeError(f"{label} must be a literal IPv4/IPv6 address for the first strict multihop runtime") from exc


def endpoint_host(value: str, label: str) -> str:
    return str(literal_ip(value, label))


def patch_entry_conf(text: str, endpoint: str, socks_host: str) -> str:
    if "[Peer]" not in text or "Endpoint" not in text:
        raise RuntimeError("entry split config has no WireGuard/AmneziaWG peer endpoint")
    host = f"[{endpoint}]" if ":" in endpoint else endpoint

    def endpoint_repl(match: re.Match[str]) -> str:
        return f"{match.group(1)}{host}:{match.group(2)}"

    text, count = re.subn(r"(?mi)^(Endpoint\s*=\s*).*:(\d+)\s*$", endpoint_repl, text)
    if count != 1:
        raise RuntimeError("entry split config must contain exactly one Endpoint")
    socks_ip = literal_ip(socks_host, "entry SOCKS host")
    allowed = f"{socks_ip}/32" if socks_ip.version == 4 else f"{socks_ip}/128"
    text, count = re.subn(r"(?mi)^AllowedIPs\s*=.*$", f"AllowedIPs = {allowed}", text)
    if count != 1:
        raise RuntimeError("entry split config must contain exactly one AllowedIPs line")
    if re.search(r"(?mi)^AllowedIPs\s*=.*(?:0\.0\.0\.0/0|::/0)", text):
        raise RuntimeError("entry multihop config unexpectedly owns the default route")
    return text


def entry_source(root: Path, entry_id: str, base: str) -> tuple[Path, str, str]:
    generated = safe_under(root, root / "generated" / entry_id)
    if base == "wg":
        path = generated / "wg" / "wg-socks.conf"
        return path, "wg-quick", "wg.conf"
    if base == "awg":
        for mode in ("awg2-fast", "awg2-strong"):
            path = generated / mode / "awg-socks.conf"
            if path.is_file():
                return path, "awg-quick", "awg.conf"
        return generated / "awg2-fast" / "awg-socks.conf", "awg-quick", "awg.conf"
    raise RuntimeError("multihop entry base must be wg or awg")


def proxy_outbound(config: dict[str, Any]) -> dict[str, Any]:
    found = [x for x in config.get("outbounds", []) if isinstance(x, dict) and x.get("tag") == "proxy"]
    if len(found) != 1:
        raise RuntimeError("exit profile must contain exactly one proxy outbound")
    return found[0]


def reject_direct_routes(config: dict[str, Any]) -> None:
    route = config.get("route") if isinstance(config.get("route"), dict) else {}
    if route.get("final") == "direct":
        raise RuntimeError("exit profile routes final traffic directly")
    for rule in route.get("rules", []) if isinstance(route.get("rules"), list) else []:
        if isinstance(rule, dict) and rule.get("outbound") == "direct":
            raise RuntimeError("exit profile contains a direct escape route")


def patch_exit_config(config: dict[str, Any], exit_mode: str, exit_endpoint: str, entry: dict[str, Any]) -> dict[str, Any]:
    config = copy.deepcopy(config)
    proxy = proxy_outbound(config)
    expected = SUPPORTED_EXIT[exit_mode]
    if proxy.get("type") != expected:
        raise RuntimeError(f"{exit_mode} exit profile has unexpected outbound type {proxy.get('type')!r}")
    reject_direct_routes(config)
    proxy["server"] = exit_endpoint
    proxy["detour"] = "entry-hop"

    socks_host = str(entry.get("socks_host") or "").strip().strip("[]")
    socks_ip = literal_ip(socks_host, "entry SOCKS host")
    try:
        socks_port = int(entry.get("socks_port") or 1080)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("entry SOCKS port is invalid") from exc
    if not 1 <= socks_port <= 65535:
        raise RuntimeError("entry SOCKS port is invalid")
    hop: dict[str, Any] = {
        "type": "socks",
        "tag": "entry-hop",
        "server": str(socks_ip),
        "server_port": socks_port,
        "version": "5",
    }
    user = str(entry.get("socks_username") or "")
    password = str(entry.get("socks_password") or "")
    if bool(user) != bool(password):
        raise RuntimeError("entry SOCKS credentials are incomplete")
    if user:
        hop["username"] = user
        hop["password"] = password

    outbounds = [x for x in config.get("outbounds", []) if not (isinstance(x, dict) and x.get("tag") in {"direct", "entry-hop"})]
    outbounds.append(hop)
    config["outbounds"] = outbounds

    inbounds = [x for x in config.get("inbounds", []) if isinstance(x, dict) and x.get("tag") != "multihop-proof"]
    tun_found = False
    for inbound in inbounds:
        if inbound.get("type") == "tun":
            inbound["interface_name"] = "router-vpn"
            inbound["auto_route"] = True
            inbound["strict_route"] = True
            inbound["mtu"] = min(int(inbound.get("mtu") or 1280), 1280)
            tun_found = True
    if not tun_found:
        raise RuntimeError("exit profile has no full-device TUN inbound")
    inbounds.append({"type": "mixed", "tag": "multihop-proof", "listen": "127.0.0.1", "listen_port": PROOF_PORT, "users": []})
    config["inbounds"] = inbounds

    dns = config.get("dns") if isinstance(config.get("dns"), dict) else {}
    for server in dns.get("servers", []) if isinstance(dns.get("servers"), list) else []:
        if isinstance(server, dict):
            server["detour"] = "proxy"
    config["dns"] = dns
    route = config.get("route") if isinstance(config.get("route"), dict) else {}
    route["final"] = "proxy"
    route["auto_detect_interface"] = True
    config["route"] = route
    reject_direct_routes(config)
    return config


def _runtime_parent(path: Path) -> os.stat_result:
    parent = path.parent
    try:
        info = parent.lstat()
    except FileNotFoundError:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink multihop runtime parent: {parent}")
    return info


def write_private(path: Path, data: str) -> None:
    body = data.encode("utf-8")
    if not body or len(body) > MAX_RUNTIME_FILE_BYTES:
        raise RuntimeError(f"multihop runtime file is empty or oversized: {path}")
    parent_info = _runtime_parent(path)
    try:
        current = path.lstat()
    except FileNotFoundError:
        current = None
    if current is not None and (stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode)):
        raise RuntimeError(f"refusing non-regular/symlink multihop runtime target: {path}")

    fd, name = tempfile.mkstemp(prefix=f".{path.name}.multihop-", dir=path.parent)
    tmp = Path(name)
    committed = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        parent_current = _runtime_parent(path)
        if not os.path.samestat(parent_info, parent_current):
            raise RuntimeError(f"multihop runtime parent changed before adoption: {path.parent}")
        try:
            target = path.lstat()
        except FileNotFoundError:
            target = None
        if target is not None and (stat.S_ISLNK(target.st_mode) or not stat.S_ISREG(target.st_mode)):
            raise RuntimeError(f"multihop runtime target changed before adoption: {path}")
        os.replace(tmp, path)
        committed = True
        try:
            dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        if not committed:
            tmp.unlink(missing_ok=True)


def write_env(path: Path, values: dict[str, str]) -> None:
    lines = [f"{key}={shlex.quote(str(value))}" for key, value in values.items()]
    write_private(path, "\n".join(lines) + "\n")


def build(entry_id: str, exit_id: str, base: str, exit_mode: str, outdir: Path) -> dict[str, Any]:
    root = root_dir()
    entry_id = valid_id(entry_id, "entry id")
    exit_id = valid_id(exit_id, "exit id")
    if entry_id == exit_id:
        raise RuntimeError("multihop entry and exit nodes must be different")
    if exit_mode not in SUPPORTED_EXIT:
        raise RuntimeError("first multihop runtime supports only shadowsocks or hysteria2 exit transports")
    store = read_store(root)
    entry = profile(store, entry_id, "entry")
    exit_profile = profile(store, exit_id, "exit")
    entry_endpoint = endpoint_host(str(entry.get("endpoint") or ""), "entry endpoint")
    exit_endpoint = endpoint_host(str(exit_profile.get("endpoint") or ""), "exit endpoint")
    socks_host = str(entry.get("socks_host") or "").strip().strip("[]")
    literal_ip(socks_host, "entry SOCKS host")

    run_root = (root / "run").resolve()
    outdir = safe_under(run_root, outdir)
    if outdir.exists():
        shutil.rmtree(outdir)
    entry_dir = outdir / "entry"
    exit_dir = outdir / "exit"
    entry_dir.mkdir(parents=True, mode=0o700)

    source_conf, quick_tool, target_name = entry_source(root, entry_id, base)
    if not source_conf.is_file():
        raise RuntimeError(f"entry {base} split profile is missing: {source_conf}")
    entry_text = patch_entry_conf(source_conf.read_text(encoding="utf-8"), entry_endpoint, socks_host)
    entry_conf = entry_dir / target_name
    write_private(entry_conf, entry_text)

    exit_source = safe_under(root, root / "generated" / exit_id / exit_mode)
    if not exit_source.is_dir():
        raise RuntimeError(f"exit {exit_mode} profile is missing: {exit_source}")
    for source_path in exit_source.rglob("*"):
        if source_path.is_symlink():
            raise RuntimeError(f"exit multihop profile contains a symlink: {source_path}")
        if not source_path.is_dir() and not source_path.is_file():
            raise RuntimeError(f"exit multihop profile contains a non-regular entry: {source_path}")
    shutil.copytree(exit_source, exit_dir)
    exit_config = exit_dir / "sing-box.json"
    if not exit_config.is_file() or exit_config.is_symlink():
        raise RuntimeError("exit profile has no safe sing-box.json")
    raw_exit = json.loads(exit_config.read_text(encoding="utf-8"))
    patched = patch_exit_config(raw_exit, exit_mode, exit_endpoint, entry)
    write_private(exit_config, json.dumps(patched, indent=2) + "\n")
    for p in exit_dir.iterdir():
        if p.is_file():
            try:
                p.chmod(0o600)
            except OSError:
                pass

    proof_url = str(exit_profile.get("path_probe_url") or "http://10.77.0.1:8787/health")
    manifest = {
        "schema_version": 1,
        "entry_id": entry_id,
        "exit_id": exit_id,
        "entry_name": str(entry.get("name") or entry_id),
        "exit_name": str(exit_profile.get("name") or exit_id),
        "entry_endpoint": entry_endpoint,
        "exit_endpoint": exit_endpoint,
        "entry_base": base,
        "exit_mode": exit_mode,
        "entry_socks_host": socks_host,
        "entry_socks_port": int(entry.get("socks_port") or 1080),
        "proof_proxy": f"http://127.0.0.1:{PROOF_PORT}",
        "exit_path_probe_url": proof_url,
        "route": "client -> entry tunnel -> entry private SOCKS5 -> exit transport -> exit node -> Internet",
        "direct_exit_exception": False,
    }
    write_private(outdir / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    write_env(
        outdir / "runtime.env",
        {
            "ENTRY_ID": entry_id,
            "EXIT_ID": exit_id,
            "ENTRY_ENDPOINT": entry_endpoint,
            "EXIT_ENDPOINT": exit_endpoint,
            "ENTRY_SOCKS_HOST": socks_host,
            "ENTRY_SOCKS_PORT": str(manifest["entry_socks_port"]),
            "QUICK_TOOL": quick_tool,
            "ENTRY_CONF": str(entry_conf),
            "EXIT_DIR": str(exit_dir),
            "EXIT_CONFIG": str(exit_config),
            "EXIT_PROOF_URL": proof_url,
            "PROOF_PROXY": str(manifest["proof_proxy"]),
        },
    )
    return manifest


def main() -> int:
    try:
        if len(sys.argv) != 7 or sys.argv[1] != "build":
            print("usage: multihop.py build <entry-id> <exit-id> <wg|awg> <shadowsocks|hysteria2> <run-dir>", file=sys.stderr)
            return 2
        manifest = build(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], Path(sys.argv[6]))
        print(json.dumps(manifest, sort_keys=True))
        return 0
    except Exception as exc:
        print(f"multihop build error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
