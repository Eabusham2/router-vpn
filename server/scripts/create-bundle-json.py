#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile

MAX_PRIVATE_JSON = 32 << 20


def write_private_json(path: pathlib.Path, value: object) -> None:
    body = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    if not body or len(body) > MAX_PRIVATE_JSON:
        raise RuntimeError(f"private JSON output is empty or oversized: {path}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        info = path.lstat()
    except FileNotFoundError:
        info = None
    if info is not None and (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)):
        raise RuntimeError(f"refusing non-regular/symlink private JSON target: {path}")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    tmp = pathlib.Path(name)
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


def read_optional_private_json(path: pathlib.Path) -> dict:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {}
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink private JSON input: {path}")
    if info.st_size > MAX_PRIVATE_JSON:
        raise RuntimeError(f"private JSON input is oversized: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else {}


base = pathlib.Path(sys.argv[1])
endpoint, token, router_api, socks_host, socks_user, socks_password = sys.argv[2:8]
proof_script = pathlib.Path(__file__).with_name("ensure-node-proof.py")
subprocess.run([sys.executable, str(proof_script), str(base)], check=True, stdout=subprocess.DEVNULL)
agent_config = json.loads((base / "config" / "router-agent.json").read_text(encoding="utf-8"))
node_proof_id = str(agent_config.get("node_id") or "").strip()
if not re.fullmatch(r"[0-9a-f]{64}", node_proof_id):
    raise SystemExit("router-agent node proof id is missing or invalid")
modes = json.loads((base / "client-bundle/modes.json").read_text(encoding="utf-8"))
logical_path = base / "client-bundle" / "logical-modes.json"
if not logical_path.is_file():
    logical_path = pathlib.Path(__file__).resolve().parents[2] / "configs" / "client" / "logical-modes.json"
try:
    logical_modes = json.loads(logical_path.read_text(encoding="utf-8"))
except Exception:
    logical_modes = []
profiles: dict[str, dict[str, str]] = {}
for mode_dir in (base / "client-bundle/generated").glob("*"):
    if not mode_dir.is_dir():
        continue
    files: dict[str, str] = {}
    for path in mode_dir.iterdir():
        if path.is_file() and not path.is_symlink():
            files[path.name] = base64.b64encode(path.read_bytes()).decode()
    if files:
        profiles[mode_dir.name] = files

dns_benchmark = read_optional_private_json(base / "config" / "dns-fastest.json")
winner = dns_benchmark.get("winner") or {}
dns_results = dns_benchmark.get("results") or []
fastest_host = str(winner.get("address") or "1.1.1.1")
fastest_name = str(winner.get("name") or "Cloudflare IPv4 fallback")
fastest_latency = winner.get("latency_ms")
try:
    fastest_latency = float(fastest_latency) if fastest_latency is not None else 0.0
except Exception:
    fastest_latency = 0.0

setup_assets = read_optional_private_json(base / "client-bundle" / "setup-assets.json")

router_profile = {
    "schema_version": 4,
    "id": "home",
    "name": "Home Router",
    "node_kind": "router-vpn",
    "node_proof_id": node_proof_id,
    "endpoint": endpoint,
    "router_api": router_api,
    "api_token": token,
    "adguard_ipv4": socks_host,
    "adguard_ipv6": "fd77:77::1",
    "socks_host": socks_host,
    "socks_port": 1080,
    "socks_username": socks_user,
    "socks_password": socks_password,
    "daita_host": socks_host,
    "daita_port": 45999,
    "daita_rate_kbps": 192,
    "base_tunnel": "auto",
    "base_fallback": True,
    "custom_layers": [],
    "home_lan_access": True,
    "home_lan_cidrs": ["192.168.50.0/24"],
    "kill_switch": False,
    "kill_switch_policy": "off",
    "ipv6_mode": "on",
    "startup_mode": "smart-auto",
    "auto_connect": False,
    "auto_require_encrypted": False,
    "auto_require_obfuscation": False,
    "multihop_enabled": False,
    "multihop_entry_id": "",
    "multihop_exit_id": "",
    "mtu_policy": "auto",
    "manual_mtu": 0,
    "effective_mtu": 0,
    "effective_mtu_source": "",
    "effective_mtu_path_key": "",
    "effective_underlay_pmtu": 0,
    "effective_mtu_tested_at": "",
    "diagnostics_enabled": False,
    "diagnostics_retention_days": 7,
    "share_diagnostics": False,
    "telemetry_enabled": False,
    "path_probe_url": "http://10.77.0.1:8787/health",
    "location": "Home",
    "use_count": 0,
    "dns_mode": "home",
    "dns_protocol": "udp",
    "dns_host": socks_host,
    "dns_port": 53,
    "dns_server_name": "",
    "dns_path": "/dns-query",
    "fastest_dns_host": fastest_host,
    "fastest_dns_name": fastest_name,
    "fastest_dns_latency_ms": fastest_latency,
    "dns_results": dns_results,
}
client_config = {
    "listen": "127.0.0.1:8788",
    "health_url": "http://10.77.0.1:8787/health",
    "auto_test_seconds": 8,
    "modes_file": "./modes.json",
    "state_file": "./state.json",
    "scripts_dir": "./modes",
    "profiles_file": "./routers.json",
}
write_private_json(base / "client-bundle" / "client.json", client_config)
write_private_json(
    base / "client-bundle" / "routers.json",
    {"schema_version": 4, "selected_id": "home", "profiles": [router_profile]},
)
bundle = {
    "bundleVersion": 4,
    "profileSchemaVersion": 4,
    "nodeProofId": node_proof_id,
    "endpoint": endpoint,
    "apiToken": token,
    "routerAPI": router_api,
    "adGuardIPv4": socks_host,
    "adGuardIPv6": "fd77:77::1",
    "socks5Host": socks_host,
    "socks5Port": 1080,
    "socks5Username": socks_user,
    "socks5Password": socks_password,
    "dnsBenchmark": dns_benchmark,
    "setupAssets": setup_assets,
    "routerProfiles": [router_profile],
    "selectedRouterID": "home",
    "logicalModes": logical_modes,
    "modes": modes,
    "profiles": profiles,
}
write_private_json(base / "client-bundle" / "router-vpn-bundle.json", bundle)
