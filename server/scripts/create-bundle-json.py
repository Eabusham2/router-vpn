#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import pathlib
import re
import runpy
import stat
import subprocess
import sys
import tempfile

MAX_PRIVATE_JSON = 32 << 20
SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
VERIFIED = runpy.run_path(str(SCRIPT_DIR / "verified-regular-read.py"))
PRIVATE_WRITE = runpy.run_path(str(SCRIPT_DIR / "atomic-private-write.py"))
PRIVATE_DIR = runpy.run_path(str(SCRIPT_DIR / "private-directory.py"))
read_verified_regular = VERIFIED["read_verified_regular"]
atomic_private_write = PRIVATE_WRITE["atomic_private_write"]
validate_existing_ancestors = PRIVATE_DIR["validate_existing_ancestors"]


def encoded_json(value: object) -> bytes:
    body = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    if not body or len(body) > MAX_PRIVATE_JSON:
        raise RuntimeError("private JSON output is empty or oversized")
    return body


def write_private_json(path: pathlib.Path, value: object) -> None:
    # Retained as a reusable single-file primitive. Canonical node metadata is
    # committed below with write_private_json_batch.
    atomic_private_write(path, encoded_json(value))


def write_private_json_batch(items: list[tuple[pathlib.Path, object]]) -> None:
    if not items:
        raise RuntimeError("private JSON batch is empty")
    parents = {path.parent for path, _ in items}
    if len(parents) != 1:
        raise RuntimeError("private JSON batch destinations must share one parent")
    parent = next(iter(parents))
    PRIVATE_WRITE["ensure_private_parent"](parent / ".bundle-json-parent-probe")
    with tempfile.TemporaryDirectory(prefix=".bundle-json.", dir=parent) as td:
        stage = pathlib.Path(td)
        argv = [sys.executable, str(SCRIPT_DIR / "atomic-private-batch.py")]
        for index, (dest, value) in enumerate(items):
            staged = stage / f"{index}.json"
            staged.write_bytes(encoded_json(value))
            staged.chmod(0o600)
            argv.append(f"{dest}={staged}")
        subprocess.run(argv, check=True)


def decode_json(body: bytes, path: pathlib.Path, expected: type):
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid JSON bundle source: {path}: {exc}") from exc
    if not isinstance(value, expected):
        raise RuntimeError(f"bundle source has wrong JSON type: {path}")
    return value


def read_json(path: pathlib.Path, *, private: bool, optional: bool = False, expected: type = dict):
    try:
        body = read_verified_regular(path, MAX_PRIVATE_JSON, private=private)
    except FileNotFoundError:
        if optional:
            return expected()
        raise RuntimeError(f"required bundle source is missing: {path}")
    return decode_json(body, path, expected)


def read_optional_private_json(path: pathlib.Path) -> dict:
    return read_json(path, private=True, optional=True, expected=dict)


def read_generated_profiles(root: pathlib.Path) -> dict[str, dict[str, str]]:
    root = pathlib.Path(os.path.abspath(root))
    validate_existing_ancestors(root)
    root_before = root.lstat()
    if stat.S_ISLNK(root_before.st_mode) or not stat.S_ISDIR(root_before.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink generated profile root: {root}")

    profiles: dict[str, dict[str, str]] = {}
    for mode_dir in sorted(root.iterdir(), key=lambda p: p.name):
        info = mode_dir.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError(f"refusing symlink generated profile entry: {mode_dir}")
        if stat.S_ISREG(info.st_mode):
            # Root-level catalogs/manifests are not mode directories.
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"refusing non-regular generated profile entry: {mode_dir}")
        mode_identity = (info.st_dev, info.st_ino)
        files: dict[str, str] = {}
        for path in sorted(mode_dir.iterdir(), key=lambda p: p.name):
            item = path.lstat()
            if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
                raise RuntimeError(f"generated mode contains non-regular/symlink entry: {path}")
            body = read_verified_regular(path, MAX_PRIVATE_JSON, private=True)
            files[path.name] = base64.b64encode(body).decode()
        current = mode_dir.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != mode_identity:
            raise RuntimeError(f"generated mode directory changed during read: {mode_dir}")
        if files:
            profiles[mode_dir.name] = files

    root_after = root.lstat()
    if stat.S_ISLNK(root_after.st_mode) or not stat.S_ISDIR(root_after.st_mode) or (root_after.st_dev, root_after.st_ino) != (root_before.st_dev, root_before.st_ino):
        raise RuntimeError("generated profile root changed during read")
    return profiles

base = pathlib.Path(os.path.abspath(sys.argv[1]))
endpoint, token, router_api, socks_host, socks_user, socks_password = sys.argv[2:8]
proof_script = SCRIPT_DIR / "ensure-node-proof.py"
subprocess.run([sys.executable, str(proof_script), str(base)], check=True, stdout=subprocess.DEVNULL)
agent_config = read_json(base / "config" / "router-agent.json", private=True, expected=dict)
node_proof_id = str(agent_config.get("node_id") or "").strip()
if not re.fullmatch(r"[0-9a-f]{64}", node_proof_id):
    raise SystemExit("router-agent node proof id is missing or invalid")
modes = read_json(base / "client-bundle/modes.json", private=True, expected=list)
logical_path = base / "client-bundle" / "logical-modes.json"
try:
    logical_path.lstat()
except FileNotFoundError:
    logical_modes = read_json(
        pathlib.Path(__file__).resolve().parents[2] / "configs" / "client" / "logical-modes.json",
        private=False,
        expected=list,
    )
else:
    logical_modes = read_json(logical_path, private=True, expected=list)
profiles = read_generated_profiles(base / "client-bundle/generated")

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
routers_store = {"schema_version": 4, "selected_id": "home", "profiles": [router_profile]}
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
write_private_json_batch(
    [
        (base / "client-bundle" / "client.json", client_config),
        (base / "client-bundle" / "routers.json", routers_store),
        (base / "client-bundle" / "router-vpn-bundle.json", bundle),
    ]
)
