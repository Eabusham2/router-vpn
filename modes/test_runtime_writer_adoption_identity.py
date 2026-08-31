#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PIDS = load("router_vpn_runtime_pids_identity", "runtime-pids.py")
CONFIG = load("router_vpn_runtime_config_identity", "runtime-config.py")
DNS = load("router_vpn_dns_policy_identity", "dns-policy.py")


def private_file(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    os.chmod(path, 0o600)


def replace_then_foreign_swap(module, target: Path, foreign: Path):
    real_replace = module.os.replace
    swapped = False

    def side_effect(src, dst):
        nonlocal swapped
        result = real_replace(src, dst)
        if Path(dst) == target and not swapped:
            swapped = True
            real_replace(foreign, target)
        return result

    return side_effect


def test_runtime_pid_post_rename_swap(root: Path) -> None:
    run = PIDS.run_dir(str(root))
    target = run / "wg.pids"
    PIDS.atomic_write(target, [])
    foreign = run / "foreign.pids"
    foreign_body = b'{"version":1,"pid":999999,"start":"foreign","command_sha256":"deadbeef"}\n'
    private_file(foreign, foreign_body)

    with mock.patch.object(
        PIDS.os,
        "replace",
        side_effect=replace_then_foreign_swap(PIDS, target, foreign),
    ):
        try:
            PIDS.atomic_write(target, [])
        except RuntimeError as exc:
            assert "adopted runtime PID registry identity changed" in str(exc)
        else:
            raise AssertionError("runtime PID writer accepted a foreign post-rename replacement")

    assert target.read_bytes() == foreign_body
    assert not list(run.glob(".wg.pids.pid-*"))


def test_runtime_config_post_rename_swap(root: Path) -> None:
    run = root / "run"
    run.mkdir(exist_ok=True)
    os.chmod(run, 0o700)
    target = run / "runtime.json"
    private_file(target, b'{"old":true}\n')
    foreign = run / "foreign-runtime.json"
    foreign_body = b'{"foreign":true}\n'
    private_file(foreign, foreign_body)

    with mock.patch.object(
        CONFIG.os,
        "replace",
        side_effect=replace_then_foreign_swap(CONFIG, target, foreign),
    ):
        try:
            CONFIG.atomic_write(str(root), str(target), b'{"new":true}\n')
        except RuntimeError as exc:
            assert "adopted runtime config identity changed" in str(exc)
        else:
            raise AssertionError("runtime config writer accepted a foreign post-rename replacement")

    assert target.read_bytes() == foreign_body
    assert not list(run.glob(".runtime.json.runtime-*"))


def test_runtime_config_read_replacement_rejected(root: Path) -> None:
    run = root / "run"
    run.mkdir(exist_ok=True)
    os.chmod(run, 0o700)
    target = run / "read.json"
    private_file(target, b'{"owned":true}\n')
    foreign = run / "foreign-read.json"
    foreign_body = b'{"foreign":true}\n'
    private_file(foreign, foreign_body)
    real_read = CONFIG.os.read
    swapped = False

    def read_then_swap(fd: int, count: int) -> bytes:
        nonlocal swapped
        chunk = real_read(fd, count)
        if not swapped:
            swapped = True
            os.replace(foreign, target)
        return chunk

    with mock.patch.object(CONFIG.os, "read", side_effect=read_then_swap):
        try:
            CONFIG.read_bytes(str(root), str(target))
        except RuntimeError as exc:
            assert "changed during read" in str(exc)
        else:
            raise AssertionError("runtime config reader accepted a foreign replacement")

    assert target.read_bytes() == foreign_body


def dns_config() -> dict:
    return {
        "log": {"level": "warn"},
        "outbounds": [
            {"type": "shadowsocks", "tag": "proxy", "server": "example.invalid", "server_port": 8388},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"rules": []},
    }


def dns_policy() -> dict:
    return {
        "mode": "custom",
        "protocol": "https",
        "host": "1.1.1.1",
        "port": 443,
        "server_name": "cloudflare-dns.com",
        "path": "/dns-query",
        "fastest_name": "test",
        "fastest_latency_ms": 1.0,
    }


def test_dns_runtime_post_rename_swap(root: Path) -> None:
    target = root / "dns-runtime.json"
    private_file(target, (json.dumps(dns_config()) + "\n").encode())
    foreign = root / "foreign-dns.json"
    foreign_body = b'{"foreign":true}\n'
    private_file(foreign, foreign_body)

    with mock.patch.object(
        DNS.os,
        "replace",
        side_effect=replace_then_foreign_swap(DNS, target, foreign),
    ):
        try:
            DNS.patch_sing(target, dns_policy())
        except RuntimeError as exc:
            assert "adopted runtime DNS config identity changed" in str(exc)
        else:
            raise AssertionError("DNS runtime writer accepted a foreign post-rename replacement")

    assert target.read_bytes() == foreign_body
    assert not list(root.glob(".dns-runtime.json.dns-*"))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-runtime-writer-identity-") as td:
        root = Path(td)
        test_runtime_pid_post_rename_swap(root)
        test_runtime_config_post_rename_swap(root)
        test_runtime_config_read_replacement_rejected(root)
        test_dns_runtime_post_rename_swap(root)
    print("Runtime writer adoption identity tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
