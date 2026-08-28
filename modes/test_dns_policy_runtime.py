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
SPEC = importlib.util.spec_from_file_location("router_vpn_dns_policy", HERE / "dns-policy.py")
assert SPEC and SPEC.loader
DNS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DNS)


def base_config() -> dict:
    return {
        "log": {"level": "warn"},
        "outbounds": [
            {"type": "shadowsocks", "tag": "proxy", "server": "example.invalid", "server_port": 8388},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"rules": []},
    }


def policy() -> dict:
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


def write_config(path: Path, value) -> bytes:
    body = (json.dumps(value, indent=2) + "\n").encode()
    path.write_bytes(body)
    os.chmod(path, 0o600)
    return body


def test_atomic_patch() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-dns-runtime-") as td:
        root = Path(td)
        path = root / "sing-box.json"
        write_config(path, base_config())
        DNS.patch_sing(path, policy())
        value = json.loads(path.read_text())
        server = value["dns"]["servers"][0]
        assert server["tag"] == "selected-dns"
        assert server["detour"] == "proxy"
        assert server["type"] == "https"
        assert server["tls"]["server_name"] == "cloudflare-dns.com"
        assert value["route"]["rules"][0] == {"protocol": "dns", "action": "hijack-dns"}
        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o600
        assert not list(root.glob(".sing-box.json.dns-*"))


def test_replace_failure_preserves_original() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-dns-runtime-fail-") as td:
        root = Path(td)
        path = root / "sing-box.json"
        original = write_config(path, base_config())
        with mock.patch.object(DNS.os, "replace", side_effect=OSError("injected adoption failure")):
            try:
                DNS.patch_sing(path, policy())
            except OSError:
                pass
            else:
                raise AssertionError("injected DNS adoption failure did not fail")
        assert path.read_bytes() == original, "failed DNS adoption changed the authoritative runtime config"
        assert not list(root.glob(".sing-box.json.dns-*")), "failed DNS adoption leaked a temp file"


def test_foreign_regular_replacement_rejected() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-dns-runtime-swap-") as td:
        root = Path(td)
        path = root / "sing-box.json"
        write_config(path, base_config())
        foreign = root / "foreign.json"
        foreign_body = write_config(foreign, {"foreign": True})
        real_mkstemp = DNS.tempfile.mkstemp

        def mkstemp_then_swap(*args, **kwargs):
            fd, name = real_mkstemp(*args, **kwargs)
            os.replace(foreign, path)
            return fd, name

        with mock.patch.object(DNS.tempfile, "mkstemp", side_effect=mkstemp_then_swap):
            try:
                DNS.patch_sing(path, policy())
            except RuntimeError as exc:
                assert "target identity changed before adoption" in str(exc)
            else:
                raise AssertionError("DNS runtime patch overwrote a foreign regular replacement")
        assert path.read_bytes() == foreign_body
        assert not list(root.glob(".sing-box.json.dns-*"))


def test_symlink_target_rejected() -> None:
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory(prefix="router-vpn-dns-runtime-link-") as td:
        root = Path(td)
        real = root / "real.json"
        link = root / "sing-box.json"
        original = write_config(real, base_config())
        link.symlink_to(real)
        try:
            DNS.patch_sing(link, policy())
        except RuntimeError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("DNS runtime patch followed a symlink target")
        assert real.read_bytes() == original


def test_invalid_and_oversized_rejected() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-dns-runtime-invalid-") as td:
        root = Path(td)
        non_object = root / "array.json"
        write_config(non_object, [])
        try:
            DNS.patch_sing(non_object, policy())
        except RuntimeError as exc:
            assert "JSON object" in str(exc)
        else:
            raise AssertionError("DNS runtime accepted a non-object config")

        oversized = root / "large.json"
        oversized.write_bytes(b"{" + b" " * 128 + b"}")
        os.chmod(oversized, 0o600)
        old = DNS.MAX_RUNTIME_CONFIG_BYTES
        DNS.MAX_RUNTIME_CONFIG_BYTES = 64
        try:
            try:
                DNS.patch_sing(oversized, policy())
            except RuntimeError as exc:
                assert "safety limit" in str(exc)
            else:
                raise AssertionError("DNS runtime accepted an oversized config")
        finally:
            DNS.MAX_RUNTIME_CONFIG_BYTES = old


def main() -> int:
    test_atomic_patch()
    test_replace_failure_preserves_original()
    test_foreign_regular_replacement_rejected()
    test_symlink_target_rejected()
    test_invalid_and_oversized_rejected()
    print("DNS runtime atomic adoption tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
