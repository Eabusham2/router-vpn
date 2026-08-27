#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from unittest import mock

SCRIPT = pathlib.Path(__file__).with_name("mtu-policy.py")
SPEC = importlib.util.spec_from_file_location("router_vpn_mtu_policy", SCRIPT)
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def cache_entries(root: pathlib.Path) -> dict:
    path = root / "state" / "mtu-auto-cache.json"
    if not path.is_file():
        return {}
    data = json.loads(path.read_text())
    assert data.get("version") == 1
    assert isinstance(data.get("entries"), dict)
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    return data["entries"]


def run_case(policy: str, expected: int, probe: str = "", manual: int = 0, jumbo: bool = False) -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-mtu-") as td:
        root = pathlib.Path(td)
        conf = root / "run" / "profile-node-shadowsocks"
        conf.mkdir(parents=True)
        generated = root / "generated" / "node" / "shadowsocks"
        generated.mkdir(parents=True)
        (generated / "sing-box.json").write_text(json.dumps({"server": "203.0.113.10", "server_port": 8388}) + "\n")
        (root / "modes.json").write_text(json.dumps([{"id": "shadowsocks", "mtu": 1380}]) + "\n")
        profile = {"id": "node", "endpoint": "203.0.113.10", "mtu_policy": policy, "manual_mtu": manual}
        routers = root / "routers.json"
        routers.write_text(json.dumps({"selected_id": "node", "profiles": [profile]}) + "\n")
        routers.chmod(0o600)
        before = routers.read_bytes()
        (conf / "sing-box.json").write_text(json.dumps({"inbounds": [{"type": "tun", "tag": "tun-in", "mtu": 1280}]}) + "\n")
        (conf / "wg.conf").write_text("[Interface]\nPrivateKey = test\n")
        env = os.environ.copy()
        env.update(
            {
                "HOMEVPN_ROOT": str(root),
                "HOMEVPN_PROFILE_ID": "node",
                "HOMEVPN_MODE": "shadowsocks",
                "HOMEVPN_ENDPOINT": "203.0.113.10",
                "HOMEVPN_MTU": "1380",
                "HOMEVPN_JUMBO": "true" if jumbo else "false",
                "HOMEVPN_NETWORK_CONTEXT": "test-network-a",
            }
        )
        if probe:
            env["HOMEVPN_MTU_PROBE_RESULT"] = probe
        p = subprocess.run([sys.executable, str(SCRIPT), "apply", str(conf)], env=env, text=True, capture_output=True)
        assert p.returncode == 0, p.stderr
        sj = json.loads((conf / "sing-box.json").read_text())
        assert sj["inbounds"][0]["mtu"] == expected, (sj, p.stderr)
        assert f"MTU = {expected}" in (conf / "wg.conf").read_text()
        assert routers.read_bytes() == before, "runtime MTU policy mutated controller-owned routers.json"
        entries = cache_entries(root)
        if policy == "auto" and not jumbo:
            assert len(entries) == 1
            entry = next(iter(entries.values()))
            assert entry["effective_mtu"] == expected
            assert entry.get("network_fingerprint") != "test-network-a"
        else:
            assert entries == {}, f"non-auto runtime unexpectedly persisted MTU cache: {entries}"


def test_network_specific_cache() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-mtu-network-") as td:
        root = pathlib.Path(td)
        conf = root / "run" / "profile-node-shadowsocks"
        conf.mkdir(parents=True)
        generated = root / "generated" / "node" / "shadowsocks"
        generated.mkdir(parents=True)
        (generated / "sing-box.json").write_text(json.dumps({"server": "203.0.113.10", "server_port": 8388}) + "\n")
        (root / "modes.json").write_text(json.dumps([{"id": "shadowsocks", "mtu": 1380}]) + "\n")
        routers = root / "routers.json"
        routers.write_text(json.dumps({"selected_id": "node", "profiles": [{"id": "node", "endpoint": "203.0.113.10", "mtu_policy": "auto"}]}) + "\n")
        routers.chmod(0o600)
        before = routers.read_bytes()
        (conf / "sing-box.json").write_text(json.dumps({"inbounds": [{"type": "tun", "mtu": 1380}]}) + "\n")

        base = os.environ.copy()
        base.update(
            {
                "HOMEVPN_ROOT": str(root),
                "HOMEVPN_PROFILE_ID": "node",
                "HOMEVPN_MODE": "shadowsocks",
                "HOMEVPN_ENDPOINT": "203.0.113.10",
                "HOMEVPN_MTU": "1380",
                "HOMEVPN_JUMBO": "false",
            }
        )

        first = dict(base, HOMEVPN_NETWORK_CONTEXT="wifi-a", HOMEVPN_MTU_PROBE_RESULT="1400")
        p = subprocess.run([sys.executable, str(SCRIPT), "apply", str(conf)], env=first, text=True, capture_output=True)
        assert p.returncode == 0, p.stderr
        assert routers.read_bytes() == before
        entries = cache_entries(root)
        assert len(entries) == 1
        key_a, entry_a = next(iter(entries.items()))
        assert entry_a["effective_mtu"] == 1280
        fp_a = entry_a["network_fingerprint"]
        assert fp_a != "wifi-a"

        # Same network/path must reuse cached 1280 even though the fake probe
        # would now allow the catalog default.
        second = dict(base, HOMEVPN_NETWORK_CONTEXT="wifi-a", HOMEVPN_MTU_PROBE_RESULT="1500")
        p = subprocess.run([sys.executable, str(SCRIPT), "apply", str(conf)], env=second, text=True, capture_output=True)
        assert p.returncode == 0, p.stderr
        assert "auto-cache" in p.stderr
        assert routers.read_bytes() == before
        entries = cache_entries(root)
        assert entries[key_a]["effective_mtu"] == 1280

        # Network change must invalidate the old winner and retest, keeping the
        # old path measurement as a separate bounded cache entry.
        third = dict(base, HOMEVPN_NETWORK_CONTEXT="cellular-b", HOMEVPN_MTU_PROBE_RESULT="1500")
        p = subprocess.run([sys.executable, str(SCRIPT), "apply", str(conf)], env=third, text=True, capture_output=True)
        assert p.returncode == 0, p.stderr
        assert "auto-proven" in p.stderr
        assert routers.read_bytes() == before
        entries = cache_entries(root)
        assert len(entries) == 2
        new_keys = [key for key in entries if key != key_a]
        assert len(new_keys) == 1
        key_b = new_keys[0]
        assert entries[key_b]["effective_mtu"] == 1380
        assert entries[key_b]["network_fingerprint"] != fp_a
        assert entries[key_b]["network_fingerprint"] != "cellular-b"

        # Protocol/port/profile-input change must also invalidate the path key.
        (generated / "sing-box.json").write_text(json.dumps({"server": "203.0.113.10", "server_port": 443}) + "\n")
        fourth = dict(base, HOMEVPN_NETWORK_CONTEXT="cellular-b", HOMEVPN_MTU_PROBE_RESULT="1400")
        p = subprocess.run([sys.executable, str(SCRIPT), "apply", str(conf)], env=fourth, text=True, capture_output=True)
        assert p.returncode == 0, p.stderr
        assert routers.read_bytes() == before
        entries = cache_entries(root)
        newest = [item for key, item in entries.items() if key not in {key_a, key_b}]
        assert len(newest) == 1
        assert newest[0]["effective_mtu"] == 1280


def test_runtime_profile_symlink_is_never_followed() -> None:
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory(prefix="router-vpn-mtu-runtime-symlink-") as td:
        root = pathlib.Path(td)
        conf = root / "run" / "profile-node-shadowsocks"
        conf.mkdir(parents=True)
        generated = root / "generated" / "node" / "shadowsocks"
        generated.mkdir(parents=True)
        (generated / "sing-box.json").write_text(json.dumps({"server": "203.0.113.10", "server_port": 8388}) + "\n")
        (root / "modes.json").write_text(json.dumps([{"id": "shadowsocks", "mtu": 1380}]) + "\n")
        routers = root / "routers.json"
        routers.write_text(json.dumps({"selected_id": "node", "profiles": [{"id": "node", "endpoint": "203.0.113.10", "mtu_policy": "default"}]}) + "\n")
        routers.chmod(0o600)
        routers_before = routers.read_bytes()
        runtime = conf / "sing-box.json"
        runtime.write_text(json.dumps({"inbounds": [{"type": "tun", "mtu": 1280}]}) + "\n")
        runtime_before = runtime.read_bytes()
        outside = root / "outside.conf"
        outside.write_text("[Interface]\nMTU = 777\n")
        (conf / "escape.conf").symlink_to(outside)
        env = os.environ.copy()
        env.update({
            "HOMEVPN_ROOT": str(root), "HOMEVPN_PROFILE_ID": "node", "HOMEVPN_MODE": "shadowsocks",
            "HOMEVPN_ENDPOINT": "203.0.113.10", "HOMEVPN_MTU": "1380", "HOMEVPN_JUMBO": "false",
            "HOMEVPN_NETWORK_CONTEXT": "wifi-a",
        })
        p = subprocess.run([sys.executable, str(SCRIPT), "apply", str(conf)], env=env, text=True, capture_output=True)
        assert p.returncode != 0
        assert "symlink MTU runtime profile path" in p.stderr, p.stderr
        assert outside.read_text() == "[Interface]\nMTU = 777\n"
        assert runtime.read_bytes() == runtime_before, "runtime tree changed before symlink rejection"
        assert routers.read_bytes() == routers_before


def test_runtime_profile_late_adoption_failure_rolls_back() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-mtu-runtime-rollback-") as td:
        conf = pathlib.Path(td).resolve()
        first = conf / "a.json"
        second = conf / "b.conf"
        first.write_text(json.dumps({"inbounds": [{"type": "tun", "mtu": 1280}]}) + "\n")
        second.write_text("[Interface]\nMTU = 1280\n")
        before_first, before_second = first.read_bytes(), second.read_bytes()
        real_replace = MOD.os.replace
        calls = 0
        failed = False

        def fail_second_replace(src, dst):
            nonlocal calls, failed
            calls += 1
            if calls == 2 and not failed:
                failed = True
                raise OSError("injected second MTU adoption failure")
            return real_replace(src, dst)

        with mock.patch.object(MOD.os, "replace", side_effect=fail_second_replace):
            try:
                MOD.apply_tree(conf, 1380)
            except RuntimeError as exc:
                assert "prior runtime profile restored" in str(exc), exc
            else:
                raise AssertionError("late MTU runtime adoption failure was ignored")
        assert first.read_bytes() == before_first
        assert second.read_bytes() == before_second


def test_symlink_cache_is_never_followed() -> None:
    if os.name == "nt":
        return
    with tempfile.TemporaryDirectory(prefix="router-vpn-mtu-symlink-") as td:
        root = pathlib.Path(td)
        conf = root / "run" / "profile-node-shadowsocks"
        conf.mkdir(parents=True)
        generated = root / "generated" / "node" / "shadowsocks"
        generated.mkdir(parents=True)
        (generated / "sing-box.json").write_text(json.dumps({"server": "203.0.113.10", "server_port": 8388}) + "\n")
        (root / "modes.json").write_text(json.dumps([{"id": "shadowsocks", "mtu": 1380}]) + "\n")
        routers = root / "routers.json"
        routers.write_text(json.dumps({"selected_id": "node", "profiles": [{"id": "node", "endpoint": "203.0.113.10", "mtu_policy": "auto"}]}) + "\n")
        routers.chmod(0o600)
        before = routers.read_bytes()
        (conf / "sing-box.json").write_text(json.dumps({"inbounds": [{"type": "tun", "mtu": 1380}]}) + "\n")
        state = root / "state"
        state.mkdir()
        outside = root / "outside-cache"
        outside.write_text("do-not-touch\n")
        (state / "mtu-auto-cache.json").symlink_to(outside)
        env = os.environ.copy()
        env.update({
            "HOMEVPN_ROOT": str(root), "HOMEVPN_PROFILE_ID": "node", "HOMEVPN_MODE": "shadowsocks",
            "HOMEVPN_ENDPOINT": "203.0.113.10", "HOMEVPN_MTU": "1380", "HOMEVPN_JUMBO": "false",
            "HOMEVPN_MTU_PROBE_RESULT": "1400", "HOMEVPN_NETWORK_CONTEXT": "wifi-a",
        })
        p = subprocess.run([sys.executable, str(SCRIPT), "apply", str(conf)], env=env, text=True, capture_output=True)
        assert p.returncode == 0, p.stderr
        assert "cache was not persisted" in p.stderr
        assert outside.read_text() == "do-not-touch\n"
        assert routers.read_bytes() == before


run_case("default", 1380)
run_case("manual", 1312, manual=1312)
run_case("auto", 1380, probe="1500")
run_case("auto", 1280, probe="1400")
run_case("auto", 1380, probe="0")
run_case("auto", 9000, probe="1500", jumbo=True)
test_network_specific_cache()
test_runtime_profile_symlink_is_never_followed()
test_runtime_profile_late_adoption_failure_rolls_back()
test_symlink_cache_is_never_followed()
print("MTU policy tests: OK")
