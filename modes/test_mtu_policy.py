#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

SCRIPT = pathlib.Path(__file__).with_name("mtu-policy.py")


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
        (root / "routers.json").write_text(json.dumps({"selected_id": "node", "profiles": [profile]}) + "\n")
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
        store = json.loads((root / "routers.json").read_text())
        assert store["profiles"][0]["effective_mtu"] == expected
        assert store["profiles"][0].get("effective_mtu_network_fingerprint") != "test-network-a"


def test_network_specific_cache() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-mtu-network-") as td:
        root = pathlib.Path(td)
        conf = root / "run" / "profile-node-shadowsocks"
        conf.mkdir(parents=True)
        generated = root / "generated" / "node" / "shadowsocks"
        generated.mkdir(parents=True)
        (generated / "sing-box.json").write_text(json.dumps({"server": "203.0.113.10", "server_port": 8388}) + "\n")
        (root / "modes.json").write_text(json.dumps([{"id": "shadowsocks", "mtu": 1380}]) + "\n")
        (root / "routers.json").write_text(json.dumps({"selected_id": "node", "profiles": [{"id": "node", "endpoint": "203.0.113.10", "mtu_policy": "auto"}]}) + "\n")
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
        store = json.loads((root / "routers.json").read_text())
        profile = store["profiles"][0]
        assert profile["effective_mtu"] == 1280
        key_a = profile["effective_mtu_path_key"]
        fp_a = profile["effective_mtu_network_fingerprint"]
        assert fp_a != "wifi-a"

        # Same network/path must reuse the cached 1280 even though the fake
        # probe would now allow the catalog default.
        second = dict(base, HOMEVPN_NETWORK_CONTEXT="wifi-a", HOMEVPN_MTU_PROBE_RESULT="1500")
        p = subprocess.run([sys.executable, str(SCRIPT), "apply", str(conf)], env=second, text=True, capture_output=True)
        assert p.returncode == 0, p.stderr
        assert "auto-cache" in p.stderr
        store = json.loads((root / "routers.json").read_text())
        assert store["profiles"][0]["effective_mtu"] == 1280
        assert store["profiles"][0]["effective_mtu_path_key"] == key_a

        # Network change must invalidate the old winner and retest.
        third = dict(base, HOMEVPN_NETWORK_CONTEXT="cellular-b", HOMEVPN_MTU_PROBE_RESULT="1500")
        p = subprocess.run([sys.executable, str(SCRIPT), "apply", str(conf)], env=third, text=True, capture_output=True)
        assert p.returncode == 0, p.stderr
        assert "auto-proven" in p.stderr
        store = json.loads((root / "routers.json").read_text())
        profile = store["profiles"][0]
        assert profile["effective_mtu"] == 1380
        assert profile["effective_mtu_path_key"] != key_a
        assert profile["effective_mtu_network_fingerprint"] != fp_a
        assert profile["effective_mtu_network_fingerprint"] != "cellular-b"

        # Protocol/port/profile-input change must also invalidate the path key.
        (generated / "sing-box.json").write_text(json.dumps({"server": "203.0.113.10", "server_port": 443}) + "\n")
        fourth = dict(base, HOMEVPN_NETWORK_CONTEXT="cellular-b", HOMEVPN_MTU_PROBE_RESULT="1400")
        old_key = profile["effective_mtu_path_key"]
        p = subprocess.run([sys.executable, str(SCRIPT), "apply", str(conf)], env=fourth, text=True, capture_output=True)
        assert p.returncode == 0, p.stderr
        store = json.loads((root / "routers.json").read_text())
        assert store["profiles"][0]["effective_mtu_path_key"] != old_key
        assert store["profiles"][0]["effective_mtu"] == 1280


run_case("default", 1380)
run_case("manual", 1312, manual=1312)
run_case("auto", 1380, probe="1500")
run_case("auto", 1280, probe="1400")
run_case("auto", 1380, probe="0")  # filtered/unavailable -> safe default
run_case("auto", 9000, probe="1500", jumbo=True)
test_network_specific_cache()
print("MTU policy tests: OK")
