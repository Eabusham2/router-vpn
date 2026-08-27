#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("router_vpn_runtime_config", HERE / "runtime-config.py")
assert SPEC and SPEC.loader
CFG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CFG)


def private(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    os.chmod(path, 0o600)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-runtime-config-") as td:
        root = Path(td)
        run = root / "run"
        conf = run / "profile-home-wg"
        conf.mkdir(parents=True)

        wg = conf / "wg.conf"
        private(wg, "[Interface]\nAddress = 10.77.0.2/24\n[Peer]\nEndpoint = 203.0.113.1:51820\n")
        CFG.patch_kernel_dns(str(root), str(wg))
        assert "DNS = 127.0.0.1" in wg.read_text()
        if os.name != "nt":
            assert wg.stat().st_mode & 0o777 == 0o600

        rp = conf / "rosenpass.toml"
        private(rp, 'endpoint = "router.invalid:51822"\n')
        CFG.patch_rosenpass(str(root), str(rp), "2001:db8::1", "51822")
        assert 'endpoint = "[2001:db8::1]:51822"' in rp.read_text()

        ss = conf / "sslocal.json"
        private(ss, json.dumps({"server": "router.invalid", "local_port": 1092}) + "\n")
        CFG.sslocal_endpoint(str(root), str(ss), "203.0.113.8")
        assert json.loads(ss.read_text())["server"] == "203.0.113.8"
        ss_socks = run / "ss-v2ray-socks.json"
        CFG.sslocal_socks(str(root), str(ss), str(ss_socks))
        assert json.loads(ss_socks.read_text())["local_port"] == 1080

        sing = conf / "sing-box.json"
        private(sing, json.dumps({"inbounds": [{"type": "tun", "mtu": 1380}], "outbounds": []}) + "\n")
        socks = run / "socks.json"
        jumbo = run / "jumbo.json"
        CFG.sing_variant(str(root), str(sing), str(socks), "socks")
        CFG.sing_variant(str(root), str(sing), str(jumbo), "jumbo")
        assert json.loads(socks.read_text())["inbounds"][0]["type"] == "socks"
        assert json.loads(jumbo.read_text())["inbounds"][0]["mtu"] == 9000

        local = run / "local-socks.json"
        CFG.local_socks(str(root), str(local), "10.77.0.1", "1080")
        assert json.loads(local.read_text())["outbounds"][0]["server"] == "10.77.0.1"

        hint = run / "dns.txt"
        CFG.dns_hint(str(root), str(hint), "home", "udp", "10.77.0.1", "53")
        assert hint.read_text() == "mode=home\nprotocol=udp\nserver=10.77.0.1:53\n"

        # Atomic replacement failure preserves prior complete bytes and cleans temp.
        original = wg.read_bytes()
        with mock.patch.object(CFG.os, "replace", side_effect=OSError("injected runtime config adoption failure")):
            try:
                CFG.patch_kernel_dns(str(root), str(wg))
            except OSError:
                pass
            else:
                raise AssertionError("injected runtime config adoption failure did not fail")
        assert wg.read_bytes() == original
        assert not list(conf.glob(".wg.conf.runtime-*"))

        # A same-type target swap after staging must be detected by inode
        # identity, not merely by checking that the replacement is a regular file.
        race = conf / "race.json"
        foreign = conf / "foreign.json"
        private(race, "old-owned\n")
        private(foreign, "foreign-replacement\n")
        real_trusted_path = CFG.trusted_path
        trusted_calls = 0

        def swap_target_on_recheck(root_text, path_text, *, must_exist=False):
            nonlocal trusted_calls
            result = real_trusted_path(root_text, path_text, must_exist=must_exist)
            if Path(path_text) == race:
                trusted_calls += 1
                if trusted_calls == 2:
                    os.replace(foreign, race)
            return result

        with mock.patch.object(CFG, "trusted_path", side_effect=swap_target_on_recheck):
            try:
                CFG.atomic_write(str(root), str(race), b"new-owned\n")
            except RuntimeError as exc:
                assert "target identity changed" in str(exc)
            else:
                raise AssertionError("runtime config replacement race was accepted")
        assert race.read_text(encoding="utf-8") == "foreign-replacement\n"
        assert not list(conf.glob(".race.json.runtime-*"))

        outside = root / "outside.conf"
        private(outside, "keep\n")
        try:
            CFG.patch_kernel_dns(str(root), str(outside))
        except RuntimeError as exc:
            assert "HOMEVPN_ROOT/run" in str(exc)
        else:
            raise AssertionError("runtime config mutation escaped run directory")
        assert outside.read_text() == "keep\n"

    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix="router-vpn-runtime-config-link-") as td:
            root = Path(td)
            run = root / "run"
            run.mkdir()
            real = root / "real.conf"
            private(real, "[Interface]\n")
            link = run / "wg.conf"
            link.symlink_to(real)
            try:
                CFG.patch_kernel_dns(str(root), str(link))
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("runtime config mutation followed a symlink target")
            assert real.read_text() == "[Interface]\n"

            outside = root / "outside"
            outside.mkdir()
            linked = run / "linked"
            linked.symlink_to(outside, target_is_directory=True)
            try:
                CFG.local_socks(str(root), str(linked / "proxy.json"), "10.77.0.1", "1080")
            except RuntimeError as exc:
                assert "symlink" in str(exc) or "HOMEVPN_ROOT/run" in str(exc)
            else:
                raise AssertionError("runtime config mutation followed a symlink ancestor")
            assert not (outside / "proxy.json").exists()

    print("Atomic runtime config mutation tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
