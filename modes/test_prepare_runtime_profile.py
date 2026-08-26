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
SPEC = importlib.util.spec_from_file_location("router_vpn_prepare_runtime", HERE / "prepare-runtime-profile.py")
assert SPEC and SPEC.loader
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)


def make_source(root: Path) -> Path:
    source = root / "generated" / "home" / "hysteria2"
    source.mkdir(parents=True)
    (source / "cert.pem").write_text("cert\n", encoding="utf-8")
    os.chmod(source / "cert.pem", 0o600)
    cfg = {
        "inbounds": [{"type": "tun", "tag": "tun-in"}],
        "outbounds": [{"type": "hysteria2", "tag": "proxy", "server": "router.invalid", "server_port": 8443, "tls": {"enabled": True, "certificate_path": "cert.pem"}}],
        "route": {"final": "proxy"},
    }
    (source / "sing-box.json").write_text(json.dumps(cfg) + "\n", encoding="utf-8")
    os.chmod(source / "sing-box.json", 0o600)
    return source


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-runtime-stage-") as td:
        root = Path(td)
        make_source(root)
        dest = PREP.prepare(str(root), "home", "hysteria2", "203.0.113.9")
        assert dest == root / "run" / "profile-home-hysteria2"
        cfg = json.loads((dest / "sing-box.json").read_text())
        proxy = cfg["outbounds"][0]
        assert proxy["server"] == "203.0.113.9"
        assert proxy["tls"]["certificate_path"] == str(dest / "cert.pem")
        assert not list((root / "run").glob(".profile-home-hysteria2.stage-*"))
        if os.name != "nt":
            assert (dest / "sing-box.json").stat().st_mode & 0o777 == 0o600

        # A second successful preparation atomically replaces the old tree.
        (root / "generated" / "home" / "hysteria2" / "new.txt").write_text("new\n")
        os.chmod(root / "generated" / "home" / "hysteria2" / "new.txt", 0o600)
        PREP.prepare(str(root), "home", "hysteria2", "203.0.113.10")
        assert (dest / "new.txt").read_text() == "new\n"
        cfg = json.loads((dest / "sing-box.json").read_text())
        assert cfg["outbounds"][0]["server"] == "203.0.113.10"

        # Inject failure when staged tree is adopted after the prior tree was
        # moved aside; the old complete tree must be restored.
        before = (dest / "sing-box.json").read_bytes()
        real_rename = PREP.os.rename

        def fail_stage_to_dest(src, dst):
            if Path(dst) == dest and ".stage-" in Path(src).name:
                raise OSError("injected runtime profile adoption failure")
            return real_rename(src, dst)

        with mock.patch.object(PREP.os, "rename", side_effect=fail_stage_to_dest):
            try:
                PREP.prepare(str(root), "home", "hysteria2", "203.0.113.11")
            except OSError:
                pass
            else:
                raise AssertionError("injected runtime profile adoption failure did not fail")
        assert (dest / "sing-box.json").read_bytes() == before, "failed runtime tree adoption did not restore prior tree"
        assert not list((root / "run").glob(".profile-home-hysteria2.stage-*"))

    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix="router-vpn-runtime-stage-link-") as td:
            root = Path(td)
            source = make_source(root)
            outside = root / "outside"
            outside.write_text("keep\n")
            os.chmod(outside, 0o600)
            (source / "evil").symlink_to(outside)
            try:
                PREP.prepare(str(root), "home", "hysteria2", "203.0.113.9")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("runtime profile staging followed a source symlink")
            assert outside.read_text() == "keep\n"

        with tempfile.TemporaryDirectory(prefix="router-vpn-runtime-run-link-") as td:
            root = Path(td)
            make_source(root)
            outside = root / "outside"
            outside.mkdir()
            (root / "run").symlink_to(outside, target_is_directory=True)
            try:
                PREP.prepare(str(root), "home", "hysteria2", "203.0.113.9")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("runtime staging followed a symlink run directory")
            assert not list(outside.iterdir())

    print("Transactional runtime profile staging tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
