#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("router_vpn_aux_private_state", HERE / "generate-aux-proxies.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def private_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if os.name != "nt":
        os.chmod(path, 0o600)


with tempfile.TemporaryDirectory(prefix="router-vpn-aux-private-") as td:
    base = Path(td)
    settings = base / "config/tls/settings.env"
    private_write(settings, "TLS_NAME='vpn.example'\n")
    assert MOD.read_private_text(settings, "TLS settings") == "TLS_NAME='vpn.example'\n"
    secrets = base / "config/aux/secrets.json"
    private_write(secrets, json.dumps({"overtls_path": "/rvpn-test/", "ssr_password": "x" * 28}) + "\n")
    saved = MOD.load_preserved_json(secrets)
    assert saved["overtls_path"] == "/rvpn-test/"
    assert saved["ssr_password"] == "x" * 28

with tempfile.TemporaryDirectory(prefix="router-vpn-aux-corrupt-") as td:
    path = Path(td) / "config/aux/secrets.json"
    private_write(path, "{broken\n")
    try:
        MOD.load_preserved_json(path)
    except RuntimeError as exc:
        assert "corrupt" in str(exc) and "rotation" in str(exc)
    else:
        raise AssertionError("corrupt auxiliary credential state was accepted")

if os.name != "nt":
    with tempfile.TemporaryDirectory(prefix="router-vpn-aux-mode-") as td:
        path = Path(td) / "config/tls/settings.env"
        private_write(path, "TLS_NAME='vpn.example'\n")
        os.chmod(path, 0o644)
        try:
            MOD.read_private_text(path, "TLS settings")
        except RuntimeError as exc:
            assert "mode 0600" in str(exc)
        else:
            raise AssertionError("broad-permission TLS settings were accepted")

    with tempfile.TemporaryDirectory(prefix="router-vpn-aux-leaf-") as td:
        base = Path(td)
        real = base / "real-settings"
        private_write(real, "TLS_NAME='vpn.example'\n")
        link = base / "config/tls/settings.env"
        link.parent.mkdir(parents=True)
        link.symlink_to(real)
        try:
            MOD.read_private_text(link, "TLS settings")
        except RuntimeError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("symlink TLS settings were accepted")

    with tempfile.TemporaryDirectory(prefix="router-vpn-aux-parent-") as td:
        base = Path(td)
        real_parent = base / "real-tls"
        real_parent.mkdir(parents=True)
        private_write(real_parent / "settings.env", "TLS_NAME='vpn.example'\n")
        link_parent = base / "config/tls"
        link_parent.parent.mkdir(parents=True)
        link_parent.symlink_to(real_parent, target_is_directory=True)
        try:
            MOD.read_private_text(link_parent / "settings.env", "TLS settings")
        except RuntimeError as exc:
            assert "parent" in str(exc) and "symlink" in str(exc)
        else:
            raise AssertionError("symlink TLS-settings parent was accepted")

    with tempfile.TemporaryDirectory(prefix="router-vpn-aux-race-") as td:
        path = Path(td) / "config/tls/settings.env"
        private_write(path, "TLS_NAME='vpn.example'\n")
        replacement = path.with_name("replacement.env")
        private_write(replacement, "TLS_NAME='attacker.example'\n")
        real_fstat = MOD.os.fstat
        changed = [False]

        def swap_after_open(fd):
            info = real_fstat(fd)
            if not changed[0]:
                changed[0] = True
                os.replace(replacement, path)
            return info

        with mock.patch.object(MOD.os, "fstat", side_effect=swap_after_open):
            try:
                MOD.read_private_text(path, "TLS settings")
            except RuntimeError as exc:
                assert "changed during open" in str(exc)
            else:
                raise AssertionError("auxiliary credential replacement race was accepted")

    with tempfile.TemporaryDirectory(prefix="router-vpn-aux-output-parent-") as td:
        base = Path(td)
        real = base / "real-overtls"
        real.mkdir()
        linked = base / "client-bundle/generated/overtls"
        linked.parent.mkdir(parents=True)
        linked.symlink_to(real, target_is_directory=True)
        try:
            MOD.ensure_private_dir(linked, "OverTLS generated directory", create=True)
        except RuntimeError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("symlink auxiliary output directory was accepted")

print("Auxiliary credential private-state tests: OK")
