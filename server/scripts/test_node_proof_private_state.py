#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("router_vpn_node_proof", HERE / "ensure-node-proof.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def private_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if os.name != "nt":
        os.chmod(path, 0o600)


def configure(base: Path) -> None:
    MOD.BASE = base
    MOD.WG_CLIENT = base / "client-bundle/generated/wg/wg.conf"
    MOD.AGENT_CONFIG = base / "config/router-agent.json"
    MOD.PROOF_FILE = base / "config/node-proof-id"


def valid_fixture(base: Path) -> str:
    configure(base)
    public = "server-public-key-material"
    private_write(MOD.WG_CLIENT, "[Interface]\nPrivateKey = client-private\n[Peer]\nPublicKey = " + public + "\n")
    private_write(MOD.AGENT_CONFIG, json.dumps({"token": "private-token"}) + "\n")
    return MOD.derive(public)


with tempfile.TemporaryDirectory(prefix="router-vpn-node-proof-") as td:
    base = Path(td)
    expected = valid_fixture(base)
    assert MOD.main() == 0
    agent = json.loads(MOD.AGENT_CONFIG.read_text())
    assert agent["node_id"] == expected
    assert MOD.PROOF_FILE.read_text().strip() == expected
    if os.name != "nt":
        assert MOD.AGENT_CONFIG.stat().st_mode & 0o777 == 0o600
        assert MOD.PROOF_FILE.stat().st_mode & 0o777 == 0o600
    # Running again is identity-preserving, not rotating.
    assert MOD.main() == 0
    assert json.loads(MOD.AGENT_CONFIG.read_text())["node_id"] == expected

if os.name != "nt":
    with tempfile.TemporaryDirectory(prefix="router-vpn-node-proof-mode-") as td:
        base = Path(td)
        valid_fixture(base)
        os.chmod(MOD.AGENT_CONFIG, 0o644)
        try:
            MOD.main()
        except SystemExit as exc:
            assert "mode 0600" in str(exc)
        else:
            raise AssertionError("broad router-agent identity state was accepted")

    with tempfile.TemporaryDirectory(prefix="router-vpn-node-proof-link-") as td:
        base = Path(td)
        valid_fixture(base)
        real = MOD.WG_CLIENT.with_name("real-wg.conf")
        MOD.WG_CLIENT.replace(real)
        MOD.WG_CLIENT.symlink_to(real)
        try:
            MOD.main()
        except SystemExit as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("symlink WireGuard identity source was accepted")

    with tempfile.TemporaryDirectory(prefix="router-vpn-node-proof-parent-") as td:
        base = Path(td)
        valid_fixture(base)
        original_parent = MOD.WG_CLIENT.parent
        real_parent = original_parent.with_name("wg-real")
        original_parent.replace(real_parent)
        original_parent.symlink_to(real_parent, target_is_directory=True)
        try:
            MOD.main()
        except SystemExit as exc:
            assert "parent" in str(exc) and "symlink" in str(exc)
        else:
            raise AssertionError("symlink parent for WireGuard identity source was accepted")

    with tempfile.TemporaryDirectory(prefix="router-vpn-node-proof-race-") as td:
        base = Path(td)
        valid_fixture(base)
        replacement = MOD.WG_CLIENT.with_name("replacement.conf")
        private_write(replacement, "[Peer]\nPublicKey = replacement-server-key\n")
        real_fstat = MOD.os.fstat
        changed = [False]

        def swap_after_open(fd):
            info = real_fstat(fd)
            if not changed[0]:
                changed[0] = True
                os.replace(replacement, MOD.WG_CLIENT)
            return info

        with mock.patch.object(MOD.os, "fstat", side_effect=swap_after_open):
            try:
                MOD.peer_public_key(MOD.WG_CLIENT)
            except SystemExit as exc:
                assert "changed during open" in str(exc)
            else:
                raise AssertionError("WireGuard identity source replacement race was accepted")

print("Node proof private-state tests: OK")
