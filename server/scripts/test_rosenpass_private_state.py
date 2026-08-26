#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("router_vpn_rosenpass_private_state", HERE / "rosenpass-private-state.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def private_write(path: Path, body: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(body, str):
        body = body.encode()
    path.write_bytes(body)
    if os.name != "nt":
        os.chmod(path, 0o600)


def make_family(base: Path) -> dict[str, Path]:
    items = MOD.paths(base)
    content = {
        "server_public": b"server-public\n",
        "server_secret": b"server-secret\n",
        "wg_server_peer": b"wg-client-public\n",
        "awg_server_peer": b"awg-client-public\n",
        "server_toml": b"listen = []\n",
        "server_env": b"ROSENPASS_PORT=51822\n",
        "wg_secret": b"wg-client-secret\n",
        "wg_public": b"wg-client-public\n",
        "wg_server_public": b"server-public\n",
        "wg_toml": b'endpoint = "old.example:51822"\nkey_out = "rosenpass.psk"\n',
        "wg_env": b"ROSENPASS_INTERFACE=wrong\nROSENPASS_PORT=51822\n",
        "awg_secret": b"awg-client-secret\n",
        "awg_public": b"awg-client-public\n",
        "awg_server_public": b"server-public\n",
        "awg_toml": b'endpoint = "old.example:51822"\nkey_out = "rosenpass.psk"\n',
        "awg_env": b"ROSENPASS_INTERFACE=wrong\nROSENPASS_PORT=51822\n",
    }
    for name, path in items.items():
        private_write(path, content[name])
    return items


with tempfile.TemporaryDirectory(prefix="router-vpn-rp-state-") as td:
    base = Path(td)
    items = make_family(base)
    before_keys = {name: items[name].read_bytes() for name in ("server_public", "server_secret", "wg_secret", "awg_secret")}
    assert MOD.verify_existing(base) is not None
    MOD.refresh_existing(base, "203.0.113.9", 51822)
    assert items["wg_env"].read_text().splitlines()[0] == "ROSENPASS_INTERFACE=wg"
    assert items["awg_env"].read_text().splitlines()[0] == "ROSENPASS_INTERFACE=awg"
    assert 'endpoint = "203.0.113.9:51822"' in items["wg_toml"].read_text()
    assert 'endpoint = "203.0.113.9:51822"' in items["awg_toml"].read_text()
    for name, before in before_keys.items():
        assert items[name].read_bytes() == before, f"refresh mutated Rosenpass identity {name}"
    if os.name != "nt":
        for path in items.values():
            assert path.stat().st_mode & 0o777 == 0o600

with tempfile.TemporaryDirectory(prefix="router-vpn-rp-base-") as td:
    base = Path(td)
    private_write(base / "config/wireguard/wg0.conf", "[Interface]\nPrivateKey = wg-private\n[Peer]\nPublicKey = wg-client-public\n")
    private_write(base / "config/awg2/awg0.conf", "[Interface]\nPrivateKey = awg-private\n[Peer]\nPublicKey = awg-client-public\n")
    values = MOD.base_key_assignments(base)
    assert values == {
        "WG_SERVER_PRIV": "wg-private",
        "WG_CLIENT_PUB": "wg-client-public",
        "AWG_SERVER_PRIV": "awg-private",
        "AWG_CLIENT_PUB": "awg-client-public",
    }

with tempfile.TemporaryDirectory(prefix="router-vpn-rp-partial-") as td:
    base = Path(td)
    items = make_family(base)
    items["awg_secret"].unlink()
    try:
        MOD.verify_existing(base)
    except RuntimeError as exc:
        assert "partial/unsafe" in str(exc) and "rotation" in str(exc)
    else:
        raise AssertionError("partial Rosenpass identity was accepted")

if os.name != "nt":
    with tempfile.TemporaryDirectory(prefix="router-vpn-rp-mode-") as td:
        base = Path(td)
        items = make_family(base)
        os.chmod(items["server_secret"], 0o644)
        try:
            MOD.verify_existing(base)
        except RuntimeError as exc:
            assert "mode 0600" in str(exc)
        else:
            raise AssertionError("broad Rosenpass secret was accepted")

    with tempfile.TemporaryDirectory(prefix="router-vpn-rp-parent-") as td:
        base = Path(td)
        items = make_family(base)
        server_dir = base / "config/rosenpass"
        real_dir = server_dir.with_name("rosenpass-real")
        server_dir.replace(real_dir)
        server_dir.symlink_to(real_dir, target_is_directory=True)
        try:
            MOD.verify_existing(base)
        except RuntimeError as exc:
            assert "parent" in str(exc) and "symlink" in str(exc)
        else:
            raise AssertionError("symlink Rosenpass identity parent was accepted")

    with tempfile.TemporaryDirectory(prefix="router-vpn-rp-race-") as td:
        base = Path(td)
        items = make_family(base)
        target = items["server_public"]
        replacement = target.with_name("replacement-public")
        private_write(replacement, b"replacement-public\n")
        real_fstat = MOD.os.fstat
        changed = [False]

        def swap_after_open(fd):
            info = real_fstat(fd)
            if not changed[0]:
                changed[0] = True
                os.replace(replacement, target)
            return info

        with mock.patch.object(MOD.os, "fstat", side_effect=swap_after_open):
            try:
                MOD.read_private(target, "Rosenpass server public")
            except RuntimeError as exc:
                assert "changed during open" in str(exc)
            else:
                raise AssertionError("Rosenpass identity replacement race was accepted")

print("Rosenpass private-state tests: OK")
