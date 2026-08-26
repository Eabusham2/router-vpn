#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("router_vpn_preserve_generated_state", HERE / "preserve-generated-state.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    if os.name != "nt":
        os.chmod(path, 0o600)


with tempfile.TemporaryDirectory(prefix="router-vpn-preserve-state-") as td:
    base = Path(td)
    transport_state = base / "config/transports/generated-secrets.json"
    write_json(transport_state, {
        "hysteria2_password": "hy2-existing-password",
        "shadowsocks_key": "ss-existing-key-material",
    })
    got = MOD.transports(base)
    assert got["HY2_PASSWORD"] == "hy2-existing-password"
    assert got["SS_KEY"] == "ss-existing-key-material"

    server = {
        "inbounds": [
            {
                "tag": "reality-in",
                "settings": {"clients": [{"id": "11111111-1111-1111-1111-111111111111"}], "decryption": "none"},
                "streamSettings": {"realitySettings": {"privateKey": "private-reality-key", "shortIds": ["0011223344556677"]}},
            },
            {
                "tag": "pq-reality-in",
                "settings": {"clients": [{"id": "22222222-2222-2222-2222-222222222222"}], "decryption": "pq-server-decryption"},
                "streamSettings": {"realitySettings": {"privateKey": "private-reality-key", "shortIds": ["8899aabbccddeeff"]}},
            },
            {
                "tag": "max-xhttp-in",
                "settings": {"clients": [{"id": "33333333-3333-3333-3333-333333333333"}]},
                "streamSettings": {"realitySettings": {"privateKey": "advanced-private-key", "shortIds": ["0123456789abcdef"]}},
            },
        ]
    }
    write_json(base / "config/xray/server.json", server)
    write_json(base / "config/xray/generated-secrets.json", {
        "reality_public_key": "reality-public-key",
        "standard_uuid": "11111111-1111-1111-1111-111111111111",
        "standard_short_id": "0011223344556677",
        "pq_uuid": "22222222-2222-2222-2222-222222222222",
        "pq_short_id": "8899aabbccddeeff",
        "vless_encryption": "pq-client-encryption",
        "mldsa65_verify": "mldsa-verify",
    })
    xray = MOD.xray(base)
    assert xray["STD_UUID"] == "11111111-1111-1111-1111-111111111111"
    assert xray["PQ_UUID"] == "22222222-2222-2222-2222-222222222222"
    assert xray["REALITY_PRIVATE"] == "private-reality-key"
    assert xray["REALITY_PASSWORD"] == "reality-public-key"
    assert xray["SERVER_DEC"] == "pq-server-decryption"
    assert xray["CLIENT_ENC"] == "pq-client-encryption"

    write_json(base / "config/xray/advanced-secrets.json", {
        "xhttp_uuid": "33333333-3333-3333-3333-333333333333",
        "xhttp_short_id": "0123456789abcdef",
        "xhttp_reality_public": "advanced-public-key",
    })
    advanced = MOD.advanced(base)
    assert advanced["UUID"] == "33333333-3333-3333-3333-333333333333"
    assert advanced["REALITY_PRIVATE"] == "advanced-private-key"
    assert advanced["REALITY_PASSWORD"] == "advanced-public-key"

    settings = base / "config/tls/settings.env"
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(
        "TLS_NAME='vpn.example'\n"
        "SS_V2RAY_PASSWORD='existing-v2ray-secret'\n"
        "NAIVE_USER='existing-naive-user'\n"
        "NAIVE_PASSWORD='existing-naive-password'\n",
        encoding="utf-8",
    )
    if os.name != "nt":
        os.chmod(settings, 0o600)
    tls = MOD.tls(base)
    assert tls == {
        "SS_V2RAY_PASSWORD": "existing-v2ray-secret",
        "NAIVE_USER": "existing-naive-user",
        "NAIVE_PASSWORD": "existing-naive-password",
    }

    broken = json.loads((base / "config/xray/generated-secrets.json").read_text())
    broken["standard_uuid"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    write_json(base / "config/xray/generated-secrets.json", broken)
    try:
        MOD.xray(base)
    except ValueError:
        pass
    else:
        raise AssertionError("inconsistent preserved Xray state was accepted")

    transport_state.write_text("{broken json\n", encoding="utf-8")
    try:
        MOD.transports(base)
    except ValueError as exc:
        assert "corrupt JSON" in str(exc)
    else:
        raise AssertionError("corrupt preserved transport state was accepted")

    settings.write_text(
        "TLS_NAME='vpn.example'\n"
        "SS_V2RAY_PASSWORD='first-secret'\n"
        "SS_V2RAY_PASSWORD='second-secret'\n"
        "NAIVE_USER='existing-naive-user'\n"
        "NAIVE_PASSWORD='existing-naive-password'\n",
        encoding="utf-8",
    )
    try:
        MOD.tls(base)
    except ValueError as exc:
        assert "exactly one preserved SS_V2RAY_PASSWORD" in str(exc)
    else:
        raise AssertionError("ambiguous preserved TLS credentials were accepted")

if os.name != "nt":
    with tempfile.TemporaryDirectory(prefix="router-vpn-preserve-symlink-") as td:
        base = Path(td)
        real = base / "real.json"
        real.write_text(json.dumps({"hysteria2_password": "hy2-existing-password", "shadowsocks_key": "ss-existing-key-material"}), encoding="utf-8")
        os.chmod(real, 0o600)
        link = base / "config/transports/generated-secrets.json"
        link.parent.mkdir(parents=True)
        link.symlink_to(real)
        try:
            MOD.transports(base)
        except ValueError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("symlink preserved transport state was accepted")

    with tempfile.TemporaryDirectory(prefix="router-vpn-preserve-parent-") as td:
        base = Path(td)
        real_parent = base / "real-transports"
        real_parent.mkdir(parents=True)
        state = real_parent / "generated-secrets.json"
        state.write_text(json.dumps({"hysteria2_password": "hy2-existing-password", "shadowsocks_key": "ss-existing-key-material"}), encoding="utf-8")
        os.chmod(state, 0o600)
        linked_parent = base / "config" / "transports"
        linked_parent.parent.mkdir(parents=True)
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        try:
            MOD.transports(base)
        except ValueError as exc:
            assert "parent" in str(exc) and "symlink" in str(exc)
        else:
            raise AssertionError("symlink parent for preserved transport state was accepted")

    with tempfile.TemporaryDirectory(prefix="router-vpn-preserve-mode-") as td:
        base = Path(td)
        path = base / "config/transports/generated-secrets.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"hysteria2_password": "hy2-existing-password", "shadowsocks_key": "ss-existing-key-material"}), encoding="utf-8")
        os.chmod(path, 0o644)
        try:
            MOD.transports(base)
        except ValueError as exc:
            assert "mode 0600" in str(exc)
        else:
            raise AssertionError("broad-permission preserved credential state was accepted")

    with tempfile.TemporaryDirectory(prefix="router-vpn-preserve-race-") as td:
        base = Path(td)
        path = base / "config/transports/generated-secrets.json"
        path.parent.mkdir(parents=True)
        write_json(path, {"hysteria2_password": "hy2-existing-password", "shadowsocks_key": "ss-existing-key-material"})
        replacement = path.with_name("replacement.json")
        write_json(replacement, {"hysteria2_password": "replacement-password", "shadowsocks_key": "replacement-key-material"})
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
                MOD.transports(base)
            except ValueError as exc:
                assert "changed during open" in str(exc)
            else:
                raise AssertionError("preserved credential file replacement race was accepted")

print("Preserved generated state tests: OK")
