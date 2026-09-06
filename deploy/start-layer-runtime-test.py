#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "modes" / "start-layer.py"
AES_METHOD = "2022-blake3-aes-256-gcm"
PASSWORD = "0123456789abcdef0123456789abcdef"


def write_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    path.chmod(mode)


def source_ss() -> dict:
    return {
        "log": {"level": "warn"},
        "outbounds": [
            {
                "type": "shadowsocks",
                "tag": "proxy",
                "server": "198.51.100.8",
                "server_port": 8388,
                "method": AES_METHOD,
                "password": PASSWORD,
            },
            {"type": "direct", "tag": "direct"},
        ],
    }


def target_hy2() -> dict:
    return {
        "outbounds": [
            {
                "type": "hysteria2",
                "tag": "proxy",
                "server": "198.51.100.8",
                "server_port": 8443,
                "password": "hy2-secret",
                "tls": {"enabled": True, "server_name": "vpn.example"},
            },
            {"type": "direct", "tag": "direct"},
        ]
    }


def run_prepare(root: Path, layer: str, mode: str, target: dict, endpoint: str = "203.0.113.9") -> tuple[subprocess.CompletedProcess[str], Path]:
    write_json(
        root / "routers.json",
        {
            "schema_version": 4,
            "selected_id": "home",
            "profiles": [{"schema_version": 4, "id": "home", "name": "Home", "node_kind": "router-vpn", "start_layer": layer}],
        },
    )
    write_json(root / "generated" / "home" / "shadowsocks" / "sing-box.json", source_ss())
    conf = root / "run" / "mode"
    write_json(conf / "sing-box.json", target)
    proc = subprocess.run(
        ["python3", str(HELPER), "prepare", str(root), "home", mode, str(conf), endpoint],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return proc, conf


def row(doc: dict, tag: str) -> dict:
    for item in doc.get("outbounds", []):
        if isinstance(item, dict) and item.get("tag") == tag:
            return item
    raise AssertionError(f"missing outbound {tag!r}")


def test_off() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        original = target_hy2()
        proc, conf = run_prepare(root, "off", "hysteria2", original)
        assert proc.returncode == 0, proc.stderr
        assert json.loads((conf / "sing-box.json").read_text()) == original
        state = json.loads((conf / "start-layer.json").read_text())
        assert state == {"active": "off", "xor": False}


def test_aes_detour() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        proc, conf = run_prepare(Path(tmp), "aes-256-gcm", "hysteria2", target_hy2())
        assert proc.returncode == 0, proc.stderr
        doc = json.loads((conf / "sing-box.json").read_text())
        inner = row(doc, "proxy")
        outer = row(doc, "start-layer-aes")
        assert inner["server"] == "127.0.0.1"
        assert inner["detour"] == "start-layer-aes"
        assert outer["type"] == "shadowsocks"
        assert outer["method"] == AES_METHOD
        assert outer["server"] == "203.0.113.9"
        assert outer["server_port"] == 8388
        state = json.loads((conf / "start-layer.json").read_text())
        assert state["active"] == "aes-256-gcm" and state["xor"] is False


def test_aes_xor_and_ipv6() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        proc, conf = run_prepare(Path(tmp), "aes-256-gcm+xor-whitening", "hysteria2", target_hy2(), "2001:db8::9")
        assert proc.returncode == 0, proc.stderr
        doc = json.loads((conf / "sing-box.json").read_text())
        outer = row(doc, "start-layer-aes")
        assert outer["server"] == "127.0.0.1" and outer["server_port"] == 18389
        state = json.loads((conf / "start-layer.json").read_text())
        assert state["xor"] is True
        assert state["relay_listen"] == "127.0.0.1:18389"
        assert state["relay_target"] == "[2001:db8::9]:8389"


def test_existing_shadowsocks_is_not_double_wrapped() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        proc, conf = run_prepare(Path(tmp), "aes-256-gcm+xor-whitening", "shadowsocks", source_ss())
        assert proc.returncode == 0, proc.stderr
        doc = json.loads((conf / "sing-box.json").read_text())
        ss = row(doc, "proxy")
        assert ss["server"] == "127.0.0.1" and ss["server_port"] == 18389
        assert not any(isinstance(x, dict) and x.get("tag") == "start-layer-aes" for x in doc["outbounds"])


def test_unsupported_graph_fails_without_mutating() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        original = target_hy2()
        proc, conf = run_prepare(root, "aes-256-gcm", "reality-vision", original)
        assert proc.returncode != 0
        assert "does not yet have a proved start-layer composition path" in proc.stderr
        assert json.loads((conf / "sing-box.json").read_text()) == original


def main() -> None:
    tests = [test_off, test_aes_detour, test_aes_xor_and_ipv6, test_existing_shadowsocks_is_not_double_wrapped, test_unsupported_graph_fails_without_mutating]
    for test in tests:
        test()
    print(f"PASS start-layer runtime transactions ({len(tests)} cases)")


if __name__ == "__main__":
    main()
