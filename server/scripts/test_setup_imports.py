#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile

SCRIPT_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("router_vpn_import_payloads", SCRIPT_DIR / "import_payloads.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load import_payloads.py")
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_sip002() -> None:
    uri = m.sip002_uri("2022-blake3-aes-256-gcm", "p@ss:word/with+chars", "2001:db8::1", 8388, label="Home SS")
    parsed = m.parse_sip002(uri)
    check(parsed["method"] == "2022-blake3-aes-256-gcm", "SIP002 method round trip")
    check(parsed["password"] == "p@ss:word/with+chars", "SIP002 password round trip")
    check(parsed["host"] == "2001:db8::1" and parsed["port"] == 8388, "SIP002 IPv6 endpoint round trip")
    check(parsed["label"] == "Home SS", "SIP002 label round trip")
    userinfo = uri.split("ss://", 1)[1].split("@", 1)[0]
    check(":" not in userinfo, "SIP002 userinfo must be base64url, not raw/percent-encoded method:password")


def test_sip002_plugin() -> None:
    uri = m.sip002_uri("aes-256-gcm", "secret", "vpn.example", 12443, plugin="v2ray-plugin;tls;host=example.com")
    parsed = m.parse_sip002(uri)
    check(parsed["plugin"] == "v2ray-plugin;tls;host=example.com", "SIP002 plugin round trip")


def test_ssr() -> None:
    cfg = {
        "password": "legacy-secret",
        "method": "aes-256-ctr",
        "protocol": "auth_aes128_md5",
        "protocol_param": "",
        "obfs": "tls1.2_ticket_auth",
        "obfs_param": "",
        "client_settings": {"server": "203.0.113.4", "server_port": 15443},
    }
    uri = m.ssr_uri(cfg, label="Home SSR")
    parsed = m.parse_ssr(uri)
    check(parsed["host"] == "203.0.113.4" and parsed["port"] == 15443, "SSR endpoint round trip")
    check(parsed["password"] == cfg["password"], "SSR password round trip")
    check(parsed["protocol"] == cfg["protocol"] and parsed["obfs"] == cfg["obfs"], "SSR layers round trip")
    check(parsed["label"] == "Home SSR", "SSR remarks round trip")


def test_hysteria_validation() -> None:
    parsed = m.validate_hysteria2_uri("hysteria2://secret@example.com:8443/?sni=edge.example#Home")
    check(parsed["host"] == "example.com" and parsed["port"] == 8443, "Hysteria endpoint")
    try:
        m.validate_hysteria2_uri("https://example.com/")
    except ValueError:
        pass
    else:
        raise AssertionError("non-Hysteria URI accepted")


def test_shadowsocks_config_builder() -> None:
    doc = {"outbounds": [{"tag": "proxy", "type": "shadowsocks", "server": "ignored", "server_port": 8388, "method": "aes-256-gcm", "password": "secret"}]}
    uri = m.shadowsocks_from_singbox(json.dumps(doc), "198.51.100.9")
    parsed = m.parse_sip002(uri)
    check(parsed["host"] == "198.51.100.9", "external endpoint override must be explicit")
    check(parsed["method"] == "aes-256-gcm", "sing-box method")


def main() -> int:
    test_sip002()
    test_sip002_plugin()
    test_ssr()
    test_hysteria_validation()
    test_shadowsocks_config_builder()
    print("typed Setup Center import payload tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
