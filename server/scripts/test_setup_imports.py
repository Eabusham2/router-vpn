#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("router_vpn_import_payloads", SCRIPT_DIR / "import_payloads.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load import_payloads.py")
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)

_norm_spec = importlib.util.spec_from_file_location("router_vpn_normalize_setup", SCRIPT_DIR / "normalize-setup-imports.py")
if _norm_spec is None or _norm_spec.loader is None:
    raise RuntimeError("cannot load normalize-setup-imports.py")
norm = importlib.util.module_from_spec(_norm_spec)
_norm_spec.loader.exec_module(norm)


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


def test_method_lane_truth() -> None:
    sample = {"id": "reality-vision", "available": True, "config": "{}"}
    norm.normalize_method(sample, "198.51.100.9")
    check(sample["methodLane"] == "manual-advanced", "complex Reality mode must be classified manual-advanced")
    check(sample["methodLane"] not in norm.SETUP_METHOD_LANES, "complex Router VPN mode leaked into Setup Center simple Methods lanes")
    socks = {"id": "socks5", "available": True, "config": "server: 192.168.50.133:1080"}
    norm.normalize_method(socks, "198.51.100.9")
    check(socks["methodLane"] == "manual-app-proxy", "SOCKS5 must remain a manual app proxy")
    check(socks["endpointScope"] == "tunnel-private-only", "SOCKS5 must remain LAN/tunnel only")
    check(not socks["qrSupported"], "SOCKS5 must not get a fake remote QR")


def test_setup_center_ui_contract() -> None:
    data = {
        "endpoint": "198.51.100.9",
        "socksHost": "192.168.50.133",
        "devices": {},
        "methods": [],
        "modes": [],
        "methodLaneOrder": ["simple-native", "app", "universal", "universal-compat", "manual-app-proxy", "manual-advanced"],
    }
    html = norm.patch_html(norm.generator.build_html(data))
    for marker in (
        "1. Simple / native",
        "2. Router VPN app — recommended",
        "3. Universal third-party client",
        "4. Manual / custom",
        "/api/download-jobs",
        "startDownloadJob",
        "cancelDownloadJob",
        "setupMethodLanes",
        "Private node-link bundle",
    ):
        check(marker in html, f"Setup Center UI contract missing {marker!r}")
    check("The Setup Center does not pretend complex Router VPN stacks are generic third-party imports." in html, "simple Methods boundary is not explained")
    check("href=\"/router-vpn-bundle.json\"" not in html, "stale statically-published private bundle link remains")
    check("Easy —" not in html and "Advanced —" not in html, "old broad Methods labels remain")
    positions = [html.index(x) for x in ("1. Simple / native", "2. Router VPN app — recommended", "3. Universal third-party client", "4. Manual / custom")]
    check(positions == sorted(positions), "setup lanes are not easiest-to-advanced")


def main() -> int:
    test_sip002()
    test_sip002_plugin()
    test_ssr()
    test_hysteria_validation()
    test_shadowsocks_config_builder()
    test_method_lane_truth()
    test_setup_center_ui_contract()
    print("typed Setup Center import + UI contract tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
