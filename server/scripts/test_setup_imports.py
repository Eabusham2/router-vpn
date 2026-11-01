#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import copy
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
    password = "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI="
    uri = m.sip002_uri("2022-blake3-aes-256-gcm", password, "2001:db8::1", 8388, label="Home SS")
    parsed = m.parse_sip002(uri)
    check(parsed["method"] == "2022-blake3-aes-256-gcm", "SIP002 method round trip")
    check(parsed["password"] == password, "SIP002 password round trip")
    check(parsed["host"] == "2001:db8::1" and parsed["port"] == 8388, "SIP002 IPv6 endpoint round trip")
    check(parsed["label"] == "Home SS", "SIP002 label round trip")
    userinfo = uri.split("ss://", 1)[1].split("@", 1)[0]
    check(userinfo == "2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D",
          "SIP002 AEAD-2022 must match the official percent-encoded userinfo vector")
    legacy = m.sip002_uri("aes-256-gcm", "p@ss:word/with+chars%?#", "vpn.example", 8388, label="Home + SS")
    check(":" not in legacy.split("ss://", 1)[1].split("@", 1)[0], "legacy SIP002 keeps Base64URL userinfo")
    check(m.parse_sip002(legacy)["password"] == "p@ss:word/with+chars%?#", "legacy reserved credentials retained")
    check(m.parse_sip002(legacy)["label"] == "Home + SS", "SIP002 fragment plus must not become a space")
    check(m.parse_sip002("ss://aes-256-gcm:secret%3A%40%2F%2B@vpn.example:8388")["password"] == "secret:@/+",
          "SIP002 also permits explicitly percent-encoded legacy userinfo")


def test_sip002_rejects_ambiguous_input() -> None:
    old_2022 = "ss://" + m.b64url_encode(b"2022-blake3-aes-256-gcm:secret") + "@vpn.example:8388"
    for value in (
        old_2022,
        "ss://aes-256-gcm:secret@attacker@vpn.example:8388",
        "ss://aes-256-gcm:secret@vpn.example:0",
        "ss://aes-256-gcm:secret@vpn.example:65536",
        "ss://aes-256-gcm:secret@vpn.example:8388/unselected-path",
        "ss://aes-256-gcm:secret@2001:db8::1:8388",
        "ss://aes-256-gcm:secret@vpn%2Eexample:8388",
        "ss://aes-256-gcm:secret@vpn\\example:8388",
        "ss://aes-256-gcm:secret%ZZ@vpn.example:8388",
        "ss://aes-256-gcm:secret%FF@vpn.example:8388",
        "ss://aes-256-gcm:secret+raw@vpn.example:8388",
        "ss://aes-256-gcm:secret:raw@vpn.example:8388",
        "ss://aes-256-gcm:@vpn.example:8388",
        "ss://YWVzLTI1Ni1nY206c2VjcmV0$@vpn.example:8388",
        "ss://YWVzLTI1Ni1nY206c2VjcmV0=@vpn.example:8388",
        "ss://aes-256-gcm:secret@vpn.example:8388/?plugin=first&plugin=second",
        "ss://aes-256-gcm:secret@vpn.example:8388/#bad%ZZ",
        "ss://aes-256-gcm:secret@vpn.example:8388/#bad label",
        "ss://aes-256-gcm:secret@vpn.example:8388\n",
    ):
        try:
            m.parse_sip002(value)
        except ValueError:
            continue
        raise AssertionError("malformed or ambiguous SIP002 input accepted: " + repr(value))


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
    password = "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI="
    doc["outbounds"][0].update(method="2022-blake3-aes-256-gcm", password=password)
    final = {"id": "shadowsocks", "available": True, "config": json.dumps(doc)}
    norm.normalize_method(final, "198.51.100.9")
    check(final["url"].startswith("ss://2022-blake3-aes-256-gcm:"), "final normalization must preserve AEAD-2022 plain userinfo")
    check(final["qrPayload"] == final["url"], "the published QR must carry the corrected final URI")
    check(m.parse_sip002(final["url"])["password"] == password, "final normalized credential identity")


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


def test_overtls_import() -> None:
    config = {"method": "none", "password": "", "tunnel_path": "/rvpn-selected-path/",
              "client_settings": {"server_host": "198.51.100.9", "server_port": 14443,
                                  "server_domain": "tls.selected.example", "disable_tls": False,
                                  "dangerous_mode": False, "listen_host": "127.0.0.1", "listen_port": 1080}}
    method = {"id": "overtls", "config": json.dumps(config), "available": True}
    norm.normalize_method(method, "different-outer-metadata.example")
    check(method["qrSupported"] and method["qrPayload"] == method["url"], "OverTLS has an actual compatible QR import")
    check(method["importType"] == "overtls-ssr-uri" and method["configFilename"] == "router-vpn-overtls.json", "OverTLS import/download identity")
    raw = m.b64url_decode(method["url"][6:]).decode()
    check(raw.startswith("198.51.100.9:14443:origin:none:plain:/?"), "OverTLS selected endpoint changed")
    fields = dict(m.urllib.parse.parse_qsl(raw.split("/?", 1)[1]))
    check(fields["ot_enable"] == "1" and fields["dangerous_mode"] == "false", "OverTLS import weakened verification")
    check(m.b64url_decode(fields["ot_domain"]).decode() == config["client_settings"]["server_domain"], "OverTLS selected TLS name changed")
    check(m.b64url_decode(fields["ot_path"]).decode() == config["tunnel_path"], "OverTLS selected path changed")
    check(method["clientReleaseURL"].endswith("/v0.3.12"), "OverTLS client release must be pinned")
    for change, value in (("server_host", "2001:db8::7"), ("cafile", "selected-root.crt"), ("listen_user", "selected-user")):
        altered = copy.deepcopy(config)
        altered["client_settings"][change] = value
        selected = {"id": "overtls", "config": json.dumps(altered), "url": "stale-import", "available": True}
        norm.normalize_method(selected, "198.51.100.9")
        check(not selected["url"] and not selected["qrPayload"] and not selected["qrSupported"], "unrepresentable OverTLS URI published")
        check(json.loads(selected["config"])["client_settings"][change] == value, "OverTLS JSON fallback changed the selected setting")
        check(selected["configFilename"] == "router-vpn-overtls.json", "OverTLS JSON fallback is not downloadable")
    for change, value in (("test_timeout_secs", 37), ("tunnel_path", ["/selected-first/", "/selected-second/"]),
                          ("server_settings", {"listen_host": "127.0.0.1", "listen_port": 14444}),
                          ("future_top_level_option", "preserve-me")):
        altered = copy.deepcopy(config)
        altered[change] = value
        selected = {"id": "overtls", "config": json.dumps(altered), "available": True}
        norm.normalize_method(selected, "198.51.100.9")
        check(not selected["url"] and not selected["qrSupported"], "OverTLS URI silently dropped top-level settings")
        check(json.loads(selected["config"])[change] == value, "OverTLS top-level JSON setting changed")
    for fallback in ({"server_host": "2001:db8::7"}, {"listen_user": "selected-user"}, {"cafile": "selected-root.crt"}):
        for invalid in ({"cafile": "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"},
                        {"client_id": "invalid-id"}, {"client_id": 7}):
            altered = copy.deepcopy(config)
            altered["client_settings"].update(fallback)
            altered["client_settings"].update(invalid)
            try:
                m.overtls_uri(altered)
            except ValueError as exc:
                check(not isinstance(exc, m.OverTLSJSONRequired), "malformed trust/identity accepted as a JSON-only config")
            else:
                raise AssertionError("malformed OverTLS trust/identity accepted")
    for change, value in (("server_host", "host:14443@other"), ("server_host", "host/path"),
                          ("server_port", 0), ("server_port", 65536), ("server_port", True),
                          ("dangerous_mode", True), ("disable_tls", True),
                          ("server_domain", ""), ("server_domain", "name\nother"),
                          ("cafile", "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----")):
        altered = copy.deepcopy(config)
        altered["client_settings"][change] = value
        try:
            m.overtls_uri(altered)
        except ValueError as exc:
            check(not isinstance(exc, m.OverTLSJSONRequired), "invalid OverTLS settings cannot use the JSON fallback")
        else:
            raise AssertionError("invalid OverTLS setting accepted: " + change)
    altered = copy.deepcopy(config)
    altered["tunnel_path"] = "/selected/?other-path"
    try:
        m.overtls_uri(altered)
    except ValueError:
        pass
    else:
        raise AssertionError("ambiguous OverTLS tunnel path accepted")


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
    test_sip002_rejects_ambiguous_input()
    test_sip002_plugin()
    test_ssr()
    test_hysteria_validation()
    test_shadowsocks_config_builder()
    test_method_lane_truth()
    test_overtls_import()
    test_setup_center_ui_contract()
    print("typed Setup Center import + UI contract tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
