#!/usr/bin/env python3
"""Normalize Setup Center method metadata to truthful typed import contracts."""
from __future__ import annotations

import argparse
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def load_module(name: str, path: Path):
    spec = spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


imports = load_module("router_vpn_import_payloads", SCRIPT_DIR / "import_payloads.py")
generator = load_module("router_vpn_setup_generator", SCRIPT_DIR / "generate-setup-assets.py")


CONTRACTS = {
    "router-vpn-app": ("router-vpn-node-bundle", "app", False, True, "private-node-data"),
    "wireguard": ("wireguard-config", "simple-native", True, True, "public-direct-tunnel"),
    "amneziawg2": ("amneziawg-config", "simple-native", False, True, "public-direct-tunnel"),
    "shadowsocks": ("sip002", "universal", True, False, "public-proxy"),
    "hysteria2": ("hysteria2-uri", "universal", True, False, "public-proxy-or-tun-client"),
    "ss-v2ray": ("sip002-plugin", "manual-advanced", True, False, "public-proxy"),
    "reality-vision": ("xray-json", "manual-advanced", False, False, "public-proxy-or-tun-client"),
    "reality-pq-vision": ("xray-json", "manual-advanced", False, False, "public-proxy-or-tun-client"),
    "reality-xhttp": ("xray-json", "manual-advanced", False, False, "public-proxy-or-tun-client"),
    "naive-h2": ("sing-box-json", "manual-advanced", False, False, "public-proxy"),
    "naive-h3": ("sing-box-json", "manual-advanced", False, False, "public-proxy"),
    "overtls": ("overtls-json", "universal-compat", False, False, "public-proxy"),
    "shadowsocksr": ("ssr-uri", "universal-compat", True, False, "public-proxy"),
    "socks5": ("socks5-manual", "manual-app-proxy", False, False, "tunnel-private-only"),
}


def normalize_method(method: dict, endpoint: str) -> None:
    ident = str(method.get("id") or "")
    contract = CONTRACTS.get(ident, ("config-file", "manual-advanced", False, False, "unknown"))
    import_type, lane, qr_supported, full_vpn, endpoint_scope = contract
    method["importType"] = import_type
    method["methodLane"] = lane
    method["qrSupported"] = qr_supported
    method["fullVpnCapable"] = full_vpn
    method["proxyOnly"] = not full_vpn and ident not in ("router-vpn-app",)
    method["endpointScope"] = endpoint_scope

    if ident == "shadowsocks" and method.get("config") and endpoint:
        method["url"] = imports.shadowsocks_from_singbox(str(method["config"]), endpoint)
    elif ident == "ss-v2ray" and method.get("config") and endpoint:
        method["url"] = imports.shadowsocks_plugin_from_json(str(method["config"]), endpoint)
    elif ident == "shadowsocksr" and method.get("config"):
        method["url"] = imports.ssr_uri(imports.json_config(str(method["config"])))
    elif ident == "hysteria2" and method.get("url"):
        imports.validate_hysteria2_uri(str(method["url"]))

    # Compact QR exists only where an actual client import contract exists.
    if qr_supported:
        if ident == "wireguard":
            payload = str(method.get("config") or "")
        else:
            payload = str(method.get("url") or "")
        if not payload:
            method["qrSupported"] = False
            method["qrPayload"] = ""
            method["qrPngBase64"] = ""
        else:
            method["qrPayload"] = payload
            method["qrPngBase64"] = generator.qr_png(payload)
    else:
        method["qrPayload"] = ""
        method["qrPngBase64"] = ""

    # The existing simple boolean is retained for compatibility, but the new
    # lane is authoritative and prevents complex Router VPN stacks from being
    # presented as generic easy third-party methods.
    method["simple"] = lane in ("simple-native", "universal") or ident == "router-vpn-app"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base", nargs="?", default="/opt/router-vpn")
    args = ap.parse_args()
    base = Path(args.base).resolve()
    bundle = base / "client-bundle"
    assets_path = bundle / "setup-assets.json"
    html_path = bundle / "router-vpn-device-setup.html"
    if not assets_path.is_file():
        raise SystemExit(f"missing setup assets: {assets_path}")
    data = json.loads(assets_path.read_text())
    if not isinstance(data, dict):
        raise SystemExit("setup-assets.json must be an object")
    endpoint = str(data.get("endpoint") or "").strip().strip("[]")
    methods = data.get("methods")
    if not isinstance(methods, list):
        raise SystemExit("setup-assets.json methods must be an array")
    for method in methods:
        if isinstance(method, dict):
            normalize_method(method, endpoint)
    data["methodContractVersion"] = 2
    data["methodLaneOrder"] = ["simple-native", "app", "universal", "universal-compat", "manual-app-proxy", "manual-advanced"]
    data["qrPolicy"] = "QR is emitted only for an actual interoperable import payload; arbitrary JSON/text configs are file/text imports."
    assets_path.write_text(json.dumps(data, indent=2) + "\n")
    assets_path.chmod(0o600)
    html_path.write_text(generator.build_html(data))
    html_path.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
