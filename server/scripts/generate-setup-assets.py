#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import subprocess
import sys
import urllib.parse


def hostport(host: str, port: int) -> str:
    host = host.strip().strip("[]")
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{port}"


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text()
    except Exception:
        return ""


def qr_png(payload: str) -> str:
    if not payload:
        return ""
    try:
        png = subprocess.check_output(
            ["qrencode", "-l", "M", "-s", "7", "-m", "3", "-t", "PNG", "-o", "-", payload],
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return ""
    return base64.b64encode(png).decode()


def cert_sha256(path: pathlib.Path) -> str:
    try:
        der = subprocess.check_output(
            ["openssl", "x509", "-in", str(path), "-outform", "DER"],
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return ""
    return hashlib.sha256(der).hexdigest()


def outbound(path: pathlib.Path, tag: str = "proxy") -> dict:
    try:
        doc = json.loads(path.read_text())
    except Exception:
        return {}
    for item in doc.get("outbounds", []):
        if isinstance(item, dict) and item.get("tag") == tag:
            return item
    return {}


def method_asset(
    ident: str,
    label: str,
    category: str,
    *,
    url: str = "",
    config: str = "",
    qr_payload: str = "",
    apps: list[str] | None = None,
    note: str = "",
    native: str = "",
) -> dict:
    payload = qr_payload or url or config
    return {
        "id": ident,
        "label": label,
        "category": category,
        "url": url,
        "config": config,
        "qrPayload": payload,
        "qrPngBase64": qr_png(payload),
        "apps": apps or [],
        "note": note,
        "native": native,
        "available": bool(url or config or payload),
    }


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: generate-setup-assets.py BASE ENDPOINT SOCKS_HOST", file=sys.stderr)
        return 2

    base = pathlib.Path(sys.argv[1])
    endpoint = sys.argv[2].strip().strip("[]")
    socks_host = sys.argv[3].strip()
    gen = base / "client-bundle" / "generated"

    assets: list[dict] = []

    wg = read_text(gen / "wg" / "wg.conf")
    assets.append(method_asset(
        "wireguard",
        "WireGuard",
        "VPN",
        config=wg,
        apps=["WireGuard", "Router VPN"],
        note="Best universal config. WireGuard mobile/desktop apps can import the file; mobile apps can scan this QR.",
        native="Not built into the OS by itself; install a WireGuard-compatible app/profile provider.",
    ))

    awg = read_text(gen / "awg2-fast" / "awg.conf")
    assets.append(method_asset(
        "amneziawg2",
        "AmneziaWG 2",
        "VPN",
        config=awg,
        apps=["AmneziaVPN / AmneziaWG", "Router VPN"],
        note="Use the generated AWG config. QR import support depends on the Amnezia client/version.",
        native="Requires an AmneziaWG-compatible client; it is not a built-in OS VPN type.",
    ))

    ss = outbound(gen / "shadowsocks" / "sing-box.json")
    ss_url = ""
    if endpoint and ss:
        method = str(ss.get("method") or "")
        password = str(ss.get("password") or "")
        port = int(ss.get("server_port") or 8388)
        # SIP002: AEAD-2022 userinfo must remain plain (percent encoded), not Base64URL.
        userinfo = urllib.parse.quote(method, safe="") + ":" + urllib.parse.quote(password, safe="")
        ss_url = f"ss://{userinfo}@{hostport(endpoint, port)}/#Router%20VPN%20Shadowsocks"
    assets.append(method_asset(
        "shadowsocks",
        "Shadowsocks 2022",
        "Proxy / full tunnel in Router VPN",
        url=ss_url,
        config=read_text(gen / "shadowsocks" / "sing-box.json"),
        apps=["Shadowsocks", "sing-box", "Potatso-compatible clients", "Router VPN"],
        note="The share URL follows SIP002. Router VPN uses the full sing-box config for full-device TUN.",
        native="No mainstream OS has native Shadowsocks settings; import the URL/config into a compatible client.",
    ))

    hy = outbound(gen / "hysteria2" / "sing-box.json")
    hy_url = ""
    if endpoint and hy:
        port = int(hy.get("server_port") or 8443)
        password = str(hy.get("password") or "")
        tls = hy.get("tls") if isinstance(hy.get("tls"), dict) else {}
        obfs = hy.get("obfs") if isinstance(hy.get("obfs"), dict) else {}
        query: list[tuple[str, str]] = []
        if tls.get("server_name"):
            query.append(("sni", str(tls["server_name"])))
        pin = cert_sha256(gen / "hysteria2" / "cert.pem")
        if pin:
            query.append(("pinSHA256", pin))
        if obfs.get("type"):
            query.append(("obfs", str(obfs["type"])))
        if obfs.get("password"):
            query.append(("obfs-password", str(obfs["password"])))
        hy_url = (
            "hysteria2://"
            + urllib.parse.quote(password, safe="")
            + "@"
            + hostport(endpoint, port)
            + "/?"
            + urllib.parse.urlencode(query)
            + "#Router%20VPN%20Hysteria2"
        )
    assets.append(method_asset(
        "hysteria2",
        "Hysteria2 + QUIC",
        "Proxy / full tunnel in Router VPN",
        url=hy_url,
        config=read_text(gen / "hysteria2" / "sing-box.json"),
        apps=["Hysteria 2", "sing-box", "Router VPN"],
        note="Uses the official Hysteria2 URI fields, including the generated certificate pin when available.",
        native="Requires a Hysteria2/sing-box-compatible client; it is not a built-in OS VPN type.",
    ))

    sslocal_path = gen / "ss-v2ray" / "sslocal.json"
    ss_v2ray_url = ""
    try:
        sslocal = json.loads(sslocal_path.read_text())
    except Exception:
        sslocal = {}
    if endpoint and sslocal:
        method = str(sslocal.get("method") or "")
        password = str(sslocal.get("password") or "")
        port = int(sslocal.get("server_port") or 12443)
        plugin = str(sslocal.get("plugin") or "")
        opts = str(sslocal.get("plugin_opts") or "")
        userinfo = urllib.parse.quote(method, safe="") + ":" + urllib.parse.quote(password, safe="")
        plugin_arg = plugin + (";" + opts if opts else "")
        ss_v2ray_url = (
            f"ss://{userinfo}@{hostport(endpoint, port)}/?"
            + urllib.parse.urlencode({"plugin": plugin_arg})
            + "#Router%20VPN%20SS%2BV2Ray"
        )
    assets.append(method_asset(
        "ss-v2ray",
        "Shadowsocks + V2Ray TLS",
        "Proxy / full tunnel in Router VPN",
        url=ss_v2ray_url,
        config=read_text(sslocal_path),
        apps=["Shadowsocks clients with SIP003/V2Ray plugin", "Router VPN"],
        note="Use only in clients that support the V2Ray SIP003 plugin. Router VPN also carries the UDP fallback automatically.",
        native="Requires a compatible Shadowsocks+plugin client; no native OS import exists.",
    ))

    socks_text = f"SOCKS5 host: {socks_host}\nPort: 1080\nAuthentication: none\nUse only after the VPN reaches home."
    assets.append(method_asset(
        "socks5",
        "SOCKS5 (inside VPN)",
        "App proxy",
        config=socks_text,
        qr_payload=socks_text,
        apps=["Potatso", "Browsers/apps with SOCKS5", "macOS SOCKS proxy"],
        note="The QR is plain settings text, not a universal SOCKS import URI. Never WAN-forward TCP 1080.",
        native="macOS can set a SOCKS proxy per network service. iOS/Android/Windows generally need an app for SOCKS5 rather than a native system-wide SOCKS setting.",
    ))

    device_guides = {
        "ios": {
            "label": "iPhone / iPad",
            "customApp": "The current Router VPN IPA is a controller/importer until its Packet Tunnel adapters are linked; do not treat it as a finished all-mode VPN client yet.",
            "steps": [
                "For WireGuard: install WireGuard, choose Add a tunnel → Create from QR code, then scan the WireGuard QR.",
                "For AmneziaWG: import the generated AWG config into an Amnezia-compatible client.",
                "For Shadowsocks/SOCKS5 testing: Potatso or another compatible proxy client can be used when it supports the selected format.",
                "For Hysteria2: use a Hysteria2/sing-box-compatible iOS client and import the share URL/QR.",
            ],
        },
        "android": {
            "label": "Android",
            "customApp": "The current Router VPN APK is a controller/importer until its native VpnService engine adapters are linked.",
            "steps": [
                "WireGuard: import the config file or scan its QR in WireGuard for Android.",
                "AmneziaWG: import the AWG config in an Amnezia-compatible client.",
                "Shadowsocks: import the SIP002 URL/QR in a compatible Shadowsocks client.",
                "Hysteria2: import the Hysteria2 URL/QR in a compatible client.",
            ],
        },
        "macos": {
            "label": "macOS",
            "customApp": "From the extracted private bundle run: bash client/install-macos-final.sh \"$PWD\" ; then open http://127.0.0.1:8788.",
            "steps": [
                "Router VPN is the easiest way to use AUTO/SMART AUTO/CUSTOM and the complete mode set.",
                "WireGuard/AWG configs can also be imported into their native client apps.",
                "For app-only plain SOCKS5 after connecting home: System Settings → Network → your service → Details → Proxies → SOCKS Proxy; use the shown home SOCKS host and port 1080.",
            ],
        },
        "windows": {
            "label": "Windows",
            "customApp": "Use the Windows x64/ARM64 or PortableApps artifact from Build all platforms. Full multi-engine shell parity currently uses WSL2; raw WG/AWG profiles remain importable in native clients.",
            "steps": [
                "WireGuard: import wg.conf in WireGuard for Windows.",
                "AmneziaWG: import the AWG config in a compatible Windows client.",
                "Shadowsocks/Hysteria2: use a compatible protocol client or Router VPN/WSL2 path.",
            ],
        },
        "linux": {
            "label": "Linux",
            "customApp": "From the extracted private bundle run: sudo bash client/install-linux.sh \"$PWD\" ; then open http://127.0.0.1:8788.",
            "steps": [
                "Router VPN supports the complete client engine path on Linux.",
                "WireGuard/AWG configs may also be imported into compatible native/network-manager tooling.",
                "SOCKS5 can be configured per app after a home tunnel is active.",
            ],
        },
        "other": {
            "label": "Other / router / manual client",
            "customApp": "Use the generated protocol URL/config shown below. Router VPN's custom app packages are currently strongest on macOS/Linux; other builds expose only the capabilities actually linked for that platform.",
            "steps": [
                "Prefer the exact generated config over manually retyping keys.",
                "Do not upload/share this private bundle or its QR codes.",
            ],
        },
    }

    output = {
        "version": 1,
        "private": True,
        "warning": "These URLs, configs, and QR codes contain private connection material. Keep them private.",
        "devices": device_guides,
        "methods": assets,
    }
    path = base / "client-bundle" / "setup-assets.json"
    path.write_text(json.dumps(output, indent=2) + "\n")
    path.chmod(0o600)
    print(f"Generated {sum(1 for x in assets if x['available'])} setup assets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
