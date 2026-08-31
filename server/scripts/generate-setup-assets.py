#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
import pathlib
import subprocess
import sys
import tempfile
import urllib.parse

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
_verified_spec = spec_from_file_location(
    "router_vpn_setup_assets_verified_read",
    SCRIPT_DIR / "verified-regular-read.py",
)
if _verified_spec is None or _verified_spec.loader is None:
    raise RuntimeError("cannot load verified-regular-read.py")
_verified = module_from_spec(_verified_spec)
_verified_spec.loader.exec_module(_verified)
read_verified_regular = _verified.read_verified_regular


def hostport(host: str, port: int) -> str:
    host = host.strip().strip("[]")
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def read_text(path: pathlib.Path, *, private: bool = True) -> str:
    try:
        return read_verified_regular(path, private=private).decode("utf-8")
    except (OSError, RuntimeError, UnicodeError):
        return ""


def read_json(path: pathlib.Path, *, private: bool = True) -> dict | list:
    try:
        return json.loads(read_text(path, private=private))
    except Exception:
        return {}


def qr_png(payload: str) -> str:
    if not payload:
        return ""
    try:
        png = subprocess.check_output(
            ["qrencode", "-l", "M", "-s", "7", "-m", "3", "-t", "PNG", "-o", "-", payload],
            stderr=subprocess.DEVNULL,
        )
        return base64.b64encode(png).decode()
    except Exception:
        return ""


def cert_sha256(path: pathlib.Path) -> str:
    try:
        pem = read_verified_regular(path, private=True)
        der = subprocess.check_output(
            ["openssl", "x509", "-inform", "PEM", "-outform", "DER"],
            input=pem,
            stderr=subprocess.DEVNULL,
        )
        return hashlib.sha256(der).hexdigest()
    except Exception:
        return ""


def outbound(path: pathlib.Path, tag: str = "proxy") -> dict:
    doc = read_json(path)
    if not isinstance(doc, dict):
        return {}
    for item in doc.get("outbounds", []):
        if isinstance(item, dict) and item.get("tag") == tag:
            return item
    return {}


def asset(ident: str, label: str, category: str, *, url: str = "", config: str = "", apps=None, note="", native="", simple=False) -> dict:
    payload = url or config
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
        "available": bool(payload),
        "simple": bool(simple),
    }


def generic_config(gen: pathlib.Path, ident: str, label: str, rel: str, note: str, apps=None) -> dict:
    return asset(
        ident, label, "Advanced config", config=read_text(gen / rel), apps=apps or ["Router VPN", "compatible protocol client"],
        note=note, native="No universal native OS import exists for this stack; use Router VPN or a compatible client."
    )


def build_methods(gen: pathlib.Path, endpoint: str, socks_host: str) -> list[dict]:
    methods: list[dict] = []
    methods.append(asset(
        "wireguard", "WireGuard Raw", "Simple VPN", config=read_text(gen/"wg"/"wg.conf"),
        apps=["WireGuard", "Router VPN"],
        note="Fastest and simplest full-tunnel profile. Recommended first independent-client connectivity test.",
        native="WireGuard app: add/import a tunnel, choose the generated .conf or scan its QR, approve the OS VPN permission, then connect.", simple=True,
    ))
    methods.append(asset(
        "amneziawg2", "AmneziaWG 2", "Simple obfuscated VPN", config=read_text(gen/"awg2-fast"/"awg.conf"),
        apps=["AmneziaVPN / AmneziaWG", "Router VPN"],
        note="WireGuard-family tunnel with packet/header obfuscation.",
        native="Amnezia-compatible app: import the generated AWG config and approve VPN permission. Third-party off-LAN interoperability remains a live validation gate; generated configuration alone is not proof of readiness.", simple=True,
    ))

    ss = outbound(gen/"shadowsocks"/"sing-box.json"); ss_url=""
    if endpoint and endpoint != "router.invalid" and ss:
        ui=urllib.parse.quote(str(ss.get("method") or ""),safe="")+":"+urllib.parse.quote(str(ss.get("password") or ""),safe="")
        ss_url=f"ss://{ui}@{hostport(endpoint,int(ss.get('server_port') or 8388))}/#Router%20VPN%20Shadowsocks"
    methods.append(asset(
        "shadowsocks", "Shadowsocks 2022", "Simple proxy", url=ss_url,
        config=read_text(gen/"shadowsocks"/"sing-box.json"),
        apps=["Shadowsocks/SIP002-compatible client", "sing-box", "Router VPN"],
        note="Uses the public node endpoint. If a public endpoint is not known yet, Setup Center keeps the config available but does not fabricate a public QR.",
        native="Import the SIP002 URL/QR in a client that explicitly supports its Shadowsocks 2022 method.", simple=True,
    ))

    hy=outbound(gen/"hysteria2"/"sing-box.json"); hy_url=""
    if endpoint and endpoint != "router.invalid" and hy:
        tls=hy.get("tls") if isinstance(hy.get("tls"),dict) else {}; obfs=hy.get("obfs") if isinstance(hy.get("obfs"),dict) else {}; q=[]
        if tls.get("server_name"): q.append(("sni",str(tls["server_name"])))
        pin=cert_sha256(gen/"hysteria2"/"cert.pem")
        if pin:q.append(("pinSHA256",pin))
        if obfs.get("type"):q.append(("obfs",str(obfs["type"])))
        if obfs.get("password"):q.append(("obfs-password",str(obfs["password"])))
        hy_url="hysteria2://"+urllib.parse.quote(str(hy.get("password") or ""),safe="")+"@"+hostport(endpoint,int(hy.get("server_port") or 8443))+"/?"+urllib.parse.urlencode(q)+"#Router%20VPN%20Hysteria2"
    methods.append(asset(
        "hysteria2", "Hysteria2 + QUIC", "Simple QUIC VPN/proxy", url=hy_url,
        config=read_text(gen/"hysteria2"/"sing-box.json"), apps=["Hysteria2", "sing-box", "Router VPN"],
        note="Public-endpoint Hysteria2 import URL plus full config.", native="Import into a Hysteria2/sing-box-compatible client.", simple=True,
    ))

    overtls=read_text(gen/"overtls"/"overtls-client.json")
    methods.append(asset(
        "overtls", "SOCKS5 + TLS (OverTLS)", "Simple compatibility proxy", config=overtls,
        apps=["OverTLS-compatible client"],
        note="Public TLS terminates on the home node; backend 14444 stays loopback-only. This is separate from Router VPN's logical-mode catalog.",
        native="Import the generated OverTLS client config in an explicitly compatible client.", simple=True,
    ))
    ssr=read_text(gen/"shadowsocksr"/"ssr-client.json")
    methods.append(asset(
        "shadowsocksr", "ShadowsocksR", "Legacy compatibility", config=ssr,
        apps=["ShadowsocksR-compatible client"],
        note="Legacy compatibility only; prefer WireGuard, Shadowsocks 2022, Hysteria2, or Router VPN.", native="Import only into an SSR-compatible client.", simple=True,
    ))

    # SOCKS5 is intentionally private and only useful after the device already
    # has a route home. Never turn its LAN host into a WAN QR or expose 1080.
    socks=f"SOCKS5 host: {socks_host}\nPort: 1080\nAuthentication: none\nUse only after the device already reaches home through Router VPN/WireGuard/AmneziaWG."
    item=asset(
        "socks5", "SOCKS5 (inside VPN)", "Private app proxy", config=socks,
        apps=["Potatso (manual SOCKS5 profile)", "Apps with SOCKS5 support", "Router VPN"],
        note="Private in-tunnel proxy only. Never WAN-forward TCP 1080. The private host is intentional and is not the public VPN exit IP.",
        native=f"Potatso/manual client: add SOCKS5 host {socks_host}, port 1080, no authentication, only after the device is already connected home through a VPN tunnel.", simple=True,
    )
    item["qrPayload"]=""; item["qrPngBase64"]=""
    methods.append(item)
    return methods


def build_html(data: dict) -> str:
    packed = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    page = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Router VPN — Setup Center</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='16' fill='%230d1220'/%3E%3Cpath d='M32 8 52 16v14c0 13-8.4 22.1-20 27C20.4 52.1 12 43 12 30V16l20-8Z' fill='%2362d5ff'/%3E%3Cpath d='m24 32.5 5.5 5.5L41 25' fill='none' stroke='white' stroke-width='5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2d;--panel2:#0e1527;--line:#273550;--text:#eef4ff;--muted:#9cabca;--accent:#69d2ff;--ok:#7ce39a;--warn:#ffd27d;--bad:#ff8d9a}*{box-sizing:border-box}body{font-family:ui-sans-serif,system-ui,-apple-system;margin:0;background:radial-gradient(circle at 20% -10%,#1b2b50 0,transparent 36%),var(--bg);color:var(--text)}a{color:var(--accent)}.wrap{max-width:1220px;margin:auto;padding:20px}.top{display:flex;gap:14px;align-items:center;justify-content:space-between;flex-wrap:wrap}.brand{display:flex;gap:12px;align-items:center}.logo{width:46px;height:46px;border-radius:14px;background:#0d172a;display:grid;place-items:center;font-size:25px}.tag{color:var(--muted);font-size:13px}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0;position:sticky;top:0;padding:10px 0;background:linear-gradient(var(--bg) 70%,transparent);z-index:4}.tabs button,.btn,button,select,input{font:inherit}.tabs button,.btn,button{-webkit-appearance:none;appearance:none;display:inline-flex;align-items:center;justify-content:center;gap:7px;min-height:40px;padding:10px 13px;border-radius:11px;border:1px solid var(--line);background-color:#15213a;background-image:none;background-clip:padding-box;color:var(--text);cursor:pointer;text-decoration:none;line-height:1.2;font-weight:600;box-shadow:inset 0 1px 0 #ffffff0b;transition:border-color .15s ease,background-color .15s ease,transform .08s ease,opacity .15s ease}.tabs button:hover,.btn:hover,button:hover{border-color:#426c92;background-color:#1a2a47}.tabs button:active,.btn:active,button:active{transform:translateY(1px);background-color:#112039}.tabs button:focus-visible,.btn:focus-visible,button:focus-visible,select:focus-visible,input:focus-visible{outline:3px solid #69d2ff66;outline-offset:2px}.tabs button:disabled,.btn[aria-disabled="true"],button:disabled{cursor:not-allowed;opacity:.48;transform:none;background-color:#101a2d;color:#9cabca}.tabs button.active,.btn.primary{border-color:#4aa6cf;background-color:#163d54;color:#eefaff}.btn.danger{border-color:#80434d;background-color:#391b24;color:#ffeef1}.btn.danger:hover{background-color:#4a202b}.btn>svg,button>svg{flex:none}.panel{display:none}.panel.active{display:block}.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:17px;padding:17px;margin:13px 0;box-shadow:0 14px 40px #0002}.hero{padding:22px}.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px}.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:13px}@media(max-width:820px){.grid2,.grid3{grid-template-columns:1fr}.wrap{padding:max(12px,env(safe-area-inset-top)) max(12px,env(safe-area-inset-right)) max(12px,env(safe-area-inset-bottom)) max(12px,env(safe-area-inset-left))}.card{padding:13px}.tabs{position:static;overflow-x:auto;flex-wrap:nowrap;padding-bottom:6px;-webkit-overflow-scrolling:touch}.tabs button{white-space:nowrap;flex:0 0 auto}.download{align-items:flex-start;flex-direction:column}.grow{min-width:0;width:100%}.row>.btn,.row>button{max-width:100%}.wizard{padding:15px}.overlay{padding:max(10px,env(safe-area-inset-top)) max(10px,env(safe-area-inset-right)) max(10px,env(safe-area-inset-bottom)) max(10px,env(safe-area-inset-left))}}@media(forced-colors:active){.tabs button,.btn,button,select,input{forced-color-adjust:auto;border:1px solid ButtonText}.tabs button.active,.btn.primary{outline:2px solid Highlight}.btn.danger{border-color:Mark}}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.grow{flex:1;min-width:210px}.small{font-size:13px;color:var(--muted)}.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#080d18;border:1px solid var(--line);border-radius:11px;padding:12px;max-height:330px;overflow:auto}code{overflow-wrap:anywhere}.pill{display:inline-block;padding:5px 8px;border:1px solid var(--line);border-radius:999px;margin:3px;font-size:12px}.download{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border:1px solid var(--line);border-radius:12px;margin:8px 0}.step{display:grid;grid-template-columns:36px 1fr;gap:12px;margin:14px 0}.num{width:34px;height:34px;border-radius:50%;display:grid;place-items:center;background:#183d58;color:#bfefff;font-weight:700}.scroll{overflow:auto;-webkit-overflow-scrolling:touch}table{width:100%;border-collapse:collapse;font-size:13px;min-width:1120px}th,td{padding:9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.simple{border-color:#356782}.qr{background:#fff;padding:10px;border-radius:12px;max-width:265px;width:100%}select,input{-webkit-appearance:none;appearance:none;min-height:40px;padding:10px 12px;border-radius:10px;border:1px solid var(--line);background-color:#0c1425;background-image:none;color:var(--text);caret-color:var(--accent)}select{padding-right:34px;background-image:linear-gradient(45deg,transparent 50%,#9cabca 50%),linear-gradient(135deg,#9cabca 50%,transparent 50%);background-position:calc(100% - 17px) 50%,calc(100% - 12px) 50%;background-size:5px 5px,5px 5px;background-repeat:no-repeat}.overlay{position:fixed;inset:0;background:#000c;z-index:50;display:grid;place-items:center;padding:18px}.overlay[hidden]{display:none}.wizard{width:min(900px,100%);max-height:92vh;overflow:auto;background:#10192c;border:1px solid #385073;border-radius:18px;padding:20px;box-shadow:0 30px 100px #000}.progress{font-size:12px;color:var(--muted)}.notice{border:1px solid #695628;background:#251f12;padding:12px;border-radius:12px}.method-card{padding:13px;border:1px solid var(--line);border-radius:13px;margin:9px 0}.method-card:hover{border-color:#426c92}.hidden{display:none!important}
</style></head><body><div class="wrap">
<div class="top"><div class="brand"><div class="logo">🛡️</div><div><h1 style="margin:0">Router VPN</h1><div class="tag">Private LAN Setup Center • onboarding, downloads, devices, modes, forwarding and troubleshooting</div></div></div><div class="row"><button class="btn primary" onclick="startWizard(true)">Start / resume setup</button><a class="btn" href="/router-vpn-bundle.json" download>Download router profile</a></div></div>
<div class="notice" style="margin-top:14px"><b>Keep this page private.</b> It can contain router-specific import data and QR codes. Port 8786 is intended for your home LAN only; do not WAN-forward it.</div>
<div class="tabs" id="tabs"></div>

<section class="panel active" data-tab="start"><div class="card hero"><h2>Choose the easiest path</h2><div class="grid3">
<div class="card simple"><h3>1. Router VPN app</h3><p>Best overall. Install the small platform package, pair/import <code>router-vpn-bundle.json</code>, then choose WireGuard, AUTO, SMART AUTO, CUSTOM or any validated mode in the app.</p><button onclick="gotoTab('downloads')">Get the app/controller</button></div>
<div class="card simple"><h3>2. WireGuard only</h3><p>Fastest simple setup. Use the WireGuard config/QR from Devices & methods. It is the default base and the first connectivity test.</p><button onclick="gotoTab('devices')">Show WireGuard setup</button></div>
<div class="card simple"><h3>3. Compatible protocol app</h3><p>Use AmneziaWG, Shadowsocks, Hysteria2, OverTLS, ShadowsocksR, or the private in-tunnel SOCKS5 method only with clients that explicitly support that simple protocol. Complex Router VPN stacks stay in the Router VPN app.</p><button onclick="gotoTab('devices')">Choose a method</button></div>
</div></div>
<div class="card"><h2>Full setup at a glance</h2><div id="quickSteps"></div></div></section>

<section class="panel" data-tab="downloads"><div class="card"><h2>Small downloads first</h2><p class="small">You do not need the all-platform private ZIP for normal setup. Use the direct profile/helper or the package matching this device. The complete bundle remains an offline/advanced fallback.</p><div id="downloads"></div></div><div class="card"><h2>macOS security warning / “malware” or developer warning</h2><p>Router VPN includes locally-built/open-source networking binaries. macOS may quarantine an unsigned binary. <b>Do not bypass a warning blindly.</b> First verify the file came from this Setup Center and compare the included checksum.</p><ol><li>Open <b>System Settings → Privacy & Security</b> and use <b>Open Anyway</b> for the Router VPN binary/app you just verified.</li><li>If you intentionally need to remove quarantine from the trusted extracted Router VPN folder, Terminal can use:</li></ol><pre>xattr -dr com.apple.quarantine /path/to/router-vpn</pre><p class="small">Use that command only on the Router VPN folder you verified; never run it broadly on Downloads or your whole Mac.</p></div></section>

<section class="panel" data-tab="devices"><div class="card"><h2>Device & method setup</h2><div class="row"><select id="device" class="grow"></select><select id="method" class="grow"></select></div><div id="deviceHelp" class="card"></div><div id="methodHelp" class="grid2"><div><h3 id="methodLabel"></h3><div id="methodApps"></div><p id="methodNote"></p><p><b>System/native:</b> <span id="methodNative"></span></p><div id="urlBox" hidden><h4>Import URL</h4><pre id="urlText"></pre><button onclick="copyText('urlText')">Copy URL</button></div><div id="cfgBox" hidden><h4>Config/settings</h4><pre id="cfgText"></pre><button onclick="copyText('cfgText')">Copy config</button></div></div><div id="qrBox"></div></div></div></section>

<section class="panel" data-tab="router"><div class="card"><h2>ASUS / Asuswrt-Merlin forwarding</h2><p>The helper is downloadable directly—no huge ZIP required. It preserves existing <code>nat-start</code>/<code>firewall-start</code> contents and installs only direct tagged IPv4 WAN-interface + protocol + exact-port rules. There is no broad Router VPN WAN catch-all; failures leave ordinary household Internet untouched.</p><label>ASUS SSH username <input id="routerUser" autocomplete="username" value="ROUTER_USER" oninput="updateRouterInstall()"></label><p class="small">This value stays in your browser and is used only to render the commands below.</p><div class="row"><a class="btn primary" href="/asus-merlin-router-vpn-forwards.sh" download>Download forwarding helper</a><button onclick="copyText('routerInstall')">Copy install commands</button></div><pre id="routerInstall"></pre></div><div class="card"><h3>Enable SSH safely</h3><ol><li>ASUS GUI → <b>Administration → System</b> (wording can vary by firmware).</li><li>Enable the SSH daemon for <b>LAN only</b>. Do not enable WAN SSH.</li><li>Enter the ASUS username above and test the generated SSH command.</li></ol><p class="small">Some newer ASUS builds have an SFTP-incomplete SSH server, so the Setup Center uses SSH stdin instead of <code>scp</code>.</p></div><div class="card"><h3>Check compatibility / existing rules before changing anything</h3><pre>/usr/sbin/iptables --version
nvram get vts_rulelist
cat /jffs/scripts/nat-start 2>/dev/null
cat /jffs/scripts/firewall-start 2>/dev/null
/jffs/scripts/router-vpn-forward.sh status 2>/dev/null || true
/jffs/scripts/router-vpn-forward.sh verify 2>/dev/null || true</pre><p>If <code>/usr/sbin/iptables --version</code> works even when <code>command -v iptables</code> does not, the current Router VPN helper supports that ASUS quirk. If your firmware has neither working iptables nor the expected Merlin JFFS hooks, stop and use the firmware-specific forwarding path instead of forcing this helper.</p></div><div class="card"><h3>Expected public listeners</h3><pre>TCP      80      → AI Board 18080
TCP      443     → 443
UDP      585     → 585
TCP+UDP  8388    → 8388
UDP      8443    → 8443
TCP      10443   → 10443
TCP      11443   → 11443
TCP      12443   → 12443
TCP+UDP  13443   → 13443
TCP      14443   → 14443
TCP+UDP  15443   → 15443
UDP      51820   → 51820
UDP      51822   → 51822</pre><p class="small">Do not expose 1080, 8786–8793, 9443, 14444, 45999, SSH, Portainer, AdGuard admin, or any internal health/debug listener. ASUS management TCP 8443 does not conflict with Router VPN's UDP-only 8443 listener.</p></div><div class="card"><h3>Safe manual ASUS-GUI fallback</h3><p>If this firmware does not provide compatible <code>iptables</code> + Merlin JFFS hooks, do not force the script. First confirm <code>http://__SOCKS__:8786/healthz</code> works from your LAN. Then use ASUS <b>WAN → Virtual Server / Port Forwarding</b> and add only the exact protocol/port mappings listed above to <code>__SOCKS__</code> (TCP 80 targets 18080). Never use DMZ/Exposed Host, never forward the private/admin ports listed above, and never replace an unrelated existing forward that already owns the same protocol/port. Verify normal LAN Internet still works before testing from off-LAN. Roll back by disabling/deleting only the Router VPN GUI forwards you added.</p></div></section>

<section class="panel" data-tab="modes"><div class="card"><h2>All Router VPN raw runtimes — lightest to strongest</h2><p class="small"><b>Server/source readiness</b> below means the home-node profile/catalog entry was generated. It does <b>not</b> promise every platform has that engine. The installed Router VPN app revalidates platform engine/path availability and shows the exact live reason before Connect. The app groups these 20 raw runtimes into the 16 logical modes.</p><div class="scroll"><table><thead><tr><th># / mode</th><th>Protection/layers</th><th>Engine</th><th>Added ping</th><th>Traffic</th><th>Speed loss</th><th>Server/source readiness</th><th>Reason / next gate</th></tr></thead><tbody id="modeRows"></tbody></table></div></div><div class="card"><h3>AUTO / SMART AUTO / CUSTOM / ALL</h3><p><b>AUTO</b> tries the lightest eligible validated mode first and stops at the first healthy connection. <b>SMART AUTO</b> connects, then attempts simplifications while keeping a last-good stack. <b>CUSTOM</b> chooses a compatible validated stack containing the requested layers. <b>MAX</b> fails closed. <b>ALL</b> reports the strongest validated branch and cannot silently claim an unavailable stronger path.</p><p><b>DAITA-like</b> is bounded cover traffic; it is not claimed to be Mullvad's exact Maybenot DAITA implementation. <b>Jumbo TUN</b> is for compatible proxy/TUN paths, not raw WireGuard/AWG.</p></div></section>

<section class="panel" data-tab="forward"><div class="card"><h2>Port forwarding after you connect</h2><ol><li>Connect using WireGuard or AmneziaWG so the home router-agent can identify your tunnel peer.</li><li>In the Router VPN app open <b>Port forwarding</b>.</li><li>Choose TCP, UDP, or both; enter From/To; target 0 preserves the same range.</li><li><b>Protected DMZ</b> forwards unused ports only. Router VPN listeners and management ports remain reserved.</li><li>Use <b>Clear</b> when finished.</li></ol><p class="small">Proxy-only modes are outbound paths and cannot receive peer-targeted inbound forwarding the same way.</p></div><div class="card"><h2>SOCKS5</h2><p>Internal proxy: <code>__SOCKS__:1080</code>, no authentication, only after the VPN reaches home. The app separately tests/displays the <b>public exit IP</b>; do not interpret this private SOCKS address as the public internet address.</p></div></section>

<section class="panel" data-tab="guide"><div class="card"><h2>Complete guide</h2><div id="fullGuide"></div></div><div class="card"><h2>Multiple routers / nodes</h2><p>Install the app once, then pair/import one or many Router VPN or validated external nodes. The app remembers selection/recent use and can store optional real location/latitude/longitude. Desktop node ranking uses at least 50 TCP handshake samples and shows robust measured latency statistics; automatic fastest selection is never guessed.</p><p class="small"><b>Multihop truth:</b> Windows, macOS and Linux have real desktop entry→exit source paths; Android supports a narrower real subset; full desktop-equivalent iOS Router VPN multihop remains unavailable. The installed app still revalidates compatibility, DNS/exit proof, rollback and kill-switch interaction before claiming a chain is connected.</p></div><div class="card"><h2>Kill switch / client control</h2><p>Emergency Stop is separate from strict kill-switch policy. Windows/Linux/macOS have platform firewall source paths; Android and iOS use their platform VPN/route-lockdown mechanisms with truthful limits. Final Wi‑Fi/cellular/reconnect/sleep/failure leak proof is a physical-device release gate, not something this Setup Center page can prove.</p></div></section>

<section class="panel" data-tab="trouble"><div class="card"><h2>Troubleshooting</h2><h3>Mode says unavailable</h3><p>Read the exact reason in the app's mode table. Missing cert/profile/engine errors are real checks; do not silently downgrade a requested protection layer.</p><h3>Can’t SSH to ASUS</h3><p>Confirm SSH is enabled for LAN, the username is correct, and you can reach 192.168.50.1. Use the stdin transfer commands in this Setup Center rather than SFTP/scp on firmware that lacks an SFTP server.</p><h3>VPN works but incoming port does not</h3><p>Confirm the fixed WAN listener rules exist on ASUS, connect via WireGuard/AWG, then apply the client forwarding rule. Do not use a proxy-only mode for peer-targeted inbound forwarding.</p><h3>DNS</h3><p>Home AdGuard is default. If AdGuard <b>Allowed Clients</b> is blank, blank already means unrestricted—do not create a restrictive allowlist just to add VPN clients. If you intentionally use a restrictive allowlist, include <code>10.77.0.0/24</code>, <code>10.78.0.0/24</code>, <code>fd77:77::/64</code>, and <code>fd78:78::/64</code>. Native Router VPN apps expose Home, Fastest measured, Custom UDP/TCP, DoT, DoH, DoH3 and Rescue where the platform dataplane supports them. Resolver benchmark numbers are real A/AAAA DNS query RTTs measured from the selected home node—not ICMP ping—and runtime/session proof remains authoritative after reconnect.</p></div></section>

<div id="wizard" class="overlay" hidden><div class="wizard"><div id="wizardProgress" class="progress"></div><h2 id="wizardTitle"></h2><div id="wizardBody"></div><div class="row"><button onclick="wizardBack()">Back</button><button onclick="closeWizard()">Close for now</button><span class="grow"></span><button class="btn primary" onclick="wizardNext()" id="wizardNext">Next</button></div></div></div>
</div><script>
const DATA=__DATA__;const $=id=>document.getElementById(id);const tabs=['start','downloads','devices','router','modes','forward','guide','trouble'];const tabNames={start:'Start',downloads:'Downloads',devices:'Devices & methods',router:'ASUS forwarding',modes:'Modes',forward:'Port forwarding',guide:'Full guide',trouble:'Troubleshooting'};
function gotoTab(name){document.querySelectorAll('.panel').forEach(x=>x.classList.toggle('active',x.dataset.tab===name));document.querySelectorAll('#tabs button').forEach(x=>x.classList.toggle('active',x.dataset.tab===name));history.replaceState(null,'','#'+name)}
for(const t of tabs){const b=document.createElement('button');b.textContent=tabNames[t];b.dataset.tab=t;b.onclick=()=>gotoTab(t);$('tabs').appendChild(b)}gotoTab(location.hash.slice(1)&&tabs.includes(location.hash.slice(1))?location.hash.slice(1):'start');
const guideSteps=[
['Deploy the home node','Choose one verified exact main release SHA. Require Publish ARM64 Portainer images and Exact-SHA production compose to succeed for that same SHA. Verify the generated RouterVPN-Portainer-RELEASE_SHA.yaml checksum and image/broker pins, then use that generated YAML as the Portainer stack definition. The tracked server/portainer-current.yaml is only a template/baseline. Normal variables: WAN_INTERFACE=eth0, LAN_CIDR=192.168.50.0/24, ADGUARD4='+DATA.socksHost+'. ENDPOINT can stay blank for automatic public IPv4 detection.'],
['Verify services','router-vpn-init and router-vpn-finalize are one-shot containers and should exit 0. Agent, WireGuard, AWG2, Rosenpass, transports, Xray, Naive, SS+V2Ray, aux, bundle-web and SOCKS5 should run when their profiles are enabled.'],
['Install ASUS forwarding','Enable LAN-only SSH, check existing rules, download the forwarding helper, transfer it with SSH stdin, run install, then run /jffs/scripts/router-vpn-forward.sh verify. The helper uses narrow tagged exact-port rules and fails open for normal household Internet.'],
['Install/link a client','Choose the small package for your OS or a simple protocol app. You do not need the all-platform ZIP. Install Router VPN once, then pair/import router-vpn-bundle.json or validated external node data without reinstalling.'],
['Choose DNS','Home AdGuard is default. Optional choices include Fastest measured, common IPv4/IPv6 resolvers, Custom UDP/TCP, DoT, DoH, DoH3 and DNS Rescue. Resolver benchmark means home-node DNS query RTT, not ICMP.'],
['Connect','Start with WireGuard Raw. Then use AUTO, the recommended REALITY mode, SMART AUTO, CUSTOM, or a manual logical mode whose installed-platform readiness check is green.'],
['Test & forward','Confirm selected-node/path proof, public exit IP, DNS and IPv4/IPv6 behavior. For inbound forwarding, stay on a WireGuard/AWG peer path and use the app Port forwarding page.']
];
function stepHTML(items){return items.map((x,i)=>`<div class="step"><div class="num">${i+1}</div><div><h3 style="margin:4px 0">${x[0]}</h3><p>${x[1]}</p></div></div>`).join('')}$('quickSteps').innerHTML=stepHTML(guideSteps);$('fullGuide').innerHTML=stepHTML(guideSteps)+`<h3>Useful commands</h3><pre>ASUS status: /jffs/scripts/router-vpn-forward.sh status\nASUS verify: /jffs/scripts/router-vpn-forward.sh verify\nASUS firewall: /usr/sbin/iptables --version\nExisting ASUS GUI forwards: nvram get vts_rulelist\nMac local controller: http://127.0.0.1:8788\nHome Setup Center: http://${DATA.socksHost}:8786/</pre>`;
const downloads=[['Node data only','router-vpn-bundle.json','Private node data for an already-installed Router VPN app'],['Windows x64','router-vpn-windows-amd64.zip','Native installed app'],['Windows ARM64','router-vpn-windows-arm64.zip','Native installed app'],['Windows Portable x64','router-vpn-windows-portable-amd64.zip','Normal portable app; no PAF/PortableApps wrapper'],['Windows Portable ARM64','router-vpn-windows-portable-arm64.zip','Normal portable app; no PAF/PortableApps wrapper'],['macOS Apple Silicon','router-vpn-macos-arm64.zip','Native AppKit app'],['macOS Intel','router-vpn-macos-amd64.zip','Native AppKit app'],['Linux ARM64','router-vpn-linux-arm64.zip','Native GTK app'],['Linux x86-64','router-vpn-linux-amd64.zip','Native GTK app'],['Android','router-vpn-android.apk','Native Android VpnService app'],['iPhone / iPad','router-vpn-ios.ipa','Native iOS/iPadOS app; signing may be required'],['ASUS forwarding helper','asus-merlin-router-vpn-forwards.sh','Persistent Merlin NAT/FORWARD helper'],['Private node-link bundle','router-vpn-client-bundle.zip','Separate private node data for an already-installed Router VPN app; extract router-vpn-bundle.json for file import'],['Checksums','SHA256SUMS','Verify downloads before bypassing OS security warnings']];$('downloads').innerHTML=downloads.map(x=>`<div class="download"><div><b>${x[0]}</b><div class="small">${x[2]}</div></div><a class="btn" href="/${x[1]}" download>Download</a></div>`).join('');
const devices=DATA.devices||{};for(const [id,d] of Object.entries(devices)){const o=document.createElement('option');o.value=id;o.textContent=d.label||id;$('device').appendChild(o)}
const availableMethods=(DATA.methods||[]).filter(x=>x.available);availableMethods.sort((a,b)=>(b.simple?1:0)-(a.simple?1:0)||a.label.localeCompare(b.label));for(const m of availableMethods){const o=document.createElement('option');o.value=m.id;o.textContent=(m.simple?'Easy — ':'Advanced — ')+m.label;$('method').appendChild(o)}
function renderDevice(){const d=devices[$('device').value]||{};$('deviceHelp').innerHTML=`<h3>${d.label||''}</h3><p>${d.customApp||''}</p><ol>${(d.steps||[]).map(s=>`<li>${s}</li>`).join('')}</ol>`}
function renderMethod(){const m=availableMethods.find(x=>x.id===$('method').value)||{};$('methodLabel').textContent=m.label||'';$('methodApps').innerHTML=(m.apps||[]).map(a=>`<span class="pill">${a}</span>`).join('');$('methodNote').textContent=m.note||'';$('methodNative').textContent=m.native||'';$('urlBox').hidden=!m.url;$('urlText').textContent=m.url||'';$('cfgBox').hidden=!m.config;$('cfgText').textContent=m.config||'';const q=$('qrBox');q.innerHTML=m.qrPngBase64?`<h3>QR code</h3><img class="qr" alt="${m.label||'Setup'} QR" src="data:image/png;base64,${m.qrPngBase64}"><p class="small">This QR may contain private credentials. Scan only with a client you trust.</p>`:'<p class="small">No compact QR for this method; use the config/import file.</p>'}
$('device').onchange=renderDevice;$('method').onchange=renderMethod;renderDevice();renderMethod();
const layerLabel=x=>({'wireguard':'WireGuard','amneziawg2':'AmneziaWG 2','rosenpass-pq':'Rosenpass PQ','vless':'VLESS','vless-pq':'PQ VLESS','reality':'REALITY','xtls-vision':'XTLS Vision','utls-chrome':'Chrome uTLS','hysteria2':'Hysteria2','quic':'QUIC','shadowsocks2022':'Shadowsocks 2022','xhttp':'XHTTP','finalmask':'FinalMask','salamander':'Salamander'}[x]||x);$('modeRows').innerHTML=(DATA.modes||[]).filter(x=>!['smart-auto','custom'].includes(x.id)).map((x,i)=>{const ready=(x.maturity||'catalog').toLowerCase()==='generated'?'Generated':'Catalog';const why=ready==='Generated'?'Home-node profile was generated; installed client still revalidates its platform engine/path and reports the exact live reason before Connect.':'Server/source catalog entry only; installed client must report a runnable platform variant and exact live reason before Connect.';return `<tr><td><b>${x.name}</b><div class="small">${x.maturity||''}</div></td><td>${x.protection}<div class="small">${(x.layers||[]).map(layerLabel).join(' → ')}</div></td><td>${x.engine}</td><td>${x.ping_min_ms}–${x.ping_max_ms} ms</td><td>+${x.traffic_min_pct}–${x.traffic_max_pct}%</td><td>${x.speed_loss_min_pct}–${x.speed_loss_max_pct}%</td><td>${ready}</td><td>${why}</td></tr>`}).join('');
function updateRouterInstall(){const raw=($('routerUser')?.value||'ROUTER_USER').trim();const user=/^[A-Za-z0-9._-]{1,64}$/.test(raw)?raw:'ROUTER_USER';$('routerInstall').textContent=`# On your Mac/Linux computer\ncurl -fsS http://${DATA.socksHost}:8786/asus-merlin-router-vpn-forwards.sh -o /tmp/router-vpn-forwards.sh\nssh ${user}@192.168.50.1 'cat > /tmp/router-vpn-forwards.sh && chmod 755 /tmp/router-vpn-forwards.sh' < /tmp/router-vpn-forwards.sh\nssh ${user}@192.168.50.1 'sh /tmp/router-vpn-forwards.sh install && /jffs/scripts/router-vpn-forward.sh verify && /jffs/scripts/router-vpn-forward.sh status'`;}updateRouterInstall();
async function copyText(id){const v=$(id).textContent;try{await navigator.clipboard.writeText(v)}catch{const t=document.createElement('textarea');t.value=v;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove()}}
const WIZKEY='routervpn.setupcenter.done.v5',WIZSTEP='routervpn.setupcenter.step.v5';const wiz=[
['Welcome',`Install the generic native Router VPN app once, then link one or many private nodes by bundle/pairing. This wizard covers the complete path without requiring the huge ZIP. Choose a simple protocol or Router VPN app, deploy the home node, enable safe router SSH, install forwarding, install/link the client, choose DNS, connect, test, and optionally configure port forwarding.`],
['Choose a client method',`<b>Easiest full feature set:</b> Router VPN native app + router-vpn-bundle.json or one-time pairing.<br><b>Simplest single tunnel:</b> WireGuard config/QR.<br><b>Other simple methods:</b> AmneziaWG, Shadowsocks, Hysteria2, OverTLS or compatible legacy SSR. Complex Router VPN stacks stay in the Router VPN app.`],
['Deploy exact release',`Choose one verified exact <code>main</code> release SHA. Require <code>Publish ARM64 Portainer images</code> and <code>Exact-SHA production compose</code> to succeed for that same SHA. Verify the generated <code>RouterVPN-Portainer-RELEASE_SHA.yaml</code> checksum and image/broker pins, then use that generated YAML as the Portainer stack definition. The tracked <code>server/portainer-current.yaml</code> is only a template/baseline.<br>Set <code>WAN_INTERFACE=eth0</code>, <code>LAN_CIDR=192.168.50.0/24</code>, <code>ADGUARD4=${DATA.socksHost}</code>. Leave ENDPOINT blank for automatic detection unless you intentionally need to override it.`],
['Enable ASUS SSH',`ASUS GUI → Administration → System → enable SSH for <b>LAN only</b>. Enter the ASUS username in the forwarding tab and use its generated SSH command. Never expose SSH to WAN.`],
['Check current router rules',`Before changing forwarding, inspect <code>/usr/sbin/iptables --version</code>, <code>nvram get vts_rulelist</code>, existing JFFS hooks, and any prior Router VPN status. This protects custom firewall scripts from being overwritten.`],
['Install forwarding helper',`Open the ASUS forwarding tab and use the <b>SSH stdin</b> commands. This works on ASUS firmware where SFTP/scp is unavailable. Run verify after install. It must show no legacy broad catch-all, forbidden/private exposure, duplicate, LAN-to-WAN mutation, or Router VPN IPv6 rule; existing hooks stay preserved.`],
['Install/link the app',`Downloads provides a small platform-specific package. Install it once, then pair with a one-time Setup Center code or import <code>router-vpn-bundle.json</code>. Later Router VPN/external nodes are linked as data without reinstalling.`],
['macOS warning if shown',`Verify the package/checksum first. Then use System Settings → Privacy & Security → Open Anyway. Only for a verified Router VPN folder, <code>xattr -dr com.apple.quarantine /path/to/router-vpn</code> removes quarantine.`],
['DNS',`Home AdGuard is the default. Native Router VPN apps expose Fastest measured, common IPv4/IPv6 resolvers, Custom UDP/TCP, DoT, DoH, DoH3 and Rescue where supported. Retest uses real home-node A/AAAA DNS query RTT; reconnect and runtime proof confirm what is actually active.`],
['Connect & verify',`Start with WireGuard Raw. Then use AUTO, SMART AUTO, CUSTOM or another logical mode whose installed-platform readiness check is green. Modes shows 20 raw runtimes grouped into 16 logical modes, with layers, engineering latency/traffic/speed estimates, readiness and the exact live reason. Confirm selected-node/path proof and public exit; generic Internet alone is not enough.`],
['Forward ports if needed',`Use a WireGuard/AmneziaWG peer path, then configure TCP/UDP/both in the app. Protected DMZ excludes Router VPN and management ports. Clear forwarding when no longer needed.`],
['Finished',`Setup is complete. This full guide never disappears: use the Setup Center tabs or reopen this wizard at any time.`]
];let wi=+(localStorage.getItem(WIZSTEP)||0);function startWizard(force=false){if(force||localStorage.getItem(WIZKEY)!=='1'){$('wizard').hidden=false;renderWiz()}}function renderWiz(){wi=Math.max(0,Math.min(wi,wiz.length-1));localStorage.setItem(WIZSTEP,wi);$('wizardProgress').textContent=`Step ${wi+1} of ${wiz.length}`;$('wizardTitle').textContent=wiz[wi][0];$('wizardBody').innerHTML=`<p>${wiz[wi][1]}</p>`;$('wizardNext').textContent=wi===wiz.length-1?'Finish':'Next'}function wizardNext(){if(wi===wiz.length-1){localStorage.setItem(WIZKEY,'1');$('wizard').hidden=true;return}wi++;renderWiz()}function wizardBack(){if(wi>0)wi--;renderWiz()}function closeWizard(){$('wizard').hidden=true}if(localStorage.getItem(WIZKEY)!=='1')startWizard(false);
</script></body></html>'''
    return page.replace("__DATA__", packed).replace("__SOCKS__", data.get("socksHost", "home node"))


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: generate-setup-assets.py BASE ENDPOINT SOCKS_HOST", file=sys.stderr)
        return 2
    base = pathlib.Path(sys.argv[1])
    endpoint = sys.argv[2].strip().strip("[]")
    socks_host = sys.argv[3].strip()
    gen = base / "client-bundle" / "generated"
    methods = build_methods(gen, endpoint, socks_host)

    devices={
      "ios":{"label":"iPhone / iPad","customApp":"Router VPN is a real native app. Raw WireGuard uses the PacketTunnel engine today; supported Libbox paths are source-wired; unsupported AWG/OpenVPN/full desktop-equivalent multihop combinations stay visibly unavailable instead of being faked.","steps":["Install Router VPN or a simple compatible protocol app.","Import/pair router-vpn-bundle.json to add this node without reinstalling Router VPN.","For independent WireGuard, import/scan the generated profile in the WireGuard app.","Only choose a Setup Center Method whose client explicitly supports that protocol."]},
      "android":{"label":"Android","customApp":"Router VPN Android is a native VpnService app with native WireGuard/AmneziaWG and supported layered engines. Unsupported combinations fail closed with a reason.","steps":["Install the Router VPN APK.","Import/pair router-vpn-bundle.json to add this node; add later nodes the same way.","Approve Android VPN permission on first connection.","For an independent simple client, import the matching WireGuard/AWG/Shadowsocks/Hysteria2 method below."]},
      "macos":{"label":"macOS","customApp":"Router VPN is a native AppKit application. Install once, then import/pair one or many Router VPN/external nodes.","steps":["Download the package matching Apple Silicon or Intel.","Install/launch Router VPN and grant required network permissions.","Import/pair router-vpn-bundle.json.","Use Nodes/Map, Modes, DNS, Advanced, Forwarding, Settings and Help inside the native app."]},
      "windows":{"label":"Windows","customApp":"Router VPN is a native WPF Windows application; WSL is not part of the product path. Installed and normal Portable packages are available for x64 and ARM64.","steps":["Download the matching Installed or Portable package.","Launch Router VPN with the privileges required for full-device tunnel/firewall operations and approve Windows network prompts.","Import/pair router-vpn-bundle.json; add more nodes later without reinstalling.","Use WireGuard separately only when you intentionally want the simplest independent profile."]},
      "linux":{"label":"Linux","customApp":"Router VPN is a native GTK application on x86-64 and ARM64.","steps":["Download the matching Linux package.","Install/launch Router VPN and grant the required TUN/firewall privileges.","Import/pair router-vpn-bundle.json.","Use the native app for complex modes/stacks; Methods below are only simple external-client options."]},
      "manual":{"label":"Other / manual","customApp":"Use only a simple generated protocol that another client explicitly supports. Complex Router VPN stacks are not exported as fake universal imports.","steps":["Choose a simple Method below.","Follow its exact client/import guidance.","If no compact interoperable QR exists, use the config/manual fields instead.","Never expose Setup Center, admin, SSH or private SOCKS5 ports to WAN."]},
    }
    # modes.json is a public source catalog; generated tunnel/import material above is private.
    modes = read_json(base/"client-bundle"/"modes.json", private=False)
    if not isinstance(modes, list):
        modes=[]
    data={
      "warning":"This page and its QR codes can contain private router credentials. Keep port 8786 LAN-only.",
      "endpoint":endpoint,
      "socksHost":socks_host,
      "devices":devices,
      "methods":methods,
      "modes":modes,
      "downloads":["router-vpn-bundle.json","asus-merlin-router-vpn-forwards.sh","router-vpn-macos-arm64.zip","router-vpn-macos-amd64.zip","router-vpn-linux-arm64.zip","router-vpn-linux-amd64.zip","router-vpn-client-bundle.zip","SHA256SUMS"],
    }
    out=base/"client-bundle"
    out.mkdir(parents=True, exist_ok=True)
    assets_path=out/"setup-assets.json"
    html_path=out/"router-vpn-device-setup.html"
    with tempfile.TemporaryDirectory(prefix=".setup-assets.", dir=out) as td:
        stage=pathlib.Path(td)
        staged_assets=stage/"setup-assets.json"
        staged_html=stage/"router-vpn-device-setup.html"
        staged_assets.write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8")
        staged_html.write_text(build_html(data),encoding="utf-8")
        staged_assets.chmod(0o600)
        staged_html.chmod(0o600)
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR/"atomic-private-batch.py"),
                f"{assets_path}={staged_assets}",
                f"{html_path}={staged_html}",
            ],
            check=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
