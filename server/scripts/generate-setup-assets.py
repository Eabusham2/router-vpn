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
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text()
    except Exception:
        return ""


def read_json(path: pathlib.Path) -> dict | list:
    try:
        return json.loads(path.read_text())
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
        der = subprocess.check_output(
            ["openssl", "x509", "-in", str(path), "-outform", "DER"], stderr=subprocess.DEVNULL
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
        "router-vpn-app", "Router VPN app / controller", "Recommended full experience",
        config="Import router-vpn-bundle.json in the Router VPN app/controller. The app exposes AUTO, SMART AUTO, CUSTOM, all validated modes, DNS selection, node profiles, SOCKS5-only and forwarding.",
        apps=["Router VPN desktop controller", "Router VPN PWA", "Router VPN mobile controller/importer"],
        note="Best when you want the complete Router VPN feature set. Desktop currently provides the full local controller. Mobile builds must not be described as native all-mode VPNs until their platform tunnel adapters are validated.",
        native="Uses Router VPN itself; protocol-specific native apps remain available below.", simple=True,
    ))
    methods.append(asset(
        "wireguard", "WireGuard Raw", "Simple VPN", config=read_text(gen/"wg"/"wg.conf"),
        apps=["WireGuard", "Router VPN"],
        note="Fastest and simplest full-tunnel profile. Recommended first connectivity test.",
        native="Import with the WireGuard app/profile provider.", simple=True,
    ))
    methods.append(asset(
        "amneziawg2", "AmneziaWG 2", "Simple obfuscated VPN", config=read_text(gen/"awg2-fast"/"awg.conf"),
        apps=["AmneziaVPN / AmneziaWG", "Router VPN"],
        note="WireGuard-family tunnel with packet/header obfuscation. It remains an optional base; WireGuard is the default.",
        native="Requires an AmneziaWG-compatible app.", simple=True,
    ))

    ss = outbound(gen/"shadowsocks"/"sing-box.json"); ss_url=""
    if endpoint and ss:
        ui=urllib.parse.quote(str(ss.get("method") or ""),safe="")+":"+urllib.parse.quote(str(ss.get("password") or ""),safe="")
        ss_url=f"ss://{ui}@{hostport(endpoint,int(ss.get('server_port') or 8388))}/#Router%20VPN%20Shadowsocks"
    methods.append(asset(
        "shadowsocks", "Shadowsocks 2022", "Simple proxy", url=ss_url,
        config=read_text(gen/"shadowsocks"/"sing-box.json"),
        apps=["Shadowsocks", "sing-box", "Potatso-compatible clients", "Router VPN"],
        note="Compact SIP002 URL plus full sing-box config.", native="Import into a compatible app.", simple=True,
    ))

    hy=outbound(gen/"hysteria2"/"sing-box.json"); hy_url=""
    if endpoint and hy:
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
        note="QUIC transport with generated import URL and full config.", native="Requires a Hysteria2/sing-box-compatible client.", simple=True,
    ))

    sslocal=read_json(gen/"ss-v2ray"/"sslocal.json"); sv_url=""
    if endpoint and isinstance(sslocal, dict) and sslocal:
        ui=urllib.parse.quote(str(sslocal.get("method") or ""),safe="")+":"+urllib.parse.quote(str(sslocal.get("password") or ""),safe="")
        plugin=str(sslocal.get("plugin") or "")+(";"+str(sslocal.get("plugin_opts")) if sslocal.get("plugin_opts") else "")
        sv_url=f"ss://{ui}@{hostport(endpoint,int(sslocal.get('server_port') or 12443))}/?"+urllib.parse.urlencode({"plugin":plugin})+"#Router%20VPN%20SS%2BV2Ray"
    methods.append(asset(
        "ss-v2ray", "Shadowsocks + V2Ray TLS", "Advanced proxy", url=sv_url,
        config=read_text(gen/"ss-v2ray"/"sslocal.json"), apps=["SIP003/V2Ray-plugin Shadowsocks client", "Router VPN"],
        note="TLS/WebSocket compatibility path; UDP uses the generated fallback path where supported.", native="No native OS import."
    ))

    methods += [
        generic_config(gen,"reality-vision","VLESS + REALITY + Vision","reality-vision/xray.json","Recommended HTTPS-like camouflage stack.",["Xray-compatible client","Router VPN"]),
        generic_config(gen,"reality-pq-vision","PQ VLESS + REALITY + Vision","reality-pq-vision/xray.json","Hybrid-PQ VLESS payload protection with REALITY/Vision.",["Xray-compatible client","Router VPN"]),
        generic_config(gen,"reality-xhttp","PQ REALITY + XHTTP + FinalMask","reality-xhttp/xray.json","Advanced XHTTP/FinalMask configuration when generated and validated.",["Xray-compatible client","Router VPN"]),
        generic_config(gen,"naive-h2","Naive HTTPS H2","naive-h2/sing-box.json","HTTPS forward-proxy transport over HTTP/2.",["Naive/sing-box compatible client","Router VPN"]),
        generic_config(gen,"naive-h3","Naive HTTPS H3","naive-h3/sing-box.json","HTTPS/QUIC transport over HTTP/3.",["Naive/sing-box compatible client","Router VPN"]),
    ]

    overtls=read_text(gen/"overtls"/"overtls-client.json")
    methods.append(asset(
        "overtls", "SOCKS5 + TLS (OverTLS)", "Compatibility proxy", config=overtls,
        apps=["OverTLS-compatible clients"],
        note="Public TLS terminates at the home node; backend 14444 stays loopback-only. Separate from the 20-mode AUTO ladder.",
        native="Requires an OverTLS-compatible client."
    ))
    ssr=read_text(gen/"shadowsocksr"/"ssr-client.json")
    methods.append(asset(
        "shadowsocksr", "ShadowsocksR", "Legacy compatibility", config=ssr,
        apps=["ShadowsocksR-compatible clients"],
        note="Legacy compatibility only; prefer Shadowsocks 2022 or modern Router VPN modes.", native="Requires an SSR-compatible client."
    ))

    socks=f"SOCKS5 host: {socks_host}\nPort: 1080\nAuthentication: none\nUse only after the VPN reaches home."
    methods.append(asset(
        "socks5", "SOCKS5 (inside VPN)", "App proxy", config=socks,
        apps=["Potatso", "Browsers/apps with SOCKS5", "macOS SOCKS proxy"],
        note="Plain internal app proxy; never WAN-forward TCP 1080. The Router VPN app separately shows the public exit IP so this private address is not confused with your internet-facing IP.",
        native="macOS supports a per-network SOCKS proxy; other platforms typically use an app."
    ))
    return methods


def build_html(data: dict) -> str:
    packed = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    page = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Router VPN — Setup Center</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='16' fill='%230d1220'/%3E%3Cpath d='M32 8 52 16v14c0 13-8.4 22.1-20 27C20.4 52.1 12 43 12 30V16l20-8Z' fill='%2362d5ff'/%3E%3Cpath d='m24 32.5 5.5 5.5L41 25' fill='none' stroke='white' stroke-width='5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2d;--panel2:#0e1527;--line:#273550;--text:#eef4ff;--muted:#9cabca;--accent:#69d2ff;--ok:#7ce39a;--warn:#ffd27d;--bad:#ff8d9a}*{box-sizing:border-box}body{font-family:ui-sans-serif,system-ui,-apple-system;margin:0;background:radial-gradient(circle at 20% -10%,#1b2b50 0,transparent 36%),var(--bg);color:var(--text)}a{color:var(--accent)}.wrap{max-width:1220px;margin:auto;padding:20px}.top{display:flex;gap:14px;align-items:center;justify-content:space-between;flex-wrap:wrap}.brand{display:flex;gap:12px;align-items:center}.logo{width:46px;height:46px;border-radius:14px;background:#0d172a;display:grid;place-items:center;font-size:25px}.tag{color:var(--muted);font-size:13px}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0;position:sticky;top:0;padding:10px 0;background:linear-gradient(var(--bg) 70%,transparent);z-index:4}.tabs button,.btn,button,select,input{font:inherit}.tabs button,.btn,button{padding:10px 13px;border-radius:11px;border:1px solid var(--line);background:#15213a;color:var(--text);cursor:pointer}.tabs button.active,.btn.primary{border-color:#4aa6cf;background:#163d54}.btn.danger{border-color:#80434d;background:#391b24}.panel{display:none}.panel.active{display:block}.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:17px;padding:17px;margin:13px 0;box-shadow:0 14px 40px #0002}.hero{padding:22px}.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px}.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:13px}@media(max-width:820px){.grid2,.grid3{grid-template-columns:1fr}}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.grow{flex:1;min-width:210px}.small{font-size:13px;color:var(--muted)}.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#080d18;border:1px solid var(--line);border-radius:11px;padding:12px;max-height:330px;overflow:auto}code{overflow-wrap:anywhere}.pill{display:inline-block;padding:5px 8px;border:1px solid var(--line);border-radius:999px;margin:3px;font-size:12px}.download{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border:1px solid var(--line);border-radius:12px;margin:8px 0}.step{display:grid;grid-template-columns:36px 1fr;gap:12px;margin:14px 0}.num{width:34px;height:34px;border-radius:50%;display:grid;place-items:center;background:#183d58;color:#bfefff;font-weight:700}.scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px;min-width:820px}th,td{padding:9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.simple{border-color:#356782}.qr{background:#fff;padding:10px;border-radius:12px;max-width:265px;width:100%}select,input{padding:10px;border-radius:10px;border:1px solid var(--line);background:#0c1425;color:var(--text)}.overlay{position:fixed;inset:0;background:#000c;z-index:50;display:grid;place-items:center;padding:18px}.overlay[hidden]{display:none}.wizard{width:min(900px,100%);max-height:92vh;overflow:auto;background:#10192c;border:1px solid #385073;border-radius:18px;padding:20px;box-shadow:0 30px 100px #000}.progress{font-size:12px;color:var(--muted)}.notice{border:1px solid #695628;background:#251f12;padding:12px;border-radius:12px}.method-card{padding:13px;border:1px solid var(--line);border-radius:13px;margin:9px 0}.method-card:hover{border-color:#426c92}.hidden{display:none!important}
</style></head><body><div class="wrap">
<div class="top"><div class="brand"><div class="logo">🛡️</div><div><h1 style="margin:0">Router VPN</h1><div class="tag">Private LAN Setup Center • onboarding, downloads, devices, modes, forwarding and troubleshooting</div></div></div><div class="row"><button class="btn primary" onclick="startWizard(true)">Start / resume setup</button><a class="btn" href="/router-vpn-bundle.json" download>Download router profile</a></div></div>
<div class="notice" style="margin-top:14px"><b>Keep this page private.</b> It can contain router-specific import data and QR codes. Port 8786 is intended for your home LAN only; do not WAN-forward it.</div>
<div class="tabs" id="tabs"></div>

<section class="panel active" data-tab="start"><div class="card hero"><h2>Choose the easiest path</h2><div class="grid3">
<div class="card simple"><h3>1. Router VPN app</h3><p>Best overall. Install the small platform package, import <code>router-vpn-bundle.json</code>, then choose WireGuard, AUTO, SMART AUTO, CUSTOM or any validated mode in the app.</p><button onclick="gotoTab('downloads')">Get the app/controller</button></div>
<div class="card simple"><h3>2. WireGuard only</h3><p>Fastest simple setup. Use the WireGuard config/QR from Devices & methods. It is the default base and the first connectivity test.</p><button onclick="gotoTab('devices')">Show WireGuard setup</button></div>
<div class="card simple"><h3>3. Compatible protocol app</h3><p>Use Shadowsocks, Hysteria2, AmneziaWG, Xray, OverTLS or another compatible app without installing the full Router VPN controller.</p><button onclick="gotoTab('devices')">Choose a method</button></div>
</div></div>
<div class="card"><h2>Full setup at a glance</h2><div id="quickSteps"></div></div></section>

<section class="panel" data-tab="downloads"><div class="card"><h2>Small downloads first</h2><p class="small">You do not need the all-platform private ZIP for normal setup. Use the direct profile/helper or the package matching this device. The complete bundle remains an offline/advanced fallback.</p><div id="downloads"></div></div><div class="card"><h2>macOS security warning / “malware” or developer warning</h2><p>Router VPN includes locally-built/open-source networking binaries. macOS may quarantine an unsigned binary. <b>Do not bypass a warning blindly.</b> First verify the file came from this Setup Center and compare the included checksum.</p><ol><li>Open <b>System Settings → Privacy & Security</b> and use <b>Open Anyway</b> for the Router VPN binary/app you just verified.</li><li>If you intentionally need to remove quarantine from the trusted extracted Router VPN folder, Terminal can use:</li></ol><pre>xattr -dr com.apple.quarantine /path/to/router-vpn</pre><p class="small">Use that command only on the Router VPN folder you verified; never run it broadly on Downloads or your whole Mac.</p></div></section>

<section class="panel" data-tab="devices"><div class="card"><h2>Device & method setup</h2><div class="row"><select id="device" class="grow"></select><select id="method" class="grow"></select></div><div id="deviceHelp" class="card"></div><div id="methodHelp" class="grid2"><div><h3 id="methodLabel"></h3><div id="methodApps"></div><p id="methodNote"></p><p><b>System/native:</b> <span id="methodNative"></span></p><div id="urlBox" hidden><h4>Import URL</h4><pre id="urlText"></pre><button onclick="copyText('urlText')">Copy URL</button></div><div id="cfgBox" hidden><h4>Config/settings</h4><pre id="cfgText"></pre><button onclick="copyText('cfgText')">Copy config</button></div></div><div id="qrBox"></div></div></div></section>

<section class="panel" data-tab="router"><div class="card"><h2>ASUS / Asuswrt-Merlin forwarding</h2><p>The helper is downloadable directly—no huge ZIP required. It preserves existing <code>nat-start</code>/<code>firewall-start</code> contents and adds Router VPN chains.</p><div class="row"><a class="btn primary" href="/asus-merlin-router-vpn-forwards.sh" download>Download forwarding helper</a><button onclick="copyText('routerInstall')">Copy install commands</button></div><pre id="routerInstall"></pre></div><div class="card"><h3>Enable SSH safely</h3><ol><li>ASUS GUI → <b>Administration → System</b> (wording can vary by firmware).</li><li>Enable the SSH daemon for <b>LAN only</b>. Do not enable WAN SSH.</li><li>From Mac/Linux test: <code>ssh ROUTER_USER@192.168.50.1</code>.</li></ol><p class="small">Some newer ASUS builds have an SFTP-incomplete SSH server, so the Setup Center uses SSH stdin instead of <code>scp</code>.</p></div><div class="card"><h3>Check compatibility / existing rules before changing anything</h3><pre>/usr/sbin/iptables --version
nvram get vts_rulelist
cat /jffs/scripts/nat-start 2>/dev/null
cat /jffs/scripts/firewall-start 2>/dev/null
/jffs/scripts/router-vpn-forward.sh status 2>/dev/null || true</pre><p>If <code>/usr/sbin/iptables --version</code> works even when <code>command -v iptables</code> does not, the current Router VPN helper supports that ASUS quirk. If your firmware has neither working iptables nor the expected Merlin JFFS hooks, stop and use the firmware-specific forwarding path instead of forcing this helper.</p></div><div class="card"><h3>Expected public listeners</h3><pre>TCP      80      → AI Board 18080
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
UDP      51822   → 51822</pre><p class="small">Do not expose 1080, 8786, 8787, 9443, SSH, Portainer, AdGuard admin, or OverTLS loopback 14444. ASUS management TCP 8443 does not conflict with Router VPN's UDP-only 8443 listener.</p></div></section>

<section class="panel" data-tab="modes"><div class="card"><h2>All Router VPN modes — lightest to strongest</h2><p class="small">Availability is validated again by the installed client. “Generated” describes the profile source, not a promise that every platform has every required engine.</p><div class="scroll"><table><thead><tr><th># / mode</th><th>Protection/layers</th><th>Engine</th><th>Added ping</th><th>Traffic</th><th>Speed loss</th></tr></thead><tbody id="modeRows"></tbody></table></div></div><div class="card"><h3>AUTO / SMART AUTO / CUSTOM / ALL</h3><p><b>AUTO</b> tries the lightest eligible validated mode first and stops at the first healthy connection. <b>SMART AUTO</b> connects, then attempts simplifications while keeping a last-good stack. <b>CUSTOM</b> chooses the lightest validated stack containing the required layers. <b>ALL</b> is the strongest MAX orchestrator and only becomes usable when a validated MAX branch is present.</p><p><b>DAITA-like</b> is bounded cover traffic; it is not claimed to be Mullvad's exact Maybenot DAITA implementation. <b>Jumbo TUN</b> is for compatible proxy/TUN paths, not raw WireGuard/AWG.</p></div></section>

<section class="panel" data-tab="forward"><div class="card"><h2>Port forwarding after you connect</h2><ol><li>Connect using WireGuard or AmneziaWG so the home router-agent can identify your tunnel peer.</li><li>In the Router VPN app open <b>Port forwarding</b>.</li><li>Choose TCP, UDP, or both; enter From/To; target 0 preserves the same range.</li><li><b>Protected DMZ</b> forwards unused ports only. Router VPN listeners and management ports remain reserved.</li><li>Use <b>Clear</b> when finished.</li></ol><p class="small">Proxy-only modes are outbound paths and cannot receive peer-targeted inbound forwarding the same way.</p></div><div class="card"><h2>SOCKS5</h2><p>Internal proxy: <code>__SOCKS__:1080</code>, no authentication, only after the VPN reaches home. The app separately tests/displays the <b>public exit IP</b>; do not interpret this private SOCKS address as the public internet address.</p></div></section>

<section class="panel" data-tab="guide"><div class="card"><h2>Complete guide</h2><div id="fullGuide"></div></div><div class="card"><h2>Multiple routers / nodes</h2><p>Import one router profile per home node. The app remembers the selected node and can store an optional location/latitude/longitude. Desktop node ranking uses at least 50 TCP handshake samples and shows minimum, median, 10% trimmed mean, ordinary average, p90 and maximum so a few outliers do not dominate the result.</p><p class="small">Multi-hop is intentionally not labeled ready here yet. A real multi-hop feature must route one validated self-hosted node through another without leaking DNS or bypassing kill-switch policy; the UI must not pretend that exists before the chain adapter is tested.</p></div><div class="card"><h2>Kill switch / client control</h2><p>The desktop controller has <b>Off</b> and an emergency local transport stop. A strict firewall kill switch and remote “kick every peer” control are not advertised as ready until their platform-specific firewall/peer implementations are tested. This avoids a cosmetic switch that could leak traffic.</p></div></section>

<section class="panel" data-tab="trouble"><div class="card"><h2>Troubleshooting</h2><h3>Mode says unavailable</h3><p>Read the exact reason in the app's mode table. Missing cert/profile/engine errors are real checks; do not silently downgrade a requested protection layer.</p><h3>Can’t SSH to ASUS</h3><p>Confirm SSH is enabled for LAN, the username is correct, and you can reach 192.168.50.1. Use the stdin transfer commands in this Setup Center rather than SFTP/scp on firmware that lacks an SFTP server.</p><h3>VPN works but incoming port does not</h3><p>Confirm the fixed WAN listener rules exist on ASUS, connect via WireGuard/AWG, then apply the client forwarding rule. Do not use a proxy-only mode for peer-targeted inbound forwarding.</p><h3>DNS</h3><p>Home AdGuard is default. The client also carries a full public DNS benchmark list and can retest from the home node after connecting. Fastest public DNS is optional, not the default.</p></div></section>

<div id="wizard" class="overlay" hidden><div class="wizard"><div id="wizardProgress" class="progress"></div><h2 id="wizardTitle"></h2><div id="wizardBody"></div><div class="row"><button onclick="wizardBack()">Back</button><button onclick="closeWizard()">Close for now</button><span class="grow"></span><button class="btn primary" onclick="wizardNext()" id="wizardNext">Next</button></div></div></div>
</div><script>
const DATA=__DATA__;const $=id=>document.getElementById(id);const tabs=['start','downloads','devices','router','modes','forward','guide','trouble'];const tabNames={start:'Start',downloads:'Downloads',devices:'Devices & methods',router:'ASUS forwarding',modes:'Modes',forward:'Port forwarding',guide:'Full guide',trouble:'Troubleshooting'};
function gotoTab(name){document.querySelectorAll('.panel').forEach(x=>x.classList.toggle('active',x.dataset.tab===name));document.querySelectorAll('#tabs button').forEach(x=>x.classList.toggle('active',x.dataset.tab===name));history.replaceState(null,'','#'+name)}
for(const t of tabs){const b=document.createElement('button');b.textContent=tabNames[t];b.dataset.tab=t;b.onclick=()=>gotoTab(t);$('tabs').appendChild(b)}gotoTab(location.hash.slice(1)&&tabs.includes(location.hash.slice(1))?location.hash.slice(1):'start');
const guideSteps=[
['Deploy the home node','Portainer → Stacks → Add stack → Repository. Repository: Eabusham2/router-vpn. Compose path: server/portainer-current.yaml. Normal variables: WAN_INTERFACE=eth0, LAN_CIDR=192.168.50.0/24, ADGUARD4='+DATA.socksHost+'. ENDPOINT can stay blank for automatic public IPv4 detection.'],
['Verify services','router-vpn-init and router-vpn-finalize are one-shot containers and should exit 0. Agent, WireGuard, AWG2, Rosenpass, transports, Xray, Naive, SS+V2Ray, aux, bundle-web and SOCKS5 should run when their profiles are enabled.'],
['Install ASUS forwarding','Enable LAN-only SSH, check existing rules, download the forwarding helper, transfer it with SSH stdin, run install, then run /jffs/scripts/router-vpn-forward.sh status.'],
['Install a client','Choose the small package for your OS or a simple protocol app. You do not need the all-platform ZIP. Import router-vpn-bundle.json into Router VPN after the controller is installed.'],
['Choose DNS','Home AdGuard is default. Optional choices include fastest measured public resolver, common resolvers, custom UDP/TCP, DoT, DoH, DoH3 and DNS Rescue.'],
['Connect','Start with WireGuard Raw. Then use AUTO, the recommended REALITY mode, SMART AUTO, CUSTOM, or a manual validated mode.'],
['Test & forward','Confirm the public exit IP, DNS and IPv4/IPv6 behavior. For inbound forwarding, stay on a WireGuard/AWG peer path and use the app Port forwarding page.']
];
function stepHTML(items){return items.map((x,i)=>`<div class="step"><div class="num">${i+1}</div><div><h3 style="margin:4px 0">${x[0]}</h3><p>${x[1]}</p></div></div>`).join('')}$('quickSteps').innerHTML=stepHTML(guideSteps);$('fullGuide').innerHTML=stepHTML(guideSteps)+`<h3>Useful commands</h3><pre>ASUS status: /jffs/scripts/router-vpn-forward.sh status\nASUS firewall: /usr/sbin/iptables --version\nExisting ASUS GUI forwards: nvram get vts_rulelist\nMac local controller: http://127.0.0.1:8788\nHome Setup Center: http://${DATA.socksHost}:8786/</pre>`;
const downloads=[['Router profile only','router-vpn-bundle.json','For an already-installed Router VPN app/controller'],['ASUS forwarding helper','asus-merlin-router-vpn-forwards.sh','Persistent Merlin NAT/FORWARD helper'],['macOS Apple Silicon','router-vpn-macos-arm64.zip','M1/M2/M3/M4 and later arm64 Macs'],['macOS Intel','router-vpn-macos-amd64.zip','Intel Macs'],['Linux ARM64','router-vpn-linux-arm64.zip','ARM64 Linux'],['Linux x86-64','router-vpn-linux-amd64.zip','x86-64 Linux'],['Complete private fallback','router-vpn-client-bundle.zip','All platforms/profiles; largest download'],['Checksums','SHA256SUMS','Verify direct downloads before bypassing OS security warnings']];$('downloads').innerHTML=downloads.map(x=>`<div class="download"><div><b>${x[0]}</b><div class="small">${x[2]}</div></div><a class="btn" href="/${x[1]}" download>Download</a></div>`).join('');
const devices=DATA.devices||{};for(const [id,d] of Object.entries(devices)){const o=document.createElement('option');o.value=id;o.textContent=d.label||id;$('device').appendChild(o)}
const availableMethods=(DATA.methods||[]).filter(x=>x.available);availableMethods.sort((a,b)=>(b.simple?1:0)-(a.simple?1:0)||a.label.localeCompare(b.label));for(const m of availableMethods){const o=document.createElement('option');o.value=m.id;o.textContent=(m.simple?'Easy — ':'Advanced — ')+m.label;$('method').appendChild(o)}
function renderDevice(){const d=devices[$('device').value]||{};$('deviceHelp').innerHTML=`<h3>${d.label||''}</h3><p>${d.customApp||''}</p><ol>${(d.steps||[]).map(s=>`<li>${s}</li>`).join('')}</ol>`}
function renderMethod(){const m=availableMethods.find(x=>x.id===$('method').value)||{};$('methodLabel').textContent=m.label||'';$('methodApps').innerHTML=(m.apps||[]).map(a=>`<span class="pill">${a}</span>`).join('');$('methodNote').textContent=m.note||'';$('methodNative').textContent=m.native||'';$('urlBox').hidden=!m.url;$('urlText').textContent=m.url||'';$('cfgBox').hidden=!m.config;$('cfgText').textContent=m.config||'';const q=$('qrBox');q.innerHTML=m.qrPngBase64?`<h3>QR code</h3><img class="qr" alt="${m.label||'Setup'} QR" src="data:image/png;base64,${m.qrPngBase64}"><p class="small">This QR may contain private credentials. Scan only with a client you trust.</p>`:'<p class="small">No compact QR for this method; use the config/import file.</p>'}
$('device').onchange=renderDevice;$('method').onchange=renderMethod;renderDevice();renderMethod();
const layerLabel=x=>({'wireguard':'WireGuard','amneziawg2':'AmneziaWG 2','rosenpass-pq':'Rosenpass PQ','vless':'VLESS','vless-pq':'PQ VLESS','reality':'REALITY','xtls-vision':'XTLS Vision','utls-chrome':'Chrome uTLS','hysteria2':'Hysteria2','quic':'QUIC','shadowsocks2022':'Shadowsocks 2022','xhttp':'XHTTP','finalmask':'FinalMask','salamander':'Salamander'}[x]||x);$('modeRows').innerHTML=(DATA.modes||[]).filter(x=>!['smart-auto','custom'].includes(x.id)).map((x,i)=>`<tr><td><b>${x.name}</b><div class="small">${x.maturity||''}</div></td><td>${x.protection}<div class="small">${(x.layers||[]).map(layerLabel).join(' → ')}</div></td><td>${x.engine}</td><td>${x.ping_min_ms}–${x.ping_max_ms} ms</td><td>+${x.traffic_min_pct}–${x.traffic_max_pct}%</td><td>-${x.speed_loss_min_pct}–${x.speed_loss_max_pct}%</td></tr>`).join('');
$('routerInstall').textContent=`# On your Mac/Linux computer\ncurl -fsS http://${DATA.socksHost}:8786/asus-merlin-router-vpn-forwards.sh -o /tmp/router-vpn-forwards.sh\nssh ROUTER_USER@192.168.50.1 'cat > /tmp/router-vpn-forwards.sh && chmod 755 /tmp/router-vpn-forwards.sh' < /tmp/router-vpn-forwards.sh\nssh ROUTER_USER@192.168.50.1 'sh /tmp/router-vpn-forwards.sh install && /jffs/scripts/router-vpn-forward.sh status'`;
async function copyText(id){const v=$(id).textContent;try{await navigator.clipboard.writeText(v)}catch{const t=document.createElement('textarea');t.value=v;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove()}}
const WIZKEY='routervpn.setupcenter.done.v4',WIZSTEP='routervpn.setupcenter.step.v4';const wiz=[
['Welcome',`This wizard covers the complete path without requiring the huge ZIP. Choose a simple protocol or Router VPN app, deploy the home node, enable safe router SSH, install forwarding, install/link the client, choose DNS, connect, test, and optionally configure port forwarding.`],
['Choose a client method',`<b>Easiest full feature set:</b> Router VPN app/controller + router-vpn-bundle.json.<br><b>Simplest single tunnel:</b> WireGuard config/QR.<br><b>Other simple methods:</b> AmneziaWG, Shadowsocks or Hysteria2. Every generated method stays available in Devices & methods.`],
['Deploy Portainer stack',`Repository: <code>Eabusham2/router-vpn</code><br>Compose: <code>server/portainer-current.yaml</code><br>Set <code>WAN_INTERFACE=eth0</code>, <code>LAN_CIDR=192.168.50.0/24</code>, <code>ADGUARD4=${DATA.socksHost}</code>. Leave ENDPOINT blank for automatic detection unless you intentionally need to override it.`],
['Enable ASUS SSH',`ASUS GUI → Administration → System → enable SSH for <b>LAN only</b>. Test <code>ssh ROUTER_USER@192.168.50.1</code>. Never expose SSH to WAN.`],
['Check current router rules',`Before changing forwarding, inspect <code>/usr/sbin/iptables --version</code>, <code>nvram get vts_rulelist</code>, existing JFFS hooks, and any prior Router VPN status. This protects custom firewall scripts from being overwritten.`],
['Install forwarding helper',`Open the ASUS forwarding tab and use the <b>SSH stdin</b> commands. This works on ASUS firmware where SFTP/scp is unavailable. Confirm the helper status lists every expected public listener and preserves existing hooks.`],
['Install/link the app',`Downloads provides a small platform-specific package. Once installed, import <code>router-vpn-bundle.json</code>. WireGuard-only users can skip the Router VPN app and import the WireGuard config/QR instead.`],
['macOS warning if shown',`Verify the package/checksum first. Then use System Settings → Privacy & Security → Open Anyway. Only for a verified Router VPN folder, <code>xattr -dr com.apple.quarantine /path/to/router-vpn</code> removes quarantine.`],
['DNS',`Home AdGuard is the default. The Router VPN client can also show common public resolvers and stored benchmark timings, and can retest them from the home node after the tunnel connects.`],
['Connect & verify',`Start with WireGuard Raw. Confirm a public exit IP, then try AUTO or the recommended REALITY mode. The mode table explains all 20 modes and their expected overhead. Unavailable means the validation check failed; read the exact reason instead of forcing it.`],
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
      "ios":{"label":"iPhone / iPad","customApp":"Router VPN mobile is the onboarding/controller/import surface. Until the native Packet Tunnel adapters are validated, use the generated WireGuard/AWG/Hysteria2/etc. profiles in compatible iOS clients rather than claiming every mode is native in the IPA.","steps":["For quickest setup, scan the WireGuard QR in the WireGuard app.","For AmneziaWG, import the generated AWG profile in a compatible app.","For Shadowsocks/Hysteria2/OverTLS/SSR, choose the matching method below and use a compatible client.","Keep router-vpn-bundle.json private; it can be imported into Router VPN controller surfaces."]},
      "android":{"label":"Android","customApp":"Router VPN Android provides onboarding/controller/import. Native all-mode VpnService adapters must be validated before being advertised as complete.","steps":["WireGuard: import config/QR in WireGuard for Android.","AmneziaWG: import AWG config in a compatible client.","Shadowsocks/Hysteria2: use the generated URL/QR in a compatible app.","Use the Router VPN app/controller for the complete profile catalog and setup guidance where supported."]},
      "macos":{"label":"macOS","customApp":"Full local Router VPN controller is supported. Install the small package matching Apple Silicon or Intel, then import router-vpn-bundle.json.","steps":["Download the matching small macOS package from Downloads.","Extract it, cd into router-vpn, and run bash client/install-macos-final.sh \"$PWD\".","Open the Router VPN local app/PWA at 127.0.0.1:8788 and import router-vpn-bundle.json.","If macOS quarantines a verified local build, follow the checksum + Privacy & Security steps in Downloads."]},
      "windows":{"label":"Windows","customApp":"Use the Router VPN Windows controller package from GitHub build artifacts/releases when available. Raw WireGuard/AWG profiles can be imported into native clients immediately.","steps":["For the simplest path use WireGuard and import the generated profile.","For the full multi-engine controller, use the matching Windows build and WSL2 transport environment described in repository docs.","Import router-vpn-bundle.json after installation."]},
      "linux":{"label":"Linux","customApp":"Full local Router VPN controller is supported on x86-64 and ARM64 using the small platform package.","steps":["Download the matching Linux package.","Extract it and run sudo bash client/install-linux.sh \"$PWD\".","Open the local Router VPN UI and import router-vpn-bundle.json."]},
      "manual":{"label":"Other / manual","customApp":"Use a protocol-specific generated config/URL/QR. Router VPN does not invent unsupported native imports.","steps":["Choose a method below.","Copy/import its URL or config into a client that explicitly supports that protocol.","Never expose management/SOCKS/setup ports to WAN."]},
    }
    modes = read_json(base/"client-bundle"/"modes.json")
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
    (out/"setup-assets.json").write_text(json.dumps(data,indent=2)+"\n")
    (out/"setup-assets.json").chmod(0o600)
    (out/"router-vpn-device-setup.html").write_text(build_html(data))
    (out/"router-vpn-device-setup.html").chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
