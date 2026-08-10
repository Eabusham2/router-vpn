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


def read_json(path: pathlib.Path) -> dict:
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
    for item in read_json(path).get("outbounds", []):
        if isinstance(item, dict) and item.get("tag") == tag:
            return item
    return {}


def asset(ident: str, label: str, category: str, *, url: str = "", config: str = "", apps=None, note="", native="") -> dict:
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
    }


def generic_config(gen: pathlib.Path, ident: str, label: str, rel: str, note: str, apps=None) -> dict:
    return asset(
        ident, label, "Advanced config", config=read_text(gen / rel), apps=apps or ["Router VPN", "compatible protocol client"],
        note=note, native="No universal native OS import exists for this stack; use Router VPN or a compatible client."
    )


def build_html(data: dict) -> str:
    packed = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    page = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Router VPN — Device Setup</title><style>
:root{color-scheme:dark}body{font-family:system-ui;margin:0;background:#101010;color:#eee}.wrap{max-width:1050px;margin:auto;padding:20px}.card{background:#1b1b1b;border:1px solid #333;border-radius:15px;padding:16px;margin:14px 0}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}select,button{font:inherit;padding:10px 12px;border-radius:10px;border:1px solid #555;background:#242424;color:#fff}button{cursor:pointer}.grow{flex:1;min-width:220px}.small{font-size:13px;opacity:.78}.warn{border-color:#745b1b;background:#211d12}.grid{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:16px}@media(max-width:760px){.grid{grid-template-columns:1fr}}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0e0e0e;border:1px solid #333;border-radius:10px;padding:12px;max-height:320px;overflow:auto}.qr{background:white;padding:12px;border-radius:12px;max-width:275px;width:100%;box-sizing:border-box}.muted{opacity:.55}.pill{display:inline-block;border:1px solid #444;border-radius:999px;padding:5px 8px;margin:3px;font-size:12px}.ok{color:#7ce39a}h1,h2,h3{margin-top:5px}
</style></head><body><div class="wrap">
<h1>Router VPN — Device Setup</h1>
<div class="card warn"><b>Private setup page.</b> <span id="warning"></span><div class="small">QRs are generated locally on your home node; no external QR service receives your keys or passwords.</div></div>
<div class="card"><h2>1. Device</h2><select id="device" class="grow"></select><h3 id="deviceLabel"></h3><div id="customApp"></div><ol id="steps"></ol></div>
<div class="card"><h2>2. Method</h2><select id="method" class="grow"></select><div id="methodBody" class="grid" style="margin-top:15px"><div><h2 id="methodLabel"></h2><div id="apps"></div><p id="note"></p><p><b>Native/system:</b> <span id="native"></span></p><div id="urlBox" hidden><h3>Share/import URL</h3><pre id="urlText"></pre><button id="copyUrl">Copy URL</button></div><div id="cfgBox" hidden><h3>Config/settings</h3><pre id="cfgText"></pre><button id="copyCfg">Copy config</button></div><span id="copyStatus" class="ok"></span></div><div id="qrBox"></div></div></div>
<div class="card"><h2>3. Which should I use?</h2><div class="small"><b>Router VPN custom app:</b> AUTO/SMART AUTO/CUSTOM, full mode set, DNS policy, DAITA-like, Jumbo TUN and protected forwarding. <b>Native/single-protocol app:</b> simplest when you only need WireGuard, AWG, Shadowsocks, Hysteria2, OverTLS or SSR. OverTLS and SSR are compatibility methods and are not inserted into the 20-mode AUTO ladder. Never WAN-forward internal SOCKS5 port 1080 or OverTLS loopback 14444.</div></div>
</div><script>const DATA=__DATA__;const $=id=>document.getElementById(id),device=$('device'),method=$('method');let current={};
$('warning').textContent=DATA.warning||'Keep these profiles private.';
for(const [id,x] of Object.entries(DATA.devices||{})){let o=document.createElement('option');o.value=id;o.textContent=x.label||id;device.appendChild(o)}
for(const x of (DATA.methods||[]).filter(x=>x.available)){let o=document.createElement('option');o.value=x.id;o.textContent=x.label+' — '+x.category;method.appendChild(o)}
function renderDevice(){const x=(DATA.devices||{})[device.value]||{};$('deviceLabel').textContent=x.label||'';$('customApp').textContent='Router VPN custom app: '+(x.customApp||'');$('steps').replaceChildren(...(x.steps||[]).map(s=>{let li=document.createElement('li');li.textContent=s;return li}))}
function renderMethod(){current=(DATA.methods||[]).find(x=>x.id===method.value)||{};$('methodLabel').textContent=current.label||'';$('apps').replaceChildren(...(current.apps||[]).map(a=>{let s=document.createElement('span');s.className='pill';s.textContent=a;return s}));$('note').textContent=current.note||'';$('native').textContent=current.native||'';$('urlBox').hidden=!current.url;$('urlText').textContent=current.url||'';$('cfgBox').hidden=!current.config;$('cfgText').textContent=current.config||'';let q=$('qrBox');q.replaceChildren();if(current.qrPngBase64){let h=document.createElement('h3');h.textContent='QR code';let i=document.createElement('img');i.className='qr';i.alt=(current.label||'Setup')+' QR';i.src='data:image/png;base64,'+current.qrPngBase64;let p=document.createElement('div');p.className='small';p.textContent='Scan only with a client you trust. This QR may contain private keys/passwords.';q.append(h,i,p)}else{q.textContent='QR omitted because this config is too large or has no compact import form.';q.className='muted'}}
async function copy(v){try{await navigator.clipboard.writeText(v)}catch{let t=document.createElement('textarea');t.value=v;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove()}$('copyStatus').textContent='Copied';setTimeout(()=>$('copyStatus').textContent='',1200)}
$('copyUrl').onclick=()=>copy(current.url||'');$('copyCfg').onclick=()=>copy(current.config||'');device.onchange=renderDevice;method.onchange=renderMethod;renderDevice();renderMethod();</script></body></html>'''
    return page.replace("__DATA__", packed)


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: generate-setup-assets.py BASE ENDPOINT SOCKS_HOST", file=sys.stderr)
        return 2
    base = pathlib.Path(sys.argv[1]); endpoint = sys.argv[2].strip().strip("[]"); socks_host = sys.argv[3].strip()
    gen = base / "client-bundle" / "generated"
    methods: list[dict] = []

    methods.append(asset("wireguard", "WireGuard", "VPN", config=read_text(gen/"wg"/"wg.conf"), apps=["WireGuard", "Router VPN"], note="Universal fast VPN profile; file import works on desktop and QR import works in mobile WireGuard apps.", native="Requires the WireGuard app/profile provider."))
    methods.append(asset("amneziawg2", "AmneziaWG 2", "VPN", config=read_text(gen/"awg2-fast"/"awg.conf"), apps=["AmneziaVPN / AmneziaWG", "Router VPN"], note="WireGuard-derived obfuscated profile. Import the generated AWG config.", native="Requires an AmneziaWG-compatible app."))

    ss = outbound(gen/"shadowsocks"/"sing-box.json"); ss_url=""
    if endpoint and ss:
        ui=urllib.parse.quote(str(ss.get("method") or ""),safe="")+":"+urllib.parse.quote(str(ss.get("password") or ""),safe="")
        ss_url=f"ss://{ui}@{hostport(endpoint,int(ss.get('server_port') or 8388))}/#Router%20VPN%20Shadowsocks"
    methods.append(asset("shadowsocks", "Shadowsocks 2022", "Proxy", url=ss_url, config=read_text(gen/"shadowsocks"/"sing-box.json"), apps=["Shadowsocks", "sing-box", "Potatso-compatible clients", "Router VPN"], note="Compact SIP002 URL plus full sing-box config.", native="No mainstream OS has native Shadowsocks; import into a compatible app."))

    hy=outbound(gen/"hysteria2"/"sing-box.json"); hy_url=""
    if endpoint and hy:
        tls=hy.get("tls") if isinstance(hy.get("tls"),dict) else {}; obfs=hy.get("obfs") if isinstance(hy.get("obfs"),dict) else {}; q=[]
        if tls.get("server_name"): q.append(("sni",str(tls["server_name"])))
        pin=cert_sha256(gen/"hysteria2"/"cert.pem")
        if pin:q.append(("pinSHA256",pin))
        if obfs.get("type"):q.append(("obfs",str(obfs["type"])))
        if obfs.get("password"):q.append(("obfs-password",str(obfs["password"])))
        hy_url="hysteria2://"+urllib.parse.quote(str(hy.get("password") or ""),safe="")+"@"+hostport(endpoint,int(hy.get("server_port") or 8443))+"/?"+urllib.parse.urlencode(q)+"#Router%20VPN%20Hysteria2"
    methods.append(asset("hysteria2", "Hysteria2 + QUIC", "Proxy/VPN client", url=hy_url, config=read_text(gen/"hysteria2"/"sing-box.json"), apps=["Hysteria2", "sing-box", "Router VPN"], note="QUIC transport with generated import URL and full config.", native="Requires a Hysteria2/sing-box-compatible client."))

    sslocal=read_json(gen/"ss-v2ray"/"sslocal.json"); sv_url=""
    if endpoint and sslocal:
        ui=urllib.parse.quote(str(sslocal.get("method") or ""),safe="")+":"+urllib.parse.quote(str(sslocal.get("password") or ""),safe=""); plugin=str(sslocal.get("plugin") or "")+(";"+str(sslocal.get("plugin_opts")) if sslocal.get("plugin_opts") else "")
        sv_url=f"ss://{ui}@{hostport(endpoint,int(sslocal.get('server_port') or 12443))}/?"+urllib.parse.urlencode({"plugin":plugin})+"#Router%20VPN%20SS%2BV2Ray"
    methods.append(asset("ss-v2ray", "Shadowsocks + V2Ray TLS", "Proxy", url=sv_url, config=read_text(gen/"ss-v2ray"/"sslocal.json"), apps=["SIP003/V2Ray-plugin Shadowsocks client", "Router VPN"], note="TLS/WebSocket compatibility path; use a client that supports the V2Ray SIP003 plugin.", native="No native OS import."))

    methods += [
        generic_config(gen,"reality-vision","VLESS + REALITY + Vision","reality-vision/xray.json","Recommended HTTPS-like camouflage stack.",["Xray-compatible client","Router VPN"]),
        generic_config(gen,"reality-xhttp","PQ REALITY + XHTTP + FinalMask","reality-xhttp/xray.json","Advanced XHTTP/FinalMask configuration when generated and validated.",["Xray-compatible client","Router VPN"]),
        generic_config(gen,"naive-h2","Naive HTTPS H2","naive-h2/sing-box.json","HTTPS forward-proxy transport over HTTP/2.",["Naive/sing-box compatible client","Router VPN"]),
        generic_config(gen,"naive-h3","Naive HTTPS H3","naive-h3/sing-box.json","HTTPS/QUIC transport over HTTP/3.",["Naive/sing-box compatible client","Router VPN"]),
    ]

    overtls=read_text(gen/"overtls"/"overtls-client.json")
    methods.append(asset("overtls", "SOCKS5 + TLS (OverTLS)", "Compatibility proxy", config=overtls, apps=["OverTLS", "ssrDroid/OverTLS-compatible clients"], note="Public TLS is terminated by Caddy; the home-node OverTLS backend is loopback-only. This method stays separate from AUTO.", native="Requires an OverTLS-compatible client; import the generated JSON/QR when supported."))
    ssr=read_text(gen/"shadowsocksr"/"ssr-client.json")
    methods.append(asset("shadowsocksr", "ShadowsocksR (legacy)", "Legacy compatibility", config=ssr, apps=["ShadowsocksR-native/compatible clients"], note="Legacy SSR compatibility only; Shadowsocks 2022 and OverTLS remain preferred. Not part of AUTO.", native="Requires an SSR-compatible client; use the generated JSON settings."))

    socks=f"SOCKS5 host: {socks_host}\nPort: 1080\nAuthentication: none\nUse only after the VPN reaches home."
    methods.append(asset("socks5", "SOCKS5 (inside VPN)", "App proxy", config=socks, apps=["Potatso", "Browsers/apps with SOCKS5", "macOS SOCKS proxy"], note="Plain internal app proxy; never WAN-forward TCP 1080.", native="macOS supports a per-network SOCKS proxy; iOS/Android/Windows generally use an app."))

    devices={
      "ios":{"label":"iPhone / iPad","customApp":"Current Router VPN IPA is a controller/importer until native Packet Tunnel adapters are linked.","steps":["WireGuard: Add tunnel → Create from QR code.","AmneziaWG: import the AWG config.","Shadowsocks/SOCKS5: Potatso or another compatible proxy app can test supported settings.","Hysteria2/OverTLS/SSR: use a compatible client and the generated URL/config/QR."]},
      "android":{"label":"Android","customApp":"Current Router VPN APK is a controller/importer until native VpnService adapters are linked.","steps":["WireGuard: import file or scan QR.","AmneziaWG: import AWG config.","Shadowsocks/Hysteria2/OverTLS/SSR: import into a compatible app."]},
      "macos":{"label":"macOS","customApp":"Extract the bundle, run: bash client/install-macos-final.sh \"$PWD\" ; open http://127.0.0.1:8788.","steps":["Use Router VPN for AUTO/SMART AUTO/CUSTOM.","WireGuard/AWG can also use their protocol apps.","For app-only SOCKS5: System Settings → Network → service → Details → Proxies → SOCKS Proxy."]},
      "windows":{"label":"Windows","customApp":"Use the Windows x64/ARM64 or PortableApps artifact. Full multi-engine shell parity currently uses WSL2.","steps":["WireGuard/AWG: import in compatible native clients.","Other protocols: use their compatible app or Router VPN/WSL2 path."]},
      "linux":{"label":"Linux","customApp":"Extract the bundle, run: sudo bash client/install-linux.sh \"$PWD\" ; open http://127.0.0.1:8788.","steps":["Router VPN supports the complete engine path.","Protocol configs can also be used directly in compatible tools."]},
      "other":{"label":"Other / router / manual","customApp":"Use a generated URL/config with a compatible client; do not upload the private bundle/QRs.","steps":["Prefer generated profiles over retyping secrets.","Compatibility depends on the protocol client, not just the operating system."]}
    }
    output={"version":2,"private":True,"warning":"These URLs, configs and QR codes contain private connection material. Keep them private.","devices":devices,"methods":methods}
    (base/"client-bundle"/"setup-assets.json").write_text(json.dumps(output,indent=2)+"\n")
    (base/"client-bundle"/"setup-assets.json").chmod(0o600)
    web=base/"client-bundle"/"router-vpn-device-setup.html"; web.write_text(build_html(output)); web.chmod(0o600)
    print(f"Generated {sum(1 for x in methods if x['available'])} setup methods and private Device Setup WebGUI.")
    return 0

if __name__ == "__main__": raise SystemExit(main())
