#!/usr/bin/env python3
"""Normalize Setup Center method metadata and patch the generated UI to the current product contract."""
from __future__ import annotations

import argparse
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
import tempfile

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

SETUP_METHOD_LANES = ("simple-native", "universal", "universal-compat", "manual-app-proxy")


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

    if ident == "shadowsocks" and method.get("config") and endpoint and endpoint != "router.invalid":
        method["url"] = imports.shadowsocks_from_singbox(str(method["config"]), endpoint)
    elif ident == "ss-v2ray" and method.get("config") and endpoint:
        method["url"] = imports.shadowsocks_plugin_from_json(str(method["config"]), endpoint)
    elif ident == "shadowsocksr" and method.get("config"):
        method["url"] = imports.ssr_uri(imports.json_config(str(method["config"])))
    elif ident == "hysteria2" and method.get("url"):
        imports.validate_hysteria2_uri(str(method["url"]))

    if qr_supported:
        payload = str(method.get("config") or "") if ident == "wireguard" else str(method.get("url") or "")
        if not payload or "router.invalid" in payload.lower():
            method["qrSupported"] = False
            method["qrPayload"] = ""
            method["qrPngBase64"] = ""
        else:
            method["qrPayload"] = payload
            method["qrPngBase64"] = generator.qr_png(payload)
    else:
        method["qrPayload"] = ""
        method["qrPngBase64"] = ""
    method["simple"] = lane in SETUP_METHOD_LANES or ident == "router-vpn-app"


def _replace_required(html: str, old: str, new: str, label: str) -> str:
    if old in html:
        return html.replace(old, new, 1)
    if new in html:
        return html
    raise RuntimeError(f"Setup Center UI template drifted before {label} patch")


def _replace_wizard(html: str) -> str:
    # Historical generator revisions used v4; the reconciled generator already
    # emits a static v5 wizard. In both cases normalize to the same action-driven
    # v5 contract instead of treating the current template as drift.
    start = html.find("const WIZKEY='routervpn.setupcenter.done.v4'")
    if start < 0:
        start = html.find("const WIZKEY='routervpn.setupcenter.done.v5'")
    end = html.find("</script></body></html>", start)
    if start < 0 or end < 0:
        raise RuntimeError("Setup Center wizard template drifted")
    wizard = r'''const WIZKEY='routervpn.setupcenter.done.v5',WIZSTEP='routervpn.setupcenter.step.v5';
const wiz=[
 {title:'Welcome',body:'This onboarding starts from zero and keeps setup separate from day-to-day Router VPN use. It teaches the action, sends you to the correct page, and checks server-side steps when Setup Center can verify them.',action:'Check Setup Center',kind:'health'},
 {title:'Verify the home node',body:'Confirm the Router VPN server is running before downloading or linking anything. The check reads the authenticated router-agent status through Setup Center; it does not expose an admin port.',action:'Check server',kind:'admin-status'},
 {title:'Choose the simplest usable method',body:'Start with Simple/native. WireGuard is the baseline. AmneziaWG, Shadowsocks and Hysteria2 are shown only when a real import contract exists. Complex Router VPN stacks belong in the Router VPN app.',action:'Open methods',kind:'tab',tab:'devices'},
 {title:'Install Router VPN once',body:'For the full feature set, install the generic app for this device. The package is secret-free and is not tied to this home. You can link this node and additional nodes after installation.',action:'Open downloads',kind:'tab',tab:'downloads'},
 {title:'Link this node separately',body:'Use the authenticated private node-link bundle or one-time LAN pairing. This keeps one Router VPN install usable with multiple homes/nodes instead of baking a node into the installer.',action:'Open downloads',kind:'tab',tab:'downloads'},
 {title:'Understand modes and bases',body:'WireGuard and AmneziaWG are selectable base paths. AUTO stops at the first proven working mode; SMART AUTO connects, then tests simplification and restores the last known-good stack if reduction fails; CUSTOM is explicit composition. The native app shows layers, engineering latency/traffic/speed estimates, runtime readiness and the exact live reason.',action:'Open modes',kind:'tab',tab:'modes'},
 {title:'DNS policy',body:'Home AdGuard is the home default. Router VPN also offers Fastest measured, Custom UDP/TCP, DoT, DoH, DoH3, Rescue and common IPv4/IPv6 choices. Resolver RTT means real A/AAAA DNS query time from the selected home node, not ICMP; the active session still has to prove what was applied.',action:'Open guide',kind:'tab',tab:'guide'},
 {title:'Home LAN access',body:'Choose whether tunnel peers may reach the home LAN. The Server page enforces this as a persistent router policy instead of storing a decorative preference.',action:'Check LAN policy',kind:'admin-settings'},
 {title:'Connected clients and access control',body:'The Server page shows real WireGuard/AmneziaWG handshake age and transfer counters. Ban is reversible network blocking. Revoke also removes the live peer and persists the revocation.',action:'Open Server',kind:'tab',tab:'server-admin'},
 {title:'Port forwarding',body:'Use the persistent forwarding master and rules only for tunnel peer addresses. Reserved Router VPN and management ports are blocked from generic forwarding. Leave the master off when you do not need inbound forwarding.',action:'Check forwarding',kind:'admin-forwarding'},
 {title:'First connection',body:'In the Router VPN app, start with WireGuard Raw, then try AUTO or the recommended REALITY path. Connection state must be backed by selected-node path proof; a generic public HTTP success is not enough.',action:'Show app downloads',kind:'tab',tab:'downloads'},
 {title:'Verify and learn recovery',body:'Verify public exit IP, DNS and IPv4/IPv6 behavior in the app. If a mode is unavailable, use its exact readiness reason instead of forcing it. Server status and policy can be rechecked here at any time.',action:'Run final server check',kind:'admin-status'},
 {title:'Finished',body:'Setup onboarding is complete. It will stay completed on this browser, and Run full onboarding can reopen it whenever you want. Day-to-day connect/disconnect belongs in the real Router VPN app, not this web page.',action:'Finish',kind:'finish'}
];
let wi=+(localStorage.getItem(WIZSTEP)||0);
function wizResult(text,kind=''){const box=$('wizardActionResult');if(!box)return;box.textContent=text;box.className='small '+kind}
function startWizard(force=false){if(force||localStorage.getItem(WIZKEY)!=='1'){$('wizard').hidden=false;renderWiz()}}
function renderWiz(){wi=Math.max(0,Math.min(wi,wiz.length-1));localStorage.setItem(WIZSTEP,wi);const s=wiz[wi];$('wizardProgress').textContent=`Step ${wi+1} of ${wiz.length}`;$('wizardTitle').textContent=s.title;$('wizardBody').innerHTML=`<p>${s.body}</p><div class="row"><button class="btn primary" onclick="wizardAction()">${s.action}</button><span id="wizardActionResult" class="small"></span></div>`;$('wizardNext').textContent=wi===wiz.length-1?'Finish':'Next'}
async function wizardAction(){const s=wiz[wi];wizResult('Working…');try{
 if(s.kind==='health'){const r=await fetch('/healthz',{cache:'no-store'});if(!r.ok)throw new Error(`HTTP ${r.status}`);wizResult('Setup Center is reachable and this page is authenticated.','ok');return}
 if(s.kind==='admin-status'){const r=await fetch('/api/admin/status',{cache:'no-store'}),d=await r.json();if(!r.ok||d.ok===false)throw new Error(d.error||`HTTP ${r.status}`);const n=(d.listeners||[]).length;wizResult(`Server check passed • ${n} listener(s) visible • ${(d.active_reserved_ports||[]).length} protected listener(s) active.`,'ok');return}
 if(s.kind==='admin-settings'){const r=await fetch('/api/admin/settings',{cache:'no-store'}),d=await r.json();if(!r.ok||d.ok===false)throw new Error(d.error||`HTTP ${r.status}`);wizResult(`LAN access is ${d.settings&&d.settings.lan_access?'ON':'OFF'}; forwarding master is ${d.settings&&d.settings.forwarding_master?'ON':'OFF'}. Change them on Server.`,'ok');gotoTab('server-admin');if(window.refreshServerAdmin)refreshServerAdmin();return}
 if(s.kind==='admin-forwarding'){const r=await fetch('/api/admin/forwarding',{cache:'no-store'}),d=await r.json();if(!r.ok||d.ok===false)throw new Error(d.error||`HTTP ${r.status}`);wizResult(`Forwarding master ${d.master?'ON':'OFF'} • ${(d.rules||[]).length} persistent rule(s).`,'ok');gotoTab('server-admin');if(window.refreshServerAdmin)refreshServerAdmin();return}
 if(s.kind==='tab'){gotoTab(s.tab);if(s.tab==='server-admin'&&window.refreshServerAdmin)refreshServerAdmin();wizResult('Opened the page for this action.','ok');return}
 if(s.kind==='finish'){localStorage.setItem(WIZKEY,'1');localStorage.setItem(WIZSTEP,'0');$('wizard').hidden=true;return}
 }catch(e){wizResult('Check failed: '+e.message,'bad')}}
function wizardNext(){if(wi===wiz.length-1){localStorage.setItem(WIZKEY,'1');localStorage.setItem(WIZSTEP,'0');$('wizard').hidden=true;return}wi++;renderWiz()}
function wizardBack(){if(wi>0)wi--;renderWiz()}
function closeWizard(){$('wizard').hidden=true}
if(localStorage.getItem(WIZKEY)!=='1')startWizard(false);
'''
    return html[:start] + wizard + html[end:]


def patch_html(html: str) -> str:
    html = _replace_required(
        html,
        '<a class="btn" href="/router-vpn-bundle.json" download>Download router profile</a>',
        '<button class="btn" onclick="startDownloadJob(\'router-vpn-client-bundle.zip\',this)">Download node-link bundle</button>',
        "node-link action",
    )
    html = _replace_required(
        html,
        '<div class="card hero"><h2>Choose the easiest path</h2><div class="grid3">',
        '<div class="card hero"><h2>Choose the easiest path</h2><div class="grid2">',
        "setup lane grid",
    )
    old_cards = '''<div class="card simple"><h3>1. Router VPN app</h3><p>Best overall. Install the small platform package, pair/import <code>router-vpn-bundle.json</code>, then choose WireGuard, AUTO, SMART AUTO, CUSTOM or any validated mode in the app.</p><button onclick="gotoTab('downloads')">Get the app/controller</button></div>
<div class="card simple"><h3>2. WireGuard only</h3><p>Fastest simple setup. Use the WireGuard config/QR from Devices & methods. It is the default base and the first connectivity test.</p><button onclick="gotoTab('devices')">Show WireGuard setup</button></div>
<div class="card simple"><h3>3. Compatible protocol app</h3><p>Use AmneziaWG, Shadowsocks, Hysteria2, OverTLS, ShadowsocksR, or the private in-tunnel SOCKS5 method only with clients that explicitly support that simple protocol. Complex Router VPN stacks stay in the Router VPN app.</p><button onclick="gotoTab('devices')">Choose a method</button></div>'''
    new_cards = '''<div class="card simple"><h3>1. Simple / native</h3><p>Start with an interoperable protocol your platform or a normal client can configure directly. WireGuard is the baseline; AmneziaWG, Shadowsocks and Hysteria2 appear only with their truthful import contract.</p><button onclick="gotoTab('devices')">Choose a simple method</button></div>
<div class="card simple"><h3>2. Router VPN app — recommended</h3><p>Install Router VPN once, then link this node separately. Use the app for logical modes, AUTO / SMART AUTO / CUSTOM, DNS policy and the full Router VPN feature set.</p><button onclick="gotoTab('downloads')">Get Router VPN</button></div>
<div class="card simple"><h3>3. Universal third-party client</h3><p>Use only the compatible protocols listed under Devices & methods. The Setup Center does not pretend complex Router VPN stacks are generic third-party imports.</p><button onclick="gotoTab('devices')">Show compatible methods</button></div>
<div class="card simple"><h3>4. Manual / custom</h3><p>Advanced Router VPN stacks and CUSTOM composition belong in the Router VPN app or the full guide. They are not advertised as ordinary QR/config imports.</p><button onclick="gotoTab('guide')">Open advanced guide</button></div>'''
    html = _replace_required(html, old_cards, new_cards, "setup lane order")

    html = _replace_required(
        html,
        "const downloads=[['Router profile only','router-vpn-bundle.json','For an already-installed Router VPN app/controller'],",
        "const downloads=[",
        "stale static node bundle download",
    )
    html = _replace_required(
        html,
        "['Complete private fallback','router-vpn-client-bundle.zip','All platforms/profiles; largest download']",
        "['Private node-link bundle','router-vpn-client-bundle.zip','Separate private node data for an already-installed Router VPN app; extract router-vpn-bundle.json for file import']",
        "private node-link download label",
    )

    old_download_render = "$('downloads').innerHTML=downloads.map(x=>`<div class=\"download\"><div><b>${x[0]}</b><div class=\"small\">${x[2]}</div></div><a class=\"btn\" href=\"/${x[1]}\" download>Download</a></div>`).join('');"
    new_download_render = r'''const downloadJobs={};
function asyncDownloadName(name){return /^router-vpn-(windows|macos|linux)-/.test(name)||['router-vpn-android.apk','router-vpn-ios-preview.ipa','router-vpn-client-bundle.zip'].includes(name)}
function bytesLabel(n){n=Number(n||0);if(!n)return '';const u=['B','KiB','MiB','GiB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return `${n.toFixed(i?1:0)} ${u[i]}`}
function jobStatusEl(name){return document.querySelector(`[data-job-status="${CSS.escape(name)}"]`)}
function setJobStatus(name,text,kind=''){const el=jobStatusEl(name);if(!el)return;el.textContent=text;el.className='small '+kind}
async function cancelDownloadJob(name){const job=downloadJobs[name];if(!job)return;try{await fetch(job.status_url,{method:'DELETE'});setJobStatus(name,'Cancelled','warn')}catch(e){setJobStatus(name,'Cancel failed: '+e.message,'bad')}}
async function startDownloadJob(name,button){
  if(!asyncDownloadName(name)){location.href='/'+name;return}
  if(button)button.disabled=true;setJobStatus(name,'Queued…');
  try{
    let r=await fetch('/api/download-jobs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
    let data=await r.json();if(!r.ok||!data.ok)throw new Error(data.error||`HTTP ${r.status}`);
    let job=data.job;downloadJobs[name]=job;
    for(;;){
      const size=job.size?` • ${bytesLabel(job.size)}`:'';const source=job.source?` • ${job.source}`:'';
      setJobStatus(name,`${job.phase||job.status} • ${Number(job.progress||0)}%${size}${source}`);
      if(job.status==='ready'){
        const a=document.createElement('a');a.href=job.download_url;a.download=name;a.hidden=true;document.body.appendChild(a);a.click();a.remove();
        setJobStatus(name,`Ready • 100%${size}${source}`,'ok');break;
      }
      if(['failed','cancelled','expired','delivery-interrupted'].includes(job.status))throw new Error(job.error||job.status);
      await new Promise(resolve=>setTimeout(resolve,650));
      r=await fetch(job.status_url);data=await r.json();if(!r.ok||!data.ok)throw new Error(data.error||`HTTP ${r.status}`);job=data.job;downloadJobs[name]=job;
    }
  }catch(e){setJobStatus(name,'Failed: '+e.message,'bad')}
  finally{if(button)button.disabled=false}
}
$('downloads').innerHTML=downloads.map(x=>{const async=asyncDownloadName(x[1]);return `<div class="download"><div class="grow"><b>${x[0]}</b><div class="small">${x[2]}</div><div class="small" data-job-status="${x[1]}"></div></div>${async?`<div class="row"><button class="btn" onclick="startDownloadJob('${x[1]}',this)">Build / download</button><button class="btn" onclick="cancelDownloadJob('${x[1]}')">Cancel</button></div>`:`<a class="btn" href="/${x[1]}" download>Download</a>`}</div>`}).join('');'''
    html = _replace_required(html, old_download_render, new_download_render, "async download jobs")

    old_methods = "const availableMethods=(DATA.methods||[]).filter(x=>x.available);availableMethods.sort((a,b)=>(b.simple?1:0)-(a.simple?1:0)||a.label.localeCompare(b.label));for(const m of availableMethods){const o=document.createElement('option');o.value=m.id;o.textContent=(m.simple?'Easy — ':'Advanced — ')+m.label;$('method').appendChild(o)}"
    new_methods = "const setupMethodLanes=new Set(['simple-native','universal','universal-compat','manual-app-proxy']);const laneNames={'simple-native':'Simple/native','universal':'Third-party','universal-compat':'Compatibility','manual-app-proxy':'Manual proxy'};const laneOrder=DATA.methodLaneOrder||[];const availableMethods=(DATA.methods||[]).filter(x=>x.available&&setupMethodLanes.has(x.methodLane));availableMethods.sort((a,b)=>laneOrder.indexOf(a.methodLane)-laneOrder.indexOf(b.methodLane)||a.label.localeCompare(b.label));for(const m of availableMethods){const o=document.createElement('option');o.value=m.id;o.textContent=(laneNames[m.methodLane]||'Method')+' — '+m.label;$('method').appendChild(o)}"
    html = _replace_required(html, old_methods, new_methods, "simple-only Methods selector")

    for old, new in (
        ("Mac local controller: http://127.0.0.1:8788", "Desktop app: launch Router VPN; localhost controller is an internal compatibility surface"),
        ("Open the Router VPN local app/PWA at 127.0.0.1:8788 and import router-vpn-bundle.json.", "Open the Router VPN desktop app and link/import this node separately. The localhost controller is not the final daily-use UI."),
        ("For the full multi-engine controller, use the matching Windows build and WSL2 transport environment described in repository docs.", "Use the matching Windows build. Layered modes stay disabled with an exact reason until the native Windows TUN adapter for that mode is available; WSL is not counted as native support."),
    ):
        html = html.replace(old, new)
    return _replace_wizard(html)


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
    data["setupCenterMethodLanes"] = list(SETUP_METHOD_LANES)
    data["qrPolicy"] = "QR is emitted only for an actual interoperable import payload; arbitrary JSON/text configs are file/text imports."
    data["downloadUI"] = "authenticated-async-jobs-with-progress-cancel"
    data["setupOnboarding"] = {
        "version": 5,
        "auto_show_until_completed": True,
        "persistent_browser_progress": True,
        "action_driven_checks": ["health", "admin-status", "admin-settings", "admin-forwarding"],
        "daily_use_surface": "native-app-not-setup-center",
    }
    normalized_html = patch_html(generator.build_html(data))
    with tempfile.TemporaryDirectory(prefix=".normalize-setup.", dir=bundle) as td:
        stage = Path(td)
        staged_assets = stage / "setup-assets.json"
        staged_html = stage / "router-vpn-device-setup.html"
        staged_assets.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        staged_html.write_text(normalized_html, encoding="utf-8")
        staged_assets.chmod(0o600)
        staged_html.chmod(0o600)
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "atomic-private-batch.py"),
                f"{assets_path}={staged_assets}",
                f"{html_path}={staged_html}",
            ],
            check=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
