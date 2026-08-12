#!/usr/bin/env python3
"""Normalize Setup Center method metadata and patch the generated UI to the current product contract."""
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

# Setup Center Methods is deliberately limited to protocols a normal/native or
# third-party client can actually configure. Complex Router VPN orchestration
# stays in the Router VPN app instead of masquerading as a generic import.
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

    # Retained only for older consumers. methodLane is authoritative.
    method["simple"] = lane in ("simple-native", "universal") or ident == "router-vpn-app"


def _replace_required(html: str, old: str, new: str, label: str) -> str:
    if old not in html:
        raise RuntimeError(f"Setup Center UI template drifted before {label} patch")
    return html.replace(old, new, 1)


def patch_html(html: str) -> str:
    """Patch the legacy generator surface without weakening its private-data model."""
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
    old_cards = '''<div class="card simple"><h3>1. Router VPN app</h3><p>Best overall. Install the small platform package, import <code>router-vpn-bundle.json</code>, then choose WireGuard, AUTO, SMART AUTO, CUSTOM or any validated mode in the app.</p><button onclick="gotoTab('downloads')">Get the app/controller</button></div>
<div class="card simple"><h3>2. WireGuard only</h3><p>Fastest simple setup. Use the WireGuard config/QR from Devices & methods. It is the default base and the first connectivity test.</p><button onclick="gotoTab('devices')">Show WireGuard setup</button></div>
<div class="card simple"><h3>3. Compatible protocol app</h3><p>Use Shadowsocks, Hysteria2, AmneziaWG, Xray, OverTLS or another compatible app without installing the full Router VPN controller.</p><button onclick="gotoTab('devices')">Choose a method</button></div>'''
    new_cards = '''<div class="card simple"><h3>1. Simple / native</h3><p>Start with an interoperable protocol your platform or a normal client can configure directly. WireGuard is the baseline; AmneziaWG, Shadowsocks and Hysteria2 appear only with their truthful import contract.</p><button onclick="gotoTab('devices')">Choose a simple method</button></div>
<div class="card simple"><h3>2. Router VPN app — recommended</h3><p>Install Router VPN once, then link this node separately. Use the app for logical modes, AUTO / SMART AUTO / CUSTOM, DNS policy and the full Router VPN feature set.</p><button onclick="gotoTab('downloads')">Get Router VPN</button></div>
<div class="card simple"><h3>3. Universal third-party client</h3><p>Use only the compatible protocols listed under Devices & methods. The Setup Center does not pretend complex Router VPN stacks are generic third-party imports.</p><button onclick="gotoTab('devices')">Show compatible methods</button></div>
<div class="card simple"><h3>4. Manual / custom</h3><p>Advanced Router VPN stacks and CUSTOM composition belong in the Router VPN app or the full guide. They are not advertised as ordinary QR/config imports.</p><button onclick="gotoTab('guide')">Open advanced guide</button></div>'''
    html = _replace_required(html, old_cards, new_cards, "setup lane order")

    # Do not leave a stale direct JSON link after private node data stopped being
    # statically published. The explicit private node-link ZIP is generated
    # ephemerally and contains router-vpn-bundle.json for file import.
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
    return html


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
    data["methodContractVersion"] = 3
    data["methodLaneOrder"] = ["simple-native", "app", "universal", "universal-compat", "manual-app-proxy", "manual-advanced"]
    data["setupCenterMethodLanes"] = list(SETUP_METHOD_LANES)
    data["qrPolicy"] = "QR is emitted only for an actual interoperable import payload; arbitrary JSON/text configs are file/text imports."
    data["downloadUI"] = "authenticated-async-jobs-with-progress-cancel"
    assets_path.write_text(json.dumps(data, indent=2) + "\n")
    assets_path.chmod(0o600)
    html_path.write_text(patch_html(generator.build_html(data)))
    html_path.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
