#!/usr/bin/env python3
"""Router VPN Setup Center server with authenticated admin proxy/UI.

This wraps download-broker.py rather than widening the router-agent admin plane.
The router-agent remains loopback-only on 127.0.0.1:8789 and the browser only
sees authenticated same-origin Setup Center routes on LAN-only port 8786.
"""
from __future__ import annotations

import argparse
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

SCRIPT_DIR = Path(__file__).resolve().parent
BROKER_PATH = SCRIPT_DIR / "download-broker.py"
_spec = spec_from_file_location("router_vpn_download_broker", BROKER_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"cannot load {BROKER_PATH}")
_broker = module_from_spec(_spec)
_spec.loader.exec_module(_broker)

ADMIN_BASE = "http://127.0.0.1:8789"
ADMIN_READ_ROUTES = {"/api/admin/clients", "/api/admin/status"}
MAX_ADMIN_RESPONSE = 2 * 1024 * 1024

ADMIN_PANEL = r'''
<section class="panel" data-tab="server-admin">
  <div class="card hero">
    <div class="row"><div class="grow"><h2 style="margin-bottom:4px">Server status</h2><div class="small">Live read-only data from the loopback-only router-agent admin plane. Refreshes only through this authenticated Setup Center session.</div></div><button class="btn primary" onclick="refreshServerAdmin()">Refresh now</button></div>
    <div id="adminSummary" class="grid3" style="margin-top:12px"></div>
  </div>
  <div class="card"><h2>Connected clients</h2><p class="small">WireGuard/AmneziaWG peer state is based on real handshake age and transfer counters. Proxy protocols are not falsely shown as session-enumerable.</p><div id="adminClients" class="scroll"><div class="small">Loading…</div></div></div>
  <div class="card"><h2>Protected ports & listeners</h2><p class="small">Reserved Router VPN/management ports stay protected from generic forwarding. This view reports the listeners the node can actually see.</p><div id="adminListeners" class="scroll"><div class="small">Loading…</div></div></div>
  <div class="card"><h2>Administration capability boundary</h2><div id="adminCapabilities" class="small">Loading…</div><p class="small">Ban/unban, peer revoke, settings writes and server update controls stay disabled until persistent authenticated mutation semantics are implemented and tested. This page does not fake those controls.</p></div>
</section>
'''

ADMIN_SCRIPT = r'''
<script id="routerVpnServerAdminScript">
(function(){
  const tab=document.createElement('button');tab.textContent='Server';tab.dataset.tab='server-admin';tab.onclick=()=>{gotoTab('server-admin');refreshServerAdmin()};document.getElementById('tabs').appendChild(tab);
  function esc(v){return String(v??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]))}
  function fmtBytes(n){n=Number(n||0);const u=['B','KiB','MiB','GiB','TiB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return `${n.toFixed(i?1:0)} ${u[i]}`}
  function fmtAge(n,state){if(state==='never-handshaken')return 'Never';n=Number(n||0);if(n<60)return `${n}s`;if(n<3600)return `${Math.floor(n/60)}m`;if(n<86400)return `${Math.floor(n/3600)}h`;return `${Math.floor(n/86400)}d`}
  function stateClass(s){return s==='recent-handshake'?'ok':s==='idle'?'warn':s==='stale'||s==='never-handshaken'?'bad':''}
  function card(title,value,note,kind=''){return `<div class="card" style="margin:0"><div class="small">${esc(title)}</div><div class="${kind}" style="font-size:24px;font-weight:750;margin:4px 0">${esc(value)}</div><div class="small">${esc(note||'')}</div></div>`}
  async function getJSON(path){const r=await fetch(path,{cache:'no-store'});let d={};try{d=await r.json()}catch{}if(!r.ok||d.ok===false)throw new Error(d.error||`HTTP ${r.status}`);return d}
  window.refreshServerAdmin=async function(){
    const summary=document.getElementById('adminSummary'),clientsEl=document.getElementById('adminClients'),listenersEl=document.getElementById('adminListeners'),capsEl=document.getElementById('adminCapabilities');
    summary.innerHTML=card('Status','Loading…','Reading router-agent');
    try{
      const [clients,status]=await Promise.all([getJSON('/api/admin/clients'),getJSON('/api/admin/status')]);
      const peers=Array.isArray(clients.clients)?clients.clients:[];const listeners=Array.isArray(status.listeners)?status.listeners:[];const recent=peers.filter(x=>x.state==='recent-handshake').length;const reserved=Array.isArray(status.reserved_ports)?status.reserved_ports:[];const active=Array.isArray(status.active_reserved_ports)?status.active_reserved_ports:[];const rules=Number(status.forwarding?.rule_count||0);
      summary.innerHTML=card('Recently active peers',recent,`${peers.length} WireGuard-family peer(s) discovered`,recent?'ok':'')+card('Forward rules',rules,status.forwarding?.master||'runtime status')+card('Protected listeners',active.length,`${reserved.length} reserved port(s) configured`);
      if(!peers.length){clientsEl.innerHTML='<p class="small">No WireGuard/AmneziaWG peers were returned by the node yet.</p>'}
      else{clientsEl.innerHTML='<table><thead><tr><th>State</th><th>Interface</th><th>Allowed IPs</th><th>Endpoint</th><th>Last handshake</th><th>RX</th><th>TX</th><th>Peer key</th></tr></thead><tbody>'+peers.map(p=>`<tr><td class="${stateClass(p.state)}"><b>${esc(p.state)}</b></td><td>${esc(p.interface)}<div class="small">${esc(p.source)}</div></td><td>${esc((p.allowed_ips||[]).join(', '))}</td><td>${esc(p.endpoint||'—')}</td><td>${esc(fmtAge(p.handshake_age_seconds,p.state))}</td><td>${esc(fmtBytes(p.rx_bytes))}</td><td>${esc(fmtBytes(p.tx_bytes))}</td><td><code>${esc(p.public_key||'')}</code></td></tr>`).join('')+'</tbody></table>'}
      listenersEl.innerHTML='<table><thead><tr><th>Protocol</th><th>Address</th><th>Port</th><th>Protected</th></tr></thead><tbody>'+listeners.map(x=>`<tr><td>${esc(x.protocol)}</td><td><code>${esc(x.address)}</code></td><td>${esc(x.port)}</td><td>${reserved.includes(Number(x.port))?'<span class="ok">Yes</span>':'No'}</td></tr>`).join('')+'</tbody></table>';
      const caps=status.capabilities||{};capsEl.innerHTML=Object.entries(caps).map(([k,v])=>`<span class="pill ${v?'ok':'warn'}">${esc(k.replaceAll('_',' '))}: ${v?'ready':'not implemented'}</span>`).join('')+(status.errors?.length?`<p class="warn">Diagnostics: ${esc(status.errors.join(' • '))}</p>`:'');
    }catch(e){summary.innerHTML=card('Server admin','Unavailable',e.message,'bad');clientsEl.innerHTML=`<p class="bad">${esc(e.message)}</p>`;listenersEl.innerHTML='<p class="small">No live listener data.</p>';capsEl.textContent='Read-only server status could not be loaded.'}
  };
  if(location.hash==='#server-admin'){gotoTab('server-admin');refreshServerAdmin()}
})();
</script>
'''


def _inject_admin_ui(text: str) -> str:
    if 'data-tab="server-admin"' in text:
        return text
    marker = '<div id="wizard" class="overlay"'
    if marker not in text:
        raise RuntimeError("Setup Center HTML no longer has the wizard marker")
    text = text.replace(marker, ADMIN_PANEL + "\n" + marker, 1)
    if "</body>" not in text:
        raise RuntimeError("Setup Center HTML has no body terminator")
    return text.replace("</body>", ADMIN_SCRIPT + "\n</body>", 1)


class Handler(_broker.Handler):
    server_version = "RouterVPNSetupCenter/5"

    def _proxy_admin(self, path: str) -> None:
        req = urllib.request.Request(
            ADMIN_BASE + path,
            headers={"Authorization": f"Bearer {self.server.setup_token}", "Accept": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=4) as response:
                body = response.read(MAX_ADMIN_RESPONSE + 1)
                status = int(response.status)
                content_type = response.headers.get("Content-Type", "application/json")
            if len(body) > MAX_ADMIN_RESPONSE:
                raise RuntimeError("router-agent admin response exceeds safety limit")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read(16384).decode("utf-8", "replace").strip()
            except Exception:
                detail = ""
            self._json(exc.code, {"ok": False, "error_code": "router_admin_rejected", "error": detail or f"router-agent returned HTTP {exc.code}"})
        except Exception as exc:
            self._json(503, {"ok": False, "error_code": "router_admin_unavailable", "error": f"router-agent admin plane unavailable: {type(exc).__name__}: {exc}"})

    def _serve_setup_html(self, name: str) -> None:
        path = Path(self.server.static_dir) / name
        if not path.is_file():
            self.send_error(404)
            return
        try:
            text = _inject_admin_ui(path.read_text(encoding="utf-8"))
        except Exception as exc:
            self._json(500, {"ok": False, "error_code": "setup_ui_error", "error": str(exc)})
            return
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path in ADMIN_READ_ROUTES:
            if not self._require_auth():
                return
            self._proxy_admin(path)
            return
        if path in ("/", "/index.html", "/router-vpn-device-setup.html"):
            if self._bootstrap_cookie():
                return
            if not self._require_auth():
                return
            self._serve_setup_html("index.html" if path in ("/", "/index.html") else "router-vpn-device-setup.html")
            return
        super().do_GET()


class Server(_broker.Server):
    pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/opt/router-vpn")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8786)
    args = ap.parse_args()
    base = Path(args.base).resolve()
    static = base / "downloads"
    static.mkdir(parents=True, exist_ok=True)
    _broker.cleanup_stale_temp()
    server = Server((args.bind, args.port), Handler, base, static)
    print(f"Router VPN Setup Center on {args.bind}:{args.port}; authenticated downloads + loopback server status proxy", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
