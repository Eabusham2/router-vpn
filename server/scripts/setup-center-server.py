#!/usr/bin/env python3
"""Router VPN Setup Center server with authenticated admin proxy/UI.

The browser talks only to authenticated same-origin Setup Center routes on LAN
port 8786. Router-agent administration remains server-side on loopback:
- 127.0.0.1:8789: live/read-only status
- 127.0.0.1:8790: persistent, authenticated mutations
Neither loopback admin port nor the Setup Center token is exposed to browser JS.
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

ADMIN_READ_BASE = "http://127.0.0.1:8789"
ADMIN_MUTATION_BASE = "http://127.0.0.1:8790"
ADMIN_READ_ROUTES = {"/api/admin/clients", "/api/admin/status"}
ADMIN_MUTATION_EXACT = {
    "/api/admin/settings": {"GET", "PUT"},
    "/api/admin/forwarding": {"GET", "POST"},
    "/api/admin/clients/ban": {"POST"},
    "/api/admin/clients/unban": {"POST"},
    "/api/admin/clients/revoke": {"POST"},
}
MAX_ADMIN_RESPONSE = 2 * 1024 * 1024
MAX_ADMIN_REQUEST = 16 * 1024

ADMIN_PANEL = r'''
<style id="routerVpnAdminStyle">
button,.btn{appearance:none;-webkit-appearance:none;background-color:#15213a!important;background-image:none!important;color:var(--text)!important;opacity:1}
button:hover,.btn:hover{background-color:#1c2d4d!important;border-color:#426c92!important}
button:focus-visible,.btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
button:disabled,.btn:disabled{opacity:.55;cursor:not-allowed;background-color:#10192c!important}
.switchrow{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:12px;border:1px solid var(--line);border-radius:12px;margin:8px 0}.admin-actions{display:flex;gap:6px;flex-wrap:wrap}.danger-note{border-left:3px solid var(--bad);padding-left:10px}.admin-form{display:grid;grid-template-columns:repeat(6,minmax(100px,1fr));gap:8px;align-items:end}.admin-form label{font-size:12px;color:var(--muted)}.admin-form input,.admin-form select{width:100%}@media(max-width:980px){.admin-form{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style>
<section class="panel" data-tab="server-admin">
  <div class="card hero">
    <div class="row"><div class="grow"><h2 style="margin-bottom:4px">Server status & administration</h2><div class="small">Live state and persistent server controls are proxied through this authenticated LAN-only Setup Center. Router-agent admin ports stay loopback-only.</div></div><button class="btn primary" onclick="refreshServerAdmin()">Refresh now</button></div>
    <div id="adminSummary" class="grid3" style="margin-top:12px"></div>
  </div>
  <div class="card"><h2>Server policy</h2><div id="adminPolicy"><div class="small">Loading…</div></div><p class="small">Forwarding master is a real forward-path gate. LAN access blocks tunnel-to-home-LAN forwarding while leaving the tunnel itself available.</p></div>
  <div class="card"><h2>Connected clients</h2><p class="small">WireGuard/AmneziaWG peer state uses real handshake age and transfer counters. <b>Ban</b> is reversible network blocking. <b>Revoke</b> also removes the live WireGuard-family peer and persists that revocation; it is intentionally harder to undo.</p><div id="adminClients" class="scroll"><div class="small">Loading…</div></div></div>
  <div class="card"><h2>Persistent port forwarding</h2><p class="small">Rules here are server-owned and survive router-agent restarts. Reserved Router VPN/management ports cannot be selected, and target IP must be a tunnel peer.</p>
    <div class="admin-form">
      <label>Protocol<select id="adminFwdProto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP + UDP</option></select></label>
      <label>External from<input id="adminFwdFrom" type="number" min="1" max="65535" placeholder="25565"></label>
      <label>External to<input id="adminFwdTo" type="number" min="1" max="65535" placeholder="25565"></label>
      <label>Target tunnel IP<input id="adminFwdIP" placeholder="10.77.0.2"></label>
      <label>Target port<input id="adminFwdTarget" type="number" min="0" max="65535" value="0"></label>
      <button class="btn primary" onclick="addAdminForwardRule()">Add rule</button>
    </div><div id="adminForwardRules" class="scroll" style="margin-top:12px"></div>
  </div>
  <div class="card"><h2>Protected ports & listeners</h2><p class="small">Reserved Router VPN/management ports stay protected from generic forwarding. This view reports listeners the node can actually see.</p><div id="adminListeners" class="scroll"><div class="small">Loading…</div></div></div>
  <div class="card"><h2>Administration capability boundary</h2><div id="adminCapabilities" class="small">Loading…</div><p class="small">Server update and one-click recovery remain unavailable until they have an authenticated rollback-safe implementation. They are not rendered as fake working controls.</p></div>
</section>
'''

ADMIN_SCRIPT = r'''
<script id="routerVpnServerAdminScript">
(function(){
  const tab=document.createElement('button');tab.textContent='Server';tab.dataset.tab='server-admin';tab.onclick=()=>{gotoTab('server-admin');refreshServerAdmin()};document.getElementById('tabs').appendChild(tab);
  let adminPeers=[],adminSettings={},adminForwarding={rules:[]},adminBanned=new Set(),adminRevoked=new Set();
  function esc(v){return String(v??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]))}
  function fmtBytes(n){n=Number(n||0);const u=['B','KiB','MiB','GiB','TiB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return `${n.toFixed(i?1:0)} ${u[i]}`}
  function fmtAge(n,state){if(state==='never-handshaken')return 'Never';n=Number(n||0);if(n<60)return `${n}s`;if(n<3600)return `${Math.floor(n/60)}m`;if(n<86400)return `${Math.floor(n/3600)}h`;return `${Math.floor(n/86400)}d`}
  function stateClass(s){return s==='recent-handshake'?'ok':s==='idle'?'warn':s==='stale'||s==='never-handshaken'?'bad':''}
  function card(title,value,note,kind=''){return `<div class="card" style="margin:0"><div class="small">${esc(title)}</div><div class="${kind}" style="font-size:24px;font-weight:750;margin:4px 0">${esc(value)}</div><div class="small">${esc(note||'')}</div></div>`}
  async function api(path,opt={}){const options={cache:'no-store',...opt};if(options.body&&typeof options.body!=='string'){options.headers={...(options.headers||{}),'Content-Type':'application/json'};options.body=JSON.stringify(options.body)}const r=await fetch(path,options);let d={};try{d=await r.json()}catch{}if(!r.ok||d.ok===false)throw new Error(d.error||`HTTP ${r.status}`);return d}
  function peerPayload(p){return {interface:p.interface,public_key:p.public_key,allowed_ips:p.allowed_ips||[]}}
  function renderPolicy(){const el=document.getElementById('adminPolicy');const f=!!adminSettings.forwarding_master,l=!!adminSettings.lan_access;el.innerHTML=`<div class="switchrow"><div><b>Port-forwarding master</b><div class="small">${f?'WAN-to-tunnel forwarding allowed by master policy.':'Blocked at the forward path even if a NAT rule exists.'}</div></div><button class="btn ${f?'':'danger'}" onclick="setAdminSetting('forwarding_master',${!f})">${f?'Turn off':'Turn on'}</button></div><div class="switchrow"><div><b>Home LAN access</b><div class="small">${l?'Tunnel peers may reach permitted home-LAN destinations.':'Tunnel-to-home-LAN forwarding is blocked by policy.'}</div></div><button class="btn ${l?'':'danger'}" onclick="setAdminSetting('lan_access',${!l})">${l?'Turn off':'Turn on'}</button></div>`}
  function renderClients(){const el=document.getElementById('adminClients');if(!adminPeers.length){el.innerHTML='<p class="small">No WireGuard/AmneziaWG peers were returned by the node yet.</p>';return}el.innerHTML='<table><thead><tr><th>State</th><th>Interface</th><th>Allowed IPs</th><th>Endpoint</th><th>Last handshake</th><th>RX</th><th>TX</th><th>Actions</th></tr></thead><tbody>'+adminPeers.map(p=>{const banned=adminBanned.has(p.public_key),revoked=adminRevoked.has(p.public_key);return `<tr><td class="${stateClass(p.state)}"><b>${esc(revoked?'revoked':banned?'banned':p.state)}</b></td><td>${esc(p.interface)}<div class="small">${esc(p.source)}</div></td><td>${esc((p.allowed_ips||[]).join(', '))}</td><td>${esc(p.endpoint||'—')}</td><td>${esc(fmtAge(p.handshake_age_seconds,p.state))}</td><td>${esc(fmtBytes(p.rx_bytes))}</td><td>${esc(fmtBytes(p.tx_bytes))}</td><td><div class="admin-actions">${revoked?'<span class="bad">Revoked</span>':banned?`<button class="btn" onclick="unbanAdminPeer('${esc(p.public_key)}')">Unban</button>`:`<button class="btn" onclick="banAdminPeer('${esc(p.public_key)}')">Ban</button>`}${revoked?'':`<button class="btn danger" onclick="revokeAdminPeer('${esc(p.public_key)}')">Revoke</button>`}</div></td></tr>`}).join('')+'</tbody></table>'}
  function renderForwardRules(){const el=document.getElementById('adminForwardRules'),rules=Array.isArray(adminForwarding.rules)?adminForwarding.rules:[];if(!rules.length){el.innerHTML='<p class="small">No persistent server-owned forwarding rules.</p>';return}el.innerHTML='<table><thead><tr><th>Enabled</th><th>Protocol</th><th>External</th><th>Target</th><th>Actions</th></tr></thead><tbody>'+rules.map(r=>`<tr><td>${r.enabled?'<span class="ok">On</span>':'<span class="warn">Off</span>'}</td><td>${esc(r.protocol)}</td><td>${esc(r.from)}${Number(r.to)!==Number(r.from)?'–'+esc(r.to):''}</td><td>${esc(r.target_ip)}${Number(r.target_port)>0?':'+esc(r.target_port):' (same port)'}</td><td class="admin-actions"><button class="btn" onclick="toggleAdminForward('${esc(r.id)}')">${r.enabled?'Disable':'Enable'}</button><button class="btn danger" onclick="deleteAdminForward('${esc(r.id)}')">Delete</button></td></tr>`).join('')+'</tbody></table>'}
  window.setAdminSetting=async function(key,value){try{await api('/api/admin/settings',{method:'PUT',body:{[key]:value}});await refreshServerAdmin()}catch(e){alert('Setting failed: '+e.message)}};
  window.banAdminPeer=async function(key){const p=adminPeers.find(x=>x.public_key===key);if(!p)return;try{await api('/api/admin/clients/ban',{method:'POST',body:peerPayload(p)});await refreshServerAdmin()}catch(e){alert('Ban failed: '+e.message)}};
  window.unbanAdminPeer=async function(key){try{await api('/api/admin/clients/unban',{method:'POST',body:{public_key:key}});await refreshServerAdmin()}catch(e){alert('Unban failed: '+e.message)}};
  window.revokeAdminPeer=async function(key){const p=adminPeers.find(x=>x.public_key===key);if(!p)return;if(!confirm('Revoke this peer? This removes the live WireGuard-family peer and persists the revocation. Use a newly issued node/client profile to restore access.'))return;try{await api('/api/admin/clients/revoke',{method:'POST',body:peerPayload(p)});await refreshServerAdmin()}catch(e){alert('Revoke failed: '+e.message)}};
  window.addAdminForwardRule=async function(){const from=Number(document.getElementById('adminFwdFrom').value),to=Number(document.getElementById('adminFwdTo').value||from),target=Number(document.getElementById('adminFwdTarget').value||0),ip=document.getElementById('adminFwdIP').value.trim(),protocol=document.getElementById('adminFwdProto').value;try{await api('/api/admin/forwarding',{method:'POST',body:{protocol,from,to,target_ip:ip,target_port:target,enabled:true}});document.getElementById('adminFwdFrom').value='';document.getElementById('adminFwdTo').value='';document.getElementById('adminFwdIP').value='';document.getElementById('adminFwdTarget').value='0';await refreshServerAdmin()}catch(e){alert('Forwarding rule failed: '+e.message)}};
  window.toggleAdminForward=async function(id){const r=(adminForwarding.rules||[]).find(x=>x.id===id);if(!r)return;try{await api('/api/admin/forwarding',{method:'POST',body:{...r,enabled:!r.enabled}});await refreshServerAdmin()}catch(e){alert('Forwarding update failed: '+e.message)}};
  window.deleteAdminForward=async function(id){if(!confirm('Delete this persistent forwarding rule?'))return;try{await api('/api/admin/forwarding/'+encodeURIComponent(id),{method:'DELETE'});await refreshServerAdmin()}catch(e){alert('Delete failed: '+e.message)}};
  window.refreshServerAdmin=async function(){
    const summary=document.getElementById('adminSummary'),clientsEl=document.getElementById('adminClients'),listenersEl=document.getElementById('adminListeners'),capsEl=document.getElementById('adminCapabilities');
    summary.innerHTML=card('Status','Loading…','Reading router-agent');
    try{
      const [clients,status,settings,forwarding]=await Promise.all([api('/api/admin/clients'),api('/api/admin/status'),api('/api/admin/settings'),api('/api/admin/forwarding')]);
      adminPeers=Array.isArray(clients.clients)?clients.clients:[];adminSettings=settings.settings||{};adminForwarding=forwarding||{rules:[]};adminBanned=new Set((settings.banned_peers||[]).map(x=>x.public_key));adminRevoked=new Set((settings.revoked_peers||[]).map(x=>x.public_key));
      const listeners=Array.isArray(status.listeners)?status.listeners:[],recent=adminPeers.filter(x=>x.state==='recent-handshake'&&!adminBanned.has(x.public_key)).length,reserved=Array.isArray(status.reserved_ports)?status.reserved_ports:[],active=Array.isArray(status.active_reserved_ports)?status.active_reserved_ports:[],rules=Array.isArray(adminForwarding.rules)?adminForwarding.rules:[];
      summary.innerHTML=card('Recently active peers',recent,`${adminPeers.length} WireGuard-family peer(s) discovered`,recent?'ok':'')+card('Forwarding master',adminSettings.forwarding_master?'ON':'OFF',`${rules.filter(x=>x.enabled).length}/${rules.length} persistent rule(s) enabled`,adminSettings.forwarding_master?'ok':'warn')+card('Home LAN access',adminSettings.lan_access?'ON':'OFF',`${active.length}/${reserved.length} protected port(s) listening`,adminSettings.lan_access?'ok':'warn');
      renderPolicy();renderClients();renderForwardRules();
      listenersEl.innerHTML='<table><thead><tr><th>Protocol</th><th>Address</th><th>Port</th><th>Protected</th></tr></thead><tbody>'+listeners.map(x=>`<tr><td>${esc(x.protocol)}</td><td><code>${esc(x.address)}</code></td><td>${esc(x.port)}</td><td>${reserved.includes(Number(x.port))?'<span class="ok">Yes</span>':'No'}</td></tr>`).join('')+'</tbody></table>';
      const caps={...(status.capabilities||{}),...(settings.capabilities||{})};capsEl.innerHTML=Object.entries(caps).map(([k,v])=>`<span class="pill ${v?'ok':'warn'}">${esc(k.replaceAll('_',' '))}: ${v?'ready':'not implemented'}</span>`).join('')+(status.errors?.length?`<p class="warn">Diagnostics: ${esc(status.errors.join(' • '))}</p>`:'');
    }catch(e){summary.innerHTML=card('Server admin','Unavailable',e.message,'bad');clientsEl.innerHTML=`<p class="bad">${esc(e.message)}</p>`;listenersEl.innerHTML='<p class="small">No live listener data.</p>';capsEl.textContent='Server administration could not be loaded.'}
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


def _mutation_route(path: str, method: str) -> bool:
    allowed = ADMIN_MUTATION_EXACT.get(path)
    if allowed and method in allowed:
        return True
    prefix = "/api/admin/forwarding/"
    return method == "DELETE" and path.startswith(prefix) and bool(path[len(prefix):]) and "/" not in path[len(prefix):]


class Handler(_broker.Handler):
    server_version = "RouterVPNSetupCenter/6"

    def _proxy_admin(self, base: str, path: str, method: str = "GET") -> None:
        body = None
        headers = {"Authorization": f"Bearer {self.server.setup_token}", "Accept": "application/json"}
        if method in ("POST", "PUT", "PATCH"):
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._json(400, {"ok": False, "error_code": "bad_request", "error": "invalid Content-Length"})
                return
            if length <= 0 or length > MAX_ADMIN_REQUEST:
                self._json(400, {"ok": False, "error_code": "bad_request", "error": "admin request body size is invalid"})
                return
            body = self.rfile.read(length)
            try:
                parsed = json.loads(body)
            except Exception as exc:
                self._json(400, {"ok": False, "error_code": "bad_request", "error": f"invalid JSON: {exc}"})
                return
            if not isinstance(parsed, dict):
                self._json(400, {"ok": False, "error_code": "bad_request", "error": "admin request must be a JSON object"})
                return
            body = json.dumps(parsed, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(base + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                response_body = response.read(MAX_ADMIN_RESPONSE + 1)
                status = int(response.status)
                content_type = response.headers.get("Content-Type", "application/json")
            if len(response_body) > MAX_ADMIN_RESPONSE:
                raise RuntimeError("router-agent admin response exceeds safety limit")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
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
            self._proxy_admin(ADMIN_READ_BASE, path)
            return
        if _mutation_route(path, "GET"):
            if not self._require_auth():
                return
            self._proxy_admin(ADMIN_MUTATION_BASE, path)
            return
        if path in ("/", "/index.html", "/router-vpn-device-setup.html"):
            if self._bootstrap_cookie():
                return
            if not self._require_auth():
                return
            self._serve_setup_html("index.html" if path in ("/", "/index.html") else "router-vpn-device-setup.html")
            return
        super().do_GET()

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if _mutation_route(path, "POST"):
            if not self._require_auth():
                return
            self._proxy_admin(ADMIN_MUTATION_BASE, path, "POST")
            return
        super().do_POST()

    def do_PUT(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if not _mutation_route(path, "PUT"):
            self.send_error(404)
            return
        if not self._require_auth():
            return
        self._proxy_admin(ADMIN_MUTATION_BASE, path, "PUT")

    def do_DELETE(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if _mutation_route(path, "DELETE"):
            if not self._require_auth():
                return
            self._proxy_admin(ADMIN_MUTATION_BASE, path, "DELETE")
            return
        super().do_DELETE()


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
    print(f"Router VPN Setup Center on {args.bind}:{args.port}; authenticated downloads + loopback read/mutation admin proxy", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
