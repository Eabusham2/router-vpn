#!/usr/bin/env python3
"""Authenticated Setup Center UI for real Router VPN server Stop/Emergency/Resume."""

SERVER_CONTROL_PANEL = r'''
<style id="rvpn-server-control-style">
#rvpn-server-control-card .rvpn-control-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:12px}
#rvpn-server-control-card .rvpn-control-state{font-size:20px;font-weight:800;margin:4px 0}
#rvpn-server-control-card .rvpn-control-ports{overflow-wrap:anywhere}
@media(max-width:760px){#rvpn-server-control-card .rvpn-control-grid{grid-template-columns:1fr}}
</style>
<script id="rvpn-server-control-script">
(()=>{
 let installed=false;
 const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 async function api(path,opt={}){const r=await fetch(path,{credentials:'same-origin',cache:'no-store',...opt});let d={};try{d=await r.json()}catch{}if(!r.ok||d.ok===false)throw new Error(d.error||`HTTP ${r.status}`);return d}
 function install(){
   if(installed)return true;
   const panel=document.querySelector('section[data-tab="server-admin"]');if(!panel)return false;
   const card=document.createElement('div');card.className='card';card.id='rvpn-server-control-card';card.innerHTML=`<div class="row"><div class="grow"><h2 style="margin-bottom:4px">VPN server control</h2><div class="small">Real network controls. Stop pauses Router VPN transport/service ingress but leaves Setup Center/admin/recovery reachable. Emergency Stop also removes and re-verifies live WireGuard-family peers. Neither action deletes profiles, rotates keys, prunes Docker, or exposes a container-management socket.</div></div><button class="btn" type="button" onclick="refreshRouterVpnServerControl()">Refresh</button></div><div class="rvpn-control-grid"><div><div class="small">State</div><div id="rvpn-server-control-state" class="rvpn-control-state">Loading…</div><div id="rvpn-server-control-note" class="small"></div></div><div><div class="small">Blocked Router VPN service ports</div><div id="rvpn-server-control-ports" class="rvpn-control-ports">—</div></div><div><div class="small">Actions</div><div class="admin-actions" style="margin-top:6px"><button id="rvpn-stop-vpn" class="btn" type="button" onclick="routerVpnStopServer()">Stop VPN</button><button id="rvpn-emergency-stop-vpn" class="btn danger" type="button" onclick="routerVpnEmergencyStopServer()">Emergency Stop</button><button id="rvpn-resume-vpn" class="btn primary" type="button" onclick="routerVpnResumeServer()">Resume VPN</button></div></div></div>`;
   const hero=panel.querySelector('.card.hero');if(hero&&hero.nextSibling)panel.insertBefore(card,hero.nextSibling);else panel.appendChild(card);
   for(const tab of document.querySelectorAll('#tabs [data-tab="server-admin"]'))tab.addEventListener('click',()=>setTimeout(window.refreshRouterVpnServerControl,0));
   installed=true;return true;
 }
 function render(d){const state=document.getElementById('rvpn-server-control-state'),note=document.getElementById('rvpn-server-control-note'),ports=document.getElementById('rvpn-server-control-ports');if(!state)return;state.textContent=d.emergency?'EMERGENCY STOPPED':d.paused?'STOPPED':'RUNNING';state.className='rvpn-control-state '+(d.emergency?'bad':d.paused?'warn':'ok');note.textContent=d.semantics||'';ports.textContent=Array.isArray(d.blocked_service_ports)&&d.blocked_service_ports.length?d.blocked_service_ports.join(', '):'No transport/service ports discovered';const paused=!!d.paused;document.getElementById('rvpn-stop-vpn').disabled=paused;document.getElementById('rvpn-emergency-stop-vpn').disabled=!!d.emergency;document.getElementById('rvpn-resume-vpn').disabled=!paused}
 window.refreshRouterVpnServerControl=async()=>{if(!install())return;try{render(await api('/api/admin/server-control'))}catch(e){const state=document.getElementById('rvpn-server-control-state'),note=document.getElementById('rvpn-server-control-note');if(state){state.textContent='UNAVAILABLE';state.className='rvpn-control-state bad'}if(note)note.textContent=e.message}};
 window.routerVpnStopServer=async()=>{if(!confirm('Stop Router VPN transport/service ingress? Setup Center/admin/recovery will remain reachable and profiles/keys will be preserved.'))return;try{render(await api('/api/admin/server-control/stop',{method:'POST'}))}catch(e){alert('Stop VPN failed: '+e.message)}};
 window.routerVpnEmergencyStopServer=async()=>{if(!confirm('Emergency Stop Router VPN? This immediately blocks transport/service ingress, removes live WireGuard-family peers, then verifies both wg and awg report no remaining peers. Profiles/keys remain stored for recovery.'))return;try{const d=await api('/api/admin/server-control/emergency-stop',{method:'POST'});await window.refreshRouterVpnServerControl();if(Number(d.live_peers_removed||0)>0)alert(`Emergency Stop removed ${d.live_peers_removed} live WireGuard-family peer(s).`)}catch(e){await window.refreshRouterVpnServerControl();alert('Emergency Stop incomplete; transport/service ingress may still be paused: '+e.message)}};
 window.routerVpnResumeServer=async()=>{try{render(await api('/api/admin/server-control/resume',{method:'POST'}))}catch(e){alert('Resume VPN failed: '+e.message)}};
 let tries=0;const timer=setInterval(()=>{tries++;if(install()||tries>40){clearInterval(timer);if(installed)window.refreshRouterVpnServerControl()}},50);
})();
</script>
'''
