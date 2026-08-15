#!/usr/bin/env python3
"""Final product-only Setup Center reconciliation and verified onboarding UI.

This module intentionally layers on top of the mature authenticated Setup Center
instead of replacing its broker/admin/AI implementations. It repairs a few old
generated-page claims, supplies the canonical easiest-to-advanced setup lanes,
and makes first-run completion depend on real same-origin authenticated checks
that Setup Center can actually observe.
"""
from __future__ import annotations

import re


_CANONICAL_START = r'''
<section class="panel active" data-tab="start"><div class="card hero"><h2>Choose the easiest path</h2><div class="grid2">
<div class="card simple"><h3>1. Simple / native</h3><p>Start with the simplest proven native or external-client method for your platform, normally WireGuard Raw. This is the quickest independent connectivity test and a full VPN when the selected method is a tunnel.</p><button onclick="gotoTab('devices')">Show simple methods</button></div>
<div class="card simple"><h3>2. Router VPN app — recommended</h3><p>Install the generic native app once, then link one or many private nodes. Use it for the full supported feature set: logical modes, AUTO/SMART/CUSTOM, node proof, DNS policy, supported kill switch, multihop, diagnostics and native app UX.</p><button onclick="gotoTab('downloads')">Get Router VPN</button></div>
<div class="card simple"><h3>3. Universal third-party</h3><p>Use only an interoperable config/URL/QR that Setup Center names for a compatible external client. A generated complex Router VPN stack is never presented as a fake universal import.</p><button onclick="gotoTab('devices')">Choose a compatible method</button></div>
<div class="card"><h3>4. Manual / custom</h3><p>Use manual/custom configuration for advanced troubleshooting or protocol-specific setup. Manual Router VPN connections still require runtime health/path proof and fail closed on unsupported combinations.</p><button onclick="gotoTab('guide')">Open advanced guide</button></div>
</div></div>
<div class="card"><h2>Full setup at a glance</h2><div id="quickSteps"></div></div></section>
'''


def reconcile_setup_text(text: str) -> str:
    """Repair only known obsolete generated-page product copy.

    The generated asset remains useful for its data/method/download tables. These
    replacements intentionally target exact product sections/phrases so future
    generator changes fail visibly in tests instead of broad-rewriting arbitrary
    documentation or protocol text.
    """
    if not isinstance(text, str):
        raise TypeError("Setup Center HTML must be text")

    text, count = re.subn(
        r'<section class="panel active" data-tab="start">.*?</section>\s*\n\s*<section class="panel" data-tab="downloads">',
        _CANONICAL_START + '\n<section class="panel" data-tab="downloads">',
        text,
        count=1,
        flags=re.S,
    )
    if count != 1:
        raise RuntimeError("Setup Center start section marker changed; refusing silent lane-order regression")

    text = text.replace(
        'onclick="startWizard(true)"',
        'onclick="routerVpnOpenVerifiedOnboarding()"',
        1,
    )
    text = text.replace(
        "if(localStorage.getItem(WIZKEY)!=='1')startWizard(false);",
        "/* legacy generated wizard is superseded by verified onboarding + always-accessible Full Guide */",
        1,
    )
    text = text.replace(
        'The mode table explains all 20 modes and their expected overhead.',
        'The app presents 16 logical user modes; the server keeps 20 raw runtimes internally for validated variants/fallbacks. The mode table shows the underlying raw runtime catalog and expected overhead.',
        1,
    )
    text = text.replace(
        '<p class="small">Multi-hop is intentionally not labeled ready here yet. A real multi-hop feature must route one validated self-hosted node through another without leaking DNS or bypassing kill-switch policy; the UI must not pretend that exists before the chain adapter is tested.</p>',
        '<p class="small">Multihop is available only on platform/runtime combinations with a real validated chain adapter and exit-node proof. Unsupported combinations remain unavailable, and the UI shows the added path-latency cost instead of pretending parity.</p>',
        1,
    )
    text = text.replace(
        '<p>The desktop controller has <b>Off</b> and an emergency local transport stop. A strict firewall kill switch and remote “kick every peer” control are not advertised as ready until their platform-specific firewall/peer implementations are tested. This avoids a cosmetic switch that could leak traffic.</p>',
        '<p>Kill-switch behavior is platform-specific and fail-closed: supported desktop firewall policies, Android system lockdown checks, and Apple NetworkExtension route lockdown are enforced only where the runtime can prove them. Manual disconnect remains distinct from reconnect/failure recovery, and unsupported semantics stay unavailable.</p>',
        1,
    )
    text = text.replace(
        'Router VPN is a real native app. Raw WireGuard uses the PacketTunnel engine today; unsupported layered/AWG/multihop combinations stay visibly unavailable instead of being faked.',
        'Router VPN is a real native app. Raw WireGuard uses WireGuardKit; compatible imported sing-box profiles use the pinned Libbox PacketTunnel with exact selected-node proof. AWG/Xray-only, ALL/MAX and unsupported multihop combinations stay visibly unavailable instead of being faked.',
        1,
    )
    return text


VERIFIED_ONBOARDING_PANEL = r'''
<style id="rvpn-verified-onboarding-style">
#rvpn-verified-onboarding .rv-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}#rvpn-verified-onboarding .rv-lane{border:1px solid var(--line);border-radius:13px;padding:13px;background:#0d1628}#rvpn-verified-onboarding .rv-check{display:grid;grid-template-columns:minmax(170px,1fr) auto;gap:10px;align-items:center;padding:12px 0;border-bottom:1px solid var(--line)}#rvpn-verified-onboarding .rv-state{font-weight:750}.rv-ext-grid{display:grid;grid-template-columns:repeat(4,minmax(120px,1fr));gap:8px;align-items:end}.rv-ext-grid label{font-size:12px;color:var(--muted)}.rv-ext-grid input,.rv-ext-grid select{width:100%}@media(max-width:850px){#rvpn-verified-onboarding .rv-grid,.rv-ext-grid{grid-template-columns:1fr}}
</style>
<section class="panel" data-tab="verified-onboarding" id="rvpn-verified-onboarding">
  <div class="card hero"><div class="row"><div class="grow"><h2 style="margin-bottom:4px">Verified Setup</h2><div class="small">Setup Center only marks the checks it can actually observe. It does not convert “page opened” or generic Internet access into a successful VPN/path proof.</div></div><button class="btn" type="button" onclick="routerVpnRunOnboardingAgain()">Run onboarding again</button></div></div>
  <div class="card"><h2>Setup lanes — easiest → advanced</h2><div class="rv-grid">
    <div class="rv-lane"><b>1. Simple / native</b><p class="small">Use a proven native/external client and exact config. WireGuard Raw is the normal first full-tunnel test. Each method states whether it is full VPN or proxy-only and names compatible clients.</p></div>
    <div class="rv-lane"><b>2. Router VPN app — recommended</b><p class="small">Generic app installed once; private nodes linked separately. Full supported logical-mode/AUTO/SMART/CUSTOM, DNS, diagnostics, kill-switch and multihop behavior belongs here.</p></div>
    <div class="rv-lane"><b>3. Universal third-party</b><p class="small">Only verified interoperable protocol imports belong here. Complex Router VPN stacks are not disguised as universal third-party methods.</p></div>
    <div class="rv-lane"><b>4. Manual / custom</b><p class="small">Advanced/manual path for troubleshooting or explicit protocol configuration. Unsupported engines or combinations remain unavailable.</p></div>
  </div></div>
  <div class="card"><h2>Observable setup checks</h2><div id="rvpn-verify-checks"></div><div class="row" style="margin-top:14px"><button class="btn primary" type="button" onclick="routerVpnRunAllSetupChecks()">Run all checks</button><button id="rvpn-verify-complete" class="btn" type="button" onclick="routerVpnCompleteVerifiedOnboarding()" disabled>Complete verified onboarding</button><span id="rvpn-verify-summary" class="small"></span></div></div>
</section>
<script id="rvpn-verified-onboarding-script">
(()=>{
 const KEY='routervpn.verified-onboarding.v1',GUIDEKEY='routervpn.setup-guide.v1',checks={health:false,admin:false,release:false,clients:false};
 const labels={health:'Home-node health / protected listeners',admin:'Authenticated forwarding / Protected-DMZ state',release:'Release & recovery status',clients:'Connected-client observation (informational)'};
 const stateText={};
 function read(){try{return JSON.parse(localStorage.getItem(KEY)||'{}')}catch(_){return{}}}
 function save(extra={}){const prior=read();localStorage.setItem(KEY,JSON.stringify({...prior,...extra,checks:{...checks},updatedAt:new Date().toISOString()}))}
 function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
 async function api(path,opt={}){const r=await fetch(path,{cache:'no-store',credentials:'same-origin',...opt});let d={};try{d=await r.json()}catch{}if(!r.ok||d.ok===false)throw new Error(d.error||`HTTP ${r.status}`);return d}
 function requiredDone(){return checks.health&&checks.admin&&checks.release}
 function render(){
   const host=document.getElementById('rvpn-verify-checks');if(!host)return;
   host.innerHTML=Object.keys(labels).map(k=>`<div class="rv-check"><div><b>${esc(labels[k])}</b><div class="small">${esc(stateText[k]||'Not checked yet')}</div></div><div><span class="rv-state ${checks[k]?'ok':'warn'}">${checks[k]?'Checked':'Pending'}</span> <button class="btn" type="button" data-rvpn-check="${k}">Check</button></div></div>`).join('');
   host.querySelectorAll('[data-rvpn-check]').forEach(b=>b.addEventListener('click',()=>runCheck(b.dataset.rvpnCheck)));
   const complete=document.getElementById('rvpn-verify-complete');if(complete)complete.disabled=!requiredDone();
   const summary=document.getElementById('rvpn-verify-summary');if(summary)summary.textContent=requiredDone()?'Required Setup Center checks passed. Finish the Full Guide/first-run flow when ready.':'Required checks still need real responses.';
   save();
 }
 async function runCheck(kind){
   checks[kind]=false;stateText[kind]='Checking real Setup Center state…';render();
   try{
     if(kind==='health'){
       const d=await api('/api/admin/status');
       const listeners=Array.isArray(d.listeners)?d.listeners:[],active=Array.isArray(d.active_reserved_ports)?d.active_reserved_ports:[];
       checks.health=true;stateText.health=`Router-agent responded; ${active.length}/${Array.isArray(d.reserved_ports)?d.reserved_ports.length:0} protected port(s) currently listening; ${listeners.length} listener row(s) observed.`;
     }else if(kind==='admin'){
       const d=await api('/api/admin/forwarding-extension');
       const rules=Array.isArray(d.rules)?d.rules:[],dmz=d.protected_dmz;
       checks.admin=true;stateText.admin=`Authenticated persistent state read succeeded. Master ${d.forwarding_master?'ON':'OFF'}; ${rules.length} explicit rule(s); Protected DMZ ${dmz&&dmz.enabled?'ON':'OFF'}.`;
     }else if(kind==='release'){
       const d=await api('/api/release-status');
       checks.release=true;stateText.release=`Release/recovery status endpoint responded truthfully${d.sha?' for '+d.sha:''}. This check does not claim production/device proof.`;
     }else if(kind==='clients'){
       const d=await api('/api/admin/clients');const rows=Array.isArray(d.clients)?d.clients:[],recent=rows.filter(x=>x&&x.state==='recent-handshake').length;
       checks.clients=true;stateText.clients=`Observed ${rows.length} WireGuard-family peer row(s), ${recent} with a recent handshake. Zero peers is reported as zero, not converted to success.`;
     }
   }catch(e){stateText[kind]=`Check failed: ${e.message}`}
   render();
 }
 window.routerVpnRunAllSetupChecks=async()=>{for(const kind of ['health','admin','release','clients'])await runCheck(kind)};
 window.routerVpnCompleteVerifiedOnboarding=()=>{if(!requiredDone())return;save({completed:true,completedAt:new Date().toISOString()});render()};
 window.routerVpnOpenVerifiedOnboarding=()=>{if(typeof gotoTab==='function')gotoTab('verified-onboarding');else location.hash='verified-onboarding'};
 window.routerVpnRunOnboardingAgain=()=>{localStorage.removeItem(KEY);localStorage.removeItem(GUIDEKEY);localStorage.removeItem('routervpn.setupcenter.done.v4');localStorage.removeItem('routervpn.setupcenter.step.v4');for(const k of Object.keys(checks)){checks[k]=false;delete stateText[k]}render();const open=document.getElementById('rvpn-guide-open');if(open)open.click();else window.routerVpnOpenVerifiedOnboarding()};
 const old=read();if(old.checks)for(const k of Object.keys(checks))checks[k]=!!old.checks[k];
 const tabs=document.getElementById('tabs');if(tabs&&!tabs.querySelector('[data-tab="verified-onboarding"]')){const b=document.createElement('button');b.textContent='Verify setup';b.dataset.tab='verified-onboarding';b.onclick=window.routerVpnOpenVerifiedOnboarding;tabs.appendChild(b)}
 render();
 const next=document.getElementById('rvpn-guide-next'),dlg=document.getElementById('rvpn-full-guide');if(next&&dlg){next.addEventListener('click',e=>{const last=dlg.querySelector('.rg-step.active[data-step="7"]');if(last&&!requiredDone()){e.preventDefault();e.stopImmediatePropagation();dlg.close();window.routerVpnOpenVerifiedOnboarding();stateText.release=stateText.release||'Run the required Setup Center checks before finishing first-run onboarding.';render()}},true)}
 if(!old.completed)setTimeout(window.routerVpnOpenVerifiedOnboarding,650);

 function installForwardingExtensionUI(){const panel=document.querySelector('section[data-tab="server-admin"]');if(!panel||document.getElementById('rvpn-forwarding-extension-card'))return;const card=document.createElement('div');card.className='card';card.id='rvpn-forwarding-extension-card';card.innerHTML=`<h2>Forwarding ownership & Protected DMZ</h2><p class="small">Owner/client association is persistent metadata for explicit rules. Protected DMZ forwards only otherwise-unused allowed ports to one tunnel peer; Router VPN/management listeners and explicit forwarding ports remain excluded, and the forwarding master still gates the path.</p><div id="rvpn-forward-owner-list" class="scroll"><div class="small">Loading…</div></div><h3>Protected DMZ</h3><div class="rv-ext-grid"><label>Owner / client<input id="rvpn-dmz-owner" placeholder="Gaming PC / wg peer"></label><label>Target tunnel IP<input id="rvpn-dmz-ip" placeholder="10.77.0.2 or fd77:77::2"></label><label>Protocol<select id="rvpn-dmz-proto"><option value="both">TCP + UDP</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><label><input id="rvpn-dmz-enabled" type="checkbox" checked> Enabled</label></div><div class="row" style="margin-top:10px"><button class="btn primary" type="button" onclick="routerVpnSaveProtectedDMZ()">Save Protected DMZ</button><button class="btn danger" type="button" onclick="routerVpnClearProtectedDMZ()">Clear Protected DMZ</button><span id="rvpn-dmz-state" class="small"></span></div>`;panel.appendChild(card);refreshForwardingExtension()}
 async function refreshForwardingExtension(){const list=document.getElementById('rvpn-forward-owner-list');if(!list)return;try{const d=await api('/api/admin/forwarding-extension');const rules=Array.isArray(d.rules)?d.rules:[];list.innerHTML=rules.length?'<table><thead><tr><th>Rule</th><th>Target</th><th>Owner / client</th><th>Save</th></tr></thead><tbody>'+rules.map(r=>`<tr><td>${esc(r.protocol)} ${esc(r.from)}${Number(r.to)!==Number(r.from)?'–'+esc(r.to):''}<div class="small">${esc(r.id)}</div></td><td>${esc(r.target_ip)}${Number(r.target_port)>0?':'+esc(r.target_port):''}</td><td><input data-rvpn-owner-id="${esc(r.id)}" value="${esc(r.owner||'')}" placeholder="Client / device"></td><td><button class="btn" type="button" data-rvpn-save-owner="${esc(r.id)}">Save owner</button></td></tr>`).join('')+'</tbody></table>':'<p class="small">No explicit persistent forwarding rules yet. Create one above, then associate it with its client here.</p>';list.querySelectorAll('[data-rvpn-save-owner]').forEach(b=>b.addEventListener('click',()=>saveOwner(b.dataset.rvpnSaveOwner)));const dmz=d.protected_dmz||null;if(dmz){document.getElementById('rvpn-dmz-owner').value=dmz.owner||'';document.getElementById('rvpn-dmz-ip').value=dmz.target_ip||'';document.getElementById('rvpn-dmz-proto').value=dmz.protocol||'both';document.getElementById('rvpn-dmz-enabled').checked=!!dmz.enabled}document.getElementById('rvpn-dmz-state').textContent=dmz?`Protected DMZ ${dmz.enabled?'ON':'OFF'} → ${dmz.target_ip} • ${dmz.owner}`:'Protected DMZ is off';}catch(e){list.innerHTML=`<p class="bad">Forwarding extension unavailable: ${esc(e.message)}</p>`}}
 async function saveOwner(id){const input=document.querySelector(`[data-rvpn-owner-id="${CSS.escape(id)}"]`),owner=input?input.value.trim():'';if(!owner){alert('Owner/client association is required.');return}try{await api('/api/admin/forwarding-extension/owners/'+encodeURIComponent(id),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({owner})});await refreshForwardingExtension()}catch(e){alert('Owner save failed: '+e.message)}}
 window.routerVpnSaveProtectedDMZ=async()=>{const owner=document.getElementById('rvpn-dmz-owner').value.trim(),target_ip=document.getElementById('rvpn-dmz-ip').value.trim(),protocol=document.getElementById('rvpn-dmz-proto').value,enabled=document.getElementById('rvpn-dmz-enabled').checked;if(!owner||!target_ip){alert('Owner/client and target tunnel IP are required.');return}try{await api('/api/admin/forwarding-extension/dmz',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({owner,target_ip,protocol,enabled})});await refreshForwardingExtension()}catch(e){alert('Protected DMZ save failed: '+e.message)}};
 window.routerVpnClearProtectedDMZ=async()=>{if(!confirm('Clear Protected DMZ? Explicit forwarding rules are kept.'))return;try{await api('/api/admin/forwarding-extension/dmz',{method:'DELETE'});await refreshForwardingExtension()}catch(e){alert('Protected DMZ clear failed: '+e.message)}};
 installForwardingExtensionUI();
 const baseRefresh=window.refreshServerAdmin;if(typeof baseRefresh==='function')window.refreshServerAdmin=async function(){const out=await baseRefresh.apply(this,arguments);await refreshForwardingExtension();return out};
})();
</script>
'''
