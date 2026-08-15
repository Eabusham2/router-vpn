#!/usr/bin/env python3
"""Self-contained first-run + always-accessible Full Guide UI for Setup Center."""

GUIDE_PANEL = r'''
<style>
#rvpn-guide-open{position:fixed;left:22px;bottom:22px;z-index:999;border:1px solid #334155;border-radius:14px;padding:10px 14px;background:#172033;color:#f8fafc;font:700 14px system-ui;cursor:pointer;box-shadow:0 14px 40px #0006}
#rvpn-full-guide{width:min(820px,calc(100vw - 30px));max-height:min(820px,calc(100vh - 30px));border:1px solid #334155;border-radius:20px;background:#0f172a;color:#f8fafc;padding:0;box-shadow:0 24px 80px #000a}
#rvpn-full-guide::backdrop{background:#020617c9}
#rvpn-full-guide .rg-head{position:sticky;top:0;background:#111827;padding:16px 18px;border-bottom:1px solid #334155;z-index:2}
#rvpn-full-guide .rg-title{font:800 22px system-ui;margin:0 0 4px}
#rvpn-full-guide .rg-sub{font:13px/1.4 system-ui;color:#94a3b8}
#rvpn-full-guide .rg-body{padding:18px;font:14px/1.55 system-ui}
#rvpn-full-guide .rg-step{display:none}
#rvpn-full-guide .rg-step.active{display:block}
#rvpn-full-guide h3{font-size:19px;margin:.2em 0 .55em}
#rvpn-full-guide h4{font-size:15px;margin:1.1em 0 .3em}
#rvpn-full-guide code{background:#020617;border:1px solid #243047;border-radius:6px;padding:1px 5px}
#rvpn-full-guide .rg-note{background:#172033;border-left:3px solid #60a5fa;padding:10px 12px;border-radius:8px;margin:10px 0}
#rvpn-full-guide .rg-warn{background:#3f1d27;border-left:3px solid #fb7185;padding:10px 12px;border-radius:8px;margin:10px 0}
#rvpn-full-guide .rg-actions{display:flex;align-items:center;gap:8px;position:sticky;bottom:0;background:#111827;padding:12px 18px;border-top:1px solid #334155}
#rvpn-full-guide button{border:0;border-radius:10px;padding:9px 13px;background:#3157e3;color:white;font-weight:700;cursor:pointer}
#rvpn-full-guide button.secondary{background:#334155}
#rvpn-full-guide .rg-progress{height:6px;background:#1e293b;border-radius:6px;overflow:hidden;margin-top:10px}
#rvpn-full-guide .rg-bar{height:100%;background:#60a5fa;width:0}
#rvpn-full-guide ul{padding-left:20px}
#rvpn-full-guide .method{padding:10px 12px;border:1px solid #334155;border-radius:12px;margin:8px 0;background:#111827}
</style>
<button id="rvpn-guide-open" type="button">Full Guide</button>
<dialog id="rvpn-full-guide" aria-labelledby="rvpn-guide-title">
  <div class="rg-head">
    <div class="rg-title" id="rvpn-guide-title">Router VPN — Full Guide</div>
    <div class="rg-sub" id="rvpn-guide-counter">Setup from zero • progress is saved on this browser</div>
    <div class="rg-progress"><div class="rg-bar" id="rvpn-guide-bar"></div></div>
  </div>
  <div class="rg-body">
    <section class="rg-step" data-step="0">
      <h3>1. What gets installed — and what does not</h3>
      <p>Router VPN has two separate pieces: the <b>home node</b> running on the ASUS AI Board/Docker host, and a <b>generic Router VPN app</b> on each client device. Installing an app does not link it to your home. Linking a router later is a private data/import operation, so you install the app once and can add more routers without reinstalling it.</p>
      <div class="rg-note"><b>Direct public IP works.</b> DDNS is optional. Do not create a DDNS dependency when the public address is already usable.</div>
      <p>Normal setup is done here in Setup Center. Huge all-platform bundles are an advanced/offline fallback, not the normal path.</p>
    </section>
    <section class="rg-step" data-step="1">
      <h3>2. Deploy the home node from zero</h3>
      <ol>
        <li>Choose one verified exact <code>main</code> release SHA after its source/native/runtime gates and <b>Publish ARM64 Portainer images</b> are green.</li>
        <li>Download and checksum-verify the same-SHA <b>Exact-SHA production compose</b> artifact; use its generated <code>RouterVPN-Portainer-RELEASE_SHA.yaml</code> as the Portainer stack definition.</li>
        <li>The tracked <code>server/portainer-current.yaml</code> is only a reproducible template/baseline. Keep production image-only and never add a <code>build:</code> section.</li>
        <li>Use the real WAN interface and home-LAN CIDR. The endpoint can stay blank when automatic public-address detection is appropriate.</li>
        <li>Let initialization/finalization finish, then open Setup Center and use its health/admin surfaces before linking clients.</li>
      </ol>
      <div class="rg-warn">Never WAN-expose Setup Center 8786, Router API/private proof 8787, SOCKS5 1080, loopback OverTLS 14444, Portainer, AdGuard admin, or SSH.</div>
    </section>
    <section class="rg-step" data-step="2">
      <h3>3. ASUS router forwarding</h3>
      <p>Use the current ASUS Merlin forwarding helper from Setup Center rather than hand-editing old rules. It preserves existing hooks and probes the router firewall backend.</p>
      <ul>
        <li>ACME: WAN TCP 80 → AI Board 18080.</li>
        <li>WireGuard, AmneziaWG, Rosenpass, and explicitly exposed transport ports use their generated/current values.</li>
        <li>Protected internal control ports stay private.</li>
      </ul>
      <p>After a production update, revalidate the live ASUS rules once instead of blindly reinstalling them.</p>
    </section>
    <section class="rg-step" data-step="3">
      <h3>4. Pick the right setup method</h3>
      <div class="method"><b>1 — Simple / native method</b><br>Use a protocol's proven native/external client when Setup Center marks that exact method ready and provides the exact config/QR/instructions.</div>
      <div class="method"><b>2 — Router VPN app</b><br>Best for Router VPN AUTO/SMART/CUSTOM behavior, node selection, path proof, app-native diagnostics, supported kill-switch behavior, and supported multihop.</div>
      <div class="method"><b>3 — Universal third-party</b><br>Use only when the generated format is verified with the named external app. A config merely existing is not proof of interoperability.</div>
      <div class="method"><b>4 — Manual / custom</b><br>For advanced troubleshooting and custom protocol configuration. Manual Connect still requires health proof and rollback on failure.</div>
      <div class="rg-note">Unavailable or unproven lanes must stay grey/unavailable. Setup Center should never present an external app as supported only because the protocol name looks compatible.</div>
    </section>
    <section class="rg-step" data-step="4">
      <h3>5. Download for this device, then link the router</h3>
      <p>Use <b>Download for this device</b> in Setup Center when available. Windows, macOS, Linux, Android, and iOS/iPadOS packages are platform-specific; generic packages contain no home secrets.</p>
      <h4>Link after install</h4>
      <ul>
        <li>On home LAN, use secure one-time LAN pairing/direct import when offered.</li>
        <li>Or import the small private <code>router-vpn-bundle.json</code> through the app's Add Router/Files flow.</li>
        <li>The imported node identity is bound to the server WireGuard public key and must match the private path proof before Connected is accepted.</li>
      </ul>
      <p>For Apple platforms, Local Network permission is requested only for local discovery/import/control that actually needs it; it is not described as a VPN permission.</p>
    </section>
    <section class="rg-step" data-step="5">
      <h3>6. First connection</h3>
      <ol>
        <li>Select the router/node.</li>
        <li>Choose AUTO for the simplest validated route, or choose a supported manual mode.</li>
        <li>Where the logical mode supports it, choose WireGuard/AmneziaWG base preference and fallback.</li>
        <li>Choose DNS: Home AdGuard, fastest measured home-exit public DNS, Rescue, or an explicitly configured encrypted/custom resolver.</li>
        <li>Choose home-LAN access, MTU/Jumbo, supported kill-switch policy, and supported multihop options.</li>
        <li>Connect and watch connection progress. Connected is not accepted until selected-node private identity/path proof succeeds.</li>
      </ol>
      <div class="rg-note">AUTO stops at the first proven working candidate. SMART AUTO may connect first, test simplifications, and must restore the last proven stack if a reduction fails.</div>
    </section>
    <section class="rg-step" data-step="6">
      <h3>7. Forwarding, SOCKS5, and safety</h3>
      <p>Incoming forwarding has a master state plus per-rule state, supports TCP/UDP/both, ranges, address binding and IPv4/IPv6 targets where the runtime actually supports them. Proxy-only modes cannot pretend to provide DNAT.</p>
      <p>SOCKS5 is an internal/LAN or tunneled service. Keep its WAN exposure closed. If a method says “no servers found,” Setup Center should keep that method open and show what prerequisite/config is missing rather than collapsing the entire setup lane.</p>
      <p>LAN Off blocks ordinary home-LAN reachability while preserving only the minimum Router VPN control plane needed for safe management/recovery.</p>
    </section>
    <section class="rg-step" data-step="7">
      <h3>8. Prove, diagnose, recover</h3>
      <ul>
        <li>Use Connected Clients for real client/revoke/ban state.</li>
        <li>Use path proof and public-exit proof separately: Internet reachability alone is not a selected-node VPN proof.</li>
        <li>Retest DNS through the selected VPN path when DNS behavior is in question.</li>
        <li>Use Emergency Stop/rollback when a manual connection or policy transition fails.</li>
        <li>For strict kill switch, distinguish boot/always, connected, reconnecting, manual disconnect and failure states. Unsupported platform semantics fail closed.</li>
      </ul>
      <div class="rg-warn">On macOS, use the specific System Settings → Privacy & Security → Open Anyway flow only for a trusted locally-built artifact. Never globally disable Gatekeeper or platform security. Signed/notarized distribution remains the long-term target.</div>
      <p><b>Finishing this guide only marks first-run onboarding complete.</b> The Full Guide button remains available here permanently, and you can rerun from step 1 whenever needed.</p>
    </section>
  </div>
  <div class="rg-actions">
    <button id="rvpn-guide-back" class="secondary" type="button">Back</button>
    <button id="rvpn-guide-close" class="secondary" type="button">Close & resume later</button>
    <span style="flex:1"></span>
    <button id="rvpn-guide-restart" class="secondary" type="button">Restart guide</button>
    <button id="rvpn-guide-next" type="button">Next</button>
  </div>
</dialog>
<script>
(()=>{
 const KEY='routervpn.setup-guide.v1',dlg=document.getElementById('rvpn-full-guide'),open=document.getElementById('rvpn-guide-open'),back=document.getElementById('rvpn-guide-back'),next=document.getElementById('rvpn-guide-next'),close=document.getElementById('rvpn-guide-close'),restart=document.getElementById('rvpn-guide-restart'),bar=document.getElementById('rvpn-guide-bar'),counter=document.getElementById('rvpn-guide-counter'),steps=[...dlg.querySelectorAll('.rg-step')];
 const read=()=>{try{return JSON.parse(localStorage.getItem(KEY)||'{}')}catch(_){return{}}};
 let state=read(); if(!Number.isInteger(state.step))state.step=0; state.step=Math.max(0,Math.min(steps.length-1,state.step));
 const save=()=>localStorage.setItem(KEY,JSON.stringify({step:state.step,completed:!!state.completed,updatedAt:new Date().toISOString()}));
 function render(){steps.forEach((x,i)=>x.classList.toggle('active',i===state.step));back.disabled=state.step===0;next.textContent=state.step===steps.length-1?'Finish setup guide':'Next';counter.textContent=`Step ${state.step+1} of ${steps.length} • progress is saved on this browser`;bar.style.width=`${((state.step+1)/steps.length)*100}%`;save()}
 function show(){render();if(!dlg.open)dlg.showModal()}
 open.addEventListener('click',show); back.addEventListener('click',()=>{if(state.step>0){state.step--;render()}}); close.addEventListener('click',()=>{save();dlg.close()}); restart.addEventListener('click',()=>{state={step:0,completed:false};render()}); next.addEventListener('click',()=>{if(state.step<steps.length-1){state.step++;render();return}state.completed=true;state.step=0;save();dlg.close()});
 dlg.addEventListener('cancel',e=>{e.preventDefault();save();dlg.close()});
 // First-run lifecycle: automatically open every visit until explicit Finish.
 if(!state.completed)setTimeout(show,250);
})();
</script>
'''
