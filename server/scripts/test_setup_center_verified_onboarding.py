#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("routervpn_verified_onboarding_tested", HERE / "setup_center_verified_onboarding.py")
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

sample = '''
<button onclick="startWizard(true)">Start / resume setup</button>
<section class="panel active" data-tab="start"><div class="card hero"><h2>Choose the easiest path</h2><div class="grid3"><div>old app-first cards</div></div></div><div class="card"><h2>Full setup at a glance</h2><div id="quickSteps"></div></div></section>
<section class="panel" data-tab="downloads"><div>downloads</div></section>
The mode table explains all 20 modes and their expected overhead.
<p class="small">Multi-hop is intentionally not labeled ready here yet. A real multi-hop feature must route one validated self-hosted node through another without leaking DNS or bypassing kill-switch policy; the UI must not pretend that exists before the chain adapter is tested.</p>
<p>The desktop controller has <b>Off</b> and an emergency local transport stop. A strict firewall kill switch and remote “kick every peer” control are not advertised as ready until their platform-specific firewall/peer implementations are tested. This avoids a cosmetic switch that could leak traffic.</p>
Router VPN is a real native app. Raw WireGuard uses the PacketTunnel engine today; unsupported layered/AWG/multihop combinations stay visibly unavailable instead of being faked.
if(localStorage.getItem(WIZKEY)!=='1')startWizard(false);
'''
fixed = MOD.reconcile_setup_text(sample)

lanes = ["1. Simple / native", "2. Router VPN app — recommended", "3. Universal third-party", "4. Manual / custom"]
positions = [fixed.index(x) for x in lanes]
assert positions == sorted(positions), positions
assert 'onclick="routerVpnOpenVerifiedOnboarding()"' in fixed
assert "legacy generated wizard is superseded" in fixed
assert "16 logical user modes" in fixed and "20 raw runtimes internally" in fixed
assert "Multi-hop is intentionally not labeled ready" not in fixed
assert "strict firewall kill switch" not in fixed
assert "WireGuard and AmneziaWG" in fixed and "system VPN" in fixed

# Exercise the actual generator seam, not just the old hand-written sample.
# A previous generator revision changed the iOS sentence without updating the
# reconciler, leaving the obsolete AWG/multihop claims in the shipped page.
with tempfile.TemporaryDirectory(prefix="router-vpn-setup-guidance-") as temporary:
    base = Path(temporary)
    subprocess.run(
        [sys.executable, str(HERE / "generate-setup-assets.py"), str(base),
         "router.invalid", "192.168.50.133"],
        check=True, capture_output=True, timeout=15,
    )
    generated = json.loads((base / "client-bundle/setup-assets.json").read_text())
    current = generated["devices"]["ios"]["customApp"]
    page = (base / "client-bundle/router-vpn-device-setup.html").read_text()
    rendered = MOD.reconcile_setup_text(page)
    packed = rendered.split("const DATA=", 1)[1].split(";const $=", 1)[0]
    assert json.loads(packed)["devices"]["ios"]["customApp"] == current
    assert current in fixed, "the generator and legacy-page repair disagree about iOS support"
    for obsolete in (
        "Router VPN is a real native app. Raw WireGuard uses the PacketTunnel engine today; supported Libbox paths are source-wired; unsupported AWG/OpenVPN/full desktop-equivalent multihop combinations stay visibly unavailable instead of being faked.",
        "Router VPN is a real native app. Raw WireGuard uses WireGuardKit; compatible imported sing-box profiles use the pinned Libbox PacketTunnel with exact selected-node proof. AWG/Xray-only, ALL/MAX and unsupported multihop combinations stay visibly unavailable instead of being faked.",
    ):
        legacy = page.replace(current, obsolete)
        assert legacy != page, "fixture did not exercise the generated data"
        repaired = MOD.reconcile_setup_text(legacy)
        packed = repaired.split("const DATA=", 1)[1].split(";const $=", 1)[0]
        assert json.loads(packed)["devices"]["ios"]["customApp"] == current
        assert obsolete not in repaired

panel = MOD.VERIFIED_ONBOARDING_PANEL
for endpoint in (
    "/api/admin/status",
    "/api/admin/clients",
    "/api/admin/forwarding-extension",
    "/api/release-status",
):
    assert endpoint in panel, endpoint
for marker in (
    "Run onboarding again",
    "Complete verified onboarding",
    "Protected DMZ",
    "Owner / client",
    "routervpn.verified-onboarding.v1",
    "stopImmediatePropagation",
):
    assert marker in panel, marker
for lane in lanes:
    assert lane in panel, lane
assert "Authorization" not in panel
assert "setup-center.token" not in panel

# Run both shipping scripts together: denied/corrupt storage must not abort
# verified checks or the later forwarding UI, and Restart resets the live guide.
guide_spec = importlib.util.spec_from_file_location("verified_guide", HERE / "setup_center_guide.py")
guide = importlib.util.module_from_spec(guide_spec)
guide_spec.loader.exec_module(guide)
scripts = [re.search(r"<script[^>]*>(.*?)</script>", value, re.S).group(1)
           for value in (guide.GUIDE_PANEL, panel)]
harness = r'''
const assert=require('node:assert/strict'),vm=require('node:vm');
const scripts=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
async function exercise(raw,denied={},testResponses=false,resumeVerified=false){
 const endpoints={health:'/api/admin/status',admin:'/api/admin/forwarding-extension',release:'/api/release-status',clients:'/api/admin/clients'};
 const responses={
  [endpoints.health]:{ok:true,listeners:null,reserved_ports:null,active_reserved_ports:[],errors:[]},
  [endpoints.admin]:{ok:true,forwarding_master:false,rules:[],protected_dmz:null},
  [endpoints.release]:{ok:true,deployed_sha:'unknown',exact_sha:false,recovery:{safe_sequence:['Record the deployed revision.']}},
  [endpoints.clients]:{ok:true,clients:[],coverage:{sources:['wg']},errors:null}};
 const overrides=new Map(),holds=new Map();
 const nodes=new Map(),timers=[],requests=[],stored=new Map([
  ['routervpn.verified-onboarding.v1',raw],
  ['routervpn.setup-guide.v1','{"step":4,"completed":false}']]);
 const steps=Array.from({length:8},()=>({active:false,classList:{toggle(_,v){this.owner.active=v}}}));
 steps.forEach(s=>s.classList.owner=s);
 function element(id){const value={id,events:{},style:{},dataset:{},open:false,disabled:false,
  addEventListener(name,fn,capture){(this.events[name]??=[]).push({fn,capture:!!capture})},
  querySelector(){return null},querySelectorAll(selector){
   if(this.id==='rvpn-verify-checks'&&selector==='[data-rvpn-check]'){
    return Object.keys(endpoints).map(kind=>{const button=element('verify-'+kind);button.dataset.rvpnCheck=kind;return button});
   }
   return this.id==='rvpn-full-guide'?steps:[];
  },
  appendChild(child){nodes.set(child.id,child)},showModal(){this.open=true},close(){this.open=false},
  click(){let stopped=false,result;const event={preventDefault(){},stopImmediatePropagation(){stopped=true}};
   for(const {fn} of [...(this.events.click??[])].sort((a,b)=>Number(b.capture)-Number(a.capture))){result=fn(event);if(stopped)break}return result}};
  if(id)nodes.set(id,value);return value;
 }
 for(const id of ['rvpn-full-guide','tabs','server-admin','rvpn-verify-checks','rvpn-verify-complete',
  'rvpn-verify-summary','rvpn-forward-owner-list','rvpn-dmz-state',
  ...['open','back','next','close','restart','bar','counter'].map(x=>'rvpn-guide-'+x)])element(id);
 const context={document:{getElementById:id=>nodes.get(id)||null,
  querySelector:selector=>selector==='section[data-tab="server-admin"]'?nodes.get('server-admin'):null,
  createElement:()=>element('')},localStorage:{getItem(key){if(denied.read)throw Error('SecurityError');return stored.get(key)??null},
  setItem(key,value){if(denied.write)throw Error('QuotaExceededError');stored.set(key,value)},
  removeItem(key){if(denied.remove)throw Error('SecurityError');stored.delete(key)}},
  setTimeout(fn){timers.push(fn)},gotoTab(){},fetch:async(path,options)=>{
   assert.equal(options.credentials,'same-origin');requests.push(path);
   const body=overrides.has(path)?overrides.get(path):JSON.stringify(responses[path]);
   const hold=holds.get(path)?.shift();if(hold)await hold();
   return{ok:true,json:async()=>JSON.parse(body)};
  },Date,JSON,Number,Math};context.window=context;vm.createContext(context);
 for(const script of scripts)vm.runInContext(script,context);
 for(const timer of timers)timer();
 assert.ok(nodes.has('rvpn-forwarding-extension-card'),'forwarding UI did not initialize');
 assert.equal(nodes.get('rvpn-verify-complete').disabled,!resumeVerified,'incorrect saved verification state');
 if(!denied.read)assert.equal(steps.findIndex(s=>s.active),4,'verification migration reset Full Guide progress');
 if(resumeVerified){assert.ok(!requests.includes(endpoints.health));return}
 await context.routerVpnRunAllSetupChecks();
 assert.equal(nodes.get('rvpn-verify-complete').disabled,false);
 for(const path of Object.values(endpoints))assert.ok(requests.includes(path));
 if(testResponses){
  const persisted=()=>JSON.parse(stored.get('routervpn.verified-onboarding.v1'));
  const rows=()=>nodes.get('rvpn-verify-checks').innerHTML;
  assert.match(rows(),/deployed revision is unknown/);assert.match(rows(),/Observed 0 peer row/);
  for(const [kind,path] of Object.entries(endpoints)){
   for(const body of ['{bad','null','"ready"','[]','{}','{"ok":false}','{"ok":true}']){
    overrides.set(path,body);await context.routerVpnRunAllSetupChecks();
    assert.equal(persisted().checks[kind],false,kind+' accepted '+body);
    assert.equal(nodes.get('rvpn-verify-complete').disabled,kind!=='clients');
    if(kind!=='clients'){context.routerVpnCompleteVerifiedOnboarding();assert.notEqual(persisted().completed,true)}
   }
   overrides.delete(path);
  }
  for(const [kind,changes] of [
   ['health',{listeners:null,errors:['ss: unavailable']}],['health',{active_reserved_ports:['443']}],
   ['admin',{protected_dmz:{}}],['admin',{forwarding_master:'OFF'}],
   ['release',{exact_sha:true}],['release',{recovery:{}}],
   ['clients',{coverage:{sources:null}}],['clients',{clients:[{}]}]]){
   const path=endpoints[kind];overrides.set(path,JSON.stringify({...responses[path],...changes}));
   await context.routerVpnRunAllSetupChecks();assert.equal(persisted().checks[kind],false,JSON.stringify(changes));
   assert.equal(nodes.get('rvpn-verify-complete').disabled,kind!=='clients');overrides.delete(path);
  }
  Object.assign(responses[endpoints.health],{listeners:[{protocol:'tcp',address:'127.0.0.1:8786',port:8786}],reserved_ports:[8786],active_reserved_ports:[8786]});
  Object.assign(responses[endpoints.admin],{forwarding_master:true,rules:[{id:'rule1'}],protected_dmz:{enabled:true}});
  responses[endpoints.release].deployed_sha='a'.repeat(40);responses[endpoints.release].exact_sha=true;
  responses[endpoints.clients].clients=[{state:'recent-handshake'}];responses[endpoints.clients].errors=['awg: unavailable'];
  await context.routerVpnRunAllSetupChecks();
  assert.equal(nodes.get('rvpn-verify-complete').disabled,false);assert.match(rows(),/deployed revision a{40}/);
  assert.match(rows(),/1\/1 protected port/);assert.match(rows(),/Master ON; 1 explicit rule\(s\); Protected DMZ ON/);
  assert.match(rows(),/1 with a recent handshake/);assert.match(rows(),/Some sources were unavailable/);
 }
 context.routerVpnCompleteVerifiedOnboarding();
 const completedRecord=stored.get('routervpn.verified-onboarding.v1');
 nodes.get('rvpn-guide-next').click();
 assert.ok(steps.findIndex(s=>s.active)>0);
 context.routerVpnRunOnboardingAgain();
 assert.equal(steps.findIndex(s=>s.active),0,'Restart reused the previous in-memory guide step');
 assert.equal(nodes.get('rvpn-full-guide').open,true);
 assert.equal(nodes.get('rvpn-verify-complete').disabled,true);
 if(!denied.read&&!denied.write)assert.equal(JSON.parse(stored.get('routervpn.setup-guide.v1')).completed,false);
 if(testResponses){
  function defer(kind){
   let arrive,finish;
   const started=new Promise(resolve=>arrive=resolve),held=new Promise(resolve=>finish=resolve);
   holds.set(endpoints[kind],[()=>{arrive();return held}]);
   return {started,finish};
  }
  let old=defer('health');
  const oldRun=context.routerVpnRunAllSetupChecks();
  context.routerVpnRunOnboardingAgain();
  const requestCount=requests.length;
  old.finish();await oldRun;
  assert.equal(requests.length,requestCount,'Restart allowed an old check batch to start more requests');
  assert.deepEqual(JSON.parse(stored.get('routervpn.verified-onboarding.v1')).checks,
   {health:false,admin:false,release:false,clients:false},'a response from before Restart restored old checks');
  old=defer('health');
  const olderRun=context.routerVpnRunAllSetupChecks();
  overrides.set(endpoints.health,'{"ok":false,"error":"current health unavailable"}');
  overrides.set(endpoints.admin,'{"ok":false,"error":"current forwarding unavailable"}');
  await context.routerVpnRunAllSetupChecks();
  const latestRequestCount=requests.length;
  overrides.delete(endpoints.health);overrides.delete(endpoints.admin);old.finish();await olderRun;
  assert.equal(requests.length,latestRequestCount,'an older batch resumed after the newer batch completed');
  assert.equal(JSON.parse(stored.get('routervpn.verified-onboarding.v1')).checks.health,false,
   'an older successful response replaced the newer failed health check');
  assert.equal(JSON.parse(stored.get('routervpn.verified-onboarding.v1')).checks.admin,false,
   'an older batch replaced the newer failed forwarding check');
  assert.equal(nodes.get('rvpn-verify-complete').disabled,true);
  const persistedChecks=()=>JSON.parse(stored.get('routervpn.verified-onboarding.v1')).checks;
  const rows=()=>nodes.get('rvpn-verify-checks').innerHTML;
  for(const newerValid of [false,true]){
   if(newerValid)overrides.set(endpoints.health,'null');
   const releaseOld=defer('health'),old=nodes.get('verify-health').click();
   await releaseOld.started;overrides.delete(endpoints.health);
   if(!newerValid)overrides.set(endpoints.health,'null');
   await nodes.get('verify-health').click();overrides.delete(endpoints.health);
   assert.equal(persistedChecks().health,newerValid);
   const latestRows=rows();releaseOld.finish();await old;
   assert.equal(persistedChecks().health,newerValid);assert.equal(rows(),latestRows);
  }
  for(const first of ['batch','individual']){
   for(const staleFailure of [false,true]){
    context.routerVpnRunOnboardingAgain();
    if(staleFailure)overrides.set(endpoints.admin,'{"ok":false,"error":"retired forwarding failure"}');
    const admin=defer('admin');
    const previous=first==='batch'?context.routerVpnRunAllSetupChecks():nodes.get('verify-admin').click();
    await admin.started;
    overrides.delete(endpoints.admin);
    const health=defer('health'),latest=context.routerVpnRunAllSetupChecks();
    await health.started;
    const beforeRows=rows(),beforeRequests=requests.length;
    admin.finish();await previous;
    assert.equal(rows(),beforeRows,'retired '+first+' changed the pending batch display');
    assert.equal(persistedChecks().admin,false,'retired '+first+' verified forwarding for the pending batch');
    assert.equal(requests.length,beforeRequests,'retired '+first+' started another request');
    health.finish();await latest;
    assert.ok(Object.values(persistedChecks()).every(Boolean),'new batch lost a reserved check');
   }
  }
  const lastClient=defer('clients');
  overrides.set(endpoints.clients,'{"ok":false,"error":"retired client failure"}');
  const individual=nodes.get('verify-clients').click();
  await lastClient.started;context.routerVpnRunOnboardingAgain();
  const resetRows=rows();lastClient.finish();await individual;overrides.delete(endpoints.clients);
  assert.equal(rows(),resetRows,'an individual failure survived Restart');
  assert.deepEqual(persistedChecks(),{health:false,admin:false,release:false,clients:false});
  for(const pending of ['health','admin']){
   context.routerVpnRunOnboardingAgain();
   const gate=defer(pending),batch=context.routerVpnRunAllSetupChecks();
   await gate.started;
   overrides.set(endpoints.admin,'{"ok":false,"error":"individual forwarding failure"}');
   await nodes.get('verify-admin').click();overrides.delete(endpoints.admin);
   const adminRequests=requests.filter(path=>path===endpoints.admin).length;
   gate.finish();await batch;
   assert.equal(requests.filter(path=>path===endpoints.admin).length,adminRequests,'old batch reissued the individually retried check');
   assert.deepEqual(persistedChecks(),{health:true,admin:false,release:true,clients:true});
   assert.match(rows(),/individual forwarding failure/);
  }
 }
 return completedRecord;
}
(async()=>{
 for(const raw of [null,'null','[]','42','"saved"','{bad','{"completed":"false","checks":{"health":"true","admin":1,"release":[]}}'])await exercise(raw);
 for(const denied of [{read:true},{write:true},{remove:true},{read:true,write:true,remove:true}])await exercise(null,denied);
 const legacy=JSON.stringify({completed:true,checks:{health:true,admin:true,release:true,clients:true}});
 await exercise(legacy);
 const verified=await exercise(null,{},true);await exercise(verified,{},false,true);
 console.log('Composed verified onboarding: invalid/denied storage, authenticated checks, forwarding initialization and live guide restart PASS');
})().catch(error=>{console.error(error);process.exitCode=1});
'''
result = subprocess.run(["node", "-e", harness], input=json.dumps(scripts), text=True,
                        capture_output=True, timeout=20)
assert result.returncode == 0, result.stdout + result.stderr
assert result.stdout.strip().endswith("live guide restart PASS"), "Deferred onboarding checks did not complete"
print(result.stdout.strip())

try:
    MOD.reconcile_setup_text("<html>changed generator</html>")
except RuntimeError:
    pass
else:
    raise AssertionError("reconciliation must fail closed when the generated start-section seam changes")

print("Verified Setup Center onboarding contract: OK")
