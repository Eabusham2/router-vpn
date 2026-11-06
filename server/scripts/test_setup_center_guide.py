#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("setup_center_guide_test", HERE / "setup_center_guide.py")
mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class SetupCenterGuideTests(unittest.TestCase):
    def setUp(self):
        self.guide = mod.GUIDE_PANEL

    def test_actual_guide_lifecycle_with_unavailable_or_invalid_browser_storage(self):
        script = self.guide.split("<script>", 1)[1].split("</script>", 1)[0]
        harness = r'''
const assert = require('node:assert/strict');
const vm = require('node:vm');
const source = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
function boot(raw, {readDenied=false, writeDenied=false}={}) {
 const nodes=new Map(), timers=[], writes=[];
 const steps=Array.from({length:9},()=>({active:false,classList:{toggle(_name,on){this.owner.active=on}}}));
 for(const step of steps)step.classList.owner=step;
 const node=id=>{
  if(!nodes.has(id))nodes.set(id,{open:false,style:{},events:{},textContent:'',
   addEventListener(name,fn){this.events[name]=fn},
   querySelectorAll(){return steps},showModal(){this.open=true},close(){this.open=false}});
  return nodes.get(id);
 };
 const storage={getItem(){if(readDenied)throw new Error('SecurityError');return raw},
  setItem(key,value){if(writeDenied)throw new Error('QuotaExceededError');writes.push([key,value]);raw=value}};
 vm.runInNewContext(source,{document:{getElementById:node},localStorage:storage,
  setTimeout(fn){timers.push(fn)},Date,JSON,Number,Math});
 for(const fn of timers)fn();
 return {node,steps,writes,timers,stored:()=>raw,
  click(name){node('rvpn-guide-'+name).events.click()},
  step(){return steps.findIndex(s=>s.active)}};
}
for(const raw of [null,'null','[]','0','true','"saved"','{bad',
 '{"step":3,"completed":"false"}','{"step":-3}', '{"step":1.5}']) {
 const ui=boot(raw);
 assert.equal(ui.node('rvpn-full-guide').open,true,'first-run guide failed for '+raw);
 assert.equal(ui.step(),raw==='{"step":3,"completed":"false"}'?3:0);
 ui.click('next');ui.click('close');assert.equal(ui.node('rvpn-full-guide').open,false);
 ui.click('open');assert.equal(ui.node('rvpn-full-guide').open,true);
}
for(const options of [{readDenied:true},{writeDenied:true},{readDenied:true,writeDenied:true}]) {
 const ui=boot(null,options);
 assert.equal(ui.node('rvpn-full-guide').open,true);
 assert.match(ui.node('rvpn-guide-counter').textContent,/this visit/);
 assert.doesNotMatch(ui.node('rvpn-guide-counter').textContent,/saved on this browser/);
 ui.click('next');assert.equal(ui.step(),1);
 let prevented=false;
 ui.node('rvpn-full-guide').events.cancel({preventDefault(){prevented=true}});
 assert.equal(prevented,true);assert.equal(ui.node('rvpn-full-guide').open,false);
 ui.click('open');assert.equal(ui.step(),1);ui.click('back');assert.equal(ui.step(),0);
 for(let i=0;i<9;i++)ui.click('next');
 assert.equal(ui.node('rvpn-full-guide').open,false);
 ui.click('open');ui.click('restart');assert.equal(ui.step(),0);
 assert.equal(ui.node('rvpn-full-guide').open,true);
}
const resumed=boot('{"step":4,"completed":false}');
assert.equal(resumed.step(),4);assert.match(resumed.node('rvpn-guide-counter').textContent,/saved on this browser/);
resumed.click('next');resumed.click('close');
assert.equal(boot(resumed.stored()).step(),5);
const done=boot('{"step":8,"completed":false}');done.click('next');
assert.equal(JSON.parse(done.stored()).completed,true);
const later=boot(done.stored());assert.equal(later.timers.length,0);
later.click('open');assert.equal(later.node('rvpn-full-guide').open,true);
later.click('restart');assert.equal(JSON.parse(later.stored()).completed,false);
assert.equal(later.step(),0);assert.equal(boot(later.stored()).node('rvpn-full-guide').open,true);
assert.equal(boot('{"step":999,"completed":false}').step(),8);
console.log('Actual Full Guide storage, resume, close, finish and restart lifecycle passed');
'''
        result = subprocess.run(["node", "-e", harness], input=json.dumps(script), text=True,
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_first_run_persistence_completion_resume_and_independent_access(self):
        for marker in (
            'id="rvpn-guide-open"',
            'id="rvpn-full-guide"',
            "routervpn.setup-guide.v1",
            "localStorage.getItem(KEY)",
            "localStorage.setItem(KEY",
            "if(!state.completed)setTimeout(show,250)",
            "Close & resume later",
            "Restart guide",
            "Finish setup guide",
            "state.completed=true",
        ):
            self.assertIn(marker, self.guide)

    def test_zero_knowledge_install_from_zero_and_linking_is_separate_data_operation(self):
        for marker in (
            "What gets installed — and what does not",
            "Installing an app does not link it to your home",
            "install the app once and can add more routers without reinstalling",
            "Deploy the home node from zero",
            "Exact-SHA production compose",
            "RouterVPN-Portainer-RELEASE_SHA.yaml",
            "server/portainer-current.yaml",
            "template/baseline",
            "ASUS router forwarding",
            "Link after install",
            "one-time LAN pairing",
            "router-vpn-bundle.json",
        ):
            self.assertIn(marker, self.guide)
        self.assertNotIn("Create a stack from the Router VPN repository using <code>server/portainer-current.yaml</code>", self.guide)

    def test_method_hierarchy_is_explicit_and_capability_honest(self):
        ordered = [
            "1 — Simple / native method",
            "2 — Router VPN app",
            "3 — Universal third-party",
            "4 — Manual / custom",
        ]
        positions = [self.guide.index(x) for x in ordered]
        self.assertEqual(positions, sorted(positions))
        for marker in (
            "Use only when the generated format is verified with the named external app",
            "Unavailable or unproven lanes must stay grey/unavailable",
            "Manual Connect still requires health proof and rollback on failure",
        ):
            self.assertIn(marker, self.guide)

    def test_guide_covers_daily_connection_dns_lan_killswitch_multihop_forwarding_and_recovery(self):
        for marker in (
            "AUTO",
            "SMART AUTO",
            "WireGuard/AmneziaWG",
            "Home AdGuard",
            "fastest measured home-exit public DNS",
            "home-LAN access",
            "MTU/Jumbo",
            "kill-switch policy",
            "multihop",
            "Connected Clients",
            "public-exit proof",
            "Emergency Stop/rollback",
            "boot/always, connected, reconnecting, manual disconnect and failure states",
        ):
            self.assertIn(marker, self.guide)

    def test_safety_and_distribution_guidance_are_explicit(self):
        for marker in (
            "Never WAN-expose Setup Center/control 8786–8793",
            "private DAITA-like UDP 45999",
            "SOCKS5 1080",
            "loopback OverTLS 14444",
            "Direct public IP works",
            "DDNS is optional",
            "Open Anyway",
            "Never globally disable Gatekeeper",
            "Signed/notarized distribution remains the long-term target",
        ):
            self.assertIn(marker, self.guide)


if __name__ == "__main__":
    unittest.main()
