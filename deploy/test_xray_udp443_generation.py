#!/usr/bin/env python3
"""Exercise original Vision-flow generation, preservation and private rebundling.

The shipping shell, preservation reader, bundle writer and atomic transaction
execute unchanged apart from their /src mount relocation. Engine CLI commands
are explicit test doubles; actual encrypted DNS is proved by the native gate.
The generated bundle also passes the real shared Go compiler.
"""
from pathlib import Path
import base64
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'server/scripts'
PLAIN = 'xtls-rprx-vision'
UDP443 = 'xtls-rprx-vision-udp443'
MODES = ('reality-vision', 'reality-pq-vision')
SPEC = importlib.util.spec_from_file_location('vision_preservation', SCRIPTS / 'preserve-generated-state.py')
PRESERVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRESERVE)

ENGINE = r'''
import base64,json,os,pathlib,sys
args=sys.argv[1:]
log=pathlib.Path(os.environ['ROUTERVPN_FLOW_TEST_ENGINE_LOG'])
previous=log.read_text().splitlines() if log.exists() else []
with log.open('a') as f:f.write(json.dumps([pathlib.Path(sys.argv[0]).name,*args])+'\n')
if args[0]=='uuid':
    number=1+sum(json.loads(line)[1:] == ['uuid'] for line in previous)
    print('11111111-1111-4111-8111-'+f'{number:012d}')
elif args[0]=='x25519':
    print('PrivateKey: '+base64.urlsafe_b64encode(bytes([9])*32).decode().rstrip('='))
    print('Password: '+base64.urlsafe_b64encode(bytes([8])*32).decode().rstrip('='))
elif args[0]=='mldsa65':pass
elif args[0]=='vlessenc':
    print('Authentication: ML-KEM-768')
    print('"decryption": "mlkem768x25519plus.native.600s.server-fixture"')
    print('"encryption": "mlkem768x25519plus.native.0rtt.client-fixture"')
elif args[0] in ('run','check'):
    path=pathlib.Path(args[args.index('-c')+1]); value=json.loads(path.read_text())
    if path.name==os.environ.get('ROUTERVPN_FLOW_TEST_FAIL_CONFIG'):sys.exit(7)
    if path.name=='server.json':
        assert all(x['settings']['clients'][0]['flow']=='xtls-rprx-vision' for x in value['inbounds'] if x['tag'] in ('reality-in','pq-reality-in'))
    elif path.name.endswith('xray.json'):
        assert value['outbounds'][0]['settings']['vnext'][0]['users'][0]['flow'] in ('xtls-rprx-vision','xtls-rprx-vision-udp443')
else:raise SystemExit('unowned fixture engine command')
'''

COMPILER = r'''
package main
import("encoding/base64";"encoding/json";"fmt";"os";"router-vpn/internal/applexray")
func main(){
 raw,err:=os.ReadFile(os.Args[1]);if err!=nil{panic(err)}
 var bundle struct{Profiles map[string]map[string]string `json:"profiles"`}
 if json.Unmarshal(raw,&bundle)!=nil{panic("invalid bundle")}
 for i,mode:=range []string{"reality-vision","reality-pq-vision"}{
  files:=bundle.Profiles[mode]; source,e:=base64.StdEncoding.DecodeString(files["xray.json"]);if e!=nil{panic(e)}
  wrapper,e:=base64.StdEncoding.DecodeString(files["sing-box.json"]);if e!=nil{panic(e)}
  graph,e:=applexray.Compile(mode,wrapper,source);if e!=nil{panic(e)}
  value,e:=applexray.Object(graph);if e!=nil{panic(e)}
  out:=value["outbounds"].([]any)[0].(map[string]any)
  if out["mode"]!=mode||out["config_json"]!=string(source){panic("original capture changed")}
  plan,e:=applexray.Prepare(mode,source);if e!=nil{panic(e)}
  native,e:=applexray.Object(plan.JSON);if e!=nil{panic(e)}
  settings:=native["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)
  user:=settings["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
  if user["flow"]!=os.Args[i+2]{panic("original client flow changed")}
 }
 fmt.Println("generated original Vision client assets compiled without changing flow or mode")
}
'''


class VisionGeneration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler_workspace = tempfile.TemporaryDirectory(prefix='.vision-flow-check-', dir=ROOT)
        directory = Path(cls.compiler_workspace.name)
        (directory / 'main.go').write_text(COMPILER)
        cls.compiler = directory / 'compiler'
        try:
            subprocess.run(['go', 'build', '-buildvcs=false', '-o', str(cls.compiler), str(directory / 'main.go')],
                           cwd=ROOT, check=True, timeout=90)
        except BaseException:
            cls.compiler_workspace.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.compiler_workspace.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='routervpn-vision-flow-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = self.root / 'state'
        self.base.mkdir()
        self.bin = self.root / 'bin'; self.bin.mkdir()
        for name in ('xray', 'sing-box'):
            path = self.bin / name
            path.write_text('#!' + sys.executable + '\n' + ENGINE)
            path.chmod(0o755)
        self.log = self.root / 'engine.jsonl'
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'],
                        ROUTERVPN_FLOW_TEST_ENGINE_LOG=str(self.log))
        self.env.pop('REALITY_CLIENT_FLOW', None)
        self.env.pop('ROUTERVPN_FLOW_TEST_FAIL_CONFIG', None)
        self.script = self.root / 'generator.sh'
        self.script.write_text((SCRIPTS / 'generate-xray-pq.sh').read_text().replace('/src/', str(ROOT)+'/'))

    def generate(self, flow=None, extra=None, expected=0):
        env = dict(self.env)
        if flow is not None: env['REALITY_CLIENT_FLOW'] = flow
        if extra: env.update(extra)
        result = subprocess.run(['bash', str(self.script), str(self.base), '192.0.2.1', '10.77.0.1', '10443', 'www.example.com:443', '24443'],
                                env=env, text=True, capture_output=True, timeout=30)
        if expected == 0:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, 'invalid generation succeeded')
        return result

    def path(self, mode):
        return self.base / 'client-bundle/generated' / mode / 'xray.json'

    def read(self, path): return json.loads(path.read_text())

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2)+'\n'); path.chmod(0o600)

    def user(self, value): return value['outbounds'][0]['settings']['vnext'][0]['users'][0]

    def flows(self): return tuple(self.user(self.read(self.path(mode)))['flow'] for mode in MODES)

    def snapshot(self):
        return {str(p.relative_to(self.base)):p.read_bytes() for p in self.base.rglob('*') if p.is_file() and not p.is_symlink()}

    def set_flows(self, standard, pq, saved=True):
        state_path = self.base / 'config/xray/generated-secrets.json'
        state = self.read(state_path)
        for mode, key, flow in zip(MODES, ('standard_client_flow','pq_client_flow'), (standard,pq)):
            value = self.read(self.path(mode)); self.user(value)['flow'] = flow; self.write(self.path(mode), value)
            if saved: state[key] = flow
            else: state.pop(key, None)
        self.write(state_path, state)

    def rebundle(self, expected):
        self.write(self.base/'config/router-agent.json', {'token':'flow-fixture-private-token'})
        wg = self.base/'client-bundle/generated/wg/wg.conf'; wg.parent.mkdir()
        wg.write_text('[Interface]\nPrivateKey = fixture\n[Peer]\nPublicKey = '+base64.b64encode(bytes([31])*32).decode()+'\n'); wg.chmod(0o600)
        for source, target in (('modes.json','modes.json'),('logical-modes.json','logical-modes.json')):
            path=self.base/'client-bundle'/target
            path.write_bytes((ROOT/'configs/client'/source).read_bytes()); path.chmod(0o600)
        before={mode:self.path(mode).read_bytes() for mode in MODES}
        command=[sys.executable,str(SCRIPTS/'create-bundle-json.py'),str(self.base),'192.0.2.1','flow-fixture-private-token','http://10.77.0.1:8787','10.77.0.1','','']
        subprocess.run(command,check=True,capture_output=True,timeout=30)
        bundle_path=self.base/'client-bundle/router-vpn-bundle.json'; bundle=self.read(bundle_path)
        for mode in MODES:
            self.assertEqual(base64.b64decode(bundle['profiles'][mode]['xray.json'],validate=True),before[mode])
            self.assertEqual(self.path(mode).read_bytes(),before[mode])
        self.assertEqual(bundle['logicalModes'],self.read(ROOT/'configs/client/logical-modes.json'))
        self.assertEqual(bundle['modes'],self.read(ROOT/'configs/client/modes.json'))
        subprocess.run([str(self.compiler),str(bundle_path),*expected],check=True,capture_output=True,timeout=15)
        return bundle

    def test_fresh_default_keeps_ordinary_vision(self):
        self.generate(); self.assertEqual(self.flows(),(PLAIN,PLAIN))
        self.rebundle((PLAIN,PLAIN))

    def test_explicit_opt_in_reaches_original_bundle_and_shared_compiler(self):
        self.generate(); server=(self.base/'config/xray/server.json').read_bytes()
        old=PRESERVE.xray(self.base)
        self.generate(UDP443); self.assertEqual(self.flows(),(UDP443,UDP443))
        self.assertEqual((self.base/'config/xray/server.json').read_bytes(),server)
        new=PRESERVE.xray(self.base)
        self.assertEqual({k:v for k,v in old.items() if not k.endswith('CLIENT_FLOW')},
                         {k:v for k,v in new.items() if not k.endswith('CLIENT_FLOW')})
        bundle=self.rebundle((UDP443,UDP443))
        self.assertEqual(bundle['routerProfiles'][0]['dns_mode'],'home')
        self.assertEqual(bundle['routerProfiles'][0]['dns_protocol'],'udp')

    def test_unset_preserves_independent_mixed_saved_choices(self):
        self.generate(); self.set_flows(UDP443,PLAIN)
        before=self.snapshot(); self.generate(); self.assertEqual(self.snapshot(),before)
        PRESERVE.verify_xray_client_flow(self.base,'')
        with self.assertRaises(ValueError):PRESERVE.verify_xray_client_flow(self.base,UDP443)

    def test_legacy_original_flow_is_not_downgraded(self):
        self.generate(); self.set_flows(PLAIN,UDP443,saved=False)
        original={mode:self.path(mode).read_bytes() for mode in MODES}
        self.generate(); self.assertEqual(self.flows(),(PLAIN,UDP443))
        self.assertEqual({mode:self.path(mode).read_bytes() for mode in MODES},original)
        self.rebundle((PLAIN,UDP443))

    def test_explicit_disable_keeps_server_identity(self):
        self.generate(UDP443); server=(self.base/'config/xray/server.json').read_bytes()
        self.generate(PLAIN); self.assertEqual(self.flows(),(PLAIN,PLAIN))
        self.assertEqual((self.base/'config/xray/server.json').read_bytes(),server)
        self.generate(); self.assertEqual(self.flows(),(PLAIN,PLAIN))

    def test_missing_generated_client_recovers_only_saved_flow(self):
        self.generate(UDP443); before=self.snapshot(); self.path(MODES[0]).unlink()
        self.generate(); self.assertEqual(self.snapshot(),before)

    def test_invalid_request_never_changes_authoritative_files(self):
        self.generate(); before=self.snapshot()
        for value in ('on','true','xtls-rprx-vision-udp','xtls-rprx-vision-udp443 ','xtls-rprx-direct','\n'+UDP443):
            with self.subTest(value=value):
                self.generate(value,expected=1); self.assertEqual(self.snapshot(),before)

    def test_malformed_or_inconsistent_originals_fail_before_adoption(self):
        self.generate(); client=self.read(self.path(MODES[0])); state_path=self.base/'config/xray/generated-secrets.json'; state=self.read(state_path)
        for kind in ('foreign-flow','missing-flow','boolean-flow','foreign-id','ambiguous-user','empty-object','stored-foreign','stored-null','stored-disagrees','duplicate-flow'):
            with self.subTest(kind=kind):
                self.write(self.path(MODES[0]),client); self.write(state_path,state)
                value=self.read(self.path(MODES[0])); saved=dict(state)
                if kind=='foreign-flow':self.user(value)['flow']='foreign'
                elif kind=='missing-flow':del self.user(value)['flow']
                elif kind=='boolean-flow':self.user(value)['flow']=True
                elif kind=='foreign-id':self.user(value)['id']='22222222-2222-4222-8222-222222222222'
                elif kind=='ambiguous-user':value['outbounds'][0]['settings']['vnext'][0]['users'].append(dict(self.user(value)))
                elif kind=='empty-object':value={}
                elif kind=='stored-foreign':saved['standard_client_flow']='foreign'
                elif kind=='stored-null':saved['standard_client_flow']=None
                elif kind=='stored-disagrees':saved['standard_client_flow']=UDP443
                self.write(self.path(MODES[0]),value); self.write(state_path,saved)
                if kind=='duplicate-flow':
                    path=self.path(MODES[0]); path.write_text(path.read_text().replace('"flow": "'+PLAIN+'"','"flow": "'+PLAIN+'", "flow": "'+UDP443+'"'))
                before=self.snapshot(); self.generate(UDP443,expected=1); self.assertEqual(self.snapshot(),before)

    def test_original_client_private_file_guards_remain_required(self):
        self.generate(); path=self.path(MODES[0]); original=path.read_bytes()
        path.chmod(0o644); before=self.snapshot(); self.generate(UDP443,expected=1); self.assertEqual(self.snapshot(),before)
        path.chmod(0o600); path.unlink(); target=self.root/'foreign-client.json'; target.write_bytes(original); target.chmod(0o600); path.symlink_to(target)
        self.generate(UDP443,expected=1); self.assertTrue(path.is_symlink()); self.assertEqual(target.read_bytes(),original)

    def test_candidate_engine_failure_keeps_previous_generation(self):
        self.generate(); before=self.snapshot()
        self.generate(UDP443,{'ROUTERVPN_FLOW_TEST_FAIL_CONFIG':'pq-xray.json'},expected=1)
        self.assertEqual(self.snapshot(),before)
        self.assertFalse(list((self.base/'config/xray').glob('.generate.*')))

    def test_atomic_adoption_failure_rolls_back_client_flow_and_state(self):
        self.generate(); before=self.snapshot(); wrapper=self.root/'fail-batch.py'; witness=self.root/'adoption-witness'
        wrapper.write_text('import json,os,pathlib,runpy,sys\n'+f'm=runpy.run_path({str(SCRIPTS / "atomic-private-batch.py")!r})\n'+
            'original=os.replace\nfailed=False\ndef replace(a,b):\n global failed\n if not failed and str(b).endswith("reality-pq-vision/xray.json"):\n  failed=True\n  adopted=json.loads((pathlib.Path(b).parent.parent/"reality-vision/xray.json").read_text())\n  assert adopted["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"]=="xtls-rprx-vision-udp443"\n'+
            f'  pathlib.Path({str(witness)!r}).write_text("adopted-original-client-before-rollback")\n'+
            '  raise OSError("injected owned adoption failure")\n return original(a,b)\nos.replace=replace\nraise SystemExit(m["main"](sys.argv))\n')
        text=self.script.read_text(); old='PRIVATE_BATCH='+str(SCRIPTS/'atomic-private-batch.py')
        self.assertEqual(text.count(old),1); self.script.write_text(text.replace(old,'PRIVATE_BATCH='+str(wrapper)))
        result=self.generate(UDP443,expected=1)
        self.assertIn('injected owned adoption failure',result.stderr)
        self.assertEqual(witness.read_text(),'adopted-original-client-before-rollback')
        self.assertEqual(self.snapshot(),before)

    def test_actual_entrypoints_reject_invalid_request_or_saved_flow_before_writes(self):
        self.generate()
        names=('server/init/noninteractive.sh','server/finalize/finalize.sh','server/finalize/upgrade-safe.sh','server/finalize/ensure-profile-engines.sh')
        for invalid_state in (False,True):
            if invalid_state:
                value=self.read(self.path(MODES[0])); self.user(value)['flow']='foreign'; self.write(self.path(MODES[0]),value)
            before=self.snapshot()
            for name in names:
                with self.subTest(name=name,invalid_state=invalid_state):
                    script=self.root/(Path(name).name+'.entrypoint')
                    text=(ROOT/name).read_text().replace('/src/',str(ROOT)+'/').replace('BASE=/opt/router-vpn','BASE='+str(self.base))
                    script.write_text(text)
                    env=dict(self.env,BASE=str(self.base),REALITY_CLIENT_FLOW=UDP443 if invalid_state else 'foreign')
                    result=subprocess.run(['bash',str(script),str(self.base)],env=env,text=True,capture_output=True,timeout=15)
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn('preserved state unavailable' if invalid_state else 'Invalid REALITY_CLIENT_FLOW',result.stderr)
                    self.assertEqual(self.snapshot(),before)

    def test_readiness_checks_requested_flow_without_rewriting_sources(self):
        self.generate(); before=self.snapshot()
        command=[sys.executable,str(SCRIPTS/'preserve-generated-state.py'),'verify-xray-client-flow',str(self.base)]
        for value,status in (('',0),(PLAIN,0),(UDP443,1),('foreign',1)):
            result=subprocess.run(command+[value],capture_output=True,timeout=15)
            self.assertEqual(result.returncode,status); self.assertEqual(self.snapshot(),before)
        source=(ROOT/'server/finalize/ensure-profile-engines.sh').read_text()
        body=source.split('core_ready(){',1)[1].split('\n}',1)[0]
        self.assertIn('preserve-generated-state.py verify-xray-client-flow "$BASE" "$REALITY_CLIENT_FLOW" || return 1',body)


if __name__ == '__main__':
    unittest.main()
