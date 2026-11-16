#!/usr/bin/env python3
"""Strict typed SOCKS installed receipt and original namespace-source controls."""
from pathlib import Path
import importlib.util,inspect,json,os,re,subprocess,tempfile,unittest,hashlib
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('linux_socks_gate',ROOT/'deploy/test_linux_socks_execution_host.py')
GATE=importlib.util.module_from_spec(spec);spec.loader.exec_module(GATE)

def output(case):
 root=GATE.TEST
 counters=dict(case=case,launches=1,restore_launches=int(case in GATE.CASES[:6] and not case.endswith('auto-local')),comparison_trials=2 if '-auto-'in case else 0,entry_raw_udp=1,entry_tcp=1,entry_proofs=1,
  middle_raw_tcp=1,middle_tcp=1,middle_public=1,final_raw_tcp=1,final_tcp=1,final_proofs=1,dns=1,middle_raw_udp=1,final_raw_udp=1,middle_udp=1,final_udp=1,
  auth_refusals=0,rejected_replies=0,negotiated_relays=1,open_associations=0,entry_layer=GATE.ENTRY_LAYERS[case],entry_layer_packets=int(GATE.ENTRY_LAYERS[case]!='off'),entry_layer_ciphertext=int(GATE.ENTRY_LAYERS[case]!='off'),entry_layer_auth=0)
 if case=='socks-wrong-auth':
  for key in ('middle_tcp','middle_public','middle_raw_udp','middle_udp','final_raw_tcp','final_raw_udp','final_tcp','final_udp','final_proofs','dns','negotiated_relays'):counters[key]=0
  counters['auth_refusals']=1
 elif case in ('socks-auth-downgrade','socks-relay-domain'):
  for key in ('middle_tcp','middle_public','middle_raw_udp','middle_udp','final_raw_tcp','final_raw_udp','final_tcp','final_udp','final_proofs','dns','negotiated_relays'):counters[key]=0
  counters['rejected_replies']=1
 elif case in ('socks-relay-route','socks-control-eof'):
  for key in ('middle_udp','final_raw_udp','final_udp','dns'):counters[key]=0
  counters['middle_raw_udp']=int(case=='socks-control-eof')
 elif case=='socks-wrong-public':
  for key in ('final_raw_tcp','final_raw_udp','final_tcp','final_udp','final_proofs','dns'):counters[key]=0
 elif case=='socks-wrong-final':
  for key in ('final_tcp','final_udp','final_proofs','dns'):counters[key]=0
 return '\n'.join(('=== RUN   '+root,'=== RUN   '+root+'/'+case,
  '    desktop_socks_execution_linux_tun_native_test.go:510: LINUX_SOCKS_EXECUTION_COUNTERS '+json.dumps(counters),
  '    desktop_socks_execution_linux_tun_native_test.go:511: '+GATE.receipt(case),
  '--- PASS: '+root+' (1.00s)','    --- PASS: '+root+'/'+case+' (1.00s)','PASS',*(f'Linux guardian namespace phase: {phase} (pid=1, monotonic=123.456)'for phase in GATE.NAMESPACE_RETIREMENT_PHASES),''))

ENDPOINT_TESTS = 'package routervpnamnezia\nimport("errors";"net";"net/netip";"testing")\nvar fixtureIndex=7\nvar fixtureName="rvpn-peer"\nvar fixtureFlags=net.FlagUp\nvar fixtureAddresses=[]string{"192.168.210.2/30","fd50::2/64"}\nvar fixtureNamespace="net:[456]"\nvar fixtureFailure error\nfunc fixtureInterface(name string)(*net.Interface,error){if name!="rvpn-peer"{return nil,errors.New("foreign interface query")};return &net.Interface{Index:fixtureIndex,Name:fixtureName,Flags:fixtureFlags},fixtureFailure}\nfunc fixtureAddrs(original *net.Interface)([]net.Addr,error){if original.Index!=fixtureIndex{return nil,errors.New("foreign original interface")};var result []net.Addr;for _,value:=range fixtureAddresses{ip,network,err:=net.ParseCIDR(value);if err!=nil{return nil,err};network.IP=ip;result=append(result,network)};return result,fixtureFailure}\nfunc fixtureReadlink(path string)(string,error){if path!="/proc/self/ns/net"{return "",errors.New("foreign namespace query")};return fixtureNamespace,fixtureFailure}\nfunc TestOriginalPhysicalPeer(t *testing.T){\n cases:=[]string{"original","purpose","flag","swapped","same-host","parent-namespace","missing-parent","index","name","down","address","mask","duplicate","read-error"}\n for _,name:=range cases{t.Run(name,func(t *testing.T){\n  t.Setenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS","1");t.Setenv("ROUTERVPN_SOCKS_EXECUTION_REFERENCE","1");t.Setenv("ROUTERVPN_SOCKS_EXECUTION_PARENT_NETNS","net:[123]")\n  fixtureIndex=7;fixtureName="rvpn-peer";fixtureFlags=net.FlagUp;fixtureAddresses=[]string{"192.168.210.2/30","fd50::2/64"};fixtureNamespace="net:[456]";fixtureFailure=nil\n  local,remote:=netip.MustParseAddr("192.168.210.2"),netip.MustParseAddr("192.168.210.1")\n  switch name{case"purpose":t.Setenv("ROUTERVPN_SOCKS_EXECUTION_REFERENCE","");case"flag":t.Setenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS","");case"swapped":local,remote=remote,local;case"same-host":remote=local;case"parent-namespace":fixtureNamespace="net:[123]";case"missing-parent":t.Setenv("ROUTERVPN_SOCKS_EXECUTION_PARENT_NETNS","");case"index":fixtureIndex=0;case"name":fixtureName="foreign";case"down":fixtureFlags=0;case"address":fixtureAddresses=[]string{"192.168.211.2/30"};case"mask":fixtureAddresses=[]string{"192.168.210.2/29"};case"duplicate":fixtureAddresses=[]string{"192.168.210.2/30","192.168.210.2/30"};case"read-error":fixtureFailure=errors.New("original read refused")}\n  err:=socksExecutionPhysicalPeer(local,remote)\n  if name=="original"{if err!=nil{t.Fatal("original distinct Linux physical peer refused",err)}}else if err==nil{t.Fatal("foreign physical peer accepted",name)}\n })}\n}\n'

def require_endpoint_control(output,returncode,name,witness):
 wanted={'TestOriginalPhysicalPeer','TestOriginalPhysicalPeer/'+witness}
 if name=='same-host-only':wanted.add('TestOriginalPhysicalPeer/same-host')
 actual=re.findall(r'^\s*--- FAIL: (\S+) \([0-9.]+s\)$',output,re.M)
 if returncode!=1 or not output.endswith('FAIL\n') or len(actual)!=len(wanted) or set(actual)!=wanted or ('foreign physical peer accepted'not in output and 'original distinct Linux physical peer refused'not in output) or re.search(r'panic:|fatal|signal|SIG[A-Z0-9]+|DATA RACE|--- SKIP:|build failed|build aborted|link:|compiler',output,re.I):
  raise ValueError('SOCKS endpoint causal result lost its normal exact assertion: '+name+'\n'+output)

def execute_endpoint_controls(go,environment):
 source=ROOT/'mobile/desktop/node_chain_socks_execution_peer_linux_test.go.tmpl'
 original=source.read_text();marker='func socksExecutionPhysicalPeer('
 if original.count(marker)!=1:raise ValueError('Original SOCKS physical helper moved')
 adapter='package routervpnamnezia\nimport("errors";"net";"net/netip";"os";"regexp")\n'+original[original.index(marker):]
 for before,after in (('net.InterfaceByName("rvpn-peer")','fixtureInterface("rvpn-peer")'),('original.Addrs()','fixtureAddrs(original)'),('os.Readlink("/proc/self/ns/net")','fixtureReadlink("/proc/self/ns/net")')):
  if adapter.count(before)!=1:raise ValueError('Original SOCKS OS observation moved')
  adapter=adapter.replace(before,after,1)
 controls={
  'original':(adapter,None),
  'same-host-only':(adapter.replace('local != netip.MustParseAddr("192.168.210.2") || remote != netip.MustParseAddr("192.168.210.1")','local != remote',1),'original'),
  'namespace-omitted':(adapter.replace(' || current == parent',' || current == ""',1),'parent-namespace'),
  'purpose-omitted':(adapter.replace(' || os.Getenv("ROUTERVPN_SOCKS_EXECUTION_REFERENCE") != "1"','',1),'purpose'),
  'interface-name-omitted':(adapter.replace('original.Name != "rvpn-peer" || ','',1),'name'),
  'prefix-mask-omitted':(adapter.replace('prefix.Bits() != 30 || ','',1),'mask'),
 }
 receipts={}
 with tempfile.TemporaryDirectory(prefix='linux-socks-endpoint-')as temporary:
  work=Path(temporary);(work/'go.mod').write_text('module fixture\n\ngo 1.25\n');(work/'owner_test.go').write_text(ENDPOINT_TESTS)
  for name,(body,witness)in controls.items():
   if name!='original'and body==adapter:raise ValueError('SOCKS endpoint causal anchor unchanged: '+name)
   (work/'owner.go').write_text(body);image=work/(name+'.test')
   built=subprocess.run([str(go),'test','-race','-c','-p=1','-o',str(image),'.'],cwd=work,env=environment,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
   if built.returncode:raise ValueError('Original SOCKS endpoint helper did not compile: '+built.stdout[-4096:])
   ran=subprocess.run([str(image),'-test.v','-test.count=1','-test.timeout=20s'],cwd=work,env=environment,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
   if witness is None:
    expected=('TestOriginalPhysicalPeer',*('TestOriginalPhysicalPeer/'+case for case in ('original','purpose','flag','swapped','same-host','parent-namespace','missing-parent','index','name','down','address','mask','duplicate','read-error')))
    if ran.returncode:raise ValueError('Original SOCKS endpoint failed: '+ran.stdout)
    GATE.NODE.require_native_verdicts(ran.stdout,expected,'original SOCKS endpoint with explicit OS observations')
   else:
    require_endpoint_control(ran.stdout,ran.returncode,name,witness)
   print(ran.stdout,end='',flush=True)
   receipts[name]={'exit_code':ran.returncode,'source_sha256':hashlib.sha256(body.encode()).hexdigest(),'image_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'output_sha256':hashlib.sha256(ran.stdout.encode()).hexdigest()}
 if source.read_text()!=original:raise ValueError('Original SOCKS endpoint source changed')
 return {'boundary':'actual original physical-purpose checks; OS interface/netns observations are explicit component doubles, not kernel acceptance','attempts':receipts}

class LinuxSOCKSExecutionGate(unittest.TestCase):
 def test_exact_inventory(self):
  self.assertEqual(GATE.case_inventory(),GATE.CASES);self.assertEqual(len(GATE.CASES),16)
  self.assertEqual(sum(len(v)+1 for v in GATE.SOURCE_TESTS.values()),10)
 def test_all_native_receipts(self):
  for case in GATE.CASES:GATE.check_verdict(output(case),case)
 def test_package_verdict_and_original_namespace_retirement_are_required(self):
  case=GATE.CASES[0];original=output(case);before,tail=original.split('\nPASS\n',1)
  for changed in (before+'\n'+tail,before+'\nPASS\nPASS\n'+tail,before+'\nPASS\n',original+'PASS\n',original.replace('test status 0','test status 1'),original.replace('pid=1','pid=foreign'),original.replace('monotonic=123.456','monotonic=nan'),before+'\nPASS\n'+'\n'.join(reversed(tail.splitlines()))+'\n',*(before+'\nPASS\n'+'\n'.join(tail.splitlines()[:i]+tail.splitlines()[i+1:])+'\n'for i in range(4))):
   with self.subTest(output=changed),self.assertRaises(ValueError):GATE.check_verdict(changed,case)
 def test_missing_duplicate_and_foreign_receipts(self):
  for case in GATE.CASES:
   text=output(case);lines=text.splitlines()
   for index,line in enumerate(lines):
    if 'LINUX_SOCKS_EXECUTION_' in line or line.startswith('=== RUN') or '--- PASS:' in line:
     with self.subTest(case=case,line=index),self.assertRaises(ValueError):GATE.check_verdict('\n'.join(lines[:index]+lines[index+1:]),case)
   with self.assertRaises(ValueError):GATE.check_verdict(text+text,case)
   with self.assertRaises(ValueError):GATE.check_verdict(text.replace('case='+case,'case=foreign'),case)
 def test_fail_skip_race_not_success(self):
  for marker in ('--- FAIL: x (0.01s)','--- SKIP: x (0.01s)','WARNING: DATA RACE','panic: failed'):
   with self.subTest(marker=marker),self.assertRaises(ValueError):GATE.check_verdict(output(GATE.CASES[0])+marker+'\n',GATE.CASES[0])
 def test_each_counter_required(self):
  case=GATE.CASES[0];text=output(case)
  prefix='LINUX_SOCKS_EXECUTION_COUNTERS '
  line=next(x for x in text.splitlines() if prefix in x);record=json.loads(line.split(prefix)[1])
  for key in record:
   changed=dict(record);del changed[key]
   with self.subTest(key=key),self.assertRaises(ValueError):GATE.check_verdict(text.replace(line,line.split(prefix)[0]+prefix+json.dumps(changed)),case)
 def test_rerank_and_fresh_worker_required(self):
  for case in GATE.CASES[:6]:
   text=output(case)
   for key in ('restore_launches','comparison_trials'):
    prefix='LINUX_SOCKS_EXECUTION_COUNTERS ';line=next(x for x in text.splitlines() if prefix in x);record=json.loads(line.split(prefix)[1]);record[key]+=1
    with self.subTest(case=case,key=key),self.assertRaises(ValueError):GATE.check_verdict(text.replace(line,line.split(prefix)[0]+prefix+json.dumps(record)),case)
 def test_actual_encrypted_and_dns_required(self):
  text=output(GATE.CASES[0]);prefix='LINUX_SOCKS_EXECUTION_COUNTERS ';line=next(x for x in text.splitlines() if prefix in x)
  for key in ('launches','entry_raw_udp','entry_tcp','entry_proofs','middle_raw_tcp','middle_tcp','middle_public','final_raw_tcp','final_tcp','final_proofs','dns','middle_raw_udp','middle_udp','final_raw_udp','final_udp','negotiated_relays'):
   record=json.loads(line.split(prefix)[1]);record[key]=0
   with self.subTest(key=key),self.assertRaises(ValueError):GATE.check_verdict(text.replace(line,line.split(prefix)[0]+prefix+json.dumps(record)),GATE.CASES[0])
 def test_negotiated_association_and_negative_boundaries_cannot_be_substituted(self):
  faults=(('socks-wg-server','open_associations',1),('socks-wg-server','middle_raw_udp',0),('socks-wrong-auth','auth_refusals',0),('socks-auth-downgrade','rejected_replies',0),('socks-relay-domain','middle_raw_udp',1),('socks-relay-route','middle_raw_udp',1),('socks-control-eof','middle_raw_udp',0),('socks-wrong-final','final_proofs',1))
  for case,key,value in faults:
   text=output(case);prefix='LINUX_SOCKS_EXECUTION_COUNTERS ';line=next(x for x in text.splitlines()if prefix in x);record=json.loads(line.split(prefix)[1]);record[key]=value
   with self.subTest(case=case,key=key),self.assertRaises(ValueError):GATE.check_verdict(text.replace(line,line.split(prefix)[0]+prefix+json.dumps(record)),case)
 def test_original_host_optin(self):
  with patch.object(GATE.platform,'system',return_value='Linux'),patch.object(GATE.platform,'machine',return_value='x86_64'):
   self.assertEqual(GATE.required_host({GATE.FLAG:'1'}),'linux/amd64')
   for env in ({},{GATE.FLAG:'0'},{GATE.FLAG:'1','HOMEVPN_MTU_BENCH_FAKE':''},{GATE.FLAG:'1','GOOS':'darwin'},{GATE.FLAG:'1','CGO_ENABLED':'0'}):
    with self.assertRaises(ValueError):GATE.required_host(env)
 def test_original_linux_compiler_rejects_foreign_host_and_uses_pinned_capture(self):
  environment={'GOFLAGS':'foreign-overlay','GOWORK':'foreign-work'}
  for arch in ('amd64','arm64'):
   captured={'GOOS':'linux','GOARCH':arch,'GOTOOLCHAIN':'local','GOWORK':'off','GOFLAGS':''}
   compiler=Path('/captured/go/bin/go')
   with patch.object(GATE.NODE,'selected_compiler',return_value=(compiler,captured,arch)) as select:
    actual,env=GATE.selected_compiler('go',environment,'linux/'+arch)
   select.assert_called_once_with('go',GATE.ROOT,environment)
   self.assertEqual(actual,compiler);self.assertEqual(env['CGO_ENABLED'],'1')
   for target,values in (('linux/foreign',captured),('linux/'+arch,dict(captured,GOOS='darwin')),('linux/'+arch,dict(captured,GOARCH='foreign'))):
    with patch.object(GATE.NODE,'selected_compiler',return_value=(compiler,values,arch)),self.assertRaises(ValueError):GATE.selected_compiler('go',environment,target)
  source=inspect.getsource(GATE.execute)
  self.assertIn('selected_compiler(go,environment,target)',source)
  self.assertNotIn('.RACE',source)
  self.assertIn("validation_toolchain=BUILD.TOOLCHAIN",source)
  self.assertIn("version.stdout.strip()!=str(image)+': '+BUILD.TOOLCHAIN",source)
 def test_namespace_exact_case_and_images(self):
  with self.assertRaises(ValueError):GATE.namespace_test(Path('/x'),Path('/y'),Path('/z'),'a'*64,'b'*64,'c'*64,'foreign')
  with patch.object(GATE.CHILD,'image_identity',return_value=(1,2,3,4,'d'*64)):
   with self.assertRaises(ValueError):GATE.namespace_test(Path('/x'),Path('/y'),Path('/z'),'a'*64,'b'*64,'c'*64,GATE.CASES[0])
 def test_original_and_new_namespace_budgets(self):
  with patch.object(GATE.GUARD.subprocess,'run') as run:
   for case in GATE.CASES:
    GATE.GUARD.namespace_test_execution('/image','selector','SOCKSExecution/'+case,{})
    self.assertIn('-test.timeout=240s',run.call_args.args[0]);self.assertEqual(run.call_args.kwargs['timeout'],250)
   for case in ('NodeHostTUN/node-chain-3-connect','SOCKSExecution/foreign','SOCKSExecution/socks-wg-server-extra'):
    GATE.GUARD.namespace_test_execution('/image','selector',case,{})
    self.assertIn('-test.timeout=120s',run.call_args.args[0]);self.assertEqual(run.call_args.kwargs['timeout'],135)
   GATE.GUARD.namespace_test_execution('/image','selector','NodeHostTUN/node-chain-connect-https-wg-eight-connect',{})
   self.assertIn('-test.timeout=250s',run.call_args.args[0]);self.assertEqual(run.call_args.kwargs['timeout'],265)
 def test_original_provider_and_platform_registration(self):
  self.assertEqual(len(GATE.peer_inventory()),14)
  prep=GATE.load('prepare-desktop-external')
  with tempfile.TemporaryDirectory() as directory:
   prep.copy_encrypted_peer_templates(Path(directory))
   for source,target in {GATE.PEER_TEMPLATE:GATE.PEER_TARGET,**GATE.PEER_HELPERS}.items():
    self.assertEqual((Path(directory)/target).read_bytes(),(ROOT/source).read_bytes())
 def test_native_owner_source_checks_remain(self):
  source=(ROOT/'cmd/client/desktop_socks_execution_linux_tun_native_test.go').read_text()
  for anchor in ('h.transaction.execution != s.execution','h.transaction.baseline == nil','h.socksChain != original','linuxHostTUNNamespace(t)','linuxHostTUNInstallBundle(t)','a.nativeMultihopConnect(w, r)','s.Current(ctx)','h.readReadyLocked(ctx, false)'):
   self.assertIn(anchor,source)
  dispatch=(ROOT/'cmd/client/desktop_node_host_linux_tun_native_test.go').read_text()
  self.assertIn('if _, captured := linuxSOCKSExecutionScenarios[scenario]; captured {',dispatch)
  self.assertIn('return linuxHostTUNNodeChainFixture(controller, scenario)',dispatch)
 def test_causal_endpoint_requires_normal_failure_without_abort(self):
  original='    owner_test.go:1: foreign physical peer accepted purpose\n--- FAIL: TestOriginalPhysicalPeer (0.01s)\n    --- FAIL: TestOriginalPhysicalPeer/purpose (0.01s)\nFAIL\n'
  require_endpoint_control(original,1,'purpose-omitted','purpose')
  for text,code in ((original,0),(original,2),(original,-9),(original[:-5],1),(original+original,1),*((original.replace('FAIL\n',marker+'\nFAIL\n'),1)for marker in ('panic: test timed out','fatal error: runtime failure','signal: killed','SIGSEGV','WARNING: DATA RACE','build aborted','link: failed'))):
   with self.subTest(code=code,text=text),self.assertRaises(ValueError):require_endpoint_control(text,code,'purpose-omitted','purpose')
 def test_actual_typed_suffix_admission_component_is_required(self):
  self.assertEqual(len(GATE.PEER_COMPONENT_NAMES),16)
  self.assertEqual(len(set(GATE.PEER_COMPONENT_NAMES)),16)
  source=inspect.getsource(GATE.execute)
  self.assertIn("'-test.run=^'+PEER_COMPONENT_ROOT+'$'",source)
  self.assertIn('NODE.require_native_verdicts(peer_component.stdout,PEER_COMPONENT_NAMES',source)
  helper=(ROOT/'mobile/desktop/node_chain_socks_execution_peer_linux_test.go.tmpl').read_text()
  self.assertEqual(helper.count('socksExecutionPolicyAdmission(ctx, r.policy, capture)'),1)
  self.assertIn('capture.Source.Schema != 3 || policy == nil || policy.NativeCarrierRequired()',helper)
 def test_source_clock_and_original_identity(self):
  source=inspect.getsource(GATE.execute)
  for anchor in ('timeout=300','timeout=130','timeout=265','source_identity(core) != before','REPOSITORY.repository_identity(required_commit) != repository'):
   self.assertIn(anchor.replace(' ',''),source.replace(' ',''))
  self.assertEqual(source.count('for case in CASES:'),1)

if __name__=='__main__':unittest.main()
