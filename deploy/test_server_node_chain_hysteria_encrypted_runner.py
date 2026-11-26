#!/usr/bin/env python3
"""Require exact Hysteria2 original transport, source, case and joined verdicts."""
from pathlib import Path
import ast
import hashlib
import importlib.util
import json
import re
import tempfile
import unittest

P=Path(__file__).with_name('test_server_node_chain_hysteria_encrypted.py')
spec=importlib.util.spec_from_file_location('hysteria_server_gate',P);G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)

def receipt(case):
    topology,fault=case.split('/');n=G.PREFIXES[topology];ready=fault in ('original','joined-active-udp')
    layer_failure=fault in ('wrong-layer-key','wrong-whitening')
    packet_failure=layer_failure or fault in ('wrong-first-key','wrong-middle-key')
    final_failure=fault in ('wrong-final-layer-key','wrong-final-whitening')
    reached=[3 if n and not layer_failure and (not packet_failure or i<=(0 if fault=='wrong-first-key' else 1)) else 0 for i in range(max(1,n))]
    proven=[2 if n and not layer_failure and (not packet_failure or fault=='wrong-middle-key' and i==0) else 0 for i in range(max(1,n))]
    inner=not packet_failure and not final_failure and fault not in ('wrong-password','wrong-mask','wrong-sni','wrong-trust')
    layers=[]
    for i,mode in enumerate(G.LAYERS.get(topology,('off',)*n)):
        layer=dict(mode=mode,outer='',inner='',private='',raw=0,authenticated=0,forwarded=0,rejected=0)
        if mode!='off':layer.update(outer=('192.168.210.2' if i==0 else '127.0.0.1')+(':'+str(8389 if i==0 and mode.endswith('whitening') else 40000+i)),inner='127.0.0.1:42000',private=(f'10.{80+i}.0.1' if i<n-1 else '10.78.0.1')+(':'+str(42000 if i==0 else 51820)),raw=3,authenticated=0 if layer_failure else 2,forwarded=0 if layer_failure else 3,rejected=2 if layer_failure else 0)
        layers.append(layer)
    final_mode=G.FINAL_LAYERS.get(topology,'off')
    final_layer=dict(mode=final_mode,outer='',inner='',private='',raw=0,authenticated=0,forwarded=0,rejected=0)
    if final_mode!='off':final_layer.update(outer=('203.0.113.25' if n==0 else '127.0.0.2')+(':'+str(8389 if final_mode.endswith('whitening') else 44000)),inner='127.0.0.1:43000',private='127.0.0.1:443',raw=3,authenticated=0 if final_failure else 2,forwarded=0 if final_failure else 3,rejected=2 if final_failure else 0)
    return dict(case=case,capture_sha256='a'*64,source_sha256='b'*64,ready=ready,selected_dns=ready,prefixes=n,prefix_packets=reached,prefix_proofs=proven,prefix_layers=layers,final_layer=final_layer,
                provider_udp=0 if packet_failure or final_failure else 5,auth_refusals=1 if fault=='wrong-password' else 0,streams=3 if inner else 0,packets=2 if inner else 0,
                private_proofs=3 if inner else 0,dns_queries=2 if inner else 0,public_queries=1 if inner and fault!='failed-selected-dns' else 0,cover_replies=2 if ready else 0,
                ss_tcp=0,ss_udp=0,retired=True,worker_joined=True,peer_joined=True)

def transcript(case=None,*,source=False,provider=False):
    root=G.PROVIDER if provider else G.SOURCE if source else G.NATIVE
    names=() if provider else G.CASES if source else (case,)
    rows=['=== RUN   '+root]
    for name in names:
        rows.append('=== RUN   '+root+'/'+name)
        if not source and not provider:rows.append('    fixture.go:19: HYSTERIA_SERVER_RECEIPT '+json.dumps(receipt(name)))
    rows.append('--- PASS: '+root+' (0.01s)')
    rows.extend('    --- PASS: '+root+'/'+name+' (0.01s)' for name in names)
    return '\n'.join([*rows,'PASS',''])

def required_workflow(value):
    command='python3 deploy/test_server_node_chain_hysteria_encrypted.py --standalone --require-commit "$ROUTERVPN_EXPECTED_SOURCE" --receipt "$ROUTERVPN_HYSTERIA_SERVER_RECEIPT"'
    runner='python3 deploy/test_server_node_chain_hysteria_encrypted_runner.py'
    required=(command,runner,'    timeout-minutes: 45','        timeout-minutes: 40',
              '          - arch: amd64','            runner: ubuntu-24.04','          - arch: arm64','            runner: ubuntu-24.04-arm',
              "          go-version: '1.26.3'","          CGO_ENABLED: '1'",'          ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}',
              '          ROUTERVPN_HYSTERIA_SERVER_RECEIPT: ${{ runner.temp }}/server-hysteria-${{ matrix.arch }}.json',
              '          path: ${{ runner.temp }}/server-hysteria-${{ matrix.arch }}.json','          if-no-files-found: error')
    if any(value.count(x+'\n')!=1 for x in required):raise ValueError('Required Hysteria2 workflow changed')
    if not value.index("go-version: '1.26.3'")<value.index(runner)<value.index(command)<value.index('      - uses: actions/upload-artifact@v4'):raise ValueError('Required Hysteria2 order changed')
    if re.search(r'^\s*(?:if:|continue-on-error:|allow_failure:)',value,re.M) or any(v in value for v in ('--compile-only','|| true','|| :','set +e')):raise ValueError('Hysteria2 acceptance bypass')
    if not all(event in value for event in ('  workflow_call:\n','  workflow_dispatch:\n','  pull_request:\n')) or re.search(r'^  push:', value, re.M):
        raise ValueError('Use the release caller for main pushes; keep PR and manual checks')
    for path in ('mobile/server_chain/**','mobile/server_chain_acceptance/**','mobile/desktop/**','internal/mobilemultihop/**','internal/multihoprelay/**','deploy/**'):
        if value.count("      - '"+path+"'\n")!=1:raise ValueError('Hysteria2 source trigger missing')

class HysteriaServerGateTests(unittest.TestCase):
    def refuse(self,text,case=G.CASES[0]):
        with self.assertRaises(ValueError):G.check_verdict(text,case)
    def changed(self,case,key,value):
        old=receipt(case);new=dict(old);new[key]=value
        self.refuse(transcript(case).replace(json.dumps(old),json.dumps(new)),case)
    def test_actual_request_generator_preserves_independent_provider_identities(self):
        # Compile the exact request generator and original provider admission.
        # No namespace, peer socket, encrypted traffic or successful native
        # receipt is simulated by this constructor-only regression.
        import subprocess
        def declaration(source, marker):
            self.assertEqual(source.count(marker),1)
            return marker+source.split(marker,1)[1].split('\n}',1)[0]+'\n}\n'
        encrypted=(G.ROOT/'mobile/server_chain_acceptance/encrypted_linux_test.go.tmpl').read_text()
        driver=(G.ROOT/G.TEMPLATE).read_text()
        peer=(G.ROOT/'mobile/desktop/node_chain_peer_linux_test.go.tmpl').read_text()
        hysteria=(G.ROOT/G.PEER_TEMPLATE).read_text()
        self.assertEqual(declaration(driver,'func serverChainHysteriaStart(').count('json.NewEncoder(p.original.process.input).Encode(serverChainHysteriaRequest(p))'),1)
        parts=[]
        for source,names in (
            (encrypted,('serverChainEncryptedPrefix','serverChainEncryptedPrefixStats','serverChainEncryptedFinalStats','serverChainEncryptedStats','serverChainEncryptedPeer')),
            (driver,('serverChainHysteriaObservation','serverChainHysteriaLayer','serverChainHysteriaLayerReceipt','serverChainHysteriaReply','serverChainHysteriaPeer')),
            (peer,('desktopNodeChainPrefixRequest','desktopNodeChainPeerRequest')),
            (hysteria,('desktopHysteriaServerRequest','desktopHysteriaServerLayer'))):
            for name in names:parts.append(declaration(source,'type '+name+' struct {'))
        for source,names in (
            (encrypted,('serverChainEncryptedKey','serverChainEncryptedRandom','serverChainEncryptedProof','serverChainEncryptedKeys')),
            (driver,('serverChainHysteriaKeys','serverChainHysteriaRequest')),
            (peer,('desktopNodeChainReferenceAddressPair','desktopNodeChainInner','desktopNodeChainPeerIdentityBounds',
                   'desktopNodeChainPeerIdentityWithin')),
            (hysteria,('desktopHysteriaServerRequestValid',))):
            for name in names:parts.append(declaration(source,'func '+name+'('))
        for name in ('serverChainHysteriaPassword','serverChainHysteriaMask'):
            parts.append(next(line for line in driver.splitlines() if line.startswith('const '+name+' = ')))
        cases=declaration(driver,'var serverChainHysteriaCases = []string{')
        parts.append(cases)
        originals='\n'.join(parts)
        harness=r'''package fixture
import("bytes";"crypto/ecdh";"crypto/rand";"crypto/sha256";"encoding/base64";"encoding/hex";"encoding/json";"errors";"fmt";"io";"net";"net/netip";"os";"runtime";"strings";"testing";"fixture/awgpolicy")
// The source generator only stores this process pointer; no native process
// implementation is exercised or claimed by the constructor test.
type serverChainEncryptedProcess struct{}
ORIGINALS
func originalRequest(t *testing.T,topology string) desktopHysteriaServerRequest {
 t.Helper();p:=serverChainHysteriaKeys(t,topology)
 raw,err:=json.Marshal(serverChainHysteriaRequest(p));if err!=nil{t.Fatal(err)}
 var request desktopHysteriaServerRequest
 decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields()
 if decoder.Decode(&request)!=nil||decoder.Decode(new(any))!=io.EOF{t.Fatal("actual constructor request did not satisfy original provider schema")}
 return request
}
func TestActualCapturedProviderRequest(t *testing.T){
 seen:=map[string]bool{}
 for _,name:=range serverChainHysteriaCases {
  topology:=strings.Split(name,"/")[0];if seen[topology]{continue};seen[topology]=true
  t.Run(topology,func(t *testing.T){
   request:=originalRequest(t,topology)
   if !desktopHysteriaServerRequestValid(request){t.Fatal("actual complete Hysteria provider rejected original independent request")}
   count:=request.Prefixes;if count==0{count=1}
   ipc,err:=desktopNodeChainPeerIdentityBounds(request.Paired,1,6)
   if err!=nil||len(ipc)!=count||len(request.Layers)!=request.Prefixes{t.Fatal("actual original identity inventory changed")}
  })
 }
}
func TestProviderKeepsForeignIdentityRefusals(t *testing.T){
 for _,fault:=range []string{"duplicate-token","final-token","duplicate-key","duplicate-node","missing-token","foreign-key","foreign-node","prefix-count","layer-count","foreign-physical","missing-password","wrong-awg"}{
  t.Run(fault,func(t *testing.T){
   request:=originalRequest(t,"max-six")
   if !desktopHysteriaServerRequestValid(request){t.Fatal("original six-prefix setup failed before named mutation")}
   switch fault {
   case "duplicate-token":request.Paired.Prefixes[3].APIToken=request.Paired.Prefixes[0].APIToken
   case "final-token":request.Paired.FinalAPIToken=request.Paired.Prefixes[0].APIToken
   case "duplicate-key":request.Paired.Prefixes[3].PrivateKey=request.Paired.Prefixes[0].PrivateKey
   case "duplicate-node":request.Paired.Prefixes[3].NodeProofID=request.Paired.Prefixes[0].NodeProofID
   case "missing-token":request.Paired.Prefixes[3].APIToken=""
   case "foreign-key":request.Paired.Prefixes[3].PrivateKey="foreign"
   case "foreign-node":request.Paired.Prefixes[3].NodeProofID=strings.Repeat("f",64)
   case "prefix-count":request.Prefixes=5
   case "layer-count":request.Layers=request.Layers[:5]
   case "foreign-physical":request.Paired.Address="192.168.210.1"
   case "missing-password":request.Password=""
   case "wrong-awg":request.Paired.Prefixes[1].Parameters["h1"]="foreign"
   }
   if desktopHysteriaServerRequestValid(request){t.Fatal("original provider admitted named foreign identity",fault)}
  })
 }
}
'''
        correction='''\t\tfor i := range other.prefixes {
\t\t\tother.prefixes[i].APIToken = fmt.Sprintf("encrypted-server-prefix-%d-token", len(p.original.prefixes)+i)
\t\t}
'''
        self.assertEqual(originals.count(correction),1)
        with tempfile.TemporaryDirectory(prefix='hysteria-provider-identity-') as directory:
            root=Path(directory);(root/'go.mod').write_text('module fixture\n\ngo 1.26\n')
            policy=root/'awgpolicy';policy.mkdir()
            for path in (G.ROOT/'internal/awgpolicy').glob('*.go'):
                if not path.name.endswith('_test.go'):(policy/path.name).write_bytes(path.read_bytes())
            test=root/'identity_test.go'
            def run(body,selector):
                test.write_text(harness.replace('ORIGINALS',body))
                return subprocess.run(['go','test','-race','-count=1','-timeout=30s','-v','-run',selector,'.'],cwd=root,text=True,capture_output=True,timeout=60)
            positive=run(originals,'^Test(ActualCapturedProviderRequest|ProviderKeepsForeignIdentityRefusals)$')
            self.assertEqual(positive.returncode,0,positive.stdout+positive.stderr)
            topologies=('direct','wg','awg-fast','awg-strong','max-six','wg-aes','awg-xor','mixed-layers','direct-final-aes','direct-final-xor','wg-final-aes','awg-final-xor','max-final-aes','max-final-xor','mixed-final-xor')
            faults=('duplicate-token','final-token','duplicate-key','duplicate-node','missing-token','foreign-key','foreign-node','prefix-count','layer-count','foreign-physical','missing-password','wrong-awg')
            expected=['TestActualCapturedProviderRequest',*('TestActualCapturedProviderRequest/'+v for v in topologies),'TestProviderKeepsForeignIdentityRefusals',*('TestProviderKeepsForeignIdentityRefusals/'+v for v in faults)]
            self.assertEqual(re.findall(r'^=== RUN   (\S+)$',positive.stdout,re.M),expected)
            self.assertEqual(re.findall(r'^\s*--- PASS: (\S+) \([0-9.]+s\)$',positive.stdout,re.M),expected)
            for marker in ('--- FAIL:','--- SKIP:','panic:','fatal error:','WARNING: DATA RACE','[build failed]','SIGQUIT','SIGKILL'):
                self.assertNotIn(marker,positive.stdout+positive.stderr)
            self.assertEqual(positive.stderr,'')
            self.assertRegex(positive.stdout,r'(?m)^PASS$')
            self.assertRegex(positive.stdout,r'(?m)^ok\s+fixture\s+[0-9.]+s$')
            old=run(originals.replace(correction,'',1),'^TestActualCapturedProviderRequest$/^max-six$')
            self.assertEqual(old.returncode,1,old.stdout+old.stderr)
            failed=['TestActualCapturedProviderRequest','TestActualCapturedProviderRequest/max-six']
            self.assertEqual(re.findall(r'^=== RUN   (\S+)$',old.stdout,re.M),failed)
            self.assertEqual(re.findall(r'^\s*--- FAIL: (\S+) \([0-9.]+s\)$',old.stdout,re.M),failed)
            witness='actual complete Hysteria provider rejected original independent request'
            self.assertEqual(old.stdout.count(witness),1)
            for marker in ('--- PASS:','--- SKIP:','panic:','fatal error:','WARNING: DATA RACE','[build failed]','SIGQUIT','SIGKILL','timed out'):
                self.assertNotIn(marker,old.stdout+old.stderr)
            self.assertEqual(old.stderr,'')
            self.assertRegex(old.stdout,r'(?m)^FAIL\s+fixture\s+[0-9.]+s$')

    def test_complete_native_inventory(self):
        self.assertEqual(len(G.CASES),36)
        for case in G.CASES:self.assertEqual(G.check_verdict(transcript(case),case),receipt(case))
        source=(G.ROOT/G.TEMPLATE).read_text();block=source.split('var serverChainHysteriaCases = []string{',1)[1].split('\n}',1)[0]
        self.assertEqual(tuple(re.findall(r'"([^"\n]+)"',block)),G.CASES)
    def test_source_and_provider_exact_inventory(self):
        for kwargs,raw in (({'source_only':True},transcript(source=True)),({'provider':True},transcript(provider=True))):
            G.check_verdict(raw,**kwargs)
            for line in raw.splitlines(keepends=True):
                for changed in (raw.replace(line,'',1),raw.replace(line,line*2,1)):
                    with self.assertRaises(ValueError):G.check_verdict(changed,**kwargs)
    def test_missing_duplicate_terminal_and_receipt(self):
        raw=transcript(G.CASES[0]);self.refuse('PASS\n')
        for line in raw.splitlines(keepends=True):self.refuse(raw.replace(line,'',1));self.refuse(raw.replace(line,line*2,1))
        receipt_line=next(v for v in raw.splitlines(keepends=True) if 'HYSTERIA_SERVER_RECEIPT' in v)
        self.refuse(raw.replace(receipt_line,'')+receipt_line)
    def test_failure_skip_race_panic_late_output(self):
        raw=transcript(G.CASES[0])
        for marker in ('WARNING: DATA RACE','--- SKIP: original (0.01s)','--- FAIL: original (0.01s)','panic: original','fatal error: original','foreign'):
            self.refuse(raw+marker+'\n');self.refuse(marker+'\n'+raw)
    def test_strict_json_types_duplicate_keys_and_source(self):
        raw=transcript(G.CASES[0]);self.refuse(raw.replace('"ready": true','"ready": true, "ready": true'))
        for key in ('ready','retired','worker_joined','peer_joined','selected_dns'):self.changed(G.CASES[0],key,1)
        for key in ('provider_udp','ss_tcp','prefixes','streams'):self.changed(G.CASES[0],key,True)
        for key in ('capture_sha256','source_sha256'):self.changed(G.CASES[0],key,'foreign')
    def test_all_native_transport_and_join_fields_required(self):
        for key in ('retired','worker_joined','peer_joined','selected_dns','ready'):self.changed(G.CASES[0],key,False)
        for key in ('provider_udp','streams','packets','private_proofs','dns_queries','public_queries','cover_replies'):self.changed(G.CASES[0],key,0)
        for key in ('ss_tcp','ss_udp','auth_refusals'):self.changed(G.CASES[0],key,1)
    def test_direct_unused_reference_cannot_supply_authority(self):
        for key in ('prefix_packets','prefix_proofs'):self.changed('direct/original',key,[1]);self.changed('direct/original',key,[])
        self.changed('direct/original','prefixes',1)
    def test_packet_prefix_omission_reordering_and_bypass(self):
        for case in ('wg/original','awg-fast/original','awg-strong/original','max-six/original','max-six/wrong-first-key','max-six/wrong-middle-key'):
            for key in ('prefix_packets','prefix_proofs'):
                values=receipt(case)[key]
                self.changed(case,key,values[:-1]);self.changed(case,key,values+[1])
                for i,old in enumerate(values):
                    changed=list(values);changed[i]=0 if old else 1;self.changed(case,key,changed)
        for case in ('max-six/wrong-first-key','max-six/wrong-middle-key'):self.changed(case,'provider_udp',1)
    def test_failed_auth_tls_mask_never_deliver_application(self):
        for case in ('direct/wrong-password','direct/wrong-mask','direct/wrong-sni','direct/wrong-trust','max-six/wrong-first-key','max-six/wrong-middle-key'):
            for key in ('streams','packets','private_proofs','dns_queries','public_queries','cover_replies'):self.changed(case,key,1)
        self.changed('direct/wrong-password','auth_refusals',0)
    def test_failed_selected_dns_requires_its_original_failure_boundary(self):
        cases=tuple(case for case in G.CASES if case.endswith('/failed-selected-dns'))
        self.assertEqual(cases,('direct/failed-selected-dns','max-six/failed-selected-dns','max-final-aes/failed-selected-dns'))
        for case in cases:
            self.assertEqual(G.check_verdict(transcript(case),case),receipt(case))
            for key,value in [('streams',0),('packets',0),('private_proofs',0),('dns_queries',0),('auth_refusals',1),('public_queries',1),('cover_replies',1)]:
                with self.subTest(case=case,counter=key):
                    old=receipt(case);changed=dict(old);changed[key]=value
                    with self.assertRaisesRegex(ValueError,'Hysteria2 selected DNS failure boundary missing'):
                        G.check_verdict(transcript(case).replace(json.dumps(old),json.dumps(changed)),case)

    def test_missing_dns_failure_guard_recreates_early_failure_acceptance(self):
        source=P.read_text();tree=ast.parse(source)
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='check_verdict')
        original=ast.get_source_segment(source,function)
        guard="            if fault=='failed-selected-dns' and (min(value[k] for k in ('streams','packets','private_proofs','dns_queries'))<=0 or any(value[k] for k in ('auth_refusals','public_queries','cover_replies'))):raise ValueError('Hysteria2 selected DNS failure boundary missing')\n"
        self.assertEqual(original.count(guard),1)
        scope=dict(vars(G));exec(compile(original.replace(guard,''),'<removed-selected-DNS-failure-boundary>','exec'),scope)
        for case in ('direct/failed-selected-dns','max-six/failed-selected-dns','max-final-aes/failed-selected-dns'):
            old=receipt(case);early=dict(old);early.update(private_proofs=0,dns_queries=0)
            raw=transcript(case).replace(json.dumps(old),json.dumps(early))
            with self.assertRaisesRegex(ValueError,'Hysteria2 selected DNS failure boundary missing'):G.check_verdict(raw,case)
            # This is only a validator control: no native receipt or traffic is
            # created. Removing the exact guard admits the same earlier failure.
            self.assertEqual(scope['check_verdict'](raw,case),early)

    def test_actual_independent_layers_require_authenticated_forwarding(self):
        for case in ('wg-aes/original','awg-xor/original','mixed-layers/original','wg-aes/wrong-layer-key','awg-xor/wrong-whitening'):
            layers=receipt(case)['prefix_layers']
            self.changed(case,'prefix_layers',layers[:-1]);self.changed(case,'prefix_layers',layers+layers[:1])
            for i,layer in enumerate(layers):
                for key in layer:
                    changed=[dict(v) for v in layers];old=changed[i][key]
                    changed[i][key]=('foreign' if isinstance(old,str) else 0 if old else 1)
                    self.changed(case,'prefix_layers',changed)
        for case in ('wg-aes/wrong-layer-key','awg-xor/wrong-whitening'):
            for key in ('provider_udp','streams','packets','private_proofs','dns_queries','public_queries','cover_replies'):self.changed(case,key,1)
            self.changed(case,'prefix_packets',[1]);self.changed(case,'prefix_proofs',[1])
    def test_component_full_inventory_and_original_bounds(self):
        names=[G.LAYER_COMPONENT,*(G.LAYER_COMPONENT+'/'+v for v in G.LAYER_CASES)]
        raw='\n'.join([*('=== RUN   '+v for v in names),*('--- PASS: '+v+' (0.01s)' for v in names),'PASS',''])
        G.check_layer_component(raw)
        for line in raw.splitlines(keepends=True):
            for altered in (raw.replace(line,'',1),raw.replace(line,line*2,1)):
                with self.assertRaises(ValueError):G.check_layer_component(altered)
        with self.assertRaises(ValueError):G.check_layer_component(raw+'unexpected\n')
        self.assertIn("'-test.timeout=90s'",Path(G.__file__).read_text())

    def test_independent_final_layer_exact_owner_and_rejections(self):
        for case in G.CASES:
            original=receipt(case)['final_layer']
            for key,old in original.items():
                changed=dict(original);changed[key]='foreign' if isinstance(old,str) else 0 if old else 1
                self.changed(case,'final_layer',changed)
        for case in ('direct-final-aes/wrong-final-layer-key','direct-final-xor/wrong-final-whitening','max-final-aes/wrong-final-layer-key','max-final-xor/wrong-final-whitening'):
            for key in ('provider_udp','streams','packets','private_proofs','dns_queries','public_queries','cover_replies'):self.changed(case,key,1)
        self.changed('direct-final-aes/original','final_layer',receipt('max-final-aes/original')['final_layer'])
        self.changed('max-final-xor/original','final_layer',receipt('max-final-aes/original')['final_layer'])

    def test_final_layer_component_inventory_and_projection(self):
        names=[G.FINAL_LAYER_COMPONENT,*(G.FINAL_LAYER_COMPONENT+'/'+v for v in G.FINAL_LAYER_CASES)]
        raw='\n'.join([*('=== RUN   '+v for v in names),*('--- PASS: '+v+' (0.01s)' for v in names),'PASS',''])
        G.check_layer_component(raw,final=True)
        for line in raw.splitlines(keepends=True):
            for altered in (raw.replace(line,'',1),raw.replace(line,line*2,1)):
                with self.assertRaises(ValueError):G.check_layer_component(altered,final=True)
        with self.assertRaises(ValueError):G.check_layer_component(raw,final=False)
        source=(G.ROOT/'mobile/desktop/node_chain_hysteria_final_layer_test.go.tmpl').read_bytes()
        projected=G.BASE.NODE.PREP.darwin_node_chain_peer_copies()['protocol/routervpnamnezia/routervpn_node_chain_hysteria_final_layer_darwin_test.go']
        self.assertEqual(projected.split(b'\n\n',1)[1],source.split(b'\n\n',1)[1])
        self.assertEqual(G.BASE.NODE.PREP.PEER_TEMPLATES['node_chain_hysteria_final_layer_test.go.tmpl'],'protocol/routervpnamnezia/routervpn_hysteria_final_layer_test.go')

    def test_exact_namespace_alias_only(self):
        sha=hashlib.sha256(Path(G.BASE.__file__).read_bytes()).hexdigest()
        old=ast.parse(G.BASE.namespace_program(sha));new=ast.parse(G.namespace_program(sha))
        original=next(v for v in old.body if isinstance(v,ast.FunctionDef) and v.name=='inside_namespace')
        current=next(v for v in new.body if isinstance(v,ast.FunctionDef) and v.name=='inside_namespace')
        commands=next(v for v in ast.walk(current) if isinstance(v,ast.Assign) and isinstance(v.targets[0],ast.Name) and v.targets[0].id=='commands')
        self.assertEqual(ast.literal_eval(commands.value.elts.pop()),G.ALIAS);self.assertEqual(ast.dump(original),ast.dump(current))
        with self.assertRaises(ValueError):G.namespace_program('0'*64)
    def test_original_case_deadlines_and_tag(self):
        text=G.namespace_program(hashlib.sha256(Path(G.BASE.__file__).read_bytes()).hexdigest())
        for marker in ("'-test.timeout=90s'",'timeout=105',"'--make-rprivate'"):self.assertIn(marker,text)
        source=Path(G.__file__).read_text()
        for marker in ("if 'with_quic' not in tags",'timeout=600','timeout=125','timeout=75','timeout=45'):self.assertIn(marker,source)
    def test_provider_source_export_is_exact_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);p=root/'original.json';p.write_text('{}');p.chmod(0o600);G.profile_sources(root)
            p.chmod(0o644)
            with self.assertRaises(ValueError):G.profile_sources(root)
            p.chmod(0o600);(root/'foreign.json').write_text('{}')
            with self.assertRaises(ValueError):G.profile_sources(root)
    def test_required_workflow_and_removal_controls(self):
        source=(G.ROOT/'.github/workflows/server-hysteria-encrypted.yml').read_text();required_workflow(source)
        for line in source.splitlines(keepends=True):
            if any(x in line for x in ('test_server_node_chain_hysteria_encrypted','runner: ubuntu','timeout-minutes:',"go-version:",'if-no-files-found:','ROUTERVPN_EXPECTED_SOURCE:',"'mobile/desktop/**'")):
                with self.assertRaises(ValueError):required_workflow(source.replace(line,'',1))
        for prefix in ('    continue-on-error: true\n','    if: false\n'):
            with self.assertRaises(ValueError):required_workflow(source+prefix)
    def test_standalone_cannot_substitute_compile_only(self):
        self.assertTrue(G.parse_arguments(['--standalone','--require-commit','a'*40]).standalone)
        import contextlib,io
        for args in ([],['--standalone'],['--standalone','--require-commit','a'*40,'--compile-only'],['--standalone','--require-commit','a'*40,'--core','/tmp/core'],['--core','/tmp/core','--require-commit','a'*40]):
            with self.subTest(args=args),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):G.parse_arguments(args)
    def test_generated_peer_platform_package_and_scope_remain_explicit(self):
        source=(G.ROOT/G.PEER_TEMPLATE).read_text()
        self.assertTrue(source.startswith('//go:build linux && !android\n\npackage routervpnamnezia\n'))
        self.assertIn('desktopNodeChainPeerPhysicalNamespace(t, r.Paired)',source)
        self.assertIn('original Hysteria2 namespace alias missing',source)
        self.assertIn('explicit private Hysteria2 source export only',source)
        self.assertIn('ROUTERVPN_HYSTERIA_SERVER_SOURCES',Path(G.__file__).read_text())
        darwin=G.BASE.NODE.PREP.darwin_node_chain_peer_copies()
        projected=darwin['protocol/routervpnamnezia/routervpn_node_chain_hysteria_server_peer_darwin_test.go']
        self.assertEqual(projected.split(b'\n\n',1)[1],source.encode().split(b'\n\n',1)[1])
        self.assertTrue(projected.startswith(b'//go:build darwin && routervpn_darwin_node_chain && routervpn_darwin_external_host\n'))
    def test_required_aggregate_and_build_closure(self):
        caller=(G.ROOT/'.github/workflows/server-node-chain-encrypted.yml').read_text()
        block='  hysteria-final:\n    name: Require actual Hysteria2 Server final\n    uses: ./.github/workflows/server-hysteria-encrypted.yml\n'
        self.assertEqual(caller.count(block),1)
        builder=(G.ROOT/'deploy/build-native-runtime.py').read_text()
        for name in ('deploy/test_server_node_chain_hysteria_encrypted.py','deploy/test_server_node_chain_hysteria_encrypted_runner.py'):self.assertEqual(builder.count("ROOT/'"+name+"'"),1)
        self.assertEqual(G.BASE.NODE.PREP.PEER_TEMPLATES[Path(G.PEER_TEMPLATE).name],'protocol/routervpnamnezia/routervpn_hysteria_server_peer_test.go')

if __name__=='__main__':unittest.main()
