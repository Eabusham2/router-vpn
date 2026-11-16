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
    reached=[3 if n and not layer_failure and (not packet_failure or i<=(0 if fault=='wrong-first-key' else 1)) else 0 for i in range(max(1,n))]
    proven=[2 if n and not layer_failure and (not packet_failure or fault=='wrong-middle-key' and i==0) else 0 for i in range(max(1,n))]
    inner=not packet_failure and fault not in ('wrong-password','wrong-mask','wrong-sni','wrong-trust')
    layers=[]
    for i,mode in enumerate(G.LAYERS.get(topology,('off',)*n)):
        layer=dict(mode=mode,outer='',inner='',private='',raw=0,authenticated=0,forwarded=0,rejected=0)
        if mode!='off':layer.update(outer=('192.168.210.2' if i==0 else '127.0.0.1')+(':'+str(8389 if i==0 and mode.endswith('whitening') else 40000+i)),inner='127.0.0.1:42000',private=(f'10.{80+i}.0.1' if i<n-1 else '10.78.0.1')+(':'+str(42000 if i==0 else 51820)),raw=3,authenticated=0 if layer_failure else 2,forwarded=0 if layer_failure else 3,rejected=2 if layer_failure else 0)
        layers.append(layer)
    return dict(case=case,capture_sha256='a'*64,source_sha256='b'*64,ready=ready,selected_dns=ready,prefixes=n,prefix_packets=reached,prefix_proofs=proven,prefix_layers=layers,
                provider_udp=0 if packet_failure else 5,auth_refusals=1 if fault=='wrong-password' else 0,streams=3 if inner else 0,packets=2 if inner else 0,
                private_proofs=3 if inner else 0,dns_queries=2 if inner else 0,public_queries=1 if inner else 0,cover_replies=2 if ready else 0,
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
    for path in ('mobile/server_chain/**','mobile/server_chain_acceptance/**','mobile/desktop/**','internal/mobilemultihop/**','internal/multihoprelay/**','deploy/**'):
        if value.count("      - '"+path+"'\n")!=2:raise ValueError('Hysteria2 source trigger missing')

class HysteriaServerGateTests(unittest.TestCase):
    def refuse(self,text,case=G.CASES[0]):
        with self.assertRaises(ValueError):G.check_verdict(text,case)
    def changed(self,case,key,value):
        old=receipt(case);new=dict(old);new[key]=value
        self.refuse(transcript(case).replace(json.dumps(old),json.dumps(new)),case)
    def test_complete_native_inventory(self):
        self.assertEqual(len(G.CASES),22)
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
