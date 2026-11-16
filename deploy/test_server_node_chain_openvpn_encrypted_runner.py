#!/usr/bin/env python3
"""Fail-closed inventory controls for the actual zero-prefix OpenVPN Server gate."""
from pathlib import Path
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import re
import tempfile
import unittest

P=Path(__file__).with_name('test_server_node_chain_openvpn_encrypted.py')
spec=importlib.util.spec_from_file_location('openvpn_direct_gate',P);G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)

def receipt(case):
    network,layer,fault=case.split('/');ready=fault in ('original','joined-active-udp')
    return dict(case=case,capture_sha256='a'*64,source_sha256='b'*64,ready=ready,selected_dns=ready,
                provider_tcp=2 if network=='tcp' else 0,provider_udp=2 if network=='udp' else 0,
                auth_refusals=1 if fault=='wrong-server-password' else 0,streams=2 if ready else 0,packets=3 if ready else 0,
                unused_prefix_packets=0,unused_prefix_proofs=0,retired=True,worker_joined=True,peer_joined=True)

def transcript(case=None,*,source=False,provider=False):
    root=G.PROVIDER if provider else G.SOURCE if source else G.NATIVE
    names=G.NETWORKS if provider else G.CASES if source else (case,)
    rows=['=== RUN   '+root]
    for name in names:
        rows.append('=== RUN   '+root+'/'+name)
        if not source and not provider:rows.append('    fixture.go:19: OPENVPN_DIRECT_SERVER_RECEIPT '+json.dumps(receipt(name)))
    rows.append('--- PASS: '+root+' (0.01s)')
    rows.extend('    --- PASS: '+root+'/'+name+' (0.01s)' for name in names)
    return '\n'.join([*rows,'PASS',''])

def required_workflow(value):
    command='python3 deploy/test_server_node_chain_openvpn_encrypted.py --standalone --require-commit "$ROUTERVPN_EXPECTED_SOURCE" --receipt "$ROUTERVPN_OPENVPN_SERVER_RECEIPT"'
    runner='python3 deploy/test_server_node_chain_openvpn_encrypted_runner.py'
    required=(command,runner,'    timeout-minutes: 45','        timeout-minutes: 40',
              '          - arch: amd64','            runner: ubuntu-24.04','          - arch: arm64','            runner: ubuntu-24.04-arm',
              "          go-version: '1.26.3'","          CGO_ENABLED: '1'",'          ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}',
              '          ROUTERVPN_OPENVPN_SERVER_RECEIPT: ${{ runner.temp }}/server-openvpn-direct-${{ matrix.arch }}.json',
              '          path: ${{ runner.temp }}/server-openvpn-direct-${{ matrix.arch }}.json','          if-no-files-found: error')
    if any(value.count(x+'\n')!=1 for x in required):raise ValueError('Required OpenVPN native workflow changed')
    if not value.index("go-version: '1.26.3'")<value.index(runner)<value.index(command)<value.index('      - uses: actions/upload-artifact@v4'):raise ValueError('OpenVPN required execution order changed')
    if re.search(r'^\s*(?:if:|continue-on-error:|allow_failure:)',value,re.M) or any(v in value for v in ('--compile-only','|| true','|| :','set +e')):raise ValueError('OpenVPN native workflow bypass')
    for path in ('mobile/server_chain/**','mobile/server_chain_acceptance/**','mobile/desktop/**','internal/mobilemultihop/**','internal/multihoprelay/**','internal/nativeopenvpn/**','deploy/**'):
        if value.count("      - '"+path+"'\n")!=2:raise ValueError('OpenVPN source trigger missing')

class OpenVPNDirectGateTests(unittest.TestCase):
    def refuse(self,text,case=G.CASES[0]):
        with self.assertRaises(ValueError):G.check_verdict(text,case)
    def test_complete_native_inventory(self):
        self.assertEqual(len(G.CASES),14)
        for case in G.CASES:
            with self.subTest(case=case):self.assertEqual(G.check_verdict(transcript(case),case),receipt(case))
    def test_exact_source_and_provider_inventory(self):
        for kind,names in (('source_only',G.CASES),('provider',G.NETWORKS)):
            text=transcript(source=kind=='source_only',provider=kind=='provider')
            self.assertEqual(G.check_verdict(text,**{kind:True}),list(names))
            for line in text.splitlines(keepends=True):
                for bad in (text.replace(line,'',1),text.replace(line,line*2,1)):
                    with self.subTest(kind=kind,line=line),self.assertRaises(ValueError):G.check_verdict(bad,**{kind:True})
    def test_missing_duplicate_and_late_verdicts(self):
        raw=transcript(G.CASES[0])
        self.refuse('PASS\n')
        for line in raw.splitlines(keepends=True):
            self.refuse(raw.replace(line,'',1));self.refuse(raw.replace(line,line*2,1))
        line=next(x for x in raw.splitlines(keepends=True) if 'SERVER_RECEIPT' in x)
        self.refuse(raw.replace(line,'')+line)
    def test_race_skip_panic_foreign_output(self):
        raw=transcript(G.CASES[0])
        for tail in ('WARNING: DATA RACE','--- SKIP: foreign (0.01s)','--- FAIL: foreign (0.01s)','panic: original','unexpected'):
            self.refuse(raw+tail+'\n');self.refuse(raw.replace('--- PASS:',tail+'\n--- PASS:',1))
    def test_selected_case_identity(self):
        self.refuse(transcript(G.CASES[1]));self.refuse(transcript(G.CASES[0]).replace('"case": "'+G.CASES[0]+'"','"case": "'+G.CASES[1]+'"'))
    def test_duplicate_json_and_strict_types(self):
        raw=transcript(G.CASES[0]);self.refuse(raw.replace('"ready": true','"ready": true, "ready": true'))
        for old,new in (('"provider_tcp": 2','"provider_tcp": true'),('"ready": true','"ready": 1'),('"unused_prefix_packets": 0','"unused_prefix_packets": false'),('"source_sha256": "'+'b'*64+'"','"source_sha256": "foreign"')):self.refuse(raw.replace(old,new))
    def test_owner_transport_and_join_controls(self):
        raw=transcript(G.CASES[0])
        for key in ('retired','worker_joined','peer_joined','selected_dns'):self.refuse(raw.replace('"'+key+'": true','"'+key+'": false'))
        for key in ('unused_prefix_packets','unused_prefix_proofs','provider_udp','auth_refusals'):self.refuse(raw.replace('"'+key+'": 0','"'+key+'": 1'))
        for key,value in (('provider_tcp',2),('streams',2),('packets',3)):self.refuse(raw.replace('"'+key+'": '+str(value),'"'+key+'": 0'))
        case='udp/off/wrong-server-password';raw=transcript(case)
        for key in ('streams','packets'):self.refuse(raw.replace('"'+key+'": 0','"'+key+'": 1'),case)
        self.refuse(raw.replace('"auth_refusals": 1','"auth_refusals": 0'),case)
    def test_namespace_has_only_exact_owned_alias_delta(self):
        base_sha=hashlib.sha256(Path(G.BASE.__file__).read_bytes()).hexdigest()
        old=ast.parse(G.BASE.namespace_program(base_sha));new=ast.parse(G.namespace_program(base_sha))
        changed=next(n for n in new.body if isinstance(n,ast.FunctionDef) and n.name=='inside_namespace')
        commands=next(n for n in ast.walk(changed) if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='commands')
        self.assertEqual(ast.literal_eval(commands.value.elts[-1]),G.ALIAS)
        commands.value.elts.pop()
        original=next(n for n in old.body if isinstance(n,ast.FunctionDef) and n.name=='inside_namespace')
        self.assertEqual(ast.dump(changed),ast.dump(original))
        text=G.namespace_program(base_sha)
        for marker in ("'-test.timeout=90s'",'timeout=105',"'--make-rprivate'","'192.168.210.2'"):
            self.assertIn(marker,text)
        with self.assertRaises(ValueError):G.namespace_program('0'*64)
    def test_exact_slash_selector_and_literal_layer(self):
        program=G.namespace_program(hashlib.sha256(Path(G.BASE.__file__).read_bytes()).hexdigest())
        body=next(n for n in ast.parse(program).body if isinstance(n,ast.FunctionDef) and n.name=='inside_namespace')
        calls=[n for n in ast.walk(body) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='run' and n.args and isinstance(n.args[0],ast.List) and any(isinstance(v,ast.Constant) and v.value=='-test.v' for v in n.args[0].elts)]
        self.assertEqual(len(calls),1)
        expression=compile(ast.Expression(calls[0].args[0].elts[1]),'<actual-selector>','eval')
        for case in G.CASES:
            selected=eval(expression,dict(NATIVE=G.NATIVE,case=case,re=re)).removeprefix('-test.run=')
            patterns=selected.split('/')
            self.assertEqual(len(patterns),4)
            for pattern,value in zip(patterns,[G.NATIVE,*case.split('/')]):
                self.assertTrue(re.fullmatch(pattern,value));self.assertIsNone(re.fullmatch(pattern,value+'-foreign'))
    def test_private_exports_are_exact_and_sealed(self):
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d)
            for name in G.NETWORKS:(directory/(name+'.json')).write_bytes(b'private');(directory/(name+'.json')).chmod(0o600)
            expected={n:hashlib.sha256(b'private').hexdigest() for n in G.NETWORKS}
            self.assertEqual(G.profile_sources(directory),expected)
            (directory/'tcp.json').chmod(0o644)
            with self.assertRaises(ValueError):G.profile_sources(directory)
            (directory/'tcp.json').chmod(0o600);(directory/'foreign').write_text('')
            with self.assertRaises(ValueError):G.profile_sources(directory)
    def test_original_provider_branch_and_registered_new_source(self):
        source=(G.ROOT/'mobile/desktop/node_external_openvpn_installed_test.go.tmpl').read_text()
        for marker in ('!captured.Direct && (!physical.IsLoopback() || physical != clientAddress)','captured.Direct && (captured.Local == nil || maxClients != 2','physical != captured.Remote.Addr()','prefix.Bits() == 32','listenPort := "0"','if captured != nil && captured.Direct {'):
            self.assertIn(marker,source)
        path=G.BASE.NODE.PREP.PEER_TEMPLATES[Path(G.PEER_TEMPLATE).name]
        self.assertEqual(path,'protocol/routervpnamnezia/routervpn_openvpn_server_direct_peer_test.go')
        self.assertTrue((G.ROOT/G.PEER_TEMPLATE).read_text().startswith('//go:build linux && !android\n\n'))
    def test_go_case_inventory_is_exact(self):
        source=(G.ROOT/G.TEMPLATE).read_text();block=source[source.index('var serverChainOpenVPNDirectCases'):source.index('type serverChainOpenVPNDirectReply')]
        self.assertEqual(tuple(re.findall(r'"([^"\n]+)"',block)),G.CASES)
        for marker in ('LocalPacketPositions: []int{0}','policy.NativeCarrierRequired()','source.OpenVPNPairing.Local = source.OpenVPNPairing.Server','foreign.Source.Members[0].SourceSHA256','worker.stop(t)','p.original.process.join(t)','time.Now().Add(15 * time.Second)'):
            self.assertIn(marker,source)
    def test_mandatory_workflow_and_causal_controls(self):
        raw=(G.ROOT/'.github/workflows/server-openvpn-direct-encrypted.yml').read_text();required_workflow(raw)
        command=next(x for x in raw.splitlines(keepends=True) if ' --standalone ' in x)
        for bad in (raw.replace(command,''),raw.replace(command,command*2),raw.replace('--standalone','--compile-only'),raw.replace('        timeout-minutes: 40','        if: false\n        timeout-minutes: 40'),raw.replace('          - arch: arm64\n',''),raw.replace('          if-no-files-found: error','          if-no-files-found: warn'),raw.replace("      - 'internal/nativeopenvpn/**'\n",'',1)):
            with self.assertRaises(ValueError):required_workflow(bad)

    def test_reusable_original_release_workflow_requires_new_gate(self):
        raw=(G.ROOT/'.github/workflows/server-node-chain-encrypted.yml').read_text()
        key='  openvpn-direct:\n    name: Require actual zero-prefix OpenVPN Server suffix\n    uses: ./.github/workflows/server-openvpn-direct-encrypted.yml\n'
        self.assertEqual(raw.count(key),1)
        jobs=raw.split('jobs:',1)[1]
        block=jobs[jobs.index('  openvpn-direct:'):]
        self.assertEqual(block,key)
        builder=(G.ROOT/'deploy/build-native-runtime.py').read_text()
        for path in ('deploy/test_server_node_chain_openvpn_encrypted.py','deploy/test_server_node_chain_openvpn_encrypted_runner.py',G.TEMPLATE,'.github/workflows/server-openvpn-direct-encrypted.yml'):
            self.assertEqual(builder.count("ROOT/'"+path+"'"),1)

    def test_standalone_is_native_and_commit_bound(self):
        self.assertTrue(G.parse_arguments(['--standalone','--require-commit','a'*40]).standalone)
        for args in ([],['--standalone'],['--standalone','--require-commit','a'*40,'--compile-only'],['--standalone','--require-commit','a'*40,'--core','/tmp/core'],['--core','/tmp/core','--require-commit','a'*40]):
            with self.subTest(args=args),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):G.parse_arguments(args)
        self.assertTrue(G.parse_arguments(['--core','/tmp/core','--compile-only']).compile_only)

if __name__=='__main__':unittest.main()
