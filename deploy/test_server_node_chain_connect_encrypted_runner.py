#!/usr/bin/env python3
"""Strict receipt/namespace ownership controls for the CONNECT suffix gate."""
from pathlib import Path
import ast
import contextlib
import io
import hashlib
import importlib.util
import json
import re
import unittest
from unittest.mock import patch
P=Path(__file__).with_name('test_server_node_chain_connect_encrypted.py')
spec=importlib.util.spec_from_file_location('connect_server_gate',P);G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)

def transcript(case,source=False):
    root=G.SOURCE if source else G.NATIVE
    names=G.CASES if source else (case,)
    rows=['=== RUN   '+root]
    for name in names:
        rows.append('=== RUN   '+root+'/'+name)
        if not source:
            protocol,fault=name.split('/');original,ready,packet_failure=G.case_state(fault);restricted=fault=='admission-restrictions'
            value={'case':fault,'protocol':protocol,'capture_sha256':'a'*64,'source_sha256':'b'*64,'ready':ready,'selected_dns':ready,'middle_tcp':0 if packet_failure else 2,'middle_udp':0,'final_tcp':2 if ready else 0,'final_udp':0,'retired':True,'worker_joined':True,'peer_joined':True,'private_udp_refused':restricted,'private_sink_packets':1 if ready and not restricted else 0,'private_sink_replies':1 if ready and not restricted else 0,'middle_auth':1 if original=='wrong-middle-key' else 0,'tls_refused':1 if fault=='wrong-proxy-name' else 0}
            if fault in G.PREFIX_MODES:
                modes=G.PREFIX_MODES[fault]
                value['prefix_modes']=list(modes)
                value['prefix_packets']=[2 if not packet_failure or i<= (0 if original=='wrong-first-packet-key' else 1) else 0 for i in range(len(modes))]
                value['prefix_proofs']=[1 if not packet_failure or original=='wrong-later-packet-key' and i==0 else 0 for i in range(len(modes))]
            rows.append('    fixture.go:17: CONNECT_SERVER_RECEIPT '+json.dumps(value))
    rows.append('--- PASS: '+root+' (0.01s)')
    rows.extend('    --- PASS: '+root+'/'+name+' (0.01s)' for name in names)
    return '\n'.join(rows+['PASS',''])


def required_workflow(value):
    # Reuse the original architecture, immutable-source and unconditional gate checks.
    oldspec=importlib.util.spec_from_file_location('original_server_runner',P.with_name('test_server_node_chain_encrypted_runner.py'))
    old=importlib.util.module_from_spec(oldspec);oldspec.loader.exec_module(old)
    old.workflow(value)
    runner='python3 deploy/test_server_node_chain_connect_encrypted_runner.py'
    command='python3 deploy/test_server_node_chain_connect_encrypted.py --standalone --require-commit "$ROUTERVPN_EXPECTED_SOURCE" --receipt "$ROUTERVPN_CONNECT_SERVER_RECEIPT"'
    required=(runner,command,'    timeout-minutes: 105',
      '          ROUTERVPN_CONNECT_SERVER_RECEIPT: ${{ runner.temp }}/server-connect-node-chain-${{ matrix.arch }}.json',
      '            ${{ runner.temp }}/server-connect-node-chain-${{ matrix.arch }}.json',
      '            ${{ runner.temp }}/server-node-chain-${{ matrix.arch }}.json',
      '          name: RouterVPN-Server-encrypted-${{ matrix.arch }}-${{ github.sha }}')
    if any(value.count(x)!=1 for x in required): raise ValueError('CONNECT required native workflow inventory changed')
    blocks=re.split(r'^      - ',value,flags=re.M)
    selected=[x for x in blocks if command in x]
    if len(selected)!=1 or any(selected[0].count(x)!=1 for x in ('        timeout-minutes: 45','          ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}',"          CGO_ENABLED: '1'")):
        raise ValueError('CONNECT native step lost original source, compiler or bounded invocation')
    if not value.index(runner)<value.index(command)<value.index('      - uses: actions/upload-artifact@v4'):
        raise ValueError('CONNECT gate/receipt execution order changed')
    for path in ('mobile/chain/**','mobile/server_chain/**','mobile/server_chain_acceptance/**','mobile/desktop/**','internal/mobilemultihop/**','internal/multihoprelay/**'):
        if value.count("      - '"+path+"'")!=2: raise ValueError('CONNECT native source trigger missing')

class CONNECTServerGateTests(unittest.TestCase):
    def refuse(self,text,case='http-connect/original'):
        with self.assertRaises(ValueError):G.check_verdict(text,case)
    def test_all_original_protocol_cases(self):
        for case in G.CASES:
            with self.subTest(case=case):self.assertEqual(G.check_verdict(transcript(case),case)['case'],case.split('/')[1])
    def test_actual_provider_protocol_inventory(self):
        raw='=== RUN   '+G.PROVIDER+'\n'
        for protocol in G.PROTOCOLS:
            raw+='=== RUN   '+G.PROVIDER+'/'+protocol+'\n'
        root_pass='--- PASS: '+G.PROVIDER+' (0.02s)\n'
        leaves=['    --- PASS: '+G.PROVIDER+'/'+protocol+' (0.01s)\n' for protocol in G.PROTOCOLS]
        raw+=root_pass+''.join(leaves)+'PASS\n'
        self.assertEqual(G.check_provider(raw),list(G.PROTOCOLS))
        missing=[]
        duplicates=[]
        for line in raw.splitlines(keepends=True):
            missing.append(raw.replace(line,'',1))
            duplicates.append(raw.replace(line,line*2,1))
        premature_root=raw.replace(root_pass,'').replace('=== RUN   '+G.PROVIDER+'\n','=== RUN   '+G.PROVIDER+'\n'+root_pass)
        premature_leaf=raw.replace(leaves[0],'').replace(root_pass,leaves[0]+root_pass)
        for bad in (*missing,*duplicates,premature_root,premature_leaf,raw.replace('/https-connect','/foreign'),raw.replace(root_pass,'PASS\n'+root_pass)):
            with self.subTest(transcript=bad),self.assertRaises(ValueError):G.check_provider(bad)
        for forbidden in ('WARNING: DATA RACE','--- FAIL: '+G.PROVIDER+' (0.01s)','--- SKIP: '+G.PROVIDER+' (0.01s)','panic: provider','unexpected output'):
            for bad in (raw+forbidden+'\n',raw.replace(root_pass,forbidden+'\n'+root_pass)):
                with self.subTest(transcript=bad),self.assertRaises(ValueError):G.check_provider(bad)
    def test_actual_provider_is_mandatory_before_namespace(self):
        source=Path(G.__file__).read_text()
        begin=source.index("        provider=BASE.run([peer,'-test.run=^'+PROVIDER+'$'")
        logged=source.index("        print(provider,end='',flush=True);provider_protocols=check_provider(provider)",begin)
        check=source.index('provider_protocols=check_provider(provider)',logged)
        native=source.index('        if not compile_only:',check)
        self.assertLess(begin,logged);self.assertLess(logged,check);self.assertLess(check,native)
        self.assertIn("'provider_protocols':provider_protocols",source)
        self.assertIn("'provider_stdout_sha256':hashlib.sha256(provider.encode()).hexdigest()",source)
    def test_complete_source_inventory(self):
        self.assertEqual(G.check_verdict(transcript(None,True),source_only=True)['source_cases'],list(G.CASES))
        with self.assertRaises(ValueError):G.check_verdict(transcript(None,True).replace('=== RUN   '+G.SOURCE+'/'+G.CASES[-1]+'\n',''),source_only=True)
    def test_empty_missing_and_duplicate_roots(self):
        raw=transcript('http-connect/original')
        for text in ('PASS\n',raw.replace('=== RUN   '+G.NATIVE+'\n',''),raw+'PASS\n',raw.replace('=== RUN   '+G.NATIVE+'\n',('=== RUN   '+G.NATIVE+'\n')*2)):
            self.refuse(text)
    def test_race_skip_panic_and_foreign_output(self):
        for text in ('WARNING: DATA RACE','--- SKIP: foreign (0.01s)','panic: unrelated','unknown output'):
            self.refuse(transcript('http-connect/original')+text+'\n')
    def test_wrong_selected_leaf(self):
        self.refuse(transcript('https-connect/original'))
    def test_missing_or_duplicate_receipt(self):
        raw=transcript('http-connect/original');line=next(x for x in raw.splitlines() if 'CONNECT_SERVER_RECEIPT' in x)
        self.refuse(raw.replace(line+'\n',''));self.refuse(raw.replace(line,line+'\n'+line))
    def test_duplicate_json_key(self):
        self.refuse(transcript('http-connect/original').replace('"ready": true','"ready": true, "ready": true'))
    def test_late_receipt(self):
        raw=transcript('http-connect/original');line=next(x for x in raw.splitlines() if 'CONNECT_SERVER_RECEIPT' in x)
        self.refuse(raw.replace(line+'\n','')+line+'\n')
    def test_source_join_auth_and_transport_controls(self):
        raw=transcript('http-connect/original')
        for old,new in [('"worker_joined": true','"worker_joined": false'),('"peer_joined": true','"peer_joined": false'),('"middle_udp": 0','"middle_udp": 1'),('"final_udp": 0','"final_udp": 1'),('"middle_tcp": 2','"middle_tcp": true'),('"selected_dns": true','"selected_dns": false'),('"middle_auth": 0','"middle_auth": 1'),('"source_sha256": "'+'b'*64+'"','"source_sha256": "foreign"')]:self.refuse(raw.replace(old,new))
    def test_original_namespace_body_and_bounds(self):
        sha=hashlib.sha256(Path(G.BASE.__file__).read_bytes()).hexdigest();program=G.namespace_program(sha)
        tree=ast.parse(program)
        body=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='inside_namespace')
        original=next(x for x in ast.parse(Path(G.BASE.__file__).read_text()).body if isinstance(x,ast.FunctionDef) and x.name=='inside_namespace')
        self.assertEqual(ast.dump(body),ast.dump(original))
        self.assertIn("'-test.timeout=90s'",program);self.assertIn('timeout=105',program)
        self.assertIn(repr(G.NATIVE),program)
        with self.assertRaises(ValueError):G.namespace_program('0'*64)
    def test_standalone_requires_exact_commit_and_actual_native_run(self):
        args=G.parse_arguments(['--standalone','--require-commit','a'*40])
        self.assertTrue(args.standalone);self.assertFalse(args.compile_only)
        for args in ([],['--standalone'],['--standalone','--require-commit','a'*40,'--compile-only'],['--standalone','--require-commit','a'*40,'--core','/tmp/core'],['--core','/tmp/core','--require-commit','a'*40]):
            with self.subTest(args=args),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):G.parse_arguments(args)
        self.assertTrue(G.parse_arguments(['--core','/tmp/core','--compile-only']).compile_only)

    def test_required_workflow_and_exact_omission_controls(self):
        raw=(P.parents[1]/'.github/workflows/server-node-chain-encrypted.yml').read_text()
        required_workflow(raw)
        runner='python3 deploy/test_server_node_chain_connect_encrypted_runner.py'
        command='python3 deploy/test_server_node_chain_connect_encrypted.py --standalone'
        mutants=[
          raw.replace(runner,'true'),
          raw.replace(command,'true # omitted'),
          raw.replace(command,command+' --compile-only'),
          raw.replace('--require-commit "$ROUTERVPN_EXPECTED_SOURCE" --receipt "$ROUTERVPN_CONNECT_SERVER_RECEIPT"','--require-commit foreign --receipt "$ROUTERVPN_CONNECT_SERVER_RECEIPT"'),
          raw.replace('        run: '+runner,'        if: false\n        run: '+runner),
          raw.replace(command,command+' || true'),
          raw.replace('          - arch: arm64\n            runner: ubuntu-24.04-arm\n',''),
          raw.replace('            ${{ runner.temp }}/server-connect-node-chain-${{ matrix.arch }}.json\n',''),
          raw.replace("      - 'mobile/chain/**'\n",'',1),
          raw.replace('    timeout-minutes: 105','    timeout-minutes: 104'),
          raw.replace("          CGO_ENABLED: '1'","          CGO_ENABLED: '0'"),
        ]
        for index,mutant in enumerate(mutants):
            with self.subTest(control=index),self.assertRaises(ValueError):required_workflow(mutant)

    def test_complete_prefix_receipts_refuse_missing_or_foreign_evidence(self):
        for case in G.CASES:
            if case.split('/')[1] not in G.PREFIX_MODES:continue
            baseline=transcript(case)
            for fault in ('missing','wrong-mode','missing-packet','missing-proof','foreign-count','boolean-counter','invented-proof'):
                rows=baseline.splitlines()
                position=next(i for i,row in enumerate(rows) if 'CONNECT_SERVER_RECEIPT ' in row)
                value=json.loads(rows[position].split('CONNECT_SERVER_RECEIPT ',1)[1])
                if fault=='missing':del value['prefix_packets']
                elif fault=='wrong-mode':value['prefix_modes'][0]='foreign'
                elif fault=='missing-packet':value['prefix_packets'][0]=0
                elif fault=='missing-proof':value['prefix_proofs']=[]
                elif fault=='foreign-count':value['prefix_modes'].append('wg')
                elif fault=='boolean-counter':value['prefix_packets'][0]=True
                elif fault=='invented-proof':
                    if 'wrong-first-packet-key' not in case:continue
                    value['prefix_proofs'][0]=1
                rows[position]='    fixture.go:17: CONNECT_SERVER_RECEIPT '+json.dumps(value)
                with self.subTest(case=case,fault=fault),self.assertRaises(ValueError):G.check_verdict('\n'.join(rows)+'\n',case)

    def test_cases_are_exact_additive_family(self):
        original_connect=tuple(protocol+'/'+fault for protocol in ('http-connect','https-connect') for fault in ('original','wrong-middle-key','wrong-final-key','wrong-final-identity','failed-selected-dns','wrong-public-identity','joined-active-udp','admission-restrictions'))+('https-connect/wrong-proxy-name',)
        prefix_connect=tuple(protocol+'/'+fault for protocol in ('http-connect','https-connect') for fault in ('prefix-wg-one','prefix-awg-one','prefix-max-five','prefix-wrong-middle-key','prefix-wrong-final-key','prefix-wrong-first-packet-key','prefix-wrong-later-packet-key'))
        self.assertEqual(G.ORIGINAL_CASES,original_connect)
        self.assertEqual(G.CASES,original_connect+prefix_connect)
        self.assertEqual(len(G.CASES),len(set(G.CASES)))
        self.assertEqual(G.BASE.CASES,('wg','awg-fast','awg-strong','mixed-three','wrong-first-key','wrong-middle-key','wrong-ss-key','wrong-awg-parameters','wrong-node','failed-selected-dns','wrong-public-trust','cancel-prefix','admission-restrictions','joined-active-udp'))
        original=('original','wrong-middle-key','wrong-final-key','wrong-final-identity','failed-selected-dns','wrong-public-identity','joined-active-udp','admission-restrictions')
        prefixes=('prefix-original','prefix-wrong-middle-key','prefix-wrong-final-key','prefix-wrong-final-identity','prefix-failed-selected-dns','prefix-wrong-public-identity','prefix-joined-active-udp','prefix-admission-restrictions','prefix-wg-one','prefix-awg-fast','prefix-awg-strong','prefix-max-five','prefix-wrong-first-packet-key','prefix-wrong-later-packet-key')
        hostnames=('prefix-hostname-wg-one','prefix-hostname-awg-fast','prefix-hostname-awg-strong',
                   'prefix-hostname-max-five','prefix-hostname-wrong-transport-dns','prefix-hostname-wrong-middle-key',
                   'prefix-hostname-failed-selected-dns','prefix-hostname-joined-active-udp',
                   'prefix-hostname-wrong-first-packet-key','prefix-hostname-wrong-later-packet-key')
        self.assertEqual(G.BASE.IMPORTED_CASES,original+prefixes+hostnames)
        self.assertEqual(len(G.BASE.IMPORTED_CASES),len(set(G.BASE.IMPORTED_CASES)))

    def test_inherited_imported_inventory_rejects_omission_duplicate_and_foreign_cases(self):
        cases=G.BASE.IMPORTED_CASES
        mutants=[('original-only',cases[:8]),('without-hostname-cases',cases[:22]),('reordered',tuple(reversed(cases)))]
        for index,case in enumerate(cases):
            mutants.extend((
                ('missing-'+case,cases[:index]+cases[index+1:]),
                ('duplicate-'+case,cases[:index]+(case,)+cases[index:]),
                ('foreign-'+case,cases[:index]+('foreign-case',)+cases[index+1:]),
            ))
        for name,mutant in mutants:
            with self.subTest(control=name),patch.object(G.BASE,'IMPORTED_CASES',mutant),self.assertRaises(AssertionError):
                self.test_cases_are_exact_additive_family()

if __name__=='__main__':unittest.main()
