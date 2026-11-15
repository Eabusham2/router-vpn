#!/usr/bin/env python3
"""Strict independent-layer source, native receipt and preparation controls."""
from pathlib import Path
import importlib.util
import inspect
import json
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('layer_gate',ROOT/'deploy/test_macos_imported_execution_layers_host.py')
G=importlib.util.module_from_spec(spec); spec.loader.exec_module(G)

def observation(case):
    _,_,entry,final,_,_,fault=G.VECTORS[G.CASES.index(case)]
    def transport():
        return dict(method='2022-blake3-aes-256-gcm',address='192.0.2.20:8389',physical_tcp=1,physical_udp=1,streams=1,packets=1,public_replies=0,auth_tcp=0,auth_udp=0)
    layers=dict(entry=entry,final=final,final_transport=transport())
    if entry!='off': layers['entry_transport']=transport()
    value=dict(case=case,entry=entry,final=final,fault=fault,layers=layers,launches=1,entry_packets=1,entry_proofs=1,middle_public=1,final_proofs=1,dns=1)
    if fault.startswith('entry-'):
        layers['entry_transport'].update(auth_udp=1,packets=0)
        for key in ('launches','entry_packets','entry_proofs','middle_public','final_proofs','dns'): value[key]=0
    elif fault.startswith('final-'):
        layers['final_transport'].update(auth_tcp=1,streams=0); value.update(final_proofs=0,dns=0)
    return value

def output(case,value=None):
    return '\n'.join(('=== RUN   '+G.TEST,'=== RUN   '+G.TEST+'/'+case,
        '    desktop_imported_execution_layers_darwin_native_test.go:120: DARWIN_IMPORTED_EXECUTION_LAYERS '+json.dumps(observation(case) if value is None else value),
        '    desktop_imported_execution_darwin_native_test.go:610: '+G.receipt(case),
        '--- PASS: '+G.TEST+' (1.00s)','    --- PASS: '+G.TEST+'/'+case+' (1.00s)','PASS',''))

class IndependentDarwinLayers(unittest.TestCase):
    def test_exact_native14_source54_and_old13(self):
        self.assertEqual(G.case_inventory(),G.CASES)
        self.assertEqual(len(G.CASES),14)
        self.assertEqual(sum(len(x)+1 for x in G.SOURCE_TESTS.values()),55)
        self.assertEqual(len(G.ORIGINAL.case_inventory()),13)
        for case in G.CASES: G.check_verdict(output(case),case)
        self.assertEqual({row[2:4] for row in G.VECTORS[:8]},set((a,b) for a in G.LAYERS for b in G.LAYERS)-{('off','off')})
    def test_source_omission_and_changed_choices(self):
        source=(ROOT/G.LAYER_SOURCE).read_text()
        for before,after in (('"awg2-fast-off-aes-auto-server"','"foreign"'),('"entry-layer-key"','""'),('"aes-256-gcm"','"off"')):
            with self.subTest(before=before),self.assertRaises(ValueError): G.case_inventory(source.replace(before,after,1))
    def test_receipt_ownership_and_case(self):
        for case in G.CASES:
            for field in ('native_joined=true','relay_joined=true','aliases_retired=true'):
                with self.subTest(case=case,field=field),self.assertRaises(ValueError):
                    G.check_verdict(output(case).replace(field,field.replace('true','false')),case)
        case=G.CASES[0]
        for replacement in ('',G.receipt(G.CASES[1]),G.receipt(case)+'\n    desktop_imported_execution_darwin_native_test.go:611: '+G.receipt(case)):
            with self.assertRaises(ValueError): G.check_verdict(output(case).replace(G.receipt(case),replacement),case)
        with self.assertRaises(ValueError): G.check_verdict(output(case).replace('restored=true','restored=false'),case)
    def test_positive_proofs_are_actual(self):
        for case in G.CASES[:8]:
            for field in ('launches','entry_packets','entry_proofs','middle_public','final_proofs','dns'):
                value=observation(case); value[field]=0
                with self.subTest(case=case,field=field),self.assertRaises(ValueError): G.check_verdict(output(case,value),case)
    def test_negative_authentication_boundary(self):
        for case in G.CASES[8:]:
            value=observation(case); entry=value['fault'].startswith('entry-')
            value['layers']['entry_transport' if entry else 'final_transport']['auth_udp' if entry else 'auth_tcp']=0
            with self.subTest(case=case),self.assertRaises(ValueError): G.check_verdict(output(case,value),case)
            value=observation(case); value['dns']=1
            with self.assertRaises(ValueError): G.check_verdict(output(case,value),case)
    def test_transport_and_independent_source_required(self):
        for case in G.CASES:
            value=observation(case); value['layers']['final_transport']['method']='none'
            with self.assertRaises(ValueError): G.check_verdict(output(case,value),case)
            value=observation(case); value['entry']=G.LAYERS[(G.LAYERS.index(value['entry'])+1)%3]
            with self.assertRaises(ValueError): G.check_verdict(output(case,value),case)
        case=G.CASES[0]; value=observation(case); value['layers']['entry_transport']=value['layers']['final_transport']
        with self.assertRaises(ValueError): G.check_verdict(output(case,value),case)
    def test_duplicate_unknown_bool_counters(self):
        case=G.CASES[0]
        with self.assertRaises(ValueError): G.check_verdict(output(case).replace('"launches": 1','"launches": 1, "launches": 1'),case)
        for mutate in (lambda v:v.update(foreign=1),lambda v:v.update(launches=True)):
            value=observation(case); mutate(value)
            with self.assertRaises(ValueError): G.check_verdict(output(case,value),case)
    def test_exact_running_verdict(self):
        case=G.CASES[0]; original=output(case)
        for changed in (original.replace('--- PASS:','--- FAIL:',1),original+'WARNING: DATA RACE\n',original+'--- SKIP: foreign (0.00s)\n',original.replace('    --- PASS: '+G.TEST+'/'+case+' (1.00s)\n','')):
            with self.assertRaises(ValueError): G.check_verdict(changed,case)
        lines=original.splitlines(); line=lines.pop(2); lines.insert(-1,line)
        with self.assertRaises(ValueError): G.check_verdict('\n'.join(lines)+'\n',case)
    def test_own_flag_and_fake_refusal(self):
        env={G.FLAG:'1'}
        with patch.object(G.EXTERNAL,'required_host',return_value=('darwin/arm64',501)) as host:
            self.assertEqual(G.required_host(env),('darwin/arm64',501)); self.assertEqual(host.call_args.args[0][G.EXTERNAL.FLAG],'1')
        self.assertEqual(env,{G.FLAG:'1'})
        for env in ({},{G.ORIGINAL.FLAG:'1'},{G.FLAG:'0'},{G.FLAG:'1','HOMEVPN_MTU_BENCH_FAKE':'1'}):
            with self.assertRaises(ValueError): G.required_host(env)
    def test_actual_repeatable_preparation(self):
        prep=G.load('layer_prep','prepare-desktop-external.py')
        with tempfile.TemporaryDirectory() as folder:
            core=Path(folder); prep.copy_encrypted_peer_templates(core)
            self.assertEqual((core/G.PEER_TARGET).read_bytes(),(ROOT/G.PEER_TEMPLATE).read_bytes())
            before={str(f.relative_to(core)):f.read_bytes() for f in core.rglob('*.go')}
            prep.copy_encrypted_peer_templates(core)
            self.assertEqual(before,{str(f.relative_to(core)):f.read_bytes() for f in core.rglob('*.go')})
            for name in ('node_imported_peer_linux_test.go.tmpl','node_chain_imported_test.go.tmpl'):
                self.assertEqual((core/prep.PEER_TEMPLATES[name]).read_bytes(),(ROOT/'mobile/desktop'/name).read_bytes())
                self.assertEqual((core/prep.DARWIN_NODE_CHAIN_PEERS[name]).read_bytes(),prep.darwin_node_chain_peer_copies()[prep.DARWIN_NODE_CHAIN_PEERS[name]])
    def test_original_clocks_and_identity_rechecks(self):
        code=inspect.getsource(G.execute)
        for value in ("'-test.timeout=120s'",'timeout=130',"'-test.timeout=240s'",'timeout=250','timeout=300','source_identity(core) != before','BASE.repository_identity(required_commit) != repository','EXTERNAL.sha(path) != images[name]','alias.execute(root=ROOT, go=str(race_compiler))','runner.execute_peer_close_controls(ROOT, str(race_compiler), race_environment)'):
            self.assertIn(value,code)
        self.assertLess(code.index('alias.execute('),code.index("signed = work/'sealed-bundle'"))
        self.assertEqual(code.count('for case in CASES:'),1)
if __name__=='__main__': unittest.main()
