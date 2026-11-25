#!/usr/bin/env python3
"""Strict orchestration and inventory checks; synthetic records are not native acceptance."""
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('connected_encrypted_driver',ROOT/'deploy/test_typed_connected_candidates_native.py');D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D);V=D.PARTITIONS

def rows(family,case):
    names=V.names(family,case)
    return [dict(Action='start',Package=D.BASE.LIBBOX)]+[dict(Action='run',Package=D.BASE.LIBBOX,Test=x) for x in names]+[dict(Action='pass',Package=D.BASE.LIBBOX,Test=x) for x in reversed(names)]+[dict(Action='pass',Package=D.BASE.LIBBOX)]
def encode(events):return ('\n'.join(json.dumps(x) for x in events)+'\n').encode()

class ConnectedEncryptedRunner(unittest.TestCase):
    def exercise(self,family,fault=None):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);peer=work/'peer';client=work/'client';peer.write_bytes(b'original-peer');client.write_bytes(b'original-client');calls=[]
            base=types.SimpleNamespace(LIBBOX=D.BASE.LIBBOX,require_events=D.BASE.require_events,COMMON=types.SimpleNamespace(image_identity=lambda p:Path(p).read_bytes()))
            original={'ROUTERVPN_'+family+'_RUN_CASE':'old','ROUTERVPN_'+family+'_PREFIX_CASE':'old','ordinary':'retained'}
            def run(name,cmd,cwd,bound,env):
                case=env['ROUTERVPN_'+family+'_CONNECTED_CANDIDATE'];names=V.names(family,case);calls.append(case)
                self.assertEqual(name,'connected-candidate-'+case.replace('/','-'));self.assertEqual(bound,190);self.assertIn('-test.timeout=180s',cmd);self.assertIn('-test.run=^'+names[0]+'$',cmd);self.assertEqual(env['ordinary'],'retained');self.assertNotIn('ROUTERVPN_'+family+'_RUN_CASE',env);self.assertNotIn('ROUTERVPN_'+family+'_PREFIX_CASE',env)
                data=rows(family,case);code=0
                if fault=='terminal':data.pop()
                elif fault=='child':data=[x for x in data if x.get('Test')!=names[1]]
                elif fault=='duplicate':data.insert(2,dict(data[1]))
                elif fault=='foreign':data[2]['Test']='foreign'
                elif fault=='skip':data[3]['Action']='skip'
                elif fault=='failed':code=1
                elif fault=='timeout':code=124
                elif fault=='image':peer.write_bytes(b'foreign')
                return code,encode(data)
            result=V.validate(base,run,'pinned-go',work,peer,client,original,family)
            self.assertEqual(calls,list(V.CASES[family]));self.assertEqual(original['ROUTERVPN_'+family+'_RUN_CASE'],'old');return result
    def test_exact_nine_original_cases_and_budget(self):
        self.assertEqual(V.CASES,{'SOCKS':('3','4','8'),'CONNECT':tuple(f'{p}/{n}' for p in ('http-connect','https-connect') for n in (3,4,8))})
        for family in V.CASES:
            result=self.exercise(family);self.assertTrue(result['connected_candidate_tcp_fifty_accepted']);self.assertFalse(result['connected_candidate_replacement_authentication_accepted']);self.assertFalse(result['connected_candidate_installed_host_accepted'])
    def test_every_phase_refuses_missing_failed_foreign_or_changed_image(self):
        for family in V.CASES:
            for fault in ('terminal','child','duplicate','foreign','skip','failed','timeout','image'):
                with self.subTest(family=family,fault=fault),self.assertRaises(ValueError):self.exercise(family,fault)
    def test_no_arbitrary_family_or_case_filter(self):
        for family,case in (('','3'),('SOCKS','9'),('CONNECT','3'),('CONNECT','http-connect/5'),('socks','3')):
            with self.assertRaises(ValueError):V.names(family,case)
    def test_actual_projection_identity(self):
        for fault in (None,'mapping','bytes','source-link','native-link'):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);source=root/'source';core=root/'core';a=source/'mobile/chain'/V.TEMPLATE;b=core/V.PROJECTION;a.parent.mkdir(parents=True);b.parent.mkdir(parents=True);a.write_bytes((ROOT/'mobile/chain'/V.TEMPLATE).read_bytes());b.write_bytes(a.read_bytes());table={V.TEMPLATE:V.PROJECTION}
                if fault=='mapping':table.clear()
                elif fault=='bytes':b.write_bytes(b'foreign')
                elif fault=='source-link':a.unlink();a.symlink_to(b)
                elif fault=='native-link':b.unlink();b.symlink_to(a)
                if fault:
                    with self.assertRaises(ValueError):V.projection(source,core,table)
                else:V.projection(source,core,table)
    def test_required_release_matrix_is_separate(self):
        source=(ROOT/'.github/workflows/typed-connected-candidates.yml').read_text();release=(ROOT/'.github/workflows/release-candidate.yml').read_text();V.workflow_contract(source,release)
        for old,new in (("  workflow_call:\n",""),("        family: [SOCKS, CONNECT]","        family: [SOCKS]"),("    timeout-minutes: 75","    timeout-minutes: 90"),("      fail-fast: false","      fail-fast: true"),("  encrypted:\n","  encrypted:\n    if: false\n"),("--require-commit \"$GITHUB_SHA\"","--require-commit main")):
            self.assertEqual(source.count(old),1)
            with self.subTest(old=old),self.assertRaises(ValueError):V.workflow_contract(source.replace(old,new,1),release)
        for old,new in (("needs: [typed-connected-candidates, ","needs: ["),("    uses: ./.github/workflows/typed-connected-candidates.yml","    uses: ./.github/workflows/focused-source-validation.yml"),("  typed-connected-candidates:\n","  typed-connected-candidates:\n    if: false\n")):
            self.assertEqual(release.count(old),1)
            with self.subTest(old=old),self.assertRaises(ValueError):V.workflow_contract(source,release.replace(old,new,1))
    def test_accounting_and_payload_control_are_mandatory(self):
        for fault in (None,'missing','duplicate','skip','baseline-exit','control-exit','control-witness','changed-peer'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);peer=root/'peer';peer.write_bytes(b'original');target=root/V.ACCOUNTING_TARGET;target.parent.mkdir(parents=True);target.write_text((ROOT/V.ACCOUNTING_TEMPLATE).read_text());calls=[]
                def run(name,cmd,cwd,bound,env):
                    calls.append(name)
                    if name.endswith('build'):
                        self.assertEqual(bound,600);self.assertIn('-race',cmd);self.assertNotIn('-vet=off',cmd);return 0,b''
                    self.assertEqual(bound,45);self.assertIn('-test.timeout=30s',cmd)
                    negative=name.endswith('control');names=[V.ACCOUNTING_ROOT]+[V.ACCOUNTING_ROOT+'/'+leaf for leaf in (('payload',) if negative else V.ACCOUNTING_LEAVES)];package=D.BASE.OWNER.PACKAGE
                    data=[dict(Action='start',Package=package)]+[dict(Action='run',Package=package,Test=x) for x in names]
                    if negative:data.append(dict(Action='output',Package=package,Test=names[-1],Output=V.ACCOUNTING_WITNESS if fault!='control-witness' else 'other failure'))
                    data += [dict(Action='fail' if negative else 'pass',Package=package,Test=x) for x in reversed(names)]+[dict(Action='fail' if negative else 'pass',Package=package)]
                    if not negative and fault=='missing':data.pop()
                    if not negative and fault=='duplicate':data.insert(2,dict(data[1]))
                    if not negative and fault=='skip':data[-2]['Action']='skip'
                    if negative and fault=='changed-peer':peer.write_bytes(b'foreign')
                    return (124 if fault==('control-exit' if negative else 'baseline-exit') else 1 if negative else 0),encode(data)
                if fault:
                    with self.assertRaises(ValueError):V.accounting(D.BASE,run,'pinned-go',root,peer,{},root/'work')
                else:
                    self.assertEqual(V.accounting(D.BASE,run,'pinned-go',root,peer,{},root/'work')['records'],10)
                    self.assertEqual(calls,['peer-accounting','peer-accounting-control-build','peer-accounting-control'])

    def test_original_complete_proof_and_fifty_witnesses_remain(self):
        source=(ROOT/'mobile/chain/typed_candidates_run_test.go.tmpl').read_text()
        for family in ('SOCKS','CONNECT'):
            self.assertIn('TestRouterNodeChain'+family+'ConnectedCandidateEncrypted',source)
        for text in ('f.owner.Run(f.server)','progress.DNSProven','progress.PublicProven','Benchmark.Attempts != 50','Distribution.Samples != 50','candidate fifty bypassed original encrypted packet prefix','copied connected candidate handle started traffic','changed live catalog admitted candidate'):
            self.assertIn(text,source)
if __name__=='__main__':unittest.main()
