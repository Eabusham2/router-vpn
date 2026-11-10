#!/usr/bin/env python3
"""Require the completed native engine to parse every original WG/AWG desktop graph."""
import ast
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('imported_packet_build', ROOT/'deploy/build-native-runtime.py')
N = importlib.util.module_from_spec(spec)
spec.loader.exec_module(N)


class ImportedPacketRuntimeGate(unittest.TestCase):
    def events(self, target):
        _, names = N.imported_desktop_packet_verdicts(target)
        package = 'router-vpn/cmd/client'
        events = [{'Package':package,'Action':'start'}]
        def visit(name):
            events.append({'Package':package,'Action':'run','Test':name})
            children = {child for child in names if child.startswith(name+'/')}
            for child in sorted(children):
                if not any(child.startswith(parent+'/') for parent in children):
                    visit(child)
            events.append({'Package':package,'Action':'pass','Test':name})
        for root in sorted(name for name in names if '/' not in name):
            visit(root)
        return events + [{'Package':package,'Action':'pass'}]

    @staticmethod
    def output(events):
        return '\n'.join(json.dumps(event) for event in events)

    def test_exact_separate_inventory_and_every_required_verdict(self):
        expected_files = {entry+'--'+final+'--'+first+'--'+last+'.json'
            for entry in ('wireguard','amneziawg')
            for final in ('shadowsocks','hysteria2','wg','awg2-fast','awg2-strong','reality-vision')
            for first in ('off','aes-256-gcm','aes-256-gcm+xor-whitening')
            for last in ('off','aes-256-gcm','aes-256-gcm+xor-whitening')}
        self.assertEqual(N.IMPORTED_PACKET_FILES,expected_files)
        self.assertEqual(len(expected_files),108)
        # The packet extension must not reclassify or reduce the published gates.
        self.assertEqual(len(N.IMPORTED_DESKTOP_FILES),26)
        self.assertEqual(len(N.imported_native_dns_verdicts()),19)
        for target in N.TARGETS:
            roots,names = N.imported_desktop_packet_verdicts(target)
            self.assertEqual(len(names),185 if target.startswith('linux/') else 176)
            self.assertEqual(len(roots),7 if target.startswith('linux/') else 6)
            self.assertEqual(len(N.imported_desktop_verdicts(target)[1]),82 if target.startswith('linux/') else 78)
            verify = lambda events: N.verify_imported_native_verdicts(self.output(events),'router-vpn/cmd/client',names)
            events = self.events(target)
            verify(events)
            for index in range(len(events)):
                for changed in (events[:index]+events[index+1:],events[:index]+[events[index]]+events[index:]):
                    with self.subTest(target=target,index=index), self.assertRaises(ValueError): verify(changed)
            for action in ('skip','fail','build-fail','unknown'):
                changed = [dict(event) for event in events]
                changed[-2]['Action'] = action
                with self.assertRaises(ValueError): verify(changed)
            for changed in ([{'Package':'router-vpn/cmd/client','Action':'pass'}],
                    events+[{'Package':'foreign','Action':'pass'}],
                    events+[{'Package':'router-vpn/cmd/client','Action':'run','Test':'TestForeign'}],
                    events[:-1]+[{'Package':'router-vpn/cmd/client','Action':'output','Output':'WARNING: DATA RACE'}]+events[-1:]):
                with self.assertRaises(ValueError): verify(changed)
            # A protocol parent cannot finish while one of its proof children is active.
            parent = N.IMPORTED_PACKET_PROOF_TEST+'/wireguard'
            changed = [dict(event) for event in events]
            first = next(i for i,event in enumerate(changed) if event.get('Test') == parent and event['Action'] == 'run')
            changed.insert(first+1,{'Package':'router-vpn/cmd/client','Action':'pass','Test':parent})
            with self.assertRaises(ValueError): verify(changed)

    def exercise(self, target, fault='success'):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)/'completed-bundle'; bundle.mkdir()
            binary = bundle/N.binary_name(target); binary.write_bytes(b'complete production core')
            env = {'GOOS':target.split('/')[0],'GOARCH':target.split('/')[1],'CAPTURED_ORIGINAL':'1'}
            calls,fixtures = [],[]
            def run(command, **options):
                command = list(map(str,command)); calls.append((command,options))
                if command[:2] == ['go','test']:
                    roots,_ = N.imported_desktop_packet_verdicts(target)
                    self.assertEqual(command,['go','test','-json',*([] if target == 'windows/arm64' else ['-race']),
                        './cmd/client','-run','^('+'|'.join(roots)+')$','-count=1','-timeout=60s'])
                    self.assertEqual(options['cwd'],ROOT)
                    self.assertEqual(options['timeout'],300)
                    self.assertEqual(options['env']['CAPTURED_ORIGINAL'],'1')
                    self.assertEqual(options['env'].get('ROUTERVPN_REQUIRE_IMPORTED_DESKTOP_LIFECYCLE'),
                        '1' if target.startswith('linux/') else None)
                    directory = Path(options['env']['ROUTERVPN_IMPORTED_DESKTOP_PACKET_FIXTURES'])
                    self.assertTrue(directory.is_dir()); self.assertEqual(list(directory.iterdir()),[])
                    fixtures.append(directory)
                    for name in N.IMPORTED_PACKET_FILES: (directory/name).write_bytes(('original:'+name).encode())
                    path = directory/next(iter(N.IMPORTED_PACKET_FILES))
                    if fault == 'missing-file': path.unlink()
                    if fault == 'foreign-file': (directory/'foreign.json').write_bytes(b'foreign')
                    if fault == 'linked-file': path.unlink(); path.symlink_to(binary)
                    if fault == 'producer-failure': raise subprocess.CalledProcessError(7,command)
                    if fault == 'producer-timeout': raise subprocess.TimeoutExpired(command,300)
                    events = self.events(target)
                    if fault == 'missing-verdict': events.pop(-2)
                    if fault == 'skipped-verdict': events[-2]['Action'] = 'skip'
                    if fault == 'failed-verdict': events[-2]['Action'] = 'fail'
                    return self.output(events)
                self.assertEqual(command[:3],[str(binary),'check','-c'])
                self.assertEqual(options,{'env':env,'timeout':20})
                self.assertEqual(Path(command[3]).read_bytes(),('original:'+Path(command[3]).name).encode())
                if fault == 'parser-failure': raise subprocess.CalledProcessError(8,command)
                if fault == 'parser-timeout': raise subprocess.TimeoutExpired(command,20)
                if fault == 'changed-file': Path(command[3]).write_bytes(b'replaced after parsing')
                return ''
            def reuse(directory,actual,**options):
                self.assertEqual((directory,actual,options),(bundle,target,{'env':env}))
                return {'captured':'replaced' if calls and fault == 'bundle-change' else 'original'}
            with patch.object(N,'native_host_target',return_value=target),patch.object(N,'run',side_effect=run), \
                 patch.object(N,'reuse',side_effect=reuse) as retained,patch('builtins.print'):
                if fault == 'success': N.verify_imported_desktop_packet_configs(bundle,target,env)
                else:
                    with self.assertRaises((ValueError,subprocess.CalledProcessError,subprocess.TimeoutExpired)):
                        N.verify_imported_desktop_packet_configs(bundle,target,env)
            self.assertEqual(env,{'GOOS':target.split('/')[0],'GOARCH':target.split('/')[1],'CAPTURED_ORIGINAL':'1'})
            self.assertEqual(len(fixtures),1)
            self.assertFalse(fixtures[0].exists())
            if fault in ('success','bundle-change'):
                self.assertEqual(len(calls),109)
                self.assertEqual(retained.call_count,2)
                self.assertEqual({Path(command[3]).name for command,_ in calls[1:]},N.IMPORTED_PACKET_FILES)
            elif fault in ('missing-file','foreign-file','linked-file','producer-failure','producer-timeout',
                           'missing-verdict','skipped-verdict','failed-verdict'):
                self.assertEqual(len(calls),1)
                self.assertEqual(retained.call_count,1)

    def test_all_matching_platforms_parse_every_original_export(self):
        for target in N.TARGETS:
            with self.subTest(target=target): self.exercise(target)

    def test_incomplete_changed_failed_or_timed_out_evidence_blocks_success(self):
        for fault in ('missing-file','foreign-file','linked-file','producer-failure','producer-timeout',
                      'missing-verdict','skipped-verdict','failed-verdict','parser-failure','parser-timeout',
                      'changed-file','bundle-change'):
            with self.subTest(fault=fault): self.exercise('linux/amd64',fault)

    def test_matching_completed_bundle_precedes_execution(self):
        with patch.object(N,'native_host_target',return_value='linux/amd64'),patch.object(N,'run') as run,patch.object(N,'reuse') as reuse:
            for target,env in (('linux/arm64',{'GOOS':'linux','GOARCH':'arm64'}),
                    ('linux/amd64',{'GOOS':'linux','GOARCH':'arm64'}),('windows/amd64',{'GOOS':'windows','GOARCH':'amd64'})):
                with self.assertRaises(ValueError): N.verify_imported_desktop_packet_configs(Path('bundle'),target,env)
            reuse.assert_not_called(); run.assert_not_called()
            reuse.side_effect = ValueError('incomplete original production bundle')
            with self.assertRaisesRegex(ValueError,'incomplete original production bundle'):
                N.verify_imported_desktop_packet_configs(Path('bundle'),'linux/amd64',{'GOOS':'linux','GOARCH':'amd64'})
            run.assert_not_called()

    def test_actual_fresh_build_requires_packet_gate_after_original_gate(self):
        tree = ast.parse((ROOT/'deploy/build-native-runtime.py').read_text())
        build = next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name == 'build')
        native = next(node for node in ast.walk(build) if isinstance(node,ast.With) and any(
            isinstance(child,ast.Assign) and any(isinstance(target,ast.Name) and target.id == 'ldflags' for target in child.targets)
            for child in node.body))
        start = next(i for i,node in enumerate(native.body) if isinstance(node,ast.If) and isinstance(node.test,ast.Compare)
            and isinstance(node.test.left,ast.Name) and node.test.left.id == 'target' and any(
                isinstance(child,ast.Call) and isinstance(child.func,ast.Name) and child.func.id == 'verify_imported_desktop_configs'
                for child in ast.walk(node)))
        tail = ast.fix_missing_locations(ast.Module(body=copy.deepcopy(native.body[start:]),type_ignores=[]))
        class RequiredFailure(Exception): pass
        for target in N.TARGETS:
            for failure in (None,RequiredFailure('packet gate failed'),subprocess.TimeoutExpired(['packet-gate'],300)):
                with self.subTest(target=target,failure=type(failure).__name__),tempfile.TemporaryDirectory() as temporary:
                    stage = Path(temporary)/'stage'; stage.mkdir()
                    destination = Path(temporary)/'published'
                    calls = []
                    def original(*args): calls.append(('original',args))
                    def packet(*args):
                        calls.append(('packet',args))
                        if failure is not None: raise failure
                    def installed(*args): calls.append(('installed',args))
                    def run(command,**options): return 'sing-box version original\n' if command[-1] == 'version' else '--runtime-dir --session'
                    env = {'captured':'original'}
                    namespace = dict(target=target,host=target,stage=stage,destination=destination,binary=stage/N.binary_name(target),
                        policy='policy',marker=lambda _: 'original',source=Path('prepared-core'),env=env,run=run,os=N.os,
                        verify_imported_desktop_configs=original,verify_imported_desktop_packet_configs=packet,verify_imported_desktop_openvpn_configs=lambda *args: None,
                        verify_imported_desktop_pq_configs=lambda *args: None, verify_imported_desktop_xhttp_configs=lambda *args: None, verify_imported_desktop_naive_h2_configs=lambda *args: None, verify_imported_desktop_naive_h3_configs=lambda *args: None,
                        verify_installed_linux_host=installed,verify_installed_darwin_host=installed)
                    if failure is None: exec(compile(tail,'actual completed native build tail','exec'),namespace)
                    else:
                        with self.assertRaises(type(failure)): exec(compile(tail,'actual completed native build tail','exec'),namespace)
                    self.assertEqual(calls[:2],[('original',(stage,target,env)),('packet',(stage,target,env))])
                    self.assertEqual(destination.exists(),failure is None)
                    self.assertEqual(stage.exists(),failure is not None)
                    self.assertEqual(len(calls),3 if failure is None and target.startswith(('linux/','darwin/')) else 2)
        self.assertIn(ROOT/'deploy/test_desktop_imported_packet_runtime.py',N.inputs())

    def test_reused_bundle_cannot_report_success_before_packet_gate(self):
        for target in N.TARGETS:
            for failure in (None,ValueError('original packet verdict missing'),subprocess.CalledProcessError(7,['packet-gate']),
                            subprocess.TimeoutExpired(['packet-gate'],300)):
                with self.subTest(target=target,failure=type(failure).__name__),tempfile.TemporaryDirectory() as temporary:
                    bundle = Path(temporary)/'bundle'; bundle.mkdir(); (bundle/'retained').write_bytes(b'original complete bundle')
                    env = {'GOOS':target.split('/')[0],'GOARCH':target.split('/')[1]}
                    calls,stdout = [],io.StringIO()
                    def original(*args): calls.append(('original',args))
                    def packet(*args):
                        calls.append(('packet',args))
                        if failure is not None: raise failure
                    with patch.object(N,'environment',return_value=env),patch.object(N,'digest',return_value='original'), \
                         patch.object(N,'reuse',return_value={'captured':'receipt'}) as receipt,patch.object(N,'native_host_target',return_value=target), \
                         patch.object(N,'verify_linux_stock_dns'),patch.object(N,'verify_installed_darwin_host'), \
                         patch.object(N.DNSSEC,'test_native_bundle'),patch.object(N,'run') as run, \
                         patch.object(N,'verify_imported_desktop_configs',side_effect=original), \
                         patch.object(N,'verify_imported_desktop_packet_configs',side_effect=packet),patch.object(N,'verify_imported_desktop_openvpn_configs'), \
                         patch.object(N,'verify_imported_desktop_naive_h2_configs'), patch.object(N, 'verify_imported_desktop_naive_h3_configs'), patch.object(N,'verify_imported_desktop_xhttp_configs'), patch.object(N,'verify_imported_desktop_pq_configs'),contextlib.redirect_stdout(stdout):
                        if failure is None: self.assertEqual(N.build(target,bundle),bundle)
                        else:
                            with self.assertRaises(type(failure)) as caught: N.build(target,bundle)
                            self.assertIs(caught.exception,failure)
                    self.assertEqual(calls,[('original',(bundle,target,env)),('packet',(bundle,target,env))])
                    receipt.assert_called_once_with(bundle,target,'original',env)
                    run.assert_not_called()
                    self.assertEqual('Reused verified complete native runtime' in stdout.getvalue(),failure is None)
                    self.assertEqual((bundle/'retained').read_bytes(),b'original complete bundle')


if __name__ == '__main__':
    unittest.main()
