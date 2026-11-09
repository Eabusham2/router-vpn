#!/usr/bin/env python3
"""Require complete native packages to parse the original imported desktop graphs."""
import ast
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('imported_desktop_build', ROOT/'deploy/build-native-runtime.py')
N = importlib.util.module_from_spec(spec)
spec.loader.exec_module(N)


class ImportedDesktopRuntimeGate(unittest.TestCase):
    @staticmethod
    def inventory_events(package, names):
        events = [{'Package':package,'Action':'start'}]
        for root in sorted(name for name in names if '/' not in name):
            events.append({'Package':package,'Action':'run','Test':root})
            for name in sorted(name for name in names if name.startswith(root+'/')):
                events.extend({'Package':package,'Action':action,'Test':name} for action in ('run','pass'))
            events.append({'Package':package,'Action':'pass','Test':root})
        return events + [{'Package':package,'Action':'pass'}]

    def events(self, target):
        _, names = N.imported_desktop_verdicts(target)
        return self.inventory_events('router-vpn/cmd/client', names)

    def output(self, events):
        return '\n'.join(json.dumps(event) for event in events)

    def test_all_platform_roots_and_each_original_leaf_are_required(self):
        self.assertEqual(len(N.IMPORTED_DESKTOP_FILES),26)
        self.assertEqual(len(N.IMPORTED_DESKTOP_PAIRS),18)
        self.assertNotIn('socks5--shadowsocks.json',N.IMPORTED_DESKTOP_FILES)
        for target in N.TARGETS:
            _, names = N.imported_desktop_verdicts(target)
            self.assertEqual(len(names),82 if target.startswith('linux/') else 78)
            self.assertEqual({name.removeprefix('TestDesktopImportedDNSOperationDuration/') for name in names
                              if name.startswith('TestDesktopImportedDNSOperationDuration/')},
                             {operation+'/'+fault for operation in ('dns','observe') for fault in
                              ('positive','zero','failed-zero','cancelled-zero','negative','nan','infinite','oversized','reader','foreign-operation')})
            events = self.events(target)
            N.verify_imported_desktop_verdicts(self.output(events),target)
            for index in range(len(events)):
                for mutation in (events[:index]+events[index+1:],events[:index]+[events[index]]+events[index:]):
                    with self.subTest(target=target,index=index), self.assertRaises(ValueError):
                        N.verify_imported_desktop_verdicts(self.output(mutation),target)
            for action in ('fail','skip','build-fail','unknown'):
                changed = [dict(event) for event in events]
                changed[-2]['Action'] = action
                with self.assertRaises(ValueError): N.verify_imported_desktop_verdicts(self.output(changed),target)
            for changed in ([{'Package':'router-vpn/cmd/client','Action':'pass'}],
                            events+[{'Package':'foreign','Action':'pass'}],
                            events+[{'Package':'router-vpn/cmd/client','Action':'pass','Test':'TestForeign'}],
                            events[:-1]+[{'Package':'router-vpn/cmd/client','Action':'output','Output':'WARNING: DATA RACE'}]+events[-1:]):
                with self.assertRaises(ValueError): N.verify_imported_desktop_verdicts(self.output(changed),target)
        for output in ('not-json','[]','{"Package":"router-vpn/cmd/client","Action":"start","Action":"pass"}'):
            with self.assertRaises(ValueError): N.verify_imported_desktop_verdicts(output,'linux/amd64')

    def exercise(self, target, fault='success'):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)/'completed-bundle'; bundle.mkdir()
            binary = bundle/N.binary_name(target); binary.write_bytes(b'complete production protocol engine')
            env = {'GOOS':target.split('/')[0],'GOARCH':target.split('/')[1],'CAPTURED_ORIGINAL':'1'}
            calls, fixtures = [], []
            receipt = {'source':'original','target':target,'full-production-tags':True}
            def run(command, **options):
                command = list(map(str,command)); calls.append((command,options))
                if command[:2] == ['go','test']:
                    self.assertEqual(options['cwd'],ROOT)
                    self.assertEqual(options['timeout'],300)
                    self.assertIn('-timeout=60s',command)
                    self.assertEqual('-race' in command,target!='windows/arm64')
                    self.assertEqual(options['env']['CAPTURED_ORIGINAL'],'1')
                    if target.startswith('linux/'):
                        self.assertEqual(options['env']['ROUTERVPN_REQUIRE_IMPORTED_DESKTOP_LIFECYCLE'],'1')
                    else:
                        self.assertNotIn('ROUTERVPN_REQUIRE_IMPORTED_DESKTOP_LIFECYCLE',options['env'])
                    directory = Path(options['env']['ROUTERVPN_IMPORTED_DESKTOP_FIXTURES'])
                    self.assertTrue(directory.is_dir()); self.assertEqual(list(directory.iterdir()),[])
                    fixtures.append(directory)
                    for name in N.IMPORTED_DESKTOP_FILES: (directory/name).write_bytes(('original:'+name).encode())
                    if fault == 'missing-file': (directory/next(iter(N.IMPORTED_DESKTOP_FILES))).unlink()
                    if fault == 'foreign-file': (directory/'foreign.json').write_bytes(b'foreign')
                    if fault == 'linked-file':
                        path = directory/next(iter(N.IMPORTED_DESKTOP_FILES)); path.unlink(); path.symlink_to(binary)
                    if fault == 'producer-failure': raise subprocess.CalledProcessError(9,command)
                    if fault == 'producer-timeout': raise subprocess.TimeoutExpired(command,300)
                    events = self.events(target)
                    if fault == 'skipped-lifecycle':
                        if target.startswith('linux/'):
                            for event in events:
                                if event.get('Test') == N.IMPORTED_DESKTOP_LIFECYCLE_TEST and event['Action'] == 'pass': event['Action']='skip'
                        else: events[-2]['Action']='skip'
                    return self.output(events)
                self.assertEqual(command[:3],[str(binary),'check','-c'])
                self.assertEqual(options,{'env':env,'timeout':20})
                self.assertEqual(Path(command[3]).read_bytes(),('original:'+Path(command[3]).name).encode())
                if fault == 'parser-failure': raise subprocess.CalledProcessError(5,command)
                if fault == 'parser-timeout': raise subprocess.TimeoutExpired(command,20)
                if fault == 'changed-file':
                    Path(command[3]).write_bytes(b'changed after original parsing')
                return ''
            def reuse(directory, actual, **options):
                self.assertEqual(directory,bundle)
                self.assertEqual(actual,target)
                self.assertEqual(options,{'env':env})
                if calls and fault == 'bundle-change': return {'source':'changed'}
                return receipt
            with patch.object(N,'native_host_target',return_value=target),patch.object(N,'run',side_effect=run), \
                 patch.object(N,'reuse',side_effect=reuse) as retained,patch('builtins.print'):
                if fault == 'success': N.verify_imported_desktop_configs(bundle,target,env)
                else:
                    with self.assertRaises((ValueError,subprocess.CalledProcessError,subprocess.TimeoutExpired)):
                        N.verify_imported_desktop_configs(bundle,target,env)
            self.assertEqual(env,{'GOOS':target.split('/')[0],'GOARCH':target.split('/')[1],'CAPTURED_ORIGINAL':'1'})
            self.assertEqual(len(fixtures),1)
            self.assertFalse(fixtures[0].exists())
            if fault in ('success','bundle-change'):
                self.assertEqual(len(calls),27)
                self.assertEqual(retained.call_count,2)
            elif fault in ('producer-failure','producer-timeout','missing-file','foreign-file','linked-file','skipped-lifecycle'):
                self.assertEqual(len(calls),1)

    def test_every_complete_native_platform_parses_all_twenty_six_actual_exports(self):
        for target in N.TARGETS:
            with self.subTest(target=target): self.exercise(target)

    def test_missing_changed_failed_skipped_or_timed_out_evidence_blocks_success(self):
        for fault in ('missing-file','foreign-file','linked-file','producer-failure','producer-timeout',
                      'skipped-lifecycle','parser-failure','parser-timeout','changed-file','bundle-change'):
            with self.subTest(fault=fault): self.exercise('linux/amd64',fault)

    def test_matching_target_and_complete_receipt_precede_any_source_or_parser_execution(self):
        with patch.object(N,'native_host_target',return_value='linux/amd64'),patch.object(N,'run') as run,patch.object(N,'reuse') as reuse:
            for target,env in (('linux/arm64',{'GOOS':'linux','GOARCH':'arm64'}),
                               ('linux/amd64',{'GOOS':'linux','GOARCH':'arm64'}),
                               ('windows/amd64',{'GOOS':'windows','GOARCH':'amd64'})):
                with self.assertRaises(ValueError): N.verify_imported_desktop_configs(Path('bundle'),target,env)
            run.assert_not_called(); reuse.assert_not_called()
            reuse.side_effect=ValueError('incomplete production bundle')
            with self.assertRaisesRegex(ValueError,'incomplete production bundle'):
                N.verify_imported_desktop_configs(Path('bundle'),'linux/amd64',{'GOOS':'linux','GOARCH':'amd64'})
            run.assert_not_called()

    def test_actual_fresh_build_gate_failure_prevents_host_acceptance_and_publication(self):
        tree=ast.parse((ROOT/'deploy/build-native-runtime.py').read_text())
        build=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='build')
        native=next(node for node in ast.walk(build) if isinstance(node,ast.With) and any(
            isinstance(child,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='ldflags' for target in child.targets)
            for child in node.body))
        start=next(i for i,node in enumerate(native.body) if isinstance(node,ast.If) and isinstance(node.test,ast.Compare)
            and isinstance(node.test.left,ast.Name) and node.test.left.id=='target' and any(
                isinstance(child,ast.Call) and isinstance(child.func,ast.Name) and child.func.id=='verify_imported_desktop_configs'
                for child in ast.walk(node)))
        tail=ast.fix_missing_locations(ast.Module(body=copy.deepcopy(native.body[start:]),type_ignores=[]))
        class RequiredFailure(Exception): pass
        for target in N.TARGETS:
            with self.subTest(target=target),tempfile.TemporaryDirectory() as temporary:
                stage=Path(temporary)/'stage';stage.mkdir()
                destination=Path(temporary)/'published'
                calls=[]
                def run(command,**options):
                    return 'sing-box version original\n' if command[-1]=='version' else '--runtime-dir --session'
                def gate(*args): calls.append(args); raise RequiredFailure('original imported native gate failed')
                namespace=dict(target=target,host=target,stage=stage,destination=destination,binary=stage/N.binary_name(target),
                    policy='policy',marker=lambda _: 'original',source=Path('prepared-core'),env={'original':'1'},run=run,
                    verify_imported_desktop_configs=gate,verify_installed_linux_host=lambda *a: self.fail('later Linux gate ran'),
                    verify_installed_darwin_host=lambda *a:self.fail('later Darwin gate ran'),os=N.os)
                with self.assertRaises(RequiredFailure):exec(compile(tail,'actual native build tail','exec'),namespace)
                self.assertEqual(calls,[(stage,target,{'original':'1'})])
                self.assertFalse(destination.exists())
                self.assertTrue(stage.is_dir())
        self.assertIn(ROOT/'deploy/test_desktop_imported_runtime.py',N.inputs())

    def native_events(self):
        return self.inventory_events(N.IMPORTED_NATIVE_DNS_PACKAGE, N.imported_native_dns_verdicts())

    def test_native_dns_requires_original_and_zero_tick_verdicts_and_joined_roots(self):
        expected = N.imported_native_dns_verdicts()
        self.assertEqual(len(expected),19)
        self.assertEqual({name for name in expected if not name.startswith('TestRouterVPNImportedDNSOperationDuration')},
                         {'TestRouterVPNImportedDNSMailbox','TestRouterVPNImportedDNSCancellationJoins','TestRouterVPNImportedDNSNativeRouterIsUncached'} |
                         {'TestRouterVPNImportedDNSMailbox/'+case for case in ('success','dns-failed','session','config','path','reader','deadline','replay','source-replaced','owner-replaced')})
        self.assertEqual({name.removeprefix('TestRouterVPNImportedDNSOperationDuration/') for name in expected
                          if name.startswith('TestRouterVPNImportedDNSOperationDuration/')},
                         {'observe','dns','dns-error','cancelled-dns','cancelled-observe'})
        events = self.native_events()
        verify = lambda rows: N.verify_imported_native_verdicts(self.output(rows),N.IMPORTED_NATIVE_DNS_PACKAGE,expected)
        verify(events)
        for index in range(len(events)):
            for changed in (events[:index]+events[index+1:],events[:index]+[events[index]]+events[index:]):
                with self.subTest(index=index), self.assertRaises(ValueError): verify(changed)
        for action in ('skip','fail','build-fail','unknown'):
            for name in expected:
                changed = [dict(event) for event in events]
                next(event for event in changed if event.get('Test') == name and event['Action'] == 'pass')['Action'] = action
                with self.subTest(name=name,action=action), self.assertRaises(ValueError): verify(changed)
        for changed in (
            events+[{'Package':'foreign','Action':'pass'}],
            events[:-1]+[{'Package':N.IMPORTED_NATIVE_DNS_PACKAGE,'Action':'output','Output':'WARNING: DATA RACE'}]+events[-1:],
            events[:-1]+[{'Package':N.IMPORTED_NATIVE_DNS_PACKAGE,'Action':'run','Test':'TestForeign'}]+events[-1:],
            events[1:]+events[:1],
        ):
            with self.assertRaises(ValueError): verify(changed)
        parent = N.IMPORTED_NATIVE_DNS_ROOTS[0]
        premature = [event for event in events if not (event.get('Test') == parent and event['Action'] == 'pass')]
        start = next(index for index,event in enumerate(premature) if event.get('Test') == parent and event['Action'] == 'run')
        premature.insert(start+1,{'Package':N.IMPORTED_NATIVE_DNS_PACKAGE,'Action':'pass','Test':parent})
        with self.assertRaises(ValueError): verify(premature)

    def test_native_dns_uses_full_production_tags_and_original_timeout_and_host(self):
        for target in N.TARGETS:
            for fault in ('success','missing','skip','failed-query','process-failure','timeout'):
                with self.subTest(target=target,fault=fault):
                    env = {'GOOS':target.split('/')[0],'GOARCH':target.split('/')[1],
                           'CGO_LDFLAGS':'-L/original-pq -lroutervpn_rosenpass','ORIGINAL_CALLER':'1'}
                    before = env.copy()
                    events = self.native_events()
                    if fault == 'missing': events = [event for event in events if event.get('Test') != N.IMPORTED_NATIVE_DNS_ROOTS[2]]
                    if fault in ('skip','failed-query'):
                        next(event for event in events if event.get('Test') == N.IMPORTED_NATIVE_DNS_ROOTS[2] and event['Action'] == 'pass')['Action'] = 'skip' if fault == 'skip' else 'fail'
                    def run(command,**options):
                        self.assertEqual(command,['go','test','-json',*([] if target == 'windows/arm64' else ['-race']),
                            '-mod=readonly','-tags='+','.join(N.tags(target)),'-ldflags=-checklinkname=0',
                            './cmd/sing-box','-run','^('+'|'.join(N.IMPORTED_NATIVE_DNS_ROOTS)+')$','-count=1','-timeout=60s'])
                        self.assertIn('routervpn_native_pq',N.tags(target))
                        self.assertEqual(options,{'cwd':Path('prepared-native-core'),'env':env,'timeout':300})
                        self.assertIs(options['env'],env)
                        if fault == 'process-failure': raise subprocess.CalledProcessError(17,command)
                        if fault == 'timeout': raise subprocess.TimeoutExpired(command,300)
                        return self.output(events)
                    with patch.object(N,'native_host_target',return_value=target), patch.object(N,'run',side_effect=run) as invoke:
                        if fault == 'success': N.verify_imported_desktop_native_dns(Path('prepared-native-core'),target,env)
                        else:
                            with self.assertRaises((ValueError,subprocess.CalledProcessError,subprocess.TimeoutExpired)):
                                N.verify_imported_desktop_native_dns(Path('prepared-native-core'),target,env)
                    invoke.assert_called_once()
                    self.assertEqual(env,before)
        with patch.object(N,'native_host_target',return_value='linux/amd64'),patch.object(N,'run') as invoke:
            for target,env in (('linux/arm64',{'GOOS':'linux','GOARCH':'arm64'}),('linux/amd64',{'GOOS':'linux','GOARCH':'arm64'})):
                with self.assertRaises(ValueError): N.verify_imported_desktop_native_dns(Path('core'),target,env)
            invoke.assert_not_called()

    def test_actual_native_command_stage_requires_dns_before_later_gates(self):
        tree = ast.parse((ROOT/'deploy/build-native-runtime.py').read_text())
        build = next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name == 'build')
        owner = next(node for node in ast.walk(build) if isinstance(node,ast.If) and any(
            isinstance(child,ast.Expr) and isinstance(child.value,ast.Call) and isinstance(child.value.func,ast.Name)
            and child.value.func.id == 'verify_imported_desktop_native_dns' for child in node.body))
        index = next(index for index,node in enumerate(owner.body) if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call)
            and isinstance(node.value.func,ast.Name) and node.value.func.id == 'verify_imported_desktop_native_dns')
        selected = ast.fix_missing_locations(ast.Module(body=copy.deepcopy(owner.body[index-1:index+3]),type_ignores=[]))
        for target in N.TARGETS:
            for fault in ('success','missing','skip','failure','timeout'):
                with self.subTest(target=target,fault=fault):
                    calls = []
                    env = {'GOOS':target.split('/')[0],'GOARCH':target.split('/')[1],'ORIGINAL':'captured'}
                    def run(command,**options):
                        calls.append((list(map(str,command)),options))
                        if '-json' not in command: return ''
                        if fault == 'failure': raise subprocess.CalledProcessError(23,command)
                        if fault == 'timeout': raise subprocess.TimeoutExpired(command,300)
                        events = self.native_events()
                        if fault == 'missing': events.pop(-2)
                        if fault == 'skip': events[-2]['Action'] = 'skip'
                        return self.output(events)
                    namespace = dict(source=Path('prepared-core'),target=target,env=env,race=[] if target == 'windows/arm64' else ['-race'],
                        run=run,tags=N.tags,sys=N.sys,ROOT=ROOT,verify_imported_desktop_native_dns=N.verify_imported_desktop_native_dns,
                        verify_imported_desktop_native_openvpn=lambda *args: None)
                    with patch.object(N,'native_host_target',return_value=target),patch.object(N,'run',side_effect=run):
                        if fault == 'success': exec(compile(selected,'actual native command and DNS gate','exec'),namespace)
                        else:
                            with self.assertRaises((ValueError,subprocess.CalledProcessError,subprocess.TimeoutExpired)):
                                exec(compile(selected,'actual native command and DNS gate','exec'),namespace)
                    self.assertIn('^TestRouterVPN(Desktop(External|MTU|DNS|Tor)|NodeMTU)',calls[0][0])
                    self.assertEqual(calls[0][1]['timeout'],600)
                    self.assertIn('-timeout=120s',calls[0][0])
                    self.assertEqual(len(calls),3 if fault == 'success' else 2)
                    if fault == 'success': self.assertEqual(calls[-1][0][1],str(ROOT/'deploy/test_desktop_pt_inventory.py'))

    def test_source_preparation_registers_actual_mailbox_and_required_native_cases(self):
        tree = ast.parse((ROOT/'deploy/prepare-desktop-external.py').read_text())
        prepare = next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name == 'prepare')
        index = next(index for index,node in enumerate(prepare.body) if isinstance(node,ast.Assign)
            and any(isinstance(target,ast.Name) and target.id == 'templates' for target in node.targets))
        registration = ast.fix_missing_locations(ast.Module(body=copy.deepcopy(prepare.body[index:index+2]),type_ignores=[]))
        with tempfile.TemporaryDirectory() as directory:
            vendor = Path(directory)
            namespace = dict(ROOT=ROOT,vendor=vendor,PT_TEMPLATES=N.EXTERNAL.PT_TEMPLATES,
                BOX_TEMPLATES=N.EXTERNAL.BOX_TEMPLATES,PEER_TEMPLATES=N.EXTERNAL.PEER_TEMPLATES,write=N.EXTERNAL.write)
            exec(compile(registration,'actual desktop command template registration','exec'),namespace)
            for name in ('node_imported_dns.go','node_imported_dns_test.go','mtu_node.go'):
                source = ROOT/'mobile/desktop'/(name+'.tmpl')
                self.assertEqual((vendor/'cmd/sing-box'/('routervpn_'+name)).read_bytes(),source.read_bytes())
                self.assertIn(source,N.inputs())
        native = (ROOT/'mobile/desktop/node_imported_dns_test.go.tmpl').read_text()
        self.assertEqual(set(re.findall(r'^func (TestRouterVPNImportedDNS\w+)\(',native,re.M)),set(N.IMPORTED_NATIVE_DNS_ROOTS))
        cases = re.search(r'for _, fault := range \[\]string\{([^}]+)\}',native).group(1)
        self.assertEqual(tuple(re.findall(r'"([^"]+)"',cases)),N.IMPORTED_NATIVE_DNS_CASES)
        host = (ROOT/'cmd/client/multihop_native_imported_dns_test.go').read_text()
        self.assertEqual(set(re.findall(r'^func (TestDesktopImportedDNS\w+)\(',host,re.M)),set(N.IMPORTED_DESKTOP_DNS_ROOTS))
        cases = re.search(r'for _, fault := range \[\]string\{([^}]+)\}',host).group(1)
        self.assertEqual(tuple(re.findall(r'"([^"]+)"',cases)),N.IMPORTED_DESKTOP_DNS_CASES)

    def test_reused_bundle_gate_must_complete_before_success(self):
        for target in N.TARGETS:
            for failure in (None,ValueError('missing original DNS verdict'),subprocess.CalledProcessError(7,['native-gate']),subprocess.TimeoutExpired(['native-gate'],300)):
                with self.subTest(target=target,failure=type(failure).__name__),tempfile.TemporaryDirectory() as directory:
                    bundle = Path(directory)/'bundle';bundle.mkdir();(bundle/'retained').write_bytes(b'exact prior bundle boundary')
                    env = {'GOOS':target.split('/')[0],'GOARCH':target.split('/')[1]}
                    stdout = io.StringIO()
                    with patch.object(N,'environment',return_value=env),patch.object(N,'digest',return_value='original'), \
                         patch.object(N,'reuse',return_value={'captured':'receipt'}) as receipt,patch.object(N,'native_host_target',return_value=target), \
                         patch.object(N,'verify_linux_stock_dns'),patch.object(N,'verify_installed_darwin_host'), \
                         patch.object(N.DNSSEC,'test_native_bundle'),patch.object(N,'run') as run, \
                         patch.object(N,'verify_imported_desktop_packet_configs') as packet, \
                         patch.object(N,'verify_imported_desktop_openvpn_configs'), \
                         patch.object(N,'verify_imported_desktop_naive_h2_configs'), patch.object(N,'verify_imported_desktop_xhttp_configs'), patch.object(N,'verify_imported_desktop_pq_configs'), \
                         patch.object(N,'verify_imported_desktop_configs',side_effect=failure) as gate,contextlib.redirect_stdout(stdout):
                        if failure is None: self.assertEqual(N.build(target,bundle),bundle)
                        else:
                            with self.assertRaises(type(failure)) as caught: N.build(target,bundle)
                            self.assertIs(caught.exception,failure)
                    gate.assert_called_once_with(bundle,target,env)
                    if failure is None: packet.assert_called_once_with(bundle,target,env)
                    else: packet.assert_not_called()
                    receipt.assert_called_once_with(bundle,target,'original',env)
                    run.assert_not_called()
                    self.assertEqual('Reused verified complete native runtime' in stdout.getvalue(),failure is None)
                    self.assertEqual((bundle/'retained').read_bytes(),b'exact prior bundle boundary')


if __name__=='__main__':
    unittest.main()
