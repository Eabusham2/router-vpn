#!/usr/bin/env python3
"""Model the mandatory completed-bundle Naive H2 graph gate, never native acceptance."""
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
spec = importlib.util.spec_from_file_location('imported_naive_h2_build', ROOT/'deploy/build-native-runtime.py')
N = importlib.util.module_from_spec(spec)
spec.loader.exec_module(N)
KINDS = ('socks5', 'shadowsocks', 'hysteria2', 'http-connect', 'https-connect',
         'wireguard', 'amneziawg', 'openvpn-tcp', 'openvpn-udp')
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
GRAPH_TEST = 'TestDesktopImportedNaiveH2CapturedGraphs'


class ImportedNaiveH2RuntimeGate(unittest.TestCase):
    @staticmethod
    def events():
        def event(action, name=None):
            row = {'Package':'router-vpn/cmd/client', 'Action':action}
            if name is not None: row['Test'] = name
            return row
        result = [event('start'), event('run', GRAPH_TEST)]
        for kind in KINDS:
            for first in LAYERS:
                for last in LAYERS:
                    name = GRAPH_TEST+'/'+kind+'/'+first+'/'+last
                    result.extend((event('run', name), event('pass', name)))
        return result + [event('pass', GRAPH_TEST), event('pass')]

    @staticmethod
    def output(events):
        return '\n'.join(json.dumps(event) for event in events)

    def test_exact_separate_inventory_requires_every_original_verdict_once(self):
        expected = {kind+'--naive-h2--'+first+'--'+last+'.json'
                    for kind in KINDS for first in LAYERS for last in LAYERS}
        self.assertEqual(N.IMPORTED_NAIVE_H2_FILES, expected)
        self.assertEqual(len(expected), 81)
        names = {GRAPH_TEST} | {GRAPH_TEST+'/'+kind+'/'+first+'/'+last
                                for kind in KINDS for first in LAYERS for last in LAYERS}
        self.assertEqual(N.imported_desktop_naive_h2_verdicts(), names)
        self.assertEqual(len(names), 82)
        self.assertEqual((len(N.IMPORTED_DESKTOP_FILES), len(N.IMPORTED_PACKET_FILES),
                          len(N.IMPORTED_OPENVPN_FILES)), (26, 108, 108))
        self.assertEqual(len(N.IMPORTED_PQ_FILES),81)
        self.assertEqual(len(N.IMPORTED_XHTTP_FILES),81)
        self.assertFalse(expected & N.IMPORTED_XHTTP_FILES)
        self.assertFalse(expected & N.IMPORTED_PQ_FILES)
        self.assertFalse(expected & (N.IMPORTED_DESKTOP_FILES | N.IMPORTED_PACKET_FILES | N.IMPORTED_OPENVPN_FILES))
        verify = lambda rows: N.verify_imported_native_verdicts(self.output(rows), 'router-vpn/cmd/client', names)
        events = self.events()
        verify(events)
        for index in range(len(events)):
            for changed in (events[:index]+events[index+1:], events[:index]+[events[index]]+events[index:]):
                with self.subTest(index=index), self.assertRaises(ValueError): verify(changed)
        for action in ('skip', 'fail', 'build-fail', 'unknown'):
            changed = copy.deepcopy(events); changed[3]['Action'] = action
            with self.subTest(action=action), self.assertRaises(ValueError): verify(changed)
        for changed in ([{'Package':'router-vpn/cmd/client', 'Action':'pass'}],
                        events+[{'Package':'foreign', 'Action':'pass'}],
                        events[:-1]+[{'Package':'router-vpn/cmd/client', 'Action':'output', 'Output':'WARNING: DATA RACE'}]+events[-1:]):
            with self.assertRaises(ValueError): verify(changed)
        changed = copy.deepcopy(events); changed[2]['Test'] = 'TestDesktopImportedOrdinaryGraph'
        with self.assertRaises(ValueError): verify(changed)
        changed = events[:3]+[events[-2]]+events[3:]
        with self.assertRaises(ValueError): verify(changed)

    def exercise(self, target, fault='success'):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)/'complete'; bundle.mkdir()
            binary = bundle/N.binary_name(target); binary.write_bytes(b'completed engine boundary')
            env = {'GOOS':target.split('/')[0], 'GOARCH':target.split('/')[1], 'ORIGINAL_ENV':'1'}
            calls, fixtures = [], []
            def run(command, **options):
                command = list(map(str, command)); calls.append((command, options))
                if command[:2] == ['go', 'test']:
                    self.assertEqual(command, ['go', 'test', '-json', *([] if target == 'windows/arm64' else ['-race']),
                        './cmd/client', '-run', '^'+GRAPH_TEST+'$', '-count=1', '-timeout=180s'])
                    directory = Path(options['env']['ROUTERVPN_DESKTOP_IMPORTED_NAIVE_H2_FIXTURES'])
                    self.assertEqual(options, {'cwd':ROOT, 'env':{**env, 'ROUTERVPN_DESKTOP_IMPORTED_NAIVE_H2_FIXTURES':str(directory)}, 'timeout':300})
                    self.assertTrue(directory.is_dir()); self.assertEqual(list(directory.iterdir()), [])
                    fixtures.append(directory)
                    for name in N.IMPORTED_NAIVE_H2_FILES: (directory/name).write_bytes(('original:'+name).encode())
                    path = directory/sorted(N.IMPORTED_NAIVE_H2_FILES)[0]
                    if fault == 'missing-file': path.unlink()
                    if fault == 'foreign-file': (directory/'foreign.json').write_bytes(b'foreign')
                    if fault == 'linked-file': path.unlink(); path.symlink_to(binary)
                    if fault == 'ordinary-file': path.rename(directory/path.name.replace('naive-h2', 'reality-vision'))
                    if fault == 'producer-failure': raise subprocess.CalledProcessError(7, command)
                    if fault == 'producer-timeout': raise subprocess.TimeoutExpired(command, 300)
                    events = self.events()
                    if fault == 'missing-verdict': events.pop(3)
                    if fault == 'duplicate-verdict': events.insert(3, dict(events[3]))
                    if fault == 'skipped-verdict': events[3]['Action'] = 'skip'
                    if fault == 'failed-verdict': events[3]['Action'] = 'fail'
                    return self.output(events)
                self.assertEqual(command[:3], [str(binary), 'check', '-c'])
                self.assertEqual(options, {'env':env, 'timeout':20})
                path = Path(command[3])
                self.assertEqual(path.read_bytes(), ('original:'+path.name).encode())
                if fault == 'parser-failure': raise subprocess.CalledProcessError(8, command)
                if fault == 'parser-timeout': raise subprocess.TimeoutExpired(command, 20)
                if fault == 'changed-file': path.write_bytes(b'replaced after parsing')
                if fault == 'changed-next-file': (path.parent/sorted(N.IMPORTED_NAIVE_H2_FILES)[1]).write_bytes(b'replaced before parsing')
                if fault == 'late-foreign-file': (path.parent/'foreign.json').write_bytes(b'foreign')
                return ''
            def reuse(directory, actual, **options):
                self.assertEqual((directory, actual, options), (bundle, target, {'env':env}))
                return {'receipt':'changed' if calls and fault == 'bundle-change' else 'original'}
            with patch.object(N, 'native_host_target', return_value=target), patch.object(N, 'run', side_effect=run), \
                 patch.object(N, 'reuse', side_effect=reuse) as retained, patch('builtins.print') as printed:
                if fault == 'success': N.verify_imported_desktop_naive_h2_configs(bundle, target, env)
                else:
                    with self.assertRaises((ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired)):
                        N.verify_imported_desktop_naive_h2_configs(bundle, target, env)
                self.assertEqual(printed.call_count, 1 if fault == 'success' else 0)
            self.assertEqual(env, {'GOOS':target.split('/')[0], 'GOARCH':target.split('/')[1], 'ORIGINAL_ENV':'1'})
            self.assertEqual(len(fixtures), 1); self.assertFalse(fixtures[0].exists())
            if fault in ('success', 'bundle-change'):
                self.assertEqual(len(calls), 82); self.assertEqual(retained.call_count, 2)
                self.assertEqual({Path(command[3]).name for command,_ in calls[1:]}, N.IMPORTED_NAIVE_H2_FILES)
            elif fault in ('missing-file', 'foreign-file', 'linked-file', 'ordinary-file', 'producer-failure',
                           'producer-timeout', 'missing-verdict', 'duplicate-verdict', 'skipped-verdict', 'failed-verdict'):
                self.assertEqual(len(calls), 1); self.assertEqual(retained.call_count, 1)

    def test_all_six_matching_platforms_parse_every_original_export(self):
        self.assertEqual(set(N.TARGETS), {system+'/'+arch for system in ('linux', 'darwin', 'windows') for arch in ('amd64', 'arm64')})
        for target in N.TARGETS:
            with self.subTest(target=target): self.exercise(target)

    def test_missing_changed_failed_or_timed_out_evidence_blocks_success(self):
        for fault in ('missing-file', 'foreign-file', 'linked-file', 'ordinary-file', 'producer-failure',
                      'producer-timeout', 'missing-verdict', 'duplicate-verdict', 'skipped-verdict', 'failed-verdict',
                      'parser-failure', 'parser-timeout', 'changed-file', 'changed-next-file', 'late-foreign-file', 'bundle-change'):
            with self.subTest(fault=fault): self.exercise('linux/amd64', fault)

    def test_matching_completed_bundle_precedes_producer_or_parser_execution(self):
        with patch.object(N, 'native_host_target', return_value='linux/amd64'), patch.object(N, 'run') as run, patch.object(N, 'reuse') as reuse:
            for target,env in (('linux/arm64', {'GOOS':'linux', 'GOARCH':'arm64'}),
                               ('linux/amd64', {'GOOS':'linux', 'GOARCH':'arm64'}),
                               ('windows/amd64', {'GOOS':'windows', 'GOARCH':'amd64'})):
                with self.assertRaises(ValueError): N.verify_imported_desktop_naive_h2_configs(Path('bundle'), target, env)
            reuse.assert_not_called(); run.assert_not_called()
            reuse.side_effect = ValueError('incomplete original bundle')
            with self.assertRaisesRegex(ValueError, 'incomplete original bundle'):
                N.verify_imported_desktop_naive_h2_configs(Path('bundle'), 'linux/amd64', {'GOOS':'linux', 'GOARCH':'amd64'})
            run.assert_not_called()

    def completed_tail(self, source=None):
        tree = ast.parse((ROOT/'deploy/build-native-runtime.py').read_text() if source is None else source)
        build = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'build')
        native = next(node for node in ast.walk(build) if isinstance(node, ast.With) and any(
            isinstance(child, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'ldflags' for target in child.targets)
            for child in node.body))
        start = next(i for i,node in enumerate(native.body) if isinstance(node, ast.If) and any(
            isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == 'verify_imported_desktop_configs'
            for child in ast.walk(node)))
        return ast.fix_missing_locations(ast.Module(body=copy.deepcopy(native.body[start:]), type_ignores=[]))

    def fresh(self, target, failure=None, source=None):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)/'stage'; stage.mkdir(); destination = Path(temporary)/'published'
            calls = []
            def record(name):
                def gate(*args):
                    calls.append((name, args))
                    if name == 'naive_h2' and failure is not None: raise failure
                return gate
            env = {'original':'1'}
            namespace = dict(target=target, host=target, stage=stage, destination=destination, binary=stage/N.binary_name(target),
                policy='policy', marker=lambda _: 'original', source=Path('prepared-core'), env=env, os=N.os,
                run=lambda command,**options: 'sing-box version original\n' if command[-1] == 'version' else '--runtime-dir --session',
                verify_imported_desktop_configs=record('ordinary'), verify_imported_desktop_packet_configs=record('packet'),
                verify_imported_desktop_openvpn_configs=record('openvpn'), verify_imported_desktop_pq_configs=record('pq'), verify_imported_desktop_xhttp_configs=record('xhttp'), verify_imported_desktop_naive_h2_configs=record('naive_h2'), verify_imported_desktop_naive_h3_configs=lambda *args: None,
                verify_installed_linux_host=record('installed'), verify_installed_darwin_host=record('installed'))
            if failure is None: exec(compile(self.completed_tail(source), 'actual completed native tail', 'exec'), namespace)
            else:
                with self.assertRaises(type(failure)) as caught: exec(compile(self.completed_tail(source), 'actual completed native tail', 'exec'), namespace)
                self.assertIs(caught.exception, failure)
            self.assertEqual(calls[:6], [(name, (stage,target,env)) for name in ('ordinary','packet','openvpn','pq','xhttp','naive_h2')])
            self.assertEqual(len(calls), 7 if failure is None and target.startswith(('linux/','darwin/')) else 6)
            self.assertEqual(destination.exists(), failure is None); self.assertEqual(stage.exists(), failure is not None)

    def test_fresh_bundle_requires_naive_h2_after_all_prior_gates(self):
        for target in N.TARGETS:
            for failure in (None, ValueError('missing Naive H2 verdict'), subprocess.CalledProcessError(7, ['naive_h2']), subprocess.TimeoutExpired(['naive_h2'], 300)):
                with self.subTest(target=target, failure=type(failure).__name__): self.fresh(target, failure)
        source = (ROOT/'deploy/build-native-runtime.py').read_text()
        changed = source.replace('            verify_imported_desktop_naive_h2_configs(stage, target, env)\n', '')
        self.assertNotEqual(changed, source)
        with self.assertRaises(AssertionError): self.fresh('linux/amd64', source=changed)

    def test_reused_bundle_cannot_report_success_before_naive_h2_gate(self):
        for target in N.TARGETS:
            for failure in (None, ValueError('missing Naive H2 graph'), subprocess.CalledProcessError(7, ['naive_h2']), subprocess.TimeoutExpired(['naive_h2'], 300)):
                with self.subTest(target=target, failure=type(failure).__name__), tempfile.TemporaryDirectory() as temporary:
                    bundle = Path(temporary)/'bundle'; bundle.mkdir(); (bundle/'retained').write_bytes(b'original complete bundle')
                    env = {'GOOS':target.split('/')[0], 'GOARCH':target.split('/')[1]}
                    calls, stdout = [], io.StringIO()
                    def record(name):
                        def gate(*args):
                            calls.append((name,args))
                            if name == 'naive_h2' and failure is not None: raise failure
                        return gate
                    with patch.object(N, 'environment', return_value=env), patch.object(N, 'digest', return_value='original'), \
                         patch.object(N, 'reuse', return_value={'captured':'receipt'}) as receipt, patch.object(N, 'native_host_target', return_value=target), \
                         patch.object(N, 'verify_linux_stock_dns'), patch.object(N, 'verify_installed_darwin_host'), \
                         patch.object(N.DNSSEC, 'test_native_bundle'), patch.object(N, 'run') as run, \
                         patch.object(N, 'verify_imported_desktop_configs', side_effect=record('ordinary')), \
                         patch.object(N, 'verify_imported_desktop_packet_configs', side_effect=record('packet')), \
                         patch.object(N, 'verify_imported_desktop_openvpn_configs', side_effect=record('openvpn')), \
                         patch.object(N, 'verify_imported_desktop_pq_configs', side_effect=record('pq')), \
                         patch.object(N, 'verify_imported_desktop_xhttp_configs', side_effect=record('xhttp')), \
                         patch.object(N, 'verify_imported_desktop_naive_h2_configs', side_effect=record('naive_h2')), patch.object(N, 'verify_imported_desktop_naive_h3_configs'), contextlib.redirect_stdout(stdout):
                        if failure is None: self.assertEqual(N.build(target, bundle), bundle)
                        else:
                            with self.assertRaises(type(failure)) as caught: N.build(target, bundle)
                            self.assertIs(caught.exception, failure)
                    self.assertEqual(calls, [(name,(bundle,target,env)) for name in ('ordinary','packet','openvpn','pq','xhttp','naive_h2')])
                    receipt.assert_called_once_with(bundle,target,'original',env); run.assert_not_called()
                    self.assertEqual('Reused verified complete native runtime' in stdout.getvalue(), failure is None)
                    self.assertEqual((bundle/'retained').read_bytes(), b'original complete bundle')

    def test_gate_contract_is_part_of_source_identity_and_executed_release_audit(self):
        self.assertIn(ROOT/'deploy/test_desktop_imported_naive_h2_runtime.py', N.inputs())
        source = (ROOT/'.github/workflows/release-candidate.yml').read_text()
        command = next(line.strip() for line in source.splitlines() if line.strip().startswith('python3 -m unittest deploy.test_desktop_imported_runtime'))
        self.assertEqual(command.split(), ['python3', '-m', 'unittest', 'deploy.test_desktop_imported_runtime',
            'deploy.test_desktop_imported_packet_runtime', 'deploy.test_desktop_imported_openvpn_runtime', 'deploy.test_desktop_imported_pq_runtime', 'deploy.test_desktop_imported_xhttp_runtime', 'deploy.test_desktop_imported_naive_h2_runtime', 'deploy.test_desktop_imported_naive_h3_runtime'])


if __name__ == '__main__':
    unittest.main()
