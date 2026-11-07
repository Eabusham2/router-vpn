#!/usr/bin/env python3
"""Require every captured proxy REALITY source and executable verdict."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('connect_reality_gate', ROOT / 'deploy/test_mobile_imported_connect_xray.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class CONNECTRealityInventory(unittest.TestCase):
    def events(self, expected):
        return [{'Action': action, 'Test': name} for name in sorted(expected) for action in ('run', 'pass')]

    def encode(self, events):
        return '\n'.join(map(json.dumps, events))

    def scopes(self):
        return [gate.IMPORTED.names(gate.CORE),
                gate.IMPORTED.names({gate.SHARED_PARSER: sorted(gate.FILES)}),
                gate.IMPORTED.names({gate.ANDROID_PARSER: ['android-' + name for name in sorted(gate.FILES)]}),
                gate.IMPORTED.names({gate.APPLE_PARSER: sorted(gate.FILES)})]

    def test_exact_primary_and_separate_inventories(self):
        self.assertEqual(len(gate.IMPORTED.FILES), 346)
        self.assertEqual(len(gate.IMPORTED.CONNECT_LAYER_FILES), 32)
        self.assertEqual(len(gate.FILES), 18)
        self.assertFalse(gate.FILES & gate.IMPORTED.FILES)
        self.assertFalse(gate.FILES & gate.IMPORTED.CONNECT_LAYER_FILES)
        self.assertEqual(len(gate.IMPORTED.names(gate.CORE)), 172)
        for kind in gate.KINDS:
            self.assertEqual(len([name for name in gate.FILES if name.startswith(kind + '--')]), 9)
        self.assertFalse(gate.FILES & gate.PROXY.FILES)
        for expected in self.scopes():
            gate.SOCKS.require_verdicts(self.encode(self.events(expected)), 0, expected)

    def test_every_native_child_and_source_parser_is_required(self):
        for expected in self.scopes():
            for missing in expected:
                with self.subTest(missing=missing), self.assertRaises(ValueError):
                    gate.SOCKS.require_verdicts(self.encode(self.events(expected - {missing})), 0, expected)

    def test_foreign_duplicate_failed_and_skipped_receipts_are_rejected(self):
        for expected in self.scopes():
            events = self.events(expected)
            for mutation in (events + [events[-1]], events + [{'Action': 'pass', 'Test': 'TestForeignProxyOwner'}],
                             events[:-1] + [dict(events[-1], Action='skip')],
                             events[:-1] + [dict(events[-1], Action='fail')]):
                with self.assertRaises(ValueError):
                    gate.SOCKS.require_verdicts(self.encode(mutation), 0, expected)
            with self.assertRaises(ValueError):
                gate.SOCKS.require_verdicts(self.encode(events), 1, expected)


    def test_no_capture_can_be_missing_changed_to_link_or_foreign(self):
        for prefix in ('', 'android-'):
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                for name in gate.FILES:
                    (directory / (prefix + name)).write_bytes(b'original capture')
                original = gate.captured_matrix(directory, prefix)
                self.assertEqual(set(original), {prefix + name for name in gate.FILES})
                for name in original:
                    path = directory / name
                    path.unlink()
                    with self.assertRaises(ValueError):
                        gate.captured_matrix(directory, prefix)
                    path.symlink_to(directory / 'missing')
                    with self.assertRaises(ValueError):
                        gate.captured_matrix(directory, prefix)
                    path.unlink()
                    path.write_bytes(b'')
                    with self.assertRaises(ValueError):
                        gate.captured_matrix(directory, prefix)
                    path.write_bytes(original[name])
                (directory / 'foreign.json').write_bytes(b'foreign')
                with self.assertRaises(ValueError):
                    gate.captured_matrix(directory, prefix)


    def test_actual_android_phases_get_empty_separate_owned_directories(self):
        seen = []
        def producer(command, **options):
            self.assertEqual(options['timeout'], 240)
            phase = command[-1]
            self.assertIn(phase, ('connect-reality--http-connect', 'connect-reality--https-connect'))
            directory = Path(options['env'][gate.ANDROID_ENV])
            self.assertTrue(directory.is_dir())
            self.assertEqual(list(directory.iterdir()), [])
            self.assertNotIn(directory, seen)
            seen.append(directory)
            kind = phase.removeprefix('connect-reality--')
            for name in gate.FILES:
                if name.startswith(kind+'--'):
                    (directory/('android-'+name)).write_bytes(name.encode())
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(gate.subprocess, 'run', side_effect=producer):
            env = {'CAPTURED_ENV': '1', gate.ANDROID_ENV: 'unrelated-old-directory'}
            directory, sources = gate.android_sources(Path(temporary), env)
            self.assertEqual(len(seen), 2)
            self.assertEqual(len(sources), 18)
            self.assertEqual(sources, {'android-'+name:name.encode() for name in gate.FILES})
            self.assertEqual(env[gate.ANDROID_ENV], str(directory))
        for missing in gate.KINDS:
            def incomplete(command, **options):
                if command[-1] != 'connect-reality--'+missing:
                    producer(command, **options)
            seen.clear()
            with tempfile.TemporaryDirectory() as temporary, mock.patch.object(gate.subprocess, 'run', side_effect=incomplete):
                with self.assertRaises(ValueError):
                    gate.android_sources(Path(temporary), {})



    def test_actual_pure_parser_keeps_existing_flags_and_exact_verdicts(self):
        path = ROOT / 'deploy/test_mobile_imported_connect_xray.py'
        tree = ast.parse(path.read_text())
        statements = [node for node in ast.walk(tree) if isinstance(node, ast.Expr)
                      and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                      and node.value.func.id == 'execute' and any(isinstance(value, ast.Constant)
                          and value.value == './experimental/libbox' for value in ast.walk(node))]
        self.assertEqual(len(statements), 1)
        groups = {gate.SHARED_PARSER: sorted(gate.FILES),
                  gate.ANDROID_PARSER: ['android-' + name for name in sorted(gate.FILES)]}
        calls = []
        def capture(command, cwd, env, expected, timeout):
            calls.append((command, cwd, env, expected, timeout))
        stage = ast.fix_missing_locations(ast.Module(body=copy.deepcopy(statements), type_ignores=[]))
        exec(compile(stage, str(path), 'exec'), dict(compiler='captured-go', vendor=Path('captured-core'),
             env={'CAPTURED_ENV': '1'}, groups=groups, SOCKS=gate.SOCKS, IMPORTED=gate.IMPORTED, execute=capture))
        self.assertEqual(calls, [(['captured-go', 'test', '-mod=readonly', '-json', '-ldflags=-checklinkname=0',
            '-tags', gate.SOCKS.TAGS, './experimental/libbox', '-run', '^(' + '|'.join(groups) + ')$',
            '-count=1', '-timeout=90s'], Path('captured-core'), {'CAPTURED_ENV': '1'},
            gate.IMPORTED.names(groups), 600)])
        self.assertEqual(len(calls[0][3]), 38)

    def test_actual_android_driver_keeps_original_and_separate_parser_calls(self):
        driver = gate.module('proxy_reality_android_driver_contract', 'test_android_multihop_pinned.py')
        imported = ('test_mobile_imported_entry.py', 'test_mobile_imported_proxy_xray.py', 'test_mobile_imported_connect_xray.py')
        for failed_gate in (None, *imported):
            with self.subTest(failed_gate=failed_gate), tempfile.TemporaryDirectory() as temporary:
                vendor = Path(temporary) / 'prepared-mobile'
                native = vendor / 'experimental/libbox/routervpn_multihop_native_test.go'
                native.parent.mkdir(parents=True)
                native.write_bytes((ROOT / 'mobile/routervpn_multihop_native_test.go.tmpl').read_bytes())
                retained, calls = [], []

                def dependency(work, env):
                    self.assertNotIn('ANDROID_JSON_JAR', env)
                    self.assertTrue(work.is_dir())
                    artifact = work / 'android-json.jar'
                    artifact.write_bytes(b'owned pinned dependency')
                    retained.append(artifact)
                    return artifact

                def check_output(command, **options):
                    if command[0] == 'git':
                        return driver.PIN + '\n'
                    self.assertEqual(command[:2], ['go', 'env'])
                    return {'GOHOSTOS': 'linux', 'GOHOSTARCH': 'amd64'}[command[2]] + '\n'

                def capture(command, **options):
                    artifact = Path(options['env']['ANDROID_JSON_JAR'])
                    self.assertEqual(artifact, retained[0])
                    self.assertTrue(artifact.parent.is_dir())
                    self.assertEqual(artifact.read_bytes(), b'owned pinned dependency')
                    name = Path(command[1]).name
                    if name == 'test_android_multihop_start_layer.py':
                        directory = Path(options['env']['ROUTERVPN_ENTRY_LAYER_FIXTURES'])
                        for mode in ('wg', 'awg2-fast', 'awg2-strong', 'shadowsocks', 'hysteria2',
                                     'reality-vision', 'reality-pq-vision', 'reality-xhttp'):
                            for layer in ('aes', 'aes-xor'):
                                for execution in ('local', 'server', 'auto'):
                                    (directory / f'{mode}-{layer}-{execution}.json').write_bytes(b'capture')
                    if name in imported:
                        calls.append(([str(part) for part in command], options))
                        self.assertEqual(options['timeout'], 1200)
                        self.assertTrue(options['check'])
                        if name == failed_gate:
                            raise driver.subprocess.CalledProcessError(7, command)

                with mock.patch.dict(driver.os.environ, {'CAPTURED_ENV': '1'}, clear=True), \
                        mock.patch.object(driver, 'android_json_dependency', side_effect=dependency), \
                        mock.patch.object(driver.subprocess, 'check_output', side_effect=check_output), \
                        mock.patch.object(driver.subprocess, 'run', side_effect=capture), \
                        mock.patch.object(driver, 'require_fixture_matrix'), \
                        mock.patch.object(driver, 'require_both_layer_matrix'), mock.patch('builtins.print'):
                    if failed_gate:
                        with self.assertRaises(driver.subprocess.CalledProcessError):
                            driver.run(vendor)
                    else:
                        driver.run(vendor)
                expected = imported[:imported.index(failed_gate)+1] if failed_gate else imported
                self.assertEqual(tuple(Path(command[1]).name for command, _ in calls), expected)
                self.assertEqual(calls[0][0][-1], '--android')
                for command, _ in calls[1:]:
                    self.assertEqual(command[-2:], ['--native-parsers', '--android'])
                self.assertEqual(len(retained), 1)
                self.assertFalse(retained[0].exists())
                self.assertFalse(retained[0].parent.exists())


class CONNECTRealityShippingBoundaries(unittest.TestCase):
    def test_apple_stage_requires_actual_producer_and_all_original_verdicts(self):
        driver = gate.module('connect_reality_apple_boundary', 'test_ios_imported_router_pinned.py')
        expected = {driver.CONNECT_XRAY_PARENT} | {driver.CONNECT_XRAY_PARENT+'/'+name for name in driver.CONNECT_XRAY_NAMES}
        self.assertEqual(driver.CONNECT_XRAY_NAMES, gate.FILES)
        for fault in ('success','missing-source','foreign-source','missing-verdict','duplicate-verdict','skip','native-failure','source-change','producer-timeout','parser-timeout'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                calls = []
                original = {name:('actual-host-'+name).encode() for name in driver.CONNECT_XRAY_NAMES}
                def execute(command, **options):
                    calls.append((command,options))
                    env = options['env']
                    self.assertEqual(env['CAPTURED_ORIGINAL'],'1')
                    self.assertEqual(env[gate.REQUIRE_ENV],'1')
                    self.assertFalse(any(key.startswith('ROUTERVPN_IOS_') for key in env))
                    self.assertNotIn('ROUTERVPN_APPLE_CONNECT_LAYER_FIXTURES',env)
                    self.assertNotIn('ROUTERVPN_APPLE_IMPORTED_PROXY_XRAY_FIXTURES',env)
                    graphs = Path(env[gate.APPLE_ENV])
                    if command[0] != 'go':
                        self.assertEqual(Path(command[1]).name,'test_ios_tor_profile.py')
                        self.assertEqual(options['timeout'],420)
                        self.assertTrue(options['check'])
                        self.assertEqual(list(graphs.iterdir()),[])
                        if fault == 'producer-timeout':
                            raise driver.subprocess.TimeoutExpired(command,420)
                        for name,raw in original.items(): (graphs/name).write_bytes(raw)
                        if fault == 'missing-source': (graphs/next(iter(original))).unlink()
                        if fault == 'foreign-source': (graphs/'foreign.json').write_bytes(b'foreign')
                        return None
                    self.assertEqual(options['timeout'],600)
                    self.assertEqual(command[command.index('-run')+1],'^'+driver.CONNECT_XRAY_PARENT+'$')
                    self.assertIn('-timeout=180s',command)
                    self.assertNotIn('-race',command)
                    if fault == 'parser-timeout':
                        raise driver.subprocess.TimeoutExpired(command,600)
                    events = [{'Action':'pass','Package':driver.PACKAGE,'Test':name} for name in sorted(expected)]
                    if fault == 'missing-verdict': events.pop()
                    if fault == 'duplicate-verdict': events.append(events[-1])
                    if fault == 'skip': events[-1] = dict(events[-1],Action='skip')
                    events.append({'Action':'pass','Package':driver.PACKAGE})
                    if fault == 'source-change': (graphs/next(iter(original))).write_bytes(b'changed after original parsing')
                    return type('Result',(),{'returncode':int(fault=='native-failure'),'stdout':'\n'.join(map(json.dumps,events)),'stderr':''})()
                env={'CAPTURED_ORIGINAL':'1','ROUTERVPN_IOS_IMPORTED_ROUTER_ONLY':'1',
                     'ROUTERVPN_APPLE_CONNECT_LAYER_FIXTURES':'foreign-old-layer',
                     'ROUTERVPN_APPLE_IMPORTED_PROXY_XRAY_FIXTURES':'foreign-old-proxy'}
                with mock.patch.object(driver.subprocess,'run',side_effect=execute), mock.patch('builtins.print'):
                    if fault == 'success':
                        self.assertEqual(driver.run_connect_reality(Path('prepared-core'),work,env),original)
                    else:
                        with self.assertRaises((ValueError,driver.subprocess.TimeoutExpired)):
                            driver.run_connect_reality(Path('prepared-core'),work,env)
                self.assertEqual(len(calls),1 if fault in ('missing-source','foreign-source','producer-timeout') else 2)
                self.assertEqual(env['ROUTERVPN_APPLE_CONNECT_LAYER_FIXTURES'],'foreign-old-layer')

    def test_native_http_inventory_rejects_changed_missing_injected_and_linked_source(self):
        for fault in ('success','changed','missing','extra','symlink'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                vendor = Path(temporary)
                protocol = vendor/'protocol/http'; protocol.mkdir(parents=True)
                path = protocol/'outbound.go'; path.write_bytes(b'original-native-http')
                if fault == 'changed': path.write_bytes(b'changed-http')
                if fault == 'missing': path.unlink()
                if fault == 'extra': (protocol/'injected.go').write_bytes(b'extra')
                if fault == 'symlink':
                    target = vendor/'foreign.go'; target.write_bytes(path.read_bytes())
                    path.unlink(); path.symlink_to(target)
                def git(command, **options):
                    self.assertEqual(command[:3],['git','-C',str(vendor)])
                    if command[3] == 'ls-tree':
                        self.assertIn(gate.SOCKS.PIN,command)
                        return 'protocol/http/outbound.go\n'
                    self.assertEqual(command[3:],['show',gate.SOCKS.PIN+':protocol/http/outbound.go'])
                    return b'original-native-http'
                with mock.patch.object(gate.PROXY,'checked_sources',return_value={}), \
                     mock.patch.object(gate.subprocess,'check_output',side_effect=git):
                    if fault == 'success':
                        self.assertIn('original/protocol/http/outbound.go',gate.checked_sources(vendor))
                    else:
                        with self.assertRaises(ValueError): gate.checked_sources(vendor)

    def test_failure_output_is_retained_before_strict_verdict_rejection(self):
        for status in (1,124):
            with mock.patch.object(gate.SOCKS,'run_command',return_value=(status,'original native failure\n')), \
                 mock.patch('builtins.print') as observed:
                with self.assertRaises(ValueError):
                    gate.execute(['original-command'],Path('original-source'),{}, {'TestRequired'},90)
                observed.assert_called_once_with('original native failure\n',end='',flush=True)


if __name__ == '__main__':
    unittest.main()
