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
spec = importlib.util.spec_from_file_location('proxy_reality_gate', ROOT / 'deploy/test_mobile_imported_proxy_xray.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ProxyRealityInventory(unittest.TestCase):
    def events(self, expected):
        return [{'Action': action, 'Test': name} for name in sorted(expected) for action in ('run', 'pass')]

    def encode(self, events):
        return '\n'.join(map(json.dumps, events))

    def scopes(self):
        return [gate.IMPORTED.names(gate.CORE), set(gate.SUPPORT),
                *(gate.IMPORTED.names({parent: leaves}) for parent, leaves in gate.PEERS.items()),
                gate.IMPORTED.names({gate.SHARED_PARSER: sorted(gate.FILES)}),
                gate.IMPORTED.names({gate.ANDROID_PARSER: ['android-' + name for name in sorted(gate.FILES)]}),
                gate.IMPORTED.names({gate.APPLE_PARSER: sorted(gate.FILES)})]

    def test_exact_primary_and_separate_inventories(self):
        self.assertEqual(len(gate.IMPORTED.FILES), 346)
        self.assertEqual(len(gate.IMPORTED.CONNECT_LAYER_FILES), 32)
        self.assertEqual(len(gate.FILES), 18)
        self.assertFalse(gate.FILES & gate.IMPORTED.FILES)
        self.assertFalse(gate.FILES & gate.IMPORTED.CONNECT_LAYER_FILES)
        self.assertEqual(len(gate.IMPORTED.names(gate.CORE)), 161)
        for kind in gate.KINDS:
            self.assertEqual(len([name for name in gate.FILES if name.startswith(kind + '--')]), 9)
        self.assertEqual(sum('/' in name for leaves in gate.PEERS.values() for name in leaves), 114)
        self.assertEqual(gate.SUPPORT, ('TestRouterVPNImportedProxyRealityPhysicalOwner',))
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

    def test_all_layer_positive_and_retirement_cases_remain_mandatory(self):
        for kind, label in (('shadowsocks', 'Shadowsocks'), ('hysteria2', 'Hysteria2')):
            parent = 'TestRouterVPNImported' + label + 'RealityVisionNativeTraffic'
            expected = set(gate.PEERS[parent])
            for first in gate.LAYERS:
                for final in gate.LAYERS:
                    prefix = first + '--' + final + '/'
                    for leaf in ('success', 'cancel', 'close-owner'):
                        self.assertIn(prefix + leaf, expected)
                    for layer, value in (('entry', first), ('final', final)):
                        if value != 'off':
                            self.assertIn(prefix + layer + '-layer-key', expected)
                        if value == 'aes-256-gcm+xor-whitening':
                            self.assertIn(prefix + layer + '-layer-whitening', expected)
            for fault in ('entry-auth', 'wrong-entry-ip', 'final-reality-key', 'final-user',
                          'final-route', 'dns-route', 'final-identity', 'final-token'):
                self.assertIn('off--off/' + fault, expected)
            if kind == 'hysteria2':
                self.assertIn('off--off/entry-sni', expected)
                self.assertIn('off--off/entry-trust', expected)
        methods = set(gate.PEERS['TestRouterVPNImportedShadowsocksRealityVisionMethods'])
        for method in gate.METHODS:
            self.assertIn(method + '/success', methods)
            self.assertIn(method + '/entry-auth', methods)

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

    def test_peer_preparation_copies_actual_new_fixture(self):
        template, target = gate.PEER_COPY
        self.assertEqual(gate.SOCKS.DESKTOP.PEER_TEMPLATES[Path(template).name], target)
        self.assertIn(ROOT / template, gate.inputs())
        self.assertIn(ROOT / 'mobile/routervpn_imported_entry_native_test.go.tmpl', gate.inputs())
        self.assertIn(ROOT / 'deploy/ios_test_crypto_bridge.py', gate.inputs())
        self.assertIn(ROOT / 'deploy/test_android_multihop_pinned.py', gate.inputs())

    def test_actual_android_phases_get_empty_separate_owned_directories(self):
        seen = []
        def producer(command, **options):
            self.assertEqual(options['timeout'], 240)
            phase = command[-1]
            self.assertIn(phase, ('proxy-reality--shadowsocks', 'proxy-reality--hysteria2'))
            directory = Path(options['env'][gate.ANDROID_ENV])
            self.assertTrue(directory.is_dir())
            self.assertEqual(list(directory.iterdir()), [])
            self.assertNotIn(directory, seen)
            seen.append(directory)
            kind = phase.removeprefix('proxy-reality--')
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
                if command[-1] != 'proxy-reality--'+missing:
                    producer(command, **options)
            seen.clear()
            with tempfile.TemporaryDirectory() as temporary, mock.patch.object(gate.subprocess, 'run', side_effect=incomplete):
                with self.assertRaises(ValueError):
                    gate.android_sources(Path(temporary), {})

    def test_native_parser_requires_actual_pinned_prepared_xray_dependency(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'prepared-xray'
            source.mkdir()
            original = {'Path': 'github.com/xtls/xray-core', 'Version': gate.XRAY_VERSION,
                        'Dir': str(source), 'Replace': {'Dir': str(source)}}
            with mock.patch.object(gate.SOCKS, 'run_command', return_value=(0, json.dumps(original))), \
                    mock.patch.object(gate.SOCKS, 'checked_xray', return_value={'captured': 'digest'}) as checked:
                self.assertEqual(gate.resolved_xray('go', Path('prepared-mobile'), {}), (source, {'captured':'digest'}))
                checked.assert_called_once_with(source)
            for change in ({'Version': 'v1.260327.0'}, {'Replace': {}}, {'Path':'foreign/xray'},
                           {'Dir':'relative-xray'}, {'Replace': {'Dir': str(source/'foreign')}}):
                with mock.patch.object(gate.SOCKS, 'run_command', return_value=(0, json.dumps(dict(original, **change)))), \
                        mock.patch.object(gate.SOCKS, 'checked_xray') as checked:
                    with self.assertRaises(ValueError): gate.resolved_xray('go', Path('prepared-mobile'), {})
                    checked.assert_not_called()

    def test_actual_native_driver_executes_both_independent_reference_gates(self):
        contracts = gate.module('original_reference_driver_contract', 'test_mobile_imported_socks_xray_runner.py')
        path, selected, tree = contracts.ScopedSOCKSRealitySourceContext().native_stage()
        stage = ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(selected)], type_ignores=[]))
        for target in ('linux/amd64', 'linux/arm64', 'windows/amd64', 'windows/arm64', 'darwin/arm64'):
            calls = []
            def capture(command, **options):
                calls.append(([str(part) for part in command], options))
            namespace, loader, phases = contracts.native_stage_namespace(target=target, source=Path('captured-core'),
                             pq=Path('captured-pq'), env={'CAPTURED_ENV': '1'}, run=capture)
            exec(compile(stage, str(path), 'exec'), namespace)
            contracts.require_native_stage_phases(namespace, loader, phases)
            original = [(i, options) for i, (command, options) in enumerate(calls)
                        if any(Path(part).name == 'test_mobile_imported_socks_xray.py' for part in command)]
            addition = [(i, command, options) for i, (command, options) in enumerate(calls)
                        if any(Path(part).name == 'test_mobile_imported_proxy_xray.py' for part in command)]
            self.assertEqual(len(original), int(target.startswith('linux/')))
            self.assertEqual(len(addition), len(original))
            for index, command, options in addition:
                self.assertGreater(index, original[0][0])
                self.assertEqual(command[-1], '--reference-only')
                self.assertEqual(options, {'env': {'CAPTURED_ENV': '1'}, 'timeout': 3000})
                self.assertEqual(original[0][1]['timeout'], 3000)
        inputs = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'inputs')
        literals = {node.value for node in ast.walk(inputs) if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        for filename in ('deploy/test_mobile_imported_proxy_xray.py', 'deploy/test_mobile_imported_proxy_xray_runner.py'):
            self.assertIn(filename, literals)

    def test_actual_pure_parser_keeps_existing_flags_and_exact_verdicts(self):
        path = ROOT / 'deploy/test_mobile_imported_proxy_xray.py'
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
        imported = ('test_mobile_imported_entry.py', 'test_mobile_imported_proxy_xray.py')
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
                expected = imported[:1] if failed_gate == imported[0] else imported
                self.assertEqual(tuple(Path(command[1]).name for command, _ in calls), expected)
                self.assertEqual(calls[0][0][-1], '--android')
                if len(calls) == 2:
                    self.assertEqual(calls[1][0][-2:], ['--native-parsers', '--android'])
                self.assertEqual(len(retained), 1)
                self.assertFalse(retained[0].exists())
                self.assertFalse(retained[0].parent.exists())


if __name__ == '__main__':
    unittest.main()
