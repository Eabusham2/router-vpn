#!/usr/bin/env python3
"""Execute the shared native graph gate's complete Local/Server/Compare boundary."""
from pathlib import Path
import contextlib
import importlib.util
import io
import itertools
import json
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('mobile_external_graph_gate', ROOT/'deploy/test_mobile_external_graphs.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def names(target):
    local = {'-'.join(case)+'.json' for case in itertools.product(G.MODES, G.LAYERS, G.PROTOCOLS[target])}
    paired = {mode+'-'+layer+'-shadowsocks-'+execution+'.json'
              for mode in G.MODES for layer in G.LAYERS for execution in ('server', 'auto')}
    return local, paired


class ExternalGraphGate(unittest.TestCase):
    def test_every_mode_layer_and_supported_execution_is_required(self):
        for target in ('android', 'ios'):
            local, paired = names(target)
            self.assertEqual((len(local), len(paired)), (456, 114))
            self.assertFalse(local & paired)
            self.assertEqual(G.expected_names(target), local | paired)
            self.assertEqual(len(G.expected_names(target)), 570)
            self.assertIn('max-quic-awg-aes-256-gcm+xor-whitening-shadowsocks-auto.json', paired)

    def test_incomplete_stale_or_unsafe_matrix_is_rejected(self):
        for target in ('android', 'ios'):
            with tempfile.TemporaryDirectory(prefix='external-matrix-contract-') as tmp:
                directory = Path(tmp)/'graphs'
                directory.mkdir()
                local, paired = names(target)
                for name in local | paired:
                    (directory/name).write_text('{}')
                self.assertEqual(G.require_matrix(directory, target), 570)
                for name in ('wg-off-wireguard.json', 'wg-off-shadowsocks-server.json', 'wg-off-shadowsocks-auto.json'):
                    file = directory/name
                    file.unlink()
                    with self.assertRaisesRegex(ValueError, '1 missing, 0 extra'):
                        G.require_matrix(directory, target)
                    file.write_text('{}')
                stale = directory/'wg-off-socks5-server.json'
                stale.write_text('{}')
                with self.assertRaisesRegex(ValueError, '0 missing, 1 extra'):
                    G.require_matrix(directory, target)
                stale.unlink()
                file = directory/'wg-off-shadowsocks-auto.json'
                for content in (b'', b' '*(4*1024*1024+1)):
                    file.write_bytes(content)
                    with self.assertRaisesRegex(ValueError, 'Unsafe or invalid'):
                        G.require_matrix(directory, target)
                file.unlink()
                file.symlink_to(directory/'wg-off-shadowsocks.json')
                with self.assertRaisesRegex(ValueError, 'Unsafe or invalid'):
                    G.require_matrix(directory, target)
                file.unlink()
                file.mkdir()
                with self.assertRaisesRegex(ValueError, 'Unsafe or invalid'):
                    G.require_matrix(directory, target)
                alias = Path(tmp)/'alias'
                alias.symlink_to(directory, target_is_directory=True)
                with self.assertRaises(ValueError):
                    G.require_matrix(alias, target)

    def exercise(self, target='android', fault=''):
        with tempfile.TemporaryDirectory(prefix='external-native-runner-contract-') as tmp:
            root = Path(tmp)
            vendor = root/'vendor'
            (vendor/'experimental/libbox').mkdir(parents=True)
            reader = vendor/'experimental/libbox/routervpn_external_policy_graph_test.go'
            reader.write_bytes((ROOT/'mobile/externalpolicy/graph_test.go.tmpl').read_bytes())
            if fault == 'reader':
                reader.write_text('stale native reader')
            for name in ('go.mod', 'go.sum'):
                (vendor/name).write_text(name)
            package = root/'package'
            (package/'lib').mkdir(parents=True)
            library = package/'lib/libroutervpn_tor.so'
            library.write_bytes(b'owned test boundary')
            verified, calls, generated = [], [], []
            tor = SimpleNamespace(TORPACK=SimpleNamespace(PACKAGE=SimpleNamespace(
                verify=lambda path, target: verified.append((path, target)))))

            def module(name, relative):
                if relative == 'deploy/prepare-mobile-tor.py':
                    return tor
                self.assertEqual(relative, 'deploy/test_android_multihop_pinned.py')
                return SimpleNamespace(android_json_dependency=lambda root, env: root/'android-json.jar')

            def run(command, *, cwd, env, timeout, **kwargs):
                self.assertGreater(timeout, 0)
                calls.append(command)
                if len(calls) == 1:
                    self.assertTrue(kwargs['check'])
                    self.assertEqual(Path(command[1]), ROOT/('android/test_android_external_entries.py'
                                     if target == 'android' else 'deploy/test_ios_tor_profile.py'))
                    if fault == 'host':
                        raise subprocess.CalledProcessError(1, command)
                    directory = Path(env['ROUTERVPN_'+target.upper()+'_EXTERNAL_GRAPHS'])
                    generated.append(directory)
                    for name in set.union(*names(target)):
                        (directory/name).write_text('{}')
                    if fault == 'missing-paired':
                        (directory/'wg-off-shadowsocks-auto.json').unlink()
                    return subprocess.CompletedProcess(command, 0)
                self.assertEqual(Path(cwd), vendor)
                self.assertEqual(command[:4], ['go', 'test', '-mod=readonly', '-json'])
                self.assertEqual(command[command.index('-run')+1], '^TestRouterExternalGeneratedNativeGraphs$')
                self.assertEqual(env['ROUTERVPN_NATIVE_EXTERNAL_GRAPH_COUNT'], '570')
                self.assertEqual(env['ROUTERVPN_REQUIRE_EXTERNAL_GRAPHS'], '1')
                self.assertEqual(Path(env['ROUTERVPN_NATIVE_EXTERNAL_GRAPHS']), generated[0])
                if fault == 'native':
                    return subprocess.CompletedProcess(command, 1, 'native constructor failed')
                passed = set.union(*names(target))
                if fault == 'missing-native-paired':
                    passed.remove('wg-off-shadowsocks-auto.json')
                if fault == 'module-changed':
                    (vendor/'go.sum').write_text('changed during verification')
                events = [{'Action': 'pass', 'Test': G.TEST+'/'+name} for name in sorted(passed)]
                return subprocess.CompletedProcess(command, 0, '\n'.join(json.dumps(event) for event in events))

            with patch.object(G, 'module', side_effect=module), \
                 patch.object(G.HOST, 'environment', return_value={}), \
                 patch.object(G.subprocess, 'check_output', return_value='wrong-pin' if fault == 'pin' else G.PIN), \
                 patch.object(G.subprocess, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                if fault:
                    with self.assertRaises((ValueError, RuntimeError, subprocess.CalledProcessError)):
                        G.run(vendor, target, package, 'go')
                else:
                    G.run(vendor, target, package, 'go')
                    self.assertEqual(verified, [(package, 'host-test'), (package, 'host-test')])
            for directory in generated:
                self.assertFalse(directory.exists(), 'captured private graphs survived gate completion')
            return len(calls)

    def test_actual_runner_verifies_all_570_native_results_on_both_hosts(self):
        for target in ('android', 'ios'):
            with self.subTest(target=target):
                self.assertEqual(self.exercise(target), 2)

    def test_native_success_cannot_hide_a_missing_execution_or_source_change(self):
        for fault in ('pin', 'reader', 'host', 'missing-paired', 'native', 'missing-native-paired', 'module-changed'):
            with self.subTest(fault=fault):
                calls = self.exercise(fault=fault)
                self.assertEqual(calls, 0 if fault in ('pin', 'reader') else 1 if fault in ('host', 'missing-paired') else 2)


if __name__ == '__main__':
    unittest.main()
