#!/usr/bin/env python3
"""Require native Darwin host opt-in, unique verdicts and exact bundle receipts."""
from pathlib import Path
import hashlib
import importlib.util
import json
import re
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('macos_external_host_gate', ROOT/'deploy/test_macos_external_host.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class NativeHostVerdicts(unittest.TestCase):
    def completed(self):
        lines = ['--- PASS: '+name+' (0.5s)' for name in (G.TEST, *G.POLICY_TESTS)]
        for case in G.CASES:
            lines += ['    --- PASS: '+G.TEST+'/'+case+' (0.1s)']
        for case in G.POSITIVE_CASES:
            lines += ['    desktop_external_darwin_native_test.go:77: '+G.success_receipt(case),
                      '    desktop_external_darwin_native_test.go:88: actual sealed Darwin latency accepted '+case+
                      ': held TLS Cancel joined, foreign cancellation and replay refused, Retest50 actual responses, original session child PF and MTU retained']
        for case in G.NEGATIVE_CASES:
            lines += ['    desktop_external_darwin_native_test.go:99: '+G.refusal_receipt(case)]
        lines += ['    desktop_external_darwin_native_test.go:87: '+G.MTU_RECEIPT]
        return '\n'.join([*lines, 'PASS'])+'\n'

    def test_required_case_inventory_is_actual_compiled_native_inventory(self):
        main = (ROOT/'cmd/client/desktop_external_darwin_native_test.go').read_text()
        body = re.search(r'func TestMacOSRetainedExternalNativeSealedProtocols[\s\S]*?\[\]string\{([^}]+)\}', main)
        self.assertIsNotNone(body)
        actual = re.findall(r'"([a-z0-9-]+)"', body.group(1))
        final = None
        for source in (ROOT/'cmd/client').glob('*darwin_native_test.go'):
            for name, body in re.findall(r'var (macOSExternal\w+Cases) = \[\]string\{([^}]+)\}', source.read_text()):
                cases = re.findall(r'"([a-z0-9-]+)"', body)
                actual.extend(cases)
                if name == 'macOSExternalWireGuardFinalCases':
                    final = cases
        self.assertCountEqual(G.CASES, actual)
        self.assertIsNotNone(final)
        self.assertEqual(tuple(final[:6]), tuple(case for case in G.POSITIVE_CASES if '-entry-wireguard' in case))
        self.assertEqual(tuple(final[6:]), tuple(case for case in G.NEGATIVE_CASES if '-entry-wireguard' in case))

    def test_complete_unique_native_execution(self):
        G.check_verdict(self.completed())

    def test_missing_duplicate_prefixed_and_incomplete_verdicts(self):
        valid = self.completed()
        for case in G.CASES:
            line = '    --- PASS: '+G.TEST+'/'+case+' (0.1s)\n'
            for broken in (valid.replace(line, ''), valid.replace(line, line*2), valid.replace(line, 'diagnostic: '+line)):
                with self.subTest(case=case), self.assertRaises(ValueError):
                    G.check_verdict(broken)
        for name in G.POLICY_TESTS:
            line = '--- PASS: '+name+' (0.5s)\n'
            for broken in (valid.replace(line, ''), valid.replace(line, line*2), valid.replace(line, 'diagnostic: '+line)):
                with self.subTest(policy=name), self.assertRaises(ValueError):
                    G.check_verdict(broken)
        for broken in (valid.replace('PASS\n', ''), valid+'PASS\n', valid+'unfinished\n'):
            with self.assertRaises(ValueError):
                G.check_verdict(broken)

    def test_failure_skip_race_panic_build_error_never_counts(self):
        for failure in ('--- FAIL: unrelated (0.1s)', '--- SKIP: unrelated (0.1s)', 'FAIL', 'WARNING: DATA RACE',
                        'panic: unrelated', 'fatal error: deadlock', 'pkg [build failed]'):
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                G.check_verdict(failure+'\n'+self.completed())

    def test_each_protocol_requires_its_own_native_receipt(self):
        valid = self.completed()
        for case in G.POSITIVE_CASES:
            marker = 'actual sealed Darwin ordinary host accepted '+case+':'
            with self.subTest(case=case), self.assertRaises(ValueError):
                G.check_verdict(valid.replace(marker, 'diagnostic only:'))

    def test_each_protocol_requires_unique_actual_measurement_receipt(self):
        valid = self.completed()
        for case in G.POSITIVE_CASES:
            line = next(line for line in valid.splitlines(True) if 'actual sealed Darwin latency accepted '+case+':' in line)
            for broken in (valid.replace(line, ''), valid.replace(line, line*2), valid.replace(line, 'diagnostic only: '+line)):
                with self.subTest(case=case), self.assertRaises(ValueError):
                    G.check_verdict(broken)

    def test_each_layer_requires_unique_actual_negative_receipt(self):
        valid = self.completed()
        for case in G.NEGATIVE_CASES:
            line = next(line for line in valid.splitlines(True) if G.refusal_receipt(case) in line)
            for broken in (valid.replace(line, ''), valid.replace(line, line*2), valid.replace(line, 'diagnostic only: '+line)):
                with self.subTest(case=case), self.assertRaises(ValueError):
                    G.check_verdict(broken)

    def test_wireguard_requires_original_mtu_transfer_and_rollback(self):
        valid = self.completed()
        line = next(line for line in valid.splitlines(True) if G.MTU_RECEIPT in line)
        for broken in (valid.replace(line, ''), valid.replace(line, line*2), valid.replace(line, 'diagnostic only: '+line)):
            with self.assertRaises(ValueError):
                G.check_verdict(broken)

    def test_ordinary_build_never_mutates_native_host(self):
        with patch.object(G.platform, 'system', return_value='Darwin'), patch.object(G.platform, 'machine', return_value='arm64'), patch.object(G.os, 'getuid', return_value=501):
            for value in ('', '0', 'yes'):
                with self.assertRaises(ValueError):
                    G.required_host({G.FLAG: value})
            self.assertEqual(G.required_host({G.FLAG: '1'}), ('darwin/arm64', 501))
        with patch.object(G.BUILD, 'run') as run, patch.object(G.BUILD, 'reuse') as reuse:
            G.BUILD.verify_installed_darwin_host(None, Path('/unused'), 'darwin/arm64', {})
            run.assert_not_called()
            reuse.assert_not_called()

    def test_explicit_acceptance_rejects_foreign_host_and_architecture(self):
        with patch.object(G.platform, 'system', return_value='Linux'):
            with self.assertRaises(ValueError):
                G.required_host({G.FLAG: '1'})
        with patch.object(G.platform, 'system', return_value='Darwin'), patch.object(G.platform, 'machine', return_value='arm64'), patch.object(G.os, 'getuid', return_value=501):
            with self.assertRaises(ValueError):
                G.required_host({G.FLAG: '1', 'GOARCH': 'amd64'})

    def test_builder_requires_exact_original_bundle_source_and_all_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle/'NATIVE-RUNTIME.json').write_bytes(b'original delivered receipt\n')
            receipt = dict(schema=1, native=True, target='darwin/arm64', source_sha256='a'*64,
                           bundle_sha256=hashlib.sha256((bundle/'NATIVE-RUNTIME.json').read_bytes()).hexdigest(),
                           sealed_bundle_sha256='b'*64, images=dict(controller='c'*64, peer='d'*64),
                           cases=list(G.CASES), sources=dict(application={'a': 'e'*64}, peer={'b': 'f'*64}))
            environment = {G.FLAG: '1', 'GOOS': 'darwin', 'GOARCH': 'arm64'}
            def check(value):
                output = 'Native Darwin retained external acceptance: '+json.dumps(value)
                with patch.object(G.BUILD, 'reuse'), patch.object(G.BUILD, 'digest', return_value='a'*64), \
                     patch.object(G.BUILD.platform, 'system', return_value='Darwin'), patch.object(G.BUILD.platform, 'machine', return_value='arm64'), \
                     patch.object(G.BUILD, 'run', side_effect=['', output]) as run:
                    G.BUILD.verify_installed_darwin_host(None, bundle, 'darwin/arm64', environment)
                    self.assertNotIn('--source', run.call_args.args[0])
            check(receipt)
            for key, value in [('native', False), ('target', 'darwin/amd64'), ('source_sha256', 'f'*64),
                               ('bundle_sha256', 'f'*64), ('cases', list(G.CASES[:-1])), ('images', {'peer': 'd'*64}),
                               ('sources', {'application': {}, 'peer': {'b': 'f'*64}})]:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    check({**receipt, key: value})

    def test_builder_rejects_missing_repeated_and_duplicate_field_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle/'NATIVE-RUNTIME.json').write_bytes(b'original\n')
            prefix = 'Native Darwin retained external acceptance: '
            for output in ('no receipt', prefix+'{}\n'+prefix+'{}', prefix+'{"schema":1,"schema":1}'):
                with patch.object(G.BUILD, 'reuse'), patch.object(G.BUILD.platform, 'system', return_value='Darwin'), \
                     patch.object(G.BUILD.platform, 'machine', return_value='arm64'), patch.object(G.BUILD, 'run', side_effect=['', output]):
                    with self.assertRaises(ValueError):
                        G.BUILD.verify_installed_darwin_host(None, bundle, 'darwin/arm64',
                            {G.FLAG:'1','GOOS':'darwin','GOARCH':'arm64'})

    def test_workflow_explicitly_selects_gate_before_build_and_archive(self):
        text = (ROOT/'.github/workflows/desktop-native-runtime.yml').read_text()
        opt = text.index('export ROUTERVPN_DARWIN_NATIVE_HOST_ACCEPTANCE=1')
        build = text.index('python3 deploy/build-native-runtime.py "${runtime_args[@]}"')
        archive = text.index('python3 deploy/native-runtime-bundle.py archive')
        self.assertLess(opt, build)
        self.assertLess(build, archive)
        self.assertIn("if [[ '${{ matrix.target }}' == darwin/* ]]; then", text[:opt])


if __name__ == '__main__':
    unittest.main(verbosity=2)
