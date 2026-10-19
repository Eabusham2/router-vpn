#!/usr/bin/env python3
"""Test exact native patch ownership and execute the shipping Go close policy."""
from pathlib import Path
import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('openvpn_close_policy', ROOT/'deploy/mobile_openvpn_close_policy.py')
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class Tests(unittest.TestCase):
    def test_exact_pin_idempotency_and_drift_rejection(self):
        self.assertEqual(POLICY.SOURCE_SHA, '03f8e07a0fb478220ad0a1860acb499dd3b797bb')
        # This fixture exercises the patch transaction; the native runner
        # additionally checks the complete upstream file against SOURCE_SHA.
        original = 'func close() {\n' + POLICY.OLD + '\n}\n'
        with mock.patch.object(POLICY, 'SOURCE_SHA', POLICY.blobsha(original.encode())):
            fixed = POLICY.patch(original)
            self.assertEqual(POLICY.patch(fixed), fixed)
            for changed in (original+'changed', fixed+'changed', fixed.replace('c.device.Close()', 'nil'), fixed+POLICY.NEW):
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    POLICY.patch(changed)
        with self.assertRaises(ValueError):
            POLICY.patch(original)

    def test_linked_helper_prevents_source_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root/'protocol/openvpn/client.go'
            source.parent.mkdir(parents=True)
            source.write_text('unchanged source')
            target = root/'unrelated.go'
            target.write_text('unrelated content')
            source.with_name('routervpn_close_policy.go').symlink_to(target)
            with self.assertRaises(ValueError):
                POLICY.prepare(root)
            self.assertEqual(source.read_text(), 'unchanged source')
            self.assertEqual(target.read_text(), 'unrelated content')

    def test_runtime_cache_and_native_gate_include_policy(self):
        preparation = (ROOT/'deploy/prepare-mobile-multihop.py').read_text()
        self.assertIn('OPENVPN_CLOSE.inputs()', preparation)
        self.assertIn('OPENVPN_CLOSE.prepare(vendor)', preparation)
        self.assertIn(Path(__file__).resolve(), POLICY.inputs())
        runner = (ROOT/'deploy/test_mobile_openvpn_pinned.sh').read_text()
        self.assertIn('mobile_openvpn_close_policy.py', runner)
        self.assertIn('./protocol/openvpn -run', runner)
        self.assertIn('TestRouterVPNOpenVPNCloseError', runner)
        contract = (ROOT/'deploy/test_mobile_openvpn_contract.py').read_text()
        self.assertIn('test_mobile_openvpn_close_policy.py', contract)
        loopback = (ROOT/'mobile/routervpn_openvpn_native_test.go.tmpl').read_text()
        self.assertIn('if err := client.Close(); err != nil {\n\t\t\t\tt.Fatal(err)', loopback)
        self.assertIn('native client retained its listener after shutdown', loopback)
        self.assertNotIn('routerVPNOpenVPNCloseError', loopback)

    def test_shipping_error_classifier_rejects_mixed_failures(self):
        go = shutil.which('go')
        if not go:
            self.skipTest('Go is required for the shipping close-policy matrix')
        with tempfile.TemporaryDirectory(prefix='routervpn-openvpn-close-') as tmp:
            tmp = Path(tmp)
            (tmp/'go.mod').write_text('module routervpn-openvpn-close-test\n\ngo 1.24\n')
            for name in ('close_policy.go', 'close_policy_test.go'):
                (tmp/name).write_bytes((ROOT/'mobile/openvpn'/(name+'.tmpl')).read_bytes())
            subprocess.run([go, 'test', '-race', '-count=1', '-timeout=30s', './...'], cwd=tmp, check=True, timeout=90)
            original = (tmp/'close_policy.go').read_text()
            mutations = [
                ('skip-normalization', original.replace('if routerVPNOpenVPNOnlyClosed(err, 0) {', 'if false {')),
                ('hide-real-errors', original.replace('return err\n}', 'return nil\n}', 1)),
            ]
            for name, changed in mutations:
                self.assertNotEqual(changed, original, name+' mutation must change shipping source')
                (tmp/'close_policy.go').write_text(changed)
                result = subprocess.run([go, 'test', '-count=1', '-timeout=30s', './...'], cwd=tmp, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=90)
                self.assertNotEqual(result.returncode, 0, name+' mutation passed the real policy matrix')
                self.assertIn('--- FAIL: TestRouterVPNOpenVPNCloseError', result.stdout)
            print('Shipping OpenVPN close-policy matrix and both negative controls passed')


if __name__ == '__main__':
    unittest.main()
