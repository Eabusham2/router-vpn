#!/usr/bin/env python3
"""Test exact native patch ownership and execute the shipping Go close policy."""
from pathlib import Path
import contextlib
import hashlib
import os
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

    @contextlib.contextmanager
    def prepared_fixture(self):
        with tempfile.TemporaryDirectory(prefix='routervpn-openvpn-close-source-') as tmp:
            root = Path(tmp).resolve()
            directory = root/'protocol/openvpn'
            directory.mkdir(parents=True)
            original = 'func clientClose() {\n' + POLICY.OLD + '\n}\n'
            server = ('func serverClose() {\nserverErr = s.server.Close()\n'
                      '<-s.readLoopDone\ndeviceErr = s.device.Close()\n' + POLICY.SERVER_OLD +
                      '\nreturn E.Errors(serverErr, deviceErr, listenerErr)\n}\n')
            (directory/'client.go').write_text(original)
            (directory/'server.go').write_text(server)
            with mock.patch.object(POLICY, 'SOURCE_SHA', POLICY.blobsha(original.encode())), \
                    mock.patch.object(POLICY, 'SERVER_SOURCE_SHA', POLICY.blobsha(server.encode())):
                yield root, directory, original, server

    def test_exact_server_pin_idempotency_and_other_cleanup_preserved(self):
        self.assertEqual(POLICY.SERVER_SOURCE_SHA, 'cd8ccc66d6b05a9c733628ffba2c234dfa66e065')
        with self.prepared_fixture() as (_, _, _, original):
            fixed = POLICY.patch_server(original)
            self.assertEqual(fixed, original.replace(POLICY.SERVER_OLD, POLICY.SERVER_NEW, 1))
            self.assertEqual(POLICY.patch_server(fixed), fixed)
            for changed in (original+'changed', fixed+'changed', fixed+POLICY.SERVER_NEW,
                            fixed.replace('serverErr = s.server.Close()', 'serverErr = nil'),
                            fixed.replace('deviceErr = s.device.Close()', 'deviceErr = nil'),
                            fixed.replace('<-s.readLoopDone', ''),
                            fixed.replace('return E.Errors(serverErr, deviceErr, listenerErr)', 'return nil')):
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    POLICY.patch_server(changed)
        with self.assertRaises(ValueError):
            POLICY.patch_server(original)

    def test_complete_preparation_and_read_only_source_receipt(self):
        with self.prepared_fixture() as (root, directory, client, server):
            with self.assertRaises(ValueError):
                POLICY.verify(root)
            POLICY.prepare(root)
            expected = {'client.go': POLICY.patch(client).encode(), 'server.go': POLICY.patch_server(server).encode(),
                        'routervpn_close_policy.go': (ROOT/'mobile/openvpn/close_policy.go.tmpl').read_bytes()}
            self.assertEqual({p.name: p.read_bytes() for p in directory.iterdir()}, expected)
            records = POLICY.verify(root)
            self.assertEqual(records, {'protocol/openvpn/'+name: hashlib.sha256(raw).hexdigest() for name, raw in expected.items()})
            before = {p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in directory.iterdir()}
            self.assertEqual(POLICY.verify(root), records)
            self.assertEqual({p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in directory.iterdir()}, before)
            POLICY.prepare(root)
            self.assertEqual(POLICY.verify(root), records)

    def test_server_or_helper_drift_rejects_before_client_write(self):
        for subject in ('server', 'helper'):
            with self.subTest(subject=subject), self.prepared_fixture() as (root, directory, client, server):
                if subject == 'server':
                    (directory/'server.go').write_text(server+'unrelated source')
                else:
                    (directory/'routervpn_close_policy.go').write_text('unrelated helper')
                before = {p.name: p.read_bytes() for p in directory.iterdir()}
                with self.assertRaises(ValueError):
                    POLICY.prepare(root)
                self.assertEqual({p.name: p.read_bytes() for p in directory.iterdir()}, before)
                self.assertEqual((directory/'client.go').read_text(), client)

    def test_source_receipt_rejects_unpatched_or_changed_owned_inputs(self):
        for subject in ('client.go', 'server.go', 'routervpn_close_policy.go'):
            with self.subTest(subject=subject), self.prepared_fixture() as (root, directory, client, server):
                POLICY.prepare(root)
                actual = directory/subject
                fixed = actual.read_bytes()
                unpatched = {'client.go': client.encode(), 'server.go': server.encode(), 'routervpn_close_policy.go': b'unrelated helper'}[subject]
                actual.write_bytes(unpatched)
                with self.assertRaises(ValueError):
                    POLICY.verify(root)
                self.assertEqual(actual.read_bytes(), unpatched)
                actual.write_bytes(fixed+b'unrelated edit')
                with self.assertRaises(ValueError):
                    POLICY.verify(root)
                actual.write_bytes(fixed)
                POLICY.verify(root)

    def test_each_linked_output_refuses_before_any_source_write(self):
        for subject in ('client.go', 'server.go', 'routervpn_close_policy.go'):
            with self.subTest(subject=subject), self.prepared_fixture() as (root, directory, client, server):
                target = root/'foreign.go'
                actual = directory/subject
                raw = actual.read_bytes() if actual.exists() else (ROOT/'mobile/openvpn/close_policy.go.tmpl').read_bytes()
                target.write_bytes(raw)
                if actual.exists(): actual.unlink()
                actual.symlink_to(target)
                before = {name: (directory/name).read_bytes() for name in ('client.go', 'server.go')}
                with self.assertRaises(ValueError):
                    POLICY.prepare(root)
                self.assertTrue(actual.is_symlink())
                self.assertEqual(target.read_bytes(), raw)
                self.assertEqual({name: (directory/name).read_bytes() for name in before}, before)

    def test_linked_parent_and_hardlinked_sources_cannot_change_foreign_owner(self):
        with self.prepared_fixture() as (root, directory, client, server):
            sibling = root/'outside'
            directory.rename(sibling)
            directory.symlink_to(sibling, target_is_directory=True)
            with self.assertRaises(ValueError):
                POLICY.prepare(root)
            self.assertEqual((sibling/'client.go').read_text(), client)
            self.assertEqual((sibling/'server.go').read_text(), server)
        for name in ('client.go', 'server.go', 'routervpn_close_policy.go'):
            with self.subTest(name=name), self.prepared_fixture() as (root, directory, client, server):
                actual = directory/name
                if not actual.exists(): actual.write_bytes((ROOT/'mobile/openvpn/close_policy.go.tmpl').read_bytes())
                other = root/'other-owner.go'
                os.link(actual, other)
                before = {p.name: p.read_bytes() for p in directory.iterdir()}
                with self.assertRaises(ValueError):
                    POLICY.prepare(root)
                self.assertEqual({p.name: p.read_bytes() for p in directory.iterdir()}, before)
                self.assertEqual(other.read_bytes(), before[name])

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
        self.assertIn('TestRouterVPNOpenVPN(CloseError|ServerCloseOwnedListener)', runner)
        self.assertIn('server_close_policy_test.go.tmpl', runner)
        self.assertIn(ROOT/'mobile/openvpn/server_close_policy_test.go.tmpl', POLICY.inputs())
        native = (ROOT/'deploy/test_desktop_node_physical.py').read_text()
        self.assertIn('close_policy = PREP.RELAY.OPENVPN_CLOSE', native)
        self.assertIn('records.update(close_policy.verify(source))', native)
        self.assertIn('for path in close_policy.inputs():', native)
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
