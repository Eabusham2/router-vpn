#!/usr/bin/env python3
"""Verify deterministic server-only composition and factory source ownership."""
from pathlib import Path
from unittest import mock
import importlib.util
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('server_pq',ROOT/'deploy/prepare-server-pq.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


class ServerPreparation(unittest.TestCase):
    def fixture(self, root):
        (root/'go.mod').write_text('module github.com/sagernet/sing-box\n')

    def test_exact_server_files_and_idempotence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root)
            with mock.patch.object(P.subprocess,'check_output',return_value=P.PQ.CORE+'\n'),mock.patch.object(P.PQ,'prepare') as endpoint,mock.patch.object(P.BIND,'prepare') as bind:
                P.prepare(root)
                endpoint.assert_called_once_with(root);bind.assert_called_once_with(root)
                first={str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
                P.prepare(root)
                self.assertEqual(first,{str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()})
            for source,destination in P.COPIES.items():
                data=(ROOT/source).read_bytes()
                if destination.endswith('.c'):data=P.C_TAG+data
                self.assertEqual((root/destination).read_bytes(),data)
            self.assertFalse((root/'protocol/routervpnpq/routervpn_pq_jni.c').exists())

    def test_wrong_pin_rejected_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root)
            with mock.patch.object(P.subprocess,'check_output',return_value='0'*40),mock.patch.object(P.PQ,'prepare') as endpoint:
                with self.assertRaisesRegex(ValueError,'exact pinned'):P.prepare(root)
                endpoint.assert_not_called()
            self.assertFalse((root/'protocol').exists())

    def test_foreign_native_code_and_links_are_preserved(self):
        for relative in P.COPIES.values():
            for linked in (False,True):
                with self.subTest(path=relative,linked=linked),tempfile.TemporaryDirectory() as tmp:
                    root=Path(tmp);self.fixture(root)
                    path=root/relative;path.parent.mkdir(parents=True,exist_ok=True)
                    other=root/'do-not-touch';other.write_text('unrelated')
                    if linked:path.symlink_to(other)
                    else:path.write_text('unrelated')
                    with mock.patch.object(P.subprocess,'check_output',return_value=P.PQ.CORE+'\n'),mock.patch.object(P.PQ,'prepare') as endpoint:
                        with self.assertRaises(ValueError):P.prepare(root)
                        endpoint.assert_not_called()
                    self.assertEqual(path.read_text(),'unrelated');self.assertEqual(other.read_text(),'unrelated')

    def test_source_digest_contains_crypto_lock_and_all_adapters(self):
        sources=P.inputs()
        self.assertEqual(len(sources),len(set(sources)))
        for name in ('mobile/rosenpass/Cargo.toml','mobile/rosenpass/Cargo.lock','mobile/rosenpass/src/lib.rs','mobile/pq/native_factory.go.tmpl','mobile/pq/endpoint.go.tmpl','mobile/rosenpass/routervpn_pq_host.c','deploy/mobile_wireguard_bind_policy.py'):
            self.assertIn(ROOT/name,sources)
        self.assertEqual(len(P.digest()),64)
        # Mobile preparation must not accidentally link the server C ABI.
        mobile=(ROOT/'deploy/prepare-mobile-pq.py').read_text()
        self.assertNotIn("'protocol/routervpnpq/native_factory.go'",mobile)
        self.assertNotIn('routervpn_pq_host.c',mobile)


if __name__=='__main__':unittest.main()
