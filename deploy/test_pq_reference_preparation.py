#!/usr/bin/env python3
"""Exercise ownership and negative boundaries of the test-only PQ build gate."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pq_reference_preparation', ROOT/'deploy/build_pq_reference_fixture.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


class PQReferencePreparation(unittest.TestCase):
    def core(self, root):
        core = root/'core'
        core.mkdir()
        for relative in P.COPIES.values():
            (core/relative).parent.mkdir(parents=True, exist_ok=True)
        return core

    def test_exact_copy_and_failure_cleanup_preserve_existing_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            core = self.core(Path(tmp))
            first, relative = next(iter(P.COPIES.items()))
            existing = core/relative
            original = (ROOT/first).read_bytes()
            existing.write_bytes(original)
            with self.assertRaisesRegex(RuntimeError, 'native failure'):
                with P.test_sources(core):
                    for source, destination in P.COPIES.items():
                        self.assertEqual((core/destination).read_bytes(), (ROOT/source).read_bytes())
                    raise RuntimeError('native failure')
            self.assertEqual(existing.read_bytes(), original)
            self.assertTrue(all(not (core/path).exists() for path in list(P.COPIES.values())[1:]))

    def test_foreign_source_rejects_before_any_copy(self):
        for linked in (False, True):
            with self.subTest(linked=linked), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                core = self.core(root)
                foreign = root/'unrelated.go'
                foreign.write_text('unrelated owner')
                path = core/list(P.COPIES.values())[-1]
                if linked:
                    path.symlink_to(foreign)
                else:
                    path.write_bytes(foreign.read_bytes())
                with self.assertRaises(ValueError):
                    with P.test_sources(core):
                        self.fail('foreign test source reached compilation')
                self.assertEqual(foreign.read_text(), 'unrelated owner')
                self.assertEqual(path.read_text(), 'unrelated owner')
                self.assertTrue(all(not (core/name).exists() for name in list(P.COPIES.values())[:-1]))

    def test_ancestor_alias_keeps_copy_and_cleanup_with_the_captured_owner(self):
        # Reproduce /var -> /private/var without requiring macOS. Retarget the
        # ancestor after staging: cleanup still owns only the original files.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, replacement = root/'physical', root/'replacement'
            original.mkdir()
            replacement.mkdir()
            core = self.core(original)
            foreign = self.core(replacement)
            for relative in P.COPIES.values():
                (foreign/relative).write_text('replacement owner')
            alias = root/'var'
            alias.symlink_to(original, target_is_directory=True)
            with P.test_sources(alias/'core'):
                for source, relative in P.COPIES.items():
                    self.assertEqual((core/relative).read_bytes(), (ROOT/source).read_bytes())
                alias.unlink()
                alias.symlink_to(replacement, target_is_directory=True)
            for relative in P.COPIES.values():
                self.assertFalse((core/relative).exists())
                self.assertEqual((foreign/relative).read_text(), 'replacement owner')

    def test_linked_core_escaped_directory_and_adjacent_prefix_are_rejected(self):
        for kind in ('core', 'directory', 'adjacent-prefix'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                core = self.core(root)
                foreign = root/'core-other'
                foreign.mkdir()
                sentinel = foreign/'source.go'
                sentinel.write_text('foreign owner')
                relative = 'source.go'
                if kind == 'core':
                    alias = root/'alias'
                    alias.symlink_to(core, target_is_directory=True)
                    core = alias
                elif kind == 'directory':
                    (core/'linked').symlink_to(foreign, target_is_directory=True)
                    relative = 'linked/source.go'
                else:
                    relative = '../core-other/source.go'
                with self.assertRaisesRegex(ValueError, 'escapes the captured core'):
                    P.contained(core, relative)
                self.assertEqual(sentinel.read_text(), 'foreign owner')

    def test_exact_source_verification_captures_an_ancestor_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            physical = root/'physical'
            physical.mkdir()
            core = self.core(physical)
            (core/'go.mod').write_text('module github.com/sagernet/sing-box\n')
            sources = {**P.SERVER.COPIES,
                       'mobile/pq/endpoint.go.tmpl': 'protocol/routervpnpq/endpoint.go',
                       'mobile/pq/wireguard_protocol.go.tmpl': 'protocol/wireguard/routervpn_pq.go',
                       'mobile/pq/wireguard_transport.go.tmpl': 'transport/wireguard/routervpn_pq.go',
                       'mobile/amnezia/endpoint.go.tmpl': 'protocol/routervpnamnezia/endpoint.go',
                       'mobile/amnezia/pq_reference_fixture.go.tmpl': 'protocol/routervpnamnezia/pq_reference_fixture.go'}
            for source, relative in sources.items():
                destination = core/relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                raw = (ROOT/source).read_bytes()
                destination.write_bytes(P.SERVER.C_TAG+raw if relative.endswith('.c') else raw)
            P.BUILD.POLICY.AMNEZIA.prepare_policies(core)
            alias = root/'var'
            alias.symlink_to(physical, target_is_directory=True)
            with mock.patch.object(P.subprocess, 'check_output', return_value=P.BUILD.PIN) as git:
                self.assertEqual(P.verify_sources(alias/'core'), core.resolve())
                self.assertEqual(git.call_args.args[0], ['git', '-C', str(core.resolve()), 'rev-parse', 'HEAD'])
                path = core/'protocol/routervpnpq/endpoint.go'
                path.write_bytes(path.read_bytes()+b'\n// foreign source\n')
                with self.assertRaisesRegex(ValueError, 'exact shipping native factory'):
                    P.verify_sources(alias/'core')

    def test_cleanup_does_not_delete_a_replacement_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            core = self.core(Path(tmp))
            path = core/next(iter(P.COPIES.values()))
            with self.assertRaisesRegex(ValueError, 'owner changed'):
                with P.test_sources(core):
                    path.write_text('replacement owner')
            self.assertEqual(path.read_text(), 'replacement owner')

    def test_wrong_native_core_rejected_before_test_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            core = self.core(Path(tmp))
            (core/'go.mod').write_text('module github.com/sagernet/sing-box\n')
            with mock.patch.object(P.subprocess, 'check_output', return_value='0'*40):
                with self.assertRaisesRegex(ValueError, 'exact prepared pinned core'):
                    P.verify_sources(core)
            self.assertTrue(all(not (core/name).exists() for name in P.COPIES.values()))

    def test_existing_and_linked_key_workspaces_never_run_the_generator(self):
        for linked in (False, True):
            with self.subTest(linked=linked), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                foreign = root/'foreign'
                foreign.mkdir()
                (foreign/'sentinel').write_text('keep this owner')
                private = root/'private'
                if linked:
                    private.symlink_to(foreign, target_is_directory=True)
                else:
                    private.mkdir()
                with mock.patch.object(P.BUILD.PQ, 'run') as run:
                    with self.assertRaisesRegex(ValueError, 'new private key workspace'):
                        P.generate_keys('linux/amd64', root/'cache', private/'keys')
                    run.assert_not_called()
                self.assertEqual((foreign/'sentinel').read_text(), 'keep this owner')

    def test_failed_compiler_selection_removes_only_the_new_owned_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            foreign = root/'keep'
            foreign.write_text('unrelated')
            with mock.patch.object(P.BUILD.PQ, 'run', return_value='rustc wrong-version'):
                with self.assertRaisesRegex(ValueError, 'exact pinned Rust'):
                    P.generate_keys('linux/amd64', root/'cache', root/'private/keys')
            self.assertFalse((root/'private').exists())
            self.assertEqual(foreign.read_text(), 'unrelated')

    def test_key_output_shape_does_not_accept_duplicates_or_extra_files(self):
        # These bytes exercise only the file-shape validator. Genuine KEM keys
        # are separately generated and authenticated by the actual native gate.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index, name in enumerate(('client', 'server', 'other'), 1):
                for kind in ('secret', 'public'):
                    path = root/(name+'.'+kind)
                    path.write_bytes(bytes([index])*64)
                    path.chmod(0o600)
            P.key_files(root)
            (root/'server.public').write_bytes((root/'client.public').read_bytes())
            with self.assertRaisesRegex(ValueError, 'reused'):
                P.key_files(root)
            (root/'server.public').write_bytes(bytes([2])*64)
            (root/'unexpected').write_bytes(b'not a key')
            with self.assertRaisesRegex(ValueError, 'exactly three'):
                P.key_files(root)


if __name__ == '__main__':
    unittest.main()
