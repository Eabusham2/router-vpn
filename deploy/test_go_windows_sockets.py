#!/usr/bin/env python3
"""Exercise exact upstream preimages, atomic publication and patch provenance."""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('windows_go_sockets', ROOT / 'deploy/prepare-go-windows-sockets.py')
PATCH = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PATCH)


class WindowsGoSockets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected = json.loads(subprocess.check_output(
            [os.environ.get('GO', 'go'), 'env', '-json', 'GOVERSION', 'GOROOT'], text=True))
        if selected['GOVERSION'] != PATCH.TOOLCHAIN:
            raise RuntimeError('Go socket backport tests require the pinned compiler')
        installed = Path(selected['GOROOT'])
        cls.originals = {}
        for name, _, _, old, new in PATCH.PATCHES:
            raw = (installed / name).read_bytes()
            # The workflow has already prepared its private compiler. Recover
            # the exact checked original solely to test rejection/publication.
            if (installed / PATCH.RECEIPT).is_file():
                PATCH.verify(installed)
                raw = raw.replace(new, old, 1)
            cls.originals[name] = raw

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix='go-sockets-test-')
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name) / 'original'
        self.output = Path(self.workspace.name) / 'owned'
        self.root.mkdir()
        (self.root / 'VERSION').write_text(PATCH.TOOLCHAIN + '\ntime 2026-05-05\n')
        for name, raw in self.originals.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        (self.root / 'unchanged.txt').write_bytes(b'original toolchain input\n')

    def test_exact_two_site_patch_preserves_original_and_reuses_owned_copy(self):
        captured = {p: (self.root / p).read_bytes() for p in self.originals}
        self.assertEqual(PATCH.prepare_root(self.root, self.output), self.output)
        self.assertEqual(PATCH.verify(self.output), self.output)
        for name, _, _, old, new in PATCH.PATCHES:
            self.assertEqual((self.root / name).read_bytes(), captured[name])
            self.assertEqual((self.output / name).read_bytes(), captured[name].replace(old, new, 1))
        self.assertEqual((self.output / 'unchanged.txt').read_bytes(), b'original toolchain input\n')
        self.assertEqual(PATCH.prepare_root(self.root, self.output), self.output)
        self.assertEqual(PATCH.prepare_root(self.output, self.root), self.output)
        self.assertEqual(json.loads((self.output / PATCH.RECEIPT).read_bytes()), PATCH.receipt())

    def test_either_source_drift_is_rejected_before_publication(self):
        for name in self.originals:
            with self.subTest(source=name):
                path = self.root / name
                path.write_bytes(self.originals[name] + b'\n// unexpected source drift\n')
                with self.assertRaisesRegex(ValueError, 'preimage differs'):
                    PATCH.prepare_root(self.root, self.output)
                self.assertFalse(self.output.exists())
                path.write_bytes(self.originals[name])

    def test_wrong_version_and_partial_unrecorded_patch_are_rejected(self):
        (self.root / 'VERSION').write_text('go1.26.4\n')
        with self.assertRaisesRegex(ValueError, 'exact Go 1.26.3'):
            PATCH.prepare_root(self.root, self.output)
        (self.root / 'VERSION').write_text(PATCH.TOOLCHAIN + '\n')
        name, _, _, old, new = PATCH.PATCHES[0]
        (self.root / name).write_bytes(self.originals[name].replace(old, new, 1))
        with self.assertRaisesRegex(ValueError, 'preimage differs'):
            PATCH.prepare_root(self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_changed_published_source_or_identity_never_reuses(self):
        PATCH.prepare_root(self.root, self.output)
        name = PATCH.PATCHES[1][0]
        (self.output / name).write_bytes(self.originals[name])
        with self.assertRaisesRegex(ValueError, 'source changed'):
            PATCH.prepare_root(self.root, self.output)
        (self.output / name).write_bytes(PATCH.patched_sources(self.root)[name])
        (self.output / PATCH.RECEIPT).write_text('{}\n')
        with self.assertRaisesRegex(ValueError, 'identity differs'):
            PATCH.prepare_root(self.root, self.output)

    def test_original_tree_is_not_a_valid_output(self):
        with self.assertRaisesRegex(ValueError, 'original toolchain'):
            PATCH.prepare_root(self.root, self.root / 'owned')
        self.assertFalse((self.root / 'owned').exists())

    def test_live_fallback_requires_prepared_source_without_mutating_toolchain(self):
        installed = json.dumps({'GOVERSION': PATCH.TOOLCHAIN, 'GOROOT': str(self.root)})
        with mock.patch.object(PATCH.subprocess, 'check_output', return_value=installed) as compiler, \
                mock.patch.object(PATCH, 'prepare_root', side_effect=AssertionError('live preparation')):
            with self.assertRaisesRegex(ValueError, 'regular file'):
                PATCH.environment('/selected/go', env={'PATH': '/selected'}, require_prepared=True)
            self.assertEqual(compiler.call_count, 1)
        self.assertFalse(self.output.exists())
        owned = PATCH.prepare_root(self.root, self.output)
        binary = owned / 'bin' / ('go.exe' if os.name == 'nt' else 'go')
        binary.parent.mkdir()
        binary.write_bytes(b'captured compiler boundary\n')
        installed = json.dumps({'GOVERSION': PATCH.TOOLCHAIN, 'GOROOT': str(owned)})
        with mock.patch.object(PATCH.subprocess, 'check_output', return_value=installed) as compiler, \
                mock.patch.object(PATCH, 'prepare_root', side_effect=AssertionError('live preparation')):
            env = PATCH.environment('/selected/go', env={'PATH': '/selected'}, require_prepared=True)
            self.assertEqual(compiler.call_count, 2)
        self.assertEqual(env['GOROOT'], str(owned))
        self.assertEqual(env['GOTOOLCHAIN'], 'local')
        self.assertEqual(env['ROUTERVPN_GO_WINDOWS_SOCKETS_SHA256'], PATCH.identity())


if __name__ == '__main__':
    unittest.main(verbosity=2)
