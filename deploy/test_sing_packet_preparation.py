#!/usr/bin/env python3
"""Integrity and isolation checks against the exact pinned sing module archive."""
from pathlib import Path
import importlib.util
import json
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sing_packet_patch', ROOT/'deploy/prepare-sing-packet-concurrency.py')
PATCH = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PATCH)


class PacketPreparation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        info = json.loads(subprocess.check_output(
            ['go', 'mod', 'download', '-json', PATCH.MODULE+'@'+PATCH.VERSION], cwd=ROOT, text=True))
        if info.get('Sum') != PATCH.SUM or info.get('Error'):
            raise ValueError('Test source does not match the pinned public module')
        cls.archive = Path(info['Zip'])
        cls.before = cls.archive.read_bytes()
        with zipfile.ZipFile(cls.archive) as archive:
            cls.originals = {name: archive.read(PATCH.PREFIX+name) for name in (*PATCH.PATCHES, 'LICENSE')}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root/PATCH.COPY
        self.target.mkdir()
        PATCH.extract_verified(self.archive, self.target)

    def test_only_verified_boundaries_change_and_license_archive_stay_identical(self):
        for name, original in self.originals.items():
            actual = (self.target/name).read_bytes()
            self.assertEqual(PATCH.transform(name, original), actual)
            self.assertEqual(PATCH.transform(name, actual, reverse=True), original)
        self.assertEqual(self.archive.read_bytes(), self.before)
        PATCH.verify_tree(self.target)
        for name in PATCH.PATCHES:
            with self.assertRaises(ValueError):
                PATCH.transform(name, self.originals[name]+b'\n// unrelated change\n')

    def test_missing_extra_reverted_and_unrelated_edits_are_rejected(self):
        cases = [('common/bufio/bind.go', self.originals['common/bufio/bind.go']),
                 ('common/bufio/bind_wait.go', self.originals['common/bufio/bind_wait.go']),
                 ('LICENSE', b'altered license'), ('go.mod', None), ('extra.go', b'package extra\n')]
        for name, replacement in cases:
            with self.subTest(name=name):
                path = self.target/name
                original = path.read_bytes() if path.exists() else None
                try:
                    if replacement is None:
                        path.unlink()
                    else:
                        path.write_bytes(replacement)
                    with self.assertRaises(ValueError):
                        PATCH.verify_tree(self.target)
                finally:
                    if original is None:
                        path.unlink()
                    else:
                        path.write_bytes(original)
        PATCH.verify_tree(self.target)

    def test_linked_output_and_unsafe_archive_paths_are_rejected(self):
        if hasattr(Path, 'symlink_to'):
            outside = self.root/'outside'
            outside.write_bytes(self.originals['LICENSE'])
            license = self.target/'LICENSE'
            license.unlink()
            try:
                license.symlink_to(outside)
            except OSError:
                license.write_bytes(self.originals['LICENSE'])  # Windows without symlink privilege.
            else:
                with self.assertRaises(ValueError):
                    PATCH.verify_tree(self.target)
                self.assertEqual(outside.read_bytes(), self.originals['LICENSE'])
        for name in ('../escaped', '/absolute', 'pkg/../../escaped', 'pkg//empty', 'bad\nname', 'bad\\name'):
            archive = self.root/'unsafe.zip'
            with zipfile.ZipFile(archive, 'w') as output:
                output.writestr(PATCH.PREFIX+name, b'data')
            with self.assertRaises(ValueError):
                PATCH.extract_verified(archive, self.root/'stage')
        self.assertFalse((self.root/'escaped').exists())

    def test_wrong_version_and_foreign_replacement_are_rejected(self):
        plans = ({'Require': []},
                 {'Require': [{'Path': PATCH.MODULE, 'Version': 'v0.0.0'}]},
                 {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}],
                  'Replace': [{'Old': {'Path': PATCH.MODULE}, 'New': {'Path': '/foreign'}}]})
        for plan in plans:
            with mock.patch.object(PATCH.subprocess, 'check_output', return_value=json.dumps(plan)), self.assertRaises(ValueError):
                PATCH.module_plan(self.root)

    def test_prepare_is_idempotent_and_rejects_foreign_selected_copy(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            if args[0] == 'git':
                return PATCH.CORE+'\n'
            if args[1:4] == ['mod', 'edit', '-json']:
                return json.dumps(plan)
            if args[1:5] == ['list', '-m', '-json', PATCH.MODULE]:
                return json.dumps({'Version': PATCH.VERSION, 'Replace': {'Path': './'+PATCH.COPY, 'Dir': str(self.target)}})
            raise AssertionError('Existing checked copy must not redownload: '+str(args))
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run') as run:
            PATCH.prepare(self.root)
            plan['Replace'] = [{'Old': {'Path': PATCH.MODULE, 'Version': PATCH.VERSION}, 'New': {'Path': './'+PATCH.COPY}}]
            PATCH.prepare(self.root)
            PATCH.verify(self.root)
            self.assertEqual(run.call_count, 2)
        plan['Replace'][0]['New']['Path'] = '/foreign'
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), self.assertRaises(ValueError):
            PATCH.verify(self.root)

    def test_patch_enters_native_cache_identity(self):
        spec = importlib.util.spec_from_file_location('amnezia_preparation', ROOT/'deploy/prepare-mobile-amnezia.py')
        preparation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preparation)
        self.assertIn(ROOT/'deploy/prepare-sing-packet-concurrency.py', preparation.inputs())
        self.assertIn(ROOT/'mobile/amnezia/packet_concurrency_test.go.tmpl', preparation.inputs())
        self.assertIn('../deploy/prepare-sing-packet-concurrency.py', (ROOT/'android/app/build.gradle').read_text())


if __name__ == '__main__':
    unittest.main()
