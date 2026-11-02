#!/usr/bin/env python3
"""Verify the actual pinned AWG archive, private replacement and build closure."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('amnezia_timer_preparation', ROOT / 'deploy/prepare-amnezia-timers.py')
PATCH = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PATCH)


class TimerPreparation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        info = json.loads(subprocess.check_output(
            ['go', 'mod', 'download', '-json', PATCH.MODULE + '@' + PATCH.VERSION], cwd=ROOT, text=True))
        if info.get('Path') != PATCH.MODULE or info.get('Sum') != PATCH.SUM or info.get('Error'):
            raise ValueError('Timer fixture did not retrieve the exact original AWG archive')
        cls.archive, cls.cache = Path(info['Zip']), Path(info['Dir'])
        cls.archive_before = cls.archive.read_bytes()
        with zipfile.ZipFile(cls.archive) as archive:
            cls.originals = {name[len(PATCH.PREFIX):]: archive.read(name) for name in archive.namelist()}
        cls.cache_before = cls.cache_snapshot()

    @classmethod
    def cache_snapshot(cls):
        return {name: (hashlib.sha256((cls.cache / name).read_bytes()).hexdigest(),
                       (cls.cache / name).stat().st_mode, (cls.cache / name).parent.stat().st_mode)
                for name in cls.originals}

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = self.root / PATCH.COPY
        self.target.mkdir()
        PATCH.extract_verified(self.archive, self.target)

    def tearDown(self):
        self.assertEqual(self.archive.read_bytes(), self.archive_before)
        self.assertEqual(self.cache_snapshot(), self.cache_before)

    def test_exact_original_pin_and_only_one_locked_state_change(self):
        self.assertEqual((PATCH.VERSION, PATCH.SUM),
                         ('v3.1.20260814', 'h1:l2AhBD+sFycU8Im81n/bZORMxW7fWtlZJEuJ4Hh0+z0='))
        original = self.originals[PATCH.TIMER]
        self.assertEqual(PATCH.git_blob(original), PATCH.BLOB)
        self.assertEqual(PATCH.original(PATCH.patch(original)), original)
        for name, data in self.originals.items():
            self.assertEqual((self.target / name).read_bytes(), PATCH.patch(data) if name == PATCH.TIMER else data)
        self.assertEqual((self.target / PATCH.TEST).read_bytes(), PATCH.test_source())
        PATCH.verify_tree(self.target)
        for data in (original + b'// drift\n', original.replace(PATCH.OLD, PATCH.NEW) + b'// drift\n'):
            with self.assertRaises(ValueError):
                PATCH.patch(data)
            with self.assertRaises(ValueError):
                PATCH.original(data)

    def test_complete_module_and_exact_test_are_required(self):
        faults = ((PATCH.TIMER, self.originals[PATCH.TIMER]),
                  ('LICENSE', b'changed license'), ('go.mod', None),
                  ('unowned.go', b'package unowned\n'), (PATCH.TEST, None),
                  (PATCH.TEST, PATCH.test_source() + b'// unreviewed assertion\n'))
        for name, replacement in faults:
            with self.subTest(name=name, missing=replacement is None):
                path = self.target / name
                before = path.read_bytes() if path.exists() else None
                try:
                    if replacement is None:
                        path.unlink()
                    else:
                        path.write_bytes(replacement)
                    with self.assertRaises(ValueError):
                        PATCH.verify_tree(self.target)
                finally:
                    if before is None:
                        path.unlink()
                    else:
                        path.write_bytes(before)
        PATCH.verify_tree(self.target)

    def test_aliased_source_is_rejected_without_changing_its_other_owner(self):
        outside = self.root / 'other-license'
        outside.write_bytes(self.originals['LICENSE'])
        path = self.target / 'LICENSE'
        path.unlink()
        os.link(outside, path)
        with self.assertRaises(ValueError):
            PATCH.verify_tree(self.target)
        self.assertEqual(outside.read_bytes(), self.originals['LICENSE'])

    def test_unsafe_duplicate_foreign_and_reserved_archive_entries_are_rejected(self):
        names = ('../escape', '/absolute', 'pkg/../../escape', 'pkg//empty', 'bad\nname',
                 'bad\\name', 'C:/escape', PATCH.TEST)
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                stage = Path(temporary) / 'stage'
                stage.mkdir()
                archive = Path(temporary) / 'unsafe.zip'
                with zipfile.ZipFile(archive, 'w') as output:
                    output.writestr(PATCH.PREFIX + name, b'unowned')
                with self.assertRaises(ValueError):
                    PATCH.extract_verified(archive, stage)
        self.assertFalse((self.root / 'escape').exists())
        for label in ('foreign', 'duplicate', 'special'):
            with self.subTest(label=label), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                stage = Path(temporary) / 'stage'
                stage.mkdir()
                archive = Path(temporary) / 'unsafe.zip'
                with zipfile.ZipFile(archive, 'w') as output:
                    if label == 'foreign':
                        output.writestr('foreign@v1.0.0/file.go', b'data')
                    elif label == 'duplicate':
                        import warnings
                        with warnings.catch_warnings():
                            warnings.simplefilter('ignore', UserWarning)
                            output.writestr(PATCH.PREFIX + 'duplicate.go', b'first')
                            output.writestr(PATCH.PREFIX + 'duplicate.go', b'second')
                    else:
                        entry = zipfile.ZipInfo(PATCH.PREFIX + 'linked.go')
                        entry.external_attr = 0o120777 << 16
                        output.writestr(entry, b'/outside')
                with self.assertRaises(ValueError):
                    PATCH.extract_verified(archive, stage)

    def test_wrong_version_and_unrelated_replacements_fail_before_source_changes(self):
        valid = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        plans = ({'Require': []}, {'Require': [{'Path': PATCH.MODULE, 'Version': 'v3.0.0'}]},
                 {**valid, 'Replace': [{'Old': {'Path': PATCH.MODULE}, 'New': {'Path': './' + PATCH.COPY}}]},
                 {**valid, 'Replace': [{'Old': {'Path': PATCH.MODULE, 'Version': PATCH.VERSION}, 'New': {'Path': '/foreign'}}]})
        before = (self.target / PATCH.TIMER).read_bytes()
        for plan in plans:
            with mock.patch.object(PATCH.subprocess, 'check_output', return_value=json.dumps(plan)), self.assertRaises(ValueError):
                PATCH.module_plan(self.root)
        self.assertEqual((self.target / PATCH.TIMER).read_bytes(), before)

    def test_failed_full_checksum_never_publishes_a_copy_or_replacement(self):
        shutil.rmtree(self.target)
        altered = self.root / 'altered.zip'
        with zipfile.ZipFile(altered, 'w') as output:
            for name, data in self.originals.items():
                output.writestr(PATCH.PREFIX + name, data + b'changed' if name == 'LICENSE' else data)
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            if args[0] == 'git':
                return PATCH.CORE + '\n'
            if args[1:4] == ['mod', 'edit', '-json']:
                return json.dumps(plan)
            return json.dumps({'Path': PATCH.MODULE, 'Version': PATCH.VERSION, 'Sum': PATCH.SUM, 'Zip': str(altered)})
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run') as mutation:
            with self.assertRaises(ValueError):
                PATCH.prepare(self.root)
            mutation.assert_not_called()
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.root.glob('.routervpn-amnezia-timers-*')), [])

    def test_real_go_editor_selects_only_the_verified_idempotent_private_copy(self):
        (self.root / 'go.mod').write_text('module routervpn-timer-fixture\n\ngo 1.26.0\n\nrequire ' + PATCH.MODULE + ' ' + PATCH.VERSION + '\n')
        actual = subprocess.check_output
        def command(args, **kwargs):
            if args[0] == 'git':
                self.assertEqual(args[1:3], ['-C', str(self.root.resolve())])
                return PATCH.CORE + '\n'
            return actual(args, **kwargs)
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command):
            PATCH.prepare(self.root / '..' / self.root.name)
            PATCH.prepare(self.root)
            self.assertEqual(PATCH.verify(self.root), self.target.resolve())
        selected = json.loads(actual(['go', 'list', '-m', '-json', PATCH.MODULE], cwd=self.root, text=True))
        self.assertEqual(Path(selected['Dir']).resolve(), self.target.resolve())
        self.assertEqual(selected['Version'], PATCH.VERSION)
        subprocess.run(['go', 'mod', 'edit', '-replace=' + PATCH.MODULE + '=/foreign'], cwd=self.root, check=True)
        with self.assertRaises(ValueError):
            PATCH.verify(self.root)
        PATCH.verify_tree(self.target)

    def test_selected_foreign_directory_cannot_borrow_a_valid_local_receipt(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}],
                'Replace': [{'Old': {'Path': PATCH.MODULE, 'Version': PATCH.VERSION}, 'New': {'Path': './' + PATCH.COPY}}]}
        def command(args, **kwargs):
            if args[1:4] == ['mod', 'edit', '-json']:
                return json.dumps(plan)
            return json.dumps({'Path': PATCH.MODULE, 'Version': PATCH.VERSION, 'Dir': str(self.root / 'foreign'),
                               'Replace': {'Path': './' + PATCH.COPY, 'Dir': str(self.root / 'foreign')}})
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), self.assertRaises(ValueError):
            PATCH.verify(self.root)

    def test_native_cache_and_actual_runner_inputs_include_the_patch(self):
        spec = importlib.util.spec_from_file_location('timer_awg_owner', ROOT / 'deploy/prepare-mobile-amnezia.py')
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        self.assertTrue(set(PATCH.inputs()).issubset(owner.inputs()))
        self.assertIn("../deploy/prepare-amnezia-timers.py", (ROOT / 'android/app/build.gradle').read_text())
        for path in ('android/build-sing-box-libbox.sh', 'ios/RouterVPN/prepare-libbox.sh',
                     'deploy/test_native_awg_return.sh', 'deploy/test_desktop_amnezia_runtime.py',
                     'deploy/build-native-runtime.py'):
            self.assertIn('test_amnezia_timers_pinned.py', (ROOT / path).read_text())
        reference = (ROOT / 'deploy/build_awg_reference_fixture.py').read_text()
        self.assertIn('TIMERS.verify(core, args.go, env=environment)', reference)
        for workflow in ('native-awg-return.yml', 'desktop-amnezia-runtime.yml'):
            text = (ROOT / '.github/workflows' / workflow).read_text()
            self.assertIn('mobile/amneziatimers/**', text)
            self.assertIn('deploy/test_amnezia_timer_preparation.py', text)


if __name__ == '__main__':
    unittest.main()
