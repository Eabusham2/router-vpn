#!/usr/bin/env python3
"""Check the full pinned gVisor archive, owned patches and native source closure."""
from pathlib import Path
import base64
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
spec = importlib.util.spec_from_file_location('gvisor_scheduler', ROOT / 'deploy/prepare-gvisor-scheduler.py')
PATCH = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PATCH)
FORWARDER = PATCH.FORWARDER


class SchedulerPreparation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        info = json.loads(subprocess.check_output(
            ['go', 'mod', 'download', '-json', PATCH.MODULE + '@' + PATCH.VERSION], cwd=ROOT, text=True))
        if info.get('Path') != PATCH.MODULE or info.get('Version') != PATCH.VERSION or info.get('Sum') != PATCH.SUM or info.get('Error'):
            raise ValueError('gVisor fixture requires the exact original pinned archive')
        cls.archive, cls.cache = Path(info['Zip']), Path(info['Dir'])
        cls.archive_before = cls.archive.read_bytes()
        with zipfile.ZipFile(cls.archive) as source:
            cls.originals = {name[len(PATCH.PREFIX):]: source.read(name) for name in source.namelist()}
        cls.cache_before = cls.cache_snapshot()

    @classmethod
    def cache_snapshot(cls):
        return {name: (hashlib.sha256((cls.cache / name).read_bytes()).hexdigest(),
                       (cls.cache / name).stat().st_mode, (cls.cache / name).parent.stat().st_mode)
                for name in cls.originals}

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.vendor = self.root / 'core'
        self.vendor.mkdir()
        self.target = self.vendor / PATCH.COPY
        self.target.mkdir()
        PATCH.extract_verified(self.archive, self.target)
        self.plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}

    def tearDown(self):
        self.assertEqual(self.archive.read_bytes(), self.archive_before)
        self.assertEqual(self.cache_snapshot(), self.cache_before)

    def test_patch_is_exactly_the_original_atomic_instruction_and_five_owned_tcp_edits(self):
        self.assertEqual((PATCH.VERSION, PATCH.SUM),
                         ('v0.0.0-20260727.0-sing-box-mod.1', 'h1:IdQ7yTKkB2wv8txwshxUroPlO4npOYAV71xb7xQ7Lys='))
        self.assertEqual(set(FORWARDER.PATCHES), {
            'pkg/tcpip/transport/tcp/accept.go', 'pkg/tcpip/transport/tcp/connect.go',
            'pkg/tcpip/transport/tcp/endpoint.go', 'pkg/tcpip/transport/tcp/forwarder.go',
            'pkg/tcpip/transport/tcp/protocol.go'})
        assembly = self.originals[PATCH.ASSEMBLY]
        self.assertEqual(PATCH.BLOB, PATCH.git_blob(assembly))
        self.assertEqual(PATCH.patch(assembly), assembly.replace(b'\tMOVD new+16(FP), R1\n', b'\tMOVD new+16(FP), R2\n', 1))
        self.assertEqual(PATCH.original(PATCH.patch(assembly)), assembly)
        for name, source in self.originals.items():
            if name == PATCH.ASSEMBLY:
                expected = PATCH.patch(source)
            elif name in FORWARDER.PATCHES:
                expected = FORWARDER.patch(name, source)
                self.assertEqual(FORWARDER.original(name, expected), source)
            else:
                expected = source
            self.assertEqual((self.target / name).read_bytes(), expected, name)
        self.assertEqual((self.target / FORWARDER.TEST).read_bytes(), FORWARDER.test_source())
        PATCH.verify_tree(self.target)

    def test_changed_or_partial_patch_boundaries_cannot_borrow_the_pin(self):
        assembly = self.originals[PATCH.ASSEMBLY]
        for source in (assembly + b'// drift\n', PATCH.patch(assembly) + b'// drift\n'):
            with self.assertRaises(ValueError):
                PATCH.patch(source)
            with self.assertRaises(ValueError):
                PATCH.original(source)
        for name in FORWARDER.PATCHES:
            original = self.originals[name]
            fixed = FORWARDER.patch(name, original)
            for source in (original + b'// drift\n', fixed + b'// drift\n'):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    FORWARDER.patch(name, source)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    FORWARDER.original(name, source)
            with self.subTest(name=name), self.assertRaises(ValueError):
                FORWARDER.original(name, original)

    def test_h1_matches_the_independent_complete_canonical_summary(self):
        summary = b''.join(hashlib.sha256(self.originals[name]).hexdigest().encode() + b'  ' +
                           (PATCH.PREFIX + name).encode() + b'\n' for name in sorted(self.originals))
        self.assertEqual('h1:' + base64.b64encode(hashlib.sha256(summary).digest()).decode(), PATCH.SUM)

    def test_verification_rejects_missing_extra_changed_or_reverted_files(self):
        faults = [('LICENSE', b'changed license'), ('extra.go', b'package extra\n'),
                  ('go.mod', None), (PATCH.ASSEMBLY, self.originals[PATCH.ASSEMBLY]),
                  (FORWARDER.TEST, None), (FORWARDER.TEST, FORWARDER.test_source() + b'// unreviewed\n')]
        faults += [(name, self.originals[name]) for name in FORWARDER.PATCHES]
        for name, replacement in faults:
            path = self.target / name
            before = path.read_bytes() if path.exists() else None
            try:
                if replacement is None:
                    path.unlink()
                else:
                    path.write_bytes(replacement)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    PATCH.verify_tree(self.target)
            finally:
                if before is None:
                    path.unlink()
                else:
                    path.write_bytes(before)
        PATCH.verify_tree(self.target)

    def test_linked_or_hardlinked_output_is_rejected_without_changing_another_owner(self):
        outside = self.root / 'outside-license'
        outside.write_bytes(self.originals['LICENSE'])
        path = self.target / 'LICENSE'
        path.unlink()
        os.link(outside, path)
        with self.assertRaises(ValueError):
            PATCH.verify_tree(self.target)
        path.unlink()
        if os.name != 'nt':
            path.symlink_to(outside)
            with self.assertRaises(ValueError):
                PATCH.verify_tree(self.target)
            path.unlink()
        path.write_bytes(self.originals['LICENSE'])
        self.assertEqual(outside.read_bytes(), self.originals['LICENSE'])
        PATCH.verify_tree(self.target)

    def test_unsafe_duplicate_foreign_special_and_reserved_archive_entries_are_rejected(self):
        names = ('../escape', '/absolute', 'pkg/../../escape', 'pkg//empty', 'bad\nname',
                 'bad\\name', 'C:/escape', FORWARDER.TEST)
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                stage, archive = Path(temporary) / 'stage', Path(temporary) / 'unsafe.zip'
                stage.mkdir()
                with zipfile.ZipFile(archive, 'w') as output:
                    output.writestr(PATCH.PREFIX + name, b'unowned')
                with self.assertRaises(ValueError):
                    PATCH.extract_verified(archive, stage)
        self.assertFalse((self.root / 'escape').exists())
        for label in ('foreign', 'duplicate', 'linked', 'special'):
            with self.subTest(label=label), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                stage, archive = Path(temporary) / 'stage', Path(temporary) / 'unsafe.zip'
                stage.mkdir()
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
                        entry = zipfile.ZipInfo(PATCH.PREFIX + 'aliased.go')
                        entry.external_attr = (0o120777 if label == 'linked' else 0o020600) << 16
                        output.writestr(entry, b'/outside')
                with self.assertRaises(ValueError):
                    PATCH.extract_verified(archive, stage)

    def test_wrong_version_or_foreign_replace_fails_before_source_changes(self):
        plans = ({'Require': []}, {'Require': [{'Path': PATCH.MODULE, 'Version': 'v0.0.0'}]},
                 {**self.plan, 'Replace': [{'Old': {'Path': PATCH.MODULE}, 'New': {'Path': './' + PATCH.COPY}}]},
                 {**self.plan, 'Replace': [{'Old': {'Path': PATCH.MODULE, 'Version': PATCH.VERSION}, 'New': {'Path': '/outside'}}]})
        before = (self.target / PATCH.ASSEMBLY).read_bytes()
        for plan in plans:
            with mock.patch.object(PATCH.subprocess, 'check_output', return_value=json.dumps(plan)), self.assertRaises(ValueError):
                PATCH.module_plan(self.vendor)
        self.assertEqual((self.target / PATCH.ASSEMBLY).read_bytes(), before)

    def test_prepare_is_idempotent_and_selects_the_real_verified_copy(self):
        (self.vendor / 'go.mod').write_text('module routervpn-gvisor-fixture\n\ngo 1.26.0\n\nrequire ' + PATCH.MODULE + ' ' + PATCH.VERSION + '\n')
        actual = subprocess.check_output
        def command(args, **kwargs):
            if args[0] == 'git':
                self.assertEqual(args[1:3], ['-C', str(self.vendor.resolve())])
                return PATCH.CORE + '\n'
            return actual(args, **kwargs)
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command):
            PATCH.prepare(self.vendor / '..' / self.vendor.name)
            PATCH.prepare(self.vendor)
            self.assertEqual(PATCH.verify(self.vendor), self.target)
        selected = json.loads(actual(['go', 'list', '-m', '-json', PATCH.MODULE], cwd=self.vendor, text=True))
        self.assertEqual(Path(selected['Dir']).resolve(), self.target)
        self.assertEqual(selected['Version'], PATCH.VERSION)
        subprocess.run(['go', 'mod', 'edit', '-replace=' + PATCH.MODULE + '=/foreign'], cwd=self.vendor, check=True)
        with self.assertRaises(ValueError):
            PATCH.verify(self.vendor)
        PATCH.verify_tree(self.target)

    def test_prepare_and_verify_use_the_resolved_vendor_compiler_and_environment(self):
        alias = self.vendor / '..' / self.vendor.name
        environment = {'owned': 'environment'}
        def command(args, **kwargs):
            if args[0] == 'git':
                self.assertEqual(args[1:3], ['-C', str(self.vendor)])
                return PATCH.CORE + '\n'
            self.assertEqual(args[0], 'owned-go')
            self.assertEqual(kwargs['cwd'], self.vendor)
            self.assertIs(kwargs['env'], environment)
            if args[1:4] == ['mod', 'edit', '-json']:
                return json.dumps(self.plan)
            return json.dumps({'Path': PATCH.MODULE, 'Version': PATCH.VERSION, 'Dir': str(self.target),
                               'Replace': {'Path': './' + PATCH.COPY, 'Dir': str(self.target)}})
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run') as mutation:
            PATCH.prepare(alias, 'owned-go', env=environment)
            self.plan['Replace'] = [{'Old': {'Path': PATCH.MODULE, 'Version': PATCH.VERSION}, 'New': {'Path': './' + PATCH.COPY}}]
            PATCH.verify(alias, 'owned-go', env=environment)
            mutation.assert_called_once_with(['owned-go', 'mod', 'edit', '-replace=' + PATCH.MODULE + '@' + PATCH.VERSION + '=./' + PATCH.COPY], cwd=self.vendor, env=environment, check=True)

    def test_verify_requires_the_exact_selected_directory_and_replacement(self):
        replacement = {'Path': './' + PATCH.COPY, 'Dir': str(self.target)}
        selected = {'Path': PATCH.MODULE, 'Version': PATCH.VERSION, 'Dir': str(self.target), 'Replace': replacement}
        self.plan['Replace'] = [{'Old': {'Path': PATCH.MODULE, 'Version': PATCH.VERSION}, 'New': {'Path': './' + PATCH.COPY}}]
        faults = [dict(selected, Path='foreign'), dict(selected, Dir=str(self.root / 'foreign')),
                  dict(selected, Replace={**replacement, 'Dir': str(self.root / 'foreign')}),
                  dict(selected, Replace={**replacement, 'Version': 'v0.0.0'}),
                  dict(selected, Replace={}), dict(selected, Error='unresolved')]
        for result in faults:
            def command(args, **kwargs):
                return json.dumps(self.plan if args[1:4] == ['mod', 'edit', '-json'] else result)
            with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), self.assertRaises(ValueError):
                PATCH.verify(self.vendor)
        self.plan.pop('Replace')
        with mock.patch.object(PATCH.subprocess, 'check_output', return_value=json.dumps(self.plan)), self.assertRaises(ValueError):
            PATCH.verify(self.vendor)

    def test_failed_checksum_cannot_publish_a_partial_dependency(self):
        shutil.rmtree(self.target)
        altered = self.root / 'altered.zip'
        with zipfile.ZipFile(altered, 'w') as output:
            for name, data in self.originals.items():
                output.writestr(PATCH.PREFIX + name, data + b'changed' if name == 'LICENSE' else data)
        def command(args, **kwargs):
            if args[0] == 'git':
                return PATCH.CORE + '\n'
            if args[1:4] == ['mod', 'edit', '-json']:
                return json.dumps(self.plan)
            return json.dumps({'Path': PATCH.MODULE, 'Version': PATCH.VERSION, 'Sum': PATCH.SUM, 'Zip': str(altered)})
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run') as mutation, self.assertRaises(ValueError):
            PATCH.prepare(self.vendor)
        mutation.assert_not_called()
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.vendor.iterdir()), [])

    def test_patch_enters_mobile_cache_keys_native_gates_and_physical_source_capture(self):
        spec = importlib.util.spec_from_file_location('amnezia_preparation', ROOT / 'deploy/prepare-mobile-amnezia.py')
        preparation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preparation)
        self.assertTrue(set(PATCH.inputs()).issubset(preparation.inputs()))
        self.assertIn(ROOT / 'mobile/amnezia/scheduler_test.go.tmpl', preparation.inputs())
        gradle = (ROOT / 'android/app/build.gradle').read_text()
        self.assertIn('../deploy/prepare-gvisor-scheduler.py', gradle)
        self.assertIn('../deploy/prepare-gvisor-forwarder.py', gradle)
        self.assertIn('gvisorforwarder', gradle)
        for path in ('android/build-sing-box-libbox.sh', 'ios/RouterVPN/prepare-libbox.sh'):
            text = (ROOT / path).read_text()
            self.assertIn('prepare-mobile-multihop.py', text)
            self.assertIn('prepare-mobile-amnezia.py" --verify-dependency', text)
            self.assertIn('test_gvisor_forwarder_pinned.py', text)
        gate = (ROOT / 'deploy/test_native_awg_return.sh').read_text()
        for token in ('TestNativeTunSchedulerAtomicCAS', 'SCHEDULER.original', 'finally:', '-race', 'test_gvisor_forwarder_pinned.py'):
            self.assertIn(token, gate)
        for path in ('deploy/test_desktop_amnezia_runtime.py', 'deploy/build-native-runtime.py'):
            self.assertIn('test_gvisor_forwarder_pinned.py', (ROOT / path).read_text())
        capture = (ROOT / 'deploy/test_desktop_node_physical.py').read_text()
        self.assertIn('scheduler.verify_tree(source / scheduler.COPY)', capture)
        self.assertIn('scheduler.inputs()', capture)


if __name__ == '__main__':
    unittest.main()
