#!/usr/bin/env python3
"""Integrity and isolation checks against the exact pinned sing module archive."""
from pathlib import Path
import importlib.util
import json
import shutil
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
        cls.cache = Path(info['Dir'])
        with zipfile.ZipFile(cls.archive) as archive:
            cls.originals = {name: archive.read(PATCH.PREFIX+name) for name in (*PATCH.PATCHES, 'LICENSE')}
        cls.cache_before = {name: ((cls.cache/name).read_bytes(), (cls.cache/name).stat().st_mode,
                                  (cls.cache/name).parent.stat().st_mode) for name in cls.originals}

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

    def assert_cache_unchanged(self):
        self.assertEqual(self.archive.read_bytes(), self.before)
        self.assertEqual({name: ((self.cache/name).read_bytes(), (self.cache/name).stat().st_mode,
                               (self.cache/name).parent.stat().st_mode) for name in self.originals}, self.cache_before)

    def test_exact_older_packet_only_copy_upgrades_after_full_checksum_verification(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}],
                'Replace': [{'Old': {'Path': PATCH.MODULE, 'Version': PATCH.VERSION}, 'New': {'Path': './'+PATCH.COPY}}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        for name in PATCH.BUFFER_FILES:
            (self.target/name).write_bytes(self.originals[name])
        with self.assertRaises(ValueError):
            PATCH.verify_tree(self.target)
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'):
            PATCH.prepare(self.root)
            PATCH.prepare(self.root)
        PATCH.verify_tree(self.target)
        for name in PATCH.BUFFER_FILES:
            self.assertEqual((self.target/name).read_bytes(), PATCH.transform(name, self.originals[name]))
        self.assert_cache_unchanged()

    def test_packet_only_upgrade_rejects_unrelated_or_partial_source_before_writing(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        for fault in ('license', 'unrelated', 'partial', 'missing-lock'):
            with self.subTest(fault=fault):
                for name, original in self.originals.items():
                    (self.target/name).write_bytes(original if name in PATCH.BUFFER_FILES else PATCH.transform(name, original))
                if fault == 'license':
                    (self.target/'LICENSE').write_bytes(b'changed license')
                elif fault == 'unrelated':
                    path = self.target/'common/buf/buffer_standard.go'
                    path.write_bytes(path.read_bytes()+b'\n// unexpected source\n')
                elif fault == 'partial':
                    name = 'common/buf/buffer_standard.go'
                    (self.target/name).write_bytes(PATCH.transform(name, self.originals[name]))
                else:
                    (self.target/'common/bufio/bind.go').write_bytes(self.originals['common/bufio/bind.go'])
                before = {name: (self.target/name).read_bytes() for name in self.originals}
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'), self.assertRaises(ValueError):
                    PATCH.prepare(self.root)
                self.assertEqual({name: (self.target/name).read_bytes() for name in self.originals}, before)
        self.assert_cache_unchanged()

    def test_exact_prior_association_group_upgrades_without_resetting_packet_fixes(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        for name in PATCH.ASSOCIATION_FILES:
            (self.target/name).write_bytes(self.originals[name])
        preserved = {name: (self.target/name).read_bytes() for name in PATCH.PATCHES if name not in PATCH.ASSOCIATION_FILES}
        with self.assertRaises(ValueError):
            PATCH.verify_tree(self.target)
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'):
            PATCH.prepare(self.root)
            PATCH.prepare(self.root)
        PATCH.verify_tree(self.target)
        self.assertEqual({name: (self.target/name).read_bytes() for name in preserved}, preserved)
        self.assert_cache_unchanged()

    def test_partial_or_foreign_association_upgrade_changes_nothing(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        for fault in ('partial', 'foreign'):
            with self.subTest(fault=fault):
                for name in PATCH.ASSOCIATION_FILES:
                    (self.target/name).write_bytes(self.originals[name])
                name = 'protocol/socks/packet_wait.go'
                if fault == 'partial':
                    (self.target/name).write_bytes(PATCH.transform(name, self.originals[name]))
                else:
                    (self.target/name).write_bytes(self.originals[name]+b'\n// unrelated association\n')
                before = {name: (self.target/name).read_bytes() for name in self.originals}
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'), self.assertRaises(ValueError):
                    PATCH.prepare(self.root)
                self.assertEqual({name: (self.target/name).read_bytes() for name in self.originals}, before)
        self.assert_cache_unchanged()

    def test_exact_prior_authentication_upgrades_without_changing_owned_lifetimes(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        for name in PATCH.AUTH_FILES:
            (self.target/name).write_bytes(self.originals[name])
        preserved = {name: (self.target/name).read_bytes() for name in PATCH.PATCHES if name not in PATCH.AUTH_FILES}
        with self.assertRaises(ValueError):
            PATCH.verify_tree(self.target)
        with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'):
            PATCH.prepare(self.root)
            PATCH.prepare(self.root)
        PATCH.verify_tree(self.target)
        self.assertEqual({name: (self.target/name).read_bytes() for name in preserved}, preserved)
        self.assert_cache_unchanged()

    def test_authentication_upgrade_rejects_changed_or_aliased_source_before_writing(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        for fault in ('changed', 'symlink', 'hardlink'):
            with self.subTest(fault=fault):
                name = 'protocol/socks/handshake.go'
                path = self.target/name
                if path.exists() or path.is_symlink():
                    path.unlink()
                path.write_bytes(self.originals[name])
                outside = self.root/('auth-'+fault)
                outside.write_bytes(self.originals[name])
                if fault == 'changed':
                    path.write_bytes(self.originals[name]+b'\n// unowned authentication policy\n')
                elif fault == 'symlink':
                    path.unlink()
                    try:
                        path.symlink_to(outside)
                    except OSError:
                        path.write_bytes(self.originals[name])
                        continue  # Covered on hosts with actual link privileges.
                else:
                    path.unlink()
                    try:
                        path.hardlink_to(outside)
                    except OSError:
                        path.write_bytes(self.originals[name])
                        continue
                before = {entry: (self.target/entry).read_bytes() for entry in self.originals}
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'), self.assertRaises(ValueError):
                    PATCH.prepare(self.root)
                self.assertEqual({entry: (self.target/entry).read_bytes() for entry in self.originals}, before)
                self.assertEqual(outside.read_bytes(), self.originals[name])
                path.unlink()
                path.write_bytes(PATCH.transform(name, self.originals[name]))
        PATCH.verify_tree(self.target)
        self.assert_cache_unchanged()

    def test_exact_previous_payload_copy_upgrades_without_losing_control_or_authentication(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        name = 'protocol/socks/packet.go'
        fixed = (self.target/name).read_bytes()
        previous = PATCH.without_payload_write_fix(name, fixed)
        self.assertNotEqual(previous, self.originals[name])
        self.assertIn(b'clientAssociationControl', previous)
        for old_auth in (False, True):
            with self.subTest(old_auth=old_auth):
                (self.target/name).write_bytes(previous)
                for auth in PATCH.AUTH_FILES:
                    (self.target/auth).write_bytes(self.originals[auth] if old_auth else PATCH.transform(auth, self.originals[auth]))
                preserved = {path: (self.target/path).read_bytes() for path in self.originals
                             if path != name and not (old_auth and path in PATCH.AUTH_FILES)}
                with self.assertRaises(ValueError):
                    PATCH.verify_tree(self.target)
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'):
                    PATCH.prepare(self.root)
                    PATCH.prepare(self.root)
                self.assertEqual((self.target/name).read_bytes(), fixed)
                self.assertEqual({path: (self.target/path).read_bytes() for path in preserved}, preserved)
                PATCH.verify_tree(self.target)
        self.assert_cache_unchanged()

    def test_payload_upgrade_rejects_partial_foreign_or_incomplete_association_before_writing(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        name = 'protocol/socks/packet.go'
        fixed = (self.target/name).read_bytes()
        previous = PATCH.without_payload_write_fix(name, fixed)
        for fault in ('io-only', 'count-only', 'writepacket-only', 'foreign-packet', 'foreign-license', 'missing-control-peer'):
            with self.subTest(fault=fault):
                for path, original in self.originals.items():
                    (self.target/path).write_bytes(PATCH.transform(path, original))
                data = previous
                if fault == 'io-only':
                    data = data.replace(b'\t"errors"\n', b'\t"errors"\n\t"io"\n', 1)
                elif fault == 'count-only':
                    data = data.replace(b'\treturn c.conn.Write(buffer.Bytes())\n', b'\treturn len(p), nil\n', 1)
                elif fault == 'writepacket-only':
                    data = data.replace(b'\treturn c.conn.WriteBuffer(buffer)\n', b'\treturn nil\n', 1)
                elif fault == 'foreign-packet':
                    data += b'\n// unrelated packet policy\n'
                elif fault == 'foreign-license':
                    (self.target/'LICENSE').write_bytes(b'changed license')
                else:
                    peer = 'protocol/socks/packet_wait.go'
                    (self.target/peer).write_bytes(self.originals[peer])
                (self.target/name).write_bytes(data)
                before = {path: (self.target/path).read_bytes() for path in self.originals}
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'), self.assertRaises(ValueError):
                    PATCH.prepare(self.root)
                self.assertEqual({path: (self.target/path).read_bytes() for path in self.originals}, before)
        self.assert_cache_unchanged()

    def test_payload_upgrade_rejects_aliases_without_touching_the_original(self):
        plan = {'Require': [{'Path': PATCH.MODULE, 'Version': PATCH.VERSION}]}
        def command(args, **kwargs):
            return PATCH.CORE+'\n' if args[0] == 'git' else json.dumps(plan)
        name = 'protocol/socks/packet.go'
        path = self.target/name
        fixed = path.read_bytes()
        previous = PATCH.without_payload_write_fix(name, fixed)
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                outside = self.root/('payload-'+kind)
                outside.write_bytes(previous)
                path.unlink()
                try:
                    path.symlink_to(outside) if kind == 'symlink' else path.hardlink_to(outside)
                except OSError:
                    path.write_bytes(fixed)
                    continue  # Actual alias rejection runs on hosts with link privileges.
                before = {entry: (self.target/entry).read_bytes() for entry in self.originals}
                with mock.patch.object(PATCH.subprocess, 'check_output', side_effect=command), mock.patch.object(PATCH.subprocess, 'run'), self.assertRaises(ValueError):
                    PATCH.prepare(self.root)
                self.assertEqual({entry: (self.target/entry).read_bytes() for entry in self.originals}, before)
                self.assertEqual(outside.read_bytes(), previous)
                path.unlink()
                path.write_bytes(fixed)
        PATCH.verify_tree(self.target)
        self.assert_cache_unchanged()

    def test_payload_negative_control_only_reverses_the_exact_owned_patch(self):
        name = 'protocol/socks/packet.go'
        fixed = (self.target/name).read_bytes()
        previous = PATCH.without_payload_write_fix(name, fixed)
        self.assertIn(b'\treturn c.conn.Write(buffer.Bytes())\n', previous)
        self.assertIn(b'\treturn c.conn.WriteBuffer(buffer)\n', previous)
        self.assertIn(b'\t<-c.joined\n', previous)
        for data in (self.originals[name], previous, fixed+b'\n// foreign source\n'):
            with self.assertRaises(ValueError):
                PATCH.without_payload_write_fix(name, data)
        with self.assertRaises(ValueError):
            PATCH.without_payload_write_fix('protocol/socks/handshake.go', (self.target/'protocol/socks/handshake.go').read_bytes())
        PATCH.verify_tree(self.target)
        self.assert_cache_unchanged()

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
        self.assertIn(ROOT/'mobile/amnezia/socks_association_test.go.tmpl', preparation.inputs())
        self.assertIn('../deploy/prepare-sing-packet-concurrency.py', (ROOT/'android/app/build.gradle').read_text())
        spec = importlib.util.spec_from_file_location('whitening_preparation', ROOT/'deploy/prepare-mobile-whitening.py')
        whitening = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(whitening)
        self.assertIn(ROOT/'deploy/prepare-sing-packet-concurrency.py', whitening.inputs())

    def test_real_go_buffer_preparation_and_packet_repreparation_share_one_copy(self):
        spec = importlib.util.spec_from_file_location('combined_buffer_policy', ROOT/'deploy/prepare-mobile-buffers.py')
        buffers = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(buffers)
        # Exercise the real Go module editor, MVS selection, tidy and compiler.
        # Only the outer core's Git identity and unrelated socket insertion are
        # fixtures; both dependency preparations operate on the pinned archive.
        (self.root/'go.mod').write_text('module github.com/sagernet/sing-box\n\ngo 1.26.0\n\nrequire '+PATCH.MODULE+' '+PATCH.VERSION+'\n')
        (self.root/'main.go').write_text('package main\nimport ("fmt"; "github.com/sagernet/sing/common/buf")\nfunc main() { fmt.Printf("%d %d\\n", buf.BufferSize, buf.UDPBufferSize) }\n')
        actual = subprocess.check_output
        def command(args, **kwargs):
            if args[0] == 'git':
                self.assertEqual(args[-2:], ['rev-parse', 'HEAD'])
                return PATCH.CORE+'\n'
            return actual(args, **kwargs)
        with mock.patch.object(subprocess, 'check_output', side_effect=command), mock.patch.object(buffers.SOCKETS, 'prepare') as sockets:
            PATCH.prepare(self.root)
            buffers.prepare(self.root)
            PATCH.prepare(self.root)
            buffers.prepare(self.root)
            PATCH.verify(self.root)
            self.assertEqual(sockets.call_count, 2)
        plan = json.loads(actual(['go', 'mod', 'edit', '-json'], cwd=self.root, text=True))
        self.assertEqual([r for r in plan['Replace'] if r['Old']['Path'] == PATCH.MODULE],
                         [{'Old': {'Path': PATCH.MODULE, 'Version': PATCH.VERSION}, 'New': {'Path': './'+PATCH.COPY}}])
        for tags, expected in (('', '32768 65535'), ('with_low_memory', '16384 65535')):
            self.assertEqual(actual(['go', 'run', '-tags='+tags, '.'], cwd=self.root, text=True).strip(), expected)
        self.assertFalse((self.root/'.routervpn-sources/sing').exists())
        self.assert_cache_unchanged()
        # An explicit competing replacement remains rejected, even if an
        # intact verified owned copy is also present.
        subprocess.run(['go', 'mod', 'edit', '-replace='+PATCH.MODULE+'=/foreign'], cwd=self.root, check=True)
        with mock.patch.object(subprocess, 'check_output', side_effect=command), self.assertRaises(ValueError):
            buffers.prepare(self.root)
        PATCH.verify_tree(self.target)

    def test_buffers_first_also_create_the_same_verified_copy(self):
        spec = importlib.util.spec_from_file_location('buffers_first_policy', ROOT/'deploy/prepare-mobile-buffers.py')
        buffers = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(buffers)
        shutil.rmtree(self.target)
        (self.root/'go.mod').write_text('module github.com/sagernet/sing-box\n\ngo 1.26.0\n\nrequire '+PATCH.MODULE+' '+PATCH.VERSION+'\n')
        (self.root/'main.go').write_text('package main\nimport _ "github.com/sagernet/sing/common/buf"\nfunc main() {}\n')
        actual = subprocess.check_output
        def command(args, **kwargs):
            if args[0] == 'git':
                return PATCH.CORE+'\n'
            return actual(args, **kwargs)
        with mock.patch.object(subprocess, 'check_output', side_effect=command), mock.patch.object(buffers.SOCKETS, 'prepare'):
            buffers.prepare(self.root)
            PATCH.prepare(self.root)
            PATCH.verify(self.root)
        self.assertFalse((self.root/'.routervpn-sources/sing').exists())


if __name__ == '__main__':
    unittest.main()
