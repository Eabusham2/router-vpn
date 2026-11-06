#!/usr/bin/env python3
"""Exercise managed generation receipts using original filesystem objects."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import platform
import shutil
import subprocess
import struct
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT/'client/install-macos-generation.py'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def generation_source(source):
    module = types.ModuleType('macos_generation_mutant')
    module.__file__ = str(TARGET)
    exec(compile(source, str(TARGET), 'exec'), module.__dict__)
    return module


M = load(TARGET, 'macos_original_generation')
I = load(ROOT/'client/install-macos-native.py', 'macos_generation_installer')
F = load(ROOT/'deploy/test_macos_image_identity.py', 'macos_generation_image_fixtures')
T = load(ROOT/'deploy/test_macos_native_install.py', 'macos_generation_transaction_fixtures')


def write(path, value, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value.encode() if isinstance(value, str) else value)
    path.chmod(mode)


def uuid_identity(value):
    return {'identity_kind': 'kernel-main-uuid', 'code_directory_error': 85,
            'pid': 101, 'start_seconds': 1700000000, 'start_microseconds': 123,
            'uniqueid': 700, 'idversion': 9, 'main_uuid': value}


class GenerationReceipt(unittest.TestCase):
    generation = M

    def setUp(self):
        if os.geteuid() != 0:
            self.fail('Managed generation ownership tests require actual root in temporary directories')
        self.temporary = tempfile.TemporaryDirectory(prefix='routervpn-managed-generation-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve(strict=True)
        self.root = self.base/'installed'; self.root.mkdir(mode=0o755)
        self.trees, self.files = I.CODE_TREES, I.CODE_FILES
        for tree in self.trees: (self.root/tree).mkdir(mode=0o755)
        for name in sorted(self.generation.REQUIRED_IMAGES):
            write(self.root/name, F.thin([(0, F.directory(identity=name.encode()))]), 0o755)
        write(self.root/'bin/python3', '#!/bin/sh\nexec /usr/bin/python3 -BEsS "$@"\n', 0o700)
        write(self.root/'client.json', '{"listen":"127.0.0.1:8788"}', 0o600)
        write(self.root/'nodes/private.json', '{"credential":"original-private-node"}', 0o600)
        write(self.root/'ROUTER-VPN-SOURCE.json', '{"source_sha":"metadata-only"}')
        self.path = self.generation.receipt_path(self.root)

    def prepare(self):
        return self.generation.write_prepared(self.root, self.root, self.path,
                                              self.trees, self.files, I.FILES.ordinary)

    def capture(self):
        return self.generation.capture_receipt(self.root, self.trees, self.files, I.FILES.ordinary)

    def test_complete_original_code_and_mutable_private_state_are_separate(self):
        value = self.prepare()
        raw = self.path.read_text()
        self.assertNotIn('original-private-node', raw)
        self.assertNotIn('nodes/private.json', value['members'])
        self.assertEqual(set(self.generation.REQUIRED_IMAGES),
                         {name for name, member in value['members'].items() if member.get('code_directory_hashes')})
        with self.capture() as captured:
            self.assertEqual(captured.value, value)
            write(self.root/'nodes/private.json', '{"credential":"replacement-private-node"}', 0o600)
            write(self.root/'state.json', '{"mode":"last"}', 0o600)
            captured.verify()
            self.assertTrue(captured.hashes)

    def test_missing_replaced_changed_or_added_code_cannot_use_prior_receipt(self):
        self.prepare()
        target = self.root/'router-vpn-client'
        original = target.read_bytes()
        for fault in ('missing', 'same-bytes-new-inode', 'changed-bytes', 'added-member'):
            with self.subTest(fault=fault):
                backup = self.base/'original-member'
                if fault == 'added-member':
                    write(self.root/'client/unrecorded.py', '# new code\n')
                else:
                    target.rename(backup)
                    if fault != 'missing': write(target, original if fault == 'same-bytes-new-inode' else F.thin(), 0o755)
                try:
                    with self.assertRaises(ValueError):
                        with self.capture(): pass
                finally:
                    if fault == 'added-member': (self.root/'client/unrecorded.py').unlink()
                    else:
                        target.unlink(missing_ok=True); backup.rename(target)

    def test_changed_serialized_inventory_does_not_replace_actual_file_proof(self):
        self.prepare()
        original = self.path.read_bytes()
        for fault in ('remove-member', 'change-digest', 'reduce-scope', 'wrong-root', 'boolean-identity', 'extra-field'):
            value = json.loads(original)
            if fault == 'remove-member': del value['members']['router-vpn-client']
            elif fault == 'change-digest': value['members']['router-vpn-client']['sha256'] = 'a'*64
            elif fault == 'reduce-scope': value['code_trees'].remove('runtime')
            elif fault == 'wrong-root': value['root_object'][1] += 1
            elif fault == 'boolean-identity': value['members']['router-vpn-client']['identity'][5] = True
            else: value['trusted_signer'] = 'metadata is not image authority'
            self.path.write_text(json.dumps(value))
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                with self.capture(): pass
        self.path.write_bytes(original)

    def test_retained_receipt_rejects_equal_bytes_in_replacement_inode(self):
        self.prepare()
        with self.capture() as captured:
            original = self.path.read_bytes()
            self.path.rename(self.base/'previous-receipt')
            write(self.path, original, 0o600)
            with self.assertRaisesRegex(ValueError, 'Original managed receipt changed'):
                captured.verify()

    def test_foreign_comparison_revalidates_members_and_never_accepts_matching_or_unknown_hash(self):
        self.prepare()
        with self.capture() as captured:
            own = next(iter(captured.hashes))
            with self.assertRaisesRegex(RuntimeError, 'previous owned native processes'):
                captured.require_foreign_image({'code_directory_hash': own})
            for value in ({}, {'code_directory_hash': None}, {'code_directory_hash': '0'}, {'code_directory_hash': 'Z'*40}):
                with self.subTest(identity=value), self.assertRaises(ValueError): captured.require_foreign_image(value)
            captured.require_foreign_image({'code_directory_hash': 'a'*40})
            (self.root/'router-vpn-client').unlink()
            with self.assertRaises(ValueError): captured.require_foreign_image({'code_directory_hash': 'a'*40})

    def test_uuid_comparison_uses_fresh_all_slice_originals_not_receipt_metadata(self):
        for name in sorted(self.generation.REQUIRED_IMAGES):
            write(self.root/name, F.universal([F.thin(uuids=('1' * 32,)),
                                              F.thin(order='>', bits=32, uuids=('2' * 32,))]), 0o755)
        original = self.prepare()
        self.assertNotIn('executable_uuids', self.path.read_text(), 'Unproved serialized UUIDs became authority')
        with self.capture() as captured:
            self.assertEqual(captured.value, original)
            self.assertEqual(captured.executable_uuids, {'1' * 32, '2' * 32})
            # Zero is independently observed data, not process absence. It is
            # disjoint only because all exact original slices were nonzero.
            captured.require_foreign_image(uuid_identity('0' * 32))
            for value in captured.executable_uuids:
                with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, 'previous owned native processes'):
                    captured.require_foreign_image(uuid_identity(value))
            for changed in ({}, {'main_uuid': ''}, {'main_uuid': 'Z' * 32}, {'code_directory_error': 1},
                            {'code_directory_error': True}, {'pid': True}, {'uniqueid': 0},
                            {'start_microseconds': 1000000}, {'code_directory_hash': 'a' * 40}):
                identity = uuid_identity('0' * 32)
                if changed: identity.update(changed)
                else: del identity['idversion']
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    captured.require_foreign_image(identity)
            (self.root/'router-vpn-client').unlink()
            with self.assertRaises(ValueError): captured.require_foreign_image(uuid_identity('0' * 32))

    def test_a_slice_without_uuid_and_uuid_collisions_block_foreign_classification(self):
        for name in sorted(self.generation.REQUIRED_IMAGES):
            write(self.root/name, F.thin(uuids=('1' * 32,)), 0o755)
        # Only the second slice lacks LC_UUID. Dropping it would fabricate
        # the exact disjointness needed to admit the observed zero UUID.
        write(self.root/'router-vpn-client', F.universal([F.thin(uuids=('1' * 32,)), F.thin()]), 0o755)
        self.prepare()
        with self.capture() as captured:
            self.assertEqual(captured.executable_uuids, {'0' * 32, '1' * 32})
            for value in ('0' * 32, '1' * 32):
                with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, 'previous owned native processes'):
                    captured.require_foreign_image(uuid_identity(value))
            captured.require_foreign_image(uuid_identity('2' * 32))

    def test_private_executable_or_mach_o_never_escapes_complete_inventory(self):
        self.prepare()
        for payload, mode in ((b'#!/bin/sh\nexit 0\n', 0o700), (F.thin(), 0o600)):
            write(self.root/'nodes/new-native-image', payload, mode)
            try:
                with self.assertRaisesRegex(ValueError, 'Executable private member'):
                    with self.capture(): pass
            finally: (self.root/'nodes/new-native-image').unlink()

    def test_legacy_or_absent_root_has_no_empty_set_exclusion_authority(self):
        for root in (self.root, self.base/'never-present'):
            with self.subTest(root=root):
                with self.generation.previous_generation(root, self.trees, self.files, I.FILES.ordinary) as captured:
                    self.assertIsNone(captured)
        self.prepare()
        self.root.rename(self.base/'unavailable-original')
        with self.assertRaises(FileNotFoundError):
            with self.generation.previous_generation(self.root, self.trees, self.files, I.FILES.ordinary): pass

    def test_receipt_symlink_permissions_and_duplicate_fields_are_rejected(self):
        self.prepare()
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            with self.capture(): pass
        self.path.chmod(0o600)
        original = self.path.read_bytes()
        self.path.write_bytes(b'{"schema":1,' + original[1:])
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            with self.capture(): pass
        self.path.write_bytes(original)
        other = self.base/'receipt-original'; self.path.rename(other); self.path.symlink_to(other)
        with self.assertRaises(ValueError):
            with self.capture(): pass

    def test_unsigned_required_image_cannot_create_a_managed_generation(self):
        write(self.root/'router-vpn-client', F.thin(signed=False), 0o755)
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.path.exists())


class LegacyInstallationImages(unittest.TestCase):
    generation = M
    setUp = GenerationReceipt.setUp

    def test_legacy_capture_is_complete_ephemeral_and_revalidated(self):
        with self.generation.current_legacy_generation(self.root, self.trees, self.files, I.FILES.ordinary, None) as captured:
            self.assertIsInstance(captured, self.generation.LegacyCapture)
            self.assertFalse(self.path.exists(), 'Current observation fabricated a historical receipt')
            captured.require_foreign_image({'code_directory_hash': 'a'*40})
            with self.assertRaisesRegex(RuntimeError, 'previous owned native processes'):
                captured.require_foreign_image({'code_directory_hash': next(iter(captured.hashes))})
            member = self.root/'router-vpn-client'
            member.write_bytes(F.thin([(0, F.directory(identity=b'changed-legacy'))]))
            with self.assertRaisesRegex(ValueError, 'Legacy code members changed'):
                captured.verify()
        self.assertFalse(self.path.exists())

    def test_missing_or_private_legacy_code_cannot_supply_exclusion(self):
        for fault in ('missing', 'private', 'unsigned'):
            with self.subTest(fault=fault):
                member = self.root/'router-vpn-client'
                saved = member.read_bytes()
                private = self.root/'nodes/unrecorded-code'
                if fault == 'missing': member.unlink()
                elif fault == 'unsigned': member.write_bytes(F.thin(signed=False))
                else: write(private, F.thin(), 0o600)
                try:
                    with self.assertRaises(ValueError):
                        with self.generation.current_legacy_generation(self.root, self.trees, self.files, I.FILES.ordinary, None):
                            pass
                finally:
                    write(member, saved, 0o755)
                    private.unlink(missing_ok=True)

    def test_incoming_and_original_images_both_block_copies(self):
        incoming = self.base/'incoming'
        shutil.copytree(self.root, incoming)
        for name in M.REQUIRED_IMAGES:
            write(incoming/name, F.thin([(0, F.directory(identity=('incoming-'+name).encode()))]), 0o755)
        receipt = self.base/'prepared.json'
        M.write_prepared(incoming, self.root, receipt, self.trees, self.files, I.FILES.ordinary)
        with M.current_legacy_generation(self.root, self.trees, self.files, I.FILES.ordinary, None) as original, \
                M.capture_receipt(incoming, self.trees, self.files, I.FILES.ordinary, path=receipt, target_root=self.root) as prepared:
            images = M.InstallationImages([prepared, original])
            self.assertTrue(original.hashes.isdisjoint(prepared.hashes))
            for captured in (prepared, original):
                with self.assertRaisesRegex(RuntimeError, 'previous owned native processes'):
                    images.require_foreign_image({'code_directory_hash': next(iter(captured.hashes))})
            images.require_foreign_image({'code_directory_hash': 'a'*40})
            (incoming/'router-vpn-client').unlink()
            with self.assertRaises(ValueError): images.verify()

    def test_first_install_absence_never_becomes_empty_image_authority(self):
        root = self.base/'absent'
        with M.current_legacy_generation(root, self.trees, self.files, I.FILES.ordinary, None) as original:
            self.assertIsNone(original)
            with self.assertRaises(ValueError): M.InstallationImages([])
        with self.assertRaisesRegex(ValueError, 'appeared during original absence'):
            with M.current_legacy_generation(root, self.trees, self.files, I.FILES.ordinary, None):
                root.mkdir()


class ManagedProcessLibrary(T.ProcessLibrary):
    def __init__(self, digest, *, versions=None, uuids=None, error=0, pids=(101,), paths=None):
        super().__init__(pids=pids, paths={101: (0, 2)} if paths is None else paths)
        self.digest, self.versions, self.error = bytes.fromhex(digest), list(versions or [9, 9, 9]), error
        self.uuids = list(uuids or ['0' * 32] * 3)
        self.csops_audittoken = T.NativeCall(self.code)
        self.tokens = []
        self.before_hash = lambda: None

    def pid_info(self, pid, flavor, argument, buffer, size):
        if flavor != 17: return super().pid_info(pid, flavor, argument, buffer, size)
        if pid not in self.pids or (argument, size) != (1, 56): raise AssertionError('Managed identity lost original unique-info ABI')
        version = self.versions[0]
        if len(self.versions) > 1: self.versions.pop(0)
        info = ctypes.cast(buffer, ctypes.POINTER(I.GENERATION.IMAGE.NativeUniqueInfo)).contents
        info.uniqueid, info.idversion = 599 + pid, version
        uuid = self.uuids[0]
        if len(self.uuids) > 1: self.uuids.pop(0)
        ctypes.memmove(info.uuid, bytes.fromhex(uuid), 16)
        ctypes.set_errno(0)
        return size

    def code(self, pid, opcode, output, size, token):
        if pid not in self.pids or (opcode, size) != (5, 20): raise AssertionError('Managed comparison lost kernel p_textvp authority')
        self.tokens.append(list(ctypes.cast(token, ctypes.POINTER(ctypes.c_uint32 * 8)).contents))
        self.before_hash()
        if self.error:
            ctypes.set_errno(self.error)
            return -1
        ctypes.memmove(output, self.digest, 20)
        return 0


class ManagedProcessInventory(unittest.TestCase):
    generation = M
    installer = I
    setUp = GenerationReceipt.setUp
    prepare = GenerationReceipt.prepare
    capture = GenerationReceipt.capture

    def read(self, library, captured, *, single_scan=False):
        with mock.patch.object(self.installer, 'native_process_library', return_value=library), \
             mock.patch.object(self.installer.GENERATION.IMAGE, 'code_identity_library', return_value=library), \
             mock.patch.object(self.installer.time, 'sleep'):
            scan = self.installer.running_executables_once if single_scan else self.installer.running_executables
            return scan(captured)

    def test_only_complete_generation_excludes_captured_foreign_live_image(self):
        self.prepare()
        with self.capture() as captured:
            foreign = ManagedProcessLibrary('a'*40)
            self.assertEqual([], self.read(foreign, captured))
            self.assertEqual(foreign.tokens, [[0, 0, 0, 0, 0, 101, 0, 9]])
            with self.assertRaisesRegex(RuntimeError, 'previous native processes have exited'):
                self.read(ManagedProcessLibrary('a'*40), None)
            owned = ManagedProcessLibrary(next(iter(captured.hashes)))
            with self.assertRaisesRegex(RuntimeError, 'previous owned native processes'):
                self.read(owned, captured)

    def test_linked_renamed_copy_is_compared_by_native_image(self):
        self.prepare()
        with self.capture() as captured:
            for owned in (False, True):
                library = ManagedProcessLibrary(next(iter(captured.hashes)) if owned else 'a'*40)
                library.paths[101] = (b'/unrelated-path/renamed-image', 0)
                if owned:
                    with self.assertRaisesRegex(RuntimeError, 'previous owned native processes'):
                        self.read(library, captured)
                else:
                    self.assertEqual(['/unrelated-path/renamed-image'], self.read(library, captured))
            for fault in ('exec', 'path', 'member'):
                library = ManagedProcessLibrary('a'*40)
                library.paths[101] = (b'/unrelated-path/renamed-image', 0)
                if fault == 'exec': library.versions = [9, 9, 9, 10]
                elif fault == 'path': library.paths[101] = [(b'/first', 0), (b'/second', 0)]
                else: library.before_hash = lambda: (self.root/'router-vpn-client').unlink()
                with self.subTest(fault=fault), self.assertRaises((ValueError, RuntimeError)):
                    self.read(library, captured)

    def test_main_image_cannot_replace_the_original_unresolved_exec_generation(self):
        self.prepare()
        with self.capture() as captured:
            library = ManagedProcessLibrary('a'*40, versions=[9, 10, 10])
            with self.assertRaisesRegex(RuntimeError, 'Unresolved native image changed'):
                self.read(library, captured)

    def test_unknown_kernel_identity_and_changed_member_during_probe_stay_blocked(self):
        self.prepare()
        with self.capture() as captured:
            for error in (1, 13):
                with self.subTest(error=error), self.assertRaisesRegex(RuntimeError, 'Cannot capture the native main-image'):
                    self.read(ManagedProcessLibrary('a'*40, error=error), captured)
            # These original synthetic slices have no LC_UUID. The fenced
            # zero UUID therefore matches and must remain rejected.
            with self.assertRaisesRegex(RuntimeError, 'previous owned native processes'):
                self.read(ManagedProcessLibrary('a'*40, error=85), captured)
            library = ManagedProcessLibrary('a'*40)
            library.before_hash = lambda: (self.root/'router-vpn-client').unlink()
            with self.assertRaises(ValueError): self.read(library, captured)

    def prepare_uuid_originals(self):
        for name in sorted(self.generation.REQUIRED_IMAGES):
            write(self.root/name, F.universal([F.thin(uuids=('1' * 32,)),
                                              F.thin(order='>', bits=32, uuids=('2' * 32,))]), 0o755)
        self.prepare()

    def test_ebadexec_requires_captured_uuid_disjoint_from_every_original_slice(self):
        self.prepare_uuid_originals()
        with self.capture() as captured:
            foreign = ManagedProcessLibrary('a' * 40, error=85)
            self.assertEqual([], self.read(foreign, captured))
            self.assertEqual(foreign.tokens, [[0, 0, 0, 0, 0, 101, 0, 9]])
            for uuid in ('1' * 32, '2' * 32):
                with self.subTest(uuid=uuid), self.assertRaisesRegex(RuntimeError, 'previous owned native processes'):
                    self.read(ManagedProcessLibrary('a' * 40, uuids=[uuid] * 3, error=85), captured)
            # An unavailable signature never invents first/legacy history.
            with self.assertRaisesRegex(RuntimeError, 'previous native processes have exited'):
                self.read(ManagedProcessLibrary('a' * 40, error=85), None)
            for error in (1, 13):
                with self.subTest(error=error), self.assertRaisesRegex(RuntimeError, 'Cannot capture the native main-image'):
                    self.read(ManagedProcessLibrary('a' * 40, error=error), captured)

    def test_ebadexec_replaced_exec_or_original_receipt_still_blocks(self):
        self.prepare_uuid_originals()
        with self.capture() as captured:
            for versions, uuids, expected in (
                ([9, 10, 10], ['0' * 32] * 3, 'Unresolved native image changed'),
                ([9, 9, 10], ['0' * 32] * 3, 'process or exec generation changed'),
                ([9, 9, 9], ['0' * 32, '3' * 32, '3' * 32], 'Unresolved native image changed'),
                ([9, 9, 9], ['0' * 32, '0' * 32, '3' * 32], 'process or exec generation changed'),
            ):
                with self.subTest(versions=versions, uuids=uuids), self.assertRaisesRegex(RuntimeError, expected):
                    self.read(ManagedProcessLibrary('a' * 40, versions=versions, uuids=uuids, error=85), captured,
                              single_scan=expected == 'process or exec generation changed')
            original = self.path.read_bytes()
            foreign = json.loads(original); foreign['target_root'] = str(self.base/'foreign-installation')
            probe = ManagedProcessLibrary('a' * 40, error=85)
            probe.before_hash = lambda: self.path.write_text(json.dumps(foreign))
            with self.assertRaisesRegex(ValueError, 'Original managed receipt changed'):
                self.read(probe, captured)
            self.path.write_bytes(original)
        with self.capture() as captured:
            probe = ManagedProcessLibrary('a' * 40, error=85)
            probe.before_hash = lambda: (self.root/'router-vpn-client').unlink()
            with self.assertRaises(ValueError): self.read(probe, captured)

    def scan_sequence(self, captured, libraries):
        pending = iter(libraries)
        current = [None]
        def next_library():
            try:
                current[0] = next(pending)
            except StopIteration:
                self.fail('Native inventory exceeded its permitted complete-scan sequence')
            return current[0]
        with mock.patch.object(self.installer, 'native_process_library', side_effect=next_library), \
             mock.patch.object(self.installer.GENERATION.IMAGE, 'code_identity_library', side_effect=lambda: current[0]), \
             mock.patch.object(self.installer.time, 'sleep'):
            return self.installer.running_executables(captured)

    def transitioning_scan(self):
        # PID101 is fully classified before PID102 changes its exec during
        # the real image-capture function. Only the native ABI is modeled.
        return ManagedProcessLibrary('a' * 40, pids=(101, 102),
                                     paths={101: (b'/discarded-partial-image', 0), 102: (b'/changing-image', 0)},
                                     versions=[9] * 6 + [10])

    def test_live_transition_restarts_the_entire_inventory_without_partial_paths(self):
        self.prepare()
        with self.capture() as captured:
            first = self.transitioning_scan()
            second = ManagedProcessLibrary('a' * 40, pids=(103,), paths={103: (b'/fresh-complete-image', 0)})
            try:
                actual = self.scan_sequence(captured, [first, second])
            except RuntimeError as error:
                self.fail('A valid complete replacement scan was not captured: ' + str(error))
            self.assertEqual(actual, ['/fresh-complete-image'], 'An incomplete old scan lent its partial paths')
            for library in (first, second):
                self.assertEqual(sum(call[0] == 'count' for call in library.calls), 1)
                self.assertEqual(sum(call[0] == 'inventory' for call in library.calls), 1)
            self.assertEqual([token[5] for token in first.tokens], [101, 102])
            self.assertEqual([token[5] for token in second.tokens], [103])

    def test_replacement_inventory_preserves_owned_refusal_and_original_members(self):
        self.prepare()
        with self.capture() as captured:
            first = self.transitioning_scan()
            owned = ManagedProcessLibrary(next(iter(captured.hashes)), pids=(103,), paths={103: (b'/renamed-owned-image', 0)})
            with self.assertRaisesRegex(RuntimeError, 'previous owned native processes'):
                self.scan_sequence(captured, [first, owned])
            self.assertEqual(len(owned.tokens), 1, 'Matching native image was retried or ignored')

            first = self.transitioning_scan()
            original = self.root/'router-vpn-client'
            # Mutate the original scope only as the second PID changes exec.
            count = [0]
            def replace_original():
                count[0] += 1
                if count[0] == 2: original.unlink()
            first.before_hash = replace_original
            fresh = ManagedProcessLibrary('a' * 40)
            with self.assertRaises(ValueError):
                self.scan_sequence(captured, [first, fresh])
            self.assertEqual(fresh.calls, [], 'A changed original installation was replaced with new authority')

    def test_empty_esrch_reobserves_every_live_process_and_never_grants_absence(self):
        self.prepare()
        with self.capture() as captured:
            first = ManagedProcessLibrary('a' * 40, pids=(101, 102),
                paths={101: (b'/discarded-partial-image', 0), 102: (b'/interrupted-image', 0)})
            first.before_hash = lambda: setattr(first, 'error', 3 if len(first.tokens) == 2 else 0)
            fresh = ManagedProcessLibrary('a' * 40, pids=(101, 102),
                paths={101: (b'/fresh-first-image', 0), 102: (b'/fresh-second-image', 0)})
            self.assertEqual(self.scan_sequence(captured, [first, fresh]),
                             ['/fresh-first-image', '/fresh-second-image'])
            for library in (first, fresh):
                self.assertEqual([token[5] for token in library.tokens], [101, 102])
                self.assertEqual(sum(call[0] == 'inventory' for call in library.calls), 1)
            denied = [ManagedProcessLibrary('a' * 40, error=3) for _ in range(3)]
            with self.assertRaises(self.installer.GENERATION.IMAGE.MainImageObservationInterrupted) as failure:
                self.scan_sequence(captured, denied)
            self.assertFalse(hasattr(failure.exception, 'identity'))
            self.assertEqual([len(library.tokens) for library in denied], [1, 1, 1])
            interrupted = ManagedProcessLibrary('a' * 40, error=3)
            owned = ManagedProcessLibrary(next(iter(captured.hashes)))
            with self.assertRaisesRegex(RuntimeError, 'previous owned native processes'):
                self.scan_sequence(captured, [interrupted, owned])
            self.assertEqual(len(owned.tokens), 1)

    def test_whole_inventory_retry_is_bounded_and_does_not_catch_unknown_errors(self):
        self.prepare()
        with self.capture() as captured:
            attempts = [self.transitioning_scan() for _ in range(3)]
            with self.assertRaises(self.installer.GENERATION.IMAGE.MainImageGenerationChanged):
                self.scan_sequence(captured, attempts)
            self.assertEqual([len(library.tokens) for library in attempts], [2, 2, 2])
            for code_error in (1, 13, 22):
                library = ManagedProcessLibrary('a' * 40, versions=[9, 9, 10], error=code_error)
                with self.subTest(error=code_error):
                    with self.assertRaises(RuntimeError) as failure:
                        self.scan_sequence(captured, [library])
                    self.assertNotIsInstance(failure.exception, self.installer.GENERATION.IMAGE.MainImageGenerationChanged)
                    self.assertEqual(len(library.tokens), 1)



NATIVE_GENERATION_PROGRAM = r"""
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 64;
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(argv[1], &end, 10);
    if (errno || end == argv[1] || *end || value == 0 || value > 120) return 64;
    unsigned int remaining = (unsigned int)value;
    while (remaining) remaining = sleep(remaining);
    return 0;
}
"""


def native_generation_seed(base, architecture):
    """Build an ordinary local executable before assigning fixture identities.

    Apple system /bin/sleep may be arm64e. Re-signing it ad hoc removes its
    platform identity. XNU rejects a non-platform arm64e preview-ABI image
    without the preview boot argument, even if codesign --verify succeeds:
    https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exec.c
    This fixture uses the supported ordinary architecture and changes no host
    boot policy. Original Apple-signed foreign/copy tests remain independent.
    """
    architectures = {'arm64': (0x0100000c, 0), 'x86_64': (0x01000007, 3)}
    if architecture not in architectures:
        raise RuntimeError('Native generation fixture has no supported ordinary architecture')
    path = base/'native-generation-seed'
    if path.exists() or path.is_symlink():
        raise RuntimeError('Native generation seed already has an owner')
    command = ['/usr/bin/xcrun', '--sdk', 'macosx', 'clang', '-arch', architecture,
               '-O2', '-Wall', '-Wextra', '-Werror', '-x', 'c', '-', '-o', str(path)]
    result = subprocess.run(command, input=NATIVE_GENERATION_PROGRAM, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise RuntimeError('Native generation fixture compilation failed: '+
                           (result.stdout + result.stderr)[-8000:])
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        header = os.pread(descriptor, 32, 0)
        if (not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111
                or not os.path.samestat(info, path.lstat()) or len(header) != 32):
            raise RuntimeError('Native generation seed lacks its original executable file')
        magic, cpu, subtype, kind, _, _, _, _ = struct.unpack('<IIIIIIII', header)
        if magic != 0xfeedfacf or (cpu, subtype & 0x00ffffff) != architectures[architecture] or kind != 2:
            raise RuntimeError('Native generation seed is not the requested ordinary Mach-O executable')
    finally:
        os.close(descriptor)
    return path


class NativeGenerationBuild(unittest.TestCase):
    def compile_fixture(self, architecture, *, actual=None, status=0):
        temporary = tempfile.TemporaryDirectory(prefix='native-generation-build-')
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        commands = []
        def compiler(command, **options):
            commands.append((command, options))
            if status == 0:
                cpu, subtype = actual or {'arm64': (0x0100000c, 0), 'x86_64': (0x01000007, 3)}[architecture]
                path = Path(command[-1])
                path.write_bytes(struct.pack('<IIIIIIII', 0xfeedfacf, cpu, subtype, 2, 0, 0, 0, 0))
                path.chmod(0o700)
            return subprocess.CompletedProcess(command, status, '', 'compiler diagnostic')
        with mock.patch.object(subprocess, 'run', side_effect=compiler):
            result = native_generation_seed(base, architecture)
        return result, commands

    def test_fixed_compiler_selects_ordinary_host_architecture(self):
        for architecture in ('arm64', 'x86_64'):
            with self.subTest(architecture=architecture):
                path, commands = self.compile_fixture(architecture)
                self.assertTrue(path.is_file())
                self.assertEqual(len(commands), 1)
                command, options = commands[0]
                self.assertEqual(command[:6], ['/usr/bin/xcrun', '--sdk', 'macosx', 'clang', '-arch', architecture])
                self.assertEqual(options['input'], NATIVE_GENERATION_PROGRAM)
                self.assertEqual(options['timeout'], 30)
                self.assertNotIn('shell', options)

    def test_compiler_cannot_substitute_arm64e_or_another_architecture(self):
        for actual in ((0x0100000c, 2), (0x0100000c, 0x80000002), (0x01000007, 3)):
            with self.subTest(actual=actual), self.assertRaisesRegex(RuntimeError, 'requested ordinary Mach-O'):
                self.compile_fixture('arm64', actual=actual)
        with self.assertRaisesRegex(RuntimeError, 'requested ordinary Mach-O'):
            self.compile_fixture('x86_64', actual=(0x0100000c, 0))

    def test_failed_compilation_is_not_retried_or_adopted(self):
        with self.assertRaisesRegex(RuntimeError, 'compilation failed: compiler diagnostic'):
            self.compile_fixture('arm64', status=1)

    def test_unknown_architecture_never_invokes_the_compiler(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'supported ordinary architecture'):
                native_generation_seed(Path(temporary), 'arm64e')
            run.assert_not_called()


@unittest.skipUnless(sys.platform == 'darwin', 'actual Darwin kernel required')
class NativeGenerationReceipt(F.NativeMainImage):
    def codesign(self, *arguments, expected=True):
        result = subprocess.run(['/usr/bin/codesign', *map(str, arguments)],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        if expected and result.returncode != 0:
            self.fail('Actual native fixture signature operation failed '
                      f'(exit={result.returncode}, operation={arguments!r}):\n' +
                      (result.stdout + result.stderr)[-8000:])
        return result

    def complete_native_installation(self):
        seed = native_generation_seed(self.base, platform.machine())
        installed = self.base/'installed'; installed.mkdir(mode=0o755)
        for tree in I.CODE_TREES: (installed/tree).mkdir(mode=0o755)
        for name in M.REQUIRED_IMAGES:
            path = installed/name; path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(seed, path); path.chmod(0o755)
            # Distinguish this owned test generation from unrelated /bin/sleep
            # processes when the whole host's linked images are also compared.
            self.codesign('--force', '--sign', '-', '--timestamp=none', '--identifier',
                          'com.routervpn.fixture.' + self.base.name + '.' + name.replace('/', '.'), path)
        write(installed/'bin/python3', '#!/bin/sh\nexec /usr/bin/python3 -BEsS "$@"\n', 0o700)
        # --strict validates the enclosing application, including its sealed
        # Info.plist and resources. A copied standalone tool under .app is not
        # a complete application bundle. Use an actual locally signed fixture,
        # never relax the verifier to accommodate an incomplete test package.
        # https://developer.apple.com/library/archive/technotes/tn2206/
        application = installed/'RouterVPN.app'
        write(application/'Contents/Info.plist', plistlib.dumps({
            'CFBundleIdentifier': 'com.eabusham.routervpn.generation-fixture',
            'CFBundleExecutable': 'RouterVPN', 'CFBundlePackageType': 'APPL',
            'CFBundleVersion': '1', 'CFBundleShortVersionString': '1.0',
        }))
        self.codesign('--force', '--sign', '-', '--timestamp=none', application)
        self.codesign('--verify', '--deep', '--strict', application)
        for name in M.REQUIRED_IMAGES:
            self.codesign('--verify', '--strict', installed/name)
        return installed, application

    def test_actual_unlinked_matching_copy_is_blocked_by_complete_original_generation(self):
        installed, application = self.complete_native_installation()
        # The negative control uses a separate copy that first verifies, then
        # loses exactly its sealed Info.plist. The original receipt fixture and
        # its executable bytes remain untouched by this deliberate defect.
        broken = self.base/'broken-app/RouterVPN.app'
        shutil.copytree(application, broken)
        self.codesign('--verify', '--deep', '--strict', broken)
        (broken/'Contents/Info.plist').unlink()
        rejected = self.codesign('--verify', '--deep', '--strict', broken, expected=False)
        self.assertNotEqual(rejected.returncode, 0, 'Actual native verifier accepted an app without its sealed Info.plist')
        self.assertTrue((broken/'Contents/MacOS/RouterVPN').is_file())
        print('Actual native verifier rejected the separately copied app after its sealed Info.plist was removed: ' +
              (rejected.stdout + rejected.stderr)[-2000:].strip(), flush=True)
        receipt = M.receipt_path(installed)
        M.write_prepared(installed, installed, receipt, I.CODE_TREES, I.CODE_FILES, I.FILES.ordinary)
        owned, _ = self.copy_image(installed/'router-vpn-client', 'copied-prior-image')
        foreign, _ = self.copy_image('/bin/cat', 'other-prior-image')
        owner = self.launch(owned, '30'); unrelated = self.launch(foreign)
        owned.unlink(); foreign.unlink()
        owned_identity = M.IMAGE.main_image_identity(self.library, owner.pid, self.installer.native_process_state, system=self.system)
        foreign_identity = M.IMAGE.main_image_identity(self.library, unrelated.pid, self.installer.native_process_state, system=self.system)
        with M.capture_receipt(installed, I.CODE_TREES, I.CODE_FILES, I.FILES.ordinary) as captured:
            with self.assertRaisesRegex(RuntimeError, 'previous owned native processes'):
                captured.require_foreign_image(owned_identity)
            captured.require_foreign_image(foreign_identity)
            # Exercise the original-file/kernel-UUID comparison independently
            # of the hash path. The real kernel reads above succeeded; these
            # records model only the EBADEXEC branch, not a native hash error.
            own_uuid = dict(owned_identity, identity_kind='kernel-main-uuid', code_directory_error=85)
            other_uuid = dict(foreign_identity, identity_kind='kernel-main-uuid', code_directory_error=85)
            del own_uuid['code_directory_hash']; del other_uuid['code_directory_hash']
            self.assertIn(own_uuid['main_uuid'], captured.executable_uuids)
            self.assertNotIn(other_uuid['main_uuid'], captured.executable_uuids)
            with self.assertRaisesRegex(RuntimeError, 'previous owned native processes'):
                captured.require_foreign_image(own_uuid)
            captured.require_foreign_image(other_uuid)
            (installed/'router-vpn-client').unlink()
            with self.assertRaises(ValueError): captured.require_foreign_image(foreign_identity)
        self.assertIsNone(owner.poll()); self.assertIsNone(unrelated.poll())
        print('Actual complete generation blocked its copied/unlinked native image and refused a missing original member.', flush=True)


class NativeHostManagedInventory(NativeGenerationReceipt):
    inventory_installer = I
    scope_kind = 'managed'

    @contextmanager
    def capture_scope(self, installed):
        installer, generation = self.inventory_installer, self.inventory_installer.GENERATION
        if self.scope_kind == 'legacy':
            with generation.current_legacy_generation(installed, installer.CODE_TREES,
                                                       installer.CODE_FILES, installer.FILES.ordinary, None) as original:
                self.assertFalse(generation.receipt_path(installed).exists())
                yield generation.InstallationImages([original])
            return
        generation.write_prepared(installed, installed, generation.receipt_path(installed),
                                  installer.CODE_TREES, installer.CODE_FILES, installer.FILES.ordinary)
        with generation.capture_receipt(installed, installer.CODE_TREES,
                                        installer.CODE_FILES, installer.FILES.ordinary) as captured:
            if self.scope_kind == 'first':
                absent = self.base/'first-install-target'
                with generation.current_legacy_generation(absent, installer.CODE_TREES,
                                                           installer.CODE_FILES, installer.FILES.ordinary, None) as previous:
                    self.assertIsNone(previous)
                    yield generation.InstallationImages([captured])
            else:
                yield captured

    def test_actual_full_host_inventory_requires_the_original_complete_generation(self):
        installer = self.inventory_installer
        generation = installer.GENERATION
        original_self = T.capture_native_self(installer)
        installed, _ = self.complete_native_installation()
        foreign, foreign_file = self.copy_image('/bin/cat', 'full-host-foreign-image')
        unrelated = self.launch(foreign)
        foreign_identity = generation.IMAGE.main_image_identity(
            self.library, unrelated.pid, installer.native_process_state, system=self.system)
        self.assertIn(foreign_identity['code_directory_hash'], foreign_file['code_directory_hashes'])
        foreign.unlink()
        with self.capture_scope(installed) as captured:
            self.assertNotIn(foreign_identity['code_directory_hash'], captured.hashes)

            def scan(observations):
                original = captured.require_foreign_image
                original_scan = installer.running_executables_once

                def observe(identity):
                    record = {'identity': dict(identity), 'accepted': False}
                    observations.append(record)
                    original(identity)
                    record['accepted'] = True

                def fresh_scan(scope):
                    self.assertIs(scope, captured, 'Retry replaced the original installation authority')
                    observations.clear()
                    return original_scan(scope)

                # Observe the exact shipping decision, without replacing its
                # process list, libproc, code identity, or receipt validation.
                # A failed attempt cannot lend its foreign-image witness to
                # the later complete inventory.
                with mock.patch.object(captured, 'require_foreign_image', side_effect=observe), \
                     mock.patch.object(installer, 'running_executables_once', side_effect=fresh_scan):
                    return installer.running_executables(captured)

            def require_positive_scan():
                observations = []
                try:
                    paths = scan(observations)
                except Exception as error:
                    print('Actual full-host managed inventory remains refused; '
                          'no successful inventory or defect evidence is claimed: ' + str(error)[-1000:], flush=True)
                    raise
                T.require_native_self_inventory(installer, original_self, paths)
                self.assertIn({'identity': foreign_identity, 'accepted': True}, observations,
                              'Full-host inventory did not prove the exact original foreign child')
                self.assertIsNone(unrelated.poll(), 'Foreign original child exited before the complete host scan')
                captured.verify()
                return len(paths)

            before_count = require_positive_scan()
            owned, owned_file = self.copy_image(installed/'router-vpn-client', 'full-host-owned-image')
            owner = self.launch(owned, '120')
            owned_identity = generation.IMAGE.main_image_identity(
                self.library, owner.pid, installer.native_process_state, system=self.system)
            self.assertIn(owned_identity['code_directory_hash'], owned_file['code_directory_hashes'])
            self.assertIn(owned_identity['code_directory_hash'], captured.hashes)
            linked = []
            with self.assertRaisesRegex(RuntimeError, 'previous owned native processes',
                                        msg='Renamed linked original child did not block full host inventory'):
                scan(linked)
            self.assertIn({'identity': owned_identity, 'accepted': False}, linked)
            owned.unlink()
            rejected = []
            with self.assertRaisesRegex(RuntimeError, 'previous owned native processes',
                                        msg='Matching copied/unlinked original child did not block the full host inventory'):
                scan(rejected)
            self.assertIn({'identity': owned_identity, 'accepted': False}, rejected,
                          'An unrelated failure replaced the exact matching original-image refusal')
            self.assertEqual(owned_identity, generation.IMAGE.main_image_identity(
                self.library, owner.pid, installer.native_process_state, system=self.system))
            self.assertIsNone(owner.poll(), 'Matching original child exited before its refusal was proved')
            owner.kill(); owner.communicate(timeout=3)
            self.assertIsNotNone(owner.returncode, 'Original matching child was not joined before revalidation')
            after_count = require_positive_scan()
        print('Actual full-host managed inventory passed, rejected its exact copied/unlinked original child, '
              'and passed again only after that child was joined: ' +
              json.dumps({'before_paths': before_count, 'after_paths': after_count,
                          'foreign': foreign_identity, 'owned': owned_identity,
                          'scope': self.scope_kind + ' captured installation images; package acceptance remains separate'},
                         sort_keys=True), flush=True)


def full_host_inventory_gate(kind='managed'):
    method = 'test_actual_full_host_inventory_requires_the_original_complete_generation'
    case = type('NativeHostInstallationImages', (NativeHostManagedInventory,), {'scope_kind': kind})
    result = unittest.TextTestRunner(verbosity=2).run(case(method))
    if not result.wasSuccessful():
        raise SystemExit(1)
    # Only a successful real full-host baseline authorizes reporting these
    # executed defects. Each variant still uses real native files/processes.
    mutations = (
        ('fabricated-empty-inventory', ROOT/'client/install-macos-native.py',
         'def running_executables(generation=None):\n',
         'def running_executables(generation=None):\n    return [] # fabricate empty full-host inventory\n',
         'Native process inventory lost the captured executing image'),
        ('accept-matching-native-image', TARGET, 'if value in self.hashes:', 'if False:',
         'Renamed linked original child did not block full host inventory'),
    )
    for name, target, needle, replacement, witness in mutations:
        source = target.read_text()
        if source.count(needle) != 1:
            raise AssertionError('Full-host native control lost its exact shipping source seam: ' + name)
        changed = source.replace(needle, replacement, 1)
        installer = T.load(changed) if target != TARGET else T.load((ROOT/'client/install-macos-native.py').read_text())
        if target == TARGET: installer.GENERATION = generation_source(changed)
        broken = type('BrokenNativeHostManagedInventory', (case,), {'inventory_installer': installer})
        output = io.StringIO()
        result = unittest.TextTestRunner(stream=output).run(broken(method))
        if result.wasSuccessful() or result.errors or not result.failures or witness not in output.getvalue():
            raise AssertionError('Full-host native defect lacked its intended actual assertion: ' + name + '\n' + output.getvalue()[-8000:])
        print('Rejected executed full-host managed-inventory defect: ' + name +
              ' source_sha256=' + hashlib.sha256(changed.encode()).hexdigest(), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-full-host-inventory', action='store_true',
                        help='Require actual full-host managed inventory; unknown native images remain failures')
    parser.add_argument('--native-installation-inventory', action='store_true',
                        help='Require first-install and legacy captured-image inventory on the actual host')
    arguments = parser.parse_args()
    if (arguments.native_full_host_inventory or arguments.native_installation_inventory) and sys.platform != 'darwin':
        raise RuntimeError('Full-host native managed inventory requires actual macOS; no skipped success is permitted')
    if os.geteuid() != 0:
        owner = load(ROOT/'deploy/test_desktop_socket_uid.py', 'managed_generation_elevation')
        sudo = owner.privilege_tool()
        if sudo is None: raise RuntimeError('Generation ownership tests require root in temporary directories')
        raise SystemExit(subprocess.run([sudo, '-n', '--', sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]]).returncode)
    paths = [TARGET, ROOT/'client/install-macos-image.py', ROOT/'client/install-macos-native.py',
             ROOT/'client/install-linux-native.py', ROOT/'cmd/client/install_macos_bootstrap_darwin.go',
             ROOT/'deploy/test_macos_image_identity.py', ROOT/'deploy/test_macos_native_install.py', Path(__file__).resolve()]
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    if arguments.native_full_host_inventory or arguments.native_installation_inventory:
        for kind in ('first', 'legacy') if arguments.native_installation_inventory else ('managed',):
            full_host_inventory_gate(kind)
        if before != {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}:
            raise RuntimeError('Full-host managed-inventory source changed during verification')
        return
    suites = [GenerationReceipt, LegacyInstallationImages, ManagedProcessInventory, NativeGenerationBuild]
    if sys.platform == 'darwin': suites.append(NativeGenerationReceipt)
    for case in suites:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(case))
        if not result.wasSuccessful(): raise SystemExit(1)
    mutations = (
        ('omit-members', "if members != self.value['members']:", 'if False:',
         'test_missing_replaced_changed_or_added_code_cannot_use_prior_receipt'),
        ('omit-receipt-pin', '    def check_receipt(self):\n', '    def check_receipt(self):\n        return # omit original receipt readback\n',
         'test_retained_receipt_rejects_equal_bytes_in_replacement_inode'),
        ('accept-matching-image', 'if value in self.hashes:', 'if False:',
         'test_foreign_comparison_revalidates_members_and_never_accepts_matching_or_unknown_hash'),
        ('accept-matching-uuid', "if identity['main_uuid'] in self.executable_uuids:", 'if False:',
         'test_a_slice_without_uuid_and_uuid_collisions_block_foreign_classification'),
        ('omit-uuid-original-recheck', '    def require_foreign_image(self, identity):\n        self.verify()',
         '    def require_foreign_image(self, identity):\n        pass # accept stale original UUID inventory',
         'test_uuid_comparison_uses_fresh_all_slice_originals_not_receipt_metadata'),
        ('allow-private-code', 'if opened.st_mode & 0o111 or magic in IMAGE.THIN or magic in IMAGE.FAT:', 'if False:',
         'test_private_executable_or_mach_o_never_escapes_complete_inventory'),
    )
    for name, needle, replacement, method in mutations:
        source = TARGET.read_text()
        if source.count(needle) != 1: raise AssertionError('Generation control lost its exact source seam: '+name)
        broken = type('BrokenGeneration', (GenerationReceipt,), {'generation': generation_source(source.replace(needle, replacement, 1))})
        result = unittest.TextTestRunner(stream=io.StringIO()).run(broken(method))
        if result.wasSuccessful() or result.errors or not result.failures:
            raise AssertionError('Generation control did not fail the intended assertion: '+name)
        print('Rejected executed managed-generation defect: '+name, flush=True)
    for name, needle, replacement, method in (
        ('omit-legacy-revalidation', 'if actual != self.members or frozenset(uuids) != self.executable_uuids:',
         'if False:', 'test_legacy_capture_is_complete_ephemeral_and_revalidated'),
        ('drop-original-image-scope', 'self.generations = tuple(generations)',
         'self.generations = tuple(generations[:1])', 'test_incoming_and_original_images_both_block_copies'),
    ):
        source = TARGET.read_text()
        if source.count(needle) != 1: raise AssertionError('Installation-image control lost its source seam: '+name)
        changed = generation_source(source.replace(needle, replacement, 1))
        broken = type('BrokenInstallationImages', (LegacyInstallationImages,), {'generation': changed})
        with mock.patch.dict(globals(), M=changed):
            result = unittest.TextTestRunner(stream=io.StringIO()).run(broken(method))
        if result.wasSuccessful() or result.errors or not result.failures:
            raise AssertionError('Installation-image control missed its actual assertion: '+name)
        print('Rejected executed installation-image defect: '+name, flush=True)
    for name, needle, replacement, method in (
        ('adopt-new-exec', "(identity['uniqueid'], identity['idversion'], identity['main_uuid']) != unresolved.execution",
         'False', 'test_main_image_cannot_replace_the_original_unresolved_exec_generation'),
        ('adopt-unresolved-uuid-exec', "(identity['uniqueid'], identity['idversion'], identity['main_uuid']) != unresolved.execution",
         'False', 'test_ebadexec_replaced_exec_or_original_receipt_still_blocks'),
        ('ignore-owned-code', '                generation.require_foreign_image(identity)',
         '                pass # accept matching old native image', 'test_only_complete_generation_excludes_captured_foreign_live_image'),
        ('ignore-linked-owned-code', '                generation.require_foreign_image(\n                    identity)',
         '                pass # accept matching linked renamed image', 'test_linked_renamed_copy_is_compared_by_native_image'),
        ('omit-complete-retry', '            if attempt == 2:\n                raise',
         '            if True:\n                raise', 'test_live_transition_restarts_the_entire_inventory_without_partial_paths'),
        ('retry-unknown-native-error', '        except GENERATION.IMAGE.MainImageCaptureRetry:',
         '        except RuntimeError:', 'test_whole_inventory_retry_is_bounded_and_does_not_catch_unknown_errors'),
        ('extend-inventory-retry-bound',
         '    for attempt in range(3):\n        try:\n            return running_executables_once(generation)\n        except GENERATION.IMAGE.MainImageCaptureRetry:\n            if attempt == 2:',
         '    for attempt in range(4):\n        try:\n            return running_executables_once(generation)\n        except GENERATION.IMAGE.MainImageCaptureRetry:\n            if attempt == 3:',
         'test_whole_inventory_retry_is_bounded_and_does_not_catch_unknown_errors'),
        ('omit-original-scope-before-rescan', '    library = native_process_library()\n    if generation is not None:\n        generation.verify()',
         '    library = native_process_library()\n    # omit original installation verification before the complete scan',
         'test_replacement_inventory_preserves_owned_refusal_and_original_members'),
    ):
        source = (ROOT/'client/install-macos-native.py').read_text()
        if source.count(needle) != 1: raise AssertionError('Managed inventory control lost actual source seam: '+name)
        broken = type('BrokenManagedInventory', (ManagedProcessInventory,), {'installer': T.load(source.replace(needle, replacement, 1))})
        result = unittest.TextTestRunner(stream=io.StringIO()).run(broken(method))
        if result.wasSuccessful() or result.errors or not result.failures:
            raise AssertionError('Managed inventory control did not fail its actual assertion: '+name)
        print('Rejected executed managed-inventory defect: '+name, flush=True)
    if before != {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}:
        raise RuntimeError('Managed-generation source changed during verification')


if __name__ == '__main__': main()
