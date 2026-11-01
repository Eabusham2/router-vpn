#!/usr/bin/env python3
"""Exercise managed generation receipts using original filesystem objects."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
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


class ManagedProcessLibrary(T.ProcessLibrary):
    def __init__(self, digest, *, versions=None, error=0):
        super().__init__(paths={101: (0, 2)})
        self.digest, self.versions, self.error = bytes.fromhex(digest), list(versions or [9, 9, 9]), error
        self.csops_audittoken = T.NativeCall(self.code)
        self.tokens = []
        self.before_hash = lambda: None

    def pid_info(self, pid, flavor, argument, buffer, size):
        if flavor != 17: return super().pid_info(pid, flavor, argument, buffer, size)
        if (pid, argument, size) != (101, 1, 56): raise AssertionError('Managed identity lost original unique-info ABI')
        version = self.versions[0]
        if len(self.versions) > 1: self.versions.pop(0)
        info = ctypes.cast(buffer, ctypes.POINTER(I.GENERATION.IMAGE.NativeUniqueInfo)).contents
        info.uniqueid, info.idversion = 700, version
        ctypes.set_errno(0)
        return size

    def code(self, pid, opcode, output, size, token):
        if (pid, opcode, size) != (101, 5, 20): raise AssertionError('Managed comparison lost kernel p_textvp authority')
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

    def read(self, library, captured):
        with mock.patch.object(self.installer, 'native_process_library', return_value=library), \
             mock.patch.object(self.installer.GENERATION.IMAGE, 'code_identity_library', return_value=library), \
             mock.patch.object(self.installer.time, 'sleep'):
            return self.installer.running_executables(captured)

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

    def test_main_image_cannot_replace_the_original_unresolved_exec_generation(self):
        self.prepare()
        with self.capture() as captured:
            library = ManagedProcessLibrary('a'*40, versions=[9, 10, 10])
            with self.assertRaisesRegex(RuntimeError, 'Unresolved native image changed'):
                self.read(library, captured)

    def test_unknown_kernel_identity_and_changed_member_during_probe_stay_blocked(self):
        self.prepare()
        with self.capture() as captured:
            for error in (1, 13, 85):
                with self.subTest(error=error), self.assertRaisesRegex(RuntimeError, 'Cannot capture the native main-image'):
                    self.read(ManagedProcessLibrary('a'*40, error=error), captured)
            library = ManagedProcessLibrary('a'*40)
            library.before_hash = lambda: (self.root/'router-vpn-client').unlink()
            with self.assertRaises(ValueError): self.read(library, captured)


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
        installed = self.base/'installed'; installed.mkdir(mode=0o755)
        for tree in I.CODE_TREES: (installed/tree).mkdir(mode=0o755)
        for name in M.REQUIRED_IMAGES:
            path = installed/name; path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile('/bin/sleep', path); path.chmod(0o755)
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
            (installed/'router-vpn-client').unlink()
            with self.assertRaises(ValueError): captured.require_foreign_image(foreign_identity)
        self.assertIsNone(owner.poll()); self.assertIsNone(unrelated.poll())
        print('Actual complete generation blocked its copied/unlinked native image and refused a missing original member.', flush=True)


class NativeHostManagedInventory(NativeGenerationReceipt):
    inventory_installer = I

    def test_actual_full_host_inventory_requires_the_original_complete_generation(self):
        installer = self.inventory_installer
        generation = installer.GENERATION
        original_self = T.capture_native_self(installer)
        installed, _ = self.complete_native_installation()
        generation.write_prepared(installed, installed, generation.receipt_path(installed),
                                  installer.CODE_TREES, installer.CODE_FILES, installer.FILES.ordinary)
        foreign, foreign_file = self.copy_image('/bin/cat', 'full-host-foreign-image')
        unrelated = self.launch(foreign)
        foreign_identity = generation.IMAGE.main_image_identity(
            self.library, unrelated.pid, installer.native_process_state, system=self.system)
        self.assertIn(foreign_identity['code_directory_hash'], foreign_file['code_directory_hashes'])
        foreign.unlink()
        with generation.capture_receipt(installed, installer.CODE_TREES,
                                        installer.CODE_FILES, installer.FILES.ordinary) as captured:
            self.assertNotIn(foreign_identity['code_directory_hash'], captured.hashes)

            def scan(observations):
                original = captured.require_foreign_image

                def observe(identity):
                    record = {'identity': dict(identity), 'accepted': False}
                    observations.append(record)
                    original(identity)
                    record['accepted'] = True

                # Observe the exact shipping decision, without replacing its
                # process list, libproc, code identity, or receipt validation.
                with mock.patch.object(captured, 'require_foreign_image', side_effect=observe):
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
                          'scope': 'managed inventory; first-install, legacy and package acceptance remain separate'},
                         sort_keys=True), flush=True)


def full_host_inventory_gate():
    method = 'test_actual_full_host_inventory_requires_the_original_complete_generation'
    result = unittest.TextTestRunner(verbosity=2).run(NativeHostManagedInventory(method))
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
         'Matching copied/unlinked original child did not block the full host inventory'),
    )
    for name, target, needle, replacement, witness in mutations:
        source = target.read_text()
        if source.count(needle) != 1:
            raise AssertionError('Full-host native control lost its exact shipping source seam: ' + name)
        changed = source.replace(needle, replacement, 1)
        installer = T.load(changed) if target != TARGET else T.load((ROOT/'client/install-macos-native.py').read_text())
        if target == TARGET: installer.GENERATION = generation_source(changed)
        broken = type('BrokenNativeHostManagedInventory', (NativeHostManagedInventory,), {'inventory_installer': installer})
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
    arguments = parser.parse_args()
    if arguments.native_full_host_inventory and sys.platform != 'darwin':
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
    if arguments.native_full_host_inventory:
        full_host_inventory_gate()
        if before != {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}:
            raise RuntimeError('Full-host managed-inventory source changed during verification')
        return
    suites = [GenerationReceipt, ManagedProcessInventory]
    if sys.platform == 'darwin': suites.append(NativeGenerationReceipt)
    for case in suites:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(case))
        if not result.wasSuccessful(): raise SystemExit(1)
    mutations = (
        ('omit-members', "if snapshot(self.root_capture, self.trees, self.files) != self.value['members']:", 'if False:',
         'test_missing_replaced_changed_or_added_code_cannot_use_prior_receipt'),
        ('omit-receipt-pin', '    def check_receipt(self):\n', '    def check_receipt(self):\n        return # omit original receipt readback\n',
         'test_retained_receipt_rejects_equal_bytes_in_replacement_inode'),
        ('accept-matching-image', 'if value in self.hashes:', 'if False:',
         'test_foreign_comparison_revalidates_members_and_never_accepts_matching_or_unknown_hash'),
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
        ('adopt-new-exec', "(identity['uniqueid'], identity['idversion'], identity['main_uuid']) != unresolved.execution",
         'False', 'test_main_image_cannot_replace_the_original_unresolved_exec_generation'),
        ('ignore-owned-code', '                generation.require_foreign_image(identity)',
         '                pass # accept matching old native image', 'test_only_complete_generation_excludes_captured_foreign_live_image'),
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
