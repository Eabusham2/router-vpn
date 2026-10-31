#!/usr/bin/env python3
"""Execute original-file and native main-image identity gates.

Synthetic Mach-O records test bounded parsing only. Native tests execute copied
Apple images and retain their original file identities through unlink; Linux
execution does not claim to validate Apple's kernel or signature verifier.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT/'client/install-macos-image.py'


def load(source=None):
    module = types.ModuleType('macos_original_image')
    module.__file__ = str(TARGET)
    exec(compile(TARGET.read_text() if source is None else source, str(TARGET), 'exec'), module.__dict__)
    return module


M = load()


def directory(hash_type=2, identity=b'owned'):
    sizes = {1: 20, 2: 32, 3: 20, 4: 48}
    size = sizes.get(hash_type, 32)
    offset = 44 + len(identity) + 1
    value = bytearray(offset)
    struct.pack_into('>IIIIIIIII', value, 0, 0xfade0c02, len(value), 0x20000, 0,
                     offset, 44, 0, 0, 48)
    value[36:40] = bytes([size, hash_type, 0, 12])
    value[44:] = identity + b'\0'
    return bytes(value)


def signature(entries):
    offset = 12 + len(entries) * 8
    result = bytearray(struct.pack('>III', 0xfade0cc0, offset + sum(len(data) for _, data in entries), len(entries)))
    for slot, data in entries:
        result.extend(struct.pack('>II', slot, offset)); offset += len(data)
    for _, data in entries:
        result.extend(data)
    return bytes(result)


def thin(entries=None, *, order='<', bits=64, signed=True):
    entries = [(0, directory())] if entries is None else entries
    blob = signature(entries)
    header_size = 32 if bits == 64 else 28
    magic = 0xfeedfacf if bits == 64 else 0xfeedface
    command = struct.pack(order+'IIII', 0x1d if signed else 0xc, 16, header_size + 16, len(blob))
    header = struct.pack(order+'IIIIIII', magic, 0x01000007 if bits == 64 else 7, 3, 2, 1, len(command), 0)
    if bits == 64: header += b'\0' * 4
    return header + command + blob


def universal(images, *, order='>', width=32):
    entry_size = 20 if width == 32 else 32
    magic = 0xcafebabe if width == 32 else 0xcafebabf
    offset = 8 + entry_size * len(images)
    result = bytearray(struct.pack(order+'II', magic, len(images)))
    for index, data in enumerate(images):
        values = (0x01000007 + index, 3, offset, len(data), 0)
        if width == 64: values += (0,)
        result.extend(struct.pack(order + ('IIIII' if width == 32 else 'IIQQII'), *values))
        offset += len(data)
    return bytes(result) + b''.join(images)


class NativeCall:
    def __init__(self, call): self.call = call
    def __call__(self, *arguments): return self.call(*arguments)


class NativeFixture:
    def __init__(self):
        self.unique = [(31, 17), (31, 17)]
        self.states = [(102, 400, 50, 2), (102, 400, 50, 2)]
        self.error = 0
        self.digest = bytes.fromhex('a1' * 20)
        self.tokens = []
        self.proc_pidinfo = NativeCall(self.info)
        self.csops_audittoken = NativeCall(self.code)

    def info(self, pid, flavor, argument, pointer, size):
        if (pid, flavor, argument, size) != (102, 17, 1, 56):
            raise AssertionError('Kernel identity no longer uses the bounded unique-info ABI')
        unique, version = self.unique.pop(0)
        value = ctypes.cast(pointer, ctypes.POINTER(M.NativeUniqueInfo)).contents
        value.uniqueid, value.idversion = unique, version
        return size

    def state(self, library, pid):
        if library is not self or pid != 102: raise AssertionError('Lost the original process library/PID')
        return self.states.pop(0)

    def code(self, pid, opcode, output, size, token):
        token = list(ctypes.cast(token, ctypes.POINTER(ctypes.c_uint32 * 8)).contents)
        self.tokens.append(token)
        if (pid, opcode, size) != (102, 5, 20): raise AssertionError('Lost the actual p_textvp operation')
        if self.error:
            ctypes.set_errno(self.error)
            return -1
        ctypes.memmove(output, self.digest, 20)
        return 0


class ImageCapture(unittest.TestCase):
    image = M

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='routervpn-macos-image-')
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)/'original'

    def capture(self, data):
        self.path.write_bytes(data)
        descriptor = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try: return self.image.capture_image(descriptor)
        finally: os.close(descriptor)

    def test_all_fat_slices_and_alternate_code_directories_are_retained(self):
        directories = [directory(kind, b'image-'+bytes([kind])) for kind in (1, 2, 3, 4)]
        expected = sorted({hashlib.new(M.HASHES[blob[37]][0], blob).digest()[:20].hex() for blob in directories})
        for order in ('>', '<'):
            for width in (32, 64):
                raw = universal([thin([(0, directories[0]), (0x1000, directories[1])]),
                                 thin([(0, directories[2]), (0x1001, directories[3])], order='>', bits=32)],
                                order=order, width=width)
                with self.subTest(order=order, width=width):
                    actual = self.capture(raw)
                    self.assertEqual(actual['code_directory_hashes'], expected)
                    self.assertTrue(actual['mach_o'])
                    self.assertEqual(actual['sha256'], hashlib.sha256(raw).hexdigest())

    def test_non_image_is_explicit_without_fabricated_identity(self):
        for raw in (b'', b'x', b'#!/bin/sh\nexit 0\n', b'{"private":"state"}'):
            with self.subTest(raw=raw):
                actual = self.capture(raw)
                self.assertFalse(actual['mach_o'])
                self.assertEqual(actual['code_directory_hashes'], [])

    def test_unknown_or_unsigned_mach_o_never_becomes_empty_exclusion(self):
        for raw in (thin(signed=False), thin([(0, directory(19))]), thin([]),
                    thin([(0, directory()), (0, directory())])):
            with self.subTest(sha256=hashlib.sha256(raw).hexdigest()):
                with self.assertRaises(ValueError): self.capture(raw)

    def test_every_truncated_native_container_is_rejected(self):
        raw = universal([thin(), thin([(0, directory(4))])])
        for length in (4, 7, 8, 24, 47, 55, len(raw)-1):
            with self.subTest(length=length):
                with self.assertRaises(ValueError): self.capture(raw[:length])

    def test_overlapping_slices_and_signature_entries_are_rejected(self):
        raw = bytearray(universal([thin(), thin()]))
        first = struct.unpack_from('>I', raw, 16)[0]
        struct.pack_into('>I', raw, 36, first)
        with self.assertRaises(ValueError): self.capture(bytes(raw))
        signed = bytearray(signature([(0, directory()), (0x1000, directory(4))]))
        offset = struct.unpack_from('>I', signed, 16)[0]
        struct.pack_into('>I', signed, 24, offset)
        with self.assertRaises(ValueError): self.image.signature_hashes(bytes(signed))

    def test_original_descriptor_metadata_is_read_back_after_capture(self):
        raw = thin()
        self.path.write_bytes(raw)
        descriptor = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        original_pread = os.pread
        changed = []
        def replace_metadata(fd, size, offset):
            data = original_pread(fd, size, offset)
            if not changed:
                changed.append(True)
                os.chmod(self.path, 0o600 if self.path.stat().st_mode & 0o777 != 0o600 else 0o644)
            return data
        try:
            with mock.patch.object(os, 'pread', replace_metadata):
                with self.assertRaisesRegex(ValueError, 'Original image changed'):
                    self.image.capture_image(descriptor)
        finally: os.close(descriptor)

    def test_hardlinked_or_unlinked_source_has_no_complete_named_member_identity(self):
        self.path.write_bytes(thin())
        descriptor = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.link(self.path, self.path.with_name('alias'))
            with self.assertRaises(ValueError): self.image.capture_image(descriptor)
            self.path.with_name('alias').unlink(); self.path.unlink()
            with self.assertRaises(ValueError): self.image.capture_image(descriptor)
        finally: os.close(descriptor)


class MainImageCapture(unittest.TestCase):
    image = M

    def test_native_hash_is_fenced_by_original_pid_and_exec_generation(self):
        fake = NativeFixture()
        actual = self.image.main_image_identity(fake, 102, fake.state, system=fake)
        self.assertEqual(actual['code_directory_hash'], fake.digest.hex())
        self.assertEqual((actual['uniqueid'], actual['idversion']), (31, 17))
        self.assertEqual(fake.tokens, [[0, 0, 0, 0, 0, 102, 0, 17]])
        self.assertEqual(fake.unique, [])
        self.assertEqual(fake.states, [])

    def test_native_error_unknown_signature_and_zero_hash_never_grant_identity(self):
        for error in (errno.ESRCH, errno.EACCES, errno.EPERM, errno.EINVAL, 85):
            with self.subTest(error=error):
                fake = NativeFixture(); fake.error = error
                with self.assertRaisesRegex(RuntimeError, 'Cannot capture the native main-image'):
                    self.image.main_image_identity(fake, 102, fake.state, system=fake)
        fake = NativeFixture(); fake.digest = bytes(20)
        with self.assertRaises(RuntimeError): self.image.main_image_identity(fake, 102, fake.state, system=fake)

    def test_reused_pid_exec_changed_or_zombie_after_hash_is_rejected(self):
        for change in ('pid', 'exec', 'start', 'gone', 'zombie'):
            with self.subTest(change=change):
                fake = NativeFixture()
                if change == 'pid': fake.unique[-1] = (32, 17)
                elif change == 'exec': fake.unique[-1] = (31, 18)
                elif change == 'start': fake.states[-1] = (102, 401, 50, 2)
                elif change == 'gone': fake.states[-1] = None
                else: fake.states[-1] = (102, 400, 50, 5)
                with self.assertRaisesRegex(RuntimeError, 'process or exec generation changed'):
                    self.image.main_image_identity(fake, 102, fake.state, system=fake)


@unittest.skipUnless(sys.platform == 'darwin', 'actual Darwin kernel required')
class NativeMainImage(unittest.TestCase):
    image = M

    def setUp(self):
        spec = importlib.util.spec_from_file_location('macos_native_installer_for_image', ROOT/'client/install-macos-native.py')
        self.installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.installer)
        self.library = self.installer.native_process_library()
        self.system = self.image.code_identity_library()
        self.temporary = tempfile.TemporaryDirectory(prefix='routervpn-native-main-image-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve(strict=True)

    def copy_image(self, source, name):
        path = self.base/name
        shutil.copyfile(source, path); path.chmod(0o700)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try: captured = self.image.capture_image(descriptor)
        finally: os.close(descriptor)
        subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(path)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        return path, captured

    def launch(self, path, *arguments):
        child = subprocess.Popen([str(path), *arguments], stdin=subprocess.PIPE,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        def cleanup():
            if child.poll() is None: child.kill()
            child.communicate(timeout=3)
        self.addCleanup(cleanup)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            self.assertIsNone(child.poll(), 'Original native fixture exited before capture')
            native, _, _ = self.installer.native_process_path(self.library, child.pid)
            if native == str(path): return child
            time.sleep(0.01)
        self.fail('Original copied native fixture did not enter its exact executable')

    def test_actual_copied_unlinked_main_image_keeps_its_original_code_identity(self):
        path, original = self.copy_image('/bin/sleep', 'owned-image')
        foreign, other = self.copy_image('/bin/cat', 'foreign-image')
        self.assertTrue(set(original['code_directory_hashes']).isdisjoint(other['code_directory_hashes']))
        child = self.launch(path, '30')
        unrelated = self.launch(foreign)
        before = self.image.main_image_identity(self.library, child.pid, self.installer.native_process_state, system=self.system)
        self.assertIn(before['code_directory_hash'], original['code_directory_hashes'])
        self.assertEqual((path.stat().st_dev, path.stat().st_ino), tuple(original['file_identity'][:2]))
        path.unlink(); foreign.unlink()
        self.assertIsNone(child.poll()); self.assertIsNone(unrelated.poll())
        after = self.image.main_image_identity(self.library, child.pid, self.installer.native_process_state, system=self.system)
        actual_other = self.image.main_image_identity(self.library, unrelated.pid, self.installer.native_process_state, system=self.system)
        self.assertEqual(before, after)
        self.assertIn(after['code_directory_hash'], original['code_directory_hashes'])
        self.assertNotIn(actual_other['code_directory_hash'], original['code_directory_hashes'])
        self.assertIn(actual_other['code_directory_hash'], other['code_directory_hashes'])
        print('Actual original copied/unlinked main images retained their separate CodeDirectory identities: '+
              json.dumps({'owned': after, 'foreign': actual_other, 'admission_authority': False}, sort_keys=True), flush=True)

    def test_actual_kernel_rejects_a_wrong_exec_generation_token(self):
        path, _ = self.copy_image('/bin/sleep', 'generation-image')
        child = self.launch(path, '30')
        original = self.system.csops_audittoken
        observed = []
        def wrong_generation(pid, operation, output, size, token):
            value = ctypes.cast(token, ctypes.POINTER(ctypes.c_uint32 * 8)).contents
            self.assertEqual(value[5], child.pid)
            self.assertGreater(value[7], 0)
            value[7] -= 1
            result = original(pid, operation, output, size, token)
            observed.append((result, ctypes.get_errno()))
            return result
        boundary = types.SimpleNamespace(csops_audittoken=wrong_generation)
        with self.assertRaisesRegex(RuntimeError, 'Cannot capture the native main-image'):
            self.image.main_image_identity(self.library, child.pid, self.installer.native_process_state, system=boundary)
        self.assertEqual(observed, [(-1, errno.ESRCH)])
        self.assertIsNone(child.poll(), 'Wrong-generation control did not preserve its actual child')


def later_host_observation():
    """Read one refused PID later; no original-lookup or installation authority."""
    spec = importlib.util.spec_from_file_location('macos_image_diagnostic_installer', ROOT/'client/install-macos-native.py')
    installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)
    original = installer.native_executable
    records = []
    def observe(library, pid):
        try: return original(library, pid)
        except Exception:
            record = {'requested_pid': pid, 'admission_authority': False, 'original_lookup_identity_proved': False}
            try: record['later_main_image'] = M.main_image_identity(library, pid, installer.native_process_state)
            except Exception as error: record['identity_failure'] = str(error)
            records.append(record)
            raise
    try:
        with mock.patch.object(installer, 'native_executable', observe): installer.running_executables()
    except Exception:
        pass
    print('Later refused-host main-image observation (diagnostic only): '+json.dumps(records, sort_keys=True), flush=True)


def main():
    if sys.platform == 'darwin' and os.geteuid() != 0:
        spec = importlib.util.spec_from_file_location('macos_image_elevation', ROOT/'deploy/test_desktop_socket_uid.py')
        owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
        sudo = owner.privilege_tool()
        if sudo is None:
            raise RuntimeError('Actual hosted main-image observation requires the installer privilege boundary')
        raise SystemExit(subprocess.run([sudo, '-n', '--', sys.executable, str(Path(__file__).resolve())]).returncode)
    before = hashlib.sha256(TARGET.read_bytes()).hexdigest()
    suites = [ImageCapture, MainImageCapture]
    if sys.platform == 'darwin': suites.append(NativeMainImage)
    for case in suites:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(case))
        if not result.wasSuccessful(): raise SystemExit(1)
    mutations = (
        ('omit-alternates', 'if slot == 0 or 0x1000 <= slot < 0x1005:', 'if slot == 0:',
         ImageCapture, 'test_all_fat_slices_and_alternate_code_directories_are_retained'),
        ('omit-slices', 'for offset, length in slices:', 'for offset, length in slices[:1]:',
         ImageCapture, 'test_all_fat_slices_and_alternate_code_directories_are_retained'),
        ('omit-original-readback', 'if file_identity(original) != file_identity(os.fstat(descriptor)):', 'if False:',
         ImageCapture, 'test_original_descriptor_metadata_is_read_back_after_capture'),
        ('wrong-exec-token', 'token[5], token[7] = pid, unique[1]', 'token[5], token[7] = pid, 0',
         MainImageCapture, 'test_native_hash_is_fenced_by_original_pid_and_exec_generation'),
        ('omit-exec-recheck', 'or unique != after_unique):', '):',
         MainImageCapture, 'test_reused_pid_exec_changed_or_zombie_after_hash_is_rejected'),
        ('accept-unknown-code', 'if result != 0 or not any(digest):', 'if False:',
         MainImageCapture, 'test_native_error_unknown_signature_and_zero_hash_never_grant_identity'),
    )
    for name, needle, replacement, case, method in mutations:
        source = TARGET.read_text()
        if source.count(needle) != 1: raise AssertionError('Image control lost exact source seam: '+name)
        module = load(source.replace(needle, replacement, 1))
        broken = type('BrokenImageIdentity', (case,), {'image': module})
        result = unittest.TextTestRunner(stream=io.StringIO()).run(broken(method))
        if result.wasSuccessful() or result.errors or not result.failures:
            raise AssertionError('Image control did not fail its actual assertion: '+name)
        print('Rejected executed original-image defect: '+name, flush=True)
    if before != hashlib.sha256(TARGET.read_bytes()).hexdigest():
        raise RuntimeError('Original-image source changed during verification')
    if sys.platform == 'darwin': later_host_observation()
    print('Original-file parser and native generation gate completed; complete-installation admission remains separate.', flush=True)


if __name__ == '__main__': main()
