#!/usr/bin/env python3
"""Exercise the locked Cargo output to verified static Windows PQ link input."""
from pathlib import Path
import contextlib
import copy
import ctypes
import importlib.util
import io
import json
import os
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('desktop_pq_dependencies', ROOT/'deploy/build-desktop-pq.py')
PQ = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PQ)


def member(name, raw):
    header = f'{name:<16}{0:<12}{0:<6}{0:<6}{644:<8}{len(raw):<10}`\n'.encode()
    assert len(header) == 60
    return header+raw+(b'\n' if len(raw) & 1 else b'')


def object_bytes(target='windows/amd64', *, section=b'.text', big=False):
    machine = {'windows/amd64': 0x8664, 'windows/arm64': 0xaa64}[target]
    if big:
        header = struct.pack('<HHHHI', 0, 0xffff, 2, machine, 0)
        header += bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8')
        header += struct.pack('<IIIIIII', 0, 0, 0, 0, 1, 0, 0)
    else:
        header = struct.pack('<HHIIIHH', machine, 1, 0, 0, 0, 0, 0)
    # A minimal COFF text section gives the parser real object layout, rather
    # than substituting a successful archive-validation function.
    data = b'\xc3\0\0\0' if machine == 0x8664 else b'\xc0\x03\x5f\xd6'
    table = struct.pack('<8sIIIIIIHHI', section, 0, 0, len(data), len(header)+40, 0, 0, 0, 0, 0x60000020)
    return header+table+data


def archive(target='windows/amd64', **kwargs):
    return b'!<arch>\n'+member('/', b'index')+member('oqs.obj/', object_bytes(target, **kwargs))


def build_output(event, *, finished=True, flags='-loqs -ladvapi32 -lwindows'):
    return ('Cargo progress\n'+json.dumps(event)+'\n'+
            json.dumps({'reason': 'build-finished', 'success': finished})+'\n'+
            'note: native-static-libs: '+flags+'\n')


class OQSDependency(unittest.TestCase):
    def fixture(self, root, target='windows/amd64', directory='lib'):
        cache = root/'Cargo cache'
        out = cache/PQ.TARGETS[target]/'release/build/oqs-sys-0123456789abcdef/out'
        path = out/directory/'liboqs.a'
        path.parent.mkdir(parents=True)
        raw = archive(target)
        path.write_bytes(raw)
        event = {'reason': 'build-script-executed', 'package_id': PQ.oqs_identity()['package_id'],
                 'linked_libs': ['oqs', 'advapi32'], 'out_dir': str(out),
                 'linked_paths': ['native='+str(out/name) for name in ('lib', 'lib64')]}
        return cache, path, raw, event

    def test_both_targets_use_one_exact_current_cargo_output(self):
        for target in ('windows/amd64', 'windows/arm64'):
            for directory in ('lib', 'lib64'):
                with self.subTest(target=target, directory=directory), tempfile.TemporaryDirectory() as tmp:
                    cache, path, raw, event = self.fixture(Path(tmp), target, directory)
                    # An old, unrelated cache build must never be selected.
                    stale = path.parents[2].with_name('oqs-sys-fedcba9876543210')/'out/lib/liboqs.a'
                    stale.parent.mkdir(parents=True)
                    stale.write_bytes(b'unrelated cache bytes')
                    self.assertEqual(PQ.built_oqs_archive(build_output(event), target, cache), raw)

    def test_wrong_package_version_source_or_ambiguous_build_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache, _, _, event = self.fixture(Path(tmp))
            outputs = []
            for package in ('registry+https://unrelated.invalid#index#oqs-sys@0.11.0+liboqs-0.13.0',
                            event['package_id'].replace('@0.11.0', '@0.10.0')):
                changed = {**event, 'package_id': package}
                outputs.append(build_output(changed))
            outputs += [build_output(event)+'\n'+json.dumps(event), build_output(event, finished=False),
                        json.dumps(event), build_output(event)+'\n'+json.dumps({'reason':'build-finished','success':True})]
            for output in outputs:
                with self.subTest(output=output), self.assertRaises(ValueError):
                    PQ.built_oqs_archive(output, 'windows/amd64', cache)

    def test_cargo_cache_alias_retains_actual_directory_identity(self):
        for target in ('windows/amd64', 'windows/arm64'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                cache, path, raw, event = self.fixture(root, target)
                if os.name == 'nt':
                    short_path = ctypes.WinDLL('kernel32', use_last_error=True).GetShortPathNameW
                    short_path.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
                    short_path.restype = ctypes.c_uint32
                    length = short_path(str(cache), None, 0)
                    self.assertGreater(length, 0, 'Native cache alias read failed')
                    buffer = ctypes.create_unicode_buffer(length)
                    written = short_path(str(cache), buffer, length)
                    self.assertTrue(0 < written < length, 'Native cache alias changed while reading')
                    alias = Path(buffer.value)
                else:
                    # Exercise the same kernel identity boundary on hosts
                    # without Windows 8.3 names; linked children remain denied.
                    alias = root/'CARGO~1'
                    alias.symlink_to(cache, target_is_directory=True)
                self.assertTrue(alias.samefile(cache))
                reported = alias/path.parent.parent.relative_to(cache)
                changed = {**event, 'out_dir': str(reported),
                           'linked_paths': ['native='+str(reported/name) for name in ('lib', 'lib64')]}
                self.assertEqual(PQ.built_oqs_archive(build_output(changed), target, cache), raw)
                # Equal bytes and an identical relative target layout do not
                # make another build cache the one captured by this invocation.
                other = root/'other-cache'
                shutil.copytree(cache, other)
                foreign = other/path.parent.parent.relative_to(cache)
                changed.update(out_dir=str(foreign),
                               linked_paths=['native='+str(foreign/name) for name in ('lib', 'lib64')])
                with self.assertRaisesRegex(ValueError, 'different target cache'):
                    PQ.built_oqs_archive(build_output(changed), target, cache)

    def test_cache_alias_does_not_hide_linked_target_components(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            cache, path, _, event = self.fixture(root)
            owned = path.parents[2]
            retained = owned.with_name('original-fingerprint')
            owned.rename(retained)
            owned.symlink_to(retained, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'linked directory'):
                PQ.built_oqs_archive(build_output(event), 'windows/amd64', cache)

    def test_native_and_cross_host_linkage_must_match_rustcs_exact_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache, _, raw, native = self.fixture(Path(tmp))
            bundled = {**native, 'linked_libs': ['static=oqs']}
            flags = '-ladvapi32 -lwindows'
            self.assertEqual(PQ.built_oqs_archive(build_output(bundled, flags=flags), 'windows/amd64', cache), raw)
            for output in (build_output(native, flags=flags), build_output(bundled)):
                with self.assertRaisesRegex(ValueError, 'dependency declaration changed'):
                    PQ.built_oqs_archive(output, 'windows/amd64', cache)

    def test_target_root_and_declared_search_paths_cannot_be_substituted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache, path, _, event = self.fixture(root)
            out = path.parent.parent
            changes = [
                {'out_dir': str(root/'outside')}, {'out_dir': 'relative/out'},
                {'out_dir': str(out/'..'/'out')},
                {'out_dir': str(out).replace(PQ.TARGETS['windows/amd64'], PQ.TARGETS['windows/arm64'])},
                {'out_dir': str(out).replace('0123456789abcdef', 'not-a-cargo-fingerprint')},
                {'linked_paths': ['native='+str(out/'lib'), 'native='+str(root/'outside')]},
                {'linked_paths': ['native='+str(out/'lib')]*2},
                {'linked_paths': event['linked_paths']+['native=/ambient']},
                {'linked_libs': ['oqs']}, {'linked_libs': ['dylib=oqs', 'advapi32']},
            ]
            for change in changes:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    PQ.built_oqs_archive(build_output({**event, **change}), 'windows/amd64', cache)

    def test_missing_ambiguous_oversized_and_linked_archives_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache, path, raw, event = self.fixture(root)
            path.unlink()
            with self.assertRaises(ValueError):
                PQ.built_oqs_archive(build_output(event), 'windows/amd64', cache)
            path.write_bytes(raw)
            other = path.parent.parent/'lib64/liboqs.a'
            other.parent.mkdir()
            other.write_bytes(raw)
            with self.assertRaises(ValueError):
                PQ.built_oqs_archive(build_output(event), 'windows/amd64', cache)
            other.unlink()
            with patch.object(PQ, 'MAX_OQS_LIBRARY', len(raw)-1), self.assertRaises(ValueError):
                PQ.built_oqs_archive(build_output(event), 'windows/amd64', cache)
            outside = root/'outside.a'
            outside.write_bytes(raw)
            path.unlink()
            path.symlink_to(outside)
            with self.assertRaises(ValueError):
                PQ.built_oqs_archive(build_output(event), 'windows/amd64', cache)
            path.unlink()
            path.parent.rmdir()
            path.parent.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                PQ.built_oqs_archive(build_output(event), 'windows/amd64', cache)

    def test_import_thin_foreign_and_malformed_archives_are_rejected(self):
        import_object = struct.pack('<HHHHIIHH', 0, 0xffff, 0, 0x8664, 0, 0, 0, 0)
        image = bytearray(object_bytes())
        struct.pack_into('<H', image, 16, 240)
        malformed = bytearray(object_bytes())
        struct.pack_into('<I', malformed, 20+20, 0xfffffff0)
        samples = [b'!<thin>\n'+member('oqs.obj/', object_bytes()), archive('windows/arm64'),
                   b'!<arch>\n'+member('import/', import_object),
                   archive(section=b'.idata$4'), archive(section=b'.edata'),
                   b'!<arch>\n'+member('image/', bytes(image)),
                   b'!<arch>\n'+member('bad/', bytes(malformed)),
                   b'!<arch>\n'+member('/', b'index only'),
                   b'!<arch>\n'+member('bad/', b'not an object'), archive()[:-1]]
        for raw in samples:
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                PQ.static_oqs_archive(raw, 'windows/amd64')

    def test_static_bigobj_is_distinguished_from_a_short_import_object(self):
        for target in ('windows/amd64', 'windows/arm64'):
            raw = archive(target, big=True)
            self.assertEqual(PQ.static_oqs_archive(raw, target), raw)

    def test_long_section_names_cannot_hide_dll_import_data(self):
        obj = bytearray(object_bytes(section=b'/4'))
        strings = b'.idata$long-import-section\0'
        struct.pack_into('<I', obj, 8, len(obj))
        obj += struct.pack('<I', len(strings)+4)+strings
        with self.assertRaisesRegex(ValueError, 'DLL import/export'):
            PQ.static_oqs_archive(b'!<arch>\n'+member('import/', obj), 'windows/amd64')

    def test_actual_build_stages_and_relocates_a_complete_receipt(self):
        for target in ('windows/amd64', 'windows/arm64'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                cache, _, raw, event = self.fixture(root, target)
                rust_archive = cache/PQ.TARGETS[target]/'release/libroutervpn_rosenpass.a'
                rust_archive.write_bytes(b'owned Rust ABI fixture')
                calls = []

                @contextlib.contextmanager
                def manifest(actual_target, env):
                    self.assertEqual(actual_target, target)
                    yield root/'Cargo.toml', b'locked Windows import fixture'

                def run(command, **kwargs):
                    calls.append(command)
                    if command[:2] == ['rustc', '--version']:
                        return 'rustc '+PQ.RUST+' fixture'
                    if command[:2] == ['cargo', '--version']:
                        return 'cargo '+PQ.RUST+' fixture'
                    self.assertEqual(command[:3], ['cargo', 'rustc', '--message-format=json-render-diagnostics'])
                    self.assertIn('--locked', command)
                    self.assertEqual(command[command.index('--target')+1], PQ.TARGETS[target])
                    return build_output(event)

                output = root/'link input'
                with patch.object(PQ, 'environment', return_value={}), \
                     patch.object(PQ, 'native_manifest', side_effect=manifest), \
                     patch.object(PQ, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                    PQ.build(target, output, cache)
                    receipt = PQ.verify(output, target)
                    self.assertEqual((output/'liboqs.a').read_bytes(), raw)
                    self.assertEqual(receipt['oqs_archive']['package_id'], event['package_id'])
                    self.assertEqual(receipt['oqs_archive']['crate_checksum'], PQ.oqs_identity()['crate_checksum'])
                    self.assertEqual(receipt['native_static_libs'], ['-loqs', '-ladvapi32', '-lwindows'])
                    self.assertEqual(len(calls), 3)
                    PQ.build(target, output, cache)
                    self.assertEqual(len(calls), 3, 'verified reuse unexpectedly rebuilt its dependencies')
                moved = root/'relocated/link input'
                shutil.copytree(output, moved)
                self.assertEqual(PQ.verify(moved, target), receipt)
                original = (moved/'DESKTOP-PQ.json').read_bytes()
                for field, value in [('crate_checksum','0'*64), ('package_id','foreign'), ('linkage','bundled'),
                                     ('size',len(raw)+1), ('sha256','0'*64)]:
                    changed = copy.deepcopy(receipt)
                    changed['oqs_archive'][field] = value
                    (moved/'DESKTOP-PQ.json').write_text(json.dumps(changed))
                    with self.subTest(receipt_field=field), self.assertRaises(ValueError):
                        PQ.verify(moved, target)
                (moved/'DESKTOP-PQ.json').write_bytes(original)
                changed = bytearray(raw)
                changed[-1] ^= 1
                (moved/'liboqs.a').write_bytes(changed)
                with self.assertRaises(ValueError):
                    PQ.verify(moved, target)
                (moved/'liboqs.a').unlink()
                with self.assertRaises(ValueError):
                    PQ.verify(moved, target)


if __name__ == '__main__':
    unittest.main()
