#!/usr/bin/env python3
"""Exercise Windows delivery imports and the real native builder link boundary."""
from pathlib import Path, PureWindowsPath
import importlib.util
import json
import os
import shlex
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_dependencies', ROOT/'deploy/build-native-runtime.py')
N = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(N)

PE, OPTIONAL, HEADER = 0x80, 0x98, 0x200
SECTIONS = OPTIONAL+240


def align(value, boundary):
    return (value+boundary-1)//boundary*boundary


def image(target, ordinary=('KERNEL32.dll',), delayed=()):
    """Independent PE32+ fixture with import descriptors and names in two sections.

    The optional header's directory RVAs deliberately differ from file offsets;
    ordinary and delay names also reside outside their descriptor section.
    """
    import_size = 20*(len(ordinary)+1) if ordinary else 0
    delay_offset = align(import_size, 16)
    delay_size = 32*(len(delayed)+1) if delayed else 0
    data_size = align(max(delay_offset+delay_size, 1), 0x200)
    names = bytearray()
    locations = []
    name_address = align(0x1000+data_size, 0x1000)
    for name in (*ordinary, *delayed):
        locations.append(name_address+len(names))
        names.extend(name.encode('ascii')+b'\0')
    name_size = align(max(len(names), 1), 0x200)
    raw = bytearray(HEADER+data_size+name_size)
    raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 0x3c, PE)
    raw[PE:PE+4] = b'PE\0\0'
    machine = {'windows/amd64': 0x8664, 'windows/arm64': 0xaa64}[target]
    struct.pack_into('<HHIIIHH', raw, PE+4, machine, 2, 0, 0, 0, 240, 0x22)
    struct.pack_into('<H', raw, OPTIONAL, 0x20b)
    struct.pack_into('<Q', raw, OPTIONAL+24, 0x140000000)
    struct.pack_into('<II', raw, OPTIONAL+32, 0x1000, 0x200)
    struct.pack_into('<II', raw, OPTIONAL+56, align(name_address+name_size, 0x1000), HEADER)
    struct.pack_into('<I', raw, OPTIONAL+108, 16)
    if ordinary:
        struct.pack_into('<II', raw, OPTIONAL+112+8, 0x1000, import_size)
    if delayed:
        struct.pack_into('<II', raw, OPTIONAL+112+13*8, 0x1000+delay_offset, delay_size)
    for index, (name, size, address, offset) in enumerate((
            (b'.idata', data_size, 0x1000, HEADER),
            (b'.rdata', name_size, name_address, HEADER+data_size))):
        row = SECTIONS+40*index
        raw[row:row+len(name)] = name
        struct.pack_into('<IIII', raw, row+8, size, address, size, offset)
    for index in range(len(ordinary)):
        struct.pack_into('<IIIII', raw, HEADER+20*index, 0x1000, 0, 0, locations[index], 0x1000)
    for index in range(len(delayed)):
        struct.pack_into('<IIIIIIII', raw, HEADER+delay_offset+32*index,
                         1, locations[len(ordinary)+index], 0x1000, 0x1000, 0x1000, 0, 0, 0)
    raw[HEADER+data_size:HEADER+data_size+len(names)] = names
    return raw


def metadata(target):
    system, arch = target.split('/')
    return '\n'.join((N.TOOLCHAIN, 'build\tGOOS='+system, 'build\tGOARCH='+arch,
                      'build\tCGO_ENABLED=1', 'build\t-tags='+','.join(N.tags(target)),
                      'dep\tgithub.com/amnezia-vpn/amneziawg-go/v3\t'+N.POLICY.AMNEZIA.VERSION,
                      'dep\tgithub.com/xtls/xray-core\t'+N.POLICY.XRAY_VERSION))


def write_bundle(root, target, *, engine=None, cronet=None):
    (root/N.binary_name(target)).write_bytes(image(target) if engine is None else engine)
    (root/N.library_name(target)).write_bytes(image(target) if cronet is None else cronet)


class WindowsDependencyDelivery(unittest.TestCase):
    def test_complete_source_receipt_is_independent_of_host_path_order(self):
        expected = N.digest()
        files = N.inputs()
        names = [path.relative_to(N.ROOT).as_posix() for path in files]
        self.assertEqual(names, sorted(names))
        self.assertTrue(any(name.endswith('AndroidConnectionProfileStore.java') for name in names))
        self.assertTrue(any(name.endswith('AndroidConnectionProfilesDialog.java') for name in names))
        # Execute the real nested input collectors under Windows's case-folded
        # Path ordering. This reproduced the exact failed Windows CI digest
        # before the producer sealed a canonical final input order.
        with patch.object(Path, '__lt__', lambda left, right:
                          PureWindowsPath(str(left)) < PureWindowsPath(str(right))):
            self.assertEqual(N.inputs(), files)
            self.assertEqual(N.digest(), expected)

        # Stable discovery must not weaken the exact-byte or filename seal.
        read = Path.read_bytes
        changed = next(path for path in files if path.name == 'AndroidConnectionProfileStore.java')
        with patch.object(Path, 'read_bytes', lambda path:
                          read(path) + b'\n// changed native source\n' if path == changed else read(path)):
            self.assertNotEqual(N.digest(), expected)
        with patch.object(N, 'inputs', return_value=files[:-1]):
            self.assertNotEqual(N.digest(), expected)

    def test_both_targets_read_ordinary_delay_and_case_insensitive_owned_imports(self):
        for target in ('windows/amd64', 'windows/arm64'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                engine = image(target, ('KERNEL32.dll', 'LIBCRONET.dll'), ('WS2_32.DLL',))
                cronet = image(target, ('NTDLL.dll',), ('api-ms-win-core-winrt-l1-1-0.dll',))
                write_bundle(root, target, engine=engine, cronet=cronet)
                expected = {'kernel32.dll', 'libcronet.dll', 'ws2_32.dll'}
                self.assertEqual(N.pe_dependencies(engine, target), expected)
                imports = N.check_windows_dependencies(root, target)
                self.assertEqual(imports[N.binary_name(target)], expected)
                self.assertEqual(imports['libcronet.dll'], {'ntdll.dll', 'api-ms-win-core-winrt-l1-1-0.dll'})

    def test_actual_metadata_boundary_rejects_engine_and_cronet_compiler_dependencies(self):
        for target in ('windows/amd64', 'windows/arm64'):
            for payload in ('engine', 'cronet'):
                for delay in (False, True):
                    with self.subTest(target=target, payload=payload, delay=delay), tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp)
                        foreign = image(target, ('KERNEL32.dll',) if delay else ('libunwind.dll',),
                                        ('libunwind.dll',) if delay else ())
                        write_bundle(root, target, **{payload: foreign})
                        with patch.object(N, 'run', return_value=metadata(target)) as command:
                            with self.assertRaisesRegex(ValueError, 'imports an unowned DLL: libunwind.dll'):
                                N.check_target(root/N.binary_name(target), target, {'PATH': '/without-llvm'})
                        self.assertEqual(command.call_args.args[0], ['go', 'version', '-m', root/N.binary_name(target)])

    def test_staging_unowned_dll_never_turns_it_into_an_owned_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = 'windows/amd64'
            write_bundle(root, target, engine=image(target, ('libunwind.dll',)))
            (root/'libunwind.dll').write_bytes(image(target))
            with self.assertRaisesRegex(ValueError, 'imports an unowned DLL: libunwind.dll'):
                N.check_windows_dependencies(root, target)

    def test_cronet_is_required_and_inspected_even_without_a_static_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = 'windows/amd64'
            (root/N.binary_name(target)).write_bytes(image(target))
            with self.assertRaisesRegex(ValueError, 'Unsafe or missing.*libcronet.dll'):
                N.check_windows_dependencies(root, target)
            (root/'libcronet.dll').write_bytes(image('windows/arm64'))
            with self.assertRaisesRegex(ValueError, 'target or section count differs'):
                N.check_windows_dependencies(root, target)

    def test_complete_receipt_reuse_still_requires_imports_without_foreign_toolchain(self):
        for target in ('windows/amd64', 'windows/arm64'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                policy = 'a'*64
                write_bundle(root, target)
                for name in N.LICENSES:
                    (root/name).write_text('owned fixture license\n')

                def seal(engine):
                    (root/N.binary_name(target)).write_bytes(engine+N.marker(policy).encode())
                    files = {name: N.payload((root/name).read_bytes()) for name in N.expected_names(target)}
                    receipt = {**N.receipt_fields(target, policy), **files[N.binary_name(target)], 'files': files}
                    (root/'NATIVE-RUNTIME.json').write_text(json.dumps(receipt))
                    return receipt

                expected = seal(image(target))

                def query(command, **kwargs):
                    self.assertEqual(command, ['go', 'version', '-m', root/N.binary_name(target)])
                    return metadata(target)

                with patch.dict(os.environ, {'PATH': '/without-compiler'}, clear=True), \
                     patch.object(N.shutil, 'which', return_value=None), patch.object(N, 'run', side_effect=query):
                    self.assertEqual(N.reuse(root, target, policy), expected)
                    seal(image(target, (), ()))
                    with self.assertRaisesRegex(ValueError, 'missing or stripped'):
                        N.reuse(root, target, policy)
                    seal(image(target, ('libunwind.dll',)))
                    with self.assertRaisesRegex(ValueError, 'imports an unowned DLL'):
                        N.reuse(root, target, policy)

    def test_malformed_headers_sections_and_dependency_tables_fail_closed(self):
        target = 'windows/amd64'
        original = image(target, ('KERNEL32.dll',), ('WS2_32.dll',))

        def change(offset, fmt, *values):
            raw = original.copy()
            struct.pack_into(fmt, raw, offset, *values)
            return raw

        # Name strings begin in the second section; delay descriptors start at
        # file offset HEADER+48 in this independent two-record fixture.
        variants = {
            'empty': b'', 'truncated header': original[:63],
            'missing DOS signature': b'ZZ'+original[2:],
            'outside PE pointer': change(0x3c, '<I', 0xfffffff0),
            'wrong target': change(PE+4, '<H', 0xaa64),
            'not executable': change(PE+22, '<H', 0),
            'too many sections': change(PE+6, '<H', 97),
            'short optional header': change(PE+20, '<H', 111),
            'PE32 instead of PE32+': change(OPTIONAL, '<H', 0x10b),
            'hidden delay directory': change(OPTIONAL+108, '<I', 13),
            'outside directory table': change(OPTIONAL+108, '<I', 17),
            'outside headers': change(OPTIONAL+60, '<I', len(original)+1),
            'outside image': change(OPTIONAL+56, '<I', 0x1000),
            'section outside file': change(SECTIONS+20, '<I', len(original)),
            'section inside headers': change(SECTIONS+20, '<I', 1),
            'overlapping raw sections': change(SECTIONS+40+20, '<I', HEADER),
            'overlapping virtual sections': change(SECTIONS+40+12, '<I', 0x1000),
            'missing directory RVA': change(OPTIONAL+120, '<I', 0),
            'missing directory size': change(OPTIONAL+124, '<I', 0),
            'unmapped directory': change(OPTIONAL+120, '<I', 0xfffffff0),
            'unbounded directory': change(OPTIONAL+124, '<I', 1024*1024+1),
            'unterminated table': change(OPTIONAL+124, '<I', 20),
            'outside name': change(HEADER+12, '<I', 0xfffffff0),
            'missing name': change(HEADER+12, '<I', 0),
            'legacy delay pointers': change(HEADER+48, '<I', 0),
            'reserved delay attributes': change(HEADER+48, '<I', 3),
            'stripped imports': image(target, (), ()),
            'too many imports': image(target, ('KERNEL32.dll',)*257),
        }
        for label, raw in variants.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                N.pe_dependencies(raw, target)

    def test_unterminated_unsafe_and_lookalike_dependency_names_are_rejected(self):
        target = 'windows/amd64'
        for name in ('../kernel32.dll', 'C:kernel32.dll', 'kernel32.dll/extra',
                     'kernel32.dll ', 'kernel32.dll.exe', 'KERNEL32', 'a'*256+'.dll'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                N.pe_dependencies(image(target, (name,)), target)
        raw = image(target)
        names_offset = struct.unpack_from('<I', raw, SECTIONS+40+20)[0]
        raw[names_offset:] = b'x'*(len(raw)-names_offset)
        with self.assertRaisesRegex(ValueError, 'unterminated'):
            N.pe_dependencies(raw, target)
        for name in ('libunwind.dll', 'vcruntime140.dll', 'api-ms-win-fake.dll', 'api-ms-win-core-l1-1-0-extra.dll'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_bundle(root, target, cronet=image(target, (name,)))
                with self.assertRaisesRegex(ValueError, 'imports an unowned DLL'):
                    N.check_windows_dependencies(root, target)

    def test_final_windows_go_link_selects_static_runtime_and_keeps_verified_flags(self):
        class CompilerBoundary(Exception):
            pass

        for target in ('windows/amd64', 'windows/arm64'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source = root/'core'
                (source/'cmd/sing-box').mkdir(parents=True)
                pq = root/'verified pq'
                dependencies = ['-loqs', '-ladvapi32', '-lunwind', '-lwindows', '-lkernel32']
                builds = []

                def run(command, *, env=None, **kwargs):
                    args = [str(value) for value in command]
                    if args == ['go', 'env', 'GOVERSION']:
                        return N.TOOLCHAIN
                    if args[:2] == ['go', 'build']:
                        builds.append((args, env.copy()))
                        raise CompilerBoundary()
                    if args[:2] == ['go', 'test']:
                        self.assertIn('^TestRouterVPNDesktopExternal', args)
                        self.assertIn('./cmd/sing-box', args)
                        return ''
                    self.assertIn(args, [['go', 'mod', 'tidy'], ['go', 'mod', 'verify']])
                    return ''

                def cronet(source, stage, target, env):
                    (stage/'libcronet.dll').write_bytes(image(target))

                with patch.dict(os.environ, {'PATH': '/fixture-tools', 'CGO_LDFLAGS': '-L/ambient -lunowned'}, clear=True), \
                     patch.object(N.shutil, 'which', return_value='/verified/mingw-clang'), \
                     patch.object(N, 'run', side_effect=run), patch.object(N, 'pristine'), \
                     patch.object(N.PQ, 'verify', return_value={'native_static_libs': dependencies}), \
                     patch.object(N.POLICY, 'prepare_native'), patch.object(N.PERFORMANCE, 'prepare'), \
                     patch.object(N.OPENVPN, 'prepare'), patch.object(N.BUFFERS, 'prepare'), \
                     patch.object(N.EXTERNAL, 'prepare') as external_prepare, \
                     patch.object(N.POLICY.AMNEZIA, 'verify'), patch.object(N, 'stage_cronet', side_effect=cronet):
                    with self.assertRaises(CompilerBoundary):
                        N.build(target, root/'output', source=source, xray=root/'xray', pq=pq)
                    external_prepare.assert_called_once_with(source.resolve())
                self.assertEqual(len(builds), 1)
                self.assertEqual(shlex.split(builds[0][1]['CGO_LDFLAGS']), ['-static', '-L'+str(pq), *dependencies])


if __name__ == '__main__':
    unittest.main(verbosity=2)
