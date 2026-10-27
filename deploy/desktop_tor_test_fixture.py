"""Metadata-only Tor package fixture; never executable or network evidence.

Real C/control acceptance requires test_desktop_tor_package.py --package.
The artifact/installer boundary suites use these valid independent object
headers and exact license bytes so production validation remains enabled.
"""
from pathlib import Path
import importlib.util
import json
import struct

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('desktop_tor_fixture_builder', ROOT / 'deploy/build-desktop-tor.py')
BUILD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BUILD)
V = BUILD.VERIFY


def image(target):
    target = V.executable_target(target)
    if target.startswith('linux/'):
        raw = bytearray(64 + 3 * 56)
        raw[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
        struct.pack_into('<HHIQQQIHHHHHH', raw, 16, 2, 62 if target.endswith('amd64') else 183,
                         1, 0x400000, 64, 0, 0, 64, 56, 3, 0, 0, 0)
        for index, (kind, flags) in enumerate(((1, 5), (0x6474e552, 4), (0x6474e551, 6))):
            struct.pack_into('<IIQQQQQQ', raw, 64 + index * 56, kind, flags, 0, 0x400000, 0, len(raw), len(raw), 4096)
        return bytes(raw)
    if target.startswith('darwin/'):
        library = b'/usr/lib/libSystem.B.dylib\0'
        length = (24 + len(library) + 7) // 8 * 8
        raw = bytearray(32 + length)
        struct.pack_into('<8I', raw, 0, 0xfeedfacf, 0x1000007 if target.endswith('amd64') else 0x100000c,
                         3, 2, 1, length, 0x200000, 0)
        struct.pack_into('<6I', raw, 32, 0xc, length, 24, 0, 0, 0)
        raw[56:56 + len(library)] = library
        return bytes(raw)
    raw = bytearray(1024)
    raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 0x3c, 0x80)
    raw[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', raw, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x22)
    struct.pack_into('<H', raw, 0x98, 0x20b)
    struct.pack_into('<II', raw, 0x98 + 56, 0x2000, 512)
    struct.pack_into('<I', raw, 0x98 + 108, 16)
    struct.pack_into('<II', raw, 0x98 + 120, 0x1000, 40)
    raw[0x188:0x18e] = b'.idata'
    struct.pack_into('<IIII', raw, 0x188 + 8, 512, 0x1000, 512, 512)
    struct.pack_into('<IIIII', raw, 512, 0, 0, 0, 0x1040, 0)
    raw[576:589] = b'KERNEL32.dll\0'
    return bytes(raw)


def write(directory, target):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    raw = image(target)
    (directory / V.binary_name(target)).write_bytes(raw)
    (directory / V.SOURCE).write_bytes((ROOT / 'mobile/torpack/sources.json').read_bytes())
    (directory / V.PADDING).write_bytes((ROOT / 'mobile/tor/padding-source-lock.json').read_bytes())
    (directory / V.LICENSES).write_bytes((ROOT / 'deploy/testfixtures/desktop-tor-licenses.json').read_bytes())
    records, combined = BUILD.source_inputs()
    lock = BUILD.SERVER.source_lock()
    record = {'schema_version': 1, 'runtime': 'tor-routervpn', 'version': V.VERSION, 'upstream_revision': V.REVISION,
        'target': target, 'executable_target': V.executable_target(target), 'execution': V.execution(target),
        'source_lock_sha256': V.SOURCE_SHA256, 'padding_lock_sha256': V.PADDING_SHA256, 'padding_version': 1,
        'build_inputs': records, 'build_inputs_sha256': combined,
        'static_dependencies': {name: '1' * 64 for name in V.STATIC_LIBRARIES},
        'process_source_sha256': {name: item['original'] for name, item in lock['embedded_process_sha256'].items()},
        'compiler': {'version': 'metadata fixture only', 'target': V.executable_target(target)},
        'native_tests': {'passed': True, 'selectors': list(V.TEST_SELECTORS), 'executable_sha256': '2' * 64},
        'offline_self_test': V.offline_receipt(), 'executable_identity': V.executable_identity(raw, target),
        'files': {name: V.payload((directory / name).read_bytes()) for name in V.names(target) - {V.RECEIPT}}}
    (directory / V.RECEIPT).write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    V.verify(directory, target, source_root=ROOT, exact=False)
    return directory
