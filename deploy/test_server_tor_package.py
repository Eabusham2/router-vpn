#!/usr/bin/env python3
"""Verify an actual built standalone Tor and reject corrupted package owners.

No synthetic executable or simulated successful control exchange can satisfy
the positive gate. The native image build invokes this against its real output.
"""
from pathlib import Path
import argparse
import importlib.util
import json
import shutil
import struct
import tempfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFY = load('test_owned_server_tor_package', ROOT / 'server/scripts/server_tor_package.py')
BUILD = load('test_owned_server_tor_builder', ROOT / 'deploy/build-server-tor.py')
CHECKS = 0


def passed():
    global CHECKS
    CHECKS += 1


def reject(call, label, witness=None):
    try:
        call()
    except (ValueError, OSError) as error:
        if witness is not None and witness not in str(error):
            raise AssertionError(label + ' failed outside its intended guard: ' + str(error)) from error
        passed()
        return
    raise AssertionError('Unsafe standalone Tor package was accepted: ' + label)


def rewrite_receipt(prefix, mutate):
    path = prefix / VERIFY.PACKAGE / 'BUILD.json'
    value = json.loads(path.read_bytes())
    mutate(value)
    path.write_text(json.dumps(value, sort_keys=True) + '\n')


def refresh_hashes(prefix):
    """Re-sign a mutation's plain hashes; the semantic checks must still reject it."""
    path = prefix / VERIFY.PACKAGE / 'BUILD.json'
    value = json.loads(path.read_bytes())
    for name in value['files']:
        file = prefix / name
        if file.is_file():
            value['files'][name] = VERIFY.digest(file.read_bytes())
    executable = value['executable']
    binary = prefix / VERIFY.EXECUTABLE
    executable.update(sha256=VERIFY.digest(binary.read_bytes()), size=binary.stat().st_size)
    path.write_text(json.dumps(value, sort_keys=True) + '\n')
    sums = ''.join(checksum + '  ' + name + '\n' for name, checksum in sorted(value['files'].items()))
    (prefix / VERIFY.PACKAGE / 'SHA256SUMS').write_text(sums)


def refresh_inputs(value):
    combined = b''.join(name.encode() + b'\0' + checksum.encode() + b'\0'
                        for name, checksum in sorted(value['build_inputs'].items()))
    value['build_inputs_sha256'] = VERIFY.digest(combined)


def package_checks(prefix, target, source_root, temporary):
    original = VERIFY.verify(prefix, target, source_root)
    assert VERIFY.offline_self_test(prefix / VERIFY.EXECUTABLE, target) == VERIFY.offline_receipt()
    assert VERIFY.verify(prefix, target, source_root) == original
    passed()

    def negative(label, mutate, witness=None, rehash=False):
        with tempfile.TemporaryDirectory(prefix='package-negative-', dir=temporary) as directory:
            output = Path(directory)
            (output / 'bin').mkdir()
            shutil.copy2(prefix / VERIFY.EXECUTABLE, output / VERIFY.EXECUTABLE)
            shutil.copytree(prefix / VERIFY.PACKAGE, output / VERIFY.PACKAGE)
            mutate(output)
            if rehash:
                refresh_hashes(output)
            reject(lambda: VERIFY.verify(output, target, source_root), label, witness)

    def receipt(label, mutate, witness):
        negative(label, lambda out: rewrite_receipt(out, mutate), witness)

    for field, replacement in [('kind', 'embedded-mobile-tor'), ('schema', 2), ('schema', True),
                                ('platform', 'linux/arm64' if target.endswith('amd64') else 'linux/amd64'),
                                ('native_version', 'tor unpinned'), ('embedded_process_patches', True),
                                ('source_lock_sha256', '0' * 64), ('dependency_linkage', 'dynamic')]:
        receipt(field, lambda value, key=field, data=replacement: value.update({key: data}),
                'source or platform identity changed')
    receipt('missing original process identity', lambda value: value['process_source_sha256'].clear(),
            'source or platform identity changed')
    for field in ('static_dependencies', 'offline_self_test', 'build_inputs'):
        receipt('missing ' + field, lambda value, key=field: value.pop(key), 'receipt is incomplete')
    receipt('foreign static dependency', lambda value: value['static_dependencies'].update({'libforeign.a': '0' * 64}),
            'static dependency receipt is incomplete')
    receipt('invalid dependency hash', lambda value: value['static_dependencies'].update({'libcrypto.a': 1}),
            'static dependency receipt is incomplete')
    for replacement in (False, 1, 'true'):
        receipt('fabricated SAFECOOKIE proof', lambda value, data=replacement: value['offline_self_test'].update(safecookie=data),
                'offline control receipt is incomplete')
    receipt('fabricated network proof', lambda value: value['offline_self_test'].update(scope='public-tor-circuit'),
            'offline control receipt is incomplete')
    for replacement in (None, {}, {'version': 1}, {'version': True}):
        receipt('missing native padding capability', lambda value, data=replacement: value.update(padding_extension=data),
                'outgoing padding receipt is incomplete')
    for replacement in (False, 1, 'true'):
        receipt('fabricated native cell tests', lambda value, data=replacement: value.update(padding_native_tests=data),
                'outgoing padding receipt is incomplete')
        receipt('fabricated native capability proof', lambda value, data=replacement: value['offline_self_test'].update(owned_padding_capability=data),
                'offline control receipt is incomplete')
    receipt('changed outgoing scope', lambda value: value['padding_extension'].update(direction='bidirectional'),
            'outgoing padding receipt is incomplete')

    def unrelated_input(value):
        value['build_inputs'] = {'foreign/build.py': '0' * 64}
        refresh_inputs(value)
    receipt('self-consistent unrelated source', unrelated_input, 'build input receipt is incomplete')

    def forged_input(value):
        value['build_inputs']['deploy/build-server-tor.py'] = '0' * 64
        refresh_inputs(value)
    receipt('self-consistent stale builder', forged_input, 'build source changed')
    receipt('changed executable identity', lambda value: value['executable'].update(sha256='0' * 64),
            'executable or package bytes changed')
    negative('modified binary', lambda out: (out / VERIFY.EXECUTABLE).write_bytes(b'not Tor'),
             'exact little-endian ELF64 target')
    negative('nonexecutable binary', lambda out: (out / VERIFY.EXECUTABLE).chmod(0o644), 'binary is not executable')
    negative('writable binary', lambda out: (out / VERIFY.EXECUTABLE).chmod(0o777), 'bounded and privately writable')
    negative('writable package directory', lambda out: (out / VERIFY.PACKAGE).chmod(0o777), 'directory is not privately writable')
    negative('changed license', lambda out: next((out / VERIFY.PACKAGE / 'licenses').iterdir()).write_bytes(b'foreign license'),
             'dependency license changed', rehash=True)
    negative('unowned receipt-directory file', lambda out: (out / VERIFY.PACKAGE / 'foreign').write_text('unowned'),
             'unexpected file')
    negative('changed checksum list', lambda out: (out / VERIFY.PACKAGE / 'SHA256SUMS').write_text(''), 'checksum list changed')
    negative('modified packaged verifier', lambda out: (out / VERIFY.PACKAGE / 'verify.py').write_text('print("forged verifier")\n'),
             'captured build input', rehash=True)
    negative('modified source lock', lambda out: (out / VERIFY.PACKAGE / 'sources.json').write_text('{}'),
             'not the pinned product lock', rehash=True)

    def duplicate_field(out):
        path = out / VERIFY.PACKAGE / 'BUILD.json'
        path.write_text('{"schema":1,' + path.read_text()[1:])
    negative('duplicate receipt JSON', duplicate_field, 'Duplicate Tor package JSON field')

    def linked_binary(out):
        owned = out / VERIFY.EXECUTABLE
        real = out / 'real-tor'
        owned.rename(real)
        owned.symlink_to(real)
    negative('linked executable', linked_binary)

    def linked_parent(out):
        owned = out / VERIFY.PACKAGE / 'licenses'
        real = out / 'real-licenses'
        owned.rename(real)
        owned.symlink_to(real, target_is_directory=True)
    negative('linked license parent', linked_parent)

    def elf_mutation(out, mutate):
        binary = out / VERIFY.EXECUTABLE
        content = bytearray(binary.read_bytes())
        mutate(content)
        binary.write_bytes(content)

    negative('self-consistent foreign architecture', lambda out: elf_mutation(out, lambda value:
             struct.pack_into('<H', value, 18, 183 if target.endswith('amd64') else 62)),
             'architecture mismatch', rehash=True)

    def change_program(value, segment, flags=None):
        offset = struct.unpack_from('<Q', value, 32)[0]
        size, count = struct.unpack_from('<HH', value, 54)
        for index in range(count):
            current = offset + size * index
            kind = struct.unpack_from('<I', value, current)[0]
            if kind == 1:
                struct.pack_into('<I', value, current, segment)
                if flags is not None:
                    struct.pack_into('<I', value, current + 4, flags)
                return
        raise AssertionError('Real Tor binary did not contain a load segment')
    negative('self-consistent interpreter', lambda out: elf_mutation(out, lambda value: change_program(value, 3)),
             'system ELF interpreter', rehash=True)
    negative('self-consistent writable executable memory', lambda out: elf_mutation(out, lambda value: change_program(value, 1, 7)),
             'writable executable segment', rehash=True)
    # Source verification is an explicit build gate; the installed image does
    # not carry a writable checkout or fetch source during runtime admission.
    source = temporary / 'source'
    for name in original['build_inputs']:
        destination = source / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_root / name, destination)
    (source / 'deploy/build-server-tor.py').write_text('changed source\n')
    reject(lambda: VERIFY.verify(prefix, target, source), 'changed source checkout', 'build source changed')


def builder_admission(temporary):
    with mock.patch.object(BUILD.ARCHIVES, 'fetch', side_effect=AssertionError('invalid build reached source fetch')):
        for jobs in (0, 17):
            reject(lambda: BUILD.build(temporary / 'out', temporary / 'work', temporary / 'cache',
                                      BUILD.VERIFY.native_platform(), jobs), 'unbounded build jobs', 'between 1 and 16')
        target = 'linux/arm64' if BUILD.VERIFY.native_platform() == 'linux/amd64' else 'linux/amd64'
        reject(lambda: BUILD.build(temporary / 'out', temporary / 'work', temporary / 'cache', target, 2),
               'cross-architecture build', 'actual target architecture')
        reject(lambda: BUILD.build(temporary / 'same', temporary / 'same', temporary / 'cache',
                                  BUILD.VERIFY.native_platform(), 2), 'overlapping output and work', 'must be separate')
        occupied = temporary / 'occupied'
        occupied.mkdir()
        sentinel = occupied / 'unrelated.txt'
        sentinel.write_text('preserve this file')
        reject(lambda: BUILD.empty_directory(occupied, 'Output'), 'nonempty output', 'new or empty')
        assert sentinel.read_text() == 'preserve this file'
        linked = temporary / 'linked'
        linked.symlink_to(occupied, target_is_directory=True)
        reject(lambda: BUILD.empty_directory(linked / 'new-output', 'Output'), 'linked output ancestor', 'must not traverse')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--platform', choices=tuple(VERIFY.TARGETS), required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='server-tor-package-') as directory:
        temporary = Path(directory)
        package_checks(args.prefix.absolute(), args.platform, args.source_root.absolute(), temporary)
        builder_admission(temporary)
    print('PASS real standalone Tor package/control and rejection checks:', CHECKS, flush=True)


if __name__ == '__main__':
    main()
