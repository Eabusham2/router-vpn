#!/usr/bin/env python3
"""Exercise desktop Tor package boundaries and optionally the actual process.

The six-target metadata cases are independent object-format fixtures. Only
--package provides real native C/control evidence; CI requires it per target.
"""
from pathlib import Path
import argparse
import copy
import importlib.util
import json
import shutil
import struct
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('desktop_tor_metadata_fixture', ROOT / 'deploy/desktop_tor_test_fixture.py')
FIXTURE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(FIXTURE)
B, V = FIXTURE.BUILD, FIXTURE.V
CHECKS = 0


def check(condition, label):
    global CHECKS
    if not condition:
        raise AssertionError(label)
    CHECKS += 1


def reject(operation, label):
    global CHECKS
    try:
        operation()
    except (ValueError, OSError, KeyError):
        CHECKS += 1
        return
    raise AssertionError('Desktop Tor gate accepted ' + label)


def metadata_tests():
    with tempfile.TemporaryDirectory(prefix='desktop-tor-boundaries-') as temporary:
        root = Path(temporary).resolve()
        for target in V.TARGETS:
            directory = FIXTURE.write(root / target.replace('/', '-'), target)
            original = {p.name: p.read_bytes() for p in directory.iterdir()}
            record = V.verify(directory, target, source_root=ROOT)
            check(record['execution'] == V.execution(target), 'helper execution identity differs')
            mutations = [
                ('schema_version', True), ('runtime', 'stock-tor'), ('version', 'latest'),
                ('upstream_revision', '0' * 40), ('target', 'foreign/target'), ('executable_target', 'foreign/target'),
                ('execution', 'native' if target == 'windows/arm64' else 'emulated'),
                ('source_lock_sha256', '0' * 64), ('padding_lock_sha256', '0' * 64), ('padding_version', 2),
                ('build_inputs', {}), ('build_inputs_sha256', '0' * 64), ('static_dependencies', {}),
                ('process_source_sha256', {}), ('native_tests', {'passed': True}), ('offline_self_test', {}),
                ('files', {}), ('compiler', {'version': '', 'target': target}), ('executable_identity', {})]
            for key, value in mutations:
                altered = copy.deepcopy(record)
                altered[key] = value
                (directory / V.RECEIPT).write_text(json.dumps(altered))
                reject(lambda: V.verify(directory, target, source_root=ROOT), key)
            for key in record['offline_self_test']:
                altered = copy.deepcopy(record)
                altered['offline_self_test'][key] = 1 if record['offline_self_test'][key] is True else False
                (directory / V.RECEIPT).write_text(json.dumps(altered))
                reject(lambda: V.verify(directory, target), 'fabricated offline ' + key)
            (directory / V.RECEIPT).write_bytes(original[V.RECEIPT])
            for name in V.names(target) - {V.RECEIPT}:
                raw = bytearray(original[name]); raw[-1] ^= 1
                (directory / name).write_bytes(raw)
                reject(lambda: V.verify(directory, target), 'changed ' + name)
                (directory / name).write_bytes(original[name])
            # Rehash the corrupted executable and license records: format and
            # pinned-license admission must reject them independently of hashes.
            executable = V.binary_name(target)
            raw = bytearray(original[executable])
            if target.startswith('linux/'):
                struct.pack_into('<H', raw, 18, 183 if target.endswith('amd64') else 62)
            elif target.startswith('darwin/'):
                struct.pack_into('<I', raw, 4, 0x100000c if target.endswith('amd64') else 0x1000007)
            else:
                struct.pack_into('<H', raw, 0x84, 0xaa64)
            (directory / executable).write_bytes(raw)
            altered = copy.deepcopy(record)
            altered['files'][executable] = V.payload(raw)
            (directory / V.RECEIPT).write_text(json.dumps(altered))
            reject(lambda: V.verify(directory, target), 'rehash foreign executable')
            (directory / executable).write_bytes(original[executable])
            licenses = json.loads(original[V.LICENSES]); licenses['tor/LICENSE'] += 'changed'
            raw = json.dumps(licenses).encode()
            (directory / V.LICENSES).write_bytes(raw)
            altered = copy.deepcopy(record); altered['files'][V.LICENSES] = V.payload(raw)
            (directory / V.RECEIPT).write_text(json.dumps(altered))
            reject(lambda: V.verify(directory, target), 'rehash changed licenses')
            for name, raw in original.items():
                (directory / name).write_bytes(raw)
            changed_lock = json.loads(original[V.SOURCE])
            changed_lock['native_version'] = 'tor unpinned'
            raw = json.dumps(changed_lock).encode()
            (directory / V.SOURCE).write_bytes(raw)
            altered = copy.deepcopy(record); altered['files'][V.SOURCE] = V.payload(raw)
            (directory / V.RECEIPT).write_text(json.dumps(altered))
            reject(lambda: V.verify(directory, target), 'rehash unpinned source lock')
            for name, raw in original.items():
                (directory / name).write_bytes(raw)
            (directory / 'unowned.dll').write_bytes(b'unowned')
            reject(lambda: V.verify(directory, target), 'unowned side-loaded DLL')
            (directory / 'unowned.dll').unlink()
            (directory / V.RECEIPT).write_bytes(b'{"schema_version":1,' + original[V.RECEIPT][1:])
            reject(lambda: V.verify(directory, target), 'duplicate JSON')
            (directory / V.RECEIPT).write_bytes(original[V.RECEIPT])
            if hasattr(__import__('os'), 'symlink'):
                try:
                    (root / 'linked').symlink_to(directory, target_is_directory=True)
                except OSError:
                    pass  # Windows symlink privilege is independently gated.
                else:
                    reject(lambda: V.verify(root / 'linked', target), 'linked package ancestor')
                    (root / 'linked').unlink()
        check(V.executable_target('windows/arm64') == 'windows/amd64', 'ARM helper was falsely marked native')
        with patch.object(V, 'host_target', return_value='windows/arm64'), patch.object(V.platform, 'version', return_value='10.0.19045'):
            reject(lambda: V.require_host('windows/arm64'), 'Windows 10 ARM x64 helper')
        with patch.object(V, 'host_target', return_value='windows/arm64'), patch.object(V.platform, 'version', return_value='10.0.26100'):
            V.require_host('windows/arm64')
            check(True, 'Windows 11 ARM helper admission')
        with patch.object(V, 'host_target', return_value='linux/amd64'):
            reject(lambda: V.require_host('windows/amd64'), 'foreign native execution receipt')
        # Compile artifacts have no accepted offline receipt. A finalization
        # call must reject an unrelated file set before running either process.
        directory = root / 'linux-amd64'
        with patch.object(V, 'require_host'), patch.object(B.subprocess, 'run', side_effect=AssertionError('unverified process executed')):
            reject(lambda: B.finalize(directory, root / 'invalid-final', 'linux/amd64'), 'accepted package as compile evidence')
    print(str(CHECKS) + ' desktop Tor metadata/architecture/ownership checks passed', flush=True)


def actual_tests(package, target, within_native=False, unpatched=None):
    record = V.verify(package, target, source_root=ROOT, exact=not within_native)
    check(V.offline_self_test(package / V.binary_name(target), target) == V.offline_receipt(), 'actual offline owner/control proof')
    with tempfile.TemporaryDirectory(prefix='desktop-tor-relocation-') as temporary:
        moved = Path(temporary).resolve() / 'relocated app' / 'runtime' / 'native'
        moved.mkdir(parents=True)
        for name in V.names(target):
            shutil.copy2(package / name, moved / name)
        check(V.verify(moved, target, source_root=ROOT) == record, 'relocation changed receipt')
        check(V.offline_self_test(moved / V.binary_name(target), target) == V.offline_receipt(), 'actual relocated offline owner')
    if unpatched:
        reject(lambda: V.offline_self_test(unpatched, target), 'actual stock Tor without owned padding')
    print('PASS actual source-built Tor and relocated offline control ' + target, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path)
    parser.add_argument('--target', choices=V.TARGETS)
    parser.add_argument('--within-native', action='store_true')
    parser.add_argument('--unpatched-binary', type=Path)
    args = parser.parse_args()
    if bool(args.package) != bool(args.target):
        parser.error('--package and --target are required together')
    metadata_tests()
    if args.package:
        actual_tests(args.package, args.target, args.within_native, args.unpatched_binary)
