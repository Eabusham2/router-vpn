#!/usr/bin/env python3
"""Build the exact socket-free Rosenpass C ABI for a desktop native engine.

This produces a link input, never a VPN daemon. The application and native
endpoint retain socket ownership; the protocol ABI accepts only captured keys
and bounded packets. Cross builds require the actual target C toolchain.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import contextlib
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('desktop_mobile_pq', ROOT/'deploy/build-mobile-pq.py')
MOBILE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MOBILE)
spec = importlib.util.spec_from_file_location('desktop_packet_pq', ROOT/'deploy/prepare-desktop-rosenpass.py')
PACKET = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PACKET)
RUST = MOBILE.RUST
REVISION = '00569eb273016a10d2e75e5142236f06f7c3d4b3'
TARGETS = {
    'linux/amd64': 'x86_64-unknown-linux-gnu',
    'linux/arm64': 'aarch64-unknown-linux-gnu',
    'darwin/amd64': 'x86_64-apple-darwin',
    'darwin/arm64': 'aarch64-apple-darwin',
    'windows/amd64': 'x86_64-pc-windows-gnullvm',
    'windows/arm64': 'aarch64-pc-windows-gnullvm',
}
MAX_LIBRARY = 384 * 1024 * 1024


def run(command, *, env=None, capture=True):
    result = subprocess.run([str(arg) for arg in command], env=env,
                            text=True, stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.STDOUT if capture else None, timeout=1800)
    if result.returncode:
        if result.stdout:
            print(result.stdout[-24000:], flush=True)
        result.check_returncode()
    return result.stdout or ''


def digest():
    value = hashlib.sha256()
    for path in (Path(__file__).resolve(), ROOT/'deploy/build-mobile-pq.py', ROOT/'deploy/prepare-desktop-rosenpass.py',
                 *sorted((ROOT/'mobile/rosenpass').glob('Cargo.*')),
                 *sorted((ROOT/'mobile/rosenpass').glob('*.h')),
                 *sorted((ROOT/'mobile/rosenpass').glob('*.c')),
                 *sorted((ROOT/'mobile/rosenpass/src').rglob('*.rs'))):
        value.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+path.read_bytes())
    return value.hexdigest()


def regular(path, maximum):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError('Invalid desktop PQ input: '+str(path))
    return path.read_bytes()


def link_flags(output):
    matches = re.findall(r'^note: native-static-libs: (.+)$', output, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError('Rust did not report one exact native static dependency set')
    values = matches[0].split()
    if not values or len(values) > 80 or any(not re.fullmatch(r'-l[a-zA-Z0-9_+.]+', value) for value in values):
        raise ValueError('Unexpected native dependency flags from the pinned Rust compiler')
    return values


def verify(directory, target):
    if target not in TARGETS or directory.is_symlink() or not directory.is_dir():
        raise ValueError('Invalid desktop PQ target or directory')
    raw = regular(directory/'libroutervpn_rosenpass.a', MAX_LIBRARY)
    receipt = json.loads(regular(directory/'DESKTOP-PQ.json', 16384))
    required = {'schema_version': 1, 'abi': 1, 'target': target, 'rust_target': TARGETS[target],
                'rust_toolchain': RUST, 'rosenpass_revision': REVISION,
                'source_sha256': digest(), 'cargo_lock_sha256': MOBILE.validate_lock(),
                'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    flags = receipt.get('native_static_libs')
    if not isinstance(flags, list) or link_flags('note: native-static-libs: '+' '.join(flags)) != flags:
        raise ValueError('Invalid desktop PQ native dependency receipt')
    names = {'libroutervpn_rosenpass.a', 'DESKTOP-PQ.json'}
    if target.startswith('windows/'):
        imported = regular(directory/'libwindows.a', 32 << 20)
        required.update(windows_import_size=len(imported), windows_import_sha256=hashlib.sha256(imported).hexdigest())
        names.add('libwindows.a')
    if receipt != {**required, 'native_static_libs': flags}:
        raise ValueError('Desktop PQ archive differs from its exact source/target receipt')
    if set(path.name for path in directory.iterdir()) != names:
        raise ValueError('Unexpected desktop PQ bundle contents')
    return receipt


def environment(target, cache):
    if target not in TARGETS:
        raise ValueError('Unsupported desktop PQ architecture')
    env = MOBILE.base_env(cache)
    env.update(CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_DEV_DEBUG='0',
               CARGO_PROFILE_TEST_DEBUG='0')
    triple = TARGETS[target]
    if target.startswith('windows/'):
        prefix = 'x86_64' if target.endswith('/amd64') else 'aarch64'
        cc = shutil.which(prefix+'-w64-mingw32-clang')
        ar = shutil.which('llvm-ar')
        if not cc or not ar:
            raise ValueError('Windows native PQ requires the pinned LLVM-MinGW toolchain')
        env.update(CC=cc, AR=ar, CMAKE_SYSTEM_NAME='Windows',
                   BINDGEN_EXTRA_CLANG_ARGS='--target='+prefix+'-w64-windows-gnu')
        env['CC_'+triple.replace('-', '_')] = cc
        env['AR_'+triple.replace('-', '_')] = ar
        env['CARGO_TARGET_'+triple.replace('-', '_').upper()+'_LINKER'] = cc
    return env


def locked_metadata(env):
    return json.loads(run(['cargo', 'metadata', '--locked', '--format-version=1',
                           '--manifest-path', ROOT/'mobile/rosenpass/Cargo.toml'], env=env))


def windows_import(target, metadata):
    name = 'windows_'+('x86_64' if target.endswith('/amd64') else 'aarch64')+'_gnullvm'
    entries = [item for item in metadata['packages'] if item['name'] == name and item['version'] == '0.42.2']
    if len(entries) != 1 or not entries[0].get('source', '').startswith('registry+'):
        raise ValueError('Windows import archive does not have its exact locked provenance')
    package = Path(entries[0]['manifest_path']).parent
    lock = tomllib.loads((ROOT/'mobile/rosenpass/Cargo.lock').read_text())
    pins = [p for p in lock['package'] if p['name'] == name and p['version'] == '0.42.2']
    if len(pins) != 1:
        raise ValueError('Windows import archive version is ambiguous')
    archive = package.parents[2]/'cache'/package.parent.name/(package.name+'.crate')
    raw = regular(archive, 32 << 20)
    if hashlib.sha256(raw).hexdigest() != pins[0]['checksum']:
        raise ValueError('Windows import crate checksum differs from Cargo.lock')
    with tarfile.open(archive, 'r:gz') as tar:
        member = tar.getmember(package.name+'/lib/libwindows.a')
        if not member.isfile() or not 0 < member.size <= 32 << 20:
            raise ValueError('Invalid pinned Windows import archive member')
        return tar.extractfile(member).read()


@contextlib.contextmanager
def native_manifest(target, env):
    if not target.startswith('windows/'):
        yield ROOT/'mobile/rosenpass/Cargo.toml', None
        return
    metadata = locked_metadata(env)
    entries = [item for item in metadata['packages'] if item['name'] == 'rosenpass'
               and item.get('source', '').endswith('#'+REVISION)]
    if len(entries) != 1:
        raise ValueError('Pinned packet protocol source is ambiguous')
    source = Path(entries[0]['manifest_path']).parent.parent
    with tempfile.TemporaryDirectory(prefix='routervpn-packet-protocol-') as temp:
        manifest = PACKET.prepare(source, Path(temp)/'packet')
        before = (ROOT/'mobile/rosenpass/Cargo.lock').read_bytes()
        run(['cargo', 'metadata', '--offline', '--format-version=1', '--manifest-path', manifest], env=env)
        frozen = manifest.with_name('Cargo.lock').read_bytes()
        PACKET.verify_lock(before, frozen)
        yield manifest, windows_import(target, metadata)
        if manifest.with_name('Cargo.lock').read_bytes() != frozen:
            raise ValueError('Desktop compilation modified the verified portable dependency lock')


def build(target, output, cache):
    if target not in TARGETS:
        raise ValueError('Unsupported desktop PQ target')
    output = Path(output).absolute()
    if output.is_symlink():
        raise ValueError('Refusing a linked desktop PQ output')
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and any(output.iterdir()):
        verify(output, target)
        return output
    env = environment(target, cache)
    if not run(['rustc', '--version'], env=env).startswith('rustc '+RUST+' '):
        raise ValueError('Desktop PQ requires the exact Rust '+RUST+' compiler')
    if not run(['cargo', '--version'], env=env).startswith('cargo '+RUST+' '):
        raise ValueError('Desktop PQ requires the matching pinned Cargo compiler')
    lock = MOBILE.validate_lock()
    print('Building actual pinned Rosenpass ABI for '+target, flush=True)
    with native_manifest(target, env) as (manifest, imported):
        command = ['cargo', 'rustc', '--locked', '--manifest-path', manifest, '--target', TARGETS[target],
                   '--release', '--lib', '--', '--print', 'native-static-libs']
        result = run(command, env=env)
    flags = link_flags(result)
    if MOBILE.validate_lock() != lock:
        raise ValueError('Desktop PQ build changed the pinned dependency lock')
    library = Path(cache)/TARGETS[target]/'release/libroutervpn_rosenpass.a'
    raw = regular(library, MAX_LIBRARY)
    with tempfile.TemporaryDirectory(prefix='.desktop-pq-', dir=output.parent) as temp:
        stage = Path(temp)/'bundle'
        stage.mkdir()
        (stage/library.name).write_bytes(raw)
        receipt = {'schema_version': 1, 'abi': 1, 'target': target, 'rust_target': TARGETS[target],
                   'rust_toolchain': RUST, 'rosenpass_revision': REVISION,
                   'source_sha256': digest(), 'cargo_lock_sha256': lock,
                   'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'native_static_libs': flags}
        if imported is not None:
            (stage/'libwindows.a').write_bytes(imported)
            receipt.update(windows_import_size=len(imported), windows_import_sha256=hashlib.sha256(imported).hexdigest())
        (stage/'DESKTOP-PQ.json').write_text(json.dumps(receipt, sort_keys=True, indent=2)+'\n')
        verify(stage, target)
        if output.exists():
            output.rmdir()
        os.replace(stage, output)
    print('Built exact desktop PQ ABI '+target, flush=True)
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', choices=TARGETS)
    parser.add_argument('output', type=Path)
    parser.add_argument('--cache', type=Path, required=True)
    args = parser.parse_args()
    build(args.target, args.output, args.cache)
