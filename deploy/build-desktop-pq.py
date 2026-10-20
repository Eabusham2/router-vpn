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

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('desktop_mobile_pq', ROOT/'deploy/build-mobile-pq.py')
MOBILE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MOBILE)
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
    result = subprocess.run([str(arg) for arg in command], env=env, check=True,
                            text=True, stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.STDOUT if capture else None, timeout=1800)
    return result.stdout or ''


def digest():
    value = hashlib.sha256()
    for path in (Path(__file__).resolve(), ROOT/'deploy/build-mobile-pq.py',
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
    if receipt != {**required, 'native_static_libs': flags}:
        raise ValueError('Desktop PQ archive differs from its exact source/target receipt')
    if set(path.name for path in directory.iterdir()) != {'libroutervpn_rosenpass.a', 'DESKTOP-PQ.json'}:
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
    manifest = ROOT/'mobile/rosenpass/Cargo.toml'
    command = ['cargo', 'rustc', '--locked', '--manifest-path', manifest, '--target', TARGETS[target],
               '--release', '--lib', '--', '--print', 'native-static-libs']
    print('Building actual pinned Rosenpass ABI for '+target, flush=True)
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
