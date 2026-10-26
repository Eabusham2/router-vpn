#!/usr/bin/env python3
"""Build a test-only PQ peer with the real pinned Rust/C cryptographic owner.

Fresh disposable KEM keys, reference binaries, and their verified ABI remain
outside the delivered native bundle. The caller owns and removes that workspace
after the separately bounded desktop traffic gate has joined its child peers.
"""
import argparse
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILD = load('pq_reference_native', 'build-native-runtime.py')
TRAFFIC = load('pq_reference_traffic', 'test_server_pq_traffic.py')
SERVER = BUILD.POLICY.PQ
TAGS = 'with_quic,with_wireguard,with_gvisor,routervpn_native_pq,routervpn_pq_traffic_test'
COPIES = {**TRAFFIC.COPIES,
          'mobile/pq/desktop_reference_test.go.tmpl': 'protocol/routervpnpq/desktop_reference_test.go'}


def contained(core, relative):
    path = core/relative
    if path.is_symlink() or not path.resolve().is_relative_to(core):
        raise ValueError('PQ reference source escapes the captured core')
    return path


def verify_sources(core):
    if (core.is_symlink() or not core.is_dir() or
            subprocess.check_output(['git', '-C', str(core), 'rev-parse', 'HEAD'], text=True).strip() != BUILD.PIN or
            not (core/'go.mod').read_text().startswith('module github.com/sagernet/sing-box\n')):
        raise ValueError('PQ reference requires the exact prepared pinned core')
    sources = {**SERVER.COPIES,
               'mobile/pq/endpoint.go.tmpl': 'protocol/routervpnpq/endpoint.go',
               'mobile/pq/wireguard_protocol.go.tmpl': 'protocol/wireguard/routervpn_pq.go',
               'mobile/pq/wireguard_transport.go.tmpl': 'transport/wireguard/routervpn_pq.go',
               'mobile/amnezia/endpoint.go.tmpl': 'protocol/routervpnamnezia/endpoint.go',
               'mobile/amnezia/pq_reference_fixture.go.tmpl': 'protocol/routervpnamnezia/pq_reference_fixture.go'}
    for source, relative in sources.items():
        expected = (ROOT/source).read_bytes()
        if relative.endswith('.c'):
            expected = SERVER.C_TAG+expected
        path = contained(core, relative)
        if not path.is_file() or path.read_bytes() != expected:
            raise ValueError('PQ reference requires this exact shipping native factory and packet adapters')
    for source in sorted((ROOT/'internal/mobilepq').glob('*.go')):
        if source.name.endswith('_test.go'):
            continue
        expected = source.read_text()
        for package in BUILD.POLICY.AMNEZIA.POLICY_PACKAGES:
            expected = expected.replace('"router-vpn/internal/'+package+'"',
                                        '"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+package+'"')
        path = contained(core, 'experimental/libbox/routervpn/mobilepq/'+source.name)
        if not path.is_file() or path.read_text() != expected:
            raise ValueError('PQ reference shared protocol owner differs from this source')


@contextlib.contextmanager
def test_sources(core):
    pending = {}
    for source, relative in COPIES.items():
        path = contained(core, relative)
        data = (ROOT/source).read_bytes()
        if path.exists() and (not path.is_file() or path.read_bytes() != data):
            raise ValueError('PQ reference refuses a foreign existing traffic-test source')
        if not path.exists():
            pending[path] = data
    made = []
    try:
        for path, data in pending.items():
            with path.open('xb') as output:
                made.append(path)
                output.write(data)
        yield
    finally:
        for path in made:
            # Never erase a replacement owner's changed file during cleanup.
            if path.is_symlink() or not path.is_file() or path.read_bytes() != pending[path]:
                raise ValueError('PQ reference source owner changed before cleanup')
            path.unlink()


def key_files(keys):
    expected = {name+'.'+kind for name in ('client', 'server', 'other') for kind in ('secret', 'public')}
    if keys.is_symlink() or not keys.is_dir() or {path.name for path in keys.iterdir()} != expected:
        raise ValueError('PQ reference key generator did not create exactly three independent pairs')
    contents = {}
    for name in expected:
        path = keys/name
        if path.is_symlink() or not path.is_file() or not 32 <= path.stat().st_size <= 2*1024*1024:
            raise ValueError('PQ reference key is missing, linked, or unbounded')
        if os.name != 'nt' and path.stat().st_mode & 0o077:
            raise ValueError('PQ reference key permissions are not private')
        contents[name] = path.read_bytes()
    for kind in ('secret', 'public'):
        values = [contents[name+'.'+kind] for name in ('client', 'server', 'other')]
        if len({len(value) for value in values}) != 1 or len(set(values)) != 3 or any(not any(value) for value in values):
            raise ValueError('PQ reference keys are empty, reused, or inconsistent')
    return contents


def generate_keys(target, cache, keys):
    # The key generator itself also uses create_new. An old test's keys must not
    # silently satisfy a new traffic gate, even when the compiler cache is reused.
    private = keys.parent
    if keys.exists() or keys.is_symlink() or private.exists() or private.is_symlink():
        raise ValueError('PQ reference requires a new private key workspace')
    private.mkdir(mode=0o700)
    succeeded = False
    try:
        if target.startswith('windows/'):
            powershell = shutil.which('powershell.exe')
            if not powershell:
                raise ValueError('PQ test key generation requires Windows private ACL support')
            subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                            '-File', str(ROOT/'client/Protect-RouterVPN-Windows-PrivateRoot.ps1'),
                            '-Root', str(private)], check=True, timeout=30)
        env = BUILD.PQ.environment(target, cache)
        for compiler in ('rustc', 'cargo'):
            if not BUILD.PQ.run([compiler, '--version'], env=env).startswith(compiler+' '+BUILD.PQ.RUST+' '):
                raise ValueError('PQ reference requires the exact pinned Rust and Cargo compilers')
        before = BUILD.PQ.MOBILE.validate_lock()
        example = (ROOT/'mobile/rosenpass/examples/native_keys.rs').read_bytes()
        with BUILD.PQ.native_manifest(target, env) as (manifest, _):
            if (manifest.parent/'examples/native_keys.rs').read_bytes() != example:
                raise ValueError('PQ reference key generator differs from this exact source')
            # Windows uses the production guarded packet-only overlay and its
            # verified dependency lock; other targets use the locked manifest.
            BUILD.PQ.run(['cargo', 'build', '--locked', '--manifest-path', manifest, '--target',
                          BUILD.PQ.TARGETS[target], '--release', '--example', 'native_keys'], env=env)
            executable = Path(cache)/BUILD.PQ.TARGETS[target]/'release/examples'/('native_keys.exe' if target.startswith('windows/') else 'native_keys')
            if executable.is_symlink() or not executable.is_file():
                raise ValueError('Pinned key generator executable is missing')
            subprocess.run([str(executable), str(keys)], env=env, check=True, timeout=120)
            original = key_files(keys)
            reused = subprocess.run([str(executable), str(keys)], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            if reused.returncode == 0 or key_files(keys) != original:
                raise ValueError('PQ reference key generator reused or changed an existing owner')
        if BUILD.PQ.MOBILE.validate_lock() != before or (ROOT/'mobile/rosenpass/examples/native_keys.rs').read_bytes() != example:
            raise ValueError('PQ reference key generation changed its captured source')
        key_files(keys)
        succeeded = True
    finally:
        if not succeeded:
            shutil.rmtree(private)


def build(core, pq, keys, output, target, cache, *, go='go', race=False):
    core, pq, keys, output, cache = (Path(path).absolute() for path in (core, pq, keys, output, cache))
    verify_sources(core)
    if output.exists() or output.is_symlink():
        raise ValueError('PQ reference executable output must be new')
    env = BUILD.environment(target, compiler=True)
    identity = subprocess.check_output([go, 'env', 'GOVERSION', 'GOHOSTOS', 'GOHOSTARCH'], env=env, text=True).splitlines()
    if identity != [BUILD.TOOLCHAIN, *target.split('/')]:
        raise ValueError('PQ reference requires the pinned Go compiler on the actual target host')
    if race and target == 'windows/arm64':
        raise ValueError('The pinned compiler does not provide Windows ARM64 race instrumentation')
    amnezia = BUILD.POLICY.AMNEZIA
    dependency = json.loads(subprocess.check_output(
        [go, 'list', '-m', '-json', amnezia.MODULE], cwd=core, env=env, text=True))
    if dependency.get('Version') != amnezia.VERSION or dependency.get('Sum') != amnezia.SUM or dependency.get('Replace'):
        raise ValueError('PQ reference requires the exact unmodified packet cryptographic dependency')
    receipt = BUILD.PQ.verify(pq, target)
    flags = shlex.split(env.get('CGO_LDFLAGS', '')) if target.startswith('darwin/') else []
    if target.startswith('windows/'):
        flags.append('-static')
    env['CGO_LDFLAGS'] = shlex.join([*flags, '-L'+str(pq), *receipt['native_static_libs']])
    env['ROUTERVPN_PQ_TEST_KEYS'] = str(keys)
    with test_sources(core):
        generate_keys(target, cache, keys)
        output.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([go, 'test', '-c', '-p=1', *(['-race'] if race else []), '-mod=readonly',
                        '-ldflags=-checklinkname=0', '-tags', TAGS, '-o', str(output), './protocol/routervpnpq'],
                       cwd=core, env=env, check=True, timeout=600)
        if BUILD.PQ.verify(pq, target) != receipt:
            raise ValueError('PQ reference library receipt changed during compilation')
        # This executes the real ABI, wrong-peer rejection, independent-owner
        # close/rekey, and the reference's bounded configuration parser.
        subprocess.run([str(output), '-test.run', '^Test(RealPinnedFactory|RealFactory|DesktopPQReferenceRejects)',
                        '-test.count=1', '-test.timeout=60s'], cwd=ROOT, env=env, check=True, timeout=90)
    print('Built isolated PQ reference with real pinned Rust/C factory and fresh disposable keys', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('core', 'pq', 'keys', 'output', 'cache'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--target', choices=BUILD.TARGETS, required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--race', action='store_true')
    args = parser.parse_args()
    build(args.core, args.pq, args.keys, args.output, args.target, args.cache, go=args.go, race=args.race)
