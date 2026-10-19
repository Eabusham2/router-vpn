#!/usr/bin/env python3
"""Build and verify the pinned C Tor host on Linux/macOS.

This is a native lifetime/control integration gate, not a mobile feature switch.
It archives committed source from the exact pinned checkout; local checkout
edits are never imported. Native mobile packaging and protected PT ownership
must be integrated before Android/iOS can advertise Tor capability.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import resource
import shlex
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'mobile/tor'
TOR_COMMIT = '4a522a3ca491c6c04d4a44cb006b92101c42efc1'
TOR_REPOSITORY = 'https://github.com/bitmold/tor.git'
WORKQUEUE_ORIGINAL = 'e005bd4e9acdcc80b8c0bd260f4b6412a1327424101005c0fa6a989b54600931'
WORKQUEUE_PATCHED = '030f0a8a38cfab563e2854cef8dfa97c47d3ebdc1ba2b7302f1f2ad936a0ee95'
CONFIGURE = [
    '--enable-pic', '--disable-jni', '--disable-module-relay',
    '--disable-module-dirauth', '--disable-module-pow', '--disable-asciidoc',
    '--disable-manpage', '--disable-html-manual', '--disable-system-torrc',
    '--disable-unittests', '--disable-systemd', '--disable-lzma', '--disable-zstd',
    '--disable-tool-name-check',
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, directory, env, log, timeout=600):
    with log.open('w') as output:
        result = subprocess.run(command, cwd=directory, env=env, stdout=output,
                                stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise RuntimeError(log.name + ':\n' + log.read_text(errors='replace')[-5000:])


def patch_workqueue(source):
    file = source / 'src/lib/evloop/workqueue.c'
    if file.is_symlink() or sha(file) != WORKQUEUE_ORIGINAL:
        raise ValueError('Pinned Tor worker lifecycle source drifted')
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                    str(SOURCE / 'workqueue-lifecycle.patch')], cwd=source, check=True)
    if sha(file) != WORKQUEUE_PATCHED:
        raise ValueError('Tor worker lifecycle correction digest mismatch')


def archive_source(checkout, output):
    head = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
    if head != TOR_COMMIT:
        raise ValueError('Expected the exact pinned Tor source checkout')
    archive = output / 'tor-source.tar'
    with archive.open('wb') as target:
        subprocess.run(['git', '-C', str(checkout), 'archive', '--format=tar', TOR_COMMIT],
                       stdout=target, check=True, timeout=60)
    source = output / 'source'
    source.mkdir()
    with tarfile.open(archive) as data:
        data.extractall(source, filter='data')
    if sha(source / 'src/lib/evloop/workqueue.c') != WORKQUEUE_ORIGINAL:
        raise ValueError('Committed Tor source did not match the lifecycle pin')
    return source


def compile_fixture(source, output, compiler, flags, name, env):
    files = [SOURCE / 'unsafe_restart_negative.c'] if name == 'unsafe_restart_negative' else [
        SOURCE / 'routervpn_tor_host.c', SOURCE / 'native_host_test.c']
    binary = output / name
    command = compiler + ['-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread'] + flags
    command += ['-I' + str(source / 'src/feature/api')]
    command += [str(p) for p in files] + [str(source / 'libtor.a')]
    command += ['-levent', '-lssl', '-lcrypto', '-lz', '-lm', '-o', str(binary)]
    run(command, output, env, output / (name + '-compile.log'))
    return binary


def run_scenarios(binary, output, env):
    for scenario in ('resident', 'failed-start', 'premature-stop', 'fd-reuse'):
        with tempfile.TemporaryDirectory(prefix='tor-' + scenario + '-', dir=output) as directory:
            run([str(binary), directory, scenario], output, env, output / (scenario + '.log'), 65)
        print('PASS native Tor:', scenario)


def negative_control(source, output, compiler, flags, env):
    binary = compile_fixture(source, output, compiler, flags, 'unsafe_restart_negative', env)
    with tempfile.TemporaryDirectory(prefix='tor-upstream-negative-', dir=output) as directory:
        result = subprocess.run([str(binary), directory], env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=60)
    (output / 'upstream-negative.log').write_text(result.stdout)
    if result.returncode != -6 or 'compat_mutex_pthreads.c:120' not in result.stdout or 'Error destroying a mutex.' not in result.stdout:
        raise RuntimeError('Exact upstream worker mutex failure was not reproduced; inspect upstream-negative.log')
    print('PASS negative control: exact pinned upstream worker mutex failure reproduced')


def go_control(source, output, env, go):
    fixture = output / 'go-control'
    fixture.mkdir()
    (fixture / 'go.mod').write_text('module router-vpn/mobile/torfixture\n\ngo 1.23\n\n'
        'require router-vpn v0.0.0\nreplace router-vpn => ' + json.dumps(str(ROOT)) + '\n')
    for name in ('routervpn_tor_host.c', 'routervpn_tor_host.h'):
        shutil.copyfile(SOURCE / name, fixture / name)
    for source_name, target_name in (('native_control.go.tmpl', 'native_control.go'),
                                     ('native_control_test.go.tmpl', 'native_control_test.go')):
        shutil.copyfile(SOURCE / source_name, fixture / target_name)
    # No mobile runtime is created by this test-only Cgo module. The production
    # Control/Plan code is imported from this exact repository checkout.
    env = dict(env, CGO_ENABLED='1', CGO_CFLAGS='-I' + str(source / 'src/feature/api'),
               CGO_LDFLAGS='-L' + str(source) + ' -ltor -levent -lssl -lcrypto -lz -lm -pthread')
    run([go, 'test', '-race', '-count=1', '-timeout=30s', './...'], fixture, env,
        output / 'go-control.log', 180)
    print('PASS Go controller through the real pinned C Tor host')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='exact pinned Tor Git checkout')
    parser.add_argument('--output', type=Path, required=True, help='new or empty build directory')
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--go', default=os.environ.get('GO', 'go'))
    parser.add_argument('--sanitize', action='store_true', help='instrument the entire native library with ASan/UBSan/LSan')
    parser.add_argument('--negative-control', action='store_true', help='reproduce the unpatched mutex failure before applying the correction')
    args = parser.parse_args()
    if args.sanitize and args.negative_control:
        parser.error('Run the exact unsanitized negative control and the sanitizer gate as separate builds')
    if not 1 <= args.jobs <= 16:
        parser.error('--jobs must be between 1 and 16')
    output = args.output.absolute()
    if output.is_symlink() or (output.exists() and (not output.is_dir() or any(output.iterdir()))):
        parser.error('--output must be an empty unlinked directory')
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source = archive_source(args.source.resolve(), output)
    env = dict(os.environ)
    flags = ['-O1', '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if args.sanitize else ['-O2', '-g']
    env['CFLAGS'] = ' '.join(flags)
    env['LDFLAGS'] = '-fsanitize=address,undefined' if args.sanitize else ''
    if args.sanitize:
        env['ASAN_OPTIONS'] = 'halt_on_error=1:detect_leaks=1'
        env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    compiler = shlex.split(env.get('CC', 'cc'))
    if not args.negative_control:
        patch_workqueue(source)
    run(['./autogen.sh'], source, env, output / 'autogen.log')
    run(['./configure'] + CONFIGURE, source, env, output / 'configure.log')
    run(['make', '-j' + str(args.jobs), 'libtor.a'], source, env, output / 'make.log', 900)
    if args.negative_control:
        negative_control(source, output, compiler, flags, env)
        patch_workqueue(source)
        run(['make', '-j' + str(args.jobs), 'libtor.a'], source, env, output / 'make-patched.log', 900)
    binary = compile_fixture(source, output, compiler, flags, 'native_host_test', env)
    run_scenarios(binary, output, env)
    if not args.sanitize:
        go_control(source, output, env, args.go)
    shutil.copyfile(source / 'LICENSE', output / 'Tor-LICENSE.txt')
    inputs = [Path(__file__).resolve()] + [p for p in sorted(SOURCE.iterdir()) if p.is_file()]
    inputs += sorted((ROOT / 'internal/mobiletor').glob('*.go'))
    inputs += sorted((ROOT / 'internal/common').glob('*.go'))
    record = {
        'scope': 'offline-native-lifecycle-and-control', 'mobile_capability_enabled': False,
        'tor_repository': TOR_REPOSITORY, 'tor_commit': TOR_COMMIT,
        'workqueue_original_sha256': WORKQUEUE_ORIGINAL, 'workqueue_patched_sha256': WORKQUEUE_PATCHED,
        'sanitizers': ['address', 'undefined', 'leak'] if args.sanitize else [],
        'negative_control_verified': args.negative_control,
        'go_control_verified': not args.sanitize,
        'system_crypto_event_zlib': 'host-test dependencies; not mobile release provenance',
        'source_sha256': {str(p.relative_to(ROOT)):sha(p) for p in inputs},
    }
    (output / 'native-tor-evidence.json').write_text(json.dumps(record, indent=2) + '\n')
    print('PASS pinned native lifetime/control gate; mobile host and PT integration remain separate')

if __name__ == '__main__':
    main()
