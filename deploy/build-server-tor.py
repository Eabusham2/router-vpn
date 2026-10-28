#!/usr/bin/env python3
"""Build the exact pinned standalone Tor executable for a native Linux image.

All crypto/event/compression inputs come from the existing four-source lock.
Only archive verification/extraction is reused from the mobile packager: the
standalone process receives none of its embedded-process or lifecycle patches.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'mobile/torpack/sources.json'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ARCHIVES = load('server_tor_pinned_archives', ROOT / 'deploy/build-mobile-tor-package.py')
VERIFY = load('server_tor_package', ROOT / 'server/scripts/server_tor_package.py')
PADDING = ARCHIVES.PADDING
CONFIGURE = [
    '--disable-module-relay', '--disable-module-dirauth', '--disable-module-pow',
    '--disable-asciidoc', '--disable-manpage', '--disable-html-manual',
    '--disable-system-torrc', '--disable-systemd',
    '--disable-lzma', '--disable-zstd', '--enable-static-tor',
]


def inputs():
    return [Path(__file__).resolve(), ROOT / 'deploy/build-mobile-tor-package.py',
            ROOT / 'server/scripts/server_tor_package.py', LOCK, *PADDING.inputs()]


def source_inputs():
    records = {}
    for path in inputs():
        if path.is_symlink() or not path.is_file():
            raise ValueError('Standalone Tor build input is missing or linked')
        records[str(path.relative_to(ROOT))] = ARCHIVES.sha(path)
    encoded = b''.join(name.encode() + b'\0' + checksum.encode() + b'\0' for name, checksum in sorted(records.items()))
    return records, hashlib.sha256(encoded).hexdigest()


def source_lock():
    if LOCK.is_symlink() or ARCHIVES.sha(LOCK) != VERIFY.SOURCE_LOCK_SHA256:
        raise ValueError('Standalone Tor requires the exact pinned source lock')
    value = VERIFY.json_object(LOCK.read_bytes())
    if value['schema'] != 1 or value['native_version'] != VERIFY.VERSION or set(value['sources']) != {'tor', 'openssl', 'libevent', 'zlib'}:
        raise ValueError('Standalone Tor dependency closure changed')
    return value


def unpatched_process(source, lock):
    actual = {}
    for name, record in lock['embedded_process_sha256'].items():
        path = source.joinpath(*VERIFY.relative(name))
        if path.is_symlink() or ARCHIVES.sha(path) != record['original']:
            raise ValueError('Standalone Tor must keep the original upstream process source: ' + name)
        actual[name] = record['original']
    return actual


def environment(work):
    env = dict(os.environ)
    for name in list(env):
        if name.startswith('CGO_') or name in ('CC', 'CXX', 'CPP', 'AR', 'AS', 'RANLIB', 'NM', 'LD',
                'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'LIBS', 'CPATH', 'C_INCLUDE_PATH',
                'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH', 'SDKROOT', 'CROSS_TOP', 'CROSS_SDK',
                'CROSS_SYSROOT', 'CROSS_COMPILE', 'CHOST', 'CMAKE_TOOLCHAIN_FILE',
                'PKG_CONFIG_PATH', 'PKG_CONFIG_LIBDIR', 'PKG_CONFIG_SYSROOT_DIR', 'CONFIG_SITE'):
            env.pop(name, None)
    compiler = shutil.which('cc')
    if not compiler:
        raise ValueError('A native C compiler is required for standalone Tor')
    env.update(CC=compiler, AR=shutil.which('ar') or 'ar', RANLIB=shutil.which('ranlib') or 'ranlib',
               LC_ALL='C', TZ='UTC', SOURCE_DATE_EPOCH=str(source_lock()['source_date_epoch']),
               CONFIG_SITE='', ZERO_AR_DATE='1')
    env['CFLAGS'] = '-O2 -fstack-protector-strong -ffunction-sections -fdata-sections ' + \
        '-ffile-prefix-map=' + str(work) + '=/routervpn/server-tor -fdebug-prefix-map=' + str(work) + '=/routervpn/server-tor'
    env['LDFLAGS'] = '-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,--gc-sections'
    return env


def run(args, *, directory, env, log, timeout=900):
    return ARCHIVES.run(args, directory=directory, env=env, log=log, timeout=timeout)


def compile_sources(work, source, target, jobs):
    prefix = work / 'dependencies'
    prefix.mkdir()
    env = environment(work)
    env['PKG_CONFIG_LIBDIR'] = str(prefix / 'lib/pkgconfig')
    env['CPPFLAGS'] = '-I' + shlex.quote(str(prefix / 'include'))
    env['LDFLAGS'] += ' -L' + shlex.quote(str(prefix / 'lib'))
    openssl = 'linux-x86_64' if target == 'linux/amd64' else 'linux-aarch64'
    run(['perl', 'Configure', openssl, 'no-shared', 'no-module', 'no-dso', 'no-tests', 'no-apps',
         '--prefix=' + str(prefix), '--libdir=lib', '--openssldir=/routervpn/no-system-openssl-config'],
        directory=source['openssl'], env=env, log=work / 'openssl-configure.log')
    run(['make', '-j' + str(jobs), 'build_libs'], directory=source['openssl'], env=env, log=work / 'openssl-build.log')
    run(['make', 'install_dev'], directory=source['openssl'], env=env, log=work / 'openssl-install.log')
    run(['./autogen.sh'], directory=source['libevent'], env=env, log=work / 'libevent-autogen.log')
    run(['./configure', '--prefix=' + str(prefix), '--libdir=' + str(prefix / 'lib'), '--disable-shared',
         '--enable-static', '--disable-openssl', '--disable-libevent-regress', '--disable-samples'],
        directory=source['libevent'], env=env, log=work / 'libevent-configure.log')
    run(['make', '-j' + str(jobs)], directory=source['libevent'], env=env, log=work / 'libevent-build.log')
    run(['make', 'install'], directory=source['libevent'], env=env, log=work / 'libevent-install.log')
    run(['./configure', '--static', '--prefix=' + str(prefix), '--libdir=' + str(prefix / 'lib')],
        directory=source['zlib'], env=env, log=work / 'zlib-configure.log')
    run(['make', '-j' + str(jobs), 'libz.a'], directory=source['zlib'], env=env, log=work / 'zlib-build.log')
    run(['make', 'install'], directory=source['zlib'], env=env, log=work / 'zlib-install.log')
    archives = {name: prefix / 'lib' / name for name in ('libssl.a', 'libcrypto.a', 'libevent.a', 'libz.a')}
    for path in archives.values():
        if path.is_symlink() or not path.is_file() or path.stat().st_size < 1024:
            raise ValueError('Standalone Tor is missing a pinned static dependency')
    run(['./autogen.sh'], directory=source['tor'], env=env, log=work / 'tor-autogen.log')
    run(['./configure', *CONFIGURE, '--with-openssl-dir=' + str(prefix), '--with-libevent-dir=' + str(prefix),
         '--with-zlib-dir=' + str(prefix)], directory=source['tor'], env=env, log=work / 'tor-configure.log')
    run(['make', '-j' + str(jobs), 'src/app/tor', 'src/test/test'], directory=source['tor'], env=env, log=work / 'tor-build.log')
    run(['./src/test/test', 'routervpn_padding/..', 'routervpn_lastrelay/..', 'relaycrypt/..', 'cellqueue/..'],
        directory=source['tor'], env=env, log=work / 'tor-padding-native-tests.log', timeout=30)
    PADDING.verify(source['tor'])
    binary = source['tor'] / 'src/app/tor'
    if binary.is_symlink() or not binary.is_file():
        raise ValueError('Standalone Tor build did not produce the owned executable')
    VERIFY.elf_identity(binary.read_bytes(), target)
    return binary, {name: ARCHIVES.sha(path) for name, path in archives.items()}, env


def package(binary, source, work, stage, target, lock, libraries, env):
    destination = stage / VERIFY.EXECUTABLE
    destination.parent.mkdir(parents=True)
    shutil.copyfile(binary, destination)
    destination.chmod(0o755)
    share = stage / VERIFY.PACKAGE
    (share / 'licenses').mkdir(parents=True)
    shutil.copyfile(LOCK, share / 'sources.json')
    shutil.copyfile(PADDING.LOCK, share / 'padding-source-lock.json')
    shutil.copyfile(ROOT / 'server/scripts/server_tor_package.py', share / 'verify.py')
    for name, record in lock['sources'].items():
        for relative in record['licenses']:
            shutil.copyfile(source[name] / relative, share / 'licenses' / (name + '-' + Path(relative).name))
    self_test = VERIFY.offline_self_test(destination, target)
    files = {name: ARCHIVES.sha(stage / name) for name in sorted(VERIFY.expected_files(lock))}
    source_records, source_digest = source_inputs()
    record = dict(schema=1, kind=VERIFY.KIND, platform=target, native_version=VERIFY.VERSION,
                  source_lock_sha256=VERIFY.SOURCE_LOCK_SHA256, build_inputs_sha256=source_digest,
                  build_inputs=source_records, sources=lock['sources'],
                  process_source_sha256=unpatched_process(source['tor'], lock),
                  padding_extension=PADDING.verify(source['tor']), padding_native_tests=True,
                  lastrelay_native_tests=True,
                  embedded_process_patches=False, dependency_linkage='static', static_dependencies=libraries,
                  executable=dict(path=VERIFY.EXECUTABLE, sha256=ARCHIVES.sha(destination),
                                  size=destination.stat().st_size, **VERIFY.elf_identity(destination.read_bytes(), target)),
                  files=files, offline_self_test=self_test,
                  toolchain=dict(compiler=subprocess.check_output([env['CC'], '--version'], text=True).splitlines()[0],
                                 compiler_target=subprocess.check_output([env['CC'], '-dumpmachine'], text=True).strip()))
    (share / 'SHA256SUMS').write_text(''.join(checksum + '  ' + name + '\n' for name, checksum in sorted(files.items())))
    (share / 'BUILD.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    VERIFY.verify(stage, target, ROOT)
    return record


def empty_directory(path, label):
    path = Path(os.path.abspath(path))
    for directory in (path, *path.parents):
        if directory.is_symlink() or directory.exists() and not directory.is_dir():
            raise ValueError(label + ' must not traverse linked or non-directory components')
    if path.exists() and any(path.iterdir()):
        raise ValueError(label + ' must be a new or empty unlinked directory')
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def build(output, work, cache, target, jobs):
    if VERIFY.native_platform() != target:
        raise ValueError('Standalone Tor builds must execute on the actual target architecture')
    if not 1 <= jobs <= 16:
        raise ValueError('Standalone Tor build jobs must be between 1 and 16')
    output = empty_directory(output, 'Output')
    work = empty_directory(work, 'Work directory')
    if output == work or output.is_relative_to(work) or work.is_relative_to(output):
        raise ValueError('Standalone Tor output and disposable work must be separate')
    lock = source_lock()
    initial_inputs = source_inputs()
    work.mkdir(mode=0o700, exist_ok=True)
    source = {}
    for name, entry in lock['sources'].items():
        archive = ARCHIVES.fetch(name, entry, Path(cache))
        source[name] = ARCHIVES.extract(archive, entry, work / name)
    unpatched_process(source['tor'], lock)
    PADDING.apply(source['tor'])
    binary, libraries, env = compile_sources(work, source, target, jobs)
    if source_inputs() != initial_inputs:
        raise ValueError('Standalone Tor build inputs changed during compilation')
    stage = Path(tempfile.mkdtemp(prefix=output.name + '-stage-', dir=output.parent))
    try:
        record = package(binary, source, work, stage, target, lock, libraries, env)
        if source_inputs() != initial_inputs:
            raise ValueError('Standalone Tor inputs changed before publication')
        if output.exists():
            output.rmdir()  # Only an empty, task-owned output may be replaced.
        stage.rename(output)
        stage = None
    finally:
        if stage is not None:
            shutil.rmtree(stage)
    print('PASS built pinned standalone Tor', target, record['executable']['sha256'])
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--platform', choices=tuple(VERIFY.TARGETS), required=True)
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    build(args.output, args.work, args.cache, args.platform, args.jobs)


if __name__ == '__main__':
    main()
