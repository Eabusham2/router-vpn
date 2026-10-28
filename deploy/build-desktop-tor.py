#!/usr/bin/env python3
"""Build and seal the desktop Tor process with the owned padding extension.

Windows compilation uses the already pinned LLVM-MinGW Linux toolchain. Its
artifact remains explicitly unaccepted until the actual Windows package host
executes the C tests and disabled-network control proof. No downloaded stock
Tor executable can satisfy this package contract.
"""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import platform
import shlex
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


VERIFY = load('desktop_tor_package', 'deploy/desktop_tor_package.py')
SERVER = load('desktop_tor_source_build', 'deploy/build-server-tor.py')
ARCHIVES, PADDING = SERVER.ARCHIVES, SERVER.PADDING
WINDOWS = load('desktop_tor_windows_compiler', 'deploy/install-desktop-windows-toolchain.py')
COMPILE = 'TOR-COMPILE.json'


def inputs():
    return [ROOT / name for name in sorted(VERIFY.BUILD_INPUTS)]


def source_inputs():
    records = {path.relative_to(ROOT).as_posix(): VERIFY.digest(VERIFY.read_regular(path, 64 << 20)) for path in inputs()}
    return records, VERIFY.combined(records)


def test_name(target):
    return 'tor-native-tests' + ('.exe' if target.startswith('windows/') else '')


def compile_names(target):
    return VERIFY.names(target) - {VERIFY.RECEIPT} | {COMPILE, test_name(target)}


def test_identity(raw, target):
    # Tor's Unix test program intentionally uses the host C loader. It is a
    # CI-only artifact, never shipped; the installed Tor retains the stricter
    # static-dependency verifier. The real native execution follows this gate.
    if target.startswith('linux/'):
        if (len(raw) < 64 or raw[:7] != b'\x7fELF\x02\x01\x01' or
                struct.unpack_from('<HH', raw, 16)[0] not in (2, 3) or
                struct.unpack_from('<HH', raw, 16)[1] != (62 if target.endswith('amd64') else 183)):
            raise ValueError('Desktop Tor C tests have a foreign executable architecture')
    else:
        VERIFY.executable_identity(raw, target)


def run(command, directory, env, log, timeout=900):
    return ARCHIVES.run(command, directory=directory, env=env, log=log, timeout=timeout)


def environment(work, target, compiler=None):
    env = SERVER.environment(work)
    if target.startswith('darwin/'):
        env['CC'] = subprocess.check_output(['xcrun', '--find', 'clang'], text=True).strip()
        env['AR'] = subprocess.check_output(['xcrun', '--find', 'ar'], text=True).strip()
        env['RANLIB'] = subprocess.check_output(['xcrun', '--find', 'ranlib'], text=True).strip()
        env['SDKROOT'] = subprocess.check_output(['xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True).strip()
        if not Path(env['SDKROOT']).is_dir():
            raise ValueError('Desktop Tor requires the selected Xcode SDK')
        arch = 'x86_64' if target.endswith('amd64') else 'arm64'
        flags = shlex.join(['-target', arch + '-apple-macosx13.0', '-isysroot', env['SDKROOT']])
        env['CFLAGS'] += ' ' + flags
        env['LDFLAGS'] = flags + ' -Wl,-dead_strip'
        env['MACOSX_DEPLOYMENT_TARGET'] = '13.0'
    elif target.startswith('windows/'):
        if platform.system() != 'Linux' or compiler is None:
            raise ValueError('Windows Tor compilation requires the pinned Linux LLVM-MinGW toolchain')
        compiler = Path(compiler).absolute()
        # This verifies the complete installed compiler inventory and pin.
        bin_directory = WINDOWS.install(compiler)
        env.update(CC=str(bin_directory / 'x86_64-w64-mingw32-clang'),
                   AR=str(bin_directory / 'x86_64-w64-mingw32-ar'),
                   RANLIB=str(bin_directory / 'x86_64-w64-mingw32-ranlib'),
                   RC=str(bin_directory / 'x86_64-w64-mingw32-windres'),
                   NM=str(bin_directory / 'x86_64-w64-mingw32-nm'),
                   WINDRES=str(bin_directory / 'x86_64-w64-mingw32-windres'))
        # pkg-config reads target metadata; it is a build-host tool, unlike
        # clang/ar. Select it explicitly so Autoconf does not flag its normal
        # unprefixed fallback as a foreign compiler. compile_sources confines
        # its search to the freshly built target dependencies below.
        pkg_config = shutil.which('pkg-config')
        if not pkg_config:
            raise ValueError('Windows Tor compilation requires a host pkg-config metadata reader')
        env['PKG_CONFIG'] = pkg_config
        env['PATH'] = str(bin_directory) + os.pathsep + env.get('PATH', '')
        env['LDFLAGS'] = '-static -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va -Wl,--gc-sections'
    return env


def compile_sources(work, sources, target, jobs, compiler):
    if target.startswith('linux/'):
        binary, libraries, env = SERVER.compile_sources(work, sources, target, jobs)
        return binary, sources['tor'] / 'src/test/test', libraries, env
    env = environment(work, target, compiler)
    prefix = work / 'dependencies'
    prefix.mkdir()
    env['PKG_CONFIG_LIBDIR'] = str(prefix / 'lib/pkgconfig')
    env['CPPFLAGS'] = '-I' + shlex.quote(str(prefix / 'include'))
    env['LDFLAGS'] += ' -L' + shlex.quote(str(prefix / 'lib'))
    windows = target.startswith('windows/')
    openssl = 'mingw64' if windows else 'darwin64-x86_64-cc' if target.endswith('amd64') else 'darwin64-arm64-cc'
    host = ['--host=x86_64-w64-mingw32'] if windows else []
    # OpenSSL treats a final executable's -static flag as a request to disable
    # threads. Build its static archives with no-shared and explicit threads;
    # retain the original -static environment for Tor's final link below.
    openssl_env = dict(env)
    openssl_env['LDFLAGS'] = shlex.join(flag for flag in shlex.split(env['LDFLAGS']) if flag != '-static')
    run(['perl', 'Configure', openssl, 'threads', 'no-shared', 'no-module', 'no-dso', 'no-tests', 'no-apps',
         '--prefix=' + str(prefix), '--libdir=lib', '--openssldir=/routervpn/no-system-openssl-config'],
        sources['openssl'], openssl_env, work / 'openssl-configure.log')
    run(['make', '-j' + str(jobs), 'build_libs'], sources['openssl'], openssl_env, work / 'openssl-build.log')
    run(['make', 'install_dev'], sources['openssl'], openssl_env, work / 'openssl-install.log')
    run(['./autogen.sh'], sources['libevent'], env, work / 'libevent-autogen.log')
    run(['./configure', *host, '--prefix=' + str(prefix), '--libdir=' + str(prefix / 'lib'),
         '--disable-shared', '--enable-static', '--disable-openssl', '--disable-libevent-regress', '--disable-samples'],
        sources['libevent'], env, work / 'libevent-configure.log')
    run(['make', '-j' + str(jobs)], sources['libevent'], env, work / 'libevent-build.log')
    run(['make', 'install'], sources['libevent'], env, work / 'libevent-install.log')
    if windows:
        # The pinned zlib tree supplies this static MinGW target. Do not run its
        # host autodetection or install a DLL into the helper's directory.
        run(['make', '-f', 'win32/Makefile.gcc', '-j' + str(jobs),
             'CC=' + env['CC'], 'AR=' + env['AR'], 'ARFLAGS=rcs', 'RANLIB=' + env['RANLIB'],
             'CFLAGS=' + env['CFLAGS'], 'libz.a'], sources['zlib'], env, work / 'zlib-build.log')
        shutil.copyfile(sources['zlib'] / 'libz.a', prefix / 'lib/libz.a')
        for name in ('zlib.h', 'zconf.h'):
            shutil.copyfile(sources['zlib'] / name, prefix / 'include' / name)
    else:
        run(['./configure', '--static', '--prefix=' + str(prefix), '--libdir=' + str(prefix / 'lib')],
            sources['zlib'], env, work / 'zlib-configure.log')
        run(['make', '-j' + str(jobs), 'libz.a'], sources['zlib'], env, work / 'zlib-build.log')
        run(['make', 'install'], sources['zlib'], env, work / 'zlib-install.log')
    libraries = {name: VERIFY.digest(VERIFY.read_regular(prefix / 'lib' / name, 64 << 20)) for name in VERIFY.STATIC_LIBRARIES}
    run(['./autogen.sh'], sources['tor'], env, work / 'tor-autogen.log')
    flags = [flag for flag in SERVER.CONFIGURE if flag != '--enable-static-tor']
    flags += ['--enable-static-libevent', '--enable-static-openssl', '--enable-static-zlib']
    if windows:
        flags += ['--enable-static-tor']
    run(['./configure', *host, *flags, '--with-openssl-dir=' + str(prefix),
         '--with-libevent-dir=' + str(prefix), '--with-zlib-dir=' + str(prefix)],
        sources['tor'], env, work / 'tor-configure.log')
    suffix = '.exe' if windows else ''
    run(['make', '-j' + str(jobs), 'src/app/tor' + suffix, 'src/test/test' + suffix],
        sources['tor'], env, work / 'tor-build.log')
    PADDING.verify(sources['tor'])
    return sources['tor'] / ('src/app/tor' + suffix), sources['tor'] / ('src/test/test' + suffix), libraries, env


def write_compile(stage, target, binary, tests, sources, libraries, env):
    lock = SERVER.source_lock()
    if VERIFY.digest(PADDING.LOCK.read_bytes()) != VERIFY.PADDING_SHA256:
        raise ValueError('Desktop Tor padding source pin requires a coordinated update')
    for source, name in ((binary, VERIFY.binary_name(target)), (tests, test_name(target))):
        raw = VERIFY.read_regular(source, VERIFY.MAX_BINARY)
        (test_identity if name == test_name(target) else VERIFY.executable_identity)(raw, target)
        (stage / name).write_bytes(raw)
        (stage / name).chmod(0o755)
    for source, name in ((SERVER.LOCK, VERIFY.SOURCE), (PADDING.LOCK, VERIFY.PADDING)):
        shutil.copyfile(source, stage / name)
    licenses = {name + '/' + path: VERIFY.read_regular(sources[name] / path, VERIFY.MAX_LICENSES).decode('utf-8')
                for name, entry in lock['sources'].items() for path in entry['licenses']}
    (stage / VERIFY.LICENSES).write_text(json.dumps(licenses, ensure_ascii=False, sort_keys=True, indent=2) + '\n', encoding='utf-8', newline='\n')
    records, identity = source_inputs()
    value = {'schema_version': 1, 'phase': 'compiled-awaiting-native-execution', 'executable_target': target,
        'build_inputs': records, 'build_inputs_sha256': identity, 'static_dependencies': libraries,
        'process_source_sha256': SERVER.unpatched_process(sources['tor'], lock),
        'compiler': {'version': subprocess.check_output([env['CC'], '--version'], text=True).splitlines()[0],
                     'target': subprocess.check_output([env['CC'], '-dumpmachine'], text=True).strip()},
        'files': {name: VERIFY.payload(VERIFY.read_regular(stage / name, VERIFY.MAX_BINARY)) for name in compile_names(target) - {COMPILE}}}
    (stage / COMPILE).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n', encoding='utf-8', newline='\n')
    return value


def verify_compile(directory, target):
    directory = Path(directory)
    target = VERIFY.executable_target(target)
    if {p.name for p in directory.iterdir()} != compile_names(target):
        raise ValueError('Desktop Tor compile artifact contains missing or unowned files')
    value = VERIFY.SERVER.json_object(VERIFY.read_regular(directory / COMPILE, VERIFY.MAX_RECORD))
    if (set(value) != {'schema_version', 'phase', 'executable_target', 'build_inputs', 'build_inputs_sha256',
                      'static_dependencies', 'process_source_sha256', 'compiler', 'files'} or
            type(value.get('schema_version')) is not int or value.get('schema_version') != 1 or
            value.get('phase') != 'compiled-awaiting-native-execution' or value.get('executable_target') != target or
            (value.get('build_inputs'), value.get('build_inputs_sha256')) != source_inputs()):
        raise ValueError('Desktop Tor compile artifact is not from the exact build source')
    actual = {name: VERIFY.payload(VERIFY.read_regular(directory / name,
              VERIFY.MAX_BINARY if name == test_name(target) else VERIFY.bound(name, target))) for name in compile_names(target) - {COMPILE}}
    if not VERIFY.strict_equal(value.get('files'), actual):
        raise ValueError('Desktop Tor compile artifact bytes changed')
    for name in (VERIFY.binary_name(target), test_name(target)):
        (test_identity if name == test_name(target) else VERIFY.executable_identity)(VERIFY.read_regular(directory / name, VERIFY.MAX_BINARY), target)
    return value


def compile_package(output, work, cache, target, jobs=2, compiler=None):
    target = VERIFY.executable_target(target)
    if not 1 <= jobs <= 16:
        raise ValueError('Desktop Tor jobs must be between 1 and 16')
    if target.startswith('windows/'):
        if platform.system() != 'Linux':
            raise ValueError('Windows Tor cross compilation requires a Linux build host')
    else:
        VERIFY.require_host(target)
    output = SERVER.empty_directory(output, 'Desktop Tor compile output')
    work = SERVER.empty_directory(work, 'Desktop Tor compile work')
    if output == work or output.is_relative_to(work) or work.is_relative_to(output):
        raise ValueError('Desktop Tor output and work directories must be separate')
    initial = source_inputs()
    work.mkdir(mode=0o700, exist_ok=True)
    lock = SERVER.source_lock()
    sources = {name: ARCHIVES.extract(ARCHIVES.fetch(name, item, Path(cache)), item, work / name) for name, item in lock['sources'].items()}
    SERVER.unpatched_process(sources['tor'], lock)
    PADDING.apply(sources['tor'])
    binary, tests, libraries, env = compile_sources(work, sources, target, jobs, compiler)
    if initial != source_inputs():
        raise ValueError('Desktop Tor build source changed during compilation')
    stage = Path(tempfile.mkdtemp(prefix=output.name + '-stage-', dir=output.parent))
    try:
        write_compile(stage, target, binary, tests, sources, libraries, env)
        verify_compile(stage, target)
        if output.exists():
            output.rmdir()
        stage.rename(output)
        stage = None
    finally:
        if stage is not None:
            shutil.rmtree(stage)
    return output


def finalize(compiled, output, target):
    VERIFY.require_host(target)
    compiled = Path(compiled).absolute()
    output = SERVER.empty_directory(output, 'Desktop Tor accepted output')
    if output == compiled or output.is_relative_to(compiled) or compiled.is_relative_to(output):
        raise ValueError('Desktop Tor accepted output must be separate from compile evidence')
    before = verify_compile(compiled, target)
    tests = compiled / test_name(target)
    tests.chmod(0o755)  # Artifact transport does not preserve POSIX executable bits.
    environment = {k: v for k, v in os.environ.items() if k.upper() not in ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES')}
    result = subprocess.run([str(tests), *VERIFY.TEST_SELECTORS], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=45, env=environment)
    if result.returncode or len(result.stdout) > 128 << 10:
        raise ValueError('Desktop Tor native padding/crypto tests failed: ' + result.stdout[-8192:].decode('utf-8', errors='replace'))
    stage = Path(tempfile.mkdtemp(prefix=output.name + '-stage-', dir=output.parent))
    try:
        for name in VERIFY.names(target) - {VERIFY.RECEIPT}:
            shutil.copyfile(compiled / name, stage / name)
        binary = stage / VERIFY.binary_name(target)
        binary.chmod(0o755)
        offline = VERIFY.offline_self_test(binary, target)
        record = {key: before[key] for key in ('build_inputs', 'build_inputs_sha256', 'static_dependencies', 'process_source_sha256', 'compiler')}
        record.update(schema_version=1, runtime='tor-routervpn', version=VERIFY.VERSION, upstream_revision=VERIFY.REVISION,
            target=target, executable_target=VERIFY.executable_target(target), execution=VERIFY.execution(target),
            source_lock_sha256=VERIFY.SOURCE_SHA256, padding_lock_sha256=VERIFY.PADDING_SHA256, padding_version=1,
            native_tests={'passed': True, 'selectors': list(VERIFY.TEST_SELECTORS), 'executable_sha256': before['files'][test_name(target)]['sha256']},
            offline_self_test=offline, executable_identity=VERIFY.executable_identity(binary.read_bytes(), target),
            files={name: VERIFY.payload(VERIFY.read_regular(stage / name, VERIFY.bound(name, target))) for name in VERIFY.names(target) - {VERIFY.RECEIPT}})
        (stage / VERIFY.RECEIPT).write_text(json.dumps(record, sort_keys=True, indent=2) + '\n', encoding='utf-8', newline='\n')
        VERIFY.verify(stage, target, source_root=ROOT)
        if verify_compile(compiled, target) != before:
            raise ValueError('Desktop Tor compile artifact changed during native acceptance')
        if output.exists():
            output.rmdir()
        stage.rename(output)
        stage = None
    finally:
        if stage is not None:
            shutil.rmtree(stage)
    print('PASS desktop Tor native tests and disabled owner', target, record['files'][VERIFY.binary_name(target)]['sha256'], flush=True)
    return output


def build(target, output, *, compiled=None, cache=None, jobs=2):
    output = Path(output).absolute()
    if output.exists() and any(output.iterdir()):
        VERIFY.verify(output, target, source_root=ROOT)
        VERIFY.offline_self_test(output / VERIFY.binary_name(target), target)
        return output
    if compiled is not None:
        return finalize(compiled, output, target)
    if target.startswith('windows/'):
        raise ValueError('Windows native acceptance requires the exact compiled prerequisite artifact')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.desktop-tor-build-', dir=output.parent) as directory:
        temporary = Path(directory)
        compile_package(temporary / 'compiled', temporary / 'work', cache or ROOT / 'dist/.tor-source-cache', target, jobs)
        return finalize(temporary / 'compiled', output, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('compile', 'finalize', 'build', 'verify'))
    parser.add_argument('target', choices=VERIFY.TARGETS)
    parser.add_argument('output', type=Path)
    parser.add_argument('--compiled', type=Path)
    parser.add_argument('--work', type=Path)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--compiler', type=Path)
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if args.operation == 'compile':
        if args.work is None or args.cache is None:
            parser.error('compile requires --work and --cache')
        compile_package(args.output, args.work, args.cache, args.target, args.jobs, args.compiler)
    elif args.operation == 'finalize':
        if args.compiled is None:
            parser.error('finalize requires --compiled')
        finalize(args.compiled, args.output, args.target)
    elif args.operation == 'verify':
        VERIFY.verify(args.output, args.target, source_root=ROOT)
        VERIFY.offline_self_test(args.output / VERIFY.binary_name(args.target), args.target)
    else:
        build(args.target, args.output, compiled=args.compiled, cache=args.cache, jobs=args.jobs)


if __name__ == '__main__':
    main()
