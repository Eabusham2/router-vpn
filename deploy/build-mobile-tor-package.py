#!/usr/bin/env python3
"""Build pinned Tor C dependencies into an isolated Android/Apple dynamic ABI.

No Go archive is built here. The existing Libbox runtime links the six-function
C library; native PT/session ownership is a separate mandatory runtime boundary.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import plistlib
import re
import shlex
import shutil
import struct
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'mobile/torpack'
HOST = ROOT / 'mobile/tor'
EXPORTS = tuple('routervpn_tor_' + name for name in ('abi', 'version', 'start', 'control', 'status', 'close'))
ANDROID = (
    ('arm64-v8a', 'arm64', 'aarch64-linux-android', 'aarch64-linux-android', 'android-arm64', 183, 2),
    ('armeabi-v7a', 'arm', 'arm-linux-androideabi', 'armv7a-linux-androideabi', 'android-arm', 40, 1),
    ('x86', '386', 'i686-linux-android', 'i686-linux-android', 'android-x86', 3, 1),
    ('x86_64', 'amd64', 'x86_64-linux-android', 'x86_64-linux-android', 'android-x86_64', 62, 2),
)
APPLE = (
    ('ios-arm64', 'iphoneos', 'arm64', 'ios64-xcrun'),
    ('ios-simulator-arm64', 'iphonesimulator', 'arm64', 'iossimulator-arm64-xcrun'),
    ('ios-simulator-x86_64', 'iphonesimulator', 'x86_64', 'iossimulator-x86_64-xcrun'),
)
APPLE_SLICES = {'ios-arm64': (['arm64'], False), 'ios-arm64_x86_64-simulator': (['arm64', 'x86_64'], True)}
FRAMEWORK_MODULE = 'framework module RouterVPNTor {\n umbrella header "routervpn_tor_host.h"\n export *\n}\n'
FORBIDDEN_IMPORTS = {'fork', 'vfork', 'execve', 'execv', 'execvp', 'execl', 'execlp', 'posix_spawn', 'posix_spawnp', 'popen', 'system'}


def sha(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as source:
        for data in iter(lambda: source.read(1024 * 1024), b''):
            result.update(data)
    return result.hexdigest()


def lock():
    value = json.loads((SOURCE / 'sources.json').read_text())
    if value['schema'] != 1 or value['abi'] != 1 or value['native_version'] != 'tor 0.4.9.14':
        raise ValueError('Native Tor ABI source lock changed')
    if set(value['sources']) != {'tor', 'openssl', 'libevent', 'zlib'}:
        raise ValueError('Native Tor requires every pinned C dependency')
    for name, record in value['sources'].items():
        if not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', record['repository']):
            raise ValueError('Native Tor source repository is not an immutable GitHub source')
        if not re.fullmatch('[0-9a-f]{40}', record['commit']) or not re.fullmatch('[0-9a-f]{64}', record['archive_sha256']):
            raise ValueError('Native Tor source commit/checksum is missing')
        if not record['licenses']:
            raise ValueError('Native Tor dependency license is missing: ' + name)
        for relative, checksum in record['licenses'].items():
            if not safe_relative(relative) or not re.fullmatch('[0-9a-f]{64}', checksum):
                raise ValueError('Native Tor license path or checksum changed')
    if value['android_ndk'] != '28.0.13004108' or value['android_api'] != 24 or value['ios_minimum'] != '17.0':
        raise ValueError('Native Tor deployment target differs from the mobile apps')
    header = (HOST / 'routervpn_tor_host.h').read_text()
    declared = re.findall(r'\b(routervpn_tor_[a-z_]+)\s*\(', header)
    if set(declared) != set(EXPORTS) or len(declared) != len(EXPORTS) or '#define ROUTERVPN_TOR_ABI 1' not in header:
        raise ValueError('Native Tor C ABI requires a coordinated source lock update')
    return value


def inputs():
    return [Path(__file__).resolve(), SOURCE / 'sources.json', SOURCE / 'embedded-process.patch',
            HOST / 'routervpn_tor_host.c', HOST / 'routervpn_tor_host.h', HOST / 'workqueue-lifecycle.patch',
            ROOT / 'deploy/build-mobile-tor.py', *notice_sources().values()]


def notice_sources():
    """Redistribute the exact embedded PT notices and their verified module lock."""
    root = ROOT / 'mobile/torpt'
    paths = {root / name for name in ('go.mod', 'go.sum', 'README.md', 'SOURCE_LOCK.json')}
    paths.update(path for path in root.rglob('*') if path.name.startswith('LICENSE') or path.name in ('UPSTREAM.json', 'SOURCE_LOCK.json'))
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError('Embedded PT source notice is missing or linked')
    return {'notices/mobile/torpt/' + str(path.relative_to(root)): path for path in sorted(paths)}


def source_digest():
    value = hashlib.sha256()
    for path in sorted(inputs()):
        value.update(str(path.relative_to(ROOT)).encode() + b'\0' + path.read_bytes() + b'\0')
    return value.hexdigest()


def safe_relative(name):
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and '..' not in path.parts and str(path) == name and '\\' not in name and '\0' not in name


def run(arguments, *, directory=None, env=None, log=None, timeout=900, capture=False):
    command = [str(argument) for argument in arguments]
    if log is not None:
        with Path(log).open('w') as target:
            result = subprocess.run(command, cwd=directory, env=env, stdout=target,
                                    stderr=subprocess.STDOUT, timeout=timeout)
        if result.returncode:
            raise RuntimeError(str(log) + ':\n' + Path(log).read_text(errors='replace')[-6500:])
        return ''
    return subprocess.run(command, cwd=directory, env=env, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None, timeout=timeout).stdout or ''


def fetch(name, record, cache):
    cache.mkdir(parents=True, exist_ok=True)
    if cache.is_symlink():
        raise ValueError('Native source cache must not be a link')
    archive = cache / (name + '-' + record['commit'] + '.tar.gz')
    if archive.exists():
        if archive.is_symlink() or not archive.is_file() or sha(archive) != record['archive_sha256']:
            raise ValueError('Pinned native source cache checksum mismatch: ' + name)
        return archive
    repository = record['repository'].removeprefix('https://github.com/')
    url = 'https://codeload.github.com/' + repository + '/tar.gz/' + record['commit']
    for attempt in range(3):
        descriptor, temporary = tempfile.mkstemp(prefix=name + '-', suffix='.download', dir=cache)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                with urllib.request.urlopen(url, timeout=90) as response:
                    final = urllib.parse.urlparse(response.geturl())
                    if final.scheme != 'https' or final.hostname != 'codeload.github.com':
                        raise ValueError('Pinned native source download redirected outside its source host')
                    shutil.copyfileobj(response, output)
            if sha(temporary) != record['archive_sha256']:
                raise ValueError('Downloaded native source checksum mismatch: ' + name)
            os.replace(temporary, archive)
            return archive
        except (OSError, TimeoutError):
            if attempt == 2:
                raise
            time.sleep(attempt + 1)
        finally:
            Path(temporary).unlink(missing_ok=True)
    raise RuntimeError('Pinned native source download did not complete')


def extract(archive, record, output):
    if sha(archive) != record['archive_sha256']:
        raise ValueError('Refusing to extract a changed native source archive')
    output.mkdir()
    prefix = record['repository'].rsplit('/', 1)[-1] + '-' + record['commit']
    # These exact four archives contain only regular files/directories. Refuse
    # links, device entries, duplicate names and traversal before any write.
    with tarfile.open(archive, 'r:gz') as source:
        members = source.getmembers()
        names = set()
        for member in members:
            name = member.name.rstrip('/')
            if not safe_relative(name) or name in names or not (member.isfile() or member.isdir()):
                raise ValueError('Unsafe pinned native source archive entry')
            if PurePosixPath(name).parts[0] != prefix:
                raise ValueError('Native source archive prefix differs from the exact commit')
            names.add(name)
        for member in members:
            parts = PurePosixPath(member.name).parts[1:]
            if not parts:
                continue
            destination = output.joinpath(*parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as original, destination.open('xb') as target:
                    shutil.copyfileobj(original, target)
                destination.chmod(member.mode & 0o755)
    for relative, checksum in record['licenses'].items():
        if sha(output / relative) != checksum:
            raise ValueError('Extracted native dependency license checksum changed')
    return output


def patch_source(source, source_lock):
    spec = importlib.util.spec_from_file_location('routervpn_tor_host_build', ROOT / 'deploy/build-mobile-tor.py')
    host_build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host_build)
    if source_lock['sources']['tor']['commit'] != host_build.TOR_COMMIT:
        raise ValueError('Mobile packaging and the real Tor lifetime gate use different source pins')
    host_build.patch_workqueue(source)
    records = source_lock['embedded_process_sha256']
    for name, record in records.items():
        if not safe_relative(name) or (source / name).is_symlink() or sha(source / name) != record['original']:
            raise ValueError('Pinned native mobile subprocess boundary changed')
    run(['patch', '--batch', '--fuzz=0', '-p1', '-i', SOURCE / 'embedded-process.patch'], directory=source)
    for name, record in records.items():
        if sha(source / name) != record['patched']:
            raise ValueError('Native mobile subprocess patch checksum mismatch')
    return host_build.CONFIGURE


def base_env(work):
    env = dict(os.environ)
    for key in list(env):
        if key.startswith('CGO_') or key in ('CC', 'CXX', 'CPP', 'AR', 'AS', 'RANLIB', 'NM', 'LD',
                'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'LIBS', 'CPATH', 'C_INCLUDE_PATH',
                'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH', 'SDKROOT', 'CROSS_TOP', 'CROSS_SDK', 'CROSS_SYSROOT',
                'CROSS_COMPILE', 'CHOST', 'CMAKE_TOOLCHAIN_FILE', 'PKG_CONFIG_PATH', 'PKG_CONFIG_LIBDIR',
                'PKG_CONFIG_SYSROOT_DIR', 'MACOSX_DEPLOYMENT_TARGET', 'IPHONEOS_DEPLOYMENT_TARGET',
                'TVOS_DEPLOYMENT_TARGET', 'CONFIG_SITE'):
            env.pop(key, None)
    env.update(LC_ALL='C', TZ='UTC', SOURCE_DATE_EPOCH=str(lock()['source_date_epoch']),
               CONFIG_SITE='', ZERO_AR_DATE='1')
    env['CFLAGS'] = '-O2 -fPIC -fstack-protector-strong -ffunction-sections -fdata-sections ' + \
        '-ffile-prefix-map=' + str(work) + '=/routervpn/native-tor -fdebug-prefix-map=' + str(work) + '=/routervpn/native-tor'
    env['CPPFLAGS'] = '-DROUTERVPN_TOR_EMBEDDED=1'
    return env


def ndk_tools(explicit=None):
    source_lock = lock()
    chosen = explicit or os.environ.get('ANDROID_NDK_HOME') or os.environ.get('ANDROID_NDK_ROOT')
    if chosen:
        ndk = Path(chosen).resolve()
    else:
        sdk = Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or '/missing-sdk')
        ndk = sdk / 'ndk' / source_lock['android_ndk']
        if not (ndk / 'source.properties').is_file():
            manager = sdk / 'cmdline-tools/latest/bin/sdkmanager'
            if not manager.is_file():
                raise RuntimeError('Pinned Android NDK or sdkmanager is required for native Tor')
            run([manager, 'ndk;' + source_lock['android_ndk']])
    properties = (ndk / 'source.properties').read_text()
    if not re.search(r'^Pkg.Revision\s*=\s*' + re.escape(source_lock['android_ndk']) + r'\s*$', properties, re.M):
        raise ValueError('Native Tor Android NDK revision differs from the pinned mobile runtime')
    host = 'darwin-x86_64' if platform.system() == 'Darwin' else 'linux-x86_64'
    tools = ndk / 'toolchains/llvm/prebuilt' / host / 'bin'
    if not (tools / 'clang').is_file():
        raise RuntimeError('Pinned Android NDK compiler is missing')
    return ndk, tools


def compile_dependencies(target, work, archives, source_lock, jobs, ndk=None):
    directory = work / target['name']
    directory.mkdir()
    prefix = directory / 'install'
    prefix.mkdir()
    env = base_env(directory)
    env['PKG_CONFIG_LIBDIR'] = str(prefix / 'lib/pkgconfig')
    env['LDFLAGS'] = '-L' + shlex.quote(str(prefix / 'lib'))
    env['CPPFLAGS'] += ' -I' + shlex.quote(str(prefix / 'include'))
    args = []
    if target['platform'] == 'android':
        ndk, tools = ndk_tools(ndk)
        compiler = tools / (target['triple'] + str(source_lock['android_api']) + '-clang')
        env.update(ANDROID_NDK_HOME=str(ndk), ANDROID_NDK_ROOT=str(ndk),
                   PATH=str(tools) + os.pathsep + env['PATH'], CC=str(compiler),
                   AR=str(tools / 'llvm-ar'), RANLIB=str(tools / 'llvm-ranlib'), NM=str(tools / 'llvm-nm'))
        args = ['--host=' + target['host']]
        env['CHOST'] = target['host']
        openssl_flags = ['-D__ANDROID_API__=' + str(source_lock['android_api'])]
    elif target['platform'] == 'ios':
        if platform.system() != 'Darwin':
            raise RuntimeError('Apple Tor builds require the installed Xcode iOS SDKs')
        sdk = run(['xcrun', '--sdk', target['sdk'], '--show-sdk-path'], capture=True).strip()
        compiler = Path(run(['xcrun', '--sdk', target['sdk'], '--find', 'clang'], capture=True).strip())
        triple = target['arch'] + '-apple-ios' + source_lock['ios_minimum'] + ('-simulator' if target['sdk'] == 'iphonesimulator' else '')
        flags = '-target ' + triple + ' -isysroot ' + shlex.quote(sdk) + ' -fapplication-extension'
        env.update(CC=str(compiler), AR=run(['xcrun', '--find', 'ar'], capture=True).strip(),
                   RANLIB=run(['xcrun', '--find', 'ranlib'], capture=True).strip(),
                   NM=run(['xcrun', '--find', 'nm'], capture=True).strip(), SDKROOT=sdk,
                   IPHONEOS_DEPLOYMENT_TARGET=source_lock['ios_minimum'])
        env['CFLAGS'] += ' ' + flags
        env['LDFLAGS'] += ' ' + flags
        host = ('aarch64' if target['arch'] == 'arm64' else target['arch']) + '-apple-darwin'
        env['CHOST'] = host
        args = ['--host=' + host]
        openssl_flags = []
    else:
        compiler = Path(shutil.which('cc') or '/missing-cc')
        env.update(CC=str(compiler), AR=shutil.which('ar') or 'ar', RANLIB=shutil.which('ranlib') or 'ranlib')
        openssl_flags = []
    source = {name: extract(archives[name], record, directory / name) for name, record in source_lock['sources'].items()}
    configure = patch_source(source['tor'], source_lock)
    run(['perl', 'Configure', target['openssl'], 'no-shared', 'no-module', 'no-dso', 'no-tests', 'no-apps',
         '--prefix=' + str(prefix), '--libdir=lib', '--openssldir=/routervpn/no-system-openssl-config', *openssl_flags],
        directory=source['openssl'], env=env, log=directory / 'openssl-configure.log')
    run(['make', '-j' + str(jobs), 'build_libs'], directory=source['openssl'], env=env, log=directory / 'openssl-make.log')
    run(['make', 'install_dev'], directory=source['openssl'], env=env, log=directory / 'openssl-install.log')
    run(['./autogen.sh'], directory=source['libevent'], env=env, log=directory / 'event-autogen.log')
    run(['./configure', '--prefix=' + str(prefix), '--libdir=' + str(prefix / 'lib'), '--disable-shared',
         '--enable-static', '--with-pic', '--disable-openssl', '--disable-libevent-regress', '--disable-samples', *args],
        directory=source['libevent'], env=env, log=directory / 'event-configure.log')
    run(['make', '-j' + str(jobs)], directory=source['libevent'], env=env, log=directory / 'event-make.log')
    run(['make', 'install'], directory=source['libevent'], env=env, log=directory / 'event-install.log')
    run(['./configure', '--static', '--prefix=' + str(prefix), '--libdir=' + str(prefix / 'lib')],
        directory=source['zlib'], env=env, log=directory / 'zlib-configure.log')
    run(['make', '-j' + str(jobs), 'libz.a'], directory=source['zlib'], env=env, log=directory / 'zlib-make.log')
    run(['make', 'install'], directory=source['zlib'], env=env, log=directory / 'zlib-install.log')
    run(['./autogen.sh'], directory=source['tor'], env=env, log=directory / 'tor-autogen.log')
    run(['./configure', *configure, *args, '--enable-static-openssl', '--enable-static-libevent', '--enable-static-zlib',
         '--with-openssl-dir=' + str(prefix), '--with-libevent-dir=' + str(prefix), '--with-zlib-dir=' + str(prefix)],
        directory=source['tor'], env=env, log=directory / 'tor-configure.log')
    run(['make', '-j' + str(jobs), 'libtor.a'], directory=source['tor'], env=env, log=directory / 'tor-make.log')
    libraries = [source['tor'] / 'libtor.a'] + [prefix / 'lib' / name for name in ('libevent.a', 'libssl.a', 'libcrypto.a', 'libz.a')]
    for library in libraries:
        if not library.is_file() or not library.stat().st_size:
            raise RuntimeError('Pinned C dependency archive is missing: ' + str(library))
    return directory, source, env, compiler, libraries


def link_library(target, stage, directory, source, env, compiler, libraries):
    common = [compiler, *shlex.split(env['CFLAGS']), *shlex.split(env['CPPFLAGS']), '-std=c11',
              '-Wall', '-Wextra', '-Werror', '-pthread', '-I' + str(source['tor'] / 'src/feature/api'), HOST / 'routervpn_tor_host.c']
    if target['platform'] == 'ios':
        output = stage / target['name'] / 'RouterVPNTor.framework'
        (output / 'Headers').mkdir(parents=True)
        (output / 'Modules').mkdir()
        exported = directory / 'exports.txt'
        exported.write_text(''.join('_' + symbol + '\n' for symbol in EXPORTS))
        run([*common, '-dynamiclib', *libraries, '-lm', '-lresolv', '-Wl,-twolevel_namespace',
             '-Wl,-application_extension', '-Wl,-dead_strip', '-Wl,-exported_symbols_list,' + str(exported),
             '-Wl,-install_name,@rpath/RouterVPNTor.framework/RouterVPNTor',
             '-Wl,-compatibility_version,1', '-Wl,-current_version,1', '-o', output / 'RouterVPNTor'],
            env=env, log=directory / 'link.log')
        shutil.copyfile(HOST / 'routervpn_tor_host.h', output / 'Headers/routervpn_tor_host.h')
        (output / 'Modules/module.modulemap').write_text(FRAMEWORK_MODULE)
        (output / 'Info.plist').write_bytes(plistlib.dumps(framework_plist(target['sdk'] == 'iphonesimulator')))
        return output
    output = stage / ('jni/' + target['abi'] if target['platform'] == 'android' else 'lib') / 'libroutervpn_tor.so'
    output.parent.mkdir(parents=True, exist_ok=True)
    exported = directory / 'exports.map'
    exported.write_text('{\n global:\n' + ''.join('  ' + symbol + ';\n' for symbol in EXPORTS) + ' local: *;\n};\n')
    system_libraries = ['-ldl', '-lm'] + (['-llog'] if target['platform'] == 'android' else [])
    run([*common, '-shared', '-Wl,--start-group', *libraries, '-Wl,--end-group', *system_libraries,
         '-Wl,--no-undefined', '-Wl,--exclude-libs,ALL', '-Wl,-Bsymbolic', '-Wl,-z,relro', '-Wl,-z,now', '-Wl,-z,noexecstack',
         '-Wl,--gc-sections', '-Wl,--version-script=' + str(exported), '-Wl,-soname,libroutervpn_tor.so',
         '-Wl,-z,max-page-size=16384', '-Wl,-z,common-page-size=16384', '-o', output], env=env, log=directory / 'link.log')
    return output


def elf_identity(path, machine, elf_class):
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b'\x7fELF' + bytes((elf_class, 1)):
        raise ValueError('Native Tor ELF class or endianness differs from its ABI')
    if struct.unpack_from('<HH', data, 16) != (3, machine):
        raise ValueError('Native Tor binary is not a shared library for its ABI')
    if elf_class == 2:
        offset = struct.unpack_from('<Q', data, 32)[0]
        size, count = struct.unpack_from('<HH', data, 54)
    else:
        offset = struct.unpack_from('<I', data, 28)[0]
        size, count = struct.unpack_from('<HH', data, 42)
    expected_size = 56 if elf_class == 2 else 32
    if not count or size != expected_size or offset + size * count > len(data):
        raise ValueError('Native Tor ELF program headers are incomplete')
    loads = 0
    relro = False
    nonexec_stack = False
    for index in range(count):
        start = offset + index * size
        if elf_class == 2:
            kind, flags, file_offset, address, _, _, _, alignment = struct.unpack_from('<IIQQQQQQ', data, start)
        else:
            kind, file_offset, address, _, _, _, flags, alignment = struct.unpack_from('<IIIIIIII', data, start)
        if kind == 1:
            loads += 1
            if alignment < 16384 or alignment & (alignment - 1) or file_offset % alignment != address % alignment or flags & 3 == 3:
                raise ValueError('Native Tor requires 16 KiB compatible non-WX ELF segments')
        elif kind == 0x6474e552:
            relro = True
        elif kind == 0x6474e551:
            nonexec_stack = not flags & 1
    if not loads or not relro or not nonexec_stack:
        raise ValueError('Native Tor requires loadable segments, RELRO and a non-executable stack')


def verify_elf(path, target, tools=None):
    elf_identity(path, target['machine'], target['class'])
    nm = tools / 'llvm-nm' if tools else 'nm'
    readelf = tools / 'llvm-readelf' if tools else 'readelf'
    symbols = run([nm, '-D', '--defined-only', '--format=posix', path], capture=True)
    actual = {line.split()[0].split('@')[0] for line in symbols.splitlines() if line.strip()}
    if actual != set(EXPORTS):
        raise ValueError('Native Tor dynamic exports exceed or omit the exact C ABI: ' + repr(sorted(actual)))
    dynamic = run([readelf, '-d', path], capture=True)
    needed = set(re.findall(r'Shared library: \[([^\]]+)\]', dynamic))
    allowed = {'libc.so', 'libm.so', 'libdl.so', 'liblog.so'} if target['platform'] == 'android' else {
        'libc.so.6', 'libm.so.6', 'libdl.so.2', 'libpthread.so.0', 'ld-linux-x86-64.so.2', 'libgcc_s.so.1'}
    if not needed or not needed <= allowed or 'Library soname: [libroutervpn_tor.so]' not in dynamic or 'SYMBOLIC' not in dynamic or not re.search(r'\b(BIND_NOW|NOW)\b', dynamic):
        raise ValueError('Native Tor dependency or local-symbol binding is not isolated')
    imports = run([nm, '-D', '--undefined-only', '--format=posix', path], capture=True)
    names = {line.split()[0].split('@')[0] for line in imports.splitlines() if line.strip()}
    if names & FORBIDDEN_IMPORTS:
        raise ValueError('Native Tor imports forbidden subprocess functions: ' + repr(sorted(names & FORBIDDEN_IMPORTS)))
    sections = run([readelf, '-S', path], capture=True)
    if any(marker in sections for marker in ('.go.buildinfo', '.gopclntab', '.note.go.buildid')):
        raise ValueError('Tor C dependency must not contain a second Go runtime')


def apple_link_stub():
    targets = '[ arm64-ios, arm64-ios-simulator, x86_64-ios-simulator ]'
    return ('--- !tapi-tbd\ntbd-version: 4\ntargets: ' + targets + '\n'
            "install-name: '@rpath/RouterVPNTor.framework/RouterVPNTor'\ncurrent-version: 1\ncompatibility-version: 1\n"
            'exports:\n  - targets: ' + targets + '\n    symbols: [ ' + ', '.join('_' + name for name in EXPORTS) + ' ]\n...\n')


def framework_plist(simulator):
    return dict(CFBundleIdentifier='com.eabusham.routervpn.tor', CFBundleName='RouterVPNTor',
                CFBundleExecutable='RouterVPNTor', CFBundlePackageType='FMWK',
                CFBundleShortVersionString='0.4.9', CFBundleVersion='14',
                RouterVPNTorSourceVersion=lock()['native_version'], MinimumOSVersion=lock()['ios_minimum'],
                CFBundleSupportedPlatforms=['iPhoneSimulator' if simulator else 'iPhoneOS'])


def verify_macho(framework, architectures, simulator):
    binary = framework / 'RouterVPNTor'
    actual = set(run(['xcrun', 'lipo', '-archs', binary], capture=True).split())
    if actual != set(architectures):
        raise ValueError('Native Tor Apple framework architecture set changed')
    for architecture in architectures:
        exports = run(['xcrun', 'nm', '-arch', architecture, '-gUj', binary], capture=True)
        if set(exports.split()) != {'_' + name for name in EXPORTS}:
            raise ValueError('Apple Tor must export only the exact owning C ABI')
        imports = run(['xcrun', 'nm', '-arch', architecture, '-guj', binary], capture=True)
        if {name.lstrip('_') for name in imports.split()} & FORBIDDEN_IMPORTS:
            raise ValueError('Apple Tor imports a subprocess API')
        headers = run(['xcrun', 'otool', '-arch', architecture, '-hv', binary], capture=True)
        if 'TWOLEVEL' not in headers or 'APP_EXTENSION_SAFE' not in headers:
            raise ValueError('Apple Tor requires two-level namespace and extension-safe linkage')
        commands = run(['xcrun', 'otool', '-arch', architecture, '-l', binary], capture=True)
        expected_platform = 7 if simulator else 2
        if not re.search(r'\bplatform\s+' + str(expected_platform) + r'\b', commands) or not re.search(r'\bminos\s+17\.0\b', commands):
            raise ValueError('Apple Tor platform or deployment target changed')
        libraries = run(['xcrun', 'otool', '-arch', architecture, '-L', binary], capture=True).splitlines()[1:]
        names = {line.strip().split(' (compatibility version')[0] for line in libraries if line.strip()}
        expected = '@rpath/RouterVPNTor.framework/RouterVPNTor'
        if expected not in names or not names <= {expected, '/usr/lib/libSystem.B.dylib', '/usr/lib/libresolv.9.dylib'}:
            raise ValueError('Apple Tor contains an external crypto/event/compression dependency')


def package_apple(stage, frameworks):
    device = frameworks['ios-arm64']
    simulator = frameworks['ios-simulator-arm64']
    run(['xcrun', 'lipo', '-create', simulator / 'RouterVPNTor', frameworks['ios-simulator-x86_64'] / 'RouterVPNTor',
         '-output', simulator / 'RouterVPNTor.universal'])
    os.replace(simulator / 'RouterVPNTor.universal', simulator / 'RouterVPNTor')
    verify_macho(device, ['arm64'], False)
    verify_macho(simulator, ['arm64', 'x86_64'], True)
    run(['xcodebuild', '-create-xcframework', '-framework', device, '-framework', simulator,
         '-output', stage / 'RouterVPNTor.xcframework'])
    for name in frameworks:
        shutil.rmtree(stage / name)
    stub = stage / 'link/apple/RouterVPNTor.framework'
    stub.mkdir(parents=True)
    (stub / 'RouterVPNTor.tbd').write_text(apple_link_stub())


def tree_files(output):
    paths = list(output.rglob('*'))
    if output.is_symlink() or any(path.is_symlink() or not (path.is_file() or path.is_dir()) for path in paths):
        raise ValueError('Linked or nonregular native Tor package entry')
    return {str(path.relative_to(output)): sha(path) for path in paths if path.is_file() and path != output / 'source.json'}


def package_paths(kind):
    paths = {'SHA256SUMS', 'include/routervpn_tor_host.h', *notice_sources()}
    for name, dependency in lock()['sources'].items():
        paths.update('licenses/' + name + '-' + Path(relative).name for relative in dependency['licenses'])
    if kind == 'android':
        paths.update('jni/' + abi + '/libroutervpn_tor.so' for abi, *_ in ANDROID)
    elif kind == 'ios':
        paths.update(('RouterVPNTor.xcframework/Info.plist', 'link/apple/RouterVPNTor.framework/RouterVPNTor.tbd'))
        for identifier in APPLE_SLICES:
            prefix = 'RouterVPNTor.xcframework/' + identifier + '/RouterVPNTor.framework/'
            paths.update(prefix + relative for relative in ('RouterVPNTor', 'Info.plist', 'Headers/routervpn_tor_host.h', 'Modules/module.modulemap'))
    elif kind == 'host-test':
        paths.add('lib/libroutervpn_tor.so')
    else:
        raise ValueError('Unknown native Tor package platform')
    return paths


def output_state(output, kind):
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        raise ValueError('Refusing to replace an unowned native Tor package')
    if not output.exists():
        return 'missing'
    files = tree_files(output)
    manifest = output / 'source.json'
    if not files and not manifest.exists():
        return 'empty'
    try:
        record = json.loads(manifest.read_text())
        if record['schema'] != 1 or record['platform'] != kind or record['files'] != files or not set(files) <= package_paths(kind):
            raise ValueError('Native Tor output is not an entirely manifest-owned tree')
        if record['abi'] != 1 or not re.fullmatch('[0-9a-f]{64}', record['source_sha256']):
            raise ValueError('Native Tor output has no valid source owner')
        for name, checksum in record['files'].items():
            if not safe_relative(name) or not re.fullmatch('[0-9a-f]{64}', checksum):
                raise ValueError('Native Tor output manifest has an unsafe entry')
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError('Refusing to replace an unowned native Tor package') from error
    return 'owned'


def verify(output, kind, *, binaries=True, ndk=None):
    source_lock = lock()
    if output_state(output, kind) != 'owned':
        raise ValueError('Native Tor package is missing or incomplete')
    record = json.loads((output / 'source.json').read_text())
    if record['source_sha256'] != source_digest() or record['source_lock'] != source_lock or record['files'] != tree_files(output):
        raise ValueError('Native Tor package/source checksum mismatch')
    if set(record['files']) != package_paths(kind):
        raise ValueError('Native Tor package layout omits or adds an unowned artifact')
    if record['abi'] != 1 or record['mobile_session_proof'] is not False:
        raise ValueError('C library provenance cannot assert a protected mobile Tor session')
    for name, dependency in source_lock['sources'].items():
        for relative, checksum in dependency['licenses'].items():
            if record['files'].get('licenses/' + name + '-' + Path(relative).name) != checksum:
                raise ValueError('Native Tor package omits a pinned dependency license')
    if (output / 'include/routervpn_tor_host.h').read_bytes() != (HOST / 'routervpn_tor_host.h').read_bytes():
        raise ValueError('Native Tor public header differs from its exact owning C ABI')
    notices = {relative: sha(path) for relative, path in notice_sources().items()}
    if record.get('pt_notices') != notices or any(record['files'][relative] != checksum for relative, checksum in notices.items()):
        raise ValueError('Native Tor package omits or changes embedded PT source notices')
    if kind == 'android':
        tools = ndk_tools(ndk)[1] if binaries else None
        for abi, _, _, _, _, machine, elf_class in ANDROID:
            path = output / 'jni' / abi / 'libroutervpn_tor.so'
            if str(path.relative_to(output)) not in record['files']:
                raise ValueError('Native Tor package omits an Android ABI')
            if binaries:
                verify_elf(path, {'platform': kind, 'machine': machine, 'class': elf_class}, tools)
    elif kind == 'ios':
        metadata = plistlib.loads((output / 'RouterVPNTor.xcframework/Info.plist').read_bytes())
        if metadata.get('CFBundlePackageType') != 'XFWK' or metadata.get('XCFrameworkFormatVersion') != '1.0':
            raise ValueError('Native Tor XCFramework format changed')
        seen = {}
        for library in metadata['AvailableLibraries']:
            key = (library['SupportedPlatform'], library.get('SupportedPlatformVariant', ''))
            identifier = library['LibraryIdentifier']
            if key in seen or library['LibraryPath'] != 'RouterVPNTor.framework' or identifier not in APPLE_SLICES:
                raise ValueError('Native Tor XCFramework slice metadata is inconsistent')
            seen[key] = set(library['SupportedArchitectures'])
            architectures, simulator = APPLE_SLICES[identifier]
            if set(architectures) != seen[key] or simulator != (key[1] == 'simulator'):
                raise ValueError('Native Tor XCFramework identifier differs from its slice')
            framework = output / 'RouterVPNTor.xcframework' / identifier / library['LibraryPath']
            if (framework / 'Headers/routervpn_tor_host.h').read_bytes() != (HOST / 'routervpn_tor_host.h').read_bytes() or \
               (framework / 'Modules/module.modulemap').read_text() != FRAMEWORK_MODULE or \
               plistlib.loads((framework / 'Info.plist').read_bytes()) != framework_plist(simulator):
                raise ValueError('Native Tor framework header, module or deployment metadata changed')
            if binaries:
                verify_macho(framework, architectures, simulator)
        if seen != {('ios', ''): {'arm64'}, ('ios', 'simulator'): {'arm64', 'x86_64'}}:
            raise ValueError('Native Tor XCFramework must contain device and both simulator architectures')
        if (output / 'link/apple/RouterVPNTor.framework/RouterVPNTor.tbd').read_text() != apple_link_stub():
            raise ValueError('Native Tor Apple link stub does not match its verified dynamic ABI')
    else:
        if kind != 'host-test':
            raise ValueError('Unknown native Tor package platform')
        if binaries:
            verify_elf(output / 'lib/libroutervpn_tor.so', {'platform': kind, 'machine': 62, 'class': 2})
    checksums = ''.join(checksum + '  ' + name + '\n' for name, checksum in sorted(record['files'].items()) if name != 'SHA256SUMS')
    if (output / 'SHA256SUMS').read_text() != checksums:
        raise ValueError('Native Tor portable checksum list is inconsistent')
    return record


def publish(stage, output, kind):
    state = output_state(output, kind)
    if state == 'empty':
        for path in sorted(output.rglob('*'), key=lambda item: len(item.parts), reverse=True):
            path.rmdir()
        output.rmdir()
        state = 'missing'
    if state == 'missing':
        os.replace(stage, output)
        return
    backup = Path(tempfile.mkdtemp(prefix='.routervpn-tor-previous-', dir=output.parent))
    backup.rmdir()
    os.replace(output, backup)
    try:
        os.replace(stage, output)
    except BaseException:
        os.replace(backup, output)
        raise
    shutil.rmtree(backup)


def build(kind, output, cache, jobs, ndk=None):
    source_lock = lock()
    captured_digest = source_digest()
    output = output.parent.resolve() / output.name
    output_state(output, kind)
    try:
        verify(output, kind, ndk=ndk)
        print('Verified existing pinned Tor C package:', kind, source_digest())
        return
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError):
        pass
    for name in ('make', 'perl', 'autoconf', 'automake', 'patch', 'pkg-config'):
        if not shutil.which(name):
            raise RuntimeError(name + ' is required to build pinned native Tor sources')
    if not (shutil.which('libtoolize') or shutil.which('glibtoolize')):
        raise RuntimeError('libtool/autotools are required to build pinned native Tor sources')
    if kind == 'host-test' and (platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'AMD64')):
        raise RuntimeError('The explicit host-test package currently requires Linux x86_64')
    output.parent.mkdir(parents=True, exist_ok=True)
    if cache.is_symlink():
        raise ValueError('Native source cache must not be a link')
    cache = cache.resolve()
    archives = {name: fetch(name, record, cache) for name, record in source_lock['sources'].items()}
    work = Path(tempfile.mkdtemp(prefix='.routervpn-tor-build-', dir=output.parent))
    stage = work / 'package'
    stage.mkdir()
    targets = []
    if kind == 'android':
        for abi, goarch, host, triple, openssl, machine, elf_class in ANDROID:
            targets.append(dict(name=abi, platform=kind, abi=abi, goarch=goarch, host=host, triple=triple,
                                openssl=openssl, machine=machine, **{'class': elf_class}))
    elif kind == 'ios':
        targets = [dict(name=name, platform=kind, sdk=sdk, arch=arch, openssl=openssl) for name, sdk, arch, openssl in APPLE]
    else:
        targets = [dict(name='host-test', platform=kind, openssl='linux-x86_64', machine=62, **{'class': 2})]
    toolchains = {}
    frameworks = {}
    try:
        for target in targets:
            print('Building pinned native Tor C dependencies:', target['name'], flush=True)
            directory, sources, env, compiler, libraries = compile_dependencies(target, work, archives, source_lock, jobs, ndk)
            binary = link_library(target, stage, directory, sources, env, compiler, libraries)
            if kind == 'ios':
                verify_macho(binary, [target['arch']], target['sdk'] == 'iphonesimulator')
                frameworks[target['name']] = binary
            else:
                verify_elf(binary, target, ndk_tools(ndk)[1] if kind == 'android' else None)
            toolchains[target['name']] = run([compiler, '--version'], capture=True).strip()
            licenses = stage / 'licenses'
            licenses.mkdir(exist_ok=True)
            for name, record in source_lock['sources'].items():
                for relative in record['licenses']:
                    shutil.copyfile(sources[name] / relative, licenses / (name + '-' + Path(relative).name))
            print('Verified isolated native Tor C ABI:', target['name'], flush=True)
        if kind == 'ios':
            package_apple(stage, frameworks)
        include = stage / 'include'
        include.mkdir()
        shutil.copyfile(HOST / 'routervpn_tor_host.h', include / 'routervpn_tor_host.h')
        for relative, source in notice_sources().items():
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        if source_digest() != captured_digest:
            raise ValueError('Native Tor packaging sources changed during the captured build')
        files = tree_files(stage)
        (stage / 'SHA256SUMS').write_text(''.join(checksum + '  ' + name + '\n' for name, checksum in sorted(files.items())))
        record = dict(schema=1, platform=kind, abi=1, mobile_session_proof=False, source_sha256=captured_digest,
                      source_lock=source_lock, toolchains=toolchains, files=tree_files(stage),
                      pt_notices={relative: sha(path) for relative, path in notice_sources().items()})
        (stage / 'source.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
        verify(stage, kind, ndk=ndk)
        publish(stage, output, kind)
        # Keep compiler/configure logs for CI diagnostics; archives and object
        # files are disposable once their verified package has been published.
        for path in work.iterdir():
            if path.is_dir():
                for child in path.iterdir():
                    if child.is_dir():
                        shutil.rmtree(child)
                    elif child.suffix not in ('.log', '.map', '.txt'):
                        child.unlink()
        print('Pinned isolated Tor C package complete:', output, flush=True)
    except BaseException:
        print('Native Tor build evidence remains at:', work, flush=True)
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=('android', 'ios', 'host-test'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--source-cache', type=Path)
    parser.add_argument('--ndk', type=Path)
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest:
        lock()
        print(source_digest())
    else:
        if not args.platform or not args.output or not 1 <= args.jobs <= 16:
            parser.error('--platform, --output and 1..16 jobs are required')
        if args.verify:
            verify(args.output.parent.resolve() / args.output.name, args.platform, ndk=args.ndk)
            print('Verified exact native Tor C package:', args.platform)
        else:
            build(args.platform, args.output.absolute(), args.source_cache or args.output.parent / '.routervpn-tor-sources', args.jobs, args.ndk)
