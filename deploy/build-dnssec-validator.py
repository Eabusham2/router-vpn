#!/usr/bin/env python3
"""Build the pinned private validator; never selects ambient crypto libraries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'native/dnssec'

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def extract(archive, destination, spec):
    if digest(archive) != spec['archive_sha256']:
        raise ValueError('source archive hash mismatch: ' + str(archive))
    destination.mkdir()
    with tarfile.open(archive) as tar:
        tar.extractall(destination, filter='data')
    roots = list(destination.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
        raise ValueError('archive must contain one source root')
    source = roots[0]
    for name, expected in spec['licenses'].items():
        if digest(source / name) != expected:
            raise ValueError('license hash mismatch: ' + name)
    return source

def build_environment(home, temporary, epoch):
    return {'PATH':'/usr/bin:/bin', 'HOME':str(home), 'TMPDIR':str(temporary),
            'LC_ALL':'C', 'TZ':'UTC', 'SOURCE_DATE_EPOCH':str(epoch),
            'CONFIG_SITE':'/dev/null', 'PKG_CONFIG':'false',
            'CC':'/usr/bin/cc', 'CXX':'/usr/bin/c++', 'AR':'/usr/bin/ar',
            'RANLIB':'/usr/bin/ranlib', 'NM':'/usr/bin/nm'}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--unbound-archive', type=Path, required=True)
    p.add_argument('--openssl-archive', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--jobs', type=int, default=2)
    args = p.parse_args()
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'aarch64'):
        p.error('initial prerequisite supports native Linux amd64/arm64 only')
    if not 1 <= args.jobs <= 16:
        p.error('jobs must be between 1 and 16')
    out = args.output.resolve()
    out.mkdir()  # Refuse stale or mixed builds.
    inputs = {str(path):digest(path) for path in (SOURCE / 'validator.c', SOURCE / 'validator.h', SOURCE / 'sources.json', Path(__file__).resolve())}
    spec = json.loads((SOURCE / 'sources.json').read_text())
    openssl = extract(args.openssl_archive, out / 'openssl', spec['openssl'])
    unbound = extract(args.unbound_archive, out / 'unbound', spec['unbound'])
    # Upstream unconditionally checks expat for unbound-anchor, which this
    # library-only build never builds or links. Verify the exact build-system
    # block before excluding it; no validator/resolver source is patched.
    configure = unbound / 'configure'
    original = configure.read_text()
    start = original.index('# check for libexpat\n')
    end = original.index('# hiredis (redis C client for cachedb)\n', start)
    excluded = original[start:end]
    if hashlib.sha256(excluded.encode()).hexdigest() != 'e36da3b8403ee6723434ad496633843b38655902f794f15d321bba4c29d85825':
        raise ValueError('pinned expat configure block changed')
    configure.write_text(original[:start] + '# Library-only: no unbound-anchor/expat.\n' + original[end:])
    if digest(configure) != 'f4b9df17aab6933befc8041f6c57c1dc7b869e52dfacbab6a4b0d80cd6500792':
        raise ValueError('projected configure hash mismatch')
    prefix = out / 'prefix'
    # A positive environment allowlist excludes cross/toolchain/config inputs,
    # including compiler search paths, loader variables and shell startup files.
    home, temporary = out / 'build-home', out / 'tmp'
    home.mkdir(); temporary.mkdir()
    maps = ['-ffile-prefix-map=' + str(out) + '=/routervpn-dnssec-build',
            '-ffile-prefix-map=' + str(ROOT) + '=/routervpn-source']
    env = build_environment(home, temporary, spec['source_date_epoch'])
    env['CFLAGS'] = ' '.join(['-O2', '-fPIC'] + maps)
    env['LDFLAGS'] = '-Wl,-z,noexecstack'
    commands = []
    def run(argv, cwd):
        commands.append(argv)
        subprocess.run(argv, cwd=cwd, env=env, check=True)
    run(['./Configure', 'linux-x86_64' if platform.machine() == 'x86_64' else 'linux-aarch64',
         'no-shared', 'no-tests', 'no-module', 'no-dso', 'no-engine', 'no-zlib',
         '-fPIC', *maps, '--prefix=' + str(prefix), '--libdir=lib'], openssl)
    run(['make', '-j' + str(args.jobs), 'build_libs'], openssl)
    run(['make', 'install_dev'], openssl)
    run(['./configure', '--prefix=' + str(prefix), '--disable-shared', '--enable-static',
         '--with-pic', '--with-ssl=' + str(prefix), '--with-libevent=no',
         '--with-libhiredis=no', '--with-libnghttp2=no',
         '--with-libmnl=no', '--with-pthreads', '--without-pythonmodule',
         '--without-pyunbound', '--with-rootkey-file=/nonexistent/routervpn-no-rootkey'], unbound)
    run(['make', '-j' + str(args.jobs), 'lib'], unbound)
    run(['make', 'install-lib'], unbound)
    # The ABI shim deliberately exports no dependency ABI or internal symbols.
    artifact = out / 'libroutervpn_dnssec.so'
    run(['/usr/bin/cc', *maps, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
         '-fvisibility=hidden', '-I' + str(prefix / 'include'), str(SOURCE / 'validator.c'),
         '-Wl,--exclude-libs,ALL', '-Wl,-z,defs', '-Wl,-z,relro,-z,now,-z,noexecstack',
         str(prefix / 'lib/libunbound.a'), str(prefix / 'lib/libssl.a'),
         str(prefix / 'lib/libcrypto.a'), '-lpthread', '-ldl', '-o', str(artifact)], out)
    archive_symbols = subprocess.check_output(['/usr/bin/nm', '-u', str(prefix / 'lib/libunbound.a')], text=True)
    if any('XML_' in line for line in archive_symbols.splitlines()):
        raise ValueError('unexpected expat reference in libunbound archive')
    dependencies = subprocess.check_output(['/usr/bin/readelf', '-d', str(artifact)], text=True)
    needed = [line.split('[')[1].split(']')[0] for line in dependencies.splitlines() if '(NEEDED)' in line]
    if any(name not in ('libc.so.6', 'libpthread.so.0', 'libdl.so.2') for name in needed):
        raise ValueError('unexpected dynamic dependency: ' + repr(needed))
    elf = artifact.read_bytes()
    machine = int.from_bytes(elf[18:20], 'little')
    if elf[:6] != b'\x7fELF\x02\x01' or machine != (62 if platform.machine() == 'x86_64' else 183):
        raise ValueError('wrong ELF class, endian or target machine')
    exports = subprocess.check_output(['/usr/bin/nm', '-D', '--defined-only', str(artifact)], text=True)
    symbols = [line.split()[-1] for line in exports.splitlines()]
    expected = ['rvdns_' + x for x in ('abi','create','anchor','insecure','start','fd','process','cancel','result','destroy')]
    if sorted(symbols) != sorted(expected):
        raise ValueError('unexpected ABI exports: ' + repr(symbols))
    licenses = out / 'licenses'
    licenses.mkdir()
    for name, tree in [('unbound', unbound), ('openssl', openssl)]:
        for filename in spec[name]['licenses']:
            (licenses / (name + '-' + filename)).write_bytes((tree / filename).read_bytes())
    if any(digest(Path(path)) != expected for path, expected in inputs.items()):
        raise ValueError('build inputs changed during compilation')
    manifest = {'schema':1, 'abi':1, 'platform':'linux', 'architecture':platform.machine(),
                'sources':spec, 'artifact_sha256':digest(artifact), 'artifact_size':len(elf), 'elf_machine':machine,
                'configure_projection':{'original_sha256':hashlib.sha256(original.encode()).hexdigest(),
                    'removed_block_sha256':hashlib.sha256(excluded.encode()).hexdigest(),
                    'projected_sha256':digest(configure)},
                'shim_sha256':digest(SOURCE / 'validator.c'),
                'header_sha256':digest(SOURCE / 'validator.h'),
                'builder_sha256':digest(Path(__file__).resolve()), 'exports':symbols, 'needed':needed, 'commands':commands,
                'compiler':subprocess.check_output(['/usr/bin/cc', '--version'], text=True)}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')

if __name__ == '__main__':
    main()
