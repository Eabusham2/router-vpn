#!/usr/bin/env python3
"""Execute package/source ownership checks and real ELF isolation negatives."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import io
import json
import os
import plistlib
import shutil
import struct
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('routervpn_tor_package', ROOT / 'deploy/build-mobile-tor-package.py')
PACKAGE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PACKAGE)
CHECKS = 0


def passed():
    global CHECKS
    CHECKS += 1


def reject(call, label):
    try:
        call()
    except (ValueError, OSError, KeyError, TypeError):
        passed()
        return
    raise AssertionError('Native package negative was accepted: ' + label)


def refresh(output, kind):
    files = PACKAGE.tree_files(output)
    (output / 'SHA256SUMS').write_text(''.join(checksum + '  ' + name + '\n'
        for name, checksum in sorted(files.items()) if name != 'SHA256SUMS'))
    record = dict(schema=1, platform=kind, abi=1, mobile_session_proof=False,
                  source_sha256=PACKAGE.source_digest(), source_lock=PACKAGE.lock(),
                  padding_extension=PACKAGE.PADDING.receipt(),
                  files=PACKAGE.tree_files(output), toolchains={'policy-fixture': 'no mobile compiler claim'},
                  pt_notices={relative: PACKAGE.sha(path) for relative, path in PACKAGE.notice_sources().items()})
    (output / 'source.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')


def dependency_bytes(cache):
    result = {}
    for name, record in PACKAGE.lock()['sources'].items():
        archive = cache / (name + '-' + record['commit'] + '.tar.gz')
        if PACKAGE.sha(archive) != record['archive_sha256']:
            raise ValueError('Source policy gate requires the verified archive cache')
        prefix = record['repository'].rsplit('/', 1)[-1] + '-' + record['commit']
        with tarfile.open(archive) as source:
            for relative, expected in record['licenses'].items():
                content = source.extractfile(prefix + '/' + relative).read()
                assert hashlib.sha256(content).hexdigest() == expected
                result['licenses/' + name + '-' + Path(relative).name] = content
    return result


def fixture(output, kind, licenses):
    output.mkdir()
    for name in PACKAGE.package_paths(kind):
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'layout-fixture: no compiled mobile payload\n')
    for relative, content in licenses.items():
        (output / relative).write_bytes(content)
    shutil.copyfile(PACKAGE.HOST / 'routervpn_tor_host.h', output / 'include/routervpn_tor_host.h')
    for relative, source in PACKAGE.notice_sources().items():
        shutil.copyfile(source, output / relative)
    if kind == 'ios':
        libraries = []
        for identifier, (architectures, simulator) in PACKAGE.APPLE_SLICES.items():
            framework = output / 'RouterVPNTor.xcframework' / identifier / 'RouterVPNTor.framework'
            shutil.copyfile(PACKAGE.HOST / 'routervpn_tor_host.h', framework / 'Headers/routervpn_tor_host.h')
            (framework / 'Modules/module.modulemap').write_text(PACKAGE.FRAMEWORK_MODULE)
            (framework / 'Info.plist').write_bytes(plistlib.dumps(PACKAGE.framework_plist(simulator)))
            entry = dict(LibraryIdentifier=identifier, LibraryPath='RouterVPNTor.framework',
                         SupportedArchitectures=architectures, SupportedPlatform='ios')
            if simulator:
                entry['SupportedPlatformVariant'] = 'simulator'
            libraries.append(entry)
        (output / 'RouterVPNTor.xcframework/Info.plist').write_bytes(plistlib.dumps(dict(
            AvailableLibraries=libraries, CFBundlePackageType='XFWK', XCFrameworkFormatVersion='1.0')))
        (output / 'link/apple/RouterVPNTor.framework/RouterVPNTor.tbd').write_text(PACKAGE.apple_link_stub())
    refresh(output, kind)
    PACKAGE.verify(output, kind, binaries=False)
    passed()


def change_json(path, mutate):
    value = json.loads(path.read_text())
    mutate(value)
    path.write_text(json.dumps(value))


def change_plist(path, mutate):
    value = plistlib.loads(path.read_bytes())
    mutate(value)
    path.write_bytes(plistlib.dumps(value))


def package_checks(root, licenses):
    bases = {}
    for kind in ('host-test', 'android', 'ios'):
        bases[kind] = root / kind
        fixture(bases[kind], kind, licenses)
    index = 0

    def negative(kind, label, mutate, rehash=True):
        nonlocal index
        index += 1
        output = root / ('negative-' + str(index))
        shutil.copytree(bases[kind], output)
        mutate(output)
        if rehash:
            refresh(output, kind)
        reject(lambda: PACKAGE.verify(output, kind, binaries=False), label)

    negative('host-test', 'changed owned binary bytes', lambda out: (out / 'lib/libroutervpn_tor.so').write_bytes(b'foreign'), False)
    negative('host-test', 'forged unrelated owned filename', lambda out: (out / 'user-document.txt').write_text('unrelated'))
    negative('host-test', 'removed dependency license', lambda out: (out / 'licenses/tor-LICENSE').unlink())
    negative('host-test', 'changed dependency license', lambda out: (out / 'licenses/openssl-LICENSE.txt').write_text('wrong license'))
    negative('host-test', 'wrong ABI header', lambda out: (out / 'include/routervpn_tor_host.h').write_text('wrong ABI'))
    negative('host-test', 'missing PT lock', lambda out: (out / 'notices/mobile/torpt/SOURCE_LOCK.json').unlink())
    negative('host-test', 'changed PT notice', lambda out: (out / 'notices/mobile/torpt/internal/meeklite/LICENSE').write_text('wrong notice'))
    negative('host-test', 'stale source digest', lambda out: change_json(out / 'source.json', lambda record: record.update(source_sha256='0' * 64)), False)
    negative('host-test', 'fabricated mobile protection claim', lambda out: change_json(out / 'source.json', lambda record: record.update(mobile_session_proof=True)), False)
    for data in (None, {'version': True}, {'version': 1, 'direction': 'bidirectional'}):
        negative('host-test', 'missing or fabricated native cover receipt',
                 lambda out, value=data: change_json(out / 'source.json', lambda record: record.update(padding_extension=value)), False)
    negative('host-test', 'changed portable checksum list', lambda out: (out / 'SHA256SUMS').write_text(''), False)
    negative('android', 'missing 32-bit Android ABI', lambda out: (out / 'jni/armeabi-v7a/libroutervpn_tor.so').unlink())
    negative('android', 'foreign native Go payload', lambda out: (out / 'jni/arm64-v8a/libgojni.so').write_text('second runtime'))
    negative('ios', 'missing simulator binary', lambda out: (out / 'RouterVPNTor.xcframework/ios-arm64_x86_64-simulator/RouterVPNTor.framework/RouterVPNTor').unlink())
    negative('ios', 'wrong simulator platform', lambda out: change_plist(out / 'RouterVPNTor.xcframework/Info.plist',
             lambda value: value['AvailableLibraries'][1].update(SupportedPlatformVariant='device')))
    negative('ios', 'missing simulator architecture', lambda out: change_plist(out / 'RouterVPNTor.xcframework/Info.plist',
             lambda value: value['AvailableLibraries'][1].update(SupportedArchitectures=['arm64'])))
    negative('ios', 'weakened deployment target', lambda out: change_plist(out / 'RouterVPNTor.xcframework/ios-arm64/RouterVPNTor.framework/Info.plist',
             lambda value: value.update(MinimumOSVersion='15.0')))
    negative('ios', 'wrong framework header', lambda out: (out / 'RouterVPNTor.xcframework/ios-arm64/RouterVPNTor.framework/Headers/routervpn_tor_host.h').write_text('stale'))
    negative('ios', 'wrong framework link target', lambda out: (out / 'link/apple/RouterVPNTor.framework/RouterVPNTor.tbd').write_text(PACKAGE.apple_link_stub().replace('arm64-ios,', 'arm64-macos,')))
    linked = root / 'linked-root'; linked.symlink_to(bases['host-test'], target_is_directory=True)
    reject(lambda: PACKAGE.verify(linked, 'host-test', binaries=False), 'symlink output root')
    output = root / 'linked-entry'; shutil.copytree(bases['host-test'], output)
    (output / 'include/routervpn_tor_host.h').unlink()
    (output / 'include/routervpn_tor_host.h').symlink_to(PACKAGE.HOST / 'routervpn_tor_host.h')
    reject(lambda: PACKAGE.verify(output, 'host-test', binaries=False), 'symlink package entry')
    output = root / 'changed-owned'; shutil.copytree(bases['host-test'], output)
    (output / 'lib/libroutervpn_tor.so').write_bytes(b'user change')
    before = {str(path.relative_to(output)): path.read_bytes() for path in output.rglob('*') if path.is_file()}
    stage = root / 'publish-stage'; shutil.copytree(bases['host-test'], stage)
    reject(lambda: PACKAGE.publish(stage, output, 'host-test'), 'publish overwrites changed owned data')
    assert before == {str(path.relative_to(output)): path.read_bytes() for path in output.rglob('*') if path.is_file()}
    assert stage.is_dir()
    passed()


def archive_checks(root):
    prefix = 'fixture-' + 'a' * 40
    cases = [('valid', None), ('traversal', prefix + '/../escape'), ('absolute', '/escape'),
             ('duplicate', prefix + '/LICENSE'), ('wrong-root', 'other/LICENSE'), ('symlink', 'symlink'), ('fifo', 'fifo')]
    for label, bad in cases:
        archive = root / (label + '.tar.gz')
        with tarfile.open(archive, 'w:gz') as output:
            for name, content in ((prefix + '/LICENSE', b'license\n'), (prefix + '/src/file.c', b'source\n')):
                member = tarfile.TarInfo(name); member.size = len(content); member.mode = 0o644
                output.addfile(member, io.BytesIO(content))
            if bad:
                member = tarfile.TarInfo(prefix + '/' + bad if bad in ('symlink', 'fifo') else bad)
                if bad == 'symlink':
                    member.type = tarfile.SYMTYPE; member.linkname = '/tmp/escape'
                elif bad == 'fifo':
                    member.type = tarfile.FIFOTYPE
                output.addfile(member)
        record = dict(repository='https://github.com/test/fixture', commit='a' * 40,
                      archive_sha256=PACKAGE.sha(archive), licenses={'LICENSE': hashlib.sha256(b'license\n').hexdigest()})
        destination = root / ('extract-' + label)
        if bad:
            reject(lambda: PACKAGE.extract(archive, record, destination), label)
            assert not list(destination.rglob('*')), 'Unsafe archive wrote before full validation'
        else:
            PACKAGE.extract(archive, record, destination)
            assert (destination / 'src/file.c').read_bytes() == b'source\n'
            passed()
            record['archive_sha256'] = '0' * 64
            reject(lambda: PACKAGE.extract(archive, record, root / 'changed-archive'), 'changed archive checksum')


def patch_checks(root, cache):
    source_lock = PACKAGE.lock()
    pin = source_lock['sources']['tor']
    archive = cache / ('tor-' + pin['commit'] + '.tar.gz')
    assert PACKAGE.sha(archive) == pin['archive_sha256']
    names = ['src/lib/evloop/workqueue.c', *source_lock['embedded_process_sha256'],
             *PACKAGE.PADDING.lock()['files']]
    with tarfile.open(archive) as source:
        originals = {name: source.extractfile('tor-' + pin['commit'] + '/' + name).read() for name in names}

    def original(directory):
        directory.mkdir()
        for name, content in originals.items():
            path = directory / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)

    output = root / 'pinned-tor-patch'; original(output)
    PACKAGE.patch_source(output, source_lock)
    PACKAGE.PADDING.verify(output)
    for name, record in source_lock['embedded_process_sha256'].items():
        assert PACKAGE.sha(output / name) == record['patched']
    passed()
    for index, name in enumerate(names):
        output = root / ('foreign-tor-patch-' + str(index)); original(output)
        with (output / name).open('ab') as stream:
            stream.write(b'\n/* unowned source mutation */\n')
        reject(lambda: PACKAGE.patch_source(output, source_lock), 'changed pinned worker/process/config source')
    for index, record in enumerate(PACKAGE.PADDING.lock()['copies'].values()):
        modified = root / ('changed-padding-copy-' + str(index))
        shutil.copytree(root / 'pinned-tor-patch', modified)
        with (modified / record['target']).open('ab') as stream:
            stream.write(b'\n/* changed owned extension */\n')
        reject(lambda: PACKAGE.PADDING.verify(modified), 'changed owned padding source')
    linked = root / 'linked-padding-source'
    shutil.copytree(root / 'pinned-tor-patch', linked)
    source_file = linked / 'src/feature/control/routervpn_padding.c'
    source_file.unlink()
    source_file.symlink_to(root / 'pinned-tor-patch/src/feature/control/routervpn_padding.c')
    reject(lambda: PACKAGE.PADDING.verify(linked), 'linked padding source')


ELF_SOURCE = r'''
#include "routervpn_tor_host.h"
#include <stdlib.h>
#include <unistd.h>
int32_t routervpn_tor_abi(void) {
#ifdef BAD_FORK
 if(getenv("ROUTERVPN_TEST_UNUSED")) return (int32_t)fork();
#else
 if(getenv("ROUTERVPN_TEST_UNUSED")) return 0;
#endif
 return 1;
}
const char *routervpn_tor_version(void) { return "tor 0.4.9.14"; }
int32_t routervpn_tor_start(const char *const *args,size_t count,uint64_t *handle) {(void)args;(void)count;*handle=0;return -1;}
int32_t routervpn_tor_control(uint64_t handle) {(void)handle;return -1;}
int32_t routervpn_tor_status(uint64_t handle,int32_t *code) {(void)handle;*code=0;return -1;}
int32_t routervpn_tor_close(uint64_t handle,uint32_t wait) {(void)handle;(void)wait;return -1;}
int routervpn_unowned_export(void) { return 0; }
'''


def elf_checks(root):
    if os.uname().sysname != 'Linux' or os.uname().machine != 'x86_64':
        print('ELF executable negatives require Linux x86_64; Apple layout/source checks remain executable')
        return
    compiler = shutil.which('cc')
    if not compiler:
        raise RuntimeError('C compiler required for actual ELF package negatives')
    source = root / 'policy.c'; source.write_text(ELF_SOURCE)
    target = {'platform': 'host-test', 'machine': 62, 'class': 2}
    common = ['-shared', '-fPIC', '-Wall', '-Wextra', '-Werror', '-I' + str(PACKAGE.HOST),
              '-Wl,--no-undefined', '-Wl,-soname,libroutervpn_tor.so', '-Wl,-z,max-page-size=16384',
              '-Wl,-z,common-page-size=16384', '-Wl,-z,now', '-Wl,-z,relro', '-Wl,-z,noexecstack']
    for label in ('valid', 'missing-symbolic', 'extra-export', 'fork-import', 'executable-stack'):
        output = root / ('elf-' + label + '.so')
        symbols = list(PACKAGE.EXPORTS) + (['routervpn_unowned_export'] if label == 'extra-export' else [])
        exported = root / (label + '.map'); exported.write_text('{ global: ' + '; '.join(symbols) + '; local: *; };\n')
        flags = ([] if label == 'missing-symbolic' else ['-Wl,-Bsymbolic'])
        if label == 'fork-import':
            flags.append('-DBAD_FORK=1')
        if label == 'executable-stack':
            flags.append('-Wl,-z,execstack')
        subprocess.run([compiler, source, *common, *flags, '-Wl,--version-script=' + str(exported), '-o', output], check=True)
        if label == 'valid':
            PACKAGE.verify_elf(output, target); passed()
        else:
            reject(lambda: PACKAGE.verify_elf(output, target), label)
    source = root / 'elf-valid.so'
    reject(lambda: PACKAGE.verify_elf(source, dict(target, machine=40, **{'class': 1})), 'wrong ELF architecture')
    data = bytearray(source.read_bytes())
    offset = struct.unpack_from('<Q', data, 32)[0]; size, count = struct.unpack_from('<HH', data, 54)
    for index in range(count):
        start = offset + index * size
        if struct.unpack_from('<I', data, start)[0] == 1:
            struct.pack_into('<Q', data, start + 48, 4096)
            break
    altered = root / 'small-page.so'; altered.write_bytes(data)
    reject(lambda: PACKAGE.verify_elf(altered, target), '4 KiB only ELF segment')


def main(cache):
    licenses = dependency_bytes(cache)
    with tempfile.TemporaryDirectory(prefix='routervpn-tor-package-policy-') as temporary:
        root = Path(temporary)
        package_checks(root, licenses)
        archive_checks(root)
        patch_checks(root, cache)
        elf_checks(root)
    print('PASS pinned Tor package policy:', CHECKS, 'executable layout, source, ownership and ELF checks')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-cache', type=Path, required=True)
    main(parser.parse_args().source_cache)
