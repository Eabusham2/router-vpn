#!/usr/bin/env python3
"""Exercise final mobile Tor package checks with real cross-linked consumers."""
from pathlib import Path
import argparse
import importlib.util
import json
import shutil
import struct
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('routervpn_tor_link', ROOT / 'deploy/verify-mobile-tor-link.py')
LINK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(LINK)
PACKAGE = LINK.PACKAGE
CHECKS = 0


def passed():
    global CHECKS
    CHECKS += 1


def reject(call, label):
    try:
        call()
    except (ValueError, OSError, KeyError):
        passed()
        return
    raise AssertionError('Native package negative was accepted: ' + label)


C_SOURCE = r'''
#include "routervpn_tor_host.h"
int routervpn_link_fixture(const char *const *args, size_t count) {
 uint64_t handle=0; int32_t code=0;
#ifdef INCOMPLETE_OWNER
 (void)args; (void)count; (void)handle; (void)code;
 return routervpn_tor_abi()+routervpn_tor_version()[0];
#else
 return routervpn_tor_abi()+routervpn_tor_version()[0]+routervpn_tor_start(args,count,&handle)
  +routervpn_tor_control(handle)+routervpn_tor_status(handle,&code)+routervpn_tor_close(handle,0);
#endif
}
'''


def archive(path, files):
    with zipfile.ZipFile(path, 'w') as output:
        for name, content in files.items():
            output.writestr(name, content)


def android_checks(root, native_package, ndk):
    PACKAGE.verify(native_package, 'android', ndk=ndk)
    tools = PACKAGE.ndk_tools(ndk)[1]
    source = root / 'consumer.c'; source.write_text(C_SOURCE)
    consumers = {}
    for abi, _, _, triple, _, machine, elf_class in PACKAGE.ANDROID:
        output = root / (abi + '-consumer.so')
        command = [tools / (triple + '24-clang'), '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                   '-I' + str(native_package / 'include'), source, '-L' + str(native_package / 'jni' / abi),
                   '-lroutervpn_tor', '-Wl,-z,max-page-size=16384', '-Wl,-z,common-page-size=16384', '-o', output]
        subprocess.run([str(value) for value in command], check=True)
        LINK.android_consumer(output, tools, machine, elf_class); passed()
        consumers[abi] = output.read_bytes()
        missing = root / (abi + '-incomplete-owner.so')
        subprocess.run([str(value) for value in command[:-1]] + [str(missing), '-DINCOMPLETE_OWNER=1'], check=True)
        reject(lambda: LINK.android_consumer(missing, tools, machine, elf_class), abi + ' missing owner functions')
    aar_files = {'jni/' + abi + '/libbox.so': content for abi, content in consumers.items()}
    aar = root / 'consumer.aar'; archive(aar, aar_files)
    LINK.android(native_package, aar, False, ndk); passed()
    apk_files = {'lib/' + abi + '/libbox.so': content for abi, content in consumers.items()}
    for abi, *_ in PACKAGE.ANDROID:
        apk_files['lib/' + abi + '/libroutervpn_tor.so'] = (native_package / 'jni' / abi / 'libroutervpn_tor.so').read_bytes()
    for name, content in LINK.NOTICES.payload(native_package).items():
        apk_files['assets/third-party/routervpn-tor/' + name] = content
    apk = root / 'consumer.apk'; archive(apk, apk_files)
    LINK.android(native_package, apk, True, ndk); passed()
    for label, name, content in (
        ('missing native ABI', 'lib/x86/libroutervpn_tor.so', None),
        ('changed native library', 'lib/arm64-v8a/libroutervpn_tor.so', b'changed'),
        ('missing C license', 'assets/third-party/routervpn-tor/licenses/tor-LICENSE', None),
        ('changed PT lock', 'assets/third-party/routervpn-tor/notices/mobile/torpt/SOURCE_LOCK.json', b'{}'),
        ('wrong consumer ABI', 'lib/x86/libbox.so', consumers['arm64-v8a'])):
        files = dict(apk_files)
        if content is None:
            files.pop(name)
        else:
            files[name] = content
        altered = root / (label.replace(' ', '-') + '.apk'); archive(altered, files)
        reject(lambda: LINK.android(native_package, altered, True, ndk), label)
        altered.unlink()


def notice_checks(root, native_package):
    output = root / 'tor-notices'
    LINK.NOTICES.stage(native_package, output)
    original = LINK.NOTICES.read_tree(output)
    LINK.NOTICES.stage(native_package, output)
    assert LINK.NOTICES.read_tree(output) == original
    passed()
    (output / 'licenses/tor-LICENSE').write_text('unowned change')
    changed = LINK.NOTICES.read_tree(output)
    reject(lambda: LINK.NOTICES.stage(native_package, output), 'changed notice file')
    assert LINK.NOTICES.read_tree(output) == changed
    passed()
    (output / 'licenses/tor-LICENSE').write_bytes(original['licenses/tor-LICENSE'])
    (output / 'unrelated.txt').write_text('unrelated file')
    reject(lambda: LINK.NOTICES.stage(native_package, output), 'unrelated notice output file')
    alias = root / 'linked-notices'; alias.symlink_to(output, target_is_directory=True)
    reject(lambda: LINK.NOTICES.stage(native_package, alias), 'linked notice output root')


def macho_checks(root):
    # Explicit parser fixture: no Apple SDK or device execution is claimed.
    # Verify that text/data mutations are distinguished from signing metadata.
    data = bytearray(384)
    struct.pack_into('<IIIIIIII', data, 0, 0xfeedfacf, 0x0100000c, 0, 6, 1, 232, 0, 0)
    struct.pack_into('<II16sQQQQIIII', data, 32, 0x19, 232, b'__TEXT', 0, 4096, 0, len(data), 5, 5, 2, 0)
    struct.pack_into('<16s16sQQIIIIIIII', data, 104, b'__text', b'__TEXT', 320, 4, 320, 2, 0, 0, 0, 0, 0, 0)
    struct.pack_into('<16s16sQQIIIIIIII', data, 184, b'__bss', b'__DATA', 4096, 32, 0, 3, 0, 0, 1, 0, 0, 0)
    data[320:324] = b'code'
    binary = root / 'thin-macho'; binary.write_bytes(data)
    original = LINK.file_sections(binary)
    assert original[(b'__DATA', b'__bss')] == (32, 'zero-fill')
    passed()
    signed = root / 'signed-macho'; signed.write_bytes(data + b'code-signature-trailer-fixture')
    assert LINK.file_sections(signed) == original
    passed()
    data[320] ^= 1; binary.write_bytes(data)
    assert LINK.file_sections(binary) != original
    passed()
    struct.pack_into('<I', data, 104 + 48, 999999); binary.write_bytes(data)
    reject(lambda: LINK.file_sections(binary), 'Mach-O section bounds')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-package', type=Path, required=True)
    parser.add_argument('--ndk', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='routervpn-tor-packaged-link-') as temporary:
        root = Path(temporary)
        android_checks(root, args.native_package, args.ndk)
        notice_checks(root, args.native_package)
        macho_checks(root)
    print('PASS mobile Tor package contents and actual cross-linked consumer gates:', CHECKS, 'checks')
