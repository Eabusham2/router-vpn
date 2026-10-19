#!/usr/bin/env python3
"""Require the real Tor C ABI in Libbox and the final packaged mobile app."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import plistlib
import re
import struct
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


PACKAGE = module('routervpn_tor_package', 'deploy/build-mobile-tor-package.py')
NOTICES = module('routervpn_tor_notices', 'deploy/stage-mobile-tor-notices.py')
INSTALL_NAME = '@rpath/RouterVPNTor.framework/RouterVPNTor'


def android_consumer(path, tools, machine, elf_class):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF' + bytes((elf_class, 1)) or struct.unpack_from('<HH', data, 16) != (3, machine):
        raise ValueError('Libbox consumer has the wrong native Android ABI')
    dynamic = PACKAGE.run([tools / 'llvm-readelf', '-d', path], capture=True)
    needed = re.findall(r'Shared library: \[([^\]]+)\]', dynamic)
    if needed.count('libroutervpn_tor.so') != 1:
        raise ValueError('Libbox must directly link exactly one packaged Tor C library')
    imports = PACKAGE.run([tools / 'llvm-nm', '-D', '--undefined-only', '--format=posix', path], capture=True)
    imported = {line.split()[0].split('@')[0] for line in imports.splitlines() if line.strip()}
    if not set(PACKAGE.EXPORTS) <= imported:
        raise ValueError('Libbox does not consume every owning Tor C ABI function')


def android(native_package, archive, apk, ndk=None):
    PACKAGE.verify(native_package, 'android', ndk=ndk)
    tools = PACKAGE.ndk_tools(ndk)[1]
    with zipfile.ZipFile(archive) as source, tempfile.TemporaryDirectory(prefix='routervpn-tor-consumer-') as temporary:
        names = source.namelist()
        if len(names) != len(set(names)):
            raise ValueError('Mobile archive contains duplicate paths')
        root = Path(temporary)
        prefix = 'lib/' if apk else 'jni/'
        for abi, _, _, _, _, machine, elf_class in PACKAGE.ANDROID:
            consumer = root / (abi + '-libbox.so')
            consumer.write_bytes(source.read(prefix + abi + '/libbox.so'))
            android_consumer(consumer, tools, machine, elf_class)
            if apk:
                content = source.read(prefix + abi + '/libroutervpn_tor.so')
                if hashlib.sha256(content).hexdigest() != PACKAGE.sha(native_package / 'jni' / abi / 'libroutervpn_tor.so'):
                    raise ValueError('APK changed the exact verified native Tor C library')
        if apk:
            for relative, content in NOTICES.payload(native_package).items():
                if source.read('assets/third-party/routervpn-tor/' + relative) != content:
                    raise ValueError('APK is missing or changed a native Tor/PT source notice')


def apple_libbox(native_package, framework):
    PACKAGE.verify(native_package, 'ios')
    metadata = plistlib.loads((framework / 'Info.plist').read_bytes())
    for library in metadata['AvailableLibraries']:
        if library['SupportedPlatform'] != 'ios':
            continue
        directory = framework / library['LibraryIdentifier'] / library['LibraryPath']
        binary = directory / 'Libbox' if directory.is_dir() else directory
        for architecture in library['SupportedArchitectures']:
            imports = set(PACKAGE.run(['xcrun', 'nm', '-arch', architecture, '-uj', binary], capture=True).split())
            if not {'_' + name for name in PACKAGE.EXPORTS} <= imports:
                raise ValueError('Libbox Apple archive omits the real owning Tor C ABI')


def file_sections(binary):
    """Compare linked C bytes while allowing the containing app to code-sign."""
    data = binary.read_bytes()
    if data[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError('Native Tor comparison requires a thin 64-bit Mach-O slice')
    count = struct.unpack_from('<I', data, 16)[0]
    position = 32
    sections = {}
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, position)
        if size < 8 or position + size > len(data):
            raise ValueError('Native Tor Mach-O load commands are incomplete')
        if command == 0x19:
            section_count = struct.unpack_from('<I', data, position + 64)[0]
            if 72 + section_count * 80 > size:
                raise ValueError('Native Tor Mach-O sections are incomplete')
            for index in range(section_count):
                start = position + 72 + index * 80
                name = data[start:start + 16].split(b'\0')[0]
                segment = data[start + 16:start + 32].split(b'\0')[0]
                length = struct.unpack_from('<Q', data, start + 40)[0]
                offset = struct.unpack_from('<I', data, start + 48)[0]
                flags = struct.unpack_from('<I', data, start + 64)[0]
                key = (segment, name)
                if key in sections:
                    raise ValueError('Native Tor Mach-O contains duplicate sections')
                if flags & 255 in (1, 12, 18):
                    sections[key] = (length, 'zero-fill')
                else:
                    if offset + length > len(data):
                        raise ValueError('Native Tor Mach-O section escaped its binary')
                    sections[key] = (length, hashlib.sha256(data[offset:offset + length]).hexdigest())
        position += size
    if not sections or (b'__TEXT', b'__text') not in sections:
        raise ValueError('Native Tor framework contains no compiled C text')
    return sections


def apple_app(native_package, app):
    PACKAGE.verify(native_package, 'ios')
    NOTICES.verify(app / 'tor-notices', NOTICES.payload(native_package))
    embedded = app / 'Frameworks/RouterVPNTor.framework'
    if [path for path in app.rglob('RouterVPNTor.framework') if path.is_dir()] != [embedded]:
        raise ValueError('The containing app must embed exactly one native Tor framework')
    binary = embedded / 'RouterVPNTor'
    architectures = PACKAGE.run(['xcrun', 'lipo', '-archs', binary], capture=True).split()
    commands = PACKAGE.run(['xcrun', 'otool', '-arch', architectures[0], '-l', binary], capture=True)
    simulator = bool(re.search(r'\bplatform\s+(7|IOSSIMULATOR)\b', commands))
    PACKAGE.verify_macho(embedded, architectures, simulator)
    identifier = 'ios-arm64_x86_64-simulator' if simulator else 'ios-arm64'
    original = native_package / 'RouterVPNTor.xcframework' / identifier / 'RouterVPNTor.framework/RouterVPNTor'
    with tempfile.TemporaryDirectory(prefix='routervpn-tor-codesign-') as temporary:
        for architecture in architectures:
            copies = []
            for index, source in enumerate((original, binary)):
                destination = Path(temporary) / (architecture + '-' + str(index))
                arches = PACKAGE.run(['xcrun', 'lipo', '-archs', source], capture=True).split()
                if len(arches) == 1:
                    destination.write_bytes(source.read_bytes())
                else:
                    PACKAGE.run(['xcrun', 'lipo', source, '-thin', architecture, '-output', destination])
                copies.append(file_sections(destination))
            if copies[0] != copies[1]:
                raise ValueError('Embedded Tor C sections differ from the verified source package')
    extension = app / 'PlugIns/RouterVPNPacketTunnel.appex'
    for consumer, rpath in ((app / 'RouterVPN', '@executable_path/Frameworks'),
                            (extension / 'RouterVPNPacketTunnel', '@executable_path/../../Frameworks')):
        libraries = PACKAGE.run(['xcrun', 'otool', '-L', consumer], capture=True)
        if INSTALL_NAME not in libraries:
            raise ValueError('The app or PacketTunnel omits its native Tor dynamic dependency')
        commands = PACKAGE.run(['xcrun', 'otool', '-l', consumer], capture=True)
        if not re.search(r'\bpath\s+' + re.escape(rpath) + r'\s+\(offset', commands):
            raise ValueError('The native Tor framework cannot resolve from the app or extension')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-package', type=Path, required=True)
    parser.add_argument('--ndk', type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--android-aar', type=Path)
    group.add_argument('--android-apk', type=Path)
    group.add_argument('--apple-libbox', type=Path)
    group.add_argument('--apple-app', type=Path)
    args = parser.parse_args()
    if args.android_aar or args.android_apk:
        android(args.native_package, args.android_apk or args.android_aar, bool(args.android_apk), args.ndk)
    elif args.apple_libbox:
        apple_libbox(args.native_package, args.apple_libbox)
    else:
        apple_app(args.native_package, args.apple_app)
    print('Verified the real owning Tor C ABI and required mobile package contents')
