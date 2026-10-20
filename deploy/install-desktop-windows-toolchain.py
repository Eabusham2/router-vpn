#!/usr/bin/env python3
"""Install the exact LLVM-MinGW desktop compiler into a fresh build directory.

Only the compiler bin path is printed to stdout, for the CI PATH step. This
does not install drivers, change a system toolchain, or invoke a package manager.
Rust bindgen separately needs a host-architecture libclang C API library.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

RELEASE = '20261006'
CLANG = 'clang version 23.1.3'
ARCHIVES = {
    ('Windows', 'amd64'): ('llvm-mingw-20261006-ucrt-x86_64.zip', 190836485,
                          '317492c456aa27ee607a5919f1d2d38dcdc1112516a24d0bf4b00d078f52d17a'),
    ('Windows', 'arm64'): ('llvm-mingw-20261006-ucrt-aarch64.zip', 185727081,
                          '9a835d5179c9f3a5a783c11a7f14062a249b4765dd11add64a66786864e82ab2'),
    ('Linux', 'amd64'): ('llvm-mingw-20261006-ucrt-ubuntu-22.04-x86_64.tar.xz', 84003044,
                        '5f9c6ed95b2d4bdb2869a488c5fd5857fbdabcf288a0aa3eb1da43f6a08d8ab4'),
}


def member_path(name, prefix):
    if '\\' in name or ':' in name or '\0' in name:
        raise ValueError('Unsafe toolchain archive member')
    relative = PurePosixPath(name)
    if relative.is_absolute() or '..' in relative.parts or not relative.parts or relative.parts[0] != prefix:
        raise ValueError('Toolchain archive escaped its pinned root')
    return relative


def check_compilers(directory, system):
    suffix = '.exe' if system == 'Windows' else ''
    for target in ('x86_64', 'aarch64'):
        compiler = directory/'bin'/(target+'-w64-mingw32-clang'+suffix)
        output = subprocess.check_output([str(compiler), '--version'], text=True, timeout=20)
        if not output.startswith(CLANG+' '):
            raise ValueError('Installed LLVM-MinGW compiler version changed')


def install(output, host_arch=None):
    system = platform.system()
    detected = {'x86_64': 'amd64', 'AMD64': 'amd64', 'aarch64': 'arm64', 'ARM64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    arch = host_arch or detected
    # Windows 11 ARM64 can execute the x64 build tools while still producing
    # an actual ARM64 native engine; the Rust target remains independently fixed.
    if arch != detected and (system, detected, arch) != ('Windows', 'arm64', 'amd64'):
        raise ValueError('Unsupported build-host architecture override')
    if (system, arch) not in ARCHIVES:
        raise ValueError('No pinned LLVM-MinGW archive for this build host')
    filename, size, digest = ARCHIVES[(system, arch)]
    wanted = {'release': RELEASE, 'host': system+'/'+arch, 'archive': filename, 'size': size, 'sha256': digest}
    output = Path(output).absolute()
    if output.is_symlink():
        raise ValueError('Toolchain output cannot be a link')
    if output.exists():
        receipt = output/'INSTALL.json'
        if receipt.is_symlink() or not receipt.is_file() or json.loads(receipt.read_text()) != wanted:
            raise ValueError('Refusing an unowned or mismatched existing toolchain directory')
        check_compilers(output, system)
        return output/'bin'
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.routervpn-llvm-', dir=output.parent) as temp:
        root = Path(temp)
        archive = root/filename
        sha = hashlib.sha256()
        count = 0
        url = 'https://github.com/mstorsjo/llvm-mingw/releases/download/'+RELEASE+'/'+filename
        request = urllib.request.Request(url, headers={'User-Agent': 'RouterVPN-pinned-native-build'})
        with urllib.request.urlopen(request, timeout=60) as response, archive.open('xb') as target:
            while chunk := response.read(1 << 20):
                count += len(chunk)
                if count > size:
                    raise ValueError('Pinned compiler download exceeded its exact size')
                sha.update(chunk)
                target.write(chunk)
        if count != size or sha.hexdigest() != digest:
            raise ValueError('Compiler archive differs from the published pinned digest')
        prefix = filename.removesuffix('.zip').removesuffix('.tar.xz')
        if filename.endswith('.zip'):
            with zipfile.ZipFile(archive) as zipped:
                members = zipped.infolist()
                if len(members) > 60000 or sum(member.file_size for member in members) > 3 << 30:
                    raise ValueError('Unbounded compiler archive')
                for member in members:
                    relative = member_path(member.filename, prefix)
                    if stat.S_ISLNK(member.external_attr >> 16):
                        raise ValueError('Windows compiler archive contains a link')
                    target = root/relative
                    if member.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with zipped.open(member) as source, target.open('xb') as destination:
                            shutil.copyfileobj(source, destination)
        else:
            with tarfile.open(archive, 'r:xz') as tar:
                members = tar.getmembers()
                if len(members) > 60000 or sum(member.size for member in members) > 3 << 30:
                    raise ValueError('Unbounded compiler archive')
                for member in members:
                    member_path(member.name, prefix)
                tar.extractall(root, filter='data')
        stage = root/prefix
        check_compilers(stage, system)
        (stage/'INSTALL.json').write_text(json.dumps(wanted, sort_keys=True, indent=2)+'\n')
        os.replace(stage, output)
    return output/'bin'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--host-arch', choices=('amd64', 'arm64'))
    args = parser.parse_args()
    print(install(args.output, args.host_arch))
