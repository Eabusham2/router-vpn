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
import posixpath
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
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
    ('Linux', 'arm64'): ('llvm-mingw-20261006-ucrt-ubuntu-22.04-aarch64.tar.xz', 78002292,
                        'e77c4acfa44184f6b0c52b814d724ad63b2ecebb3c3f6f842c0846e717cbd23c'),
}
MAX_FILES, MAX_EXPANDED, MAX_MEMBER = 60000, 3 << 30, 512 << 20


def member_path(name, prefix):
    if '\\' in name or ':' in name or any(ord(c) < 32 for c in name):
        raise ValueError('Unsafe toolchain archive member')
    if any(part in ('', '.', '..') or part.rstrip(' .') != part for part in name.rstrip('/').split('/')):
        raise ValueError('Noncanonical toolchain archive member')
    relative = PurePosixPath(name)
    if relative.is_absolute() or '..' in relative.parts or not relative.parts or relative.parts[0] != prefix:
        raise ValueError('Toolchain archive escaped its pinned root')
    return relative


def inventory(directory):
    """Reused build tools must still match every file installed from the pin."""
    root = directory.resolve(strict=True)
    result, total = {}, 0
    for current, directories, files in os.walk(directory, followlinks=False):
        for name in sorted(directories + files):
            path = Path(current)/name
            relative = path.relative_to(directory).as_posix()
            if relative == 'INSTALL.json':
                continue
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root):
                raise ValueError('Installed compiler link escaped its owned directory')
            info = path.lstat()
            if path.is_symlink():
                result[relative] = {'link': os.readlink(path)}
            elif stat.S_ISDIR(info.st_mode):
                result[relative] = {'directory': True}
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
                if info.st_size > MAX_MEMBER or total > MAX_EXPANDED:
                    raise ValueError('Unbounded installed compiler files')
                digest = hashlib.sha256()
                with path.open('rb') as source:
                    while chunk := source.read(1 << 20):
                        digest.update(chunk)
                result[relative] = {'size': info.st_size, 'sha256': digest.hexdigest(), 'executable': info.st_mode & 0o111}
            else:
                raise ValueError('Installed compiler contains a special file')
            if len(result) > MAX_FILES:
                raise ValueError('Too many installed compiler files')
    return result


def extract(archive, root, prefix, system):
    """Validate the entire namespace before creating any archive-owned path."""
    if archive.name.endswith('.zip'):
        with zipfile.ZipFile(archive) as zipped:
            members = zipped.infolist()
            if len(members) > MAX_FILES or sum(member.file_size for member in members) > MAX_EXPANDED:
                raise ValueError('Unbounded compiler archive')
            seen = set()
            for member in members:
                relative = member_path(member.filename, prefix)
                canonical = relative.as_posix().casefold() if system == 'Windows' else relative.as_posix()
                reserved = (prefix+'/INSTALL.json').casefold() if system == 'Windows' else prefix+'/INSTALL.json'
                if canonical in seen or canonical == reserved or member.file_size > MAX_MEMBER:
                    raise ValueError('Duplicate, reserved or oversized compiler member')
                seen.add(canonical)
                if stat.S_ISLNK(member.external_attr >> 16):
                    raise ValueError('Windows compiler archive contains a link')
                if system == 'Windows':
                    for part in relative.parts:
                        base = part.split('.')[0].upper()
                        if base in ('CON', 'PRN', 'AUX', 'NUL') or base in {f'{kind}{n}' for kind in ('COM', 'LPT') for n in range(1, 10)}:
                            raise ValueError('Windows compiler archive contains a device path')
            for member in members:
                target = root/member_path(member.filename, prefix)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zipped.open(member) as source, target.open('xb') as destination:
                        shutil.copyfileobj(source, destination, 1 << 20)
    else:
        with tarfile.open(archive, 'r:xz') as tar:
            members = tar.getmembers()
            if len(members) > MAX_FILES or sum(member.size for member in members) > MAX_EXPANDED:
                raise ValueError('Unbounded compiler archive')
            seen, links = set(), set()
            for member in members:
                relative = member_path(member.name, prefix)
                key = relative.as_posix()
                if key in seen or key == prefix+'/INSTALL.json' or member.size > MAX_MEMBER:
                    raise ValueError('Duplicate, reserved or oversized compiler member')
                seen.add(key)
                if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                    raise ValueError('Compiler archive contains a special file')
                if member.issym() or member.islnk():
                    if not member.linkname or member.linkname.startswith('/') or '\\' in member.linkname or ':' in member.linkname or any(ord(c) < 32 for c in member.linkname):
                        raise ValueError('Unsafe compiler archive link')
                    target = posixpath.normpath(str(relative.parent/member.linkname)) if member.issym() else member.linkname
                    member_path(target, prefix)
                    links.add(key)
            for key in seen:
                if any(parent.as_posix() in links for parent in PurePosixPath(key).parents):
                    raise ValueError('Compiler member traverses an archive link')
            tar.extractall(root, filter='data')
    inventory(root/prefix)  # Also reject dangling/cyclic links before execution.


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
    wanted = {'schema': 1, 'release': RELEASE, 'host': system+'/'+arch, 'archive': filename, 'size': size, 'sha256': digest}
    output = Path(output).absolute()
    if output.is_symlink():
        raise ValueError('Toolchain output cannot be a link')
    if output.exists():
        receipt = output/'INSTALL.json'
        if not output.is_dir() or receipt.is_symlink() or not receipt.is_file() or receipt.stat().st_size > 32 << 20:
            raise ValueError('Refusing an unowned or mismatched existing toolchain directory')
        saved = json.loads(receipt.read_text())
        if saved != {**wanted, 'files': inventory(output)}:
            raise ValueError('Refusing an unowned or mismatched existing toolchain directory')
        check_compilers(output, system)
        return output/'bin'
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.routervpn-llvm-', dir=output.parent) as temp:
        root = Path(temp)
        archive = root/filename
        sha = hashlib.sha256()
        count = 0
        deadline = time.monotonic()+600
        url = 'https://github.com/mstorsjo/llvm-mingw/releases/download/'+RELEASE+'/'+filename
        request = urllib.request.Request(url, headers={'User-Agent': 'RouterVPN-pinned-native-build'})
        with urllib.request.urlopen(request, timeout=60) as response, archive.open('xb') as target:
            if not response.geturl().startswith('https://'):
                raise ValueError('Compiler download must remain on HTTPS')
            while chunk := response.read(1 << 20):
                count += len(chunk)
                if count > size or time.monotonic() > deadline:
                    raise ValueError('Pinned compiler download exceeded its exact size')
                sha.update(chunk)
                target.write(chunk)
        if count != size or sha.hexdigest() != digest:
            raise ValueError('Compiler archive differs from the published pinned digest')
        prefix = filename.removesuffix('.zip').removesuffix('.tar.xz')
        extract(archive, root, prefix, system)
        stage = root/prefix
        check_compilers(stage, system)
        (stage/'INSTALL.json').write_text(json.dumps({**wanted, 'files': inventory(stage)}, sort_keys=True, indent=2)+'\n')
        os.replace(stage, output)
    return output/'bin'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--host-arch', choices=('amd64', 'arm64'))
    args = parser.parse_args()
    print(install(args.output, args.host_arch))
