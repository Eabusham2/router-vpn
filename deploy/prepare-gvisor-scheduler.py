#!/usr/bin/env python3
"""Apply one verified ARM64 race-only scheduler fix in a disposable core copy.

The pinned gVisor CAS assembly overwrites R1 (expected value) with the new
value and never initializes R2 (replacement value). Its sleeper cannot park.
Do not change cryptography, remove race instrumentation, or edit Go's module
cache. The entire upstream module is checked with Go's documented h1 hash;
verification reverses only this one instruction before rechecking that hash.
"""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import json
import stat
import subprocess
import tempfile
import zipfile

CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
MODULE = 'github.com/sagernet/gvisor'
VERSION = 'v0.0.0-20260727.0-sing-box-mod.1'
SUM = 'h1:IdQ7yTKkB2wv8txwshxUroPlO4npOYAV71xb7xQ7Lys='
ASSEMBLY = 'pkg/sync/race_arm64.s'
BLOB = 'c4192e870a69e0274a8da2c1a00d38f22126eed9'
OLD = b'\tMOVD new+16(FP), R1\n'
NEW = b'\tMOVD new+16(FP), R2\n'
COPY = 'routervpn-patched-gvisor'
PREFIX = MODULE + '@' + VERSION + '/'
MAX_BYTES = 256 * 1024 * 1024


def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def patch(data):
    if git_blob(data) != BLOB or data.count(OLD) != 1 or NEW in data:
        raise ValueError('Pinned gVisor ARM64 atomic boundary changed')
    return data.replace(OLD, NEW, 1)


def original(data):
    if data.count(NEW) != 1 or OLD in data:
        raise ValueError('Prepared gVisor atomic instruction differs')
    restored = data.replace(NEW, OLD, 1)
    if git_blob(restored) != BLOB:
        raise ValueError('Prepared gVisor assembly has unrelated changes')
    return restored


def h1(rows):
    # golang.org/x/mod/sumdb/dirhash.Hash1: sorted SHA256/name summary.
    summary = ''.join(digest + '  ' + name + '\n' for name, digest in sorted(rows))
    return 'h1:' + base64.b64encode(hashlib.sha256(summary.encode()).digest()).decode()


def verify_tree(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Prepared gVisor must be an owned directory')
    rows = []
    total = 0
    for path in sorted(directory.rglob('*')):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ValueError('Prepared gVisor contains a linked or special entry')
        if path.is_dir():
            continue
        relative = path.relative_to(directory).as_posix()
        if '\n' in relative or '\r' in relative:
            raise ValueError('Invalid prepared gVisor path')
        total += path.stat().st_size
        if total > MAX_BYTES or len(rows) >= 20000:
            raise ValueError('Prepared gVisor exceeds source bounds')
        data = path.read_bytes()
        if relative == ASSEMBLY:
            data = original(data)
        rows.append((PREFIX + relative, hashlib.sha256(data).hexdigest()))
    if h1(rows) != SUM:
        raise ValueError('Prepared gVisor differs from its pinned module plus the atomic fix')
    # Missing ASSEMBLY also fails the whole-module checksum above.


def extract_verified(archive, target):
    rows = []
    total = 0
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if not entries or len(entries) > 20000:
            raise ValueError('Invalid gVisor archive size')
        seen = set()
        for entry in entries:
            name = entry.filename
            if not name.startswith(PREFIX):
                raise ValueError('gVisor archive has a foreign module prefix')
            relative = name[len(PREFIX):]
            parts = PurePosixPath(relative)
            mode = entry.external_attr >> 16
            if (not relative or str(parts) != relative or '\\' in relative or
                    '\n' in relative or '\r' in relative or '..' in parts.parts or
                    parts.is_absolute() or entry.is_dir() or stat.S_ISLNK(mode) or
                    relative in seen):
                raise ValueError('Unsafe or duplicate gVisor archive member')
            seen.add(relative)
            total += entry.file_size
            if total > MAX_BYTES or entry.file_size > MAX_BYTES:
                raise ValueError('gVisor archive exceeds source bounds')
            data = source.read(entry)
            rows.append((name, hashlib.sha256(data).hexdigest()))
            if relative == ASSEMBLY:
                data = patch(data)
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        if h1(rows) != SUM:
            raise ValueError('Downloaded gVisor does not match the pinned h1 checksum')
    verify_tree(target)


def module_plan(vendor):
    plan = json.loads(subprocess.check_output(['go', 'mod', 'edit', '-json'], cwd=vendor, text=True))
    requirements = [r for r in plan.get('Require', []) if r['Path'] == MODULE]
    if len(requirements) != 1 or requirements[0]['Version'] != VERSION:
        raise ValueError('Native scheduler requires the exact pinned gVisor version')
    replacements = [r for r in plan.get('Replace', []) or [] if r['Old']['Path'] == MODULE]
    expected = {'Old': {'Path': MODULE, 'Version': VERSION}, 'New': {'Path': './' + COPY}}
    if replacements and replacements != [expected]:
        raise ValueError('Refusing an unrelated gVisor replacement')


def prepare(vendor):
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != CORE:
        raise ValueError('Scheduler patch requires the exact disposable native core')
    module_plan(vendor)
    target = vendor / COPY
    if target.exists() or target.is_symlink():
        verify_tree(target)
    else:
        info = json.loads(subprocess.check_output(
            ['go', 'mod', 'download', '-json', MODULE + '@' + VERSION], cwd=vendor, text=True))
        if info.get('Path') != MODULE or info.get('Version') != VERSION or info.get('Sum') != SUM or info.get('Error'):
            raise ValueError('gVisor download metadata does not match the pinned module')
        with tempfile.TemporaryDirectory(prefix='.routervpn-gvisor-', dir=vendor) as temporary:
            staged = Path(temporary) / 'module'
            staged.mkdir()
            extract_verified(Path(info['Zip']), staged)
            staged.rename(target)
    subprocess.run(['go', 'mod', 'edit', '-replace=' + MODULE + '@' + VERSION + '=./' + COPY], cwd=vendor, check=True)
    print('Prepared checksum-verified gVisor ARM64 race scheduler fix:', VERSION)


def verify(vendor):
    vendor = vendor.resolve()
    module_plan(vendor)
    info = json.loads(subprocess.check_output(['go', 'list', '-m', '-json', MODULE], cwd=vendor, text=True))
    replacement = info.get('Replace') or {}
    if (info.get('Version') != VERSION or replacement.get('Path') != './' + COPY or
            Path(replacement.get('Dir', '')).resolve() != vendor / COPY):
        raise ValueError('Native core lost its verified local gVisor scheduler copy')
    verify_tree(vendor / COPY)
