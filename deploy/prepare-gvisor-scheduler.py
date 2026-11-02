#!/usr/bin/env python3
"""Apply verified scheduler and TCP ownership fixes in a disposable core copy.

The pinned gVisor CAS assembly overwrites R1 (expected value) with the new
value and never initializes R2 (replacement value). Its sleeper cannot park.
Do not change cryptography, remove race instrumentation, or edit Go's module
cache. The entire upstream module is checked with Go's documented h1 hash;
verification reverses only this instruction and the exact forwarder edits
before rechecking that hash. The forwarder regression is an explicitly owned
extra source, checked byte-for-byte before excluding it from the original h1.
"""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import importlib.util
import json
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
_forwarder_spec = importlib.util.spec_from_file_location('routervpn_gvisor_forwarder', ROOT / 'deploy/prepare-gvisor-forwarder.py')
FORWARDER = importlib.util.module_from_spec(_forwarder_spec)
_forwarder_spec.loader.exec_module(FORWARDER)

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
MAX_FILES = 20000


def inputs():
    return [Path(__file__).resolve(), ROOT / 'deploy/test_gvisor_scheduler_preparation.py'] + FORWARDER.inputs()


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


def safe_relative(relative):
    parts = PurePosixPath(relative)
    return (bool(relative) and str(parts) == relative and not parts.is_absolute() and
            '..' not in parts.parts and not any(c in relative for c in ('\\', ':', '\n', '\r')))


def verify_tree(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Prepared gVisor must be an owned directory')
    rows = []
    total, count, tested = 0, 0, False
    expected_test = FORWARDER.test_source()
    for path in sorted(directory.rglob('*')):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ValueError('Prepared gVisor contains a linked or special entry')
        if path.is_dir():
            continue
        relative = path.relative_to(directory).as_posix()
        info = path.stat()
        total += info.st_size
        count += 1
        if not safe_relative(relative) or info.st_nlink != 1 or total > MAX_BYTES or count > MAX_FILES:
            raise ValueError('Prepared gVisor exceeds source bounds')
        data = path.read_bytes()
        if relative == FORWARDER.TEST:
            if data != expected_test:
                raise ValueError('Prepared gVisor forwarder regression differs from its captured source')
            tested = True
            continue
        if relative == ASSEMBLY:
            data = original(data)
        elif relative in FORWARDER.PATCHES:
            data = FORWARDER.original(relative, data)
        rows.append((PREFIX + relative, hashlib.sha256(data).hexdigest()))
    if not tested or h1(rows) != SUM:
        raise ValueError('Prepared gVisor differs from its pinned module plus the exact owned fixes')
    # Missing original source also fails the whole-module checksum above.


def extract_verified(archive, target):
    if target.is_symlink() or not target.is_dir() or any(target.iterdir()):
        raise ValueError('gVisor extraction requires an empty owned staging directory')
    expected_test = FORWARDER.test_source()
    rows = []
    total = 0
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if not entries or len(entries) >= MAX_FILES:
            raise ValueError('Invalid gVisor archive size')
        seen = set()
        for entry in entries:
            name = entry.filename
            if not name.startswith(PREFIX):
                raise ValueError('gVisor archive has a foreign module prefix')
            relative = name[len(PREFIX):]
            mode = stat.S_IFMT(entry.external_attr >> 16)
            if (not safe_relative(relative) or entry.is_dir() or mode not in (0, stat.S_IFREG) or
                    relative in seen or relative == FORWARDER.TEST):
                raise ValueError('Unsafe or duplicate gVisor archive member')
            seen.add(relative)
            total += entry.file_size
            if total + len(expected_test) > MAX_BYTES or entry.file_size > MAX_BYTES:
                raise ValueError('gVisor archive exceeds source bounds')
            data = source.read(entry)
            rows.append((name, hashlib.sha256(data).hexdigest()))
            if relative == ASSEMBLY:
                data = patch(data)
            elif relative in FORWARDER.PATCHES:
                data = FORWARDER.patch(relative, data)
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('xb') as output:
                output.write(data)
        if h1(rows) != SUM:
            raise ValueError('Downloaded gVisor does not match the pinned h1 checksum')
    with (target / FORWARDER.TEST).open('xb') as output:
        output.write(expected_test)
    verify_tree(target)


def module_plan(vendor, go='go', *, env=None, required=False):
    plan = json.loads(subprocess.check_output([go, 'mod', 'edit', '-json'], cwd=vendor, env=env, text=True))
    requirements = [r for r in plan.get('Require', []) if r['Path'] == MODULE]
    if len(requirements) != 1 or requirements[0]['Version'] != VERSION:
        raise ValueError('Native scheduler requires the exact pinned gVisor version')
    replacements = [r for r in plan.get('Replace', []) or [] if r['Old']['Path'] == MODULE]
    expected = {'Old': {'Path': MODULE, 'Version': VERSION}, 'New': {'Path': './' + COPY}}
    if (required or replacements) and replacements != [expected]:
        raise ValueError('Refusing an unrelated or missing gVisor replacement')


def prepare(vendor, go='go', *, env=None):
    if vendor.is_symlink():
        raise ValueError('gVisor preparation refuses a linked native core')
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != CORE:
        raise ValueError('Scheduler patch requires the exact disposable native core')
    module_plan(vendor, go, env=env)
    target = vendor / COPY
    if target.exists() or target.is_symlink():
        verify_tree(target)
    else:
        info = json.loads(subprocess.check_output(
            [go, 'mod', 'download', '-json', MODULE + '@' + VERSION], cwd=vendor, env=env, text=True))
        if info.get('Path') != MODULE or info.get('Version') != VERSION or info.get('Sum') != SUM or info.get('Error'):
            raise ValueError('gVisor download metadata does not match the pinned module')
        with tempfile.TemporaryDirectory(prefix='.routervpn-gvisor-', dir=vendor) as temporary:
            staged = Path(temporary) / 'module'
            staged.mkdir()
            extract_verified(Path(info['Zip']), staged)
            staged.rename(target)
    subprocess.run([go, 'mod', 'edit', '-replace=' + MODULE + '@' + VERSION + '=./' + COPY], cwd=vendor, env=env, check=True)
    print('Prepared checksum-verified gVisor scheduler and forwarded TCP ownership:', VERSION)


def verify(vendor, go='go', *, env=None):
    if vendor.is_symlink():
        raise ValueError('gVisor verification refuses a linked native core')
    vendor = vendor.resolve()
    module_plan(vendor, go, env=env, required=True)
    info = json.loads(subprocess.check_output([go, 'list', '-m', '-mod=readonly', '-json', MODULE], cwd=vendor, env=env, text=True))
    replacement = info.get('Replace') or {}
    target = vendor / COPY
    if (info.get('Path') != MODULE or info.get('Version') != VERSION or info.get('Error') or
            replacement.get('Path') != './' + COPY or replacement.get('Version') or
            not info.get('Dir') or Path(info['Dir']).resolve() != target or
            not replacement.get('Dir') or Path(replacement['Dir']).resolve() != target):
        raise ValueError('Native core lost its exact selected private gVisor copy')
    verify_tree(target)
    return target
