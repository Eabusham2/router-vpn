#!/usr/bin/env python3
"""Keep the pinned AWG timer state inside its existing modification lock.

The upstream expiry callback cleared duration after unlocking, racing Mod and
Del during a failed handshake or shutdown. Move only that clear into the same
critical section. Keep callback execution and DelSync's joined lifetime intact.
The private module copy reverses that exact edit to verify the complete original
Go h1 checksum. Neither the module cache nor unrelated replacements are changed.
"""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import json
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
MODULE = 'github.com/amnezia-vpn/amneziawg-go/v3'
VERSION = 'v3.1.20260814'
SUM = 'h1:l2AhBD+sFycU8Im81n/bZORMxW7fWtlZJEuJ4Hh0+z0='
COPY = 'routervpn-patched-amnezia'
PREFIX = MODULE + '@' + VERSION + '/'
TIMER = 'device/timers.go'
BLOB = '4a5499db8ec734dfa421ac1b892782e33ae6ac3a'
OLD = b'\t\tduration := timer.duration\n\t\ttimer.modifyingLock.Unlock()\n\t\ttimer.duration = 0\n'
NEW = b'\t\tduration := timer.duration\n\t\ttimer.duration = 0\n\t\ttimer.modifyingLock.Unlock()\n'
TEST = 'device/routervpn_timers_test.go'
TEMPLATE = ROOT / 'mobile/amneziatimers/timers_test.go.tmpl'
MAX_BYTES = 32 * 1024 * 1024
MAX_FILES = 5000


def inputs():
    return [Path(__file__).resolve(), TEMPLATE,
            ROOT / 'deploy/test_amnezia_timers_pinned.py',
            ROOT / 'deploy/test_amnezia_timer_preparation.py']


def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def patch(data):
    if git_blob(data) != BLOB or data.count(OLD) != 1 or NEW in data:
        raise ValueError('Pinned AWG timer lock boundary changed')
    return data.replace(OLD, NEW, 1)


def original(data):
    if data.count(NEW) != 1 or OLD in data:
        raise ValueError('Prepared AWG timer lock boundary differs')
    restored = data.replace(NEW, OLD, 1)
    if git_blob(restored) != BLOB:
        raise ValueError('Prepared AWG timer contains unrelated changes')
    return restored


def h1(rows):
    summary = ''.join(digest + '  ' + name + '\n' for name, digest in sorted(rows))
    return 'h1:' + base64.b64encode(hashlib.sha256(summary.encode()).digest()).decode()


def test_source():
    if TEMPLATE.is_symlink() or not TEMPLATE.is_file() or not 0 < TEMPLATE.stat().st_size < 256 * 1024:
        raise ValueError('AWG timer regression source is missing or unowned')
    return TEMPLATE.read_bytes()


def safe_relative(relative):
    parts = PurePosixPath(relative)
    return (bool(relative) and str(parts) == relative and not parts.is_absolute() and
            '..' not in parts.parts and not any(c in relative for c in ('\\', ':', '\n', '\r')))


def verify_tree(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Prepared AWG timers must belong to a private directory')
    rows, total, count, tested = [], 0, 0, False
    expected_test = test_source()
    for path in sorted(directory.rglob('*')):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ValueError('Prepared AWG module contains a linked or special entry')
        if path.is_dir():
            continue
        relative = path.relative_to(directory).as_posix()
        info = path.stat()
        total += info.st_size
        count += 1
        if not safe_relative(relative) or info.st_nlink != 1 or total > MAX_BYTES or count > MAX_FILES:
            raise ValueError('Prepared AWG module lost its owned source bounds')
        data = path.read_bytes()
        if relative == TEST:
            if data != expected_test:
                raise ValueError('Prepared AWG timer regression differs from its captured source')
            tested = True
            continue
        if relative == TIMER:
            data = original(data)
        rows.append((PREFIX + relative, hashlib.sha256(data).hexdigest()))
    if not tested or h1(rows) != SUM:
        raise ValueError('Prepared AWG module differs from the exact pinned timer correction')


def extract_verified(archive, target):
    if target.is_symlink() or not target.is_dir() or any(target.iterdir()):
        raise ValueError('AWG timer extraction requires an empty owned staging directory')
    expected_test = test_source()
    rows, total, seen = [], 0, set()
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if not entries or len(entries) >= MAX_FILES:
            raise ValueError('Invalid AWG module archive size')
        for entry in entries:
            name = entry.filename
            if not name.startswith(PREFIX):
                raise ValueError('AWG archive has a foreign module identity')
            relative = name[len(PREFIX):]
            mode = stat.S_IFMT(entry.external_attr >> 16)
            if (not safe_relative(relative) or entry.is_dir() or mode not in (0, stat.S_IFREG) or
                    relative in seen or relative == TEST):
                raise ValueError('Unsafe or duplicate AWG module archive member')
            seen.add(relative)
            total += entry.file_size
            if total + len(expected_test) > MAX_BYTES or entry.file_size > MAX_BYTES:
                raise ValueError('AWG module archive exceeds source bounds')
            data = source.read(entry)
            rows.append((name, hashlib.sha256(data).hexdigest()))
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('xb') as output:
                output.write(patch(data) if relative == TIMER else data)
        if h1(rows) != SUM:
            raise ValueError('Downloaded AWG archive does not match the pinned h1 checksum')
    with (target / TEST).open('xb') as output:
        output.write(expected_test)
    verify_tree(target)


def module_plan(vendor, go='go', *, env=None, required=False):
    plan = json.loads(subprocess.check_output([go, 'mod', 'edit', '-json'], cwd=vendor, env=env, text=True))
    requirements = [row for row in plan.get('Require', []) if row['Path'] == MODULE]
    if len(requirements) != 1 or requirements[0]['Version'] != VERSION:
        raise ValueError('AWG timer correction requires the exact original dependency version')
    replacements = [row for row in plan.get('Replace', []) or [] if row['Old']['Path'] == MODULE]
    expected = [{'Old': {'Path': MODULE, 'Version': VERSION}, 'New': {'Path': './' + COPY}}]
    if (required or replacements) and replacements != expected:
        raise ValueError('Refusing an unrelated or missing AWG timer replacement')


def prepare(vendor, go='go', *, env=None):
    if vendor.is_symlink():
        raise ValueError('AWG timer preparation refuses a linked native core')
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != CORE:
        raise ValueError('AWG timer preparation requires the exact disposable native core')
    module_plan(vendor, go, env=env)
    target = vendor / COPY
    if target.exists() or target.is_symlink():
        verify_tree(target)
    else:
        info = json.loads(subprocess.check_output(
            [go, 'mod', 'download', '-json', MODULE + '@' + VERSION], cwd=vendor, env=env, text=True))
        if info.get('Path') != MODULE or info.get('Version') != VERSION or info.get('Sum') != SUM or info.get('Error'):
            raise ValueError('AWG download metadata differs from the pinned original module')
        with tempfile.TemporaryDirectory(prefix='.routervpn-amnezia-timers-', dir=vendor) as temporary:
            staged = Path(temporary) / 'module'
            staged.mkdir()
            extract_verified(Path(info['Zip']), staged)
            staged.rename(target)
    subprocess.run([go, 'mod', 'edit', '-replace=' + MODULE + '@' + VERSION + '=./' + COPY], cwd=vendor, env=env, check=True)
    print('Prepared checksum-verified AWG timer expiry synchronization:', VERSION)


def verify(vendor, go='go', *, env=None):
    if vendor.is_symlink():
        raise ValueError('AWG timer verification refuses a linked native core')
    vendor = vendor.resolve()
    module_plan(vendor, go, env=env, required=True)
    info = json.loads(subprocess.check_output([go, 'list', '-m', '-mod=readonly', '-json', MODULE], cwd=vendor, env=env, text=True))
    replacement = info.get('Replace') or {}
    target = vendor / COPY
    if (info.get('Path') != MODULE or info.get('Version') != VERSION or info.get('Error') or
            replacement.get('Path') != './' + COPY or replacement.get('Version') or
            not info.get('Dir') or Path(info['Dir']).resolve() != target or
            not replacement.get('Dir') or Path(replacement['Dir']).resolve() != target):
        raise ValueError('Native core lost its exact selected private AWG timer copy')
    verify_tree(target)
    return target
