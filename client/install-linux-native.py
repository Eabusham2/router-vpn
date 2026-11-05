#!/usr/bin/env python3
"""Install the native Linux application with fixed, root-owned launch authority.

The installed controller and protection service retain original source locks.
An idle service can retire before ordinary promotion. An active Always upgrade
requires its original authenticated coordinator, overlapping native protection,
and frozen source admission; only code is journaled in place, preserving private
state inodes. Unknown outcomes retain both generations and original owners.
All new files are staged privately; decoded metadata never creates authority.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import array
import hashlib
import json
import os
from pathlib import Path
import shutil
import select
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path('/opt/router-vpn-client')
SYSTEM_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
CODE_TREES = {'client', 'modes', 'runtime'}
CODE_FILES = {
    'modes.json', 'logical-modes.json', 'router-vpn-client', 'router-vpn-dns',
    'router-vpn-start-layer-relay', 'router-vpn-update', 'router-vpn-app',
    'RouterVPN.ico', 'router-vpn.png', 'router-vpn.desktop', 'MODES.md',
    'CLIENT.md', 'SECURITY.md', 'LICENSE', 'DNS-PROXY-NOTICES.json',
    'ROUTER-VPN-SOURCE.json',
}
REQUIRED_FILES = {
    'router-vpn-client', 'router-vpn-dns', 'router-vpn-start-layer-relay',
    'router-vpn-update', 'router-vpn-app', 'modes.json', 'logical-modes.json',
    'router-vpn.png', 'router-vpn.desktop', 'ROUTER-VPN-SOURCE.json',
}
LEGACY_EARLY_NAME = 'router-vpn-killswitch-early.service'
EARLY_NAME = 'router-vpn-standard-owner.service'
NETWORK_UNITS = ('NetworkManager.service', 'systemd-networkd.service',
                 'networking.service', 'connman.service', 'wicked.service')
UPGRADE_ARGUMENT = '--linux-standard-owner-upgrade'
SERVICE_ARGUMENT = '--linux-standard-owner-service'
GENERATION_ACTIVATION = 'service-generation.json'
GENERATION_MANIFEST = 'generation.json'
GENERATION_MAX_FILES = 8192
GENERATION_MAX_MANIFEST = 2 << 20
GENERATION_MAX_ACTIVATION = 4096
IMAGE_UPGRADE_ARGUMENT = '--linux-standard-owner-image-upgrade'
IMAGE_WORK_NS = 120 * 1_000_000_000
IMAGE_CLEANUP_NS = 30 * 1_000_000_000
IMAGE_FRAME_LIMIT = 64 << 10
EARLY_UNIT = '''# Router VPN retained original protection owner; no HTTP controller runs at boot.
[Unit]
Description=Router VPN persistent always kill switch
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
Wants=network-pre.target
RefuseManualStop=yes

[Service]
Type=notify
NotifyAccess=main
Restart=no
TimeoutStartSec=infinity
ExecStart=/opt/router-vpn-client/router-vpn-client --linux-standard-owner-service

[Install]
WantedBy=multi-user.target
RequiredBy=network-pre.target
'''
NETWORK_DROPIN = '''# Router VPN owned: a failed Always reassertion blocks network startup.
[Unit]
Requires=router-vpn-standard-owner.service
After=router-vpn-standard-owner.service
'''
LAUNCHER = '''#!/bin/sh
if [ -x /opt/router-vpn-client/router-vpn-update ]; then
  /opt/router-vpn-client/router-vpn-update --download --json >/dev/null 2>&1 &
fi
exec /opt/router-vpn-client/router-vpn-app "$@"
'''
RECOVERY = '''#!/bin/sh
set -eu
[ "$(/usr/bin/id -u)" -eq 0 ] || { echo 'Run with sudo.' >&2; exit 1; }
/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOMEVPN_ROOT=/opt/router-vpn-client /usr/bin/python3 -Es /opt/router-vpn-client/modes/kill-switch.py force-off
/usr/bin/systemctl reset-failed router-vpn-killswitch-early.service || :
printf '%s\n' 'Router VPN Always protection disabled for local recovery. Review the saved policy before rebooting.'
'''


def command(arguments, *, check=True, deadline_ns=None):
    return subprocess.run(list(map(str, arguments)), check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={'PATH': SYSTEM_PATH, 'LC_ALL': 'C'}, timeout=120 if deadline_ns is None else image_remaining(deadline_ns))


def ordinary(path: Path, *, directory=False, trusted=False):
    info = path.lstat()
    expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not expected or (not directory and info.st_nlink != 1):
        raise ValueError('Refusing a linked or nonregular installation object: ' + str(path))
    if trusted and (info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022):
        raise ValueError('Installation authority must be root-owned and not writable by another user: ' + str(path))
    return info


@contextmanager
def installation_lock(root: Path):
    ordinary(root.parent, directory=True, trusted=True)
    path = root.with_name(root.name + '.install.lock')
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        actual, named = os.fstat(descriptor), ordinary(path, trusted=True)
        if (actual.st_dev, actual.st_ino) != (named.st_dev, named.st_ino) or actual.st_mode & 0o077:
            raise ValueError('The native installation lock is unsafe')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('Close Router VPN and wait for its tunnel cleanup before upgrading.') from error
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def installation_transaction(root: Path):
    # Source EX cannot remain held while a new service takes its lifetime SH.
    # Independent transaction/controller locks exclude another installer and
    # any new GUI controller across promotion, service readiness and rollback.
    ordinary(root.parent, directory=True, trusted=True)
    descriptors = []
    try:
        for suffix in ('.install.transaction.lock', '.controller.lock'):
            path = root.with_name(root.name + suffix)
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            descriptors.append(descriptor)
            actual, named = os.fstat(descriptor), ordinary(path, trusted=True)
            if (actual.st_dev, actual.st_ino) != (named.st_dev, named.st_ino) or actual.st_mode & 0o077:
                raise ValueError('The native installation transaction lock is unsafe')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RuntimeError('Close Router VPN and wait for its original cleanup or other installation before upgrading.') from error
        yield
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def reject_retained_protection(root: Path):
    # A saved table name/handle is never authority to upgrade beneath an old
    # creator. Existing protection must be released by its live original owner.
    state = root / 'run' / 'kill-switch.json'
    if state.exists() or state.is_symlink():
        raise RuntimeError('Original Router VPN protection is retained; select Off and complete its owned cleanup before upgrading.')


def reject_running_previous(root: Path, proc=Path('/proc'), *, original_pins=()):
    # Older installations predate the shared lock. Read executable identities;
    # never signal a printed PID or kill another process to force an upgrade.
    prefixes = (str(root) + '/', str(root) + '.service-generations/')
    for process in proc.iterdir():
        if not process.name.isdecimal():
            continue
        try:
            executable = os.readlink(process / 'exe').removesuffix(' (deleted)')
        except FileNotFoundError:
            continue
        except PermissionError as error:
            raise RuntimeError('Cannot prove that the previous native installation is idle') from error
        if executable.startswith(prefixes):
            if original_pins and any(pin.excludes(process) for pin in original_pins):
                continue
            raise RuntimeError('Close Router VPN and its owned native processes before upgrading.')
        legacy = False
        if Path(executable).name == 'router-vpn-client':
            try:
                environment = (process / 'environ').read_bytes().split(b'\0')
                legacy = ('HOMEVPN_ROOT=' + str(root)).encode() in environment
            except FileNotFoundError:
                continue
        if legacy:
            raise RuntimeError('Close Router VPN and its owned native processes before upgrading.')


def copy_checked(source: Path, destination: Path, *, private=False):
    # Open every ancestor without following symlinks, then recurse by retained
    # directory descriptors. A user-owned package/private subdirectory cannot
    # redirect a later root open by replacing an ancestor during the copy.
    source = Path(os.path.abspath(source))
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in source.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
        _copy_at(parent, source.name, destination, private=private)
    finally:
        os.close(parent)


def _copy_at(parent: int, name: str, destination: Path, *, private: bool):
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if stat.S_ISDIR(info.st_mode):
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            opened = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError('Installation directory changed during open: ' + name)
            destination.mkdir(mode=0o700)
            for child in os.listdir(descriptor):
                _copy_at(descriptor, child, destination / child, private=private)
            after = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('Installation directory changed during capture: ' + name)
        finally:
            os.close(descriptor)
        os.chown(destination, 0, 0)
        destination.chmod(0o700 if private else 0o755)
        return
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Refusing a linked or nonregular installation object: ' + name)
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        opened = os.fstat(descriptor)
        fingerprint = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)
        if fingerprint(info) != fingerprint(opened):
            raise ValueError('Installation input changed during open: ' + name)
        with os.fdopen(descriptor, 'rb', closefd=False) as incoming, destination.open('xb') as output:
            shutil.copyfileobj(incoming, output, 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        if fingerprint(opened) != fingerprint(os.fstat(descriptor)) or fingerprint(opened) != fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False)):
            raise ValueError('Installation input changed during capture: ' + name)
    finally:
        os.close(descriptor)
    executable = bool(info.st_mode & 0o111)
    os.chown(destination, 0, 0)
    destination.chmod((0o700 if executable else 0o600) if private else (0o755 if executable else 0o644))


def validate_config(path: Path, root: Path):
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or value.get('listen', '127.0.0.1:8788') not in ('', '127.0.0.1:8788'):
        raise ValueError('Native Linux controller configuration must use 127.0.0.1:8788')
    for key, name in (('modes_file', 'modes.json'), ('scripts_dir', 'modes'),
                      ('profiles_file', 'routers.json'), ('state_file', 'state.json')):
        if value.get(key, './' + name) not in ('', name, './' + name, str(root / name)):
            raise ValueError('Native Linux configuration must keep ' + key + ' inside its fixed installation')


def stage_application(source: Path, root: Path, stage: Path, *, include_private=True):
    captured_source = ordinary(source, directory=True)
    if root.exists() or root.is_symlink():
        ordinary(root, directory=True, trusted=True)
    for name in CODE_TREES | REQUIRED_FILES:
        ordinary(source / name, directory=name in CODE_TREES)
    for name in sorted(CODE_TREES | CODE_FILES):
        if (source / name).exists() or (source / name).is_symlink():
            copy_checked(source / name, stage / name)
    if include_private and root.exists():
        for child in root.iterdir():
            if child.name not in CODE_TREES | CODE_FILES | {GENERATION_ACTIVATION}:
                copy_checked(child, stage / child.name, private=True)
    if include_private:
        for name in ('client.json', 'routers.json', 'generated'):
            if not (stage / name).exists():
                copy_checked(source / name, stage / name, private=True)
        validate_config(stage / 'client.json', root)
    # The only new trust root is the completed private staging directory.
    # Its parent remains 0700 until every engine verifies and promotion begins.
    for binary in ('router-vpn-client', 'router-vpn-app', 'router-vpn-dns',
                   'router-vpn-start-layer-relay', 'router-vpn-update'):
        if not os.access(stage / binary, os.X_OK):
            raise ValueError('Required native executable is not executable: ' + binary)
    final_source = ordinary(source, directory=True)
    if (captured_source.st_dev, captured_source.st_ino, captured_source.st_mtime_ns, captured_source.st_ctime_ns) != (final_source.st_dev, final_source.st_ino, final_source.st_mtime_ns, final_source.st_ctime_ns):
        raise ValueError('The source package changed during installation capture')


def generation_json(value):
    # Match encoding/json's UTF-8 representation and default HTML escaping.
    raw = json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    for character, escaped in ((b'<', br'\u003c'), (b'>', br'\u003e'), (b'&', br'\u0026'),
                               (chr(0x2028).encode(), br'\u2028'), (chr(0x2029).encode(), br'\u2029')):
        raw = raw.replace(character, escaped)
    return raw


def generation_inventory(root: Path):
    records = []
    for base, directories, files in os.walk(root, followlinks=False):
        for name in sorted(directories + files):
            path = Path(base) / name
            if path == root / GENERATION_MANIFEST:
                continue
            info = ordinary(path, directory=path.is_dir(), trusted=True)
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                records.append({'path': relative, 'mode': stat.S_IMODE(info.st_mode), 'sha256': ''})
            else:
                digest = hashlib.sha256()
                with path.open('rb') as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(block)
                records.append({'path': relative, 'mode': stat.S_IMODE(info.st_mode), 'sha256': digest.hexdigest()})
            if len(records) > GENERATION_MAX_FILES:
                raise ValueError('Service generation inventory exceeded its entry bound')
    return sorted(records, key=lambda item: item['path'])


def generation_manifest(inventory):
    if not inventory or len(inventory) > GENERATION_MAX_FILES:
        raise ValueError('Service generation inventory exceeded its entry bound')
    manifest = generation_json({'schema': 1, 'files': inventory})
    if len(manifest) > GENERATION_MAX_MANIFEST:
        raise ValueError('Service generation manifest exceeded its byte bound')
    return manifest


def bounded_generation_read(path: Path, limit: int):
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Service generation metadata exceeded its byte bound')
    return raw


def stage_service_generation(stage: Path, root: Path):
    # No live image or generation is renamed, overwritten, or inferred from a
    # saved creator. Global source EX is still required by install(). Each
    # generation additionally has its own adjacent lifetime SH/GC EX lease.
    store = root.with_name(root.name + '.service-generations')
    if not store.exists():
        store.mkdir(mode=0o700)
        os.chown(store, 0, 0)
    ordinary(store, directory=True, trusted=True)
    if stat.S_IMODE(store.stat().st_mode) != 0o700:
        raise ValueError('Service generations directory is not private')
    temporary = Path(tempfile.mkdtemp(prefix='.new-', dir=store))
    try:
        for name in sorted(CODE_FILES | CODE_TREES):
            if (stage / name).exists():
                copy_checked(stage / name, temporary / name)
        inventory = generation_inventory(temporary)
        manifest = generation_manifest(inventory)
        generation = hashlib.sha256(manifest).hexdigest()
        destination = store / generation
        lock = store / (generation + '.lock')
        descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            named = ordinary(lock, trusted=True)
            actual = os.fstat(descriptor)
            if (actual.st_dev, actual.st_ino) != (named.st_dev, named.st_ino) or stat.S_IMODE(actual.st_mode) != 0o600:
                raise ValueError('Service generation lock changed identity')
            if destination.exists() or destination.is_symlink():
                ordinary(destination, directory=True, trusted=True)
                ordinary(destination / GENERATION_MANIFEST, trusted=True)
                if bounded_generation_read(destination / GENERATION_MANIFEST, GENERATION_MAX_MANIFEST) != manifest or generation_inventory(destination) != inventory:
                    raise ValueError('Existing immutable service generation changed')
            else:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with (temporary / GENERATION_MANIFEST).open('xb') as stream:
                    stream.write(manifest)
                    stream.flush()
                    os.fsync(stream.fileno())
                    os.fchmod(stream.fileno(), 0o600)
                os.rename(temporary, destination)
                parent = os.open(store, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
        finally:
            os.close(descriptor)
        image = next(item['sha256'] for item in inventory if item['path'] == 'router-vpn-client')
        activation = generation_json({'schema': 1, 'generation': generation, 'image_sha256': image})
        with (stage / GENERATION_ACTIVATION).open('xb') as stream:
            stream.write(activation)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o600)
        return destination
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def activated_service_image(root: Path):
    activation = root / GENERATION_ACTIVATION
    if not activation.exists() and not activation.is_symlink():
        return root / 'router-vpn-client'  # Strict compatibility for old installs.
    ordinary(activation, trusted=True)
    raw = bounded_generation_read(activation, GENERATION_MAX_ACTIVATION)
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {'schema', 'generation', 'image_sha256'} or type(value['schema']) is not int or value['schema'] != 1 or generation_json({'schema': value['schema'], 'generation': value['generation'], 'image_sha256': value['image_sha256']}) != raw:
        raise ValueError('Invalid service generation activation')
    for key in ('generation', 'image_sha256'):
        if not isinstance(value[key], str) or len(value[key]) != 64 or any(c not in '0123456789abcdef' for c in value[key]):
            raise ValueError('Invalid service generation digest')
    generation = root.with_name(root.name + '.service-generations') / value['generation']
    ordinary(generation.parent, directory=True, trusted=True)
    ordinary(generation, directory=True, trusted=True)
    ordinary(generation / GENERATION_MANIFEST, trusted=True)
    manifest = bounded_generation_read(generation / GENERATION_MANIFEST, GENERATION_MAX_MANIFEST)
    if hashlib.sha256(manifest).hexdigest() != value['generation'] or generation_manifest(generation_inventory(generation)) != manifest:
        raise ValueError('Service generation source changed')
    image = generation / 'router-vpn-client'
    ordinary(image, trusted=True)
    with image.open('rb') as stream:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
        digest = digest.hexdigest()
    if digest != value['image_sha256']:
        raise ValueError('Service generation executable changed')
    return image


def verify_runtimes(stage: Path):
    for flag in ('--verify-native-runtime', '--verify-amnezia-runtime'):
        command([stage / 'router-vpn-client', flag, stage])
    command(['/usr/bin/python3', '-Es', stage / 'client/verify-bundled-xray.py', stage / 'runtime/xray'])


def image_object(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
            'uid': info.st_uid, 'gid': info.st_gid}


def image_remaining(deadline_ns):
    remaining = (deadline_ns - time.time_ns()) / 1_000_000_000
    if remaining <= 0:
        raise TimeoutError('Original active image-upgrade deadline expired')
    return remaining


def image_sync(directory):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def image_atomic_json(path, value, *, deadline_ns=None):
    if deadline_ns is not None:
        image_remaining(deadline_ns)
    descriptor, temporary = tempfile.mkstemp(prefix='.image-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(generation_json(value))
            stream.flush()
            os.fsync(stream.fileno())
        if deadline_ns is not None:
            image_remaining(deadline_ns)
        os.replace(temporary, path)
        image_sync(path.parent)
        if deadline_ns is not None:
            image_remaining(deadline_ns)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def image_decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('Duplicate image-upgrade field')
            value[key] = item
        return value
    if not raw or len(raw) > IMAGE_FRAME_LIMIT:
        raise ValueError('Image-upgrade frame exceeded original bound')
    def nonfinite(value):
        raise ValueError('Nonfinite image-upgrade number')
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    if not isinstance(value, dict) or generation_json(value) != raw:
        raise ValueError('Noncanonical image-upgrade frame')
    return value


class ActiveCodeJournal:
    """Only the live original coordinator authorizes these code moves.

    This durable log preserves exact old objects for rollback; reading it never
    reconstructs a native creator or grants permission to resume a transaction.
    """
    def __init__(self, root, temporary, stage):
        self.root, self.temporary, self.stage = root, temporary, stage
        self.previous = temporary / 'previous-code'
        self.previous.mkdir(mode=0o700)
        self.path = temporary / 'active-image.json'
        self.root_object = image_object(ordinary(root, directory=True, trusted=True))
        self.run_object = image_object(ordinary(root / 'run', directory=True, trusted=True))
        self.lock_object = image_object(ordinary(root / 'run/kill-switch.lock', trusted=True))
        self.entries = []
        self.record = {'schema': 1, 'phase': 'staged', 'root': self.root_object,
                       'run': self.run_object, 'mutation_lock': self.lock_object,
                       'envelope': None, 'entries': self.entries}
        image_atomic_json(self.path, self.record)

    def current(self):
        for path, expected, directory in ((self.root, self.root_object, True),
                (self.root / 'run', self.run_object, True),
                (self.root / 'run/kill-switch.lock', self.lock_object, False)):
            if image_object(ordinary(path, directory=directory, trusted=True)) != expected:
                raise RuntimeError('Active upgrade lost original installation/private-state inode')

    def bind(self, envelope):
        self.current()
        for field in ('root', 'run', 'mutation_lock'):
            if envelope.get(field) != self.record[field]:
                raise RuntimeError('Coordinator did not retain original private installation objects')
        self.record['envelope'] = envelope
        self.save('reserved')

    def save(self, phase):
        self.record['phase'] = phase
        image_atomic_json(self.path, self.record)

    def promote(self, deadline_ns):
        self.current()
        if self.record['phase'] != 'reserved' or not self.record['envelope']:
            raise RuntimeError('Code promotion omitted original native reservation')
        # The original global source EX is held by the caller. No root, private
        # configuration, run directory or mutation lock is ever moved.
        for name in sorted(CODE_FILES | CODE_TREES):
            image_remaining(deadline_ns)
            self.current()
            target, staged, backup = self.root / name, self.stage / name, self.previous / name
            old = image_object(ordinary(target, directory=target.is_dir(), trusted=True)) if target.exists() or target.is_symlink() else None
            new = image_object(ordinary(staged, directory=staged.is_dir(), trusted=True)) if staged.exists() or staged.is_symlink() else None
            entry = {'name': name, 'old': old, 'new': new}
            self.entries.append(entry)
            self.save('promoting')  # Durable intent before either rename.
            if old is not None:
                os.rename(target, backup)
                image_sync(self.previous)
                image_sync(self.root)
            image_remaining(deadline_ns)
            if new is not None:
                os.rename(staged, target)
                image_sync(self.root)
                image_sync(self.stage)
            self.save('promoting')
        self.current()
        image_remaining(deadline_ns)
        self.save('code-promoted')

    def restore(self, deadline_ns):
        self.current()
        for entry in reversed(self.entries):
            image_remaining(deadline_ns)
            target, staged, backup = (self.root / entry['name'], self.stage / entry['name'], self.previous / entry['name'])
            if target.exists() or target.is_symlink():
                current = image_object(ordinary(target, directory=target.is_dir(), trusted=True))
                if current == entry['new']:
                    if staged.exists() or staged.is_symlink():
                        raise RuntimeError('Rollback found a replaced staging object')
                    os.rename(target, staged)
                elif current == entry['old'] and not backup.exists():
                    continue
                else:
                    raise RuntimeError('Rollback refuses foreign code inode')
            if entry['old'] is not None:
                if image_object(ordinary(backup, directory=backup.is_dir(), trusted=True)) != entry['old']:
                    raise RuntimeError('Rollback lost exact old code inode')
                os.rename(backup, target)
            elif backup.exists() or backup.is_symlink():
                raise RuntimeError('Rollback found an unowned previous object')
            image_sync(self.root)
            image_sync(self.stage)
            image_sync(self.previous)
        self.current()
        image_remaining(deadline_ns)
        self.save('code-restored')


class ActiveProcessPin:
    """A transferred original pidfd, checked against actual native readback."""
    def __init__(self, descriptor, observation, arguments, proc=Path('/proc')):
        self.descriptor, self.observation, self.arguments, self.proc = descriptor, observation, arguments, proc
        self.directory = None
        pid = observation.get('proc_process_id')
        if type(pid) is not int or pid < 1:
            raise ValueError('Image upgrade omitted original process identity')
        self.path = proc / str(pid)
        self.directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.identity = image_object(os.fstat(self.directory))
        try:
            self.current()
        except BaseException:
            os.close(self.directory)
            self.directory = None
            raise

    def read(self, name, maximum):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.directory)
        try:
            body = os.read(descriptor, maximum + 1)
            if len(body) > maximum:
                raise RuntimeError('Original process readback exceeded its bound')
            return body
        finally:
            os.close(descriptor)

    def current(self, *, allow_exit=False):
        if self.descriptor is None:
            raise RuntimeError('Original process pin was closed')
        poll = select.poll()
        poll.register(self.descriptor, select.POLLIN)
        ended = bool(poll.poll(0))
        if ended:
            if allow_exit:
                return False
            raise RuntimeError('Original upgrade process already exited')
        if os.readlink('/proc/self/fd/' + str(self.descriptor)) != 'anon_inode:[pidfd]':
            raise RuntimeError('Image upgrade did not transfer a native pidfd')
        fields = {}
        for line in bounded_generation_read(Path('/proc/self/fdinfo') / str(self.descriptor), 4096).decode().splitlines():
            key, separator, value = line.partition(':')
            if separator and key in ('Pid', 'NSpid'):
                if key in fields:
                    raise RuntimeError('Duplicate original pidfd namespace identity')
                fields[key] = value.split()
        record = self.observation
        native, proc_pid = record.get('process_id'), record.get('proc_process_id')
        mapping = fields.get('NSpid', [])
        if fields.get('Pid') != [str(proc_pid)] or not mapping or len(mapping) > 32 or mapping[0] != str(proc_pid) or mapping[-1] != str(native) or any(not x.isdecimal() or int(x) < 1 or str(int(x)) != x for x in mapping):
            raise RuntimeError('Original pidfd changed its namespace identity')
        if image_object(os.fstat(self.directory)) != self.identity or image_object(os.stat(self.path, follow_symlinks=False)) != self.identity:
            raise RuntimeError('Original process directory was replaced')
        body = self.read('stat', 8192).decode()
        opening, closing = body.find(' ('), body.rfind(') ')
        values = body[closing + 2:].split()
        if opening < 1 or closing <= opening or body[:opening] != str(proc_pid) or len(values) < 20 or values[0] in ('Z', 'X') or int(values[1]) != record.get('proc_parent_id') or int(values[19]) != record.get('start_ticks'):
            raise RuntimeError('Original process start generation changed')
        status = {}
        for line in self.read('status', 65536).decode().splitlines():
            key, separator, value = line.partition(':')
            if separator and key in ('Uid', 'Gid', 'Pid', 'Tgid', 'PPid', 'NSpid', 'NStgid'):
                if key in status:
                    raise RuntimeError('Original process repeated native credential evidence')
                status[key] = value.split()
        expected_status = {'Uid': ['0'] * 4, 'Gid': ['0'] * 4,
                           'Pid': [str(proc_pid)], 'Tgid': [str(proc_pid)],
                           'PPid': [str(record['proc_parent_id'])],
                           'NSpid': mapping, 'NStgid': mapping}
        if status != expected_status:
            raise RuntimeError('Original process lost privileged credentials or namespace mapping')
        for name, key in (('exe', 'image'), ('ns/net', 'network_namespace'), ('ns/pid', 'pid_namespace')):
            if image_object(os.stat(name, dir_fd=self.directory)) != record.get(key):
                raise RuntimeError('Original process image or namespace changed')
        if self.read('cmdline', 16384) != b'\0'.join(os.fsencode(value) for value in self.arguments) + b'\0':
            raise RuntimeError('Original process fixed role changed')
        if bounded_generation_read(self.proc / 'sys/kernel/random/boot_id', 128).decode().strip() != record.get('boot_id'):
            raise RuntimeError('Original process boot changed')
        return True

    def excludes(self, process):
        if process.name != str(self.observation['proc_process_id']):
            return False
        return self.current()

    def close(self):
        for field in ('directory', 'descriptor'):
            descriptor = getattr(self, field)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, field, None)


def image_process_observation(pid, proc=Path('/proc'), *, descriptor=None):
    if pid == os.getpid():
        directory = proc / 'self'
    else:
        if descriptor is None or os.readlink('/proc/self/fd/' + str(descriptor)) != 'anon_inode:[pidfd]':
            raise RuntimeError('Child process observation requires its original created pidfd')
        fields = {}
        for line in bounded_generation_read(Path('/proc/self/fdinfo') / str(descriptor), 4096).decode().splitlines():
            key, separator, value = line.partition(':')
            if separator and key in ('Pid', 'NSpid'):
                if key in fields:
                    raise RuntimeError('Duplicate original child pidfd identity')
                fields[key] = value.split()
        mapping = fields.get('NSpid', [])
        if not mapping or len(mapping) > 32 or fields.get('Pid') != [mapping[0]] or mapping[-1] != str(pid) or any(not x.isdecimal() or int(x) < 1 or str(int(x)) != x for x in mapping):
            raise RuntimeError('Original child pidfd changed native namespace mapping')
        directory = proc / mapping[0]
    body = bounded_generation_read(directory / 'stat', 8192).decode()
    opening, closing = body.find(' ('), body.rfind(') ')
    values = body[closing + 2:].split()
    if opening < 1 or closing <= opening or len(values) < 20:
        raise RuntimeError('Coordinator has no bounded native process identity')
    return {'boot_id': bounded_generation_read(proc / 'sys/kernel/random/boot_id', 128).decode().strip(),
            'process_id': pid, 'proc_process_id': int(body[:opening]),
            'proc_parent_id': int(values[1]), 'start_ticks': int(values[19]),
            'image': image_object(os.stat(directory / 'exe')),
            'network_namespace': image_object(os.stat(directory / 'ns/net')),
            'pid_namespace': image_object(os.stat(directory / 'ns/pid'))}


class ActiveImageCoordinator:
    """One directly created original helper and its inherited FD3 channel."""
    def __init__(self, root, new_generation, *, deadline_ns=None):
        self.root, self.new_generation = root, new_generation
        self.deadline_ns = deadline_ns if deadline_ns is not None else time.time_ns() + IMAGE_WORK_NS
        self.cleanup_deadline_ns = 0
        self.proposed_cleanup_ns = 0
        self.sequence, self.pending, self.envelope, self.upgrade = 0, None, None, None
        self.awaiting = None
        self.pins, self.leases = [], []
        self.process = None
        self.pid = None
        self.channel = None
        self.old_image = activated_service_image(root)
        self.old_selection = image_decode(bounded_generation_read(root / GENERATION_ACTIVATION, GENERATION_MAX_ACTIVATION))
        self.activation = bounded_generation_read(root / GENERATION_ACTIVATION, GENERATION_MAX_ACTIVATION)
        self.new_image = root.with_name(root.name + '.service-generations') / new_generation['generation'] / 'router-vpn-client'
        self.activation_published = False
        try:
            for image in (self.old_image, self.new_image):
                descriptor = os.open(str(image.parent) + '.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                self.leases.append(descriptor)
                expected = ordinary(Path(str(image.parent) + '.lock'), trusted=True)
                if image_object(expected) != image_object(os.fstat(descriptor)) or stat.S_IMODE(expected.st_mode) != 0o600:
                    raise RuntimeError('Original generation source lease changed')
                fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            self.channel = parent
            try:
                actions = [(os.POSIX_SPAWN_CLOSE, parent.fileno())]
                if child.fileno() != 3:
                    actions += [(os.POSIX_SPAWN_DUP2, child.fileno(), 3), (os.POSIX_SPAWN_CLOSE, child.fileno())]
                self.pid = os.posix_spawn(str(self.old_image), [str(self.old_image), IMAGE_UPGRADE_ARGUMENT],
                                         {'PATH': SYSTEM_PATH, 'LC_ALL': 'C', 'HOME': '/root'}, file_actions=actions)
            finally:
                child.close()
            # An unreaped directly created child cannot have its PID recycled.
            descriptor = os.pidfd_open(self.pid, 0)
            try:
                observed = image_process_observation(self.pid, descriptor=descriptor)
                expected = image_object(ordinary(self.old_image, trusted=True))
                if observed['image'] != expected:
                    raise RuntimeError('Coordinator did not execute the captured immutable image')
                parent = image_process_observation(os.getpid())
                if observed['proc_parent_id'] != parent['proc_process_id'] or any(observed[key] != parent[key] for key in ('network_namespace', 'pid_namespace', 'boot_id')):
                    raise RuntimeError('Coordinator lost original creator or namespace')
                self.process = ActiveProcessPin(descriptor, observed, [str(self.old_image), IMAGE_UPGRADE_ARGUMENT])
                descriptor = None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            image_remaining(self.deadline_ns)
        except BaseException:
            self.close()
            raise

    def cleanup_clock(self):
        if not self.proposed_cleanup_ns:
            self.proposed_cleanup_ns = time.time_ns() + IMAGE_CLEANUP_NS
        return self.cleanup_deadline_ns or self.proposed_cleanup_ns

    def _accept(self, reply, descriptors, requested):
        reply_order = ('schema', 'sequence', 'action', 'complete', 'error', 'upgrade')
        if list(reply) != [key for key in reply_order if key in reply] or type(reply.get('schema')) is not int or type(reply.get('sequence')) is not int or reply.get('schema') != 1 or reply.get('sequence') != requested['sequence'] or reply.get('action') != requested['action'] or type(reply.get('complete')) is not bool:
            raise RuntimeError('Coordinator changed original control sequence or role')
        update = reply.get('upgrade')
        if update is not None:
            allowed = {'envelope', 'phase', 'cleanup_deadline_ns', 'source', 'destination', 'old_peer', 'new_peer', 'coordinator_peer', 'frozen', 'source_removed', 'ready', 'old_joined', 'rollback_allowed', 'activation_allowed'}
            update_order = ('envelope', 'phase', 'cleanup_deadline_ns', 'source', 'destination', 'old_peer', 'new_peer', 'coordinator_peer', 'frozen', 'source_removed', 'ready', 'old_joined', 'rollback_allowed', 'activation_allowed')
            if not isinstance(update, dict) or set(update) - allowed or list(update) != [key for key in update_order if key in update]:
                raise RuntimeError('Coordinator changed image-upgrade response schema')
            envelope = update.get('envelope')
            if not isinstance(envelope, dict) or type(envelope.get('schema')) is not int or envelope.get('schema') != 1 or envelope.get('deadline_ns') != self.deadline_ns or envelope.get('old_generation') != self.old_selection or envelope.get('new_generation') != self.new_generation or envelope.get('activation_sha256') != hashlib.sha256(self.activation).hexdigest():
                raise RuntimeError('Coordinator changed original immutable image scope')
            envelope_order = ('schema', 'id', 'deadline_ns', 'old_generation', 'new_generation', 'activation_sha256', 'root', 'run', 'mutation_lock', 'saved_state', 'saved_state_sha256', 'profile_id', 'profile_revision', 'home_lan', 'endpoints', 'source_sha256', 'destination_session', 'destination_sha256')
            if list(envelope) != list(envelope_order):
                raise RuntimeError('Coordinator changed canonical immutable envelope schema')
            if self.envelope is not None and envelope != self.envelope:
                raise RuntimeError('Coordinator replaced original native transaction')
            cleanup = update.get('cleanup_deadline_ns', 0)
            if cleanup:
                if type(cleanup) is not int or self.cleanup_deadline_ns and cleanup != self.cleanup_deadline_ns or self.proposed_cleanup_ns and cleanup > self.proposed_cleanup_ns or cleanup > time.time_ns() + IMAGE_CLEANUP_NS:
                    raise RuntimeError('Coordinator renewed original cleanup allowance')
            if update.get('phase') not in ('reserved', 'successor-prepared', 'frozen', 'code-verified', 'source-removed', 'successor-published', 'successor-ready', 'settled', 'aborting', 'aborted'):
                raise RuntimeError('Coordinator supplied unknown native phase')
            for field in ('frozen', 'source_removed', 'ready', 'old_joined', 'rollback_allowed', 'activation_allowed'):
                if type(update.get(field)) is not bool:
                    raise RuntimeError('Coordinator omitted explicit native phase state')
        expected = 3 if requested['action'] == 'freeze' and reply.get('complete') and not reply.get('error') and update and update['frozen'] else 0
        if len(descriptors) != expected:
            raise RuntimeError('Coordinator omitted or substituted original process descriptors')
        if expected:
            arguments = ([str(self.old_image), SERVICE_ARGUMENT], [str(self.new_image), SERVICE_ARGUMENT], [str(self.old_image), IMAGE_UPGRADE_ARGUMENT])
            keys = ('old_peer', 'new_peer', 'coordinator_peer')
            candidates = []
            try:
                for key, args in zip(keys, arguments):
                    descriptor = descriptors.pop(0)
                    try:
                        pin = ActiveProcessPin(descriptor, update.get(key, {}), args)
                    except BaseException:
                        os.close(descriptor)
                        raise
                    candidates.append(pin)
                    if pin.observation.get('image') != image_object(ordinary(Path(args[0]), trusted=True)):
                        raise RuntimeError('Transferred process did not execute its exact generation image')
                    for namespace in ('network_namespace', 'pid_namespace'):
                        if pin.observation.get(namespace) != self.process.observation.get(namespace):
                            raise RuntimeError('Transferred service changed original coordinator namespace')
                if candidates[2].observation != self.process.observation:
                    raise RuntimeError('Coordinator transferred a different process as itself')
                if self.pins:
                    if len(self.pins) != 3:
                        raise RuntimeError('Original frozen process capture was incomplete')
                    for retained, candidate in zip(self.pins, candidates):
                        retained.current()
                        if retained.observation != candidate.observation or retained.arguments != candidate.arguments:
                            raise RuntimeError('Freeze replay replaced an original retained process')
                    # Exact cached replies carry duplicate descriptors. Keep the
                    # original capabilities; close only these redundant copies.
                else:
                    self.pins, candidates = candidates, []
            finally:
                for pin in candidates:
                    pin.close()
        if update is not None:
            self.envelope = envelope
            if cleanup:
                self.cleanup_deadline_ns = cleanup
            self.upgrade = update
        if reply.get('error') or not reply['complete']:
            raise RuntimeError('Original image-upgrade operation did not complete: ' + str(reply.get('error', 'pending')))
        if update is None:
            raise RuntimeError('Coordinator omitted original native phase evidence')
        return update

    def _roundtrip(self, request, deadline_ns):
        self.process.current()
        self.channel.settimeout(image_remaining(deadline_ns))
        raw = generation_json(request)
        if len(raw) > IMAGE_FRAME_LIMIT:
            raise RuntimeError('Incomplete original coordinator frame')
        if self.awaiting is None:
            if self.channel.send(raw) != len(raw):
                raise RuntimeError('Incomplete original coordinator frame')
            self.awaiting = raw
        elif self.awaiting != raw:
            raise RuntimeError('Original coordinator response has not been consumed')
        # SOCK_SEQPACKET send is atomic. After successful send, a read timeout
        # resumes this same receive; resending would queue a stale duplicate
        # before the next abort/status response.
        self.channel.settimeout(image_remaining(deadline_ns))
        descriptors = []
        try:
            raw, ancillary, flags, _ = self.channel.recvmsg(IMAGE_FRAME_LIMIT + 1, socket.CMSG_SPACE(16 * array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
            for level, kind, value in ancillary:
                if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS or len(value) % array.array('i').itemsize:
                    raise RuntimeError('Unexpected coordinator ancillary evidence')
                values = array.array('i')
                values.frombytes(value)
                descriptors.extend(values)
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                raise RuntimeError('Truncated coordinator evidence')
            reply = image_decode(raw)
            # A fully received exact response consumes the sequence even when
            # the actual operation reports failure. Unknown replies stay pending.
            if reply.get('sequence') == request['sequence'] and reply.get('action') == request['action']:
                self.sequence, self.pending, self.awaiting = request['sequence'], None, None
            result = self._accept(reply, descriptors, request)
            self.process.current()
            image_remaining(deadline_ns)
            return result
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    def call(self, action, *, cleanup=False):
        deadline = self.cleanup_clock() if cleanup else self.deadline_ns
        if self.pending is not None:
            previous = self.pending
            result = self._roundtrip(previous, deadline)
            if previous['action'] == action:
                return result
        request = {'schema': 1, 'sequence': self.sequence + 1, 'action': action, 'deadline_ns': self.deadline_ns}
        if action == 'prepare':
            request['new_generation'] = self.new_generation
        elif self.envelope is not None:
            request['envelope'] = self.envelope
        else:
            raise RuntimeError('Later phase omitted original native reservation')
        if cleanup:
            request['cleanup_deadline_ns'] = deadline
        self.pending = request
        return self._roundtrip(request, deadline)

    def current_frozen(self):
        if not self.upgrade or not self.upgrade['frozen'] or len(self.pins) != 3:
            raise RuntimeError('Source promotion omitted both frozen original services')
        for pin in self.pins:
            pin.current()

    def verify_new_ready(self):
        update = self.upgrade or {}
        if not update.get('ready') or update.get('phase') not in ('successor-ready', 'settled') or len(self.pins) != 3:
            raise RuntimeError('Exact successor never acknowledged readiness')
        self.pins[1].current()

    def verify_settled(self):
        update = self.upgrade or {}
        if update.get('phase') != 'settled' or not update.get('old_joined') or not update.get('ready') or len(self.pins) != 3:
            raise RuntimeError('Original service upgrade was not joined and settled')
        if self.pins[0].current(allow_exit=True):
            raise RuntimeError('Original service still runs after claimed settlement')
        self.pins[1].current()

    def join(self, deadline_ns):
        if not self.upgrade or self.upgrade.get('phase') not in ('settled', 'aborted'):
            raise RuntimeError('Cannot join an unsettled original coordinator')
        self.channel.shutdown(socket.SHUT_WR)
        poll = select.poll()
        poll.register(self.process.descriptor, select.POLLIN)
        while not poll.poll(max(1, min(1000, int(image_remaining(deadline_ns) * 1000)))):
            pass
        pid, status = os.waitpid(self.pid, 0)
        if pid != self.pid or status != 0:
            raise RuntimeError('Original coordinator failed during terminal join')
        self.pid = None
        image_remaining(deadline_ns)

    def close(self):
        # Closing installer handles never kills a service or reconstructs native
        # cleanup. A lost control channel leaves settlement with its original owners.
        if self.channel is not None:
            self.channel.close()
            self.channel = None
        for pin in self.pins:
            pin.close()
        self.pins = []
        if self.process is not None:
            self.process.close()
            self.process = None
        for descriptor in self.leases:
            os.close(descriptor)
        self.leases = []
        if self.pid is not None:
            os.waitpid(self.pid, os.WNOHANG)


class SystemIntegration:
    def __init__(self, filesystem=Path('/'), run=command):
        self.filesystem, self.run = filesystem, run
        self.previous = []
        self.was_enabled = False
        self.legacy_enabled = False
        self.legacy_early_enabled = False
        self.enable_attempted = False
        self.changed = False
        self.retired_unit = None
        self.successor_unit = None
        self.successor_unit_bytes = None

    def path(self, name):
        return self.filesystem / name.lstrip('/')

    def retire_idle(self, root: Path):
        unit = EARLY_NAME
        if (root / GENERATION_ACTIVATION).exists():
            image = activated_service_image(root)
            selected = 'router-vpn-standard-owner-' + image.parent.name + '.service'
            if self.path('/etc/systemd/system/' + selected).exists():
                unit = selected
        self.retired_unit = unit
        service = self.path('/etc/systemd/system/' + unit)
        if not service.exists() and not service.is_symlink():
            return
        ordinary(service, trusted=True)
        # This identifies which installed protocol to call; it grants no
        # native cleanup authority. The helper authenticates the actual peer,
        # checks native absence and observes its original pidfd retirement.
        if SERVICE_ARGUMENT not in service.read_text():
            return
        ordinary(root / 'router-vpn-client', trusted=True)
        self.run(['/usr/bin/env', '-i', 'PATH=' + SYSTEM_PATH,
                  root / 'router-vpn-client', UPGRADE_ARGUMENT])
        return True

    def activate(self, root: Path):
        # systemd waits for the new original process's READY notification.
        # The installer runner is bounded; a degraded creator is retained by
        # the service even if this request times out without READY.
        self.run(['/usr/bin/systemctl', 'start', EARLY_NAME])
        if self.retired_unit and self.retired_unit != EARLY_NAME:
            self.run(['/usr/bin/systemctl', 'disable', self.retired_unit])
        # An old oneshot may remain active/exited. Its different unit name
        # cannot fake this new process's READY; disable only its future boot
        # activation after the retained owner is ready, without stopping it.
        if self.legacy_early_enabled:
            self.run(['/usr/bin/systemctl', 'disable', LEGACY_EARLY_NAME])

    def write(self, name, data, mode=0o644, *, deadline_ns=None):
        if deadline_ns is not None:
            image_remaining(deadline_ns)
        target = self.path(name)
        parents = []
        parent = target.parent
        while not parent.exists():
            parents.append(parent)
            parent = parent.parent
        while parent != self.filesystem.parent:
            ordinary(parent, directory=True, trusted=True)
            if parent == self.filesystem:
                break
            parent = parent.parent
        for directory in reversed(parents):
            directory.mkdir(mode=0o755)
        if target.exists() or target.is_symlink():
            info = ordinary(target, trusted=True)
            prior = (target.read_bytes(), stat.S_IMODE(info.st_mode))
        else:
            prior = None
        self.previous.append((target, prior))
        fd, temporary = tempfile.mkstemp(prefix='.routervpn-', dir=target.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), mode)
                os.fchown(stream.fileno(), 0, 0)
            if deadline_ns is not None:
                image_remaining(deadline_ns)
            os.replace(temporary, target)
            if deadline_ns is not None:
                image_remaining(deadline_ns)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def install(self, root: Path):
        legacy = self.run(['/usr/bin/systemctl', 'is-active', 'router-vpn-client.service'], check=False)
        if legacy.returncode == 0:
            raise RuntimeError('Stop the legacy router-vpn-client service before upgrading to the native authenticated controller.')
        if legacy.returncode not in (3, 4):
            raise RuntimeError('Cannot prove that the legacy controller service is inactive')
        legacy = self.run(['/usr/bin/systemctl', 'is-enabled', 'router-vpn-client.service'], check=False)
        if legacy.returncode not in (0, 1, 3, 4):
            raise RuntimeError('Cannot read the legacy controller service enablement state')
        self.legacy_enabled = legacy.returncode == 0
        result = self.run(['/usr/bin/systemctl', 'is-enabled', EARLY_NAME], check=False)
        if result.returncode not in (0, 1, 3, 4):
            raise RuntimeError('Cannot read the existing early-protection service state')
        self.was_enabled = result.returncode == 0
        previous_early = self.run(['/usr/bin/systemctl', 'is-enabled', LEGACY_EARLY_NAME], check=False)
        if previous_early.returncode not in (0, 1, 3, 4):
            raise RuntimeError('Cannot read the previous early-protection service enablement state')
        self.legacy_early_enabled = previous_early.returncode == 0
        self.changed = True
        if self.legacy_enabled:
            self.run(['/usr/bin/systemctl', 'disable', 'router-vpn-client.service'])
        self.write('/usr/local/bin/router-vpn', LAUNCHER.encode(), 0o755)
        self.write('/usr/local/sbin/router-vpn-killswitch-recovery', RECOVERY.encode(), 0o755)
        self.write('/usr/share/applications/router-vpn.desktop', (root / 'router-vpn.desktop').read_bytes())
        self.write('/usr/share/icons/hicolor/256x256/apps/router-vpn.png', (root / 'router-vpn.png').read_bytes())
        self.write('/usr/share/polkit-1/actions/com.eabusham.routervpn.controller.policy',
                   (root / 'client/linux/com.eabusham.routervpn.controller.policy').read_bytes())
        image = activated_service_image(root)
        unit = EARLY_UNIT.replace('/opt/router-vpn-client/router-vpn-client ' + SERVICE_ARGUMENT, str(image) + ' ' + SERVICE_ARGUMENT)
        self.write('/etc/systemd/system/' + EARLY_NAME, unit.encode())
        for unit in NETWORK_UNITS:
            self.write('/etc/systemd/system/' + unit + '.d/50-router-vpn-protection.conf', NETWORK_DROPIN.encode())
        self.run(['/usr/bin/systemctl', 'daemon-reload'])
        self.enable_attempted = True
        self.run(['/usr/bin/systemctl', 'enable', EARLY_NAME])
        # Activation occurs only after the source EX lock is released. Never
        # invoke a second Python reassert owner or stop/restart networking.

    def rollback(self):
        if not self.changed:
            return
        if self.enable_attempted and not self.was_enabled:
            self.run(['/usr/bin/systemctl', 'disable', EARLY_NAME])
        for target, prior in reversed(self.previous):
            if prior is None:
                target.unlink(missing_ok=True)
            else:
                data, mode = prior
                with target.open('wb') as stream:
                    stream.write(data)
                target.chmod(mode)
        self.run(['/usr/bin/systemctl', 'daemon-reload'])
        if self.legacy_enabled:
            self.run(['/usr/bin/systemctl', 'enable', 'router-vpn-client.service'])


    def active_command(self, arguments, deadline_ns, *, check=True):
        image_remaining(deadline_ns)
        result = self.run(arguments, check=check, deadline_ns=deadline_ns)
        image_remaining(deadline_ns)
        return result

    def start_successor(self, image, deadline_ns):
        ordinary(image, trusted=True)
        generation = image.parent.name
        if len(generation) != 64 or any(c not in '0123456789abcdef' for c in generation):
            raise RuntimeError('Candidate unit omitted exact immutable generation')
        self.successor_unit = 'router-vpn-standard-owner-' + generation + '.service'
        self.successor_unit_bytes = EARLY_UNIT.replace('/opt/router-vpn-client/router-vpn-client ' + SERVICE_ARGUMENT, str(image) + ' ' + SERVICE_ARGUMENT).encode()
        self.write('/etc/systemd/system/' + self.successor_unit, self.successor_unit_bytes, deadline_ns=deadline_ns)
        self.active_command(['/usr/bin/systemctl', 'daemon-reload'], deadline_ns)
        # READY is deliberately withheld until the authenticated native commit.
        # Blocking here would deadlock the original pending handoff.
        self.active_command(['/usr/bin/systemctl', '--no-block', 'start', self.successor_unit], deadline_ns)

    def publish_active(self, root, coordinator, deadline_ns):
        update = coordinator.upgrade or {}
        if not update.get('activation_allowed') or not update.get('source_removed') or update.get('phase') != 'successor-published':
            raise RuntimeError('Activation omitted the original native commit acknowledgment')
        coordinator.pins[1].current()
        image_remaining(deadline_ns)
        actual = bounded_generation_read(root / GENERATION_ACTIVATION, GENERATION_MAX_ACTIVATION)
        if actual == coordinator.activation:
            image_atomic_json(root / GENERATION_ACTIVATION, coordinator.new_generation, deadline_ns=deadline_ns)
        elif actual != generation_json(coordinator.new_generation):
            raise RuntimeError('Original activation changed before native commit publication')
        coordinator.activation_published = True
        # Private configuration/state is untouched. Only the normal installed
        # launch assets and future unit dependencies select the committed code.
        self.write('/usr/local/bin/router-vpn', LAUNCHER.encode(), 0o755, deadline_ns=deadline_ns)
        self.write('/usr/local/sbin/router-vpn-killswitch-recovery', RECOVERY.encode(), 0o755, deadline_ns=deadline_ns)
        self.write('/usr/share/applications/router-vpn.desktop', (root / 'router-vpn.desktop').read_bytes(), deadline_ns=deadline_ns)
        self.write('/usr/share/icons/hicolor/256x256/apps/router-vpn.png', (root / 'router-vpn.png').read_bytes(), deadline_ns=deadline_ns)
        self.write('/usr/share/polkit-1/actions/com.eabusham.routervpn.controller.policy',
                   (root / 'client/linux/com.eabusham.routervpn.controller.policy').read_bytes(), deadline_ns=deadline_ns)
        dropin = NETWORK_DROPIN.replace(EARLY_NAME, self.successor_unit).encode()
        for unit in NETWORK_UNITS:
            image_remaining(deadline_ns)
            self.write('/etc/systemd/system/' + unit + '.d/50-router-vpn-protection.conf', dropin, deadline_ns=deadline_ns)
        self.active_command(['/usr/bin/systemctl', 'daemon-reload'], deadline_ns)
        self.active_command(['/usr/bin/systemctl', 'enable', self.successor_unit], deadline_ns)
        image_remaining(deadline_ns)
        coordinator.pins[1].current()

    def verify_active_ready(self, coordinator, deadline_ns):
        coordinator.verify_new_ready()
        unit_path = self.path('/etc/systemd/system/' + self.successor_unit)
        ordinary(unit_path, trusted=True)
        if unit_path.read_bytes() != self.successor_unit_bytes:
            raise RuntimeError('Candidate notify unit changed its original executable or role')
        self.active_command(['/usr/bin/systemctl', 'start', self.successor_unit], deadline_ns)
        result = self.active_command(['/usr/bin/systemctl', 'show', '--property=MainPID,ActiveState,SubState', self.successor_unit], deadline_ns)
        fields = {}
        for line in result.stdout.splitlines():
            key, separator, value = line.partition('=')
            if not separator or key not in ('MainPID', 'ActiveState', 'SubState') or key in fields:
                raise RuntimeError('Candidate unit readiness was not exact')
            fields[key] = value
        expected = {'MainPID': str(coordinator.pins[1].observation['process_id']), 'ActiveState': 'active', 'SubState': 'running'}
        if fields != expected:
            raise RuntimeError('READY came from another unit/process or an active exited owner')
        coordinator.verify_new_ready()

    def finish_active(self, coordinator, deadline_ns):
        coordinator.verify_settled()
        old_unit = 'router-vpn-standard-owner-' + coordinator.old_selection['generation'] + '.service'
        if not self.path('/etc/systemd/system/' + old_unit).exists():
            old_unit = EARLY_NAME
        # Native old ownership and its actual process already joined. Disabling
        # only future boot activation never stops networking or a live creator.
        self.active_command(['/usr/bin/systemctl', 'disable', old_unit], deadline_ns)
        coordinator.verify_settled()


def install_active_image(source, root, integration, verifier, proc):
    """Actual installed Always handoff; metadata only selects this protocol.

    The original coordinator proves the live guard and joined engine before it
    permits any source mutation. The ordinary idle/legacy installer is unchanged.
    """
    temporary = Path(tempfile.mkdtemp(prefix='.' + root.name + '.install-active-', dir=root.parent))
    stage = temporary / 'new'
    stage.mkdir(mode=0o700)
    coordinator = None
    journal = None
    try:
        stage_application(source, root, stage, include_private=False)
        verifier(stage)
        stage_service_generation(stage, root)
        new_generation = image_decode(bounded_generation_read(stage / GENERATION_ACTIVATION, GENERATION_MAX_ACTIVATION))
        journal = ActiveCodeJournal(root, temporary, stage)
        # Explicit active-upgrade budget starts here, after package verification.
        # It is not a series of the ordinary idle helper's independent timeouts.
        coordinator = ActiveImageCoordinator(root, new_generation)
        update = coordinator.call('prepare')
        journal.bind(update['envelope'])
        integration.start_successor(coordinator.new_image, coordinator.deadline_ns)
        coordinator.call('successor-started')
        coordinator.call('freeze')
        coordinator.current_frozen()
        with installation_lock(root):
            coordinator.current_frozen()
            reject_running_previous(root, proc, original_pins=coordinator.pins)
            journal.promote(coordinator.deadline_ns)
            reject_running_previous(root, proc, original_pins=coordinator.pins)
            coordinator.current_frozen()
        # Each service reacquires its exact global SH only after installer EX
        # closes; holding EX while asking for this acknowledgment would deadlock.
        coordinator.call('code-promoted')
        coordinator.call('commit')
        journal.save('successor-published')
        integration.publish_active(root, coordinator, coordinator.deadline_ns)
        coordinator.call('activation-published')
        integration.verify_active_ready(coordinator, coordinator.deadline_ns)
        coordinator.call('settle')
        integration.finish_active(coordinator, coordinator.deadline_ns)
        coordinator.join(coordinator.deadline_ns)
        journal.save('settled')
        image_remaining(coordinator.deadline_ns)
        shutil.rmtree(temporary)
    except BaseException as original_error:
        if coordinator is None:
            shutil.rmtree(temporary)
            raise
        # Only this same admitted operation can activate cleanup. A serialized
        # journal, absent reply or systemd state never authorizes restoration.
        try:
            coordinator.cleanup_clock()
            try:
                update = coordinator.call('abort', cleanup=True)
            except BaseException:
                if coordinator.pending is not None or coordinator.envelope is None:
                    raise
                # An acknowledged pending operation error consumed its sequence;
                # this is the first abort action, not a replacement transaction.
                update = coordinator.call('abort', cleanup=True)
            if update['source_removed']:
                # This is safety settlement of the same accepted native commit,
                # never another candidate or a late successful installer result.
                if update['phase'] == 'source-removed':
                    update = coordinator.call('commit', cleanup=True)
                if update['phase'] == 'successor-published':
                    integration.publish_active(root, coordinator, coordinator.cleanup_clock())
                    update = coordinator.call('activation-published', cleanup=True)
                if update['phase'] == 'successor-ready':
                    integration.verify_active_ready(coordinator, coordinator.cleanup_clock())
                    update = coordinator.call('settle', cleanup=True)
                integration.finish_active(coordinator, coordinator.cleanup_clock())
                coordinator.join(coordinator.cleanup_clock())
                journal.save('settled-after-failure')
                shutil.rmtree(temporary)
            elif update['rollback_allowed']:
                coordinator.current_frozen()
                with installation_lock(root):
                    coordinator.current_frozen()
                    reject_running_previous(root, proc, original_pins=coordinator.pins)
                    journal.restore(coordinator.cleanup_clock())
                update = coordinator.call('code-restored', cleanup=True)
            if not update['source_removed']:
                if update.get('phase') != 'aborted':
                    raise RuntimeError('Original cleanup did not prove aborted handoff')
                if journal is not None and journal.entries and journal.record['phase'] != 'code-restored':
                    raise RuntimeError('Original native abort did not restore captured code')
                coordinator.join(coordinator.cleanup_clock())
                # Candidate unit was never enabled or selected before commit.
                # Its immutable source remains; an aborted empty unit is harmless.
                shutil.rmtree(temporary)
        except BaseException as cleanup_error:
            if journal is not None:
                journal.record['failure'] = 'Original operation or settlement remains incomplete'
                journal.save('retained')
            raise RuntimeError('Active image upgrade remains owned and incomplete; both generations and recovery journal retained at ' + str(temporary) + ': ' + str(cleanup_error)) from original_error
        raise
    finally:
        if coordinator is not None:
            coordinator.close()


def install(source: Path, root=ROOT, *, integration=None, verifier=verify_runtimes, proc=Path('/proc')):
    if os.geteuid() != 0:
        raise PermissionError('Run the native installer with sudo.')
    integration = integration if integration is not None else SystemIntegration()
    with installation_transaction(root):
        prefix = '.' + root.name + '.install-'
        pending = list(root.parent.glob(prefix + '*'))
        if pending:
            raise RuntimeError('An interrupted native installation needs recovery; retained files: ' + ', '.join(map(str, pending)))
        # Presence selects an authenticated protocol only. The coordinator must
        # still prove the exact live original Always creator and joined engine.
        if (root / GENERATION_ACTIVATION).exists() and (root / 'run/kill-switch.json').exists():
            if not (root / 'run/kill-switch.lock').exists():
                reject_retained_protection(root)
            return install_active_image(source, root, integration, verifier, proc)
        retired_service = integration.retire_idle(root)
        try:
            with installation_lock(root):
                reject_running_previous(root, proc)
                reject_retained_protection(root)
                temporary = Path(tempfile.mkdtemp(prefix=prefix, dir=root.parent))
                stage, previous = temporary / 'new', temporary / 'previous'
                stage.mkdir(mode=0o700)
                os.chown(stage, 0, 0)
                promoted = False
                try:
                    stage_application(source, root, stage)
                    verifier(stage)
                    stage_service_generation(stage, root)
                    # An old application cannot acquire the shared launch lock
                    # while staged state is captured. Recheck legacy executables.
                    reject_running_previous(root, proc)
                    reject_retained_protection(root)
                    if root.exists():
                        os.rename(root, previous)
                    os.rename(stage, root)
                    promoted = True
                    root.chmod(0o755)
                    integration.install(root)
                except BaseException:
                    if promoted:
                        try:
                            integration.rollback()
                            os.rename(root, stage)
                            if previous.exists():
                                os.rename(previous, root)
                        except BaseException as rollback_error:
                            raise RuntimeError('Installation rollback needs recovery; previous bytes retained at ' + str(temporary)) from rollback_error
                    elif previous.exists():
                        os.rename(previous, root)
                    shutil.rmtree(temporary)
                    raise
        except BaseException as preparation_error:
            # The old idle owner may already have joined. Once rollback has
            # restored its exact source tree and EX has closed, restart that
            # original installation through its fresh absence-checked owner.
            if retired_service and not list(root.parent.glob(prefix + '*')):
                try:
                    integration.activate(root)
                except BaseException as restart_error:
                    raise RuntimeError('Previous installation was restored but its original idle service readiness was not proved: ' + str(restart_error)) from preparation_error
            raise
        try:
            integration.activate(root)
        except BaseException as activation_error:
            # The new service may already own an actual partial native creator.
            # A failed/lost READY response cannot authorize stopping it, moving
            # its source/state inodes or deleting its previous installation.
            raise RuntimeError('New protection owner activation did not complete; current and previous installation bytes retained for owned recovery at ' + str(temporary)) from activation_error
        shutil.rmtree(temporary)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: install-linux-native.py /path/to/extracted/native/package')
    try:
        ordinary(Path('/'), directory=True, trusted=True)
        ordinary(Path('/opt'), directory=True, trusted=True)
        if not Path('/run/systemd/system').is_dir():
            raise RuntimeError('This native installer requires a running systemd manager for persistent Always protection.')
        install(Path(os.path.abspath(sys.argv[1])))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print('Router VPN installation failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
    print('Router VPN installed. Open Router VPN from the application menu and approve its administrator request.')
    print('Linked nodes and private state were preserved. Emergency local recovery: sudo router-vpn-killswitch-recovery')
