#!/usr/bin/env python3
"""Protected, complete original-code receipts for managed macOS upgrades.

A receipt is created only for freshly captured, verified installation code.
It is never reconstructed from a legacy installation. Protected metadata alone
does not establish completeness: every recorded file and directory, the exact
code scope, root inode, native image set, and absence of executable private
files are checked again before the receipt can exclude a live native image.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat

SPEC = importlib.util.spec_from_file_location('macos_generation_original_image', Path(__file__).with_name('install-macos-image.py'))
IMAGE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(IMAGE)
RECEIPT_LIMIT = 4 * 1024 * 1024
MEMBER_LIMIT = 8192
REQUIRED_IMAGES = frozenset({'router-vpn-client', 'router-vpn-dns', 'router-vpn-start-layer-relay',
                             'router-vpn-update', 'RouterVPN.app/Contents/MacOS/RouterVPN'})


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate managed installation receipt field')
        result[key] = value
    return result


def receipt_path(root):
    return root.with_name(root.name + '.generation.json')


def object_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def member_identity(info):
    # A later Gatekeeper quarantine update may legitimately change ctime.
    # Exact bytes, inode, ownership, mode, links, size and mtime remain pinned;
    # each individual read additionally requires stable ctime on both ends.
    return [*object_identity(info), info.st_nlink, info.st_size, info.st_mtime_ns]


def hexadecimal(value, size):
    return type(value) is str and len(value) == size and all(letter in '0123456789abcdef' for letter in value)


def validate_members(members):
    for name, member in members.items():
        if (type(name) is not str or not name or Path(name).is_absolute() or
                any(part in ('', '.', '..') for part in name.split('/')) or type(member) is not dict):
            raise ValueError('Invalid managed code member name or record')
        directory = member.get('kind') == 'directory'
        if set(member) != ({'kind', 'identity'} if directory else {'kind', 'identity', 'sha256', 'code_directory_hashes'}):
            raise ValueError('Invalid managed code member fields')
        identity = member['identity']
        if (member['kind'] not in ('directory', 'file') or type(identity) is not list or
                len(identity) != (5 if directory else 8) or any(type(number) is not int or number < 0 for number in identity)):
            raise ValueError('Invalid managed original-file identity')
        if not directory:
            hashes = member['code_directory_hashes']
            if (not hexadecimal(member['sha256'], 64) or type(hashes) is not list or
                    len(hashes) > 160 or any(not hexadecimal(value, 40) for value in hashes) or hashes != sorted(set(hashes))):
                raise ValueError('Invalid managed code digest inventory')


class RootCapture:
    """Retain the original directory chain without following any link."""
    def __init__(self, root, ordinary):
        self.root, self.ordinary = Path(root), ordinary
        self.descriptors, self.parts = [], []
        try:
            if not self.root.is_absolute() or self.root != Path(os.path.normpath(self.root)):
                raise ValueError('Managed installation root must be canonical and absolute')
            self.descriptors.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC))
            for part in self.root.parts[1:]:
                descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=self.descriptors[-1])
                self.parts.append(part); self.descriptors.append(descriptor)
            self.original = ordinary(self.root, directory=True, trusted=True)
            if object_identity(self.original) != object_identity(os.fstat(self.descriptor)):
                raise ValueError('Managed installation root changed before capture')
            self.check()
        except BaseException:
            self.close()
            raise

    @property
    def descriptor(self): return self.descriptors[-1]

    def check(self):
        for index, part in enumerate(self.parts):
            actual = os.fstat(self.descriptors[index + 1])
            named = os.stat(part, dir_fd=self.descriptors[index], follow_symlinks=False)
            if not stat.S_ISDIR(named.st_mode) or object_identity(named) != object_identity(actual):
                raise ValueError('Original installation directory chain changed')
        actual = self.ordinary(self.root, directory=True, trusted=True)
        if object_identity(actual) != object_identity(self.original):
            raise ValueError('Original managed installation root was replaced or changed')

    def close(self):
        for descriptor in reversed(self.descriptors): os.close(descriptor)
        self.descriptors = []


def snapshot(capture, code_trees, code_files):
    """Capture every code member; mutable data never supplies image authority."""
    trees, files = set(code_trees) | {'bin'}, set(code_files)
    if trees & files or any(type(name) is not str or not name or '/' in name or name in ('.', '..') for name in trees | files):
        raise ValueError('Invalid fixed managed code scope')
    members, images = {}, set()
    visited = 0

    def walk(parent, parent_relative, code):
        nonlocal visited
        directory_before = os.fstat(parent)
        names = sorted(os.listdir(parent))
        for name in names:
            visited += 1
            if visited > MEMBER_LIMIT:
                raise ValueError('Managed installation exceeds its complete member bound')
            relative = str(parent_relative/name) if parent_relative else name
            path = capture.root/relative
            incoming = os.stat(name, dir_fd=parent, follow_symlinks=False)
            is_directory = stat.S_ISDIR(incoming.st_mode)
            capture.ordinary(path, directory=is_directory, trusted=True)
            active_code = code or not parent_relative and name in trees | files
            if not parent_relative and name in trees and not is_directory:
                raise ValueError('Managed code tree became a non-directory')
            if not parent_relative and name in files and is_directory:
                raise ValueError('Managed code file became a directory')
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if is_directory: flags |= os.O_DIRECTORY
            descriptor = os.open(name, flags, dir_fd=parent)
            try:
                opened = os.fstat(descriptor)
                if IMAGE.file_identity(incoming) != IMAGE.file_identity(opened):
                    raise ValueError('Managed member changed before its original descriptor capture')
                if is_directory:
                    if active_code:
                        members[relative] = {'kind': 'directory', 'identity': list(object_identity(opened))}
                    walk(descriptor, Path(relative), active_code)
                elif active_code:
                    identity = IMAGE.capture_image(descriptor)
                    if identity['mach_o']: images.add(relative)
                    members[relative] = {'kind': 'file', 'identity': member_identity(opened),
                                         'sha256': identity['sha256'],
                                         'code_directory_hashes': identity['code_directory_hashes']}
                else:
                    magic = os.pread(descriptor, min(4, opened.st_size), 0)
                    if opened.st_mode & 0o111 or magic in IMAGE.THIN or magic in IMAGE.FAT:
                        raise ValueError('Executable private member has no managed code inventory: ' + relative)
                after = os.fstat(descriptor)
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if IMAGE.file_identity(opened) != IMAGE.file_identity(after) or IMAGE.file_identity(opened) != IMAGE.file_identity(named):
                    raise ValueError('Managed member changed during original-file capture')
            finally: os.close(descriptor)
        if IMAGE.file_identity(directory_before) != IMAGE.file_identity(os.fstat(parent)):
            raise ValueError('Installation directory changed during complete member capture')

    capture.check()
    walk(capture.descriptor, None, False)
    capture.check()
    if not REQUIRED_IMAGES <= images:
        raise ValueError('Complete managed generation requires every native application image')
    if not trees <= {name for name, member in members.items() if member['kind'] == 'directory'}:
        raise ValueError('Managed installation is missing a required code tree')
    return members


def record(root, target_root, trees, files, ordinary):
    capture = RootCapture(root, ordinary)
    try:
        members = snapshot(capture, trees, files)
        return {'schema': 1, 'generation': secrets.token_hex(16), 'target_root': str(target_root),
                'root_object': [capture.original.st_dev, capture.original.st_ino],
                'code_trees': sorted(set(trees) | {'bin'}), 'code_files': sorted(files), 'members': members}
    finally: capture.close()


def write_prepared(root, target_root, path, trees, files, ordinary):
    value = record(root, target_root, trees, files, ordinary)
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if len(raw) > RECEIPT_LIMIT:
        raise ValueError('Managed installation receipt exceeds its bounded format')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(descriptor, 'wb', closefd=False) as output:
            output.write(raw); output.flush(); os.fchmod(descriptor, 0o600); os.fchown(descriptor, 0, 0); os.fsync(descriptor)
    finally: os.close(descriptor)
    # The prepared receipt is still under the installer's private transaction.
    # Read it through the same retained-file validator used by an upgrade.
    with capture_receipt(root, trees, files, ordinary, path=path, target_root=target_root) as prepared:
        prepared.verify()
    return value


class GenerationCapture:
    def __init__(self, root, trees, files, ordinary, *, path=None, target_root=None):
        self.root, self.trees, self.files, self.ordinary = Path(root), set(trees), set(files), ordinary
        self.path = receipt_path(self.root) if path is None else Path(path)
        self.target_root = self.root if target_root is None else Path(target_root)
        self.root_capture = None; self.descriptor = None
        try:
            self.root_capture = RootCapture(self.root, ordinary)
            named = ordinary(self.path, trusted=True)
            if named.st_mode & 0o077 or not 0 < named.st_size <= RECEIPT_LIMIT:
                raise ValueError('Managed receipt is not protected and bounded')
            self.descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            self.original = os.fstat(self.descriptor)
            if IMAGE.file_identity(named) != IMAGE.file_identity(self.original):
                raise ValueError('Managed receipt changed before original-file capture')
            self.raw = os.pread(self.descriptor, self.original.st_size + 1, 0)
            if len(self.raw) != self.original.st_size:
                raise ValueError('Managed receipt changed length while reading')
            self.value = json.loads(self.raw, object_pairs_hook=unique_object)
            expected_keys = {'schema', 'generation', 'target_root', 'root_object', 'code_trees', 'code_files', 'members'}
            if (type(self.value) is not dict or set(self.value) != expected_keys or
                    type(self.value['schema']) is not int or self.value['schema'] != 1 or
                    type(self.value['generation']) is not str or len(self.value['generation']) != 32 or
                    any(letter not in '0123456789abcdef' for letter in self.value['generation']) or
                    self.value['target_root'] != str(self.target_root) or
                    type(self.value['root_object']) is not list or len(self.value['root_object']) != 2 or
                    any(type(number) is not int or number <= 0 for number in self.value['root_object']) or
                    self.value['root_object'] != [self.root_capture.original.st_dev, self.root_capture.original.st_ino] or
                    self.value['code_trees'] != sorted(self.trees | {'bin'}) or self.value['code_files'] != sorted(self.files) or
                    type(self.value['members']) is not dict or len(self.value['members']) > MEMBER_LIMIT):
                raise ValueError('Managed receipt does not bind the complete original installation')
            validate_members(self.value['members'])
            self.verify()
        except BaseException:
            self.close()
            raise

    def check_receipt(self):
        actual = os.fstat(self.descriptor)
        named = self.ordinary(self.path, trusted=True)
        if (IMAGE.file_identity(actual) != IMAGE.file_identity(self.original) or
                IMAGE.file_identity(named) != IMAGE.file_identity(self.original) or
                os.pread(self.descriptor, self.original.st_size + 1, 0) != self.raw):
            raise ValueError('Original managed receipt changed during installation')

    def verify(self):
        self.check_receipt()
        if snapshot(self.root_capture, self.trees, self.files) != self.value['members']:
            raise ValueError('Managed code members changed, disappeared or were replaced')
        self.check_receipt()
        # Do not expose a set derived only from serialized metadata. The set
        # becomes usable only after the complete current original-file proof.
        self.hashes = frozenset(value for member in self.value['members'].values()
                                for value in member.get('code_directory_hashes', ()))
        if not self.hashes:
            raise ValueError('Managed installation has no complete native image set')

    def require_foreign_image(self, identity):
        self.verify()
        value = identity.get('code_directory_hash') if type(identity) is dict else None
        if not hexadecimal(value, 40):
            raise ValueError('Unknown native main-image identity cannot exclude this installation')
        if value in self.hashes:
            raise RuntimeError('Close Router VPN and its previous owned native processes before upgrading.')

    def close(self):
        if self.descriptor is not None: os.close(self.descriptor); self.descriptor = None
        if self.root_capture is not None: self.root_capture.close(); self.root_capture = None


@contextmanager
def capture_receipt(root, trees, files, ordinary, *, path=None, target_root=None):
    capture = GenerationCapture(root, trees, files, ordinary, path=path, target_root=target_root)
    try: yield capture
    finally: capture.close()


@contextmanager
def previous_generation(root, trees, files, ordinary):
    path = receipt_path(root)
    try: path.lstat()
    except FileNotFoundError:
        # No receipt means legacy/first-install rules, never an empty native
        # image set or proof that a deleted previous executable did not exist.
        yield None
        return
    with capture_receipt(root, trees, files, ordinary) as capture:
        yield capture
