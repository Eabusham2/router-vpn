#!/usr/bin/env python3
"""Execute the native Linux installer in private temporary installation roots.

The production installer owns every file copy, permission change, lock,
promotion, and rollback. Only systemd and firewall process boundaries are
doubled. --package additionally runs the three actual bundled runtime
verifiers during both first installation and upgrade of a built package.
No test writes /opt, invokes host systemctl, or changes a host firewall.
"""
from __future__ import annotations

import argparse
import configparser
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


REPOSITORY = Path(__file__).resolve().parents[1]
INSTALLER_PATH = REPOSITORY / 'client/install-linux-native.py'
CONTROLLER = '''#!/usr/bin/python3
import pathlib, sys
engine = {'--verify-native-runtime': 'native', '--verify-amnezia-runtime': 'amnezia'}[sys.argv[1]]
root = pathlib.Path(sys.argv[2])
assert (root / 'runtime' / engine / 'payload').read_text() == 'verified ' + engine
assert root.name == 'new', 'runtime verification must precede promotion'
'''
XRAY_VERIFIER = '''import pathlib, sys
assert (pathlib.Path(sys.argv[1]) / 'payload').read_text() == 'verified xray'
'''
NATIVE_BINARIES = ('router-vpn-client', 'router-vpn-app', 'router-vpn-dns',
                   'router-vpn-start-layer-relay', 'router-vpn-update')


def load_installer(source=None):
    module = types.ModuleType('routervpn_native_installer_test_target')
    module.__file__ = str(INSTALLER_PATH)
    exec(compile(source if source is not None else INSTALLER_PATH.read_text(),
                 str(INSTALLER_PATH), 'exec'), module.__dict__)
    return module


INSTALLER = load_installer()


def write(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    path.chmod(mode)


def package_fixture(path, version='one'):
    path.mkdir()
    for directory in INSTALLER.CODE_TREES:
        (path / directory).mkdir()
    for filename in INSTALLER.CODE_FILES:
        write(path / filename, 'package ' + version + ': ' + filename)
    for filename in NATIVE_BINARIES:
        write(path / filename, CONTROLLER if filename == 'router-vpn-client' else '#!/bin/sh\nexit 0\n', 0o755)
    for engine in ('native', 'amnezia', 'xray'):
        write(path / 'runtime' / engine / 'payload', 'verified ' + engine)
    write(path / 'client/verify-bundled-xray.py', XRAY_VERIFIER)
    write(path / 'modes/kill-switch.py', '# only the bounded system runner may invoke this fixture\n')
    write(path / 'client/linux/com.eabusham.routervpn.controller.policy',
          (REPOSITORY / 'client/linux/com.eabusham.routervpn.controller.policy').read_bytes())
    write(path / 'client.json', json.dumps({'listen': '127.0.0.1:8788',
          'modes_file': './modes.json', 'scripts_dir': './modes',
          'profiles_file': './routers.json', 'state_file': './state.json'}), 0o600)
    write(path / 'routers.json', '{"profiles":[],"selected_id":""}', 0o600)
    write(path / 'generated/package-sentinel', 'new package private material', 0o600)
    return path


def snapshot(root, *, metadata=False):
    """Capture ordinary bytes and links without following a rejected input."""
    if not root.exists():
        return None
    result = {}
    for base, directories, filenames in os.walk(root, followlinks=False):
        for name in sorted(directories + filenames):
            path = Path(base) / name
            info = path.lstat()
            kind = stat.S_IFMT(info.st_mode)
            value = (os.readlink(path) if stat.S_ISLNK(info.st_mode) else
                     path.read_bytes() if stat.S_ISREG(info.st_mode) else None)
            record = (kind, value)
            if metadata:
                record += (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, info.st_ino)
            result[path.relative_to(root).as_posix()] = record
    return result


def file_bytes(root):
    return {key: value for key, value in (snapshot(root) or {}).items()
            if value[0] != stat.S_IFDIR}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def runtime_digests(root):
    result = {}
    for path in root.rglob('*'):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AssertionError('A packaged runtime is linked or nonregular: ' + str(path.relative_to(root)))
        result[path.relative_to(root).as_posix()] = (info.st_size, digest(path))
    return result


class SystemBoundary:
    """Strict process double; never dispatches a host command."""
    def __init__(self, installer, root, *, early_enabled=False, legacy_enabled=False,
                 legacy_active=False, fail=None, query_codes=None):
        self.installer, self.root = installer, root
        self.enabled = {installer.EARLY_NAME: early_enabled,
                        'router-vpn-client.service': legacy_enabled}
        self.legacy_active = legacy_active
        self.fail = fail
        self.failed = False
        self.calls = []
        self.query_codes = query_codes or {}

    def __call__(self, arguments, *, check=True):
        args = tuple(map(str, arguments))
        self.calls.append((args, check))
        if args[0] == '/usr/bin/systemctl':
            if len(args) not in (2, 3):
                raise AssertionError('Unexpected systemctl command: ' + repr(args))
            operation = args[1]
            unit = args[2] if len(args) == 3 else ''
            if operation not in ('is-active', 'is-enabled', 'enable', 'disable',
                                  'daemon-reload', 'start'):
                raise AssertionError('Installer may not stop/restart network services: ' + repr(args))
            if unit and unit not in self.enabled:
                raise AssertionError('Installer touched an unrelated service: ' + repr(args))
            key = (operation, unit)
            if key == self.fail and not self.failed:
                self.failed = True
                raise subprocess.CalledProcessError(19, args, stderr='injected system boundary failure')
            code = self.query_codes.get(key, 0)
            if operation == 'is-active':
                code = self.query_codes.get(key, 0 if self.legacy_active else 3)
            elif operation == 'is-enabled':
                code = self.query_codes.get(key, 0 if self.enabled[unit] else 1)
            elif operation == 'enable' and code == 0:
                self.enabled[unit] = True
            elif operation == 'disable' and code == 0:
                self.enabled[unit] = False
            if check and code:
                raise subprocess.CalledProcessError(code, args)
            return subprocess.CompletedProcess(args, code, stdout='', stderr='')
        expected = ('/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
                    'HOMEVPN_ROOT=' + str(self.root), '/usr/bin/python3', '-Es',
                    str(self.root / 'modes/kill-switch.py'), 'reassert')
        if args != expected:
            raise AssertionError('Unbounded installer process invocation: ' + repr(args))
        if self.fail == ('reassert', '') and not self.failed:
            self.failed = True
            raise subprocess.CalledProcessError(21, args, stderr='injected protection failure')
        if not (self.root / 'modes/kill-switch.py').is_file():
            raise AssertionError('Reassert did not use the promoted installation')
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')


class InstallerTransactions(unittest.TestCase):
    installer = INSTALLER

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix='routervpn-native-install-test-')
        self.addCleanup(self.workspace.cleanup)
        self.base = Path(self.workspace.name)
        self.root = self.base / 'router-vpn-client'
        self.system = self.base / 'system'
        self.system.mkdir(mode=0o700)
        self.proc = self.base / 'proc'
        self.proc.mkdir()
        self.source = package_fixture(self.base / 'package')
        self.boundary = SystemBoundary(self.installer, self.root)
        self.integration = self.installer.SystemIntegration(filesystem=self.system, run=self.boundary)

    def install(self, *, verifier=None, source=None, integration=None):
        options = {'integration': integration if integration is not None else self.integration,
                   'proc': self.proc}
        if verifier is not None:
            options['verifier'] = verifier
        self.installer.install(source if source is not None else self.source, self.root, **options)

    def new_integration(self, **arguments):
        self.boundary = SystemBoundary(self.installer, self.root, **arguments)
        self.integration = self.installer.SystemIntegration(filesystem=self.system, run=self.boundary)
        return self.integration

    def assert_no_staging(self):
        self.assertEqual(list(self.base.glob('.' + self.root.name + '.install-*')), [])

    def seed_private(self):
        write(self.root / 'routers.json', '{"profiles":[{"id":"private-node"}],"selected_id":"private-node"}', 0o600)
        write(self.root / 'generated/private-node/key', 'private key is never package data', 0o600)
        write(self.root / 'state.json', '{"mode":"smart","dns":"home-adguard","kill_switch":"always"}', 0o600)
        write(self.root / 'run/owner/session', 'captured owner', 0o600)
        write(self.root / 'saved-profiles/profile.json', '{"node":"private-node","mtu":1360}', 0o600)
        config = json.loads((self.root / 'client.json').read_text())
        config['auto_test_seconds'] = 9
        write(self.root / 'client.json', json.dumps(config), 0o600)

    def test_first_install_verifies_private_stage_before_promotion(self):
        source_before = snapshot(self.source, metadata=True)
        commands = []
        real_command = self.installer.command

        def observed(arguments, **kwargs):
            self.assertFalse(self.root.exists(), 'code promoted before bundled verification')
            arguments = tuple(map(str, arguments))
            commands.append(arguments)
            staged = Path(arguments[-1]).parent if arguments[0] == '/usr/bin/python3' else Path(arguments[-1])
            if arguments[0] == '/usr/bin/python3':
                staged = Path(arguments[2]).parent.parent
            self.assertEqual(staged.name, 'new')
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(staged.parent.stat().st_mode), 0o700)
            return real_command(arguments, **kwargs)

        with mock.patch.object(self.installer, 'command', side_effect=observed):
            self.install()
        self.assertEqual(len(commands), 3)
        self.assertEqual([command[1] for command in commands[:2]],
                         ['--verify-native-runtime', '--verify-amnezia-runtime'])
        self.assertEqual(commands[2][:2], ('/usr/bin/python3', '-Es'))
        self.assertEqual(snapshot(self.source, metadata=True), source_before)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o755)
        self.assertEqual((self.root / 'runtime/native/payload').read_text(), 'verified native')
        self.assert_no_staging()

    def test_upgrade_preserves_private_state_with_fresh_root_owned_inodes(self):
        self.install()
        self.seed_private()
        old_private = {name: snapshot(self.root / name) if (self.root / name).is_dir()
                       else (self.root / name).read_bytes()
                       for name in ('client.json', 'routers.json', 'generated', 'state.json', 'run', 'saved-profiles')}
        previous_binary = self.root / 'router-vpn-dns'
        old_inode = previous_binary.stat().st_ino
        old_handle = previous_binary.open('r+b')
        self.addCleanup(old_handle.close)
        source_binary = self.source / 'router-vpn-dns'
        os.chown(source_binary, 65534, 65534)
        write(source_binary, '#!/bin/sh\n# upgraded executable\nexit 0\n', 0o6777)
        write(self.source / 'routers.json', '{"profiles":[{"id":"wrong-new-package-node"}]}')
        write(self.source / 'generated/foreign-node', 'must not be mixed into installed private state')
        self.new_integration(early_enabled=True)
        self.install()
        self.assertNotEqual(previous_binary.stat().st_ino, old_inode)
        self.assertNotEqual(previous_binary.stat().st_ino, source_binary.stat().st_ino)
        self.assertEqual(previous_binary.read_bytes(), source_binary.read_bytes())
        old_handle.seek(0)
        old_handle.write(b'write through a retired executable handle')
        old_handle.flush()
        self.assertEqual(previous_binary.read_bytes(), source_binary.read_bytes())
        for name, before in old_private.items():
            after = snapshot(self.root / name) if (self.root / name).is_dir() else (self.root / name).read_bytes()
            self.assertEqual(after, before, 'upgrade replaced private ' + name)
        self.assertFalse((self.root / 'generated/foreign-node').exists())
        for path in [self.root, *self.root.rglob('*')]:
            info = path.lstat()
            self.assertEqual((info.st_uid, info.st_gid), (0, 0), str(path))
            self.assertFalse(info.st_mode & 0o6022, str(path))
            if path.is_file():
                self.assertEqual(info.st_nlink, 1, str(path))
        self.assertEqual(stat.S_IMODE((self.root / 'generated').stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / 'generated/private-node/key').stat().st_mode), 0o600)
        self.assert_no_staging()

    def test_invalid_runtime_keeps_previous_application_and_system_files(self):
        self.install()
        self.seed_private()
        application, system = snapshot(self.root, metadata=True), snapshot(self.system, metadata=True)
        write(self.source / 'runtime/native/payload', 'corrupted native runtime')
        self.new_integration(early_enabled=True)
        with self.assertRaises(subprocess.CalledProcessError):
            self.install()
        self.assertEqual(snapshot(self.root, metadata=True), application)
        self.assertEqual(snapshot(self.system, metadata=True), system)
        self.assertEqual(self.boundary.calls, [])
        self.assert_no_staging()

    def test_fixed_adjacent_lock_blocks_controller_and_parallel_installer(self):
        lock = self.root.with_name(self.root.name + '.install.lock')
        descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        with self.assertRaisesRegex(RuntimeError, 'Close Router VPN'):
            self.install()
        self.assertFalse(self.root.exists())
        self.assertEqual(self.boundary.calls, [])
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        with self.installer.installation_lock(self.root):
            with self.assertRaises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, 'Close Router VPN'):
                with self.installer.installation_lock(self.root):
                    self.fail('concurrent installer acquired the fixed lock')
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
        self.assertEqual(self.installer.ROOT, Path('/opt/router-vpn-client'))

    def test_unsafe_locks_and_parent_are_rejected(self):
        lock = self.root.with_name(self.root.name + '.install.lock')
        foreign = self.base / 'foreign'
        write(foreign, 'unrelated')
        for kind in ('symlink', 'hardlink', 'public', 'foreign-owner'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    lock.symlink_to(foreign)
                elif kind == 'hardlink':
                    os.link(foreign, lock)
                else:
                    write(lock, '', 0o644 if kind == 'public' else 0o600)
                    if kind == 'foreign-owner':
                        os.chown(lock, 65534, 65534)
                with self.assertRaises((OSError, ValueError)):
                    self.install()
                lock.unlink()
                self.assertEqual(foreign.read_text(), 'unrelated')
                self.assertFalse(self.root.exists())
        self.base.chmod(0o777)
        with self.assertRaisesRegex(ValueError, 'root-owned'):
            self.install()
        self.base.chmod(0o700)

    def test_source_links_and_special_files_do_not_replace_old_installation(self):
        self.install()
        baseline = snapshot(self.root, metadata=True)
        foreign = self.base / 'foreign'
        write(foreign, 'unrelated bytes')
        for relative, kind in (('router-vpn-app', 'symlink'), ('router-vpn-dns', 'hardlink'),
                               ('runtime/native/payload', 'symlink'),
                               ('client/linked.py', 'fifo'), ('generated/key', 'symlink')):
            with self.subTest(path=relative, kind=kind):
                source = package_fixture(self.base / ('input-' + str(len(list(self.base.iterdir())))))
                target = source / relative
                target.unlink(missing_ok=True)
                if kind == 'symlink':
                    target.symlink_to(foreign)
                elif kind == 'hardlink':
                    os.link(foreign, target)
                else:
                    os.mkfifo(target)
                # A package's unused private generated directory does not
                # replace existing state. Exercise that input on first install.
                if relative.startswith('generated/'):
                    shutil.rmtree(self.root)
                with self.assertRaises((ValueError, OSError)):
                    self.install(source=source)
                if self.root.exists():
                    self.assertEqual(snapshot(self.root, metadata=True), baseline)
                self.assertEqual(foreign.read_text(), 'unrelated bytes')
                if kind == 'hardlink':
                    target.unlink()
                self.assert_no_staging()

    def test_existing_private_links_are_rejected_without_following_them(self):
        self.install()
        foreign = self.base / 'foreign'
        write(foreign, 'private data outside the owned installation')
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                target = self.root / 'generated/private-key'
                if kind == 'symlink':
                    target.symlink_to(foreign)
                else:
                    os.link(foreign, target)
                baseline = snapshot(self.root, metadata=True)
                with self.assertRaises((ValueError, OSError)):
                    self.install()
                self.assertEqual(snapshot(self.root, metadata=True), baseline)
                self.assertEqual(foreign.read_text(), 'private data outside the owned installation')
                target.unlink()
                self.assert_no_staging()

    def test_copy_race_rejects_mutated_open_input(self):
        self.install()
        baseline = snapshot(self.root, metadata=True)
        original = self.installer.shutil.copyfileobj
        target = self.source / 'runtime/native/payload'
        fired = []

        def racing(incoming, output, *args):
            original(incoming, output, *args)
            if os.fstat(incoming.fileno()).st_ino == target.stat().st_ino and not fired:
                fired.append(True)
                target.write_text('same source changed after reading')

        with mock.patch.object(self.installer.shutil, 'copyfileobj', side_effect=racing):
            with self.assertRaisesRegex(ValueError, 'changed during capture'):
                self.install()
        self.assertTrue(fired)
        self.assertEqual(snapshot(self.root, metadata=True), baseline)
        self.assert_no_staging()

    def test_copy_race_rejects_replaced_directory_or_source_root(self):
        self.install()
        baseline = snapshot(self.root, metadata=True)
        original = self.installer.copy_checked
        fired = []

        def racing(source, destination, **kwargs):
            original(source, destination, **kwargs)
            if source == self.source / 'router-vpn-update' and not fired:
                fired.append(True)
                write(self.source / 'late-added-input', 'package changed while staged')

        with mock.patch.object(self.installer, 'copy_checked', side_effect=racing):
            with self.assertRaisesRegex(ValueError, 'source package changed'):
                self.install()
        self.assertTrue(fired)
        self.assertEqual(snapshot(self.root, metadata=True), baseline)
        self.assert_no_staging()

    def test_retained_directory_descriptor_cannot_be_redirected_to_foreign_files(self):
        source = self.source / 'runtime/native'
        foreign = self.base / 'foreign-directory'
        write(foreign / 'payload', 'outside the captured installation authority')
        retired = self.base / 'retired-native'
        staged = self.base / 'isolated-copy'
        original_open = self.installer.os.open
        original_copy = self.installer.shutil.copyfileobj
        fired, captured = [], []

        def redirected(name, flags, *args, **kwargs):
            if name == 'payload' and kwargs.get('dir_fd') is not None and not fired:
                fired.append(True)
                source.rename(retired)
                source.symlink_to(foreign, target_is_directory=True)
            return original_open(name, flags, *args, **kwargs)

        def observe_copy(incoming, output, *args):
            captured.append(incoming.read())
            incoming.seek(0)
            return original_copy(incoming, output, *args)

        with mock.patch.object(self.installer.os, 'open', side_effect=redirected), \
                mock.patch.object(self.installer.shutil, 'copyfileobj', side_effect=observe_copy):
            with self.assertRaisesRegex(ValueError, 'directory changed during capture'):
                self.installer.copy_checked(source, staged)
        self.assertTrue(fired)
        self.assertEqual(captured, [b'verified native'])
        self.assertEqual((foreign / 'payload').read_text(), 'outside the captured installation authority')

    def test_interrupted_backup_blocks_install_without_touching_recoverable_state(self):
        pending = self.base / ('.' + self.root.name + '.install-interrupted')
        write(pending / 'previous/generated/private-key', 'recoverable private key', 0o600)
        pending.chmod(0o700)
        before = snapshot(pending, metadata=True)
        with self.assertRaisesRegex(RuntimeError, 'interrupted native installation needs recovery') as caught:
            self.install()
        self.assertIn(str(pending), str(caught.exception))
        self.assertEqual(snapshot(pending, metadata=True), before)
        self.assertFalse(self.root.exists())
        self.assertEqual(self.boundary.calls, [])

    def test_legacy_process_identity_before_and_after_capture(self):
        process = self.proc / '123'
        process.mkdir()
        executable = process / 'exe'
        for target in (str(self.root / 'router-vpn-client'), str(self.root / 'runtime/native/routervpncore') + ' (deleted)'):
            with self.subTest(target=target):
                executable.symlink_to(target)
                try:
                    with self.assertRaisesRegex(RuntimeError, 'Close Router VPN'):
                        self.install()
                finally:
                    executable.unlink()
        executable.symlink_to(str(self.root) + '-unrelated/router-vpn-dns')
        self.installer.reject_running_previous(self.root, self.proc)
        executable.unlink()
        executable.symlink_to('/tmp/legacy-relocated/router-vpn-client')
        write(process / 'environ', b'OTHER=safe\0HOMEVPN_ROOT=' + os.fsencode(self.root) + b'\0')
        with self.assertRaisesRegex(RuntimeError, 'Close Router VPN'):
            self.install()
        executable.unlink()
        (process / 'environ').unlink()

        def starts_after_capture(stage):
            self.installer.verify_runtimes(stage)
            executable.symlink_to(str(self.root / 'router-vpn-client'))

        with self.assertRaisesRegex(RuntimeError, 'Close Router VPN'):
            self.install(verifier=starts_after_capture)
        self.assertFalse(self.root.exists())
        self.assertEqual(self.boundary.calls, [])
        self.assert_no_staging()

    def test_unreadable_process_identity_is_not_assumed_idle(self):
        process = self.proc / '123'
        process.mkdir()
        original = os.readlink

        def unavailable(path, *args, **kwargs):
            if Path(path) == process / 'exe':
                raise PermissionError('proc identity inaccessible')
            return original(path, *args, **kwargs)

        with mock.patch.object(self.installer.os, 'readlink', side_effect=unavailable):
            with self.assertRaisesRegex(RuntimeError, 'Cannot prove'):
                self.install()
        self.assertFalse(self.root.exists())

    def test_fixed_controller_configuration_rejects_external_authority(self):
        for key, value in (('listen', '0.0.0.0:8788'), ('listen', '127.0.0.1:9999'),
                           ('modes_file', '../foreign.json'), ('scripts_dir', '/tmp/foreign'),
                           ('profiles_file', '../routers.json'), ('state_file', '/etc/state.json')):
            with self.subTest(key=key, value=value):
                config = {key: value}
                write(self.source / 'client.json', json.dumps(config))
                with self.assertRaises(ValueError):
                    self.install()
                self.assertFalse(self.root.exists())
                self.assertEqual(self.boundary.calls, [])
                self.assert_no_staging()
        for value in ([], 'not-json', 'null'):
            write(self.source / 'client.json', json.dumps(value) if not isinstance(value, str) else value)
            with self.assertRaises(ValueError):
                self.install()

    def test_promotion_failure_restores_exact_old_inodes(self):
        self.install()
        self.seed_private()
        baseline = snapshot(self.root, metadata=True)
        original = os.rename
        fired = []

        def fail_promotion(source, destination, *args, **kwargs):
            if Path(source).name == 'new' and Path(destination) == self.root and not fired:
                fired.append(True)
                raise OSError('injected promotion failure')
            return original(source, destination, *args, **kwargs)

        self.new_integration(early_enabled=True)
        with mock.patch.object(self.installer.os, 'rename', side_effect=fail_promotion):
            with self.assertRaisesRegex(OSError, 'promotion failure'):
                self.install()
        self.assertTrue(fired)
        self.assertEqual(snapshot(self.root, metadata=True), baseline)
        self.assertEqual(self.boundary.calls, [])
        self.assert_no_staging()

    def test_system_failure_rolls_back_application_files_and_service_enablement(self):
        self.install()
        self.seed_private()
        write(self.system / 'usr/local/bin/router-vpn', '# previous installed launcher\n', 0o751)
        write(self.system / 'etc/systemd/system/unrelated.service', '[Service]\nExecStart=/bin/true\n')
        application, system = snapshot(self.root, metadata=True), file_bytes(self.system)
        before_modes = {name: stat.S_IMODE((self.system / name).stat().st_mode) for name in system}
        for failure in (('daemon-reload', ''), ('enable', self.installer.EARLY_NAME),
                        ('reassert', ''), ('start', self.installer.EARLY_NAME)):
            with self.subTest(failure=failure):
                self.new_integration(legacy_enabled=True, fail=failure)
                with self.assertRaises(subprocess.CalledProcessError):
                    self.install()
                self.assertEqual(snapshot(self.root, metadata=True), application)
                self.assertEqual(file_bytes(self.system), system)
                self.assertEqual({name: stat.S_IMODE((self.system / name).stat().st_mode) for name in system}, before_modes)
                self.assertFalse(self.boundary.enabled[self.installer.EARLY_NAME])
                self.assertTrue(self.boundary.enabled['router-vpn-client.service'])
                self.assert_no_staging()

    def test_first_install_system_failure_removes_new_application_and_owned_files(self):
        self.new_integration(fail=('reassert', ''))
        with self.assertRaises(subprocess.CalledProcessError):
            self.install()
        self.assertFalse(self.root.exists())
        self.assertEqual(file_bytes(self.system), {})
        self.assertFalse(self.boundary.enabled[self.installer.EARLY_NAME])
        self.assert_no_staging()

    def test_system_links_and_unsafe_parent_do_not_overwrite_foreign_files(self):
        foreign = self.base / 'foreign'
        write(foreign, 'unrelated system bytes')
        target = self.system / 'usr/local/bin/router-vpn'
        target.parent.mkdir(parents=True)
        for kind in ('symlink', 'hardlink', 'writable-parent'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    target.symlink_to(foreign)
                elif kind == 'hardlink':
                    os.link(foreign, target)
                else:
                    target.parent.chmod(0o777)
                self.new_integration()
                with self.assertRaises(ValueError):
                    self.install()
                self.assertFalse(self.root.exists())
                self.assertEqual(foreign.read_text(), 'unrelated system bytes')
                target.unlink(missing_ok=True)
                target.parent.chmod(0o755)
                self.assert_no_staging()

    def test_system_promotion_failure_restores_previous_file_bytes(self):
        write(self.system / 'usr/local/bin/router-vpn', 'previous launcher', 0o751)
        original = os.replace
        fired = []

        def fail_icon(source, target, *args, **kwargs):
            if Path(target).name == 'router-vpn.png' and not fired:
                fired.append(True)
                raise OSError('injected system promotion failure')
            return original(source, target, *args, **kwargs)

        with mock.patch.object(self.installer.os, 'replace', side_effect=fail_icon):
            with self.assertRaisesRegex(OSError, 'system promotion failure'):
                self.install()
        self.assertTrue(fired)
        self.assertFalse(self.root.exists())
        self.assertEqual((self.system / 'usr/local/bin/router-vpn').read_text(), 'previous launcher')
        self.assertEqual(stat.S_IMODE((self.system / 'usr/local/bin/router-vpn').stat().st_mode), 0o751)
        self.assertEqual(len(file_bytes(self.system)), 1)
        self.assertEqual(list(self.system.rglob('.routervpn-*')), [])
        self.assert_no_staging()

    def test_system_files_are_promoted_to_fresh_inodes(self):
        target = self.system / 'usr/local/bin/router-vpn'
        write(target, 'previous launcher', 0o751)
        previous_inode = target.stat().st_ino
        with target.open('r+b') as retired:
            self.install()
            self.assertNotEqual(target.stat().st_ino, previous_inode)
            expected = target.read_bytes()
            retired.write(b'modify the retired launcher inode')
            retired.flush()
            self.assertEqual(target.read_bytes(), expected)
        self.assertEqual((target.stat().st_uid, target.stat().st_gid), (0, 0))
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)

    def test_rollback_service_failure_keeps_recovery_material(self):
        self.install()
        self.seed_private()
        baseline = snapshot(self.root, metadata=True)
        self.new_integration(fail=('reassert', ''),
                             query_codes={('disable', self.installer.EARLY_NAME): 5})
        with self.assertRaisesRegex(RuntimeError, 'rollback needs recovery'):
            self.install()
        pending = list(self.base.glob('.' + self.root.name + '.install-*'))
        self.assertEqual(len(pending), 1)
        self.assertEqual(snapshot(pending[0] / 'previous', metadata=True), baseline)
        self.assertTrue(self.boundary.enabled[self.installer.EARLY_NAME])

    def test_rollback_failure_retains_identifiable_previous_application(self):
        self.install()
        self.seed_private()
        baseline = snapshot(self.root, metadata=True)
        self.new_integration(fail=('reassert', ''))
        with mock.patch.object(self.integration, 'rollback', side_effect=OSError('rollback unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'previous bytes retained at') as caught:
                self.install()
        pending = list(self.base.glob('.' + self.root.name + '.install-*'))
        self.assertEqual(len(pending), 1)
        self.assertIn(str(pending[0]), str(caught.exception))
        self.assertEqual(snapshot(pending[0] / 'previous', metadata=True), baseline)
        self.assertTrue(self.root.exists())
        self.assertEqual(stat.S_IMODE(pending[0].stat().st_mode), 0o700)

    def test_always_service_and_network_dependencies_are_installed_without_restart(self):
        self.new_integration(legacy_enabled=True)
        self.install()
        service = self.system / 'etc/systemd/system' / self.installer.EARLY_NAME
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(service.read_text())
        self.assertEqual(parser['Unit']['Before'], 'network-pre.target')
        self.assertEqual(parser['Unit']['DefaultDependencies'], 'no')
        self.assertEqual(parser['Unit']['After'], 'local-fs.target')
        self.assertEqual(parser['Install']['RequiredBy'], 'network-pre.target')
        self.assertEqual(parser['Service']['Type'], 'oneshot')
        self.assertEqual(parser['Service']['RemainAfterExit'], 'yes')
        self.assertEqual(parser['Service']['ExecStart'], '/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOMEVPN_ROOT=/opt/router-vpn-client /usr/bin/python3 -Es /opt/router-vpn-client/modes/kill-switch.py reassert')
        self.assertNotIn('router-vpn-client --', service.read_text())
        for name in ('NetworkManager.service', 'systemd-networkd.service', 'networking.service', 'connman.service', 'wicked.service'):
            parser.read_string((self.system / 'etc/systemd/system' / (name + '.d/50-router-vpn-protection.conf')).read_text())
            self.assertEqual(parser['Unit']['Requires'], self.installer.EARLY_NAME, name)
            self.assertEqual(parser['Unit']['After'], self.installer.EARLY_NAME, name)
        self.assertTrue(self.boundary.enabled[self.installer.EARLY_NAME])
        self.assertFalse(self.boundary.enabled['router-vpn-client.service'])
        actions = [arguments for arguments, _ in self.boundary.calls]
        reassert = next(index for index, command in enumerate(actions) if command[-1] == 'reassert')
        start = actions.index(('/usr/bin/systemctl', 'start', self.installer.EARLY_NAME))
        self.assertLess(reassert, start)
        self.assertFalse(any('restart' in command or 'stop' in command or 'force-off' in command for command in actions))
        self.assertIn('exec /opt/router-vpn-client/router-vpn-app "$@"', (self.system / 'usr/local/bin/router-vpn').read_text())
        recovery = (self.system / 'usr/local/sbin/router-vpn-killswitch-recovery').read_text()
        self.assertIn('/usr/bin/python3 -Es /opt/router-vpn-client/modes/kill-switch.py force-off', recovery)
        self.assertIn('"$(/usr/bin/id -u)" -eq 0', recovery)

    def test_active_or_unknown_service_state_aborts_and_restores_application(self):
        self.install()
        baseline = snapshot(self.root, metadata=True)
        system = file_bytes(self.system)
        scenarios = [dict(legacy_active=True)]
        for query in (('is-active', 'router-vpn-client.service'),
                      ('is-enabled', 'router-vpn-client.service'),
                      ('is-enabled', self.installer.EARLY_NAME)):
            scenarios.append(dict(query_codes={query: 5}))
        for options in scenarios:
            with self.subTest(options=options):
                self.new_integration(**options)
                with self.assertRaises(RuntimeError):
                    self.install()
                self.assertEqual(snapshot(self.root, metadata=True), baseline)
                self.assertEqual(file_bytes(self.system), system)
                self.assert_no_staging()


def real_package(package):
    package = package.resolve(strict=True)
    if not package.is_dir():
        raise ValueError('--package must be an extracted native Linux package directory')
    module = load_installer()
    with tempfile.TemporaryDirectory(prefix='routervpn-native-real-package-') as temporary:
        base = Path(temporary)
        root, system, proc = base / 'router-vpn-client', base / 'system', base / 'proc'
        system.mkdir(mode=0o700)
        proc.mkdir()
        for upgrading in (False, True):
            boundary = SystemBoundary(module, root, early_enabled=upgrading)
            integration = module.SystemIntegration(filesystem=system, run=boundary)
            commands = []
            real_command = module.command

            def verify_command(arguments, **kwargs):
                commands.append(tuple(map(str, arguments)))
                return real_command(arguments, **kwargs)

            with mock.patch.object(module, 'command', side_effect=verify_command):
                module.install(package, root, integration=integration, proc=proc)
            if len(commands) != 3:
                raise AssertionError('Actual native/Amnezia/Xray verification was not executed')
            for filename in NATIVE_BINARIES:
                if digest(package / filename) != digest(root / filename):
                    raise AssertionError('Installed packaged binary changed: ' + filename)
            if runtime_digests(package / 'runtime') != runtime_digests(root / 'runtime'):
                raise AssertionError('Installed packaged runtimes differ from their verified package')
            if upgrading:
                if (root / 'generated/test-private-key').read_text() != 'retained private state':
                    raise AssertionError('Actual package upgrade lost private material')
                if (root / 'state.json').read_text() != '{"keep":"selected-node-and-policy"}':
                    raise AssertionError('Actual package upgrade lost the saved connection state')
            else:
                write(root / 'generated/test-private-key', 'retained private state', 0o600)
                write(root / 'state.json', '{"keep":"selected-node-and-policy"}', 0o600)
            if list(base.glob('.' + root.name + '.install-*')):
                raise AssertionError('Actual package install left staging material')
            print('Actual packaged Linux runtime verification and ' + ('upgrade' if upgrading else 'first install') + ' passed', flush=True)


def negative_controls():
    source = INSTALLER_PATH.read_text()
    mutations = [
        ('ignore the shared controller lock',
         'fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)', 'None',
         'test_fixed_adjacent_lock_blocks_controller_and_parallel_installer'),
        ('copy untrusted source ownership', 'os.chown(destination, 0, 0)', 'os.chown(destination, info.st_uid, info.st_gid)',
         'test_upgrade_preserves_private_state_with_fresh_root_owned_inodes'),
        ('skip bundled runtime verification', '            verifier(stage)', '            pass',
         'test_invalid_runtime_keeps_previous_application_and_system_files'),
        ('discard previous private state', 'if child.name not in CODE_TREES | CODE_FILES:', 'if False:',
         'test_upgrade_preserves_private_state_with_fresh_root_owned_inodes'),
        ('skip system-file rollback', '                    integration.rollback()', '                    pass',
         'test_system_failure_rolls_back_application_files_and_service_enablement'),
        ('weaken the network protection dependency', 'Requires=router-vpn-killswitch-early.service',
         'Wants=router-vpn-killswitch-early.service',
         'test_always_service_and_network_dependencies_are_installed_without_restart'),
        ('stop dependent networking during installation', "self.run(['/usr/bin/systemctl', 'start', EARLY_NAME])",
         "self.run(['/usr/bin/systemctl', 'restart', EARLY_NAME])",
         'test_always_service_and_network_dependencies_are_installed_without_restart'),
        ('ignore failed rollback disable', "self.run(['/usr/bin/systemctl', 'disable', EARLY_NAME])",
         "self.run(['/usr/bin/systemctl', 'disable', EARLY_NAME], check=False)",
         'test_rollback_service_failure_keeps_recovery_material'),
        ('overwrite an interrupted recovery transaction', '        if pending:', '        if False:',
         'test_interrupted_backup_blocks_install_without_touching_recoverable_state'),
    ]
    for label, before, after, test in mutations:
        if before not in source:
            raise AssertionError('Negative control seam changed: ' + label)
        target = load_installer(source.replace(before, after))
        case = InstallerTransactions(test)
        case.installer = target
        result = unittest.TestResult()
        case.run(result)
        if result.wasSuccessful():
            raise AssertionError('Negative control accepted: ' + label)
        print('Rejected negative control: ' + label, flush=True)


def elevated_test(arguments):
    # Reuse the native gates' system-owned sudo selection and owned-process
    # timeout cleanup. The child still uses only temporary filesystem roots
    # and SystemBoundary; elevation does not turn on host integration.
    spec = importlib.util.spec_from_file_location(
        'installer_privilege_tools', REPOSITORY / 'deploy/test_desktop_socket_uid.py')
    privilege = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(privilege)
    sudo = privilege.privilege_tool()
    if sudo is None:
        raise RuntimeError('The isolated installer gate expected a nonroot build user')
    invocation = [sudo, '-n', '--', sys.executable, '-I', str(Path(__file__).resolve()), *arguments]
    output = privilege.run(invocation, cwd=Path.cwd(), timeout=1800, sudo=sudo)
    print(output, end='', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        elevated_test(sys.argv[1:])
        return
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(InstallerTransactions)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    negative_controls()
    if arguments.package:
        real_package(arguments.package)


if __name__ == '__main__':
    main()
