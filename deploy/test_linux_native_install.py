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
import array
import configparser
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import socket
import threading
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
    def __init__(self, installer, root, *, early_enabled=False, legacy_enabled=False, legacy_early_enabled=False,
                 legacy_active=False, fail=None, query_codes=None):
        self.installer, self.root = installer, root
        self.enabled = {installer.EARLY_NAME: early_enabled,
                        installer.LEGACY_EARLY_NAME: legacy_early_enabled,
                        'router-vpn-client.service': legacy_enabled}
        self.legacy_active = legacy_active
        self.fail = fail
        self.failed = False
        self.calls = []
        self.query_codes = query_codes or {}
        self.idle_service_lock = None

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
                if operation == 'enable':
                    self.enabled[unit] = True  # failure may follow partial enablement
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
            if operation == 'start':
                # Exercise the actual flock arrangement at the point where
                # the new persistent service must acquire its lifetime SH.
                descriptor = os.open(self.root.with_name(self.root.name + '.install.lock'), os.O_RDWR)
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
                finally:
                    os.close(descriptor)
                for suffix in ('.install.transaction.lock', '.controller.lock'):
                    lock = self.root.with_name(self.root.name + suffix)
                    if not lock.is_file():
                        raise AssertionError('Service readiness lost installation/controller exclusion: ' + suffix)
                    descriptor = os.open(lock, os.O_RDWR)
                    try:
                        try:
                            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError:
                            pass
                        else:
                            raise AssertionError('Service readiness lost installation/controller exclusion: ' + suffix)
                    finally:
                        os.close(descriptor)
            if check and code:
                raise subprocess.CalledProcessError(code, args)
            return subprocess.CompletedProcess(args, code, stdout='', stderr='')
        expected = ('/usr/bin/env', '-i', 'PATH=' + self.installer.SYSTEM_PATH,
                    str(self.root / 'router-vpn-client'), self.installer.UPGRADE_ARGUMENT)
        if args != expected:
            raise AssertionError('Unbounded installer process invocation: ' + repr(args))
        if self.fail == ('retire-idle', '') and not self.failed:
            self.failed = True
            raise subprocess.CalledProcessError(21, args, stderr='original protection is retained')
        if not (self.root / 'router-vpn-client').is_file():
            raise AssertionError('Upgrade helper did not use the original installation')
        if self.idle_service_lock is not None:
            os.close(self.idle_service_lock)
            self.idle_service_lock = None
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')


class ActiveSystemBoundary(SystemBoundary):
    """Only systemd's boundary is modeled; installer/journal/flocks are actual."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.owner = None
        self.ready_failures = 0
        self.wrong_ready = False
        self.active_calls = []

    def __call__(self, arguments, *, check=True, deadline_ns=None):
        if deadline_ns is None:
            return super().__call__(arguments, check=check)
        args = tuple(map(str, arguments))
        self.active_calls.append((args, deadline_ns))
        if args[0] != '/usr/bin/systemctl' or deadline_ns not in (self.owner.deadline_ns, self.owner.cleanup_deadline_ns):
            raise AssertionError('Active integration renewed deadline or invoked another process')
        if args[1:3] == ('--no-block', 'start'):
            self.owner.started = True
        elif args[1] == 'start':
            if not self.owner.upgrade['ready']:
                raise AssertionError('Installer waited for READY before original native commit')
            if self.ready_failures:
                self.ready_failures -= 1
                raise TimeoutError('injected lost notify reply')
        elif args[1] == 'show':
            body = 'MainPID=' + ('98765' if self.wrong_ready else '12345') + '\nActiveState=active\nSubState=running\n'
            return subprocess.CompletedProcess(args, 0, stdout=body, stderr='')
        elif args[1] == 'disable':
            if not self.owner.upgrade['old_joined']:
                raise AssertionError('Installer disabled original service before actual join')
            self.enabled[args[2]] = False
        elif args[1] == 'enable':
            if not self.owner.upgrade['source_removed']:
                raise AssertionError('Installer selected candidate before native commit')
            self.enabled[args[2]] = True
        elif args[1] != 'daemon-reload':
            raise AssertionError('Unexpected active system boundary: ' + repr(args))
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')


class ActiveNativeBoundary:
    """Native creator model; never presented as a native acceptance witness.

    It holds the real original source SH leases. All code/private-state moves,
    durable journal writes, system unit rendering and deadlines are production.
    """
    def __init__(self, case, root, selection, original_lock):
        self.case, self.module, self.root = case, case.installer, root
        m = self.module
        self.old_image = m.activated_service_image(root)
        self.old_selection = json.loads((root / m.GENERATION_ACTIVATION).read_bytes())
        self.activation = (root / m.GENERATION_ACTIVATION).read_bytes()
        self.new_generation = selection
        self.new_image = root.with_name(root.name + '.service-generations') / selection['generation'] / 'router-vpn-client'
        self.deadline_ns = m.time.time_ns() + m.IMAGE_WORK_NS
        self.cleanup_deadline_ns = 0
        self.pending = None
        self.envelope = {'schema': 1, 'id': 'a' * 32, 'deadline_ns': self.deadline_ns,
                         'old_generation': self.old_selection, 'new_generation': selection,
                         'activation_sha256': hashlib.sha256(self.activation).hexdigest(),
                         'root': m.image_object(root.stat()), 'run': m.image_object((root / 'run').stat()),
                         'mutation_lock': m.image_object((root / 'run/kill-switch.lock').stat())}
        self.upgrade = {'envelope': self.envelope, 'phase': 'reserved', 'frozen': False, 'source_removed': False,
                        'ready': False, 'old_joined': False, 'rollback_allowed': False, 'activation_allowed': False}
        self.calls, self.locks = [], [original_lock]
        self.started, self.joined, self.closed = False, False, False
        self.old_guard, self.new_guard = True, False
        self.pins = [types.SimpleNamespace(current=lambda: True, observation={'process_id': 12345}, excludes=lambda process: False) for _ in range(3)]
        self.activation_published = False
        case.boundary.owner = self
        case.addCleanup(self.dispose)

    def dispose(self):
        while self.locks:
            os.close(self.locks.pop())

    def acquire(self):
        descriptor = os.open(self.root.with_name(self.root.name + '.install.lock'), os.O_RDWR)
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        self.locks.append(descriptor)

    def cleanup_clock(self):
        if not self.cleanup_deadline_ns:
            self.cleanup_deadline_ns = self.module.time.time_ns() + self.module.IMAGE_CLEANUP_NS
        return self.cleanup_deadline_ns

    def call(self, action, *, cleanup=False):
        if cleanup:
            self.cleanup_clock()
        self.calls.append((action, self.cleanup_deadline_ns))
        u = self.upgrade
        if action == 'prepare':
            self.case.assertTrue(self.old_guard)
        elif action == 'successor-started':
            self.case.assertTrue(self.started)
            self.acquire()
            self.new_guard, u['phase'] = True, 'successor-prepared'
        elif action == 'freeze':
            self.dispose()
            u['phase'], u['frozen'] = 'frozen', True
        elif action == 'code-promoted':
            self.case.assertTrue(self.old_guard and self.new_guard)
            self.acquire()
            self.acquire()
            u['phase'], u['frozen'] = 'code-verified', False
        elif action == 'commit':
            self.old_guard = False
            self.module.image_atomic_json(self.root / 'run/kill-switch.json', {'owner': 'exact-new-fixture-creator'})
            u.update(phase='successor-published', source_removed=True, activation_allowed=True)
        elif action == 'activation-published':
            self.case.assertEqual(json.loads((self.root / self.module.GENERATION_ACTIVATION).read_bytes()), self.new_generation)
            u.update(phase='successor-ready', ready=True)
        elif action == 'settle':
            self.case.assertTrue(u['ready'])
            os.close(self.locks.pop(0))
            u.update(phase='settled', old_joined=True)
        elif action == 'abort':
            if not u['source_removed']:
                if u['phase'] in ('frozen', 'code-verified'):
                    self.dispose()
                    u.update(phase='aborting', frozen=True, rollback_allowed=True)
                else:
                    self.new_guard = False
                    u.update(phase='aborted')
        elif action == 'code-restored':
            self.case.assertTrue(self.old_guard)
            self.acquire()
            self.new_guard = False
            u.update(phase='aborted', frozen=False, rollback_allowed=False)
        elif action != 'status':
            raise AssertionError('Unexpected native fixture operation ' + action)
        return dict(u)

    def current_frozen(self):
        self.case.assertTrue(self.upgrade['frozen'])
        self.case.assertFalse(self.locks, 'Frozen owner still holds source SH')

    def verify_new_ready(self):
        self.case.assertTrue(self.upgrade['ready'] and self.new_guard)

    def verify_settled(self):
        self.verify_new_ready()
        self.case.assertTrue(self.upgrade['old_joined'])
        self.case.assertFalse(self.old_guard)

    def join(self, deadline_ns):
        self.module.image_remaining(deadline_ns)
        self.case.assertIn(self.upgrade['phase'], ('settled', 'aborted'))
        self.joined = True

    def close(self):
        self.closed = True  # Original service leases remain until test teardown.


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

    def active_fixture(self):
        self.install()
        self.seed_private()
        (self.root / 'run').chmod(0o700)
        write(self.root / 'run/kill-switch.lock', b'', 0o600)
        write(self.root / 'run/kill-switch.json', '{"owner":"original-fixture-creator"}', 0o600)
        self.boundary = ActiveSystemBoundary(self.installer, self.root, early_enabled=True)
        self.integration = self.installer.SystemIntegration(filesystem=self.system, run=self.boundary)
        old = os.open(self.root.with_name(self.root.name + '.install.lock'), os.O_RDWR)
        fcntl.flock(old, fcntl.LOCK_SH | fcntl.LOCK_NB)
        held = [old]
        self.addCleanup(lambda: os.close(held.pop()) if held else None)
        created = []
        def factory(root, selection):
            owner = ActiveNativeBoundary(self, root, selection, held.pop())
            created.append(owner)
            return owner
        source = package_fixture(self.base / 'next-package', version='active-generation-two')
        return source, created, factory

    def active_private(self):
        excluded = self.installer.CODE_FILES | self.installer.CODE_TREES | {self.installer.GENERATION_ACTIVATION}
        return {name: value for name, value in snapshot(self.root, metadata=True).items()
                if name.split('/')[0] not in excluded and name != 'run/kill-switch.json'}

    def test_active_image_promotes_code_preserving_original_private_inodes(self):
        source, created, factory = self.active_fixture()
        private = self.active_private()
        anchors = [self.installer.image_object(path.stat()) for path in (self.root, self.root / 'run', self.root / 'run/kill-switch.lock')]
        old_code = (self.root / 'router-vpn-client').stat().st_ino
        with mock.patch.object(self.installer, 'ActiveImageCoordinator', side_effect=factory):
            self.install(source=source)
        owner = created[0]
        self.assertTrue(owner.joined and owner.closed)
        self.assertFalse(owner.old_guard)
        self.assertTrue(owner.new_guard)
        self.assertEqual(self.active_private(), private)
        self.assertEqual([self.installer.image_object(path.stat()) for path in (self.root, self.root / 'run', self.root / 'run/kill-switch.lock')], anchors)
        self.assertNotEqual((self.root / 'router-vpn-client').stat().st_ino, old_code)
        self.assertEqual(json.loads((self.root / self.installer.GENERATION_ACTIVATION).read_bytes()), owner.new_generation)
        self.assertEqual([item[0] for item in owner.calls], ['prepare', 'successor-started', 'freeze', 'code-promoted', 'commit', 'activation-published', 'settle'])
        self.assertTrue(all(deadline == owner.deadline_ns for _, deadline in self.boundary.active_calls))
        self.assert_no_staging()
        with self.assertRaises(RuntimeError):
            with self.installer.installation_lock(self.root):
                self.fail('Committed new service did not retain actual source SH')

    def test_active_image_partial_code_failure_restores_exact_original_objects(self):
        source, created, factory = self.active_fixture()
        before = snapshot(self.root, metadata=True)
        original = os.rename
        fired = []
        def fail(source_path, target, *args, **kwargs):
            if Path(target) == self.root / 'router-vpn-client' and Path(source_path).parent.name == 'new' and not fired:
                fired.append(True)
                raise OSError('injected partial code promotion')
            return original(source_path, target, *args, **kwargs)
        with mock.patch.object(self.installer, 'ActiveImageCoordinator', side_effect=factory), mock.patch.object(self.installer.os, 'rename', side_effect=fail):
            with self.assertRaisesRegex(OSError, 'partial code promotion'):
                self.install(source=source)
        self.assertTrue(fired)
        owner = created[0]
        self.assertEqual(snapshot(self.root, metadata=True), before)
        self.assertTrue(owner.old_guard and owner.joined)
        self.assertFalse(owner.new_guard)
        self.assertEqual(owner.upgrade['phase'], 'aborted')
        self.assertIn('code-restored', [item[0] for item in owner.calls])
        self.assert_no_staging()

    def test_active_image_work_expiry_restores_with_single_cleanup_clock(self):
        source, created, factory = self.active_fixture()
        before = snapshot(self.root, metadata=True)
        real_clock, original = self.installer.time.time_ns, os.rename
        now, fired = [None], []
        def clock():
            return now[0] if now[0] is not None else real_clock()
        def cancel_after_old_move(source_path, target, *args, **kwargs):
            result = original(source_path, target, *args, **kwargs)
            if Path(target).parent.name == 'previous-code' and not fired:
                fired.append(True)
                now[0] = created[0].deadline_ns + 1
            return result
        with mock.patch.object(self.installer, 'ActiveImageCoordinator', side_effect=factory), mock.patch.object(self.installer.time, 'time_ns', side_effect=clock), mock.patch.object(self.installer.os, 'rename', side_effect=cancel_after_old_move):
            with self.assertRaisesRegex(TimeoutError, 'Original active image-upgrade deadline expired'):
                self.install(source=source)
        owner = created[0]
        self.assertTrue(fired)
        self.assertEqual(snapshot(self.root, metadata=True), before)
        stamps = [stamp for _, stamp in owner.calls if stamp]
        self.assertTrue(stamps)
        self.assertEqual(set(stamps), {owner.deadline_ns + 1 + self.installer.IMAGE_CLEANUP_NS})
        self.assertNotIn('commit', [action for action, _ in owner.calls])
        self.assertTrue(owner.old_guard and owner.joined)
        self.assert_no_staging()

    def test_active_image_lost_ready_settles_original_without_reporting_success(self):
        source, created, factory = self.active_fixture()
        private = self.active_private()
        self.boundary.ready_failures = 1
        with mock.patch.object(self.installer, 'ActiveImageCoordinator', side_effect=factory):
            with self.assertRaisesRegex(TimeoutError, 'injected lost notify reply'):
                self.install(source=source)
        owner = created[0]
        self.assertEqual(owner.upgrade['phase'], 'settled')
        self.assertTrue(owner.joined and owner.new_guard)
        self.assertFalse(owner.old_guard)
        self.assertEqual(self.active_private(), private)
        self.assertEqual(json.loads((self.root / self.installer.GENERATION_ACTIVATION).read_bytes()), owner.new_generation)
        self.assertEqual(len({stamp for _, stamp in owner.calls if stamp}), 1)
        self.assert_no_staging()

    def test_active_image_expired_committed_work_settles_only_original_cleanup(self):
        source, created, factory = self.active_fixture()
        private = self.active_private()
        real_clock, now = self.installer.time.time_ns, [None]
        def create(root, selection):
            owner = factory(root, selection)
            original_call = owner.call
            def call(action, **options):
                response = original_call(action, **options)
                if action == 'commit':
                    now[0] = owner.deadline_ns + 1
                return response
            owner.call = call
            return owner
        with mock.patch.object(self.installer, 'ActiveImageCoordinator', side_effect=create), mock.patch.object(self.installer.time, 'time_ns', side_effect=lambda: now[0] if now[0] is not None else real_clock()):
            with self.assertRaisesRegex(TimeoutError, 'Original active image-upgrade deadline expired'):
                self.install(source=source)
        owner = created[0]
        self.assertEqual(len(created), 1)
        self.assertEqual(owner.upgrade['phase'], 'settled')
        self.assertTrue(owner.joined and owner.new_guard)
        self.assertFalse(owner.old_guard)
        self.assertEqual(self.active_private(), private)
        self.assertEqual(json.loads((self.root / self.installer.GENERATION_ACTIVATION).read_bytes()), owner.new_generation)
        self.assertEqual({stamp for _, stamp in owner.calls if stamp}, {owner.deadline_ns + 1 + self.installer.IMAGE_CLEANUP_NS})
        self.assertEqual([action for action, _ in owner.calls].count('commit'), 1)
        self.assert_no_staging()

    def test_active_image_unknown_ready_keeps_both_generations_and_journal(self):
        source, created, factory = self.active_fixture()
        private = self.active_private()
        self.boundary.ready_failures = 100
        with mock.patch.object(self.installer, 'ActiveImageCoordinator', side_effect=factory):
            with self.assertRaisesRegex(RuntimeError, 'both generations and recovery journal retained'):
                self.install(source=source)
        owner = created[0]
        self.assertTrue(owner.new_guard)
        self.assertFalse(owner.old_guard or owner.joined)
        self.assertEqual(self.active_private(), private)
        self.assertTrue(owner.old_image.is_file() and owner.new_image.is_file())
        pending = list(self.base.glob('.router-vpn-client.install-*'))
        self.assertEqual(len(pending), 1)
        self.assertTrue((pending[0] / 'previous-code/router-vpn-client').is_file())
        record = json.loads((pending[0] / 'active-image.json').read_bytes())
        self.assertEqual(record['phase'], 'retained')
        self.assertEqual(record['envelope'], owner.envelope)
        self.assertNotIn('code-restored', [action for action, _ in owner.calls])
        with self.assertRaises(RuntimeError):
            with self.installer.installation_lock(self.root):
                self.fail('Unsettled successor lost real source SH')

    def test_active_image_wrong_notify_process_cannot_finish_upgrade(self):
        source, created, factory = self.active_fixture()
        self.boundary.wrong_ready = True
        with mock.patch.object(self.installer, 'ActiveImageCoordinator', side_effect=factory):
            with self.assertRaisesRegex(RuntimeError, 'READY came from another unit/process'):
                self.install(source=source)
        owner = created[0]
        self.assertNotIn('settle', [action for action, _ in owner.calls])
        self.assertFalse(owner.upgrade['old_joined'])
        self.assertTrue(owner.new_guard)
        self.assertEqual(len(list(self.base.glob('.router-vpn-client.install-*'))), 1)

    def test_active_image_rollback_refuses_replaced_code_inode(self):
        source, created, factory = self.active_fixture()
        original = os.rename
        fired = []
        def replace_after_move(source_path, target, *args, **kwargs):
            result = original(source_path, target, *args, **kwargs)
            if Path(target) == self.root / 'router-vpn-client' and Path(source_path).parent.name == 'new' and not fired:
                fired.append(True)
                foreign = self.base / 'foreign-code'
                write(foreign, 'foreign code must not be overwritten', 0o755)
                os.replace(foreign, target)
                raise OSError('injected foreign replacement')
            return result
        with mock.patch.object(self.installer, 'ActiveImageCoordinator', side_effect=factory), mock.patch.object(self.installer.os, 'rename', side_effect=replace_after_move):
            with self.assertRaisesRegex(RuntimeError, 'Rollback refuses foreign code inode'):
                self.install(source=source)
        self.assertTrue(fired)
        self.assertEqual((self.root / 'router-vpn-client').read_text(), 'foreign code must not be overwritten')
        owner = created[0]
        self.assertTrue(owner.old_guard and owner.new_guard)
        self.assertNotIn('code-restored', [action for action, _ in owner.calls])
        self.assertEqual(len(list(self.base.glob('.router-vpn-client.install-*'))), 1)

    def test_active_image_pin_requires_actual_original_pidfd_image_and_role(self):
        m = self.installer
        observed = m.image_process_observation(os.getpid())
        arguments = Path('/proc/self/cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
        fd = os.pidfd_open(os.getpid(), 0)
        pin = m.ActiveProcessPin(fd, observed, arguments)
        self.addCleanup(pin.close)
        self.assertTrue(pin.current())
        for changed in ('start', 'image', 'namespace', 'role'):
            with self.subTest(changed=changed):
                record = json.loads(json.dumps(observed))
                args = list(arguments)
                if changed == 'start': record['start_ticks'] += 1
                if changed == 'image': record['image']['inode'] += 1
                if changed == 'namespace': record['network_namespace']['inode'] += 1
                if changed == 'role': args.append('--foreign-role')
                descriptor = os.pidfd_open(os.getpid(), 0)
                try:
                    with self.assertRaises(RuntimeError):
                        m.ActiveProcessPin(descriptor, record, args)
                finally:
                    os.close(descriptor)
        reader, writer = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(writer)
            os.read(reader, 1)
            os._exit(0)
        os.close(reader)
        descriptor = os.pidfd_open(child, 0)
        try:
            with self.assertRaisesRegex(RuntimeError, 'pidfd changed its namespace identity'):
                m.ActiveProcessPin(descriptor, observed, arguments)
        finally:
            os.close(descriptor)
            os.close(writer)
            os.waitpid(child, 0)

    def active_wire_fixture(self):
        """Real native images/pidfds and SCM_RIGHTS; no firewall model evidence."""
        m = self.installer
        go = shutil.which('go')
        if not go:
            raise RuntimeError('Go required for actual coordinator image/role fixture')
        program, binary = self.base / 'held.go', self.base / 'held'
        program.write_text('package main\nimport("os";"time")\nfunc main(){if len(os.Args)!=2{os.Exit(91)};for{time.Sleep(time.Hour)}}\n')
        subprocess.run([go, 'build', '-p=2', '-o', str(binary), str(program)], check=True, timeout=120, env=dict(os.environ, GOMAXPROCS='2'))
        root = self.base / 'wire-root'
        (root / 'run').mkdir(parents=True, mode=0o700)
        write(root / 'run/kill-switch.lock', b'', 0o600)
        write(root / 'run/kill-switch.json', '{}', 0o600)
        images = []
        for name in ('a' * 64, 'b' * 64):
            target = self.base / name / 'router-vpn-client'
            write(target, binary.read_bytes(), 0o755)
            images.append(target)
        children, descriptors, observations = [], [], []
        def retire(child):
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=10)
        for image, role in ((images[0], m.SERVICE_ARGUMENT), (images[1], m.SERVICE_ARGUMENT), (images[0], m.IMAGE_UPGRADE_ARGUMENT)):
            child = subprocess.Popen([str(image), role])
            children.append(child)
            self.addCleanup(retire, child)
            descriptor = os.pidfd_open(child.pid, 0)
            descriptors.append(descriptor)
            self.addCleanup(os.close, descriptor)
            observations.append(m.image_process_observation(child.pid, descriptor=descriptor))
        owner = object.__new__(m.ActiveImageCoordinator)
        owner.root, owner.old_image, owner.new_image = root, images[0], images[1]
        owner.deadline_ns = m.time.time_ns() + m.IMAGE_WORK_NS
        owner.cleanup_deadline_ns, owner.proposed_cleanup_ns = 0, 0
        owner.sequence, owner.pending, owner.envelope, owner.upgrade, owner.awaiting = 0, None, None, None, None
        owner.pins, owner.leases, owner.pid, owner.channel = [], [], None, None
        owner.process = m.ActiveProcessPin(os.dup(descriptors[2]), observations[2], [str(images[0]), m.IMAGE_UPGRADE_ARGUMENT])
        self.addCleanup(owner.close)
        owner.old_selection = {'schema': 1, 'generation': 'a' * 64, 'image_sha256': digest(images[0])}
        owner.new_generation = {'schema': 1, 'generation': 'b' * 64, 'image_sha256': digest(images[1])}
        owner.activation = m.generation_json(owner.old_selection)
        envelope = {'schema': 1, 'id': 'c' * 32, 'deadline_ns': owner.deadline_ns,
            'old_generation': owner.old_selection, 'new_generation': owner.new_generation,
            'activation_sha256': hashlib.sha256(owner.activation).hexdigest(),
            'root': m.image_object(root.stat()), 'run': m.image_object((root / 'run').stat()),
            'mutation_lock': m.image_object((root / 'run/kill-switch.lock').stat()),
            'saved_state': m.image_object((root / 'run/kill-switch.json').stat()), 'saved_state_sha256': 'd' * 64,
            'profile_id': 'policy', 'profile_revision': 'e' * 64, 'home_lan': False, 'endpoints': ['203.0.113.77'],
            'source_sha256': 'f' * 64, 'destination_session': '1' * 32, 'destination_sha256': '2' * 64}
        upgrade = {'envelope': envelope, 'phase': 'frozen', 'old_peer': observations[0], 'new_peer': observations[1], 'coordinator_peer': observations[2],
                   'frozen': True, 'source_removed': False, 'ready': False, 'old_joined': False, 'rollback_allowed': False, 'activation_allowed': False}
        request = {'schema': 1, 'sequence': 1, 'action': 'freeze', 'deadline_ns': owner.deadline_ns, 'envelope': envelope}
        reply = {'schema': 1, 'sequence': 1, 'action': 'freeze', 'complete': True, 'upgrade': upgrade}
        return owner, request, reply, descriptors

    def test_active_image_freeze_replay_retains_exact_native_pins(self):
        m = self.installer
        owner, request, reply, originals = self.active_wire_fixture()
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(sender.close)
        self.addCleanup(receiver.close)
        def accept(body, fds):
            sender.sendmsg([m.generation_json(body)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))])
            raw, ancillary, flags, _ = receiver.recvmsg(m.IMAGE_FRAME_LIMIT, socket.CMSG_SPACE(3 * array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
            self.assertFalse(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
            actual = []
            for _, _, data in ancillary:
                values = array.array('i')
                values.frombytes(data)
                actual.extend(values)
            try:
                return owner._accept(m.image_decode(raw), actual, request)
            finally:
                for descriptor in actual:
                    os.close(descriptor)
        accept(reply, originals)
        retained = list(owner.pins)
        count = len(os.listdir('/proc/self/fd'))
        accept(reply, originals)
        self.assertEqual(owner.pins, retained)
        self.assertEqual(len(os.listdir('/proc/self/fd')), count, 'Identical freeze replay leaked duplicate native descriptors')
        # Every peer remains live but the original coordinator cannot replace
        # the old-service slot with a different, same-image native process.
        replacement = subprocess.Popen([str(owner.old_image), m.SERVICE_ARGUMENT])
        def retire_replacement():
            if replacement.poll() is None:
                replacement.terminate()
            replacement.wait(timeout=10)
        self.addCleanup(retire_replacement)
        replacement_fd = os.pidfd_open(replacement.pid, 0)
        self.addCleanup(os.close, replacement_fd)
        replacement_observation = m.image_process_observation(replacement.pid, descriptor=replacement_fd)
        count += 1  # The test deliberately retains this fourth actual pidfd.
        changed = json.loads(json.dumps(reply))
        changed['upgrade']['old_peer'] = replacement_observation
        with self.assertRaisesRegex(RuntimeError, 'Freeze replay replaced an original retained process'):
            accept(changed, [replacement_fd, originals[1], originals[2]])
        processes = self.base / 'captured-proc'
        processes.mkdir()
        for pin in retained:
            process = processes / str(pin.observation['proc_process_id'])
            process.mkdir()
            (process / 'exe').symlink_to(pin.arguments[0])
        m.reject_running_previous(self.base, processes, original_pins=retained)
        foreign_process = processes / str(replacement_observation['proc_process_id'])
        foreign_process.mkdir()
        (foreign_process / 'exe').symlink_to(owner.old_image)
        with self.assertRaisesRegex(RuntimeError, 'owned native processes'):
            m.reject_running_previous(self.base, processes, original_pins=retained)
        self.assertEqual(owner.pins, retained)
        for pin in retained:
            self.assertTrue(pin.current())
        self.assertEqual(len(os.listdir('/proc/self/fd')), count)
        # Invalid late descriptor never partially replaces an existing capture.
        foreign = os.open(self.base / 'held', os.O_RDONLY)
        try:
            with self.assertRaises(RuntimeError):
                accept(reply, [originals[0], originals[1], foreign])
        finally:
            os.close(foreign)
        self.assertEqual(owner.pins, retained)
        self.assertEqual(len(os.listdir('/proc/self/fd')), count)

    def test_active_image_freeze_late_observer_retry_preserves_original_pins(self):
        m = self.installer
        owner, request, reply, descriptors = self.active_wire_fixture()
        owner.channel, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(server.close)
        errors, seen = [], []
        def respond():
            try:
                server.settimeout(10)
                for _ in range(2):
                    seen.append(server.recv(m.IMAGE_FRAME_LIMIT))
                    server.sendmsg([m.generation_json(reply)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', descriptors))])
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=respond)
        worker.start()
        real_accept, real_clock, now = owner._accept, m.time.time_ns, [None]
        def late(*args):
            result = real_accept(*args)
            now[0] = owner.deadline_ns + 1
            return result
        try:
            with mock.patch.object(owner, '_accept', side_effect=late), mock.patch.object(m.time, 'time_ns', side_effect=lambda: now[0] if now[0] is not None else real_clock()):
                with self.assertRaises(TimeoutError):
                    owner._roundtrip(request, owner.deadline_ns)
                retained = list(owner.pins)
                self.assertEqual(len(retained), 3)
                owner._roundtrip(request, now[0] + m.IMAGE_CLEANUP_NS)
                self.assertEqual(owner.pins, retained)
        finally:
            owner.channel.close()
            server.close()
            worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertFalse(errors)
        self.assertEqual(seen, [m.generation_json(request)] * 2)

    def test_active_image_delayed_control_reply_does_not_queue_duplicate(self):
        m = self.installer
        owner, request, frozen, descriptors = self.active_wire_fixture()
        owner.channel, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(server.close)
        got_request, release_reply = threading.Event(), threading.Event()
        errors, actions = [], []
        envelope = frozen['upgrade']['envelope']
        def respond():
            try:
                server.settimeout(10)
                first = m.image_decode(server.recv(m.IMAGE_FRAME_LIMIT))
                actions.append(first['action'])
                got_request.set()
                if not release_reply.wait(10):
                    raise AssertionError('Original reply was not released')
                update = {'envelope': envelope, 'phase': 'reserved', 'frozen': False, 'source_removed': False, 'ready': False, 'old_joined': False, 'rollback_allowed': False, 'activation_allowed': False}
                server.send(m.generation_json({'schema': 1, 'sequence': first['sequence'], 'action': first['action'], 'complete': True, 'upgrade': update}))
                second = m.image_decode(server.recv(m.IMAGE_FRAME_LIMIT))
                actions.append(second['action'])
                if second['action'] != 'abort' or second['sequence'] != first['sequence'] + 1:
                    server.send(m.generation_json({'schema': 1, 'sequence': second['sequence'], 'action': second['action'], 'complete': True, 'upgrade': update}))
                    raise AssertionError('Read timeout queued a duplicate original request')
                update = {'envelope': envelope, 'phase': 'aborted', 'cleanup_deadline_ns': second['cleanup_deadline_ns'], 'frozen': False, 'source_removed': False, 'ready': False, 'old_joined': False, 'rollback_allowed': False, 'activation_allowed': False}
                server.send(m.generation_json({'schema': 1, 'sequence': second['sequence'], 'action': 'abort', 'complete': True, 'upgrade': update}))
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=respond)
        worker.start()
        # A socket-level timeout has a shorter read allowance. The admitted
        # immutable work deadline itself is never moved or reconstructed.
        original_roundtrip = owner._roundtrip
        try:
            with mock.patch.object(owner, '_roundtrip', side_effect=lambda value, deadline: original_roundtrip(value, m.time.time_ns() + 100_000_000)):
                with self.assertRaises(TimeoutError):
                    owner.call('prepare')
            self.assertTrue(got_request.is_set())
            self.assertIsNotNone(owner.pending)
            self.assertIsNotNone(owner.awaiting)
            cleanup = owner.cleanup_clock()
            release_reply.set()
            result = owner.call('abort', cleanup=True)
            self.assertEqual(result['phase'], 'aborted')
            self.assertEqual(result['cleanup_deadline_ns'], cleanup, 'Retry renewed the first cleanup allowance')
            self.assertIsNone(owner.pending)
            self.assertIsNone(owner.awaiting)
        finally:
            release_reply.set()
            owner.channel.close()
            server.close()
            worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertFalse(errors)
        self.assertEqual(actions, ['prepare', 'abort'])

    def test_active_image_control_refuses_boolean_integer_fields(self):
        owner = object.__new__(self.installer.ActiveImageCoordinator)
        request = {'sequence': 1, 'action': 'prepare'}
        for field in ('schema', 'sequence'):
            with self.subTest(field=field):
                reply = {'schema': 1, 'sequence': 1, 'action': 'prepare', 'complete': True}
                reply[field] = True
                with self.assertRaisesRegex(RuntimeError, 'control sequence or role'):
                    owner._accept(reply, [], request)

    def test_active_image_control_matches_actual_go_dto_bytes(self):
        m = self.installer
        owner, request, _, _ = self.active_wire_fixture()
        request['action'] = 'status'
        def declaration(path, name):
            source = (REPOSITORY / path).read_text()
            marker = 'type ' + name + ' struct {'
            body = source[source.index(marker):]
            return body[:body.index('\n}') + 2]
        declarations = []
        for name in ('linuxStandardImageUpgradeEnvelope', 'linuxStandardImageUpgradeControl', 'linuxStandardImageUpgradeControlReply', 'linuxStandardServiceImageUpgradeResponse'):
            declarations.append(declaration('cmd/client/linux_standard_service_image_upgrade_protocol_linux.go', name))
        declarations.append(declaration('cmd/client/linux_standard_service_generation_linux.go', 'linuxStandardGenerationSelection'))
        declarations.append(declaration('internal/linuxprotection/record.go', 'NativeObject'))
        declarations.append(declaration('internal/linuxprocess/record.go', 'Object'))
        declarations.append(declaration('internal/linuxprocess/record.go', 'Observation'))
        body = '\n'.join(declarations).replace('linuxprotection.NativeObject', 'NativeObject').replace('linuxprocess.Observation', 'Observation').replace('mobiletor.DesktopLinuxClosedTransferSnapshot', 'ClosedSnapshot')
        # Source/Destination native snapshots are omitted in this codec witness;
        # their opaque payload grants no Python-side mutation authority.
        program = self.base / 'image-codec.go'
        program.write_text('package main\nimport("bytes";"encoding/json";"io";"os";"net/netip")\ntype ClosedSnapshot struct{}\n' + body + '\n' +
            'func main(){raw,e:=io.ReadAll(os.Stdin);if e!=nil{panic(e)};var c linuxStandardImageUpgradeControl;d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields();if e=d.Decode(&c);e!=nil{panic(e)};canonical,e:=json.Marshal(c);if e!=nil||!bytes.Equal(raw,canonical){panic("Python request differs from actual Go canonical DTO")};r:=linuxStandardImageUpgradeControlReply{Schema:1,Sequence:c.Sequence,Action:c.Action,Complete:true,Upgrade:&linuxStandardServiceImageUpgradeResponse{Envelope:*c.Envelope,Phase:"reserved"}};encoded,e:=json.Marshal(r);if e!=nil{panic(e)};os.Stdout.Write(encoded)}\n')
        output = subprocess.run([shutil.which('go'), 'run', '-p=2', str(program)], input=m.generation_json(request), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=120, env=dict(os.environ, GOMAXPROCS='2')).stdout
        reply = m.image_decode(output)
        update = owner._accept(reply, [], request)
        self.assertEqual(update['envelope'], request['envelope'])
        self.assertEqual(update['phase'], 'reserved')
        self.assertEqual(m.generation_json(reply), output)

    def test_active_image_original_coordinator_fd3_spawn_and_terminal_join(self):
        m = self.installer
        root = self.base / 'direct-root'
        (root / 'run').mkdir(parents=True, mode=0o700)
        write(root / 'run/kill-switch.lock', b'', 0o600)
        write(root / 'run/kill-switch.json', '{}', 0o600)
        def declaration(path, name):
            source = (REPOSITORY / path).read_text()
            body = source[source.index('type ' + name + ' struct {'):]
            return body[:body.index('\n}') + 2]
        declarations = [declaration('cmd/client/linux_standard_service_image_upgrade_protocol_linux.go', name) for name in ('linuxStandardImageUpgradeEnvelope', 'linuxStandardImageUpgradeControl', 'linuxStandardImageUpgradeControlReply', 'linuxStandardServiceImageUpgradeResponse')]
        for path, name in (('cmd/client/linux_standard_service_generation_linux.go', 'linuxStandardGenerationSelection'), ('internal/linuxprotection/record.go', 'NativeObject'), ('internal/linuxprocess/record.go', 'Object'), ('internal/linuxprocess/record.go', 'Observation')):
            declarations.append(declaration(path, name))
        types_source = '\n'.join(declarations).replace('linuxprotection.NativeObject', 'NativeObject').replace('linuxprocess.Observation', 'Observation').replace('mobiletor.DesktopLinuxClosedTransferSnapshot', 'ClosedSnapshot')
        program, binary = self.base / 'coordinator.go', self.base / 'coordinator'
        # This tiny executable supplies no native guard authority. It exercises
        # the actual launcher, inherited seqpacket, exact Go DTO and real pidfd
        # terminal join. Real two-creator acceptance is a separate native gate.
        program.write_text('package main\nimport("os";"bytes";"encoding/json";"crypto/sha256";"fmt";"syscall";"net/netip")\ntype ClosedSnapshot struct{}\n' + types_source + '\nconst root=' + json.dumps(str(root)) + '\n' + r'''
func object(path string) NativeObject {i,e:=os.Stat(path);if e!=nil{panic(e)};s:=i.Sys().(*syscall.Stat_t);return NativeObject{Device:uint64(s.Dev),Inode:s.Ino,Mode:s.Mode,UID:s.Uid,GID:s.Gid}}
func hash(body []byte)string{return fmt.Sprintf("%x",sha256.Sum256(body))}
func read(path string)[]byte{b,e:=os.ReadFile(path);if e!=nil{panic(e)};return b}
func main(){
 if len(os.Args)!=2||os.Args[1]!="--linux-standard-owner-image-upgrade"{panic("fixed role")}
 var scope *linuxStandardImageUpgradeEnvelope
 for{b:=make([]byte,65537);n,_,flags,_,e:=syscall.Recvmsg(3,b,nil,0);if e!=nil{panic(e)};if n==0{return};if n>65536||flags!=0{panic("bad frame")};b=b[:n]
 var c linuxStandardImageUpgradeControl;d:=json.NewDecoder(bytes.NewReader(b));d.DisallowUnknownFields();if e=d.Decode(&c);e!=nil{panic(e)};canonical,_:=json.Marshal(c);if !bytes.Equal(canonical,b){panic("noncanonical")}
 phase:="reserved";cleanup:=int64(0)
 if c.Action=="prepare"{var old linuxStandardGenerationSelection;if e=json.Unmarshal(read(root+"/service-generation.json"),&old);e!=nil{panic(e)};scope=&linuxStandardImageUpgradeEnvelope{Schema:1,ID:"cccccccccccccccccccccccccccccccc",DeadlineNS:c.DeadlineNS,OldGeneration:old,NewGeneration:*c.NewGeneration,ActivationSHA256:hash(read(root+"/service-generation.json")),Root:object(root),Run:object(root+"/run"),MutationLock:object(root+"/run/kill-switch.lock"),SavedState:object(root+"/run/kill-switch.json"),SavedStateSHA256:hash(read(root+"/run/kill-switch.json")),ProfileID:"policy",ProfileRevision:hash(nil),Endpoints:[]netip.Addr{netip.MustParseAddr("203.0.113.77")},SourceSHA256:hash(nil),DestinationSession:"dddddddddddddddddddddddddddddddd",DestinationSHA256:hash(nil)}}else if c.Action=="abort"{a,_:=json.Marshal(scope);b,_:=json.Marshal(c.Envelope);if !bytes.Equal(a,b){panic("changed original scope")};phase="aborted";cleanup=c.CleanupDeadlineNS}else{panic("unexpected action")}
 r:=linuxStandardImageUpgradeControlReply{Schema:1,Sequence:c.Sequence,Action:c.Action,Complete:true,Upgrade:&linuxStandardServiceImageUpgradeResponse{Envelope:*scope,Phase:phase,CleanupDeadlineNS:cleanup}}
 raw,_:=json.Marshal(r);if n,e=syscall.SendmsgN(3,raw,nil,nil,0);e!=nil||n!=len(raw){panic("short response")}
 }
}
''')
        subprocess.run([shutil.which('go'), 'build', '-p=2', '-o', str(binary), str(program)], check=True, timeout=120, env=dict(os.environ, GOMAXPROCS='2'))
        stages = []
        for name in ('old', 'new'):
            stage = self.base / (name + '-code')
            stage.mkdir(mode=0o700)
            write(stage / 'router-vpn-client', binary.read_bytes(), 0o755)
            write(stage / 'LICENSE', name)
            m.stage_service_generation(stage, root)
            stages.append(stage)
        write(root / m.GENERATION_ACTIVATION, (stages[0] / m.GENERATION_ACTIVATION).read_bytes(), 0o600)
        selected = json.loads((stages[1] / m.GENERATION_ACTIVATION).read_bytes())
        owner = m.ActiveImageCoordinator(root, selected)
        self.addCleanup(owner.close)
        original_pid = owner.pid
        self.assertTrue(owner.process.current())
        self.assertEqual(owner.call('prepare')['phase'], 'reserved')
        first = owner.cleanup_clock()
        self.assertEqual(owner.call('abort', cleanup=True)['cleanup_deadline_ns'], first)
        owner.join(first)
        self.assertIsNone(owner.pid)
        with self.assertRaises(ChildProcessError):
            os.waitpid(original_pid, os.WNOHANG)

    def test_service_generation_manifest_matches_actual_go_decoder(self):
        name = 'café<&>' + chr(0x2028) + chr(0x2029) + '.txt'
        write(self.source / 'client' / name, 'exact Unicode source bytes')
        self.install()
        image = self.installer.activated_service_image(self.root)
        raw = (image.parent / self.installer.GENERATION_MANIFEST).read_bytes()
        self.assertEqual((image.parent / 'client' / name).read_bytes(), b'exact Unicode source bytes')
        go = shutil.which('go')
        if not go:
            raise RuntimeError('Go required for actual service generation decoder interoperability')
        source = (REPOSITORY / 'cmd/client/linux_standard_service_generation_linux.go').read_text()
        def declaration(marker):
            body = source[source.index(marker):]
            return body[:body.index('\n}') + 2]
        declarations = '\n'.join(declaration(marker) for marker in (
            'type linuxStandardGenerationEntry struct {',
            'type linuxStandardGenerationManifestData struct {',
            'func linuxStandardGenerationDecode('))
        program = self.base / 'generation-codec.go'
        program.write_text('package main\nimport("bytes";"encoding/json";"errors";"io";"os")\n' + declarations +
            '\nfunc main(){raw,e:=io.ReadAll(os.Stdin);if e!=nil{panic(e)};var value linuxStandardGenerationManifestData;if e=linuxStandardGenerationDecode(raw,&value);e!=nil{panic(e)};body,e:=json.Marshal(value);if e!=nil{panic(e)};if _,e=os.Stdout.Write(body);e!=nil{panic(e)}}\n')
        env = dict(os.environ, GOMAXPROCS='2')
        decoded = subprocess.run([go, 'run', '-p=2', str(program)], input=raw,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 timeout=120, check=True, env=env)
        self.assertEqual(decoded.stdout, raw, 'installer changed actual Go canonical bytes')

    def test_service_generation_bounds_match_native_before_publication(self):
        tree = self.base / 'oversized-source'
        tree.mkdir(mode=0o700)
        self.assertEqual(self.installer.GENERATION_MAX_FILES, 8192)
        self.assertEqual(self.installer.GENERATION_MAX_MANIFEST, 2 << 20)
        for number in range(8193):
            write(tree / (str(number).zfill(5) + '-' + 'x' * 230), b'')
        with self.assertRaisesRegex(ValueError, 'inventory exceeded'):
            self.installer.generation_inventory(tree)
        (tree / ('08192-' + 'x' * 230)).unlink()
        records = self.installer.generation_inventory(tree)
        self.assertEqual(len(records), 8192)
        self.assertGreater(len(self.installer.generation_json({'schema': 1, 'files': records})), 2 << 20)
        with self.assertRaisesRegex(ValueError, 'manifest exceeded'):
            self.installer.generation_manifest(records)
        self.assertFalse(self.root.exists(), 'oversized inventory published a service source')
        self.install()
        activation = self.root / self.installer.GENERATION_ACTIVATION
        activation.write_bytes(b' ' * 4097)
        with self.assertRaisesRegex(ValueError, 'metadata exceeded'):
            self.installer.activated_service_image(self.root)

    def test_service_generation_is_exact_code_only_and_reused_without_mutation(self):
        self.install()
        activation = self.root / self.installer.GENERATION_ACTIVATION
        first = activation.read_bytes()
        image = self.installer.activated_service_image(self.root)
        generation = image.parent
        before = snapshot(generation, metadata=True)
        self.assertNotEqual(image.stat().st_ino, (self.root / 'router-vpn-client').stat().st_ino)
        for private in ('routers.json', 'client.json', 'generated', 'run', 'state.json'):
            self.assertFalse((generation / private).exists(), private)
        manifest = (generation / self.installer.GENERATION_MANIFEST).read_bytes()
        self.assertEqual(hashlib.sha256(manifest).hexdigest(), generation.name)
        self.assertEqual(json.loads(manifest)['files'], self.installer.generation_inventory(generation))
        self.new_integration(early_enabled=True)
        self.install()
        self.assertEqual(activation.read_bytes(), first)
        self.assertEqual(snapshot(generation, metadata=True), before)

    def test_service_generation_retains_original_lease_across_selection_change(self):
        self.install()
        old = self.installer.activated_service_image(self.root)
        snapshot_before = snapshot(old.parent, metadata=True)
        lock = old.parent.with_name(old.parent.name + '.lock')
        held = os.open(lock, os.O_RDWR)
        try:
            fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
            source = package_fixture(self.base / 'next-package', version='generation-two')
            self.new_integration(early_enabled=True)
            self.install(source=source)
            new = self.installer.activated_service_image(self.root)
            self.assertNotEqual(old.parent, new.parent)
            self.assertEqual(snapshot(old.parent, metadata=True), snapshot_before)
            other = os.open(lock, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(other)
        finally:
            os.close(held)

    def test_service_generation_tampering_cannot_publish_source(self):
        self.install()
        image = self.installer.activated_service_image(self.root)
        before = snapshot(self.root, metadata=True)
        image.write_bytes(b'changed generation executable')
        self.new_integration(early_enabled=True)
        # Per-generation unit discovery validates the same immutable source
        # before staging; either exact rejection boundary preserves the owner.
        with self.assertRaisesRegex(ValueError, '(?:immutable service generation changed|Service generation source changed)'):
            self.install()
        self.assertEqual(snapshot(self.root, metadata=True), before)
        with self.assertRaisesRegex(ValueError, 'generation source changed'):
            self.installer.activated_service_image(self.root)

    def test_service_generation_lost_ready_retains_both_exact_generations(self):
        self.install()
        old = self.installer.activated_service_image(self.root)
        before = snapshot(old.parent, metadata=True)
        source = package_fixture(self.base / 'next-generation', version='next-generation')
        self.new_integration(early_enabled=True, fail=('start', self.installer.EARLY_NAME))
        with self.assertRaisesRegex(RuntimeError, 'activation did not complete'):
            self.install(source=source)
        self.assertTrue(old.is_file(), 'uncertain readiness discarded original immutable generation')
        selected = json.loads((self.root / self.installer.GENERATION_ACTIVATION).read_bytes())['generation']
        self.assertTrue((old.parent.parent / selected / 'router-vpn-client').is_file(), 'uncertain readiness discarded selected possible creator source')
        new = self.installer.activated_service_image(self.root)
        self.assertNotEqual(old.parent, new.parent)
        self.assertEqual(snapshot(old.parent, metadata=True), before)
        self.assertTrue(new.is_file())
        unit = self.system / 'etc/systemd/system' / self.installer.EARLY_NAME
        self.assertIn('ExecStart=' + str(new) + ' ' + self.installer.SERVICE_ARGUMENT, unit.read_text())
        self.assertEqual(len(list(self.base.glob('.' + self.root.name + '.install-*'))), 1)

    def test_service_generation_pre_activation_failure_restores_original_selection(self):
        self.install()
        before = (self.root / self.installer.GENERATION_ACTIVATION).read_bytes()
        original = self.installer.activated_service_image(self.root)
        source = package_fixture(self.base / 'failed-generation', version='failed-generation')
        self.new_integration(early_enabled=True, fail=('enable', self.installer.EARLY_NAME))
        with self.assertRaises(subprocess.CalledProcessError):
            self.install(source=source)
        self.assertEqual((self.root / self.installer.GENERATION_ACTIVATION).read_bytes(), before)
        self.assertEqual(self.installer.activated_service_image(self.root), original)

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
        self.assertEqual([call[0][-1] for call in self.boundary.calls],
                         [self.installer.UPGRADE_ARGUMENT, self.installer.EARLY_NAME])
        self.assertEqual(self.boundary.calls[-1][0][:2], ('/usr/bin/systemctl', 'start'))
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

    def test_idle_service_retires_before_original_source_promotion(self):
        self.install()
        original_image = (self.root / 'router-vpn-client').stat().st_ino
        self.new_integration(early_enabled=True)
        descriptor = os.open(self.root.with_name(self.root.name + '.install.lock'), os.O_RDWR)
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        self.boundary.idle_service_lock = descriptor
        observed = []

        def verify(stage):
            self.assertIsNone(self.boundary.idle_service_lock)
            self.assertEqual((self.root / 'router-vpn-client').stat().st_ino, original_image)
            self.assertEqual(self.boundary.calls[0][0][-1], self.installer.UPGRADE_ARGUMENT)
            observed.append(True)
            self.installer.verify_runtimes(stage)

        try:
            try:
                self.install(verifier=verify)
            except RuntimeError as error:
                self.fail('Original idle service was not joined before exclusive promotion: ' + str(error))
        finally:
            if self.boundary.idle_service_lock is not None:
                os.close(self.boundary.idle_service_lock)
        self.assertTrue(observed)
        self.assertNotEqual((self.root / 'router-vpn-client').stat().st_ino, original_image)
        self.assert_no_staging()

    def test_live_controller_blocks_upgrade_before_retiring_idle_service(self):
        self.install()
        baseline = snapshot(self.root, metadata=True)
        self.new_integration(early_enabled=True)
        descriptor = os.open(self.root.with_name(self.root.name + '.controller.lock'), os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, 'Close Router VPN'):
                self.install()
        finally:
            os.close(descriptor)
        self.assertEqual(self.boundary.calls, [])
        self.assertEqual(snapshot(self.root, metadata=True), baseline)
        self.assert_no_staging()

    def test_retained_service_refusal_preserves_original_application(self):
        self.install()
        baseline = snapshot(self.root, metadata=True)
        self.new_integration(early_enabled=True, fail=('retire-idle', ''))
        with self.assertRaises(subprocess.CalledProcessError):
            self.install()
        self.assertEqual(snapshot(self.root, metadata=True), baseline)
        self.assertEqual(len(self.boundary.calls), 1)
        self.assert_no_staging()

    def test_persisted_protection_never_authorizes_promotion(self):
        self.install()
        write(self.root / 'run/kill-switch.json', '{"table":"an-old-name","handle":9}', 0o600)
        baseline = snapshot(self.root, metadata=True)
        self.new_integration(early_enabled=True)
        with self.assertRaisesRegex(RuntimeError, 'Original Router VPN protection is retained'):
            self.install()
        self.assertEqual(snapshot(self.root, metadata=True), baseline)
        self.assert_no_staging()

    def test_failed_new_service_readiness_retains_both_original_installations(self):
        self.install()
        self.seed_private()
        baseline = snapshot(self.root, metadata=True)
        source = package_fixture(self.base / 'new-package', version='two')
        self.new_integration(early_enabled=True, fail=('start', self.installer.EARLY_NAME))
        with mock.patch.object(self.integration, 'rollback', side_effect=AssertionError('cannot roll back a possible native creator')):
            with self.assertRaisesRegex(RuntimeError, 'activation did not complete') as caught:
                self.install(source=source)
        pending = list(self.base.glob('.' + self.root.name + '.install-*'))
        self.assertEqual(len(pending), 1)
        self.assertIn(str(pending[0]), str(caught.exception))
        self.assertEqual(snapshot(pending[0] / 'previous', metadata=True), baseline)
        self.assertIn('package two', (self.root / 'MODES.md').read_text())
        current = snapshot(self.root, metadata=True)
        self.new_integration()
        with self.assertRaisesRegex(RuntimeError, 'interrupted native installation'):
            self.install()
        self.assertEqual(snapshot(self.root, metadata=True), current)
        self.assertEqual(self.boundary.calls, [])

    def test_active_exited_legacy_unit_cannot_supply_new_service_readiness(self):
        old = self.system / 'etc/systemd/system' / self.installer.LEGACY_EARLY_NAME
        legacy_bytes = '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/old/reassert\n'
        write(old, legacy_bytes)
        self.new_integration(legacy_early_enabled=True)
        self.install()
        self.assertNotEqual(self.installer.LEGACY_EARLY_NAME, self.installer.EARLY_NAME)
        self.assertEqual(old.read_text(), legacy_bytes)
        actions = [args for args, _ in self.boundary.calls]
        ready = actions.index(('/usr/bin/systemctl', 'start', self.installer.EARLY_NAME))
        retired_boot = actions.index(('/usr/bin/systemctl', 'disable', self.installer.LEGACY_EARLY_NAME))
        self.assertLess(ready, retired_boot)
        self.assertFalse(self.boundary.enabled[self.installer.LEGACY_EARLY_NAME])
        self.assertTrue(self.boundary.enabled[self.installer.EARLY_NAME])
        self.assertFalse(any('stop' in command or 'restart' in command for command in actions))

    def test_legacy_boot_enablement_survives_failed_new_readiness(self):
        self.new_integration(legacy_early_enabled=True, fail=('start', self.installer.EARLY_NAME))
        with self.assertRaisesRegex(RuntimeError, 'activation did not complete'):
            self.install()
        self.assertTrue(self.boundary.enabled[self.installer.LEGACY_EARLY_NAME])
        actions = [args for args, _ in self.boundary.calls]
        self.assertNotIn(('/usr/bin/systemctl', 'disable', self.installer.LEGACY_EARLY_NAME), actions)
        self.assertTrue(self.root.exists())
        self.assertEqual(len(list(self.base.glob('.' + self.root.name + '.install-*'))), 1)

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
        self.assertEqual([call[0][-1] for call in self.boundary.calls],
                         [self.installer.UPGRADE_ARGUMENT, self.installer.EARLY_NAME])
        self.assertEqual(self.boundary.calls[-1][0][:2], ('/usr/bin/systemctl', 'start'))
        self.assert_no_staging()

    def test_system_failure_rolls_back_application_files_and_service_enablement(self):
        self.install()
        self.seed_private()
        write(self.system / 'usr/local/bin/router-vpn', '# previous installed launcher\n', 0o751)
        write(self.system / 'etc/systemd/system/unrelated.service', '[Service]\nExecStart=/bin/true\n')
        application, system = snapshot(self.root, metadata=True), file_bytes(self.system)
        before_modes = {name: stat.S_IMODE((self.system / name).stat().st_mode) for name in system}
        for failure in (('daemon-reload', ''), ('enable', self.installer.EARLY_NAME)):
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
        self.new_integration(fail=('enable', self.installer.EARLY_NAME))
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
        self.new_integration(fail=('enable', self.installer.EARLY_NAME),
                             query_codes={('disable', self.installer.EARLY_NAME): 5})
        with self.assertRaises(Exception) as failed:
            self.install()
        self.assertIsInstance(failed.exception, RuntimeError)
        self.assertIn('rollback needs recovery', str(failed.exception))
        pending = list(self.base.glob('.' + self.root.name + '.install-*'))
        self.assertEqual(len(pending), 1)
        self.assertEqual(snapshot(pending[0] / 'previous', metadata=True), baseline)
        self.assertTrue(self.boundary.enabled[self.installer.EARLY_NAME])

    def test_rollback_failure_retains_identifiable_previous_application(self):
        self.install()
        self.seed_private()
        baseline = snapshot(self.root, metadata=True)
        self.new_integration(fail=('enable', self.installer.EARLY_NAME))
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
        self.assertEqual(parser['Service']['Type'], 'notify')
        self.assertEqual(parser['Service']['NotifyAccess'], 'main')
        self.assertEqual(parser['Service']['Restart'], 'no')
        self.assertEqual(parser['Service']['TimeoutStartSec'], 'infinity')
        self.assertEqual(parser['Unit']['RefuseManualStop'], 'yes')
        self.assertEqual(parser['Service']['ExecStart'], str(self.installer.activated_service_image(self.root)) + ' --linux-standard-owner-service')
        for name in ('NetworkManager.service', 'systemd-networkd.service', 'networking.service', 'connman.service', 'wicked.service'):
            parser.read_string((self.system / 'etc/systemd/system' / (name + '.d/50-router-vpn-protection.conf')).read_text())
            self.assertEqual(parser['Unit'].get('Requires'), self.installer.EARLY_NAME, name)
            self.assertEqual(parser['Unit'].get('After'), self.installer.EARLY_NAME, name)
        self.assertTrue(self.boundary.enabled[self.installer.EARLY_NAME])
        self.assertFalse(self.boundary.enabled['router-vpn-client.service'])
        actions = [arguments for arguments, _ in self.boundary.calls]
        start = actions.index(('/usr/bin/systemctl', 'start', self.installer.EARLY_NAME))
        self.assertLess(actions.index(('/usr/bin/systemctl', 'enable', self.installer.EARLY_NAME)), start)
        self.assertFalse(any(command[-1] == 'reassert' for command in actions))
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
        ('resend an already-sent control frame after read timeout',
         'if self.awaiting is None:', 'if True:',
         'test_active_image_delayed_control_reply_does_not_queue_duplicate'),
        ('accept a different native process on freeze replay',
         'if retained.observation != candidate.observation or retained.arguments != candidate.arguments:', 'if False:',
         'test_active_image_freeze_replay_retains_exact_native_pins'),
        ('ignore every matching process once any upgrade pin exists',
         'if original_pins and any(pin.excludes(process) for pin in original_pins):', 'if original_pins:',
         'test_active_image_freeze_replay_retains_exact_native_pins'),
        ('renew proposed cleanup on each retry', 'if not self.proposed_cleanup_ns:', 'if True:',
         'test_active_image_delayed_control_reply_does_not_queue_duplicate'),
        ('restore copied bytes instead of the original code inode',
         'os.rename(backup, target)', 'copy_checked(backup, target)',
         'test_active_image_partial_code_failure_restores_exact_original_objects'),
        ('accept READY from a different candidate PID', 'if fields != expected:', 'if False:',
         'test_active_image_wrong_notify_process_cannot_finish_upgrade'),
        ('continue code promotion after original work expiry', 'if remaining <= 0:', 'if False:',
         'test_active_image_work_expiry_restores_with_single_cleanup_clock'),
        ('use Python-only ASCII escaping for generation metadata',
         "ensure_ascii=False", "ensure_ascii=True", 'test_service_generation_manifest_matches_actual_go_decoder'),
        ('leave notify service on mutable canonical image',
         "unit = EARLY_UNIT.replace('/opt/router-vpn-client/router-vpn-client ' + SERVICE_ARGUMENT, str(image) + ' ' + SERVICE_ARGUMENT)",
         'unit = EARLY_UNIT', 'test_always_service_and_network_dependencies_are_installed_without_restart'),
        ('discard generations after uncertain readiness',
         "raise RuntimeError('New protection owner activation did not complete;",
         "shutil.rmtree(root.with_name(root.name + '.service-generations')); raise RuntimeError('New protection owner activation did not complete;",
         'test_service_generation_lost_ready_retains_both_exact_generations'),
        ('ignore the shared controller lock',
         'fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)', 'None',
         'test_fixed_adjacent_lock_blocks_controller_and_parallel_installer'),
        ('copy untrusted source ownership', 'os.chown(destination, 0, 0)', 'os.chown(destination, info.st_uid, info.st_gid)',
         'test_upgrade_preserves_private_state_with_fresh_root_owned_inodes'),
        ('skip bundled runtime verification', '            verifier(stage)', '            pass',
         'test_invalid_runtime_keeps_previous_application_and_system_files'),
        ('discard previous private state', 'if child.name not in CODE_TREES | CODE_FILES | {GENERATION_ACTIVATION}:', 'if False:',
         'test_upgrade_preserves_private_state_with_fresh_root_owned_inodes'),
        ('skip system-file rollback', '                    integration.rollback()', '                    pass',
         'test_system_failure_rolls_back_application_files_and_service_enablement'),
        ('weaken the network protection dependency', 'Requires=router-vpn-standard-owner.service',
         'Wants=router-vpn-standard-owner.service',
         'test_always_service_and_network_dependencies_are_installed_without_restart'),
        ('stop dependent networking during installation', "self.run(['/usr/bin/systemctl', 'start', EARLY_NAME])",
         "self.run(['/usr/bin/systemctl', 'restart', EARLY_NAME])",
         'test_always_service_and_network_dependencies_are_installed_without_restart'),
        ('ignore failed rollback disable', "self.run(['/usr/bin/systemctl', 'disable', EARLY_NAME])",
         "self.run(['/usr/bin/systemctl', 'disable', EARLY_NAME], check=False)",
         'test_rollback_service_failure_keeps_recovery_material'),
        ('overwrite an interrupted recovery transaction', '        if pending:', '        if False:',
         'test_interrupted_backup_blocks_install_without_touching_recoverable_state'),
        ('skip original idle service retirement', '        retired_service = integration.retire_idle(root)',
         '        retired_service = False', 'test_idle_service_retires_before_original_source_promotion'),
        ('ignore retained protection state', '    if state.exists() or state.is_symlink():',
         '    if False:', 'test_persisted_protection_never_authorizes_promotion'),
        ('admit controller during service readiness', "('.install.transaction.lock', '.controller.lock')",
         "('.install.transaction.lock',)", 'test_always_service_and_network_dependencies_are_installed_without_restart'),
        ('reuse active exited oneshot as readiness', "EARLY_NAME = 'router-vpn-standard-owner.service'",
         "EARLY_NAME = 'router-vpn-killswitch-early.service'", 'test_active_exited_legacy_unit_cannot_supply_new_service_readiness'),
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
