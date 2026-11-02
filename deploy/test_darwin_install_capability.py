#!/usr/bin/env python3
"""Exercise the shipping installer broker and Python/Go borrowers with real locks.

The fixed /opt fixture must be absent. Darwin runs in its explicit disposable
native test host; Linux requires a private /opt mount prepared by the runner.
No PF, launchd, route, service or installed user configuration is modified.
Linux models only Darwin's peer ABI using the actual SO_PEERCRED interface.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import importlib.util
import os
from pathlib import Path
import select
import shlex
import shutil
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1]
HELPER = None


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CAP = load('installer_capability_fixture_source', SOURCE/'modes/darwin_install_capability.py')
BASELINE = load('installer_capability_state_source', SOURCE/'modes/darwin_pf_baseline.py')
BASELINE.CAPABILITY = CAP


def linux_peer(channel, expected):
    info = os.fstat(channel.fileno())
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or
            channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM or
            channel.getsockname() != '' or channel.getpeername() != ''):
        raise RuntimeError('fixture has another anonymous root stream')
    pid, uid, _ = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if pid != expected or uid != 0:
        raise RuntimeError('fixture has another original kernel peer')


if sys.platform == 'linux':
    CAP._peer = linux_peer


def readable_line(pipe):
    if not select.select([pipe], [], [], 4)[0]:
        raise RuntimeError('captured receiver did not acknowledge before the fixture deadline')
    return pipe.readline().strip()


def child(arguments):
    descriptor, generation, issuer, mode, helper, release = arguments
    descriptor, issuer, release = int(descriptor), int(issuer), int(release)
    with CAP.borrow(descriptor, generation, issuer) as owner:
        with BASELINE.state_guard(CAP.ROOT):
            if mode == 'mutation-fail':
                CAP.possible_mutation()
                (CAP.ROOT/'fixture-current-journal').write_bytes(b'new owned PF reference\n')
                raise RuntimeError('deliberate failure after acknowledged possible mutation')
            if mode == 'python-only':
                return
            command = [helper, '--owned-installcap-fixture', str(descriptor), generation,
                       str(issuer), 'hold' if mode == 'orphan' else mode, str(release)]
            native = subprocess.Popen(command, pass_fds=(*BASELINE.process_authority_fds(), release),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if mode in ('hold', 'orphan', 'half-close'):
                if readable_line(native.stdout) != 'native-adopted':
                    raise RuntimeError('nested receiver never acquired its exact original capability')
                print('native-adopted', flush=True)
                if mode == 'orphan':
                    # Deliberately skip Python cleanup. The independent native
                    # borrower and inherited outer lease must still be joined.
                    os._exit(71)
            output, error = native.communicate(timeout=8)
            if native.returncode:
                raise RuntimeError('nested receiver rejected its capability: '+error[-1024:])


class InstallerCapabilities(unittest.TestCase):
    def setUp(self):
        if os.getuid() != 0 or os.geteuid() != 0:
            self.fail('kernel capability fixture requires its explicit root test boundary')
        if sys.platform == 'linux':
            marker = Path('/opt/routervpn-private-installcap-namespace')
            self.assertEqual(marker.read_bytes(), b'owned private mount fixture\n')
        self.assertFalse(CAP.ROOT.exists() or CAP.ROOT.is_symlink(), 'fixture refuses an existing installation')
        self.assertFalse(CAP.LOCK.exists() or CAP.LOCK.is_symlink(), 'fixture refuses an existing install lock')
        CAP.ROOT.mkdir(mode=0o700)
        self.root_info = CAP.ROOT.lstat()
        marker = CAP.ROOT/'fixture-installcap-authority'
        marker.write_bytes(b'explicit disposable installer capability fixture\n')
        marker.chmod(0o600)
        self.original = os.open(CAP.LOCK, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600)
        fcntl.flock(self.original, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.brokers, self.children, self.releases = [], [], []

    def tearDown(self):
        for release in self.releases:
            with contextlib.suppress(OSError):
                os.close(release)
        for process in self.children:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        for broker in self.brokers:
            broker.child.close()
            broker.thread.join(6)
            self.assertFalse(broker.thread.is_alive(), 'fixture retains an unjoined capability owner')
        os.close(self.original)
        # Every created process and broker joined above. Remove only this
        # captured fixture root; never recursively clean a replacement owner.
        self.assertTrue(os.path.samestat(self.root_info, CAP.ROOT.lstat()))
        shutil.rmtree(CAP.ROOT)
        CAP.LOCK.unlink()

    def blocked(self):
        for operation in (fcntl.LOCK_SH, fcntl.LOCK_EX):
            probe = os.open(CAP.LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                with self.assertRaises(BlockingIOError, msg='borrower released or downgraded original EX'):
                    fcntl.flock(probe, operation | fcntl.LOCK_NB)
            finally:
                os.close(probe)

    def start(self, mode='normal'):
        broker = CAP._Broker(self.original, time.monotonic()+5)
        self.brokers.append(broker)
        read_end, write_end = os.pipe()
        self.releases.append(write_end)
        try:
            process = subprocess.Popen([sys.executable, '-BEsS', str(Path(__file__).resolve()), '--child',
                                        str(broker.child.fileno()), broker.generation, str(os.getpid()), mode,
                                        str(HELPER), str(read_end)],
                                       pass_fds=(broker.child.fileno(), read_end),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        finally:
            os.close(read_end)
        self.children.append(process)
        broker.child.close()
        broker.thread.start()
        return broker, process, write_end

    def finish(self, broker, process, *, success):
        output, error = process.communicate(timeout=6)
        broker.thread.join(6)
        self.assertFalse(broker.thread.is_alive(), 'original capability thread did not join')
        self.assertEqual(process.returncode == 0, success, error[-2048:])
        if success:
            self.assertIsNone(broker.error)
            self.assertTrue(broker.reassert_complete)
            self.assertTrue(broker.drained)
            self.assertFalse(broker.active)
            self.assertFalse(broker.directory.exists())
        else:
            self.assertTrue(process.returncode or broker.error)
        return output, error

    def test_python_and_actual_go_retain_original_ex_and_both_state_locks(self):
        broker, process, release = self.start('hold')
        self.assertEqual(readable_line(process.stdout), 'native-adopted')
        self.blocked()
        state = os.open(CAP.ROOT/'pf-state.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(state, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(state)
        os.close(release); self.releases.remove(release)
        self.finish(broker, process, success=True)
        self.blocked()

    def test_python_death_does_not_retire_live_native_borrower(self):
        broker, process, release = self.start('orphan')
        self.assertEqual(readable_line(process.stdout), 'native-adopted')
        self.assertEqual(process.wait(timeout=3), 71)
        self.assertFalse(broker.eof.is_set())
        self.assertFalse(broker.drained)
        self.blocked()
        os.close(release); self.releases.remove(release)
        self.finish(broker, process, success=False)
        self.assertTrue(broker.eof.is_set())
        self.assertTrue(broker.drained)
        self.assertFalse(broker.reassert_complete)

    def test_half_close_is_not_original_lease_retirement(self):
        broker, process, release = self.start('half-close')
        self.assertEqual(readable_line(process.stdout), 'native-adopted')
        self.assertTrue(broker.eof.wait(3), 'fixture did not reach real half-close')
        self.assertFalse(broker.drained, 'protocol EOF was mistaken for retained lease retirement')
        for lease in broker.leases.values():
            with self.assertRaises(BlockingIOError):
                fcntl.flock(lease['probe'], fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.blocked()
        os.close(release); self.releases.remove(release)
        self.finish(broker, process, success=False)
        self.assertTrue(broker.drained)

    def test_possible_mutation_is_acknowledged_before_failed_child_returns(self):
        broker, process, _ = self.start('mutation-fail')
        self.finish(broker, process, success=False)
        self.assertTrue(broker.mutation_possible)
        self.assertTrue(broker.drained)
        self.assertEqual((CAP.ROOT/'fixture-current-journal').read_bytes(), b'new owned PF reference\n')

    def test_no_borrower_cannot_fabricate_completed_reassert(self):
        broker = CAP._Broker(self.original, time.monotonic()+3)
        self.brokers.append(broker)
        broker.child.close()
        broker.thread.start(); broker.thread.join(4)
        self.assertTrue(broker.eof.is_set())
        self.assertTrue(broker.drained)
        self.assertFalse(broker.reassert_complete)
        self.assertIsNotNone(broker.error)

    def test_canceled_native_acquisition_cannot_reach_its_action(self):
        broker, process, _ = self.start('canceled')
        self.finish(broker, process, success=False)
        self.assertFalse((CAP.ROOT/'fixture-native-adopted').exists())
        self.assertFalse(broker.mutation_possible)

    def test_python_and_native_reject_noncapability_channels(self):
        for kind in ('missing', 'regular', 'datagram', 'wrong-peer', 'named'):
            with self.subTest(kind=kind), contextlib.ExitStack() as cleanup:
                issuer = os.getpid()
                if kind == 'missing':
                    descriptor, passed = 99999, ()
                elif kind == 'regular':
                    descriptor = os.open(CAP.ROOT/'fixture-installcap-authority', os.O_RDONLY)
                    cleanup.callback(os.close, descriptor)
                    passed = (descriptor,)
                elif kind == 'named':
                    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    cleanup.callback(listener.close)
                    path = CAP.ROOT/'fixture-named-channel'
                    listener.bind(str(path)); listener.listen(1)
                    cleanup.callback(path.unlink)
                    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    cleanup.callback(endpoint.close)
                    endpoint.connect(str(path))
                    peer, _ = listener.accept(); cleanup.callback(peer.close)
                    descriptor, passed = endpoint.fileno(), (endpoint.fileno(),)
                else:
                    pair = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM if kind == 'datagram' else socket.SOCK_STREAM)
                    for endpoint in pair:
                        cleanup.callback(endpoint.close)
                    descriptor, passed = pair[0].fileno(), (pair[0].fileno(),)
                    if kind == 'wrong-peer':
                        issuer += 1
                result = subprocess.run([str(HELPER), '--owned-installcap-fixture', str(descriptor),
                                         '1'*32, str(issuer), 'normal', '0'], pass_fds=passed,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                self.assertNotEqual(result.returncode, 0, 'native receiver adopted '+kind)
                self.assertFalse((CAP.ROOT/'fixture-native-adopted').exists())
                duplicate = os.dup(descriptor) if passed else descriptor
                try:
                    with self.assertRaises((RuntimeError, OSError), msg='Python borrower adopted '+kind):
                        with CAP.borrow(duplicate, '1'*32, issuer):
                            self.fail('noncapability channel reached a protected action')
                finally:
                    if passed:
                        with contextlib.suppress(OSError):
                            os.close(duplicate)

    def test_cancellation_during_native_ack_drains_before_any_action(self):
        original = CAP._send
        waiting, acknowledge = threading.Event(), threading.Event()

        def held_ack(channel, frame, descriptors=()):
            if frame['operation'] == 'ack' and frame['phase'] == 'plan':
                waiting.set()
                if not acknowledge.wait(4):
                    raise RuntimeError('fixture acknowledgment did not retire')
            return original(channel, frame, descriptors)

        with mock.patch.object(CAP, '_send', held_ack):
            broker, process, release = self.start('cancel-during-ack')
            try:
                self.assertTrue(waiting.wait(3), 'native borrower did not reach its captured ACK boundary')
                os.close(release); self.releases.remove(release)
                self.assertNotEqual(process.wait(timeout=3), 0)
                self.assertFalse((CAP.ROOT/'fixture-native-adopted').exists())
            finally:
                acknowledge.set()
            self.finish(broker, process, success=False)
        self.assertTrue(broker.drained)
        self.assertFalse(broker.mutation_possible)

    def installed_boundary(self, mode):
        directory = CAP.ROOT/'bin'; directory.mkdir(mode=0o700)
        wrapper = directory/'python3'
        wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(sys.executable)+' -BEsS '+
                           shlex.quote(str(Path(__file__).resolve()))+' --installed-child "$@"\n')
        wrapper.chmod(0o700)
        (CAP.ROOT/'fixture-mode').write_text(mode)
        (CAP.ROOT/'fixture-helper').write_text(str(HELPER))

    def test_installer_runner_joins_success_without_releasing_its_original_ex(self):
        self.installed_boundary('python-only')
        self.assertEqual(CAP.run_reassert(CAP.ROOT, self.original), {'joined': True, 'mutation_possible': False})
        self.assertEqual(list((CAP.ROOT/'run').iterdir()), [])
        self.blocked()

    def test_installer_runner_classifies_joined_pre_mutation_failure(self):
        self.installed_boundary('canceled')
        with self.assertRaises(RuntimeError) as caught:
            CAP.run_reassert(CAP.ROOT, self.original)
        self.assertNotIsInstance(caught.exception, CAP.RetainedAuthorityError)
        self.assertEqual(list((CAP.ROOT/'run').iterdir()), [])
        self.blocked()

    def test_installer_runner_retains_current_journal_after_mutation_failure(self):
        self.installed_boundary('mutation-fail')
        with self.assertRaises(CAP.RetainedAuthorityError):
            CAP.run_reassert(CAP.ROOT, self.original)
        self.assertEqual((CAP.ROOT/'fixture-current-journal').read_bytes(), b'new owned PF reference\n')
        self.blocked()

    def test_parent_wait_error_cannot_authorize_pre_mutation_rollback(self):
        self.installed_boundary('mutation-fail')
        original = CAP.subprocess.Popen

        def process(*arguments, **options):
            child = original(*arguments, **options)
            wait = child.wait

            def failed_wait(*arguments, **options):
                wait(*arguments, **options)
                raise OSError('deliberate parent failure after the real child joined')
            child.wait = failed_wait
            return child

        with mock.patch.object(CAP.subprocess, 'Popen', process):
            with self.assertRaises(CAP.RetainedAuthorityError):
                CAP.run_reassert(CAP.ROOT, self.original)
        self.assertEqual((CAP.ROOT/'fixture-current-journal').read_bytes(), b'new owned PF reference\n')
        self.blocked()

    def rejected_grant(self, phase, fault):
        original = CAP._send
        injected = []

        def send(channel, value, descriptors=()):
            temporary = None
            if value['phase'] == phase and value['operation'] == 'grant':
                injected.append(True)
                transferred = list(descriptors)
                if fault == 'foreign':
                    temporary = transferred[0] = os.open(CAP.LOCK, os.O_RDWR | os.O_CLOEXEC)
                elif fault == 'released':
                    fcntl.flock(transferred[0], fcntl.LOCK_UN)  # explicit negative only
                elif fault == 'shared':
                    fcntl.flock(transferred[0], fcntl.LOCK_SH)  # explicit negative only
                elif fault == 'replaced':
                    CAP.LOCK.unlink(); CAP.LOCK.write_bytes(b'foreign original inode\n'); CAP.LOCK.chmod(0o600)
                elif fault == 'stale':
                    value = {**value, 'generation': '0'*32}
                descriptors = tuple(transferred)
            if value['phase'] == phase and value['operation'] == 'ack' and fault == 'drop-before-ack':
                injected.append(True)
                raise RuntimeError('deliberate original issuer loss before acknowledgement')
            try:
                return original(channel, value, descriptors)
            finally:
                if temporary is not None:
                    os.close(temporary)

        with mock.patch.object(CAP, '_send', send):
            broker, process, _ = self.start()
            self.finish(broker, process, success=False)
        self.assertTrue(injected)
        self.assertFalse((CAP.ROOT/'fixture-native-adopted').exists(), 'invalid authority reached the native action')
        self.assertFalse(broker.mutation_possible)


for _phase in ('reassert', 'plan'):
    for _fault in ('foreign', 'released', 'shared', 'replaced', 'stale', 'drop-before-ack'):
        def rejected(self, phase=_phase, fault=_fault):
            self.rejected_grant(phase, fault)
        setattr(InstallerCapabilities, 'test_'+_phase+'_rejects_'+_fault.replace('-', '_'), rejected)


def main():
    global HELPER
    if len(sys.argv) > 1 and sys.argv[1] == '--installed-child':
        expected = [str(CAP.ROOT/'modes/kill-switch-platform.py'), 'reassert-install']
        if len(sys.argv) != 7 or sys.argv[2:4] != expected:
            raise RuntimeError('fixture replaced the fixed installer command')
        mode = (CAP.ROOT/'fixture-mode').read_text()
        helper = (CAP.ROOT/'fixture-helper').read_text()
        child([*sys.argv[4:7], mode, helper, '0'])
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == '--child':
        try:
            child(sys.argv[2:])
        except Exception as error:
            print('explicit capability fixture rejected: '+str(error), file=sys.stderr)
            return 1
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', required=True, type=Path)
    options = parser.parse_args()
    HELPER = options.helper.resolve(strict=True)
    owned_opt = None
    if sys.platform == 'darwin' and not CAP.ROOT.parent.exists():
        CAP.ROOT.parent.mkdir(mode=0o755)
        owned_opt = CAP.ROOT.parent.lstat()
    try:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(InstallerCapabilities))
    finally:
        if owned_opt is not None:
            if not os.path.samestat(owned_opt, CAP.ROOT.parent.lstat()):
                raise RuntimeError('fixture cannot remove another /opt generation')
            CAP.ROOT.parent.rmdir()
    if result.wasSuccessful():
        print('Actual installer Python/Go capability, original EX, borrower retirement and failure ownership passed.')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
