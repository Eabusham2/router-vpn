#!/usr/bin/env python3
"""Prove timeout cleanup against an actual sudo child and retained pidfd.

The controlled child ignores ordinary termination and holds its output pipe.
Only the exact captured test process group is signalled. No account, mount,
interface, network route or firewall configuration is changed. Namespace
isolation itself remains the separate required guardian namespace fixture.
"""
from pathlib import Path
import hashlib
import importlib.util
import io
import json
import os
import platform
import select
import signal
import stat
import subprocess
import sys
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'deploy/test_desktop_socket_uid.py'
SPEC = importlib.util.spec_from_file_location('guardian_cleanup_uid', TARGET)
UID = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UID)


def system_sudo():
    path = Path('/usr/bin/sudo')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Guardian cleanup fixture requires the fixed protected system sudo')
    return str(path)


class GuardianTimeoutCleanup(unittest.TestCase):
    runner = staticmethod(UID.run)

    def test_real_privileged_child_and_pipe_join_on_timeout(self):
        sudo = system_sudo()
        program = (
            'import json,os,signal\n'
            'signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
            'signal.signal(signal.SIGHUP,signal.SIG_IGN)\n'
            "os.write(1,(json.dumps({'pid':os.getpid(),'group':os.getpgrp(),'session':os.getsid(0),'uid':os.geteuid()})+'\\nguardian timeout child reached its captured wait\\n').encode())\n"
            'while True:signal.pause()\n'
        )
        command = [sudo, '-n', '--', sys.executable, '-c', program]
        original_popen = subprocess.Popen
        owned = []
        child_fd = None

        def launch(arguments, **options):
            nonlocal child_fd
            process = original_popen(arguments, **options)
            if arguments == command:
                owned.append(process)
                # Start the tested timeout only after the real privileged
                # child is ready. A cold Python/sudo launch is not a cleanup
                # failure and does not create a scheduling-based assertion.
                deadline = time.monotonic() + 10
                line = bytearray()
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                        raise AssertionError('Actual privileged cleanup child did not become ready')
                    value = os.read(process.stdout.fileno(), 1)
                    if not value:
                        raise AssertionError('Actual privileged cleanup child exited before readiness')
                    line.extend(value)
                    if value != b'\n':
                        continue
                    # Some hosts emit a sudo audit warning before the child.
                    if line.startswith(b'{'):
                        actual = json.loads(line)
                        break
                    line.clear()
                self.assertEqual(actual['uid'], 0, 'cleanup did not execute its actual privileged child')
                self.assertEqual(actual['group'], process.pid, 'sudo child left the freshly owned process group')
                self.assertEqual(actual['session'], process.pid, 'sudo child left the freshly owned session')
                child_fd = os.pidfd_open(actual['pid'])
                self.assertFalse(select.select([child_fd], [], [], 0)[0], 'cleanup child was already dead before timeout')
            return process

        try:
            with mock.patch.object(UID.subprocess, 'Popen', new=launch):
                with self.assertRaisesRegex(RuntimeError, 'timed out after its process group was joined') as failure:
                    self.runner(command, cwd=ROOT, timeout=0.1, sudo=sudo)
            self.assertIn('guardian timeout child reached its captured wait', str(failure.exception),
                          'timeout cleanup discarded its actual progress output')
            self.assertEqual(len(owned), 1)
            self.assertIsNotNone(owned[0].poll(), 'timeout cleanup did not join its retained launcher')
            self.assertIsNotNone(child_fd, 'timeout proof lost its retained native child identity')
            self.assertTrue(select.select([child_fd], [], [], 5)[0], 'timeout cleanup left its actual privileged child alive')
        finally:
            # Deliberately broken cleanup must also leave no fixture behind.
            # The native child is retained by pidfd and never changes group.
            # Signal only while that exact child or its launcher remains live.
            for process in owned:
                live_child = child_fd is not None and not select.select([child_fd], [], [], 0)[0]
                if process.poll() is None or live_child:
                    cleanup = subprocess.run([sudo, '-n', '--', '/bin/kill', '-KILL', '--', '-'+str(process.pid)],
                                             capture_output=True, timeout=5)
                    if cleanup.returncode:
                        raise AssertionError('The independently retained test group could not retire: '+cleanup.stderr.decode())
                process.communicate(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()
            if child_fd is not None:
                if not select.select([child_fd], [], [], 5)[0]:
                    raise AssertionError('The exact privileged cleanup child did not retire')
                os.close(child_fd)


def check():
    if platform.system() != 'Linux' or not hasattr(os, 'pidfd_open'):
        raise ValueError('Guardian cleanup proof requires an actual Linux pidfd boundary')
    before = TARGET.read_bytes()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(GuardianTimeoutCleanup))
    if not result.wasSuccessful():
        raise AssertionError('Actual privileged guardian timeout cleanup failed')
    original = "'/bin/kill', '-KILL', '--', '-'+str(process.pid)"
    source = before.decode()
    if source.count(original) != 1:
        raise AssertionError('Guardian cleanup mutation lost its exact external kill boundary')
    module = types.ModuleType('guardian_cleanup_negative')
    module.__file__ = str(TARGET)
    exec(compile(source.replace(original, "'/bin/kill', '-KILL', '-'+str(process.pid)", 1), str(TARGET), 'exec'), module.__dict__)
    broken = type('BrokenGuardianCleanup', (GuardianTimeoutCleanup,), {'runner': staticmethod(module.run)})
    output = io.StringIO()
    result = unittest.TextTestRunner(stream=output).run(broken('test_real_privileged_child_and_pipe_join_on_timeout'))
    if (result.wasSuccessful() or result.errors or 'could not be joined' not in output.getvalue()
            or 'guardian timeout child reached its captured wait' not in output.getvalue()):
        raise AssertionError('Undelimited negative-PGID defect missed its actual live-child witness:\n'+output.getvalue())
    if TARGET.read_bytes() != before:
        raise AssertionError('Guardian timeout source changed during native verification')
    print('Guardian timeout cleanup: actual sudo child, output pipe and retained pidfd joined; rejected undelimited PGID defect. Source '+hashlib.sha256(before).hexdigest(), flush=True)


if __name__ == '__main__':
    check()
