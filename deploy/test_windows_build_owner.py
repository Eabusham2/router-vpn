#!/usr/bin/env python3
"""Exercise command admission and actual Windows descendant retirement."""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('windows_build_owner_tested', ROOT / 'deploy/windows_build_owner.py')
OWNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OWNER)


def request(command):
    return json.dumps({'owner': 'routervpn-build-job-v1', 'command': command}).encode()


class BootstrapAdmission(unittest.TestCase):
    def bootstrap(self, raw, *, cwd=None, env=None):
        return subprocess.run([sys.executable, '-I', '-S', '-c', OWNER.BOOTSTRAP],
                              input=raw, cwd=cwd, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=15)

    def test_exact_command_keeps_bytes_arguments_environment_directory_and_exit(self):
        with tempfile.TemporaryDirectory(prefix='owned-build-arguments-') as temporary:
            command = [sys.executable, '-I', '-S', '-c',
                       'import json,os,sys; os.write(1,json.dumps([sys.argv[1:],os.getcwd(),os.environ["BUILD_OWNER_TEST"]]).encode()); os.write(2,b"native stderr\\xff"); sys.exit(7)',
                       'space value', 'quote"value', 'trailing\\', 'unicode-\u2603']
            result = self.bootstrap(request(command), cwd=temporary,
                                    env=dict(os.environ, BUILD_OWNER_TEST='captured'))
            self.assertEqual(result.returncode, 7)
            arguments, directory, environment = json.loads(result.stdout)
            self.assertEqual(arguments, command[5:])
            self.assertEqual(Path(directory).resolve(), Path(temporary).resolve())
            self.assertEqual(environment, 'captured')
            self.assertEqual(result.stderr, b'native stderr\xff')

    def test_invalid_or_incomplete_admission_never_executes_the_command(self):
        with tempfile.TemporaryDirectory(prefix='owned-build-admission-') as temporary:
            marker = Path(temporary) / 'executed'
            command = [sys.executable, '-I', '-S', '-c',
                       'from pathlib import Path; Path(__import__("sys").argv[1]).touch()', str(marker)]
            valid = {'owner': 'routervpn-build-job-v1', 'command': command}
            invalid = [b'', b'{', b'x' * (OWNER.MAX_REQUEST + 1), json.dumps(command).encode(),
                       json.dumps(dict(valid, owner='another-owner')).encode(),
                       json.dumps(dict(valid, extra=True)).encode(),
                       json.dumps(dict(valid, command=[])).encode(),
                       json.dumps(dict(valid, command=[123])).encode(),
                       json.dumps(dict(valid, command=['bad\0image'])).encode()]
            for raw in invalid:
                with self.subTest(length=len(raw)):
                    result = self.bootstrap(raw)
                    self.assertEqual(result.returncode, 125)
                    self.assertFalse(marker.exists(), 'Unadmitted command executed')
                    self.assertEqual(result.stdout, b'')
                    self.assertNotIn(str(marker).encode(), result.stderr)

    def test_isolated_bootstrap_does_not_import_ambient_startup_code(self):
        with tempfile.TemporaryDirectory(prefix='owned-build-site-') as temporary:
            root = Path(temporary)
            marker = root / 'site-imported'
            (root / 'sitecustomize.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
            result = self.bootstrap(request([sys.executable, '-I', '-S', '-c', 'print("admitted")']),
                                    cwd=root, env=dict(os.environ, PYTHONPATH=str(root)))
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'admitted\r\n' if os.name == 'nt' else b'admitted\n')
            self.assertFalse(marker.exists(), 'Ambient startup ran before job admission')

    def test_non_windows_host_cannot_claim_native_job_ownership(self):
        if os.name == 'nt':
            self.skipTest('Windows is the actual native host')
        with self.assertRaisesRegex(RuntimeError, 'actual Windows host'):
            OWNER.run([sys.executable, '-c', 'print("must not start")'], timeout=5)


TREE_CHILD = r'''
import ctypes,json,os,subprocess,sys,time
from pathlib import Path
root, depth, orphan = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3] == "orphan"
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.CreateFileW.argtypes = [ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p]
kernel.CreateFileW.restype = ctypes.c_void_p
kernel.CloseHandle.argtypes = [ctypes.c_void_p]
handle = kernel.CreateFileW(str(root/"workspace"/(str(depth)+".locked")), 0xc0000000, 0, None, 2, 0x80, None)
if handle in (None, ctypes.c_void_p(-1).value):
    raise ctypes.WinError(ctypes.get_last_error())
if depth < 2:
    child = subprocess.Popen([sys.executable,"-I","-S",__file__,str(root),str(depth+1),sys.argv[3]],
                             stdout=subprocess.DEVNULL if orphan else None,
                             stderr=subprocess.DEVNULL if orphan else None)
(root/(str(depth)+".ready")).write_text(json.dumps({"pid":os.getpid()}))
if depth == 0:
    until = time.monotonic()+20
    while not (root/"2.ready").exists():
        if time.monotonic()>=until: raise RuntimeError("grandchild did not start")
        time.sleep(0.01)
    os.write(1,b"all three original command descendants started\n")
    os.write(2,b"captured native phase before retirement\xff\n")
    if orphan:
        kernel.CloseHandle(handle)
        sys.exit(0)
time.sleep(120)
kernel.CloseHandle(handle)
'''


@unittest.skipUnless(os.name == 'nt', 'actual Windows job APIs required')
class NativeJobRetirement(unittest.TestCase):
    def test_success_failure_and_timeout_keep_original_subprocess_contract(self):
        for code in (0, 7):
            command = [sys.executable, '-I', '-S', '-c',
                       'import os,sys; os.write(1,b"native stdout\\xff"); os.write(2,b"native stderr\\xfe"); sys.exit(' + str(code) + ')']
            with self.subTest(code=code):
                if code:
                    with self.assertRaises(subprocess.CalledProcessError) as caught:
                        OWNER.run(command, timeout=15)
                    result = caught.exception
                else:
                    result = OWNER.run(command, timeout=15)
                self.assertEqual(result.args if not code else result.cmd, command)
                self.assertEqual(result.returncode, code)
                self.assertEqual(result.stdout, b'native stdout\xff')
                self.assertEqual(result.stderr, b'native stderr\xfe')

    def test_assignment_failure_before_or_after_native_assignment_never_admits(self):
        original = OWNER.WindowsJob.assign
        with tempfile.TemporaryDirectory(prefix='owned-build-denial-') as temporary:
            marker = Path(temporary) / 'unadmitted'
            command = [sys.executable, '-I', '-S', '-c',
                       'from pathlib import Path; Path(__import__("sys").argv[1]).touch()', str(marker)]
            for assigned in (False, True):
                with self.subTest(assigned=assigned):
                    def refused(job, process):
                        if assigned:
                            original(job, process)
                        raise RuntimeError('actual fixture admission refused')
                    with patch.object(OWNER.WindowsJob, 'assign', refused):
                        with self.assertRaisesRegex(RuntimeError, 'fixture admission refused'):
                            OWNER.run(command, timeout=15)
                    self.assertFalse(marker.exists(), 'Command started before complete native admission')

    def test_timeout_and_parent_exit_join_all_original_descendants(self):
        for mode in ('timeout', 'orphan'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='owned-build-tree-') as temporary:
                root = Path(temporary)
                workspace = root / 'workspace'
                workspace.mkdir()
                script = root / 'tree.py'
                script.write_text(TREE_CHILD)
                command = [sys.executable, '-I', '-S', str(script), str(root), '0', mode]
                # This same-image child belongs to the test, not the owned
                # build job. Cleanup must leave it running until we release it.
                foreign = subprocess.Popen([sys.executable, '-I', '-S', '-c',
                                            'import os,sys; os.write(1,b"foreign-ready\\n"); sys.stdin.buffer.read()'],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    self.assertEqual(foreign.stdout.readline(), b'foreign-ready\n')
                    if mode == 'timeout':
                        with self.assertRaises(subprocess.TimeoutExpired) as caught:
                            OWNER.run(command, timeout=25)
                        result = caught.exception
                        self.assertEqual(result.cmd, command)
                        self.assertEqual(result.timeout, 25)
                    else:
                        result = OWNER.run(command, timeout=25)
                        self.assertEqual(result.returncode, 0)
                    self.assertIn(b'all three original command descendants started', result.stdout)
                    self.assertIn(b'captured native phase before retirement\xff', result.stderr)
                    self.assertTrue(all((root / (str(depth) + '.ready')).exists() for depth in range(3)),
                                    'The native descendant fixture never started its whole tree')
                    # Every process held its own file with no sharing; these
                    # deletes fail while any original descendant remains live.
                    for path in workspace.iterdir():
                        path.unlink()
                    workspace.rmdir()
                    self.assertIsNone(foreign.poll(), 'Cleanup killed another same-image process')
                finally:
                    try:
                        foreign.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        foreign.kill()
                        foreign.communicate(timeout=10)


if __name__ == '__main__':
    unittest.main()
