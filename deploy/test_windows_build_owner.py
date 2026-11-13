#!/usr/bin/env python3
"""Exercise command admission and actual Windows descendant retirement."""
from pathlib import Path
import ast
import ctypes
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
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


class RetirementAPI:
    """Deterministic ABI boundary, never evidence that Windows executed."""
    def __init__(self):
        self.events, self.snapshots = [], [{'members': [11, 22]}]
        self.lost, self.foreign, self.close_failures = set(), set(), {}
        self.wait_status, self.error, self.active_count = {}, 0, 0
        self.limits = OWNER.ExtendedLimits()
        self.seal_override = None

    def SetInformationJobObject(self, job, kind, record, size):
        self.events.append(('seal', job, kind))
        ctypes.memmove(ctypes.byref(self.limits), record, size)
        return 1

    def QueryInformationJobObject(self, job, kind, record, size, returned):
        length = ctypes.cast(returned, ctypes.POINTER(ctypes.c_uint32))
        if kind == 9:
            ctypes.memmove(record, ctypes.byref(self.limits), size)
            length.contents.value = size
            if self.seal_override is not None:
                self.seal_override(ctypes.cast(record, ctypes.POINTER(OWNER.ExtendedLimits)).contents, length)
        elif kind == 1:
            self.events.append(('account', self.active_count))
            ctypes.cast(record, ctypes.POINTER(OWNER.Accounting)).contents.active = self.active_count
            length.contents.value = size
        elif kind == 3:
            response = self.snapshots.pop(0) if len(self.snapshots) > 1 else self.snapshots[0]
            self.events.append(('members', size))
            values = response.get('members', [])
            header = ctypes.cast(record, ctypes.POINTER(OWNER.ProcessListHeader)).contents
            header.assigned = response.get('assigned', len(values))
            header.listed = response.get('listed', len(values))
            offset, width = ctypes.sizeof(header), ctypes.sizeof(ctypes.c_size_t)
            capacity = (size - offset) // width
            array = (ctypes.c_size_t * min(len(values), capacity)).from_buffer(record, offset)
            array[:] = values[:capacity]
            length.contents.value = response.get('returned', offset + len(values) * width)
            self.error = response.get('error', 0)
            return int(response.get('ok', not bool(self.error)))
        else:
            raise AssertionError('Unexpected modeled job information class')
        return 1

    def OpenProcess(self, access, inherited, pid):
        self.events.append(('open', access, inherited, pid))
        return None if pid in self.lost else 0x1000 + pid

    def IsProcessInJob(self, handle, job, assigned):
        self.events.append(('member', handle, job))
        ctypes.cast(assigned, ctypes.POINTER(ctypes.c_int)).contents.value = int(handle - 0x1000 not in self.foreign)
        return 1

    def TerminateJobObject(self, job, status):
        self.events.append(('terminate', job, status))
        return 1

    def WaitForSingleObject(self, handle, milliseconds):
        status = self.wait_status.get(handle, 0)
        self.events.append(('wait', handle, milliseconds, status))
        return status

    def CloseHandle(self, handle):
        failed = self.close_failures.get(handle, 0) > 0
        if failed:
            self.close_failures[handle] -= 1
            self.error = 5
        self.events.append(('close', handle, not failed))
        return int(not failed)


class JobRetirementProtocol(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.api = RetirementAPI()
        self.enterContext(patch.object(OWNER.time, 'monotonic', lambda: self.now))
        self.enterContext(patch.object(OWNER.ctypes, 'get_last_error', lambda: self.api.error, create=True))
        self.enterContext(patch.object(OWNER.ctypes, 'WinError', lambda code: OSError(code, 'modeled native error'), create=True))

    def job(self):
        job = OWNER.WindowsJob.__new__(OWNER.WindowsJob)
        job.api, job.handle = self.api, 0x7777
        job.member_handles, job.unverified_handles = {}, set()
        job.retiring, job.retirement_error = False, None
        job.bootstrap_pid = 11
        job.join_deadline = self.now + OWNER.JOIN_SECONDS
        return job

    def test_successful_snapshot_requires_every_returned_identity_byte(self):
        header, width = ctypes.sizeof(OWNER.ProcessListHeader), ctypes.sizeof(ctypes.c_size_t)
        invalid = [{'members': [], 'returned': 0}, {'members': [], 'returned': header - 1},
                   {'members': [11], 'returned': header + width - 1},
                   {'members': [11], 'returned': header + 64 * width + 1},
                   {'members': [0]}, {'members': [11, 11]}, {'members': [0x100000000]},
                   {'members': [11], 'listed': 65}, {'members': [11], 'assigned': 0},
                   {'members': [], 'assigned': OWNER.MAX_RETAINED_PROCESSES + 1}]
        for response in invalid:
            with self.subTest(response=response):
                self.api.snapshots = [response]
                with self.assertRaisesRegex(RuntimeError, 'membership|process snapshot'):
                    self.job().members()
        self.api.snapshots = [{'members': [], 'returned': header}]
        self.assertEqual(self.job().members(), set())
        self.api.snapshots = [{'members': [11, 22]}]
        self.assertEqual(self.job().members(), {11, 22})

    def test_incomplete_queries_grow_only_within_the_original_snapshot_bound(self):
        for error in (0, 5):
            self.api.snapshots = [{'ok': False, 'error': error, 'members': [11, 22]}]
            with self.assertRaises(OSError):
                self.job().members()
        self.api.events.clear()
        self.api.snapshots = [{'error': 234, 'returned': 0}, {'members': list(range(1, 66))}]
        self.assertEqual(self.job().members(), set(range(1, 66)))
        sizes = [event[1] for event in self.api.events if event[0] == 'members']
        self.assertEqual(sizes, [8 + 64 * ctypes.sizeof(ctypes.c_size_t), 8 + 128 * ctypes.sizeof(ctypes.c_size_t)])
        self.api.events.clear()
        self.api.snapshots = [{'error': 234, 'returned': 0}]
        with self.assertRaisesRegex(RuntimeError, 'captured bound'):
            self.job().members()
        self.assertEqual(len(self.api.events), 7)

    def test_actual_handle_waits_precede_release_and_zero_accounting(self):
        job = self.job()
        job.terminate()
        captured = dict(job.member_handles)
        self.assertEqual(set(captured), {11, 22})
        job.join()
        for pid, handle in captured.items():
            self.assertIn(('open', 0x101000, False, pid), self.api.events)
            member = self.api.events.index(('member', handle, job.handle))
            terminated = self.api.events.index(('terminate', job.handle, 125))
            waited = next(i for i, event in enumerate(self.api.events) if event[0] == 'wait' and event[1] == handle)
            closed = self.api.events.index(('close', handle, True))
            accounted = self.api.events.index(('account', 0))
            self.assertLess(member, terminated)
            self.assertLess(terminated, waited)
            self.assertLess(waited, closed)
            self.assertLess(closed, accounted)
        self.assertEqual(job.member_handles, {})
        job.close()
        self.assertEqual(self.api.events[-1], ('close', 0x7777, True))

    def test_zero_accounting_never_replaces_an_original_completion_signal(self):
        for status in (258, 0x80, 0xffffffff):
            with self.subTest(status=status):
                self.api = RetirementAPI()
                self.api.wait_status[0x1000 + 11] = status
                job = self.job()
                job.terminate()
                with self.assertRaisesRegex(RuntimeError, 'did not signal completion'):
                    job.join()
                self.assertFalse(any(event[0] == 'account' for event in self.api.events))
                self.assertEqual(set(job.member_handles), {11, 22})
                job.close()

    def test_missing_or_recycled_lookup_never_completes_but_still_terminates_original_job(self):
        for kind in ('missing', 'foreign', 'foreign-close-failure'):
            with self.subTest(kind=kind):
                self.api = RetirementAPI()
                if kind == 'missing':
                    self.api.lost.add(22)
                else:
                    self.api.foreign.add(22)
                    if kind == 'foreign-close-failure':
                        self.api.close_failures[0x1000 + 22] = 1
                job = self.job()
                job.terminate()
                self.assertIsNotNone(job.retirement_error)
                if kind == 'missing':
                    self.assertIn('role=descendant winerror=0 listed=2 retained=1', str(job.retirement_error))
                self.assertIn(('terminate', job.handle, 125), self.api.events)
                with self.assertRaisesRegex(RuntimeError, 'no complete original process capture'):
                    job.join()
                waits = [event[1] for event in self.api.events if event[0] == 'wait']
                self.assertEqual(waits, [0x1000 + 11])
                self.assertEqual(job.unverified_handles, set())
                if kind == 'foreign-close-failure':
                    self.assertEqual([event for event in self.api.events if event[:2] == ('close', 0x1000 + 22)],
                                     [('close', 0x1000 + 22, False), ('close', 0x1000 + 22, True)],
                                     'Failed membership discarded a still-owned observation handle')
                job.close()

    def test_changed_or_truncated_second_snapshot_remains_incomplete(self):
        for second in ({'members': [11, 22, 33]}, {'members': [], 'returned': 0}):
            with self.subTest(second=second):
                self.api = RetirementAPI()
                self.api.snapshots = [{'members': [11, 22]}, second]
                job = self.job()
                job.terminate()
                with self.assertRaisesRegex(RuntimeError, 'no complete original process capture'):
                    job.join()
                self.assertIn(('terminate', job.handle, 125), self.api.events)
                self.assertEqual(len([event for event in self.api.events if event[0] == 'wait']), 2)
                job.close()

    def test_seal_requires_exact_original_limits_readback(self):
        for field in ('flags', 'limit', 'length'):
            with self.subTest(field=field):
                self.api = RetirementAPI()
                def wrong(record, returned):
                    if field == 'flags': record.basic.flags |= 0x800
                    elif field == 'limit': record.basic.active_limit = 2
                    else: returned.contents.value -= 1
                self.api.seal_override = wrong
                job = self.job()
                job.terminate()
                with self.assertRaisesRegex(RuntimeError, 'no complete original process capture'):
                    job.join()
                self.assertFalse(any(event[0] == 'open' for event in self.api.events))
                self.assertIn(('terminate', job.handle, 125), self.api.events)
                job.close()

    def test_repeated_termination_and_join_cannot_refresh_the_ten_second_deadline(self):
        job = self.job()
        job.terminate()
        self.assertEqual(job.join_deadline, 110.0)
        self.now = 102.0
        job.terminate()
        job.join()
        self.assertEqual(job.join_deadline, 110.0)
        self.assertTrue(all(0 < event[2] <= 8000 for event in self.api.events if event[0] == 'wait'))
        self.now = 110.0
        with self.assertRaisesRegex(RuntimeError, 'original join deadline'):
            job.join()
        job.close()

    def test_failed_close_retains_original_cleanup_handles(self):
        job = self.job()
        job.terminate()
        self.api.close_failures[0x1000 + 11] = 1
        with self.assertRaises(OSError):
            job.join()
        self.assertEqual(job.member_handles, {11: 0x1000 + 11})
        self.api.close_failures[job.handle] = 1
        with self.assertRaises(OSError):
            job.close()
        self.assertEqual(job.handle, 0x7777)
        self.assertEqual(job.member_handles, {})
        job.close()
        self.assertIsNone(job.handle)

    def test_partial_assignment_cleanup_captures_job_first_even_if_termination_fails(self):
        for failure in (False, True):
            with self.subTest(termination_failure=failure):
                events = []
                class Handle:
                    def Close(inner): events.append('close-bootstrap')
                class Process:
                    returncode, _handle = None, Handle()
                    def poll(inner): return inner.returncode
                    def kill(inner): events.append('kill-original-bootstrap')
                    def communicate(inner, *, timeout):
                        self.assertEqual(timeout, 8.0)
                        events.append('join-bootstrap')
                        inner.returncode = 125
                        return b'', b''
                class Job:
                    def terminate(inner):
                        events.append('capture-and-terminate-original-job')
                        if failure: raise RuntimeError('original job termination failed')
                    def remaining(inner): return 8.0
                    def join(inner): events.append('join-original-job')
                if failure:
                    with self.assertRaisesRegex(RuntimeError, 'original job termination failed'):
                        OWNER.retire_created_process(Job(), Process(), unadmitted=True)
                else:
                    OWNER.retire_created_process(Job(), Process(), unadmitted=True)
                self.assertEqual(events, ['capture-and-terminate-original-job', 'kill-original-bootstrap',
                                          'join-bootstrap', 'join-original-job', 'close-bootstrap'])


class OriginalBootstrapLifetime(unittest.TestCase):
    """Exercise the public command/cleanup paths with a retained-handle witness."""
    def test_every_exit_keeps_the_created_object_through_original_job_retirement(self):
        for outcome in ('success', 'command-failure', 'timeout', 'unadmitted', 'join-failure'):
            with self.subTest(outcome=outcome):
                events = []
                state = {'joined_job': False, 'closed': False, 'communicated': 0}
                class Handle:
                    def Close(inner):
                        if not state['joined_job']:
                            raise AssertionError('original bootstrap released before job retirement')
                        state['closed'] = True
                        events.append('close-original-bootstrap')
                class Process:
                    returncode, pid, _handle = None, 17, Handle()
                    def communicate(inner, *, input=None, timeout):
                        state['communicated'] += 1
                        if outcome == 'timeout' and state['communicated'] == 1:
                            raise subprocess.TimeoutExpired(['original-bootstrap'], timeout)
                        events.append('join-original-bootstrap')
                        inner.returncode = 7 if outcome == 'command-failure' else 125 if outcome in ('timeout', 'unadmitted') else 0
                        return b'original stdout', b'original stderr'
                    def poll(inner): return inner.returncode
                    def kill(inner): events.append('kill-original-bootstrap')
                class Job:
                    def assign(inner, process):
                        events.append('assign-original-bootstrap')
                        if outcome == 'unadmitted':
                            raise RuntimeError('original assignment refused')
                    def terminate(inner):
                        if state['closed']:
                            raise AssertionError('original bootstrap released before job capture')
                        events.append('capture-and-terminate-original-job')
                    def remaining(inner): return 8.0
                    def join(inner):
                        if state['closed']:
                            raise AssertionError('original bootstrap released before job join')
                        state['joined_job'] = True
                        events.append('join-original-job')
                        if outcome == 'join-failure':
                            raise RuntimeError('original descendant did not join')
                    def close(inner): events.append('close-original-job')
                with patch.object(OWNER, 'WindowsJob', Job), patch.object(OWNER.subprocess, 'Popen', return_value=Process()):
                    if outcome == 'success':
                        result = OWNER.run(['captured-command'], timeout=15)
                        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'original stdout', b'original stderr'))
                    elif outcome == 'command-failure':
                        with self.assertRaises(subprocess.CalledProcessError) as caught:
                            OWNER.run(['captured-command'], timeout=15)
                        self.assertEqual((caught.exception.returncode, caught.exception.stdout, caught.exception.stderr),
                                         (7, b'original stdout', b'original stderr'))
                    elif outcome == 'timeout':
                        with self.assertRaises(subprocess.TimeoutExpired) as caught:
                            OWNER.run(['captured-command'], timeout=15)
                        self.assertEqual((caught.exception.cmd, caught.exception.timeout, caught.exception.stdout, caught.exception.stderr),
                                         (['captured-command'], 15, b'original stdout', b'original stderr'))
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'original assignment refused|original descendant did not join'):
                            OWNER.run(['captured-command'], timeout=15)
                self.assertTrue(state['closed'], 'Joined original bootstrap handle was not released')
                self.assertLess(events.index('join-original-job'), events.index('close-original-bootstrap'))
                self.assertEqual(events.count('close-original-bootstrap'), 1)
                self.assertEqual(events[-1], 'close-original-job')


TREE_CHILD = r'''
import ctypes,importlib.util,json,os,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode = True
root, depth, orphan = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3] == "orphan"
def publish(name, value):
    temporary = root/(name+".writing")
    temporary.write_text(json.dumps(value))
    os.replace(temporary, root/name)
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.CreateFileW.argtypes = [ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p]
kernel.CreateFileW.restype = ctypes.c_void_p
kernel.CloseHandle.argtypes = [ctypes.c_void_p]
handle = kernel.CreateFileW(str(root/"workspace"/(str(depth)+".locked")), 0xc0000000, 0, None, 2, 0x80, None)
if handle in (None, ctypes.c_void_p(-1).value):
    raise ctypes.WinError(ctypes.get_last_error())
nested = None
probe = [sys.executable,"-I","-S","-c","from pathlib import Path; import sys; Path(sys.argv[1]).write_text('executed')"]
if depth == 1:
    spec = importlib.util.spec_from_file_location("original_nested_build_owner", sys.argv[4])
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    nested = owner.WindowsJob()
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    original = kernel.GetCurrentProcess()
    nested.checked(nested.api.AssignProcessToJobObject(nested.handle, original))
    assigned = ctypes.c_int()
    nested.checked(nested.api.IsProcessInJob(original, nested.handle, ctypes.byref(assigned)))
    if assigned.value != 1: raise RuntimeError("nested creator lost its actual job")
    before = subprocess.run([*probe,str(root/"before-seal.executed")], timeout=10)
    if before.returncode != 0 or not (root/"before-seal.executed").is_file():
        raise RuntimeError("nested creator did not execute its actual positive child")
if depth < 2:
    child = subprocess.Popen([sys.executable,"-I","-S",__file__,str(root),str(depth+1),sys.argv[3],sys.argv[4]],
                             stdout=subprocess.DEVNULL if orphan else None,
                             stderr=subprocess.DEVNULL if orphan else None)
publish(str(depth)+".ready", {"pid":os.getpid(),"nested":nested is not None})
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
if depth == 1:
    until = time.monotonic()+120
    while not (root/"seal-request").exists():
        if time.monotonic()>=until: raise RuntimeError("original retirement seal was not requested")
        time.sleep(0.01)
    outcome = {"pid":os.getpid(),"nested":True,"created":False}
    try:
        unexpected = subprocess.Popen([*probe,str(root/"after-seal.executed")],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as error:
        outcome["winerror"] = error.winerror
    else:
        outcome["created"] = True
        try:
            unexpected.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            unexpected.kill()
            unexpected.communicate(timeout=2)
        outcome["returncode"] = unexpected.returncode
        unexpected._handle.Close()
    publish("seal-result", outcome)
time.sleep(120)
kernel.CloseHandle(handle)
'''



class IsolatedTreeBytecode(unittest.TestCase):
    def test_original_isolated_import_preserves_checkout_without_python_environment(self):
        # Execute the actual TREE_CHILD import statements without its Windows
        # API acquisition. Isolated Python intentionally ignores PYTHON* env.
        tree = ast.parse(TREE_CHILD)
        preamble = []
        imports = None
        for statement in tree.body:
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                preamble.append(statement)
            elif (isinstance(statement, ast.Assign) and
                  ast.unparse(statement.targets[0]) == "sys.dont_write_bytecode"):
                preamble.append(statement)
            elif (imports is None and isinstance(statement, ast.If) and
                  ast.unparse(statement.test) == "depth == 1"):
                imports = statement.body[:3]
        self.assertIsNotNone(imports)
        self.assertEqual([ast.unparse(item) for item in imports], [
            "spec = importlib.util.spec_from_file_location('original_nested_build_owner', sys.argv[4])",
            "owner = importlib.util.module_from_spec(spec)",
            "spec.loader.exec_module(owner)"])
        flag = [item for item in preamble if isinstance(item, ast.Assign)]
        self.assertEqual(len(flag), 1, "Original isolated child lost bytecode suppression")
        for omitted in (False, True):
            with self.subTest(omitted=omitted), tempfile.TemporaryDirectory(prefix="tree-bytecode-") as directory:
                root = Path(directory)
                original = root/"windows_build_owner.py"
                original.write_bytes((ROOT/"deploy/windows_build_owner.py").read_bytes())
                body = [item for item in preamble if not omitted or item is not flag[0]]
                program = ast.unparse(ast.Module(body=body + imports, type_ignores=[]))
                command = [sys.executable, "-I", "-S", "-c", program,
                           str(root), "1", "joined", str(original)]
                result = subprocess.run(command, cwd=root,
                    env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                bytecode = list(root.rglob("*.pyc"))
                if omitted:
                    self.assertEqual(len(bytecode), 1,
                                     "Isolated child omission did not reproduce ignored-environment bytecode")
                else:
                    self.assertEqual(bytecode, [],
                                     "Original isolated owner import changed the trusted checkout")


class NativeRetirementObservation:
    """Observe actual handle calls; every native result is returned unchanged."""
    def __init__(self, api, events):
        self.api, self.events = api, events

    def __getattr__(self, name):
        return getattr(self.api, name)

    def WaitForSingleObject(self, handle, milliseconds):
        result = self.api.WaitForSingleObject(handle, milliseconds)
        self.events.append(('wait', handle, milliseconds, result))
        return result

    def CloseHandle(self, handle):
        result = self.api.CloseHandle(handle)
        self.events.append(('close', handle, result))
        return result


@unittest.skipUnless(os.name == 'nt', 'actual Windows job APIs required')
class NativeJobRetirement(unittest.TestCase):
    def test_actual_completed_bootstrap_handle_survives_job_capture_and_join(self):
        testcase, witnessed = self, []
        class ObservedJob(OWNER.WindowsJob):
            def assign(job, process):
                super().assign(process)
                job.original = process
            def retain_original(job, phase):
                handle = int(job.original._handle)
                testcase.assertNotEqual(handle, 0, 'Original bootstrap handle released before native retirement')
                testcase.assertEqual(job.api.WaitForSingleObject(handle, 0), 0,
                                     'Actual completed bootstrap lost its original completion handle')
                witnessed.append(phase)
            def terminate(job):
                job.retain_original('capture')
                return super().terminate()
            def join(job, timeout=OWNER.JOIN_SECONDS):
                job.retain_original('before-join')
                result = super().join(timeout)
                job.retain_original('after-join')
                return result
        with patch.object(OWNER, 'WindowsJob', ObservedJob):
            result = OWNER.run([sys.executable, '-I', '-S', '-c', 'pass'], timeout=15)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(witnessed, ['capture', 'before-join', 'after-join'])

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
                command = [sys.executable, '-I', '-S', str(script), str(root), '0', mode,
                           str(ROOT/'deploy/windows_build_owner.py')]
                testcase, observed = self, []
                class ObservedJob(OWNER.WindowsJob):
                    def __init__(job):
                        super().__init__()
                        job.native_events = []
                        job.api = NativeRetirementObservation(job.api, job.native_events)
                        job.captured, job.seal_witness = {}, None
                        observed.append(job)

                    def seal(job):
                        super().seal()
                        (root/'seal-request').write_text('original job limit read back')
                        while not (root/'seal-result').exists():
                            time.sleep(min(0.01, job.remaining()))
                        witness = json.loads((root/'seal-result').read_text())
                        creator = json.loads((root/'1.ready').read_text())
                        testcase.assertTrue(creator['nested'])
                        testcase.assertEqual(witness['pid'], creator['pid'])
                        testcase.assertTrue(witness['nested'])
                        testcase.assertFalse(witness['created'], 'Sealed parent job admitted another nested child')
                        testcase.assertIn(witness.get('winerror'), (5, 1816),
                                          'Nested creation did not report a native access/quota denial')
                        testcase.assertTrue((root/'before-seal.executed').is_file())
                        testcase.assertFalse((root/'after-seal.executed').exists())
                        job.seal_witness = witness

                    def capture_members(job):
                        super().capture_members()
                        job.captured = dict(job.member_handles)
                        for depth in (1, 2):
                            pid = json.loads((root/(str(depth)+'.ready')).read_text())['pid']
                            testcase.assertIn(pid, job.captured,
                                              'Original job omitted a live nested descendant')
                            testcase.assertEqual(job.api.WaitForSingleObject(job.captured[pid], 0), 258,
                                                 'Expected original nested descendant was already signaled')
                # This same-image child belongs to the test, not the owned
                # build job. Cleanup must leave it running until we release it.
                foreign = subprocess.Popen([sys.executable, '-I', '-S', '-c',
                                            'import os,sys; os.write(1,b"foreign-ready\\n"); sys.stdin.buffer.read()'],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    self.assertEqual(foreign.stdout.readline(), b'foreign-ready\n')
                    with patch.object(OWNER, 'WindowsJob', ObservedJob):
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
                    self.assertEqual(len(observed), 1)
                    job = observed[0]
                    self.assertIsNotNone(job.seal_witness)
                    self.assertNotIn(foreign.pid, job.captured)
                    for pid, handle in job.captured.items():
                        signals = [i for i, event in enumerate(job.native_events)
                                   if event[0] == 'wait' and event[1] == handle and event[2] > 0 and event[3] == 0]
                        closes = [i for i, event in enumerate(job.native_events)
                                  if event[0] == 'close' and event[1] == handle and event[2]]
                        self.assertEqual(len(signals), 1, 'Original descendant lacked its actual completion signal')
                        self.assertEqual(len(closes), 1, 'Original descendant lacked its actual handle release')
                        self.assertLess(signals[0], closes[0], 'Original process handle closed before its completion signal')
                    # Every process held its own file with no sharing; these
                    # deletes fail while any original descendant remains live.
                    for path in workspace.iterdir():
                        path.unlink()
                    workspace.rmdir()
                    self.assertIsNone(foreign.poll(), 'Cleanup killed another same-image process')
                    print('Actual native nested build retirement: ' + json.dumps({
                        'mode': mode, 'retained_completion_handles': len(job.captured),
                        'nested_creation_denial': job.seal_witness,
                        'all_handles_signaled_before_release': True,
                        'immediate_unlink_passed': True, 'foreign_same_image_alive': True,
                    }, sort_keys=True), flush=True)
                finally:
                    try:
                        foreign.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        foreign.kill()
                        foreign.communicate(timeout=10)


if __name__ == '__main__':
    unittest.main()
