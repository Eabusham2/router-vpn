"""Run one build command inside its own retained Windows job.

The isolated bootstrap cannot start the requested command until its parent
assigns and reads back the original job. No PID/name inventory grants cleanup
authority. Nested child jobs remain inside this non-breakaway owner.
"""
import ctypes
import json
import math
import os
import subprocess
import sys
import time

JOIN_SECONDS = 10.0
KILL_ON_CLOSE = 0x2000
ACTIVE_PROCESS_LIMIT = 0x8
MAX_RETAINED_PROCESSES = 4096
MAX_REQUEST = 4 * 1024 * 1024

# -I -S prevents user/site startup code before the admission barrier. The
# bootstrap reads through EOF: no command starts while the parent still owns
# the write end without having verified job assignment.
BOOTSTRAP = r'''
import ctypes,json,os,subprocess,sys
try:
    raw = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("oversized build admission")
    request = json.loads(raw)
    if (not isinstance(request, dict) or set(request) != {"owner", "command"}
            or request["owner"] != "routervpn-build-job-v1"
            or not isinstance(request["command"], list) or not request["command"]
            or any(not isinstance(value, str) or "\0" in value for value in request["command"])
            or not request["command"][0]):
        raise ValueError("invalid build admission")
    result = subprocess.run(request["command"], stdin=subprocess.DEVNULL)
    status = result.returncode
except BaseException as error:
    # Do not echo argv or environment, which can include private build inputs.
    sys.stderr.write("Owned build bootstrap failed: " + type(error).__name__ + "\n")
    sys.stderr.flush()
    status = 125
if os.name == "nt":
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.ExitProcess.argtypes = [ctypes.c_uint32]
    kernel.ExitProcess.restype = None
    kernel.ExitProcess(status & 0xffffffff)
else:
    os._exit(status)
'''


class BasicLimits(ctypes.Structure):
    _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                ("flags", ctypes.c_uint32), ("minimum_working_set", ctypes.c_size_t),
                ("maximum_working_set", ctypes.c_size_t), ("active_limit", ctypes.c_uint32),
                ("affinity", ctypes.c_size_t), ("priority", ctypes.c_uint32),
                ("scheduling", ctypes.c_uint32)]


class ExtendedLimits(ctypes.Structure):
    _fields_ = [("basic", BasicLimits), ("io", ctypes.c_uint64 * 6),
                ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]


class Accounting(ctypes.Structure):
    _fields_ = [("times", ctypes.c_int64 * 4), ("page_faults", ctypes.c_uint32),
                ("total", ctypes.c_uint32), ("active", ctypes.c_uint32),
                ("terminated", ctypes.c_uint32)]


class ProcessListHeader(ctypes.Structure):
    _fields_ = [("assigned", ctypes.c_uint32), ("listed", ctypes.c_uint32)]


class WindowsJob:
    def __init__(self):
        if os.name != "nt":
            raise RuntimeError("Windows build ownership requires the actual Windows host")
        api = self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.member_handles = {}
        self.unverified_handles = set()
        self.retiring = False
        self.retirement_error = None
        self.join_deadline = None
        handle, pointer, dword, boolean = ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int
        declarations = {
            "CreateJobObjectW": ([pointer, ctypes.c_wchar_p], handle),
            "SetInformationJobObject": ([handle, ctypes.c_int, pointer, dword], boolean),
            "QueryInformationJobObject": ([handle, ctypes.c_int, pointer, dword, pointer], boolean),
            "GetHandleInformation": ([handle, pointer], boolean),
            "AssignProcessToJobObject": ([handle, handle], boolean),
            "IsProcessInJob": ([handle, handle, pointer], boolean),
            "TerminateJobObject": ([handle, dword], boolean),
            "OpenProcess": ([dword, boolean, dword], handle),
            "WaitForSingleObject": ([handle, dword], dword),
            "CloseHandle": ([handle], boolean),
        }
        for name, (arguments, result) in declarations.items():
            function = getattr(api, name)
            function.argtypes, function.restype = arguments, result
        self.handle = api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            limits = ExtendedLimits()
            limits.basic.flags = KILL_ON_CLOSE
            self.checked(api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
            actual = ExtendedLimits()
            returned = ctypes.c_uint32()
            self.checked(api.QueryInformationJobObject(self.handle, 9, ctypes.byref(actual), ctypes.sizeof(actual), ctypes.byref(returned)))
            flags = ctypes.c_uint32()
            self.checked(api.GetHandleInformation(self.handle, ctypes.byref(flags)))
            if returned.value != ctypes.sizeof(actual) or actual.basic.flags != KILL_ON_CLOSE or flags.value & 1:
                raise RuntimeError("Windows build job has unverified lifetime or inheritance limits")
        except BaseException:
            self.close()
            raise

    @staticmethod
    def checked(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def assign(self, process):
        # CPython's retained Popen handle refers to the created process; it is
        # not reopened using a potentially recycled PID.
        process_handle = int(process._handle)
        self.checked(self.api.AssignProcessToJobObject(self.handle, process_handle))
        assigned = ctypes.c_int()
        self.checked(self.api.IsProcessInJob(process_handle, self.handle, ctypes.byref(assigned)))
        if assigned.value != 1:
            raise RuntimeError("The original build bootstrap did not enter its retained job")

    def active(self):
        record, returned = Accounting(), ctypes.c_uint32()
        self.checked(self.api.QueryInformationJobObject(self.handle, 1, ctypes.byref(record), ctypes.sizeof(record), ctypes.byref(returned)))
        if returned.value != ctypes.sizeof(record):
            raise RuntimeError("Windows build job accounting is incomplete")
        return record.active

    def seal(self):
        # Retirement cannot admit another descendant while an original member
        # remains. Read back the original job, including the no-breakaway flag.
        # Native coverage exercises a creator inside a nested child job too.
        limits = ExtendedLimits()
        limits.basic.flags = KILL_ON_CLOSE | ACTIVE_PROCESS_LIMIT
        limits.basic.active_limit = 1
        self.checked(self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
        actual, returned = ExtendedLimits(), ctypes.c_uint32()
        self.checked(self.api.QueryInformationJobObject(self.handle, 9, ctypes.byref(actual), ctypes.sizeof(actual), ctypes.byref(returned)))
        if (returned.value != ctypes.sizeof(actual) or actual.basic.flags != limits.basic.flags or
                actual.basic.active_limit != 1):
            raise RuntimeError("Windows build retirement did not seal its original job")

    def members(self):
        # JobObjectBasicProcessIdList includes descendants in nested jobs. PIDs
        # are lookup hints only: membership on each retained handle is required.
        capacity = 64
        for _ in range(8):
            self.remaining()
            record = ctypes.create_string_buffer(ctypes.sizeof(ProcessListHeader) + capacity * ctypes.sizeof(ctypes.c_size_t))
            returned = ctypes.c_uint32()
            ok = self.api.QueryInformationJobObject(self.handle, 3, record, ctypes.sizeof(record), ctypes.byref(returned))
            error = ctypes.get_last_error() if not ok else 0
            if not ok and error != 234:  # Only ERROR_MORE_DATA permits another bounded query.
                raise ctypes.WinError(error)
            if not ok:
                # A failed call supplies no membership authority. In particular,
                # do not interpret a zero-initialized/partial header as empty.
                capacity *= 2
                if capacity > MAX_RETAINED_PROCESSES:
                    raise RuntimeError("Windows build job membership exceeded its captured bound")
                continue
            header_size = ctypes.sizeof(ProcessListHeader)
            if returned.value < header_size or returned.value > ctypes.sizeof(record):
                raise RuntimeError("Windows build job membership has an incomplete returned length")
            header = ProcessListHeader.from_buffer(record)
            if header.assigned > MAX_RETAINED_PROCESSES or header.listed > capacity or header.listed > header.assigned:
                raise RuntimeError("Windows build job membership is not bounded and complete")
            required = header_size + header.listed * ctypes.sizeof(ctypes.c_size_t)
            if returned.value < required:
                raise RuntimeError("Windows build job membership omitted returned process identities")
            if header.listed != header.assigned:
                capacity = max(capacity * 2, header.assigned)
                if capacity > MAX_RETAINED_PROCESSES:
                    raise RuntimeError("Windows build job membership exceeded its captured bound")
                continue
            values = (ctypes.c_size_t * header.listed).from_buffer(record, ctypes.sizeof(ProcessListHeader))
            members = set(values)
            if len(members) != header.listed or any(pid <= 0 or pid > 0xffffffff for pid in members):
                raise RuntimeError("Windows build job returned an invalid process snapshot")
            return members
        raise RuntimeError("Windows build job membership did not settle within its bounded snapshot")

    def capture_members(self):
        original = self.members()
        for pid in sorted(original):
            self.remaining()
            # Query plus synchronization only. No enumerated PID receives
            # PROCESS_TERMINATE, and no process-name scan grants authority.
            handle = self.api.OpenProcess(0x100000 | 0x1000, False, pid)
            if not handle:
                raise RuntimeError("Windows build lost a member before retaining its completion handle")
            self.unverified_handles.add(handle)
            try:
                assigned = ctypes.c_int()
                self.checked(self.api.IsProcessInJob(handle, self.handle, ctypes.byref(assigned)))
                if assigned.value != 1:
                    raise RuntimeError("Windows build process lookup no longer belongs to its original job")
                self.member_handles[pid] = handle
                self.unverified_handles.remove(handle)
            except BaseException:
                self.checked(self.api.CloseHandle(handle))
                self.unverified_handles.remove(handle)
                raise
        # Existing members may finish naturally; their original handles remain
        # waitable. An uncaptured/new member makes this retirement incomplete.
        if not self.members().issubset(original):
            raise RuntimeError("Windows build admitted an uncaptured process during retirement")

    def remaining(self):
        now = time.monotonic()
        if self.join_deadline is None or now >= self.join_deadline:
            raise RuntimeError("Windows build descendants exceeded their original join deadline")
        return self.join_deadline - now

    def terminate(self):
        if not self.retiring:
            self.retiring = True
            self.join_deadline = time.monotonic() + JOIN_SECONDS
            try:
                self.seal()
                self.capture_members()
            except BaseException as error:
                # Still terminate the original job. An incomplete capture must
                # subsequently fail join, even if active accounting reaches zero.
                self.retirement_error = error
        self.checked(self.api.TerminateJobObject(self.handle, 125))

    def join(self, timeout=JOIN_SECONDS):
        if not self.retiring:
            raise RuntimeError("Windows build retirement has no original process capture")
        self.join_deadline = min(self.join_deadline, time.monotonic() + timeout)
        self.remaining()
        for handle in self.member_handles.values():
            status = self.api.WaitForSingleObject(handle, max(1, math.ceil(self.remaining() * 1000)))
            if status != 0:  # WAIT_OBJECT_0 is the actual process completion witness.
                raise RuntimeError("Windows build original descendant did not signal completion")
        self.close_members()
        # Accounting is an additional check, not a replacement for waiting on
        # the actual process objects. TerminateJobObject is asynchronous.
        while self.active():
            time.sleep(min(0.01, self.remaining()))
        self.remaining()
        if self.retirement_error is not None:
            # Join every successfully retained member even after an incomplete
            # capture, but never turn those partial observations into success.
            raise RuntimeError("Windows build retirement has no complete original process capture") from self.retirement_error

    def close_members(self):
        failure = None
        for pid, handle in tuple(self.member_handles.items()):
            if self.api.CloseHandle(handle):
                del self.member_handles[pid]
            else:
                failure = ctypes.WinError(ctypes.get_last_error())
        # A failed membership/close check retains cleanup ownership only. These
        # handles never grant membership, wait, termination or success authority.
        for handle in tuple(self.unverified_handles):
            if self.api.CloseHandle(handle):
                self.unverified_handles.remove(handle)
            else:
                failure = ctypes.WinError(ctypes.get_last_error())
        if failure is not None:
            raise failure

    def close(self):
        try:
            if self.handle:
                self.checked(self.api.CloseHandle(self.handle))
                self.handle = None
        finally:
            self.close_members()


def close_created_process(process):
    """Release the already joined original process, never an inventory result."""
    if process.returncode is None:
        raise RuntimeError("Cannot release an unjoined build bootstrap")
    process._handle.Close()


def retire_created_process(job, process, *, unadmitted):
    """Finish original owners even when admission or a cleanup operation fails."""
    failures = []
    try:
        # Assignment can have entered the native job before its readback fails.
        # Capture that original membership before terminating the bootstrap.
        job.terminate()
    except BaseException as error:
        failures.append(error)
    try:
        if unadmitted and process.poll() is None:
            # This is the original retained Popen handle, never a reopened PID.
            # Still stop it if original-job termination itself failed.
            process.kill()
    except BaseException as error:
        failures.append(error)
    try:
        process.communicate(timeout=job.remaining())
        close_created_process(process)
    except BaseException as error:
        failures.append(error)
    try:
        job.join()
    except BaseException as error:
        failures.append(error)
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup("Windows build cleanup could not join its original owners", failures)


def run(command, *, cwd=None, env=None, timeout):
    """Return a CompletedProcess or the original-command subprocess exception."""
    arguments = [str(value) for value in command]
    if not arguments or not arguments[0] or any("\0" in value for value in arguments):
        raise ValueError("Invalid owned build command")
    if timeout <= 0:
        raise ValueError("Owned build command needs a positive deadline")
    request = json.dumps({"owner": "routervpn-build-job-v1", "command": arguments}).encode("utf-8")
    if len(request) > MAX_REQUEST:
        raise ValueError("Oversized owned build command")
    started = time.monotonic()
    job = WindowsJob()
    process, assigned, joined = None, False, False
    try:
        process = subprocess.Popen([sys.executable, "-I", "-S", "-c", BOOTSTRAP],
                                   cwd=cwd, env=env, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   close_fds=True)
        job.assign(process)
        assigned = True
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise subprocess.TimeoutExpired(arguments, timeout)
        try:
            stdout, stderr = process.communicate(input=request, timeout=remaining)
        except subprocess.TimeoutExpired as expired:
            job.terminate()
            # Terminating the retained job stops writers as well as the immediate
            # wrapper. communicate cannot wait forever on an orphaned pipe.
            stdout, stderr = process.communicate(timeout=job.remaining())
            close_created_process(process)
            job.join()
            joined = True
            raise subprocess.TimeoutExpired(arguments, timeout, output=stdout, stderr=stderr) from expired
        close_created_process(process)
        # Successful parent exit alone is insufficient. Clean up any retained
        # descendants before the caller removes its compiler/source workspace.
        job.terminate()
        job.join()
        joined = True
        result = subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)
        result.check_returncode()
        return result
    finally:
        try:
            if process is not None and not joined:
                retire_created_process(job, process, unadmitted=not assigned)
        finally:
            job.close()
