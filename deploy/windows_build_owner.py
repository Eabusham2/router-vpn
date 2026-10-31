"""Run one build command inside its own retained Windows job.

The isolated bootstrap cannot start the requested command until its parent
assigns and reads back the original job. No PID/name inventory grants cleanup
authority. Nested child jobs remain inside this non-breakaway owner.
"""
import ctypes
import json
import os
import subprocess
import sys
import time

JOIN_SECONDS = 10.0
KILL_ON_CLOSE = 0x2000
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


class WindowsJob:
    def __init__(self):
        if os.name != "nt":
            raise RuntimeError("Windows build ownership requires the actual Windows host")
        api = self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        handle, pointer, dword, boolean = ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int
        declarations = {
            "CreateJobObjectW": ([pointer, ctypes.c_wchar_p], handle),
            "SetInformationJobObject": ([handle, ctypes.c_int, pointer, dword], boolean),
            "QueryInformationJobObject": ([handle, ctypes.c_int, pointer, dword, pointer], boolean),
            "GetHandleInformation": ([handle, pointer], boolean),
            "AssignProcessToJobObject": ([handle, handle], boolean),
            "IsProcessInJob": ([handle, handle, pointer], boolean),
            "TerminateJobObject": ([handle, dword], boolean),
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

    def terminate(self):
        self.checked(self.api.TerminateJobObject(self.handle, 125))

    def join(self, timeout=JOIN_SECONDS):
        deadline = time.monotonic() + timeout
        while self.active():
            if time.monotonic() >= deadline:
                raise RuntimeError("Windows build descendants did not leave their retained job")
            time.sleep(0.01)

    def close(self):
        if self.handle:
            handle, self.handle = self.handle, None
            self.checked(self.api.CloseHandle(handle))


def close_created_process(process):
    """Release the already joined original process, never an inventory result."""
    if process.returncode is None:
        raise RuntimeError("Cannot release an unjoined build bootstrap")
    process._handle.Close()


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
            stdout, stderr = process.communicate(timeout=JOIN_SECONDS)
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
                if assigned:
                    job.terminate()
                elif process.poll() is None:
                    # Only the original bootstrap exists before admission.
                    # Closing its input is never interpreted as permission.
                    process.kill()
                process.communicate(timeout=JOIN_SECONDS)
                close_created_process(process)
                job.join()
        finally:
            job.close()
