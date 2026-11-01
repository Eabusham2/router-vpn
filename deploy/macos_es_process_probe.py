#!/usr/bin/env python3
"""Bounded, diagnostic-only Endpoint Security observation on actual macOS.

eslogger is Apple's already-entitled diagnostic, not an application API. Root
and an existing Full Disk Access approval are still required. This program
never changes those approvals and never supplies installer admission.

Apple documents PROC_CHECK/PIDINFO's target as es_process_t, whose executable
is the executed file. The public proc_pidpath_audittoken call checks the exact
PID/exec version before the MAC proc-info hook. See the source links in
docs/MACOS-INSTALLER-LIVE-IMAGE.md. Its ENOENT result is not absence.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('mac_es_inventory_probe', ROOT/'deploy/macos_process_inventory_probe.py')
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
PIDINFO = 2  # PROC_INFO_CALL_PIDINFO in the pinned Apple proc_info.h.
PIDPATH = 11  # PROC_PIDPATHINFO; also the proc_check flavor for the trigger.
STREAM_LIMIT = 4 * 1024 * 1024
RECORD_LIMIT = 256 * 1024


class Rejected(RuntimeError):
    pass


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise Rejected('malformed-native-integer')
    return value


def key(value):
    return (integer(value['pid'], 1, 2**31-1),
            integer(value['idversion'], 1, 2**31-1),
            integer(value['uniqueid'], 1, 2**64-1),
            integer(value['start_seconds'], 1, 2**63-1),
            integer(value['start_microseconds'], 0, 999999))


def capture(installer, library, pid):
    before = PROBE.identity(library, pid)
    state = PROBE.process_state(library, pid, installer.NativeProcessBSDInfo)
    after = PROBE.identity(library, pid)
    state_after = PROBE.process_state(library, pid, installer.NativeProcessBSDInfo)
    stable_fields = ('pid', 'start_seconds', 'start_microseconds')
    if (before != after or any(state.get(name) != state_after.get(name) for name in stable_fields) or
            'uniqueid' not in after or state.get('pid') != pid or
            not 1 <= state.get('status', 0) < 5 or not 1 <= state_after.get('status', 0) < 5):
        raise Rejected('native-process-changed-or-unavailable')
    result = {name: state[name] for name in ('pid', 'start_seconds', 'start_microseconds')}
    result.update(idversion=after['idversion'], uniqueid=after['uniqueid'])
    key(result)
    return result


def trigger(library, target):
    # Only these two token fields select the process. This is an exec fence,
    # not a fabricated credential; the ordinary caller permission checks run.
    original = key(target)
    token = (ctypes.c_uint32 * 8)()
    token[5], token[7] = original[:2]
    buffer = ctypes.create_string_buffer(4096)
    ctypes.set_errno(0)
    result = library.proc_pidpath_audittoken(ctypes.byref(token), buffer, len(buffer))
    error = ctypes.get_errno()
    if not 0 <= result < len(buffer):
        raise Rejected('invalid-pidpath-trigger-result')
    return {'result': result, 'errno': error}


def token_matches(value, expected):
    return (type(value) is dict and type(value.get('pid')) is int and
            type(value.get('pidversion')) is int and
            (value['pid'], value['pidversion']) == key(expected)[:2])


def event_record(message, instigator, target, earliest, latest):
    """Discard all unrelated events; keep no command lines or native paths."""
    if type(message) is not dict or type(message.get('process')) is not dict:
        return None
    if not token_matches(message['process'].get('audit_token'), instigator):
        return None
    event = message.get('event')
    event = event.get('proc_check') if type(event) is dict else None
    if type(event) is not dict:
        return None
    process = event.get('target')
    if type(process) is not dict or not token_matches(process.get('audit_token'), target):
        return None
    if not ((type(event.get('type')) is int and event['type'] == PIDINFO) or
            (type(event.get('type')) is str and event['type'] == 'ES_PROC_CHECK_TYPE_PIDINFO')):
        return None
    if type(event.get('flavor')) is not int or event['flavor'] != PIDPATH:
        return None
    integer(message.get('version'), 3, 2**32-1)
    emitted = integer(message.get('mach_time'), 1, 2**64-1)
    if not earliest <= emitted <= latest:
        # A delayed linked-image event is not the later unlinked observation.
        return None
    start = process.get('start_time')
    if (type(start) is not dict or type(start.get('tv_sec')) is not int or type(start.get('tv_usec')) is not int or
            (start['tv_sec'], start['tv_usec']) != key(target)[3:]):
        raise Rejected('event-target-start-does-not-match')
    source_start = message['process'].get('start_time')
    if (type(source_start) is not dict or type(source_start.get('tv_sec')) is not int or
            type(source_start.get('tv_usec')) is not int or
            (source_start['tv_sec'], source_start['tv_usec']) != key(instigator)[3:]):
        raise Rejected('event-instigator-start-does-not-match')
    executable = process.get('executable')
    metadata = executable.get('stat') if type(executable) is dict else None
    if type(metadata) is not dict:
        raise Rejected('event-designated-executable-stat-unavailable')
    widths = {'ino': 64, 'mode': 16, 'nlink': 16, 'uid': 32, 'gid': 32, 'size': 63}
    result = {name: integer(metadata.get('st_'+name), 0, 2**bits-1) for name, bits in widths.items()}
    result['dev'] = integer(metadata.get('st_dev'), -2**31, 2**32-1) & 0xffffffff
    if not result['ino'] or not stat.S_ISREG(result['mode']):
        raise Rejected('event-designated-executable-not-regular')
    return {'process': dict(target), 'executable_stat': result,
            'trigger': {'type': PIDINFO, 'flavor': PIDPATH}, 'admission_authority': False}


class EventStream:
    def __init__(self, process):
        self.process, self.buffer, self.stderr = process, b'', bytearray()
        self.total = self.records = 0
        self.selector = selectors.DefaultSelector()
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ)

    def read(self, timeout):
        messages = []
        for selected, _ in self.selector.select(timeout):
            chunk = os.read(selected.fileobj.fileno(), 65536)
            if not chunk:
                self.selector.unregister(selected.fileobj)
                continue
            self.total += len(chunk)
            if self.total > STREAM_LIMIT:
                raise Rejected('diagnostic-stream-bound-exceeded')
            if selected.fileobj is self.process.stderr:
                self.stderr.extend(chunk[:max(0, 4096-len(self.stderr))])
                continue
            self.buffer += chunk
            # eslogger emits JSONL. A complete record is necessary; a partial
            # final line cannot authorize any executable observation.
            while b'\n' in self.buffer:
                line, self.buffer = self.buffer.split(b'\n', 1)
                if not line.strip():
                    continue
                if len(line) > RECORD_LIMIT:
                    raise Rejected('diagnostic-record-bound-exceeded')
                self.records += 1
                if self.records > 2048:
                    raise Rejected('diagnostic-event-count-exceeded')
                try:
                    def unique_pairs(pairs):
                        result = {}
                        for name, value in pairs:
                            if name in result:
                                raise Rejected('duplicate-eslogger-json-key')
                            result[name] = value
                        return result
                    messages.append(json.loads(line, object_pairs_hook=unique_pairs))
                except (ValueError, UnicodeError) as error:
                    raise Rejected('unrecognized-eslogger-json-record') from error
            if len(self.buffer) > RECORD_LIMIT:
                raise Rejected('diagnostic-record-bound-exceeded')
        return messages

    def close(self):
        self.selector.close()
        self.process.stdout.close()
        self.process.stderr.close()


def join_owned(process):
    """Only this Popen's original child is signalled and actually waited."""
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def query(installer, library, stream, instigator, target, deadline, clock):
    last_trigger = None
    next_trigger, attempts = 0.0, 0
    earliest = integer(clock(), 1, 2**64-1)
    while time.monotonic() < deadline:
        if capture(installer, library, target['pid']) != target or capture(installer, library, os.getpid()) != instigator:
            raise Rejected('original-event-owner-changed-before-query')
        if attempts < 24 and time.monotonic() >= next_trigger:
            last_trigger = trigger(library, target)
            attempts += 1
            next_trigger = time.monotonic()+0.1
        for message in stream.read(min(0.05, max(0, deadline-time.monotonic()))):
            found = event_record(message, instigator, target, earliest, integer(clock(), earliest, 2**64-1))
            if found is not None:
                if (capture(installer, library, target['pid']) != target or
                        capture(installer, library, os.getpid()) != instigator):
                    raise Rejected('original-event-owner-changed-after-query')
                found['pidpath_call'] = last_trigger
                return found
        if stream.process.poll() is not None:
            # Retain the actual stderr below, including FDA/entitlement denial.
            raise Rejected('eslogger-exited-without-required-event')
    raise Rejected('no-matching-exec-bound-event-before-deadline')


def require_fixture(record, original, *, unlinked):
    observed = record['executable_stat']
    expected = {name: getattr(original, 'st_'+name) for name in ('ino', 'mode', 'uid', 'gid', 'size')}
    expected['dev'] = original.st_dev & 0xffffffff
    if any(observed[name] != value for name, value in expected.items()) or observed['nlink'] != (0 if unlinked else 1):
        raise Rejected('designated-executable-does-not-match-owned-original-file')


def run(baseline_path):
    report = {'schema': 1, 'diagnostic_only': True, 'admission_authority': False,
              'diagnostic_passed': False, 'status': 'not-started', 'observations': []}
    # Darwin's root-owned sticky temporary directory prevents another build
    # user from substituting this root-owned private parent after creation.
    work = Path(tempfile.mkdtemp(prefix='routervpn-es-diagnostic-',
                                dir='/private/tmp' if sys.platform == 'darwin' else None))
    logger = child = stream = None
    descriptor = None
    try:
        if sys.platform != 'darwin' or os.geteuid() != 0:
            raise Rejected('actual-root-macos-required')
        baseline = PROBE.load_baseline(baseline_path)
        if len(baseline['records']) != 1:
            raise Rejected('no-single-refused-pre-fixture-target')
        baseline_key = PROBE.comparison_identity(baseline['records'][0])
        spec = importlib.util.spec_from_file_location('mac_es_native_installer', ROOT/'client/install-macos-native.py')
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        library = installer.native_process_library()
        library.proc_pidpath_audittoken.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
        library.proc_pidpath_audittoken.restype = ctypes.c_int
        system = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        system.mach_absolute_time.argtypes = []
        system.mach_absolute_time.restype = ctypes.c_uint64
        clock = system.mach_absolute_time
        target = capture(installer, library, baseline_key[0])
        if (target['pid'], target['start_seconds'], target['start_microseconds'], target['uniqueid'], target['idversion']) != baseline_key[:5]:
            raise Rejected('pre-fixture-process-replaced-or-unknown')
        instigator = capture(installer, library, os.getpid())
        logger = subprocess.Popen(['/usr/bin/eslogger', 'proc_check'], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        stream = EventStream(logger)
        deadline = time.monotonic()+8
        image = work/'owned-sleep'
        shutil.copyfile('/bin/sleep', image)
        image.chmod(0o700)
        descriptor = os.open(image, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        original = os.fstat(descriptor)
        if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1 or original.st_uid != 0:
            raise Rejected('fixture-original-image-not-protected')
        child = subprocess.Popen([str(image), '30'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
        owned = capture(installer, library, child.pid)
        first = query(installer, library, stream, instigator, owned, min(deadline, time.monotonic()+3), clock)
        require_fixture(first, original, unlinked=False)
        report['observations'].append({'role': 'owned-linked', **first})
        image.unlink()
        if os.fstat(descriptor).st_nlink != 0 or child.poll() is not None:
            raise Rejected('fixture-original-unlinked-child-not-retained')
        second = query(installer, library, stream, instigator, owned, min(deadline, time.monotonic()+3), clock)
        require_fixture(second, original, unlinked=True)
        report['observations'].append({'role': 'owned-unlinked', **second})
        # Only the two real designated-vnode positive observations permit the
        # unrelated refused process query. Neither result permits installation.
        refused = query(installer, library, stream, instigator, target, deadline, clock)
        report['observations'].append({'role': 'pre-fixture-refused', **refused})
        report.update(diagnostic_passed=True, status='exec-bound-designated-file-observed')
    except Exception as error:
        report.update(status=str(error) if isinstance(error, Rejected) else type(error).__name__, diagnostic_passed=False)
    finally:
        for role, process in (('fixture', child), ('eslogger', logger)):
            if process is not None:
                try:
                    join_owned(process)
                except Exception as error:
                    report.update(diagnostic_passed=False, status='owned-child-join-failed')
                    report[role+'_join_error'] = type(error).__name__
        if stream is not None:
            try:
                stream.read(0)
            except Exception:
                pass
            try:
                stream.stderr.extend(os.read(logger.stderr.fileno(), max(0, 4096-len(stream.stderr))))
            except (BlockingIOError, OSError):
                pass
            report['eslogger_returncode'] = logger.returncode
            report['eslogger_records_observed'] = stream.records
            report['eslogger_stderr'] = ''.join(chr(byte) if 32 <= byte <= 126 or byte in (9, 10) else '?' for byte in stream.stderr)
            try:
                stream.close()
            except Exception as error:
                report.update(diagnostic_passed=False, status='owned-pipe-close-failed', close_error=type(error).__name__)
        elif logger is not None:
            for pipe in (logger.stdout, logger.stderr):
                if pipe is not None:
                    pipe.close()
        if descriptor is not None:
            os.close(descriptor)
        if child is None or child.returncode is not None:
            (work/'owned-sleep').unlink(missing_ok=True)
        # The private report contains reduced selected-event data only. Raw
        # unrelated ES events, command lines and executable paths are discarded.
        output = work/'result.json'
        report['probe_source_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        raw = (json.dumps(report, sort_keys=True)+'\n').encode()
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as file:
            file.write(raw)
        print('Endpoint Security diagnostic (no installation authority): '+raw.decode().strip(), flush=True)
        print('Private diagnostic report: '+str(output)+' sha256='+hashlib.sha256(raw).hexdigest(), flush=True)
    return 0 if report['diagnostic_passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        spec = importlib.util.spec_from_file_location('mac_es_elevation', ROOT/'deploy/test_desktop_socket_uid.py')
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        sudo = owner.privilege_tool()
        if sudo is None:
            raise Rejected('actual-root-diagnostic-required')
        return subprocess.run([sudo, '-n', '--', sys.executable, str(Path(__file__).resolve()),
                               '--baseline', str(arguments.baseline)]).returncode
    return run(arguments.baseline)


if __name__ == '__main__':
    raise SystemExit(main())
