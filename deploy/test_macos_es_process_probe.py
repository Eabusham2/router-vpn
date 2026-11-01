#!/usr/bin/env python3
"""Diagnostic binding/pipe tests; these do not simulate native ES acceptance."""
from __future__ import annotations
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('mac_es_probe_test', Path(__file__).with_name('macos_es_process_probe.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
SOURCE = {'pid': 100, 'idversion': 201, 'uniqueid': 301, 'start_seconds': 401, 'start_microseconds': 501}
TARGET = {'pid': 101, 'idversion': 202, 'uniqueid': 302, 'start_seconds': 402, 'start_microseconds': 502}


def message():
    def process(identity):
        return {'audit_token': {'pid': identity['pid'], 'pidversion': identity['idversion']},
                'start_time': {'tv_sec': identity['start_seconds'], 'tv_usec': identity['start_microseconds']}}
    target = process(TARGET)
    target['executable'] = {'path': '/private/never-publish-this-path', 'stat': {
        'st_dev': 1, 'st_ino': 2, 'st_mode': stat.S_IFREG | 0o700, 'st_nlink': 0,
        'st_uid': 0, 'st_gid': 0, 'st_size': 99}}
    return {'version': 8, 'mach_time': 700, 'process': process(SOURCE),
            'event': {'proc_check': {'type': M.PIDINFO, 'flavor': M.PIDPATH, 'target': target}}}


class EventBinding(unittest.TestCase):
    def test_target_executable_is_reduced_without_path_or_other_event_data(self):
        event = message()
        event['private_unrelated_data'] = 'do-not-persist'
        result = M.event_record(event, SOURCE, TARGET, 600, 800)
        self.assertEqual(result['process'], TARGET)
        self.assertEqual(result['executable_stat']['ino'], 2)
        self.assertFalse(result['admission_authority'])
        self.assertNotIn('never-publish', json.dumps(result))
        self.assertNotIn('do-not-persist', json.dumps(result))

    def test_other_instigator_target_generation_flavor_or_delayed_phase_does_not_match(self):
        for role in ('process', 'target'):
            for field in ('pid', 'pidversion'):
                event = message()
                process = event['process'] if role == 'process' else event['event']['proc_check']['target']
                process['audit_token'][field] += 1
                self.assertIsNone(M.event_record(event, SOURCE, TARGET, 600, 800))
        for field, value in (('type', 2.0), ('type', True), ('type', 1), ('flavor', 17), ('flavor', True)):
            event = message(); event['event']['proc_check'][field] = value
            self.assertIsNone(M.event_record(event, SOURCE, TARGET, 600, 800))
        for emitted in (599, 801):
            event = message(); event['mach_time'] = emitted
            self.assertIsNone(M.event_record(event, SOURCE, TARGET, 600, 800))

    def test_start_or_unknown_message_schema_cannot_prove_same_execution(self):
        for role in ('process', 'target'):
            event = message()
            process = event['process'] if role == 'process' else event['event']['proc_check']['target']
            process['start_time']['tv_usec'] += 1
            with self.assertRaisesRegex(M.Rejected, 'start-does-not-match'):
                M.event_record(event, SOURCE, TARGET, 600, 800)
        for field, value in (('version', 2), ('mach_time', True), ('mach_time', 0)):
            event = message(); event[field] = value
            with self.assertRaises(M.Rejected): M.event_record(event, SOURCE, TARGET, 600, 800)

    def test_designated_file_metadata_is_required_and_wrong_original_fails(self):
        for field, value in (('st_ino', 0), ('st_mode', stat.S_IFDIR | 0o700), ('st_uid', True), ('st_nlink', -1)):
            event = message(); event['event']['proc_check']['target']['executable']['stat'][field] = value
            with self.assertRaises(M.Rejected): M.event_record(event, SOURCE, TARGET, 600, 800)
        event = message(); del event['event']['proc_check']['target']['executable']
        with self.assertRaisesRegex(M.Rejected, 'stat-unavailable'):
            M.event_record(event, SOURCE, TARGET, 600, 800)
        result = M.event_record(message(), SOURCE, TARGET, 600, 800)
        original = types.SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFREG|0o700,
                                         st_uid=0, st_gid=0, st_size=99)
        M.require_fixture(result, original, unlinked=True)
        with self.assertRaises(M.Rejected): M.require_fixture(result, original, unlinked=False)
        original.st_ino = 3
        with self.assertRaises(M.Rejected): M.require_fixture(result, original, unlinked=True)

    def test_trigger_supplies_only_exact_pid_and_exec_version_without_accepting_enoent(self):
        calls = []
        def call(pointer, buffer, size):
            calls.append((list(ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32*8)).contents), size))
            ctypes.set_errno(2)
            return 0
        result = M.trigger(types.SimpleNamespace(proc_pidpath_audittoken=call), TARGET)
        self.assertEqual(calls, [([0, 0, 0, 0, 0, 101, 0, 202], 4096)])
        self.assertEqual(result, {'result': 0, 'errno': 2})
        self.assertNotIn('absent', result)

    def test_native_capture_rejects_changed_exec_but_allows_live_scheduler_state_change(self):
        native = {'uniqueid': 302, 'idversion': 202}
        state = {'pid': 101, 'start_seconds': 402, 'start_microseconds': 502, 'status': 2}
        installer = types.SimpleNamespace(NativeProcessBSDInfo=object())
        with mock.patch.object(M.PROBE, 'identity', side_effect=[native, native]), \
             mock.patch.object(M.PROBE, 'process_state', side_effect=[state, {**state, 'status': 3}]):
            self.assertEqual(M.capture(installer, object(), 101), TARGET)
        with mock.patch.object(M.PROBE, 'identity', side_effect=[native, {**native, 'idversion': 203}]), \
             mock.patch.object(M.PROBE, 'process_state', return_value=state):
            with self.assertRaises(M.Rejected): M.capture(installer, object(), 101)

    def test_late_native_exec_change_rejects_matching_message(self):
        stream = types.SimpleNamespace(read=lambda timeout: [message()], process=types.SimpleNamespace(poll=lambda: None))
        with mock.patch.object(M, 'capture', side_effect=[TARGET, SOURCE, {**TARGET, 'idversion': 203}]), \
             mock.patch.object(M, 'trigger', return_value={'errno': 2, 'result': 0}):
            with self.assertRaisesRegex(M.Rejected, 'changed-after-query'):
                M.query(object(), object(), stream, SOURCE, TARGET, time.monotonic()+1, iter((600, 800)).__next__)


class OriginalPipeAndJoin(unittest.TestCase):
    def test_real_owned_pipe_preserves_fda_error_and_parses_only_complete_records(self):
        script = 'import os,time;os.write(2,b"Full Disk Access denied\\n");os.write(1,b\'{"version":8}\');time.sleep(.1);os.write(1,b"\\n")'
        child = subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stream = M.EventStream(child)
        try:
            records = []
            deadline = time.monotonic()+2
            while not records and time.monotonic() < deadline:
                records += stream.read(0.05)
            self.assertEqual(records, [{'version': 8}])
            self.assertIn(b'Full Disk Access denied', stream.stderr)
        finally:
            M.join_owned(child); stream.close()

    def test_duplicate_json_and_record_bound_are_actual_pipe_rejections(self):
        for body, reason in ((b'{"pid":1,"pid":2}\n', 'duplicate'), (b'{'*4096, 'bound')):
            child = subprocess.Popen([sys.executable, '-c', 'import os;os.write(1,'+repr(body)+')'],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stream = M.EventStream(child)
            try:
                with mock.patch.object(M, 'RECORD_LIMIT', 1024):
                    with self.assertRaisesRegex(M.Rejected, reason):
                        deadline = time.monotonic()+2
                        while time.monotonic() < deadline: stream.read(0.05)
            finally:
                M.join_owned(child); stream.close()

    def test_original_child_is_joined_without_signalling_unrelated_same_image(self):
        command = [sys.executable, '-c', 'import time;time.sleep(10)']
        owned, foreign = subprocess.Popen(command), subprocess.Popen(command)
        try:
            M.join_owned(owned)
            self.assertIsNotNone(owned.returncode)
            self.assertIsNone(foreign.poll())
        finally:
            M.join_owned(owned); M.join_owned(foreign)

    def test_timeout_kills_and_waits_original_child_with_bounded_waits(self):
        child = mock.Mock()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired('owned', 2), -9]
        M.join_owned(child)
        self.assertEqual(child.mock_calls, [mock.call.poll(), mock.call.terminate(),
                         mock.call.wait(timeout=2), mock.call.kill(), mock.call.wait(timeout=2)])

    def test_wrong_platform_is_nonpass_and_preserves_private_reduced_report(self):
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent)/'private'; output.mkdir(mode=0o700)
            with mock.patch.object(M.sys, 'platform', 'linux'), \
                 mock.patch.object(M.tempfile, 'mkdtemp', return_value=str(output)), \
                 mock.patch('builtins.print'):
                self.assertEqual(M.run(Path(parent)/'unused'), 1)
            report = json.loads((output/'result.json').read_text())
            self.assertFalse(report['diagnostic_passed'])
            self.assertFalse(report['admission_authority'])
            self.assertEqual(report['status'], 'actual-root-macos-required')
            self.assertEqual(stat.S_IMODE((output/'result.json').stat().st_mode), 0o600)


if __name__ == '__main__':
    unittest.main(verbosity=2)
