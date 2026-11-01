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


class RejectionDiagnostics(unittest.TestCase):
    def test_each_original_rejection_keeps_its_exact_outcome_and_first_stage(self):
        def set_field(event, path, value):
            parts = path.split('.')
            for part in parts[:-1]:
                event = event[part]
            event[parts[-1]] = value
        cases = (
            ('process', None, 'message-process-schema', False),
            ('process.audit_token', 'private-token-value', 'instigator-token-schema', False),
            ('process.audit_token.pid', 987654321, 'instigator-other-pid', False),
            ('process.audit_token.pidversion', 999, 'instigator-other-exec-version', False),
            ('event.proc_check', None, 'proc-check-event-schema', False),
            ('event.proc_check.target', None, 'target-token-schema', False),
            ('event.proc_check.target.audit_token.pid', 987654321, 'target-other-pid', False),
            ('event.proc_check.target.audit_token.pidversion', 999, 'target-other-exec-version', False),
            ('event.proc_check.type', 99, 'check-type-not-pidinfo', False),
            ('event.proc_check.flavor', 99, 'check-flavor-not-pidpath', False),
            ('version', 2, 'message-version-invalid', True),
            ('mach_time', 0, 'event-mach-time-invalid', True),
            ('mach_time', 599, 'event-before-phase', False),
            ('mach_time', 801, 'event-after-observation', False),
            ('event.proc_check.target.start_time.tv_usec', 999, 'target-start-not-captured', True),
            ('process.start_time', 'private-time-value', 'instigator-start-not-captured', True),
            ('event.proc_check.target.executable.stat', None, 'designated-executable-stat-schema', True),
            ('event.proc_check.target.executable.stat.st_uid', True, 'designated-executable-stat-invalid', True),
            ('event.proc_check.target.executable.stat.st_ino', 0, 'designated-executable-not-regular', True),
        )
        for field, value, outcome, rejected in cases:
            with self.subTest(field=field, outcome=outcome):
                event, diagnostics = message(), M.EventDiagnostics('owned-linked')
                set_field(event, field, value)
                if rejected:
                    with self.assertRaises(M.Rejected) as original:
                        M.event_record(event, SOURCE, TARGET, 600, 800)
                    with self.assertRaises(M.Rejected) as observed:
                        M.event_record(event, SOURCE, TARGET, 600, 800, diagnostics)
                    self.assertEqual(str(original.exception), str(observed.exception))
                else:
                    self.assertIsNone(M.event_record(event, SOURCE, TARGET, 600, 800))
                    self.assertIsNone(M.event_record(event, SOURCE, TARGET, 600, 800, diagnostics))
                self.assertEqual(diagnostics.record['events_examined'], 1)
                self.assertEqual(diagnostics.record['outcomes'], {outcome: 1})

    def test_shapes_discard_unrelated_values_and_do_not_observe_selector_values_before_owners_match(self):
        event = message()
        event['private_unrelated_key'] = 'private-unrelated-value'
        event['process']['audit_token']['pid'] = 987654321
        event['process']['start_time'] = 'private-timestamp'
        event['event']['proc_check']['type'] = 'private-selector'
        diagnostic = M.EventDiagnostics('owned-linked')
        self.assertIsNone(M.event_record(event, SOURCE, TARGET, 600, 800, diagnostic))
        self.assertEqual(diagnostic.record['matching_token_selectors'], {})
        self.assertEqual(diagnostic.record['field_shapes']['process.start_time'], {'string': 1})
        self.assertEqual(diagnostic.record['field_shapes']['process.start_time.tv_sec'], {'missing': 1})
        self.assertEqual(set(diagnostic.record['field_shapes']), set(M.EventDiagnostics.FIELDS))
        encoded = json.dumps(diagnostic.record)
        for private in ('987654321', 'private-unrelated', 'private-timestamp', 'private-selector', 'never-publish'):
            self.assertNotIn(private, encoded)

    def test_matching_candidate_keeps_original_identity_and_bounded_nonprivate_selectors(self):
        diagnostic = M.EventDiagnostics('owned-unlinked')
        expected = M.event_record(message(), SOURCE, TARGET, 600, 800)
        self.assertEqual(M.event_record(message(), SOURCE, TARGET, 600, 800, diagnostic), expected)
        self.assertEqual(diagnostic.record['outcomes'], {'matched-exec-bound-candidate': 1})
        self.assertEqual(diagnostic.record['matching_token_selectors'], {'type': {'integer:2': 1}, 'flavor': {'integer:11': 1}})
        for value in range(256):
            event = message()
            event['event']['proc_check']['type'] = value
            M.event_record(event, SOURCE, TARGET, 600, 800, diagnostic)
        for value in ('private-arbitrary-selector', 2**100, True, None, {'private-key': 'private-value'}):
            event = message()
            event['event']['proc_check']['type'] = value
            M.event_record(event, SOURCE, TARGET, 600, 800, diagnostic)
        self.assertLessEqual(len(diagnostic.record['matching_token_selectors']['type']), 9)
        self.assertEqual(diagnostic.record['events_examined'], 262)
        self.assertNotIn('private', json.dumps(diagnostic.record))
        self.assertLess(len(json.dumps(diagnostic.record)), 8192)

    def test_query_timeout_retains_actual_trigger_result_and_filter_stage_without_becoming_a_pass(self):
        event = message()
        event['process']['audit_token']['pid'] += 1
        diagnostic = M.EventDiagnostics('owned-linked')
        stream = types.SimpleNamespace(read=lambda timeout: [event], process=types.SimpleNamespace(poll=lambda: None))
        with mock.patch.object(M, 'capture', side_effect=[TARGET, SOURCE]), \
             mock.patch.object(M, 'trigger', return_value={'errno': 2, 'result': 0}), \
             mock.patch.object(M.time, 'monotonic', side_effect=[0.0, 0.1, 0.1, 0.2, 2.0]):
            with self.assertRaisesRegex(M.Rejected, 'no-matching-exec-bound-event-before-deadline'):
                M.query(object(), object(), stream, SOURCE, TARGET, 1.0, iter((600, 800)).__next__, diagnostic)
        self.assertEqual(diagnostic.record['trigger_attempts'], 1)
        self.assertEqual(diagnostic.record['last_pidpath_call'], {'errno': 2, 'result': 0})
        self.assertEqual(diagnostic.record['outcomes'], {'instigator-other-pid': 1})
        self.assertEqual(diagnostic.record['events_examined'], 1)
        self.assertNotIn('observations', diagnostic.record)

    def test_matched_candidate_counter_cannot_replace_final_native_exec_fence(self):
        diagnostic = M.EventDiagnostics('owned-linked')
        stream = types.SimpleNamespace(read=lambda timeout: [message()], process=types.SimpleNamespace(poll=lambda: None))
        with mock.patch.object(M, 'capture', side_effect=[TARGET, SOURCE, {**TARGET, 'idversion': 203}]), \
             mock.patch.object(M, 'trigger', return_value={'errno': 2, 'result': 0}):
            with self.assertRaisesRegex(M.Rejected, 'changed-after-query'):
                M.query(object(), object(), stream, SOURCE, TARGET, time.monotonic()+1, iter((600, 800)).__next__, diagnostic)
        self.assertEqual(diagnostic.record['outcomes'], {'matched-exec-bound-candidate': 1})
        self.assertNotIn('diagnostic_passed', diagnostic.record)

    def test_only_fixed_query_roles_can_enter_the_report(self):
        for phase in ('owned-linked', 'owned-unlinked', 'pre-fixture-refused'):
            self.assertEqual(M.EventDiagnostics(phase).record['phase'], phase)
        for phase in ('private-path', '', 1, None):
            with self.assertRaisesRegex(M.Rejected, 'invalid-diagnostic-query-phase'):
                M.EventDiagnostics(phase)


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
