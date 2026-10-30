#!/usr/bin/env python3
"""Exercise the real private handoff without mutating a host PF namespace."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('owned_pf_baseline_test', Path(__file__).with_name('darwin_pf_baseline.py'))
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)


class BaselineTransition(unittest.TestCase):
    def setUp(self):
        self.current = {'present': False, 'rules_sha256': ''}
        self.saved, self.events = {}, []
        self.ambiguous = False
        self.capture = ('a'*32, 'b'*64)
        self.native = patch.object(B, '_invoke', side_effect=self.invoke)
        self.native.start()
        self.addCleanup(self.native.stop)
        self.references = {'417'}
        self.reference = patch.object(B, 'reference', side_effect=lambda value: B.token(value) in self.references)
        self.reference.start()
        self.addCleanup(self.reference.stop)

    def persist(self, value):
        self.events.append('persist')
        self.saved.update(copy.deepcopy(value))
        self.saved.setdefault('pf_token', '417')

    def invoke(self, phase, request):
        self.events.append(phase)
        if self.current not in request['expected']:
            raise RuntimeError('independently changed kernel owner')
        target = {'present': False, 'rules_sha256': ''}
        if request['action'] == 'replace':
            policy = (request['home_lan_access'], request['session_id'], request['source_sha256'])
            target = {'present': True, 'rules_sha256': hashlib.sha256(repr(policy).encode()).hexdigest()}
        result = {'schema': 1, 'request_sha256': hashlib.sha256(B._canonical(request)).hexdigest(),
                  'previous': copy.deepcopy(self.current), 'target': target, 'applied': phase == 'apply'}
        if phase == 'apply':
            self.assertIn(B.STATE_KEY, self.saved, 'native baseline mutation preceded its private pre-commit journal')
            retained = self.saved[B.STATE_KEY]
            self.assertFalse(retained['complete'])
            self.assertEqual(retained['previous'], self.current)
            self.assertEqual(retained['target'], target)
            self.current = copy.deepcopy(target)
            if self.ambiguous:
                raise RuntimeError('kernel committed but completion unknown')
        return result

    def apply(self, **options):
        result = B.transition(self.saved, action='replace', capture=self.capture, retain=self.persist, **options)
        self.saved.update(copy.deepcopy(result))
        return result

    def test_plan_and_exact_journal_precede_mutation(self):
        result = self.apply()
        self.assertEqual(self.events, ['plan', 'persist', 'apply'])
        self.assertEqual(result[B.STATE_KEY]['target'], self.current)
        self.assertTrue(result[B.STATE_KEY]['complete'])
        self.assertTrue(B.status(self.saved))

    def test_failed_persistence_never_admits_a_native_apply(self):
        def failed(value):
            self.events.append('failed-persist')
            raise OSError('private sync failed')
        with self.assertRaisesRegex(OSError, 'private sync'):
            B.transition({}, action='replace', capture=self.capture, retain=failed)
        self.assertEqual(self.events, ['plan', 'failed-persist'])
        self.assertFalse(self.current['present'])
        self.assertEqual(self.saved, {})

    def test_ambiguous_commit_retains_both_exact_outcomes_and_retries(self):
        self.ambiguous = True
        with self.assertRaisesRegex(RuntimeError, 'completion unknown'):
            self.apply()
        self.assertFalse(self.saved[B.STATE_KEY]['complete'])
        possible = B.retained(self.saved)
        self.assertEqual(possible, [{'present': False, 'rules_sha256': ''}, self.current])
        self.assertFalse(B.status(self.saved))
        self.ambiguous = False
        self.apply()
        self.assertEqual(B.retained(self.saved), [self.current])

    def test_changed_owner_does_not_replace_or_discard_a_pending_record(self):
        self.ambiguous = True
        with self.assertRaises(RuntimeError):
            self.apply()
        original = copy.deepcopy(self.saved)
        self.current = {'present': True, 'rules_sha256': 'f'*64}
        self.ambiguous = False
        with self.assertRaisesRegex(RuntimeError, 'changed kernel owner'):
            self.apply()
        self.assertEqual(self.saved, original)
        self.assertEqual(self.current['rules_sha256'], 'f'*64)

    def test_always_inactive_replaces_the_exact_active_owner_without_session_replay(self):
        self.apply()
        active = copy.deepcopy(self.current)
        result = B.transition(self.saved, action='replace', capture=None, retain=self.persist)
        self.saved.update(result)
        self.assertNotEqual(self.current, active)
        self.assertNotIn('a'*32, json.dumps(result))
        self.assertNotIn('b'*64, json.dumps(result))
        self.assertTrue(B.status(self.saved))

    def test_clear_requires_the_same_retained_native_owner(self):
        self.apply()
        old = copy.deepcopy(self.current)
        result = B.transition(self.saved, action='clear', retain=self.persist)
        self.saved.update(result)
        self.assertEqual(result[B.STATE_KEY]['previous'], old)
        self.assertEqual(B.retained(self.saved), [{'present': False, 'rules_sha256': ''}])
        self.assertFalse(B.status(self.saved))

    def test_missing_or_malformed_previous_receipt_never_reaches_native(self):
        for state in ({'native_socket_broker': True}, {'darwin_pf_anchor': 'com.apple/000.router-vpn'},
                      {B.STATE_KEY: {}}, {B.STATE_KEY: {'schema': True}}):
            with self.subTest(state=state), self.assertRaises(RuntimeError):
                B.transition(state, action='clear', retain=self.persist)
        self.assertEqual(self.events, [])

    def test_changed_native_reply_does_not_discard_pending_journal(self):
        actual = self.invoke
        def changed(phase, request):
            result = actual(phase, request)
            if phase == 'apply':
                result['target'] = {'present': True, 'rules_sha256': 'f'*64}
            return result
        with patch.object(B, '_invoke', side_effect=changed), self.assertRaisesRegex(RuntimeError, 'durably retained plan'):
            self.apply()
        self.assertFalse(self.saved[B.STATE_KEY]['complete'])
        self.assertEqual(self.saved[B.STATE_KEY]['target'], self.current)

    def test_reboot_recovery_requires_both_exact_reference_and_namespace_absence(self):
        self.apply()
        original = copy.deepcopy(self.saved)
        self.current = {'present': False, 'rules_sha256': ''}
        with self.assertRaisesRegex(RuntimeError, 'changed kernel owner'):
            self.apply()
        self.assertEqual(self.saved, original)
        self.references.clear()
        self.current = {'present': True, 'rules_sha256': 'e'*64}
        with self.assertRaisesRegex(RuntimeError, 'changed kernel owner'):
            self.apply()
        self.assertEqual(self.saved, original)
        self.current = {'present': False, 'rules_sha256': ''}
        self.apply()
        self.assertTrue(self.current['present'])
        self.assertEqual(self.saved[B.STATE_KEY]['previous'], {'present': False, 'rules_sha256': ''})

    def test_retained_rules_without_live_reference_are_not_enforced(self):
        self.apply()
        self.assertTrue(B.status(self.saved))
        self.references.clear()
        self.assertFalse(B.status(self.saved))


class BaselineRecordAndCommand(unittest.TestCase):
    def request(self):
        return B._request('replace', False, ('a'*32, 'b'*64), [{'present': False, 'rules_sha256': ''}])

    def response(self, request, apply=False):
        return {'schema': 1, 'request_sha256': hashlib.sha256(B._canonical(request)).hexdigest(),
                'previous': request['expected'][0], 'target': {'present': True, 'rules_sha256': 'c'*64}, 'applied': apply}

    def test_exact_native_record_shape_and_failure_controls(self):
        request = self.request()
        raw = B._canonical(request)
        self.assertEqual(raw, b'{"schema":1,"action":"replace","home_lan_access":false,"session_id":"'+b'a'*32+b'","source_sha256":"'+b'b'*64+b'","expected":[{"present":false,"rules_sha256":""}]}')
        response = self.response(request)
        self.assertEqual(B._result(B._canonical(response), request, False), response)
        for mutation in ({'schema': True}, {'applied': 0}, {'request_sha256': 'd'*64},
                         {'previous': {'present': True, 'rules_sha256': 'e'*64}},
                         {'target': {'present': False, 'rules_sha256': ''}}, {'extra': True}):
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                B._result(B._canonical({**response, **mutation}), request, False)
        duplicated = B._canonical(response).replace(b'"schema":1', b'"schema":1,"schema":1')
        for invalid in (duplicated, b'{}', b'null', b'x'*(B.LIMIT+1)):
            with self.assertRaises(RuntimeError):
                B._result(invalid, request, False)

    def test_fixed_native_executable_and_sanitized_environment(self):
        request = self.request()
        reply = subprocess.CompletedProcess([], 0, B._canonical(self.response(request)), b'')
        with patch.object(B.os, 'getuid', return_value=0), patch.object(B.os, 'geteuid', return_value=0), \
             patch.dict(os.environ, {'HOMEVPN_ROOT': str(B.ROOT), 'PATH': '/tmp/foreign-bin', 'DYLD_INSERT_LIBRARIES': '/tmp/foreign.dylib'}), \
             patch.object(B.subprocess, 'run', return_value=reply) as call:
            B._invoke('plan', request)
        arguments, options = call.call_args
        self.assertEqual(arguments[0], ['/opt/router-vpn-client/router-vpn-client', '--darwin-owned-pf', 'plan'])
        self.assertEqual(options['input'], B._canonical(request))
        self.assertEqual(options['cwd'], '/')
        self.assertEqual(options['env'], {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/var/root', 'LC_ALL': 'C'})
        self.assertNotIn('shell', options)

    def test_foreign_root_nonroot_and_native_failure_never_substitute_commands(self):
        request = self.request()
        for uid, root in ((501, str(B.ROOT)), (0, '/tmp/foreign')):
            with patch.object(B.os, 'getuid', return_value=uid), patch.object(B.os, 'geteuid', return_value=uid), \
                 patch.dict(os.environ, {'HOMEVPN_ROOT': root}), patch.object(B.subprocess, 'run') as call:
                with self.assertRaises(RuntimeError):
                    B._invoke('apply', request)
                call.assert_not_called()
        with patch.object(B.os, 'getuid', return_value=0), patch.object(B.os, 'geteuid', return_value=0), \
             patch.dict(os.environ, {'HOMEVPN_ROOT': str(B.ROOT)}), \
             patch.object(B.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'unknown native completion')) as call:
            with self.assertRaisesRegex(RuntimeError, 'unknown native completion'):
                B._invoke('apply', request)
            self.assertEqual(call.call_count, 1)

    def test_reference_response_requires_exact_token_and_boolean_native_proof(self):
        for present in (True, False):
            response = {'schema': 1, 'token': '417', 'present': present}
            with patch.object(B, '_native', return_value=B._canonical(response)) as native:
                self.assertEqual(B.reference('417'), present)
                native.assert_called_once_with('reference', b'{"schema":1,"token":"417"}')
        for token in ('', '0', '01', '+1', '-1', '18446744073709551616', 417, None):
            with self.subTest(token=token), patch.object(B, '_native') as native, self.assertRaises(RuntimeError):
                B.reference(token)
            native.assert_not_called()
        for value in ({'schema': True, 'token': '417', 'present': False},
                      {'schema': 1, 'token': '418', 'present': False},
                      {'schema': 1, 'token': '417', 'present': 0},
                      {'schema': 1, 'token': '417', 'present': False, 'other': True}):
            with patch.object(B, '_native', return_value=B._canonical(value)), self.assertRaises(RuntimeError):
                B.reference('417')
        for raw in (b'{}', b'{"schema":1,"token":"417","present":true,"present":false}', b'x'*129):
            with patch.object(B, '_native', return_value=raw), self.assertRaises(RuntimeError):
                B.reference('417')


class BaselinePrivateJournal(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='darwin-pf-journal-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root/'run').mkdir(mode=0o700)
        self.path = self.root/'run/kill-switch.json'
        self.value = {'policy': 'always', B.STATE_KEY: {'captured': 'fixture'}}
        self.raw = (json.dumps(self.value, indent=2)+'\n').encode()
        self.path.write_bytes(self.raw)
        self.path.chmod(0o600)
        actual = B._owned_info
        uid, gid = os.getuid(), os.getgid()
        # These portable tests own only a temporary current-user tree. The
        # native installed fixture separately executes the real root predicate.
        def fixture_owner(info, *, directory=False):
            if info.st_uid != uid or info.st_gid != gid:
                return False
            scoped = types.SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink, st_uid=0, st_gid=0)
            return actual(scoped, directory=directory)
        replacement = patch.object(B, '_owned_info', side_effect=fixture_owner)
        replacement.start()
        self.addCleanup(replacement.stop)

    def test_exact_file_and_parent_sync_both_finish_before_return(self):
        sync = os.fsync
        observed = []
        def captured(fd):
            observed.append(stat.S_IFMT(os.fstat(fd).st_mode))
            sync(fd)
        with patch.object(B.os, 'fsync', side_effect=captured):
            B.sync_state(self.root, self.value)
        self.assertEqual(observed, [stat.S_IFREG, stat.S_IFDIR], 'native journal returned before both required durable syncs')
        self.assertEqual(self.path.read_bytes(), self.raw)

    def test_sync_failure_and_post_sync_replacement_remain_failures(self):
        sync = os.fsync
        for index in (0, 1):
            calls = []
            def fail(fd):
                calls.append(fd)
                if len(calls)-1 == index:
                    raise OSError('captured fsync failure')
                sync(fd)
            with self.subTest(index=index), patch.object(B.os, 'fsync', side_effect=fail), self.assertRaisesRegex(OSError, 'captured fsync'):
                B.sync_state(self.root, self.value)
            self.assertEqual(self.path.read_bytes(), self.raw)
        def replace(fd):
            sync(fd)
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                self.path.rename(self.path.with_suffix('.old'))
                self.path.write_bytes(self.raw)
                self.path.chmod(0o600)
        with patch.object(B.os, 'fsync', side_effect=replace), self.assertRaisesRegex(RuntimeError, 'changed during'):
            B.sync_state(self.root, self.value)

    def test_modified_linked_or_public_journal_is_not_a_private_commit(self):
        self.path.write_text('{}\n')
        with self.assertRaisesRegex(RuntimeError, 'changed before'):
            B.sync_state(self.root, self.value)
        self.path.write_bytes(self.raw)
        self.path.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, 'bounded private'):
            B.sync_state(self.root, self.value)
        self.path.chmod(0o600)
        hardlink = self.root/'second-link'
        os.link(self.path, hardlink)
        with self.assertRaisesRegex(RuntimeError, 'bounded private'):
            B.sync_state(self.root, self.value)
        hardlink.unlink()
        target = self.root/'target'
        self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            B.sync_state(self.root, self.value)

    def test_retained_private_lock_rejects_reentry_and_linked_replacement(self):
        path = self.root/'lock'
        held = B._lock(path, B.fcntl.LOCK_EX)
        try:
            with self.assertRaises(BlockingIOError):
                B._lock(path, B.fcntl.LOCK_EX)
        finally:
            os.close(held)
        held = B._lock(path, B.fcntl.LOCK_EX)
        os.close(held)
        alias = self.root/'linked-lock'
        os.link(path, alias)
        with self.assertRaisesRegex(RuntimeError, 'private identity'):
            B._lock(path, B.fcntl.LOCK_EX)
        alias.unlink()
        path.unlink()
        path.symlink_to(self.path)
        with self.assertRaises(OSError):
            B._lock(path, B.fcntl.LOCK_EX)


if __name__ == '__main__':
    unittest.main(verbosity=2)
