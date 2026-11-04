#!/usr/bin/env python3
"""Real process/flock witnesses; nft policy and protected networking are not exercised."""
import importlib.util
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name('kill-switch.py')
spec = importlib.util.spec_from_file_location('linux_mutation_test', SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class MutationLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'run').mkdir(mode=0o700)
        store = {'selected_id': 'node', 'profiles': [{'id': 'node', 'endpoint': '203.0.113.9',
                  'kill_switch_policy': 'always', 'home_lan_access': False}]}
        (self.root / 'routers.json').write_text(json.dumps(store))
        (self.root / 'routers.json').chmod(0o600)
        self.env = {**os.environ, 'HOMEVPN_ROOT': str(self.root), 'HOMEVPN_PROFILE_ID': 'node',
                    'HOMEVPN_KILLSWITCH_DRY_RUN': '1'}
        self.environment = mock.patch.dict(os.environ, self.env)
        self.environment.start()
        self.addCleanup(self.environment.stop)


    def standard_state(self, boot=None):
        namespace = os.stat('/proc/thread-self/ns/net')
        baseline = {str(handle): [{'accept': None}] for handle in range(10, 15)}
        digest = hashlib.sha256(json.dumps(baseline, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        creation = dict(namespace_device=namespace.st_dev, namespace_inode=namespace.st_ino, baseline=baseline,
                        creation_generation=3, session='a'*32, config_sha256='b'*64,
                        table='router_vpn_standard_'+'a'*32, table_handle=7, chain_handle=1, baseline_sha256=digest)
        return dict(policy='always', profile_id='node', policy_profile_id='node', endpoint='203.0.113.19',
                    endpoint_ips=['203.0.113.19'], home_lan_access=False, platform='linux', enforced=True,
                    linux_standard_owner=dict(schema=1, boot_id=boot or mod._standard_boot_id(), creation=creation))

    def save_standard_state(self, state):
        path = self.root / 'run/kill-switch.json'
        path.write_text(json.dumps(state)); path.chmod(0o600)
        return path

    def test_same_boot_standard_owner_blocks_every_generic_mutation(self):
        state = self.standard_state()
        path = self.save_standard_state(state)
        original = path.read_bytes()
        actions = [lambda: mod.apply(), lambda: mod.release(), lambda: mod.release(True), lambda: mod.reassert(),
                   lambda: mod.remove_table(), lambda: mod.remove_state(self.root),
                   lambda: mod.write_state(self.root, {'policy': 'always'})]
        for action in actions:
            with self.subTest(action=action), mock.patch.object(mod, 'run_nft', side_effect=AssertionError('native mutation must not start')):
                with self.assertRaisesRegex(RuntimeError, 'original live controller'):
                    action()
                self.assertEqual(path.read_bytes(), original)

    def test_cold_reassert_preserves_captured_direct_exit_after_native_absence(self):
        state = self.standard_state('00000000-0000-0000-0000-000000000001')
        self.save_standard_state(state)
        observed = subprocess.CompletedProcess([], 0, '{"nftables":[{"metainfo":{}}]}', '')
        with mock.patch.object(mod, 'run_nft', return_value=observed) as run:
            self.assertEqual(mod.reassert(), 0)
            run.assert_called_once_with(['-j', '-n', 'list', 'tables'])
        saved = mod.read_state(self.root)
        self.assertEqual(saved['endpoint'], '203.0.113.19')
        self.assertEqual(saved['policy'], 'always')
        self.assertNotIn('linux_standard_owner', saved)

    def test_service_legacy_dispatch_rejects_standard_marker_appearing_before_child_lease(self):
        path = self.save_standard_state(self.standard_state('00000000-0000-0000-0000-000000000001'))
        original = path.read_bytes()
        with mock.patch.dict(os.environ, {'HOMEVPN_LEGACY_BOOT_ONLY': '1'}), mock.patch.object(mod, 'run_nft', side_effect=AssertionError('native mutation must not start')):
            with self.assertRaisesRegex(RuntimeError, 'legacy boot dispatch cannot replace'):
                mod.reassert()
        self.assertEqual(path.read_bytes(), original)

    def test_service_legacy_dispatch_preserves_unmarked_existing_policy(self):
        with mock.patch.dict(os.environ, {'HOMEVPN_LEGACY_BOOT_ONLY': '1'}):
            self.assertEqual(mod.reassert(), 0)
        saved = mod.read_state(self.root)
        self.assertEqual(saved['policy'], 'always')
        self.assertEqual(saved['endpoint'], '203.0.113.9')
        self.assertNotIn('linux_standard_owner', saved)

    def test_cold_state_cannot_adopt_a_new_native_table(self):
        state = self.standard_state('00000000-0000-0000-0000-000000000001')
        path = self.save_standard_state(state); original = path.read_bytes()
        for name in (mod.TABLE, 'router_vpn_node_foreign', state['linux_standard_owner']['creation']['table']):
            observed = subprocess.CompletedProcess([], 0, json.dumps({'nftables': [{'metainfo': {}}, {'table': {'family': 'inet', 'name': name, 'handle': 9}}]}), '')
            with self.subTest(name=name), mock.patch.object(mod, 'run_nft', return_value=observed):
                with self.assertRaisesRegex(RuntimeError, 'another native table'):
                    mod.reassert()
                self.assertEqual(path.read_bytes(), original)

    def test_standard_status_requires_exact_original_handle_and_inventory(self):
        state = self.standard_state(); self.save_standard_state(state)
        c = state['linux_standard_owner']['creation']
        rows = [{'metainfo': {}}, {'table': {'family': 'inet', 'name': c['table'], 'handle': c['table_handle']}},
                {'chain': {'family': 'inet', 'table': c['table'], 'name': 'output', 'handle': c['chain_handle'],
                           'type': 'filter', 'hook': 'output', 'prio': -310, 'policy': 'drop',
                           'comment': 'routervpn-owned-baseline:'+c['session']+':'+c['config_sha256']}}]
        rows += [{'rule': {'family': 'inet', 'table': c['table'], 'chain': 'output', 'handle': int(handle), 'expr': expr}} for handle, expr in c['baseline'].items()]
        def query(): return subprocess.CompletedProcess([], 0, json.dumps({'nftables': rows}), '')
        with mock.patch.object(mod, 'run_nft', side_effect=lambda *_, **__: query()):
            self.assertTrue(mod._standard_status_active(state))
            rows[1]['table']['handle'] += 1
            self.assertFalse(mod._standard_status_active(state))
            rows[1]['table']['handle'] -= 1
            rows[-1]['rule']['expr'] = [{'drop': None}]
            self.assertFalse(mod._standard_status_active(state))

    def test_force_off_refuses_scoped_tables_with_valid_empty_or_corrupt_state(self):
        path = self.root / 'run/kill-switch.json'
        for saved in (b'{"policy":"always"}', None, b'{broken'):
            for name in ('router_vpn_standard_'+'a'*32, 'router_vpn_node_'+'b'*32):
                with self.subTest(saved=saved, table=name):
                    if saved is None:
                        path.unlink(missing_ok=True)
                    else:
                        path.write_bytes(saved); path.chmod(0o600)
                    listing = {'nftables': [{'metainfo': {}}, {'table': {'family': 'inet', 'name': name, 'handle': 9}}]}
                    observed = subprocess.CompletedProcess([], 0, json.dumps(listing), '')
                    with mock.patch.object(mod, 'run_nft', return_value=observed) as query, \
                            mock.patch.object(mod, 'remove_table') as remove:
                        with self.assertRaisesRegex(RuntimeError, 'another native table'):
                            mod.release(True)
                        query.assert_called_once_with(['-j', '-n', 'list', 'tables'])
                        remove.assert_not_called()
                    self.assertEqual(path.read_bytes() if path.exists() else None, saved)

    def test_force_off_requires_native_absence_after_generic_removal(self):
        path = self.root / 'run/kill-switch.json'
        for saved in (b'{"policy":"always"}', None, b'{broken'):
            for remaining in (None, mod.TABLE, 'router_vpn_standard_'+'a'*32):
                with self.subTest(saved=saved, remaining=remaining):
                    if saved is None:
                        path.unlink(missing_ok=True)
                    else:
                        path.write_bytes(saved); path.chmod(0o600)
                    names = [mod.TABLE]
                    def listing(arguments, **kwargs):
                        self.assertEqual(arguments, ['-j', '-n', 'list', 'tables'])
                        rows = [{'metainfo': {}}] + [{'table': {'family': 'inet', 'name': name, 'handle': index+1}} for index, name in enumerate(names)]
                        return subprocess.CompletedProcess([], 0, json.dumps({'nftables': rows}), '')
                    def removal():
                        names[:] = [] if remaining is None else [remaining]
                    with mock.patch.object(mod, 'run_nft', side_effect=listing) as query, \
                            mock.patch.object(mod, 'remove_table', side_effect=removal) as remove:
                        if remaining is None:
                            self.assertEqual(mod.release(True), 0)
                            self.assertFalse(path.exists())
                        else:
                            with self.assertRaisesRegex(RuntimeError, 'another native table'):
                                mod.release(True)
                            self.assertEqual(path.read_bytes() if path.exists() else None, saved)
                        self.assertEqual(query.call_count, 2)
                        remove.assert_called_once_with()

    def test_force_off_never_substitutes_dry_run_or_failed_readback_for_absence(self):
        path = self.save_standard_state({'policy': 'always'})
        original = path.read_bytes()
        observations = [RuntimeError('native readback denied'), '{}', '{"nftables":[]}',
                        '{"nftables":[{"metainfo":{}},{"metainfo":{}}]}',
                        '{"nftables":[{"metainfo":{}},{"table":{"name":"other","family":"inet"}}]}']
        for observation in observations:
            with self.subTest(observation=observation), mock.patch.object(mod, 'remove_table') as remove:
                result = subprocess.CompletedProcess([], 0, observation, '') if isinstance(observation, str) else None
                with mock.patch.object(mod, 'run_nft', side_effect=observation if isinstance(observation, Exception) else None, return_value=result) as query:
                    with self.assertRaises((RuntimeError, ValueError)):
                        mod.release(True)
                    self.assertEqual(query.call_count, 1)
                    remove.assert_not_called()
                self.assertEqual(path.read_bytes(), original)

    def test_force_off_darwin_keeps_its_existing_native_dispatch_boundary(self):
        with mock.patch.object(mod.sys, 'platform', 'darwin'), \
                mock.patch.object(mod, 'read_state', return_value={}), \
                mock.patch.object(mod, 'remove_table') as remove, \
                mock.patch.object(mod, 'run_nft', side_effect=AssertionError('Darwin cannot query Linux nft')):
            self.assertEqual(mod.release(True), 0)
            remove.assert_called_once_with()

    def test_every_cli_mutator_and_dispatcher_waits_for_same_inode(self):
        for script in (SCRIPT, SCRIPT.with_name('kill-switch-platform.py')):
            for action in ('apply', 'release', 'force-off', 'reassert'):
                with self.subTest(script=script.name, action=action):
                    env = dict(self.env)
                    if action == 'force-off':
                        # This lock test owns no native policy observer. A
                        # missing nft must fail after lock admission, even in
                        # dry-run; the scoped-readback cases above model it.
                        env['PATH'] = str(self.root / 'no-native-tools')
                    with mod.mutation_guard(self.root):
                        process = subprocess.Popen([sys.executable, str(script), action], env=env,
                                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        try:
                            with self.assertRaises(subprocess.TimeoutExpired):
                                process.communicate(timeout=0.15)
                        except BaseException:
                            process.kill()
                            process.communicate(timeout=2)
                            raise
                    out, err = process.communicate(timeout=3)
                    if action == 'force-off':
                        self.assertNotEqual(process.returncode, 0)
                        self.assertIn(b'nftables', err)
                    else:
                        self.assertEqual(process.returncode, 0, err.decode())

    def test_direct_mutators_cannot_bypass_existing_owner(self):
        code = '''import importlib.util, pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).parent))
s=importlib.util.spec_from_file_location('helper',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
m._MUTATION_ADMISSION_SECONDS=.08
root=pathlib.Path(sys.argv[3])
getattr(m,sys.argv[2])(['list','ruleset']) if sys.argv[2]=='run_nft' else getattr(m,sys.argv[2])(root, {'policy':'always'}) if sys.argv[2]=='write_state' else getattr(m,sys.argv[2])(root) if sys.argv[2]=='remove_state' else getattr(m,sys.argv[2])()
'''
        for action in ('apply', 'release', 'reassert', 'remove_table', 'write_state', 'remove_state', 'run_nft'):
            with self.subTest(action=action), mod.mutation_guard(self.root):
                result = subprocess.run([sys.executable, '-c', code, str(SCRIPT), action, str(self.root)],
                                        env=self.env, capture_output=True, timeout=2)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'still owned by another operation', result.stderr)

    def test_nested_reassert_retains_original_descriptor(self):
        with mod.mutation_guard(self.root) as owner:
            with mod.mutation_guard(self.root) as nested:
                self.assertIs(owner, nested)
            self.assertEqual(mod.reassert(), 0)
            self.assertIs(mod._MUTATION_LOCAL.lease, owner)
        self.assertIsNone(mod._MUTATION_LOCAL.lease)

    def test_other_root_cannot_borrow_lease(self):
        with tempfile.TemporaryDirectory() as other, mod.mutation_guard(self.root):
            with self.assertRaisesRegex(RuntimeError, 'another root'):
                with mod.mutation_guard(Path(other)):
                    self.fail('foreign owner admitted')

    def test_replacement_lock_and_run_are_rejected_before_nested_mutation(self):
        for replacement in ('lock', 'run'):
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(RuntimeError, 'identity'):
                    with mod.mutation_guard(self.root):
                        if replacement == 'lock':
                            (self.root / 'run/kill-switch.lock').rename(self.root / 'run/old.lock')
                            (self.root / 'run/kill-switch.lock').touch(mode=0o600)
                        else:
                            (self.root / 'run').rename(self.root / 'old-run')
                            (self.root / 'run').mkdir(mode=0o700)
                        mod.write_state(self.root, {'policy': 'always'})
                self.assertFalse((self.root / 'run/kill-switch.json').exists())

    def test_poisoned_lock_refuses_symlink_hardlink_and_permissions(self):
        leaf = self.root / 'run/kill-switch.lock'
        target = self.root / 'target'
        target.touch(mode=0o600)
        for poison in ('symlink', 'hardlink', 'permissions'):
            with self.subTest(poison=poison):
                if poison == 'symlink':
                    leaf.symlink_to(target)
                elif poison == 'hardlink':
                    os.link(target, leaf)
                else:
                    leaf.touch(mode=0o644)
                    leaf.chmod(0o644)
                try:
                    with self.assertRaises((OSError, RuntimeError)):
                        with mod.mutation_guard(self.root):
                            self.fail('poisoned lock admitted')
                finally:
                    leaf.unlink()

    def test_child_inherits_lock_and_parent_close_does_not_unlock_it(self):
        with mod.mutation_guard(self.root) as lease:
            child = subprocess.Popen([sys.executable, '-c', 'import sys;sys.stdin.buffer.read(1)'],
                                     stdin=subprocess.PIPE, pass_fds=(lease.descriptor,))
        try:
            with mock.patch.object(mod, '_MUTATION_ADMISSION_SECONDS', 0.05):
                with self.assertRaisesRegex(RuntimeError, 'still owned'):
                    with mod.mutation_guard(self.root):
                        self.fail('live original child lost exclusion')
        finally:
            child.communicate(b'x', timeout=2)
        with mod.mutation_guard(self.root):
            pass

    def test_actual_nft_spawn_receives_original_lock_descriptor(self):
        with mod.mutation_guard(self.root) as lease, mock.patch.object(mod, 'nft_prefix', return_value=[sys.executable]):
            result = mod.run_nft(['-c', f'import os,fcntl;os.fstat({lease.descriptor});fcntl.flock({lease.descriptor},fcntl.LOCK_EX|fcntl.LOCK_NB);print("inherited")'])
            self.assertEqual(result.stdout.strip(), 'inherited')

    def test_sudo_requires_explicit_descriptor_preservation(self):
        with mod.mutation_guard(self.root) as lease, mock.patch.object(mod.os, 'geteuid', return_value=0):
            # Construct prefix as non-root without changing filesystem-owner
            # checks, which are independently exercised by the real lease.
            with mock.patch.object(lease, 'current'), mock.patch.object(mod.os, 'geteuid', return_value=1000), mock.patch.object(mod.shutil, 'which', side_effect=lambda name: '/usr/bin/' + name):
                self.assertEqual(mod.nft_prefix(), ['/usr/bin/sudo', '-n', '-C', str(lease.descriptor + 1), '/usr/bin/nft'])

    def test_denied_sudo_preservation_is_explicit_and_never_retried(self):
        denied = subprocess.CompletedProcess([], 1, '', 'sudo: you are not permitted to use the -C option')
        with mod.mutation_guard(self.root), mock.patch.object(mod, 'nft_prefix', return_value=['sudo', '-n', '-C', '9', 'nft']), mock.patch.object(mod.subprocess, 'run', return_value=denied) as run:
            with self.assertRaisesRegex(RuntimeError, 'closefrom_override'):
                mod.run_nft(['list', 'tables'], check=False)
            self.assertEqual(run.call_count, 1)

    def test_sudo_allows_ordinary_nft_missing_table_status(self):
        missing = subprocess.CompletedProcess([], 1, '', 'Error: No such file or directory\nlist table inet router_vpn_killswitch')
        with mod.mutation_guard(self.root), mock.patch.object(mod, 'nft_prefix', return_value=['sudo', '-n', '-C', '9', 'nft']), mock.patch.object(mod.subprocess, 'run', return_value=missing) as run:
            self.assertIs(mod.run_nft(['list', 'table', 'inet', mod.TABLE], check=False), missing)
            with self.assertRaisesRegex(RuntimeError, 'No such file'):
                mod.run_nft(['list', 'table', 'inet', mod.TABLE])
            self.assertEqual(run.call_count, 2)

    def test_shared_module_import_does_not_require_fcntl_on_windows(self):
        source = SCRIPT.read_text()
        code = "import builtins,sys,contextlib,functools,ipaddress,json,os,pathlib,re,shutil,stat,subprocess,tempfile,threading,time,typing;sys.path.insert(0,sys.argv[1]);import profile_id;original=builtins.__import__\n" + "def guarded(name,*args,**kwargs):\n if name=='fcntl': raise ModuleNotFoundError('fcntl unavailable')\n return original(name,*args,**kwargs)\n" + "builtins.__import__=guarded;sys.platform='win32';exec(compile(sys.stdin.read(),'kill-switch.py','exec'),{'__name__':'portable_test'})"
        subprocess.run([sys.executable, '-c', code, str(SCRIPT.parent)], input=source, text=True, check=True, timeout=5)

    def test_apply_and_release_cannot_split_kernel_and_saved_state(self):
        # The real public helper actions and their actual subprocess boundary
        # execute concurrently. Only nft is a controlled policy model. Pause
        # after kernel mutation, before apply can write its state; previously
        # release could delete the table and apply then publish active state.
        store = json.loads((self.root / 'routers.json').read_text())
        store['profiles'][0]['kill_switch_policy'] = 'on-connect'
        (self.root / 'routers.json').write_text(json.dumps(store))
        mod.write_state(self.root, {'policy': 'on-connect', 'profile_id': 'node'})
        table = self.root / 'modeled-table'
        table.write_text('old')
        started, resume = self.root / 'applied', self.root / 'continue'
        os.mkfifo(resume, 0o600)
        fixture = self.root / 'modeled-nft.py'
        fixture.write_text('''import pathlib,sys
root=pathlib.Path(sys.argv[1]);args=sys.argv[2:];table=root/'modeled-table'
if '-c' in args: sys.exit(0)
if args[:1]==['list']: sys.exit(0 if table.exists() else 1)
if args[:1]==['delete']: table.unlink();sys.exit(0)
assert args[:1]==['-f'],args
table.write_text('new')
''')
        code = '''import importlib.util,pathlib,sys
sys.path.insert(0,str(pathlib.Path(sys.argv[1]).parent))
s=importlib.util.spec_from_file_location('helper',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
m.nft_prefix=lambda:[sys.executable,sys.argv[3],sys.argv[4]]
original=m.write_state
def paused_write(*args,**kwargs):
 root=pathlib.Path(sys.argv[4]);(root/'applied').write_text('kernel committed')
 with (root/'continue').open('rb',buffering=0) as gate: assert gate.read(1)==b'x'
 return original(*args,**kwargs)
if sys.argv[2]=='apply': m.write_state=paused_write
raise SystemExit(m.apply() if sys.argv[2]=='apply' else m.release())
'''
        env = {key: value for key, value in self.env.items() if key != 'HOMEVPN_KILLSWITCH_DRY_RUN'}
        apply = subprocess.Popen([sys.executable, '-c', code, str(SCRIPT), 'apply', str(fixture), str(self.root)],
                                 env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        release = None
        try:
            deadline = time.monotonic() + 3
            while not started.exists():
                if apply.poll() is not None or time.monotonic() >= deadline:
                    self.fail('apply never reached its actual nft subprocess boundary')
                time.sleep(.01)
            release = subprocess.Popen([sys.executable, '-c', code, str(SCRIPT), 'release', str(fixture), str(self.root)],
                                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with self.assertRaises(subprocess.TimeoutExpired):
                release.communicate(timeout=.2)
            self.assertEqual(table.read_text(), 'new')
            with resume.open('wb', buffering=0) as gate:
                gate.write(b'x')
            _, apply_error = apply.communicate(timeout=3)
            _, release_error = release.communicate(timeout=3)
            self.assertEqual(apply.returncode, 0, apply_error.decode())
            self.assertEqual(release.returncode, 0, release_error.decode())
            self.assertFalse(table.exists())
            self.assertFalse((self.root / 'run/kill-switch.json').exists())
        finally:
            # Unblock the controlled state-adoption boundary after a mutant.
            try:
                fd = os.open(resume, os.O_WRONLY | os.O_NONBLOCK)
                try:
                    os.write(fd, b'x')
                finally:
                    os.close(fd)
            except OSError:
                pass
            for process in (apply, release):
                if process is not None:
                    if process.poll() is None:
                        process.kill()
                    process.communicate(timeout=3)

    def test_state_writer_uses_explicit_root_without_unrelated_environment_root(self):
        with mock.patch.dict(os.environ, {'HOMEVPN_ROOT': str(self.root / 'missing-root')}):
            mod.write_state(self.root, {'policy': 'always'})
            mod.remove_state(root=self.root)
        self.assertFalse((self.root / 'run/kill-switch.json').exists())


if __name__ == '__main__':
    unittest.main()
