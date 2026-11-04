#!/usr/bin/env python3
"""Real process/flock witnesses; nft policy and protected networking are not exercised."""
import importlib.util
import json
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

    def test_every_cli_mutator_and_dispatcher_waits_for_same_inode(self):
        for script in (SCRIPT, SCRIPT.with_name('kill-switch-platform.py')):
            for action in ('apply', 'release', 'force-off', 'reassert'):
                with self.subTest(script=script.name, action=action):
                    with mod.mutation_guard(self.root):
                        process = subprocess.Popen([sys.executable, str(script), action], env=self.env,
                                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        try:
                            with self.assertRaises(subprocess.TimeoutExpired):
                                process.communicate(timeout=0.15)
                        except BaseException:
                            process.kill()
                            process.communicate(timeout=2)
                            raise
                    out, err = process.communicate(timeout=3)
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
