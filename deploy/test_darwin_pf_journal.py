#!/usr/bin/env python3
"""Execute the shipping PF journal and isolated, meaningful source defects.

Only the explicit temporary PF backend fixtures run here. No host kernel,
installed data, privilege change or real PF command is used by these tests.
Actual native reference/namespace/root-sync proof has its separate Mac gates.
"""
from pathlib import Path
import hashlib
import os
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ('modes/darwin_pf_baseline.py', 'modes/darwin_kill_switch.py',
         'modes/kill-switch-platform.py', 'modes/kill-switch.py', 'modes/profile_id.py',
         'modes/test_darwin_pf_baseline.py', 'modes/test_darwin_owned_pf.py',
         'deploy/test_desktop_tor_unix_wrapper.py', 'modes/native-tor-bridge.sh',
         'modes/cleanup-private-runtime.py', 'modes/select-standard-engine.sh',
         'modes/tor-prelaunch-witness.py')
MUTANTS = (
    ('native root journal owner', 'darwin_pf_baseline.py', 'info.st_uid == 0 and info.st_gid == 0 and ',
     '', 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_fixture_owner_preserves_native_metadata_and_root_only_admission',
     'portable ownership fixture weakened the production root predicate'),
    ('private pre-commit journal', 'darwin_pf_baseline.py', 'retain({STATE_KEY: receipt})',
     'pass  # omitted private pre-commit journal', 'test_darwin_pf_baseline.py',
     'BaselineTransition.test_plan_and_exact_journal_precede_mutation',
     'native baseline mutation preceded its private pre-commit journal'),
    ('durable parent sync', 'darwin_pf_baseline.py', 'os.fsync(parent)',
     'pass  # omitted parent sync', 'test_darwin_pf_baseline.py',
     'BaselinePrivateJournal.test_exact_file_and_parent_sync_both_finish_before_return',
     'native journal returned before both required durable syncs'),
    ('uncertain adopted journal ownership', 'darwin_kill_switch.py', 'and error.retained is False',
     'and True', 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_adopted_but_unsynced_journal_retains_reference_for_same_retry',
     'unsynced adopted journal lost its captured reference'),
    ('exact post-release absence', 'darwin_kill_switch.py', 'if _baseline.reference(value):',
     'if False and _baseline.reference(value):', 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_failed_reference_release_retains_exact_clear_receipt_until_same_retry',
     'native reference release discarded a still-present exact owner'),
    ('dead reference reuse', 'darwin_kill_switch.py', 'if not native or _baseline.reference(_baseline.token(old)):',
     'if True:', 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_reboot_reassert_proves_absence_then_acquires_a_new_exact_reference',
     'native reboot reused a dead PF reference'),
    ('complete state transaction', 'kill-switch-platform.py', 'with _darwin._baseline.state_guard(_linux.root_dir()):',
     "with __import__('contextlib').nullcontext():", 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_shipping_actions_hold_one_complete_state_transaction',
     'shipping PF mutation escaped its complete private state lock'),
    ('old watcher native replacement owner', 'kill-switch-platform.py', "if not state or state.get('platform') != 'darwin' or state.get('native_socket_broker') is True:",
     "if not state or state.get('platform') != 'darwin':", 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_legacy_watcher_locks_its_iteration_and_never_rewrites_native_timeout',
     'older watcher changed a replacement native journal'),
    ('standalone root transaction', 'kill-switch-platform.py', 'with _watcher_state_guard(_linux.root_dir()):',
     "with __import__('contextlib').nullcontext():", 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_shipping_actions_hold_one_complete_state_transaction',
     'shipping PF mutation escaped its real per-root transaction'),
    ('watcher exact generation recheck', 'kill-switch-platform.py', 'if not _watcher_matches(state, capture, active=True):',
     'if False:', 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_watcher_rechecks_exact_generation_inside_its_transaction',
     'stale watcher changed PF after a captured generation replacement'),
    ('watcher lease retirement proof', 'kill-switch-platform.py',
     '                            try:\n                                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)\n                                break',
     '                            try:\n                                pass  # omitted captured lease proof\n                                break',
     'test_darwin_owned_pf.py', 'OwnedDarwinPF.test_unresolved_lease_retains_cancel_until_exact_holder_retires',
     'held watcher lease was treated as retired'),
    ('in-flight PF child authority', 'darwin_kill_switch.py', 'pass_fds=retained_fds,',
     'pass_fds=(),', 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_pf_child_retains_both_locks_after_its_watcher_crashes',
     'PF child lost its captured lifetime or transaction descriptor'),
    ('in-flight fixed native child authority', 'darwin_pf_baseline.py', 'pass_fds=process_authority_fds()',
     'pass_fds=()', 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_fixed_native_child_retains_installed_locks_after_its_watcher_crashes',
     'PF child lost its captured lifetime or transaction descriptor'),
    ('in-flight installed outer locks', 'darwin_pf_baseline.py', 'with process_authority((install, state_lock)):',
     "with __import__('contextlib').nullcontext():", 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_pf_child_retains_both_locks_after_its_watcher_crashes',
     'PF child lost its captured lifetime or transaction descriptor'),
    ('retired lease cleanup receipt', 'kill-switch-platform.py',
     '                        _write_watcher_state(root, state)\n                    else:',
     '                        state.pop(_WATCHER_KEY)\n                        _write_watcher_state(root, state)\n                    else:',
     'test_darwin_owned_pf.py', 'OwnedDarwinPF.test_retired_lease_cleanup_failures_keep_exact_receipt_for_retry',
     'failed lease cleanup lost its exact retry receipt'),
    ('sudo descriptor preservation', 'darwin_kill_switch.py',
     'preserve = ["-C", str(max(retained_fds) + 1)] if retained_fds else []',
     'preserve = []', 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_nonroot_pf_explicitly_preserves_descriptors_or_fails_without_retry',
     'owned PF command retried without its captured descriptors'),
    ('legacy Off watcher retirement', 'kill-switch-platform.py',
     '            _require_watcher_retired(previous)\n            _darwin.remove_darwin',
     '            pass  # omitted Off retirement\n            _darwin.remove_darwin', 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_legacy_actions_retain_unresolved_watcher_without_signaling',
     'legacy watcher action did not retain unresolved ownership'),
    ('legacy release watcher retirement', 'kill-switch-platform.py',
     '    _require_watcher_retired(state)\n    if not force',
     '    pass  # omitted release retirement\n    if not force', 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_legacy_actions_retain_unresolved_watcher_without_signaling',
     'legacy watcher action did not retain unresolved ownership'),
    ('legacy reassert watcher retirement', 'kill-switch-platform.py',
     "    lan = bool(control_profile.get(\"home_lan_access\", False))\n    _require_watcher_retired(previous)",
     "    lan = bool(control_profile.get(\"home_lan_access\", False))\n    pass  # omitted reassert retirement", 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_legacy_actions_retain_unresolved_watcher_without_signaling',
     'legacy watcher action did not retain unresolved ownership'),
    ('strict zero watcher identity', 'kill-switch-platform.py', 'if type(pid) is not int or pid != 0:',
     'if pid != 0:', 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_legacy_actions_retain_unresolved_watcher_without_signaling',
     'legacy watcher action did not retain unresolved ownership'),
    ('unknown watcher identity', 'kill-switch-platform.py', "pid = state.get('darwin_watcher_pid')",
     "pid = state.get('darwin_watcher_pid', 0)", 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_legacy_actions_retain_unresolved_watcher_without_signaling',
     'legacy watcher action did not retain unresolved ownership'),
    ('saved PID signaling', 'kill-switch-platform.py',
     "        raise RuntimeError('macOS protection requires exact prior watcher retirement; saved process identities cannot authorize signaling')",
     "        os.kill(991, __import__('signal').SIGTERM)\n        raise RuntimeError('macOS protection requires exact prior watcher retirement; saved process identities cannot authorize signaling')",
     'test_darwin_owned_pf.py', 'OwnedDarwinPF.test_legacy_actions_retain_unresolved_watcher_without_signaling',
     'legacy saved PID was signaled without captured ownership'),
)


def sources():
    result = {}
    for name in FILES:
        path = ROOT/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('PF journal gate lost a regular shipping dependency: '+name)
        result[name] = path.read_bytes()
    return result


def run(path, selected=None):
    command = [sys.executable, '-EsB', str(path)] + ([selected] if selected else [])
    result = subprocess.run(command, cwd=path.parent, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
    if len(result.stdout) > 256*1024:
        raise ValueError('PF journal test output exceeded its bounded evidence')
    return result


def main():
    before = sources()
    for name in ('test_darwin_pf_baseline.py', 'test_darwin_owned_pf.py'):
        result = run(ROOT/'modes'/name)
        if result.returncode or '\nOK\n' not in result.stdout or 'skipped=' in result.stdout:
            raise ValueError('actual PF journal baseline failed: '+name+'\n'+result.stdout)
        print(result.stdout, end='')
    for label, name, old, new, test, selected, witness in MUTANTS:
        raw = before['modes/'+name].decode('utf-8')
        if raw.count(old) != 1:
            raise ValueError('PF journal mutation lost its exact source boundary: '+label)
        with tempfile.TemporaryDirectory(prefix='routervpn-pf-journal-mutant-') as temporary:
            directory = Path(temporary)
            for relative, body in before.items():
                destination = directory/relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(body)
            (directory/'modes'/name).write_text(raw.replace(old, new), encoding='utf-8')
            result = run(directory/'modes'/test, selected)
            method = selected.split('.', 1)[1]
            if (result.returncode == 0 or 'FAIL: '+method not in result.stdout or witness not in result.stdout
                    or 'SyntaxError' in result.stdout or 'ImportError' in result.stdout or 'ModuleNotFoundError' in result.stdout):
                raise ValueError('PF journal mutation missed its actual assertion: '+label+'\n'+result.stdout)
            print('Rejected broken '+label+' through '+selected+'.')
    if sources() != before:
        raise ValueError('PF journal shipping source changed during its executable gate')
    print('PF journal actual source closure: '+str({name: hashlib.sha256(raw).hexdigest() for name, raw in before.items()}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
