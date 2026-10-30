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
         'modes/test_darwin_pf_baseline.py', 'modes/test_darwin_owned_pf.py')
MUTANTS = (
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
    ('old watcher timeout owner', 'kill-switch-platform.py', "state and state.get('native_socket_broker') is not True",
     'state', 'test_darwin_owned_pf.py',
     'OwnedDarwinPF.test_legacy_watcher_locks_its_iteration_and_never_rewrites_native_timeout',
     'older watcher timeout rewrote a replacement native journal'),
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
