#!/usr/bin/env python3
"""Actual retained worker regression, with an exact unbounded-join control."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
NAME = 'TestCleanupOperationWorkerStopRetainsUnjoinedNativeCall'
BEFORE = '''\t\t\t\tselect {
\t\t\t\tcase completed = <-done:
\t\t\t\t\tw.acceptCompletion(unit, completed)
\t\t\t\t\tgoto joined
\t\t\t\tcase <-lifetime.Done():
\t\t\t\t\t// FD10 owns the next bounded join attempt. The actual call,
\t\t\t\t\t// original reader and eventual transaction remain in this unit.
\t\t\t\t\treturn nil
\t\t\t\t}'''
AFTER = '''\t\t\t\tcompleted = <-done
\t\t\t\tw.acceptCompletion(unit, completed)
\t\t\t\tgoto joined'''

def execute():
    compiler = os.environ.get('GO') or shutil.which('go')
    if not compiler:
        raise RuntimeError('Go required for actual retained worker stop control')
    original = ROOT / 'internal/standardengine/worker_linux.go'
    raw = original.read_text()
    if raw.count(BEFORE) != 1:
        raise RuntimeError('Original native join boundary changed')
    env = dict(os.environ, GOMAXPROCS='2', GOWORK='off', GOTOOLCHAIN='local')
    command = [compiler, 'test', '-p=2', '-race', '-tags=routervpn_controller_privileged', '-count=1', '-v', '-timeout=20s', '-run=^'+NAME+'$', './internal/standardengine']
    passed = subprocess.run(command, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    if passed.returncode or any(value in passed.stdout for value in ('--- FAIL:', '--- SKIP:', 'DATA RACE', 'panic:')):
        raise RuntimeError('Actual original worker positive failed:\n'+passed.stdout)
    for name in (NAME, NAME+'/held', NAME+'/within-budget'):
        if passed.stdout.count('--- PASS: '+name+' (') != 1:
            raise RuntimeError('Actual worker omitted exact join verdict '+name)
    with tempfile.TemporaryDirectory(prefix='standard-worker-stop-') as temporary:
        changed = Path(temporary)/'worker_linux.go'
        changed.write_text(raw.replace(BEFORE, AFTER, 1))
        overlay = Path(temporary)/'overlay.json'
        overlay.write_text(json.dumps({'Replace': {str(original): str(changed)}}))
        mutated = subprocess.run([*command[:2], '-overlay='+str(overlay), *command[2:]], cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    witness = 'original Stop could not reach bounded FD10 join while native call was held'
    if mutated.returncode == 0 or mutated.stdout.count('--- FAIL: '+NAME+'/held (') != 1 or witness not in mutated.stdout or any(value in mutated.stdout for value in ('[build failed]', '--- SKIP:', 'DATA RACE', 'panic:', 'no tests to run')):
        raise RuntimeError('Unbounded native join missed exact retained-worker defect:\n'+mutated.stdout)
    print('Actual held and within-budget native worker joins passed')
    print('Rejected unbounded original worker join at exact FD10 admission witness')

if __name__ == '__main__': execute()
