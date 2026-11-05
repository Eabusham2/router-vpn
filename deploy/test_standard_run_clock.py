#!/usr/bin/env python3
"""Real FD11/provider/worker controls; native OS calls are explicitly modeled."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CORE = ('ClockIndependentAndSingle', 'ClockCancellationAndHeldLock', 'ClosureAndStaleClock',
        'BindsCommandAndRestore', 'ShortAdmissionAndOriginalBounds', 'PreviousLayoutRefused',
        'ClockInheritedProcess', 'SettlementKeepsClock', 'AdmissionHistoryIsBounded', 'UnsubmittedRequiresBothOriginalObservers',
        'WorkerOneClockAndOriginalRestore', 'WorkerExpiredWorkRejectsConstructor', 'WorkerClosesWithoutMutation', 'WorkerClosureKeepsOriginalDeadline')
PROVIDER = ('CleanupProviderSingleActivation', 'CleanupProviderCannotRenewOrRetryFailure',
            'CleanupFinishCancelsActivation', 'ControllerAdmissionUsesCapturedClock',
            'CapturedDeadlineAndCleanupMarker', 'AdmissionKeepsAcceptedDeadline',
            'FinalizationRetainsOriginalTokenUntilJoin', 'FinalizationPreservesJoinedCancellation')
CONTROLS = (
    ('operation_run_clock_linux.go',
     '\t\treturn deadline, ctx.Err()',
     '\t\treturn deadline.Add(time.Millisecond), ctx.Err()',
     'TestCleanupSharedRunClockIndependentAndSingle',
     'parent/child cleanup did not share exact independent clock'),
    ('operation_command_linux.go',
     'size = operationControlFrameSize',
     'size = operationSlotSize',
     'TestCleanupSharedRunSettlementKeepsClock',
     'transaction settlement cleared or renewed original run cleanup clock'),
)

def execute():
    go = os.environ.get('GO') or shutil.which('go')
    if not go:
        raise RuntimeError('Go required for captured shared run clock')
    env = dict(os.environ, GOMAXPROCS='2', GOWORK='off', GOTOOLCHAIN='local')
    cases = tuple('TestCleanupSharedRun'+name for name in CORE) + tuple('TestOperationShared'+name for name in PROVIDER)
    common = [go, 'test', '-p=2', '-race', '-tags=routervpn_controller_privileged', '-count=1', '-v', '-timeout=30s']
    pattern = '^('+'|'.join(cases)+')$'
    positive = subprocess.run([*common, '-run='+pattern, './internal/standardengine', './internal/mobilemtu'], cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
    bad = ('--- SKIP:', 'DATA RACE', 'panic:', '[build failed]', 'no tests to run')
    if positive.returncode or '--- FAIL:' in positive.stdout or any(x in positive.stdout for x in bad):
        raise RuntimeError('Original shared clock positive failed:\n'+positive.stdout)
    for name in (*cases, *(cases[len(CORE)+1]+'/'+leaf for leaf in ('renew','failure','expired')), *(cases[-1]+'/'+leaf for leaf in ('restored','late-measured','late-parent','closure-failure'))):
        if positive.stdout.count('--- PASS: '+name+' (') != 1:
            raise RuntimeError('Original shared clock omitted exact verdict '+name)
    for filename, before, after, case, witness in CONTROLS:
        original = ROOT/'internal/standardengine'/filename
        raw = original.read_text()
        if raw.count(before) != 1:
            raise RuntimeError('Original clock boundary changed: '+filename)
        with tempfile.TemporaryDirectory(prefix='standard-run-clock-') as directory:
            changed = Path(directory)/filename
            changed.write_text(raw.replace(before, after, 1))
            overlay = Path(directory)/'overlay.json'
            overlay.write_text(json.dumps({'Replace': {str(original): str(changed)}}))
            failed = subprocess.run([*common, '-overlay='+str(overlay), '-run=^'+case+'$', './internal/standardengine'], cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        if failed.returncode == 0 or failed.stdout.count('--- FAIL: '+case+' (') != 1 or witness not in failed.stdout or any(x in failed.stdout for x in bad):
            raise RuntimeError('Shared clock causal missed exact defect '+case+':\n'+failed.stdout)
    print('Passed '+str(len(cases)+7)+' exact original FD11/provider/native-worker verdicts')
    print('Rejected renewed shared deadline and clock-clearing settlement at exact witnesses')

if __name__ == '__main__': execute()
