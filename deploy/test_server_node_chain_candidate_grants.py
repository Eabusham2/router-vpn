#!/usr/bin/env python3
"""Bounded shared grant/agent contracts; this does not run a native worker."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
RELAY = ('TestNodeChainCandidateStrictAuthority', 'TestNodeChainCandidateConnectQuotaAndJoin',
         'TestNodeChainCandidateManagerRetainsOriginalOperation', 'TestNodeChainCandidateManagerCancellationJoin',
         'TestNodeChainCandidateManagerHeldStatusAndLeaseStop', 'TestNodeChainCandidateManagerExpiryRetainsJoin', 'TestNodeChainCandidateExpiryHeldCallbacks', 'TestNodeChainCandidateRequestDeadlineRetainsCallback',
         'TestNodeChainCandidatePrunesOnlyJoinedExpiredAttempts', 'TestNodeChainCandidateWireIdentityCannotFollowReplacement',
         'TestServerCandidateMissingRequiresJoinedOriginal')
POLICY = ('TestNodeChainServerCandidateOriginalPacketTarget', 'TestNodeChainServerCandidateRetainsLANAndIPv6Policy',
          'TestServerStreamCandidateRegistryAbsence')
AGENT = 'TestNodeChainCandidateHTTPAuthenticatedUnavailableBoundary'
REGISTERED = 'TestServerStreamCandidateUsesExistingRegistration'
STRICT = ('entry', 'final', 'foreign-owner', 'hostname', 'mapped', 'extended-deadline', 'duplicate', 'tag', 'case', 'null')
HTTP = ('unauthenticated', 'public-peer', 'unknown-tag', 'oversize', 'no-discovery')
CASES = {
 'relay': ('./internal/multihoprelay', RELAY, frozenset(RELAY) | {RELAY[0]+'/'+x for x in STRICT} | {RELAY[6]+'/'+x for x in ('prepare','status')} | {RELAY[-1]+'/'+x for x in ('original','wrong-registry','failed-close','cancelled')}, None),
 'policy': ('./internal/mobilemultihop', POLICY, frozenset(POLICY) | {POLICY[-1]+'/'+x for x in ('missing-then-registered','forged','other-candidate','stale-epoch','unjoined','missing-cleanup-held')}, None),
 'agent': ('./cmd/router-agent', (AGENT,REGISTERED), frozenset((AGENT,REGISTERED)) | {AGENT+'/'+x for x in HTTP}, None),
 'quota-control': ('./internal/multihoprelay', (RELAY[1],), frozenset((RELAY[1],)),
    ('internal/multihoprelay/node_chain_candidate.go', ' || a.accepted >= NodeChainCandidateMaximumConnects', '', 'fifty-first candidate admitted')),
 'join-control': ('./internal/multihoprelay', (RELAY[4],), frozenset((RELAY[4],)),
    ('internal/multihoprelay/node_chain_candidate_manager.go', 'if reads != nil {', 'if false && reads != nil {', 'held status released replacement slot')),
}

def closure():
    paths = [ROOT/'go.mod', ROOT/'go.sum', Path(__file__).resolve()]
    for folder in ('internal', 'cmd/router-agent'):
        paths.extend(p for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    result = {}
    for p in sorted(set(paths)):
        if p.is_symlink():
            raise ValueError('linked grant source')
        name=p.relative_to(ROOT).as_posix()
        if name=='go.sum' and not p.exists():
            result[name]=None  # The root module has no dependency sum file.
        else:
            result[name] = hashlib.sha256(p.read_bytes()).hexdigest()
    return result


def verdict(rows, code, expected, control=None):
    run, passed, failed, skipped, package = [], [], [], [], []
    output = ''
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('invalid Go event')
        action, name = row.get('Action'), row.get('Test')
        output += row.get('Output', '')
        if name:
            if action == 'run': run.append(name)
            elif action == 'pass': passed.append(name)
            elif action == 'fail': failed.append(name)
            elif action == 'skip': skipped.append(name)
        elif action in ('pass', 'fail'):
            package.append(action)
    forbidden = ('WARNING: DATA RACE', 'race detected during execution', 'panic:', 'fatal error:', 'test timed out after', 'SIGSEGV', 'SIGABRT', 'runtime: out of memory')
    if any(marker in output for marker in forbidden):
        raise ValueError('runtime diagnostic is not an ownership refusal')
    if len(run) != len(expected) or set(run) != expected or skipped:
        raise ValueError('missing, duplicated, unexpected or skipped grant record')
    if control:
        if code != 1 or package != ['fail'] or passed or len(failed) != len(expected) or set(failed) != expected or control not in output:
            raise ValueError('compiled omission did not reach its exact assertion')
    elif code != 0 or package != ['pass'] or failed or len(passed) != len(expected) or set(passed) != expected:
        raise ValueError('grant source phase failed')
    return {'records': len(run), 'control': bool(control)}


def run(phase, output):
    package, roots, expected, mutation = CASES[phase]
    output.mkdir(parents=True, exist_ok=False)
    before = closure()
    (output/'source.json').write_text(json.dumps(before, sort_keys=True, indent=2)+'\n')
    receipt = {'phase': phase, 'status': 'failed', 'scope': 'actual shared policy/manager and HTTP boundary; native worker unsupported',
               'go_test_seconds': 180, 'process_seconds': 240, 'started_unix': time.time()}
    try:
        with tempfile.TemporaryDirectory(prefix='candidate-grant-overlay-') as scratch:
            command = ['go', 'test', '-json', '-race', '-count=1', '-timeout=180s']
            if mutation:
                path, old, new, _ = mutation
                original = (ROOT/path).read_text()
                if original.count(old) != 1:
                    raise ValueError('omission anchor changed')
                replacement = Path(scratch)/Path(path).name
                replacement.write_text(original.replace(old, new, 1))
                overlay = Path(scratch)/'overlay.json'
                overlay.write_text(json.dumps({'Replace': {str(ROOT/path): str(replacement)}}))
                command += ['-overlay='+str(overlay)]
                receipt['overlay_sha256'] = hashlib.sha256(replacement.read_bytes()).hexdigest()
            command += [package, '-run', '^('+'|'.join(roots)+')$']
            receipt['command'] = command
            receipt['toolchain'] = subprocess.check_output(['go', 'version'], text=True, timeout=10).strip()
            with (output/'go.jsonl').open('w') as log:
                process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    code = process.wait(timeout=240)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    raise ValueError('original 240-second source process bound exceeded')
            receipt['exit_code'] = code
            rows = [json.loads(line) for line in (output/'go.jsonl').read_text().splitlines() if line.strip()]
            receipt.update(verdict(rows, code, expected, mutation[3] if mutation else None))
            if closure() != before:
                raise ValueError('original source changed during phase')
            receipt['status'] = 'passed'
    except Exception as error:
        receipt['error'] = str(error)
        raise
    finally:
        receipt['finished_unix'] = time.time()
        if (output/'go.jsonl').exists(): receipt['log_sha256'] = hashlib.sha256((output/'go.jsonl').read_bytes()).hexdigest()
        (output/'receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2)+'\n')

class RunnerTests(unittest.TestCase):
    def rows(self):
        return [{'Action':'run','Test':'TestOne'}, {'Action':'pass','Test':'TestOne'}, {'Action':'pass'}]
    def test_positive(self): verdict(self.rows(), 0, {'TestOne'})
    def test_missing(self):
        with self.assertRaises(ValueError): verdict(self.rows()[:-2], 0, {'TestOne'})
    def test_duplicate(self):
        with self.assertRaises(ValueError): verdict(self.rows()+[self.rows()[0]], 0, {'TestOne'})
    def test_skip(self):
        with self.assertRaises(ValueError): verdict(self.rows()+[{'Action':'skip','Test':'TestOne'}], 0, {'TestOne'})
    def test_compiler_failure_is_not_control(self):
        with self.assertRaises(ValueError): verdict([{'Action':'fail','Output':'witness'}], 1, {'TestOne'}, 'witness')
    def test_control_exact_witness(self):
        rows=[{'Action':'run','Test':'TestOne'}, {'Action':'output','Output':'witness'}, {'Action':'fail','Test':'TestOne'}, {'Action':'fail'}]
        verdict(rows, 1, {'TestOne'}, 'witness')
        with self.assertRaises(ValueError): verdict(rows, 1, {'TestOne'}, 'different')
    def test_runtime_failure_cannot_impersonate_control(self):
        for diagnostic in ('WARNING: DATA RACE', 'race detected during execution', 'panic: unexpected', 'fatal error: concurrent map writes', 'test timed out after 180s', 'SIGSEGV', 'SIGABRT', 'runtime: out of memory'):
            rows=[{'Action':'run','Test':'TestOne'}, {'Action':'output','Output':'witness '+diagnostic}, {'Action':'fail','Test':'TestOne'}, {'Action':'fail'}]
            with self.subTest(diagnostic=diagnostic), self.assertRaises(ValueError):
                verdict(rows, 1, {'TestOne'}, 'witness')
    def test_actual_module_sum_identity_or_absence(self):
        source=closure()
        expected=hashlib.sha256((ROOT/'go.sum').read_bytes()).hexdigest() if (ROOT/'go.sum').exists() else None
        self.assertEqual(source['go.sum'],expected)
    def test_registration_and_inventory(self):
        for phase,(package,roots,expected,mutation) in CASES.items():
            source='\n'.join(p.read_text() for p in (ROOT/package.removeprefix('./')).glob('*_test.go'))
            for root in roots: self.assertEqual(source.count('func '+root+'('),1,phase)
            self.assertTrue(set(roots)<=expected)
            if mutation:self.assertEqual((ROOT/mutation[0]).read_text().count(mutation[1]),1)
        workflow=(ROOT/'.github/workflows/native-xray-exits.yml').read_text()
        self.assertIn('phase: [relay, policy, agent, quota-control, join-control]',workflow)
        builder=(ROOT/'deploy/build-native-runtime.py').read_text()
        self.assertIn("for grant_phase in ('relay', 'policy', 'agent', 'quota-control', 'join-control'):",builder)
        self.assertIn("ROOT/'deploy/test_server_node_chain_candidate_grants.py'",builder)

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--phase',choices=tuple(CASES))
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.self_test:
        if not unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RunnerTests)).wasSuccessful():raise SystemExit(1)
    elif args.phase and args.output: run(args.phase,args.output)
    else:parser.error('provide --self-test or --phase with a fresh --output directory')
