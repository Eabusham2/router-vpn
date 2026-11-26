#!/usr/bin/env python3
"""Bounded selected-Server remote candidate contracts; native transport is an explicit test boundary."""
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
ROOTS = (
 'TestNodeChainExecutionRemoteCandidatesFiftyOriginalConnections',
 'TestNodeChainExecutionRemoteCandidatesCleanupAndRefusals',
 'TestNodeChainExecutionRemoteCandidateRetiresBeforeWholeLease',
 'TestNodeChainExecutionRemoteCandidatePlanClosedScope',
 'TestNodeChainExecutionRemoteCandidateDeadlineIsOriginal',
 'TestNodeChainExecutionRemoteCandidateStopJoinsOriginalCallbacks',
 'TestNodeChainExecutionRemoteCandidateGenericExchangeRemainsClosed',
 'TestNodeChainExecutionRemoteCandidateNonComparableEngine',
)
CHILDREN = {ROOTS[0]: ('server','auto'), ROOTS[1]: ('lost-put','wrong-ack','foreign-receipt','stale-catalog','captured-lease'), ROOTS[3]: ('local','auto'), ROOTS[7]: ('constructor','current')}
RECORDS = frozenset(ROOTS) | {root+'/'+child for root,children in CHILDREN.items() for child in children}
CASES = {
 'source': ('./internal/mobilemultihop', ROOTS, RECORDS, None),
 'lease-order-control': ('./internal/mobilemultihop', (ROOTS[2],), frozenset((ROOTS[2],)),
  ('internal/mobilemultihop/node_chain_execution_lease.go', 'if candidate != nil {', 'if false && candidate != nil {', 'lease stopped before candidate cleanup')),
 'ack-control': ('./internal/mobilemultihop', (ROOTS[1]+'/wrong-ack',), frozenset((ROOTS[1],ROOTS[1]+'/wrong-ack')),
  ('internal/mobilemultihop/node_chain_execution_candidate_stop.go', 'if _, err = multihoprelay.DecodeNodeChainCandidateCloseAcknowledgement(data, s.capture.request); err != nil {', 'if _, err = multihoprelay.DecodeNodeChainCandidateCloseAcknowledgement(data, s.capture.request); false && err != nil {', 'nonexact ACK released original activity')),
}

def closure():
    paths = [ROOT/'go.mod', ROOT/'go.sum', Path(__file__).resolve()]
    for folder in ('internal',):
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
    receipt = {'phase': phase, 'status': 'failed', 'scope': 'actual selected runtime, HTTP/SOCKS control framing and fifty-sample service; explicit native boundary, no encrypted acceptance',
               'go_test_seconds': 180, 'process_seconds': 240, 'started_unix': time.time()}
    try:
        with tempfile.TemporaryDirectory(prefix='remote-candidate-overlay-') as scratch:
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
            command += [package, '-run', '/'.join('^(?:'+component+')$' for component in roots[0].split('/')) if len(roots)==1 and '/' in roots[0] else '^(?:'+'|'.join(roots)+')$']
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
