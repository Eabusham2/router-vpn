#!/usr/bin/env python3
"""Require the connected typed candidate controller and its exact refusal controls."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('typed_candidate_parent_common', ROOT/'deploy/test_desktop_socks_execution_controller.py')
COMMON = importlib.util.module_from_spec(spec)
spec.loader.exec_module(COMMON)
PACKAGE = COMMON.PACKAGE
FAMILIES = ('SOCKS', 'HTTP', 'HTTPS')
AUTHORITY = ('unstaged', 'execution-owner', 'saved-prefix', 'generic-plan', 'mixed-policy', 'equal-policy', 'equal-source', 'foreign-launch', 'missing-plan', 'cancelled')
RECEIPT = ('schema', 'measurement', 'capture', 'prefix', 'prefix-id', 'candidate', 'source', 'expiry', 'renewed-expiry', 'future', 'undrained', 'failed', 'missing', 'role', 'kind', 'not-ready', 'http', 'guessed-endpoint', 'attempts', 'failed-sample', 'sample-count', 'nan', 'order', 'mean', 'trim', 'jitter')
MAILBOX = ('success', 'cancel', 'cancel-delayed', 'wrong-capture', 'partial-samples', 'catalog-away-back')
PHASES = ('source', 'receipts', 'mailbox', 'controls')
CONTROLS = (
    ('cmd/client/desktop_node_chain_candidate_catalog.go',
     'launch.chain.policy == nil && !desktopTypedCandidateSourceAllowed(launch) {',
     'launch.chain.policy == nil {',
     'TestDesktopTypedConnectedSOCKSCandidateSource', '3', 'original typed connected candidate source refused'),
    ('cmd/client/desktop_node_chain_typed_candidates.go',
     'status.CaptureSHA256 != plan.CaptureSHA256()', 'false',
     'TestDesktopTypedConnectedHTTPCandidateReceipt', 'capture', 'forged or incomplete score accepted'),
    ('cmd/client/desktop_node_chain_typed_candidate_catalog.go',
     'if c == nil || c.prefixPreparation != nil {', 'if c == nil {',
     'TestDesktopTypedConnectedHTTPSCandidateAuthority', 'saved-prefix', 'typed candidate accepted substituted original authority'),
)


def inventory(phase):
    if phase == 'source':
        return {**{'TestDesktopTypedConnected'+family+'CandidateSource': ('3', '4', '8') for family in FAMILIES},
                **{'TestDesktopTypedConnected'+family+'CandidateAuthority': AUTHORITY for family in FAMILIES},
                'TestDesktopTypedConnectedCandidatePublicCatalog': ('socks5', 'http-connect', 'https-connect')}
    if phase == 'receipts':
        return {'TestDesktopTypedConnected'+family+'CandidateReceipt': RECEIPT for family in FAMILIES}
    if phase == 'mailbox':
        return {'TestDesktopTypedConnected'+family+'CandidateMailbox': MAILBOX for family in FAMILIES}
    if phase == 'controls':
        return {root: (child,) for _, _, _, root, child, _ in CONTROLS}
    raise ValueError('unknown connected typed candidate phase')


def source_identity():
    paths = set(COMMON.BUILDER.inputs())
    required = {ROOT/name for name in (
        'deploy/test_desktop_typed_candidate_controller.py',
        'deploy/test_desktop_typed_candidate_controller_runner.py',
        '.github/workflows/multihop-contract.yml',
        'cmd/client/desktop_node_chain_typed_candidate_catalog.go',
        'cmd/client/desktop_node_chain_typed_candidates.go',
        'cmd/client/desktop_node_chain_typed_candidates_test.go',
        'cmd/client/desktop_node_chain_measurement.go',
        'cmd/client/ordered_candidate_preparation.go',
        'cmd/client/ordered_candidate_preparation_view.go',
        'internal/mobilemultihop/node_chain_typed_connected_candidates.go',
        'mobile/desktop/node_chain_socks_candidates.go.tmpl',
        'mobile/desktop/node_chain_connect_candidates.go.tmpl')}
    if not required.issubset(paths):
        raise ValueError('connected typed candidate gate lost a shipping input or runner')
    rows = []
    for path in sorted(paths):
        if path.is_symlink() or not path.is_file():
            raise ValueError('connected typed candidate source is not an original regular file')
        rows.append((path.relative_to(ROOT).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()))
    return hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()


def verify_control_result(result, root, case, witness):
    def unique_pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate control event key')
            value[key] = item
        return value
    events = [json.loads(line, object_pairs_hook=unique_pairs) for line in result.stdout.splitlines()]
    COMMON.verify_causal_result(result, root, case, witness)
    allowed = {root, case}
    if (any(event.get('Test') not in allowed for event in events if event.get('Test')) or
            any(event.get('Action') in ('pass', 'skip') for event in events) or
            sum(event.get('Action') == 'start' for event in events) != 1):
        raise ValueError('control contains a foreign, passing, skipped or repeated test')
    positions = []
    for action, name in (('run', root), ('run', case), ('fail', case), ('fail', root)):
        matches = [index for index, event in enumerate(events) if event.get('Action') == action and event.get('Test') == name]
        if len(matches) != 1:
            raise ValueError('control lost its exact failed root and child')
        positions.append(matches[0])
    if positions != sorted(positions) or positions[-1] >= len(events)-1:
        raise ValueError('control verdict is not its original ordered failure')


def run(go='go', receipt=None, without_race=False, phase='source'):
    roots = inventory(phase)
    executable, environment, target = COMMON.native_environment(go, without_race)
    identity, rows = source_identity(), []
    result = {'schema': 1, 'status': 'failed', 'phase': phase, 'target': target, 'race': not without_race,
              'source_sha256': identity, 'compiler': executable, 'toolchain': COMMON.BUILDER.TOOLCHAIN,
              'records': rows, 'scope': 'Shipping controller/source/Ready/MTU ownership and mailbox retirement. The child and kernel are explicit models; native command-loop, encrypted traffic and installed acceptance remain separate.'}
    try:
        with tempfile.TemporaryDirectory(prefix='routervpn-typed-candidate-parent-') as scratch:
            directory = Path(scratch)
            image = directory/('controller.test.exe' if target.startswith('windows/') else 'controller.test')
            if phase != 'controls':
                command, digest = COMMON.compile_image(executable, environment, image, without_race)
                result['compile'] = {'command': command, 'image_sha256': digest}
                for root, children in roots.items():
                    if source_identity() != identity or image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
                        raise ValueError('connected typed candidate source or image changed')
                    command = [executable, 'tool', 'test2json', '-p', PACKAGE, str(image), '-test.v=test2json', '-test.count=1', '-test.timeout=120s', '-test.run=^'+root+'$']
                    completed = COMMON.invoke(command, environment, ROOT/'cmd/client', 135)
                    row = {'root': root, 'command': command, 'returncode': completed.returncode,
                           'output_sha256': hashlib.sha256(completed.stdout.encode()).hexdigest(), 'image_sha256': digest}
                    rows.append(row)
                    if receipt:
                        Path(str(receipt)+'.'+root+'.jsonl').write_text(completed.stdout)
                    if completed.returncode or completed.stderr.strip():
                        raise ValueError('connected typed candidate root failed: '+root)
                    COMMON.BUILDER.verify_imported_native_verdicts(completed.stdout, PACKAGE, COMMON.expected({root: children}))
                    if source_identity() != identity or image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
                        raise ValueError('connected typed candidate source or image changed during execution')
                    row['tests'] = 1+len(children)
                if len(rows) != len(roots) or sum(row['tests'] for row in rows) != len(COMMON.expected(roots)):
                    raise ValueError('connected typed candidate gate omitted an original root')
            else:
                for index, (relative, before, after, root, child, witness) in enumerate(CONTROLS):
                    path = ROOT/relative
                    original = path.read_text()
                    if original.count(before) != 1:
                        raise ValueError('connected typed candidate causal boundary changed')
                    changed, overlay = directory/('control-'+str(index)+'.go'), directory/'overlay.json'
                    changed.write_text(original.replace(before, after, 1))
                    overlay.write_text(json.dumps({'Replace': {str(path): str(changed)}}))
                    compile_command, digest = COMMON.compile_image(executable, environment, image, without_race, overlay)
                    selection = '^'+re.escape(root)+'$/^'+re.escape(child)+'$'
                    command = [executable, 'tool', 'test2json', '-p', PACKAGE, str(image), '-test.v=test2json', '-test.count=1', '-test.timeout=120s', '-test.run='+selection]
                    completed = COMMON.invoke(command, environment, ROOT/'cmd/client', 135)
                    if receipt:
                        Path(str(receipt)+'.control-'+str(index)+'.jsonl').write_text(completed.stdout)
                    verify_control_result(completed, root, root+'/'+child, witness)
                    if source_identity() != identity or path.read_text() != original or image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
                        raise ValueError('connected typed candidate causal source/image changed')
                    rows.append({'root': root+'/'+child, 'witness': witness, 'returncode': completed.returncode,
                                 'compile_command': compile_command, 'command': command, 'image_sha256': digest,
                                 'output_sha256': hashlib.sha256(completed.stdout.encode()).hexdigest()})
                if len(rows) != len(CONTROLS):
                    raise ValueError('connected typed candidate gate omitted a required control')
        result['status'] = 'passed'
    except BaseException as error:
        result['error'] = repr(error)
        raise
    finally:
        if receipt:
            Path(receipt).write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
        print(json.dumps(result, sort_keys=True), flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--without-race', action='store_true')
    parser.add_argument('--phase', required=True, choices=PHASES)
    args = parser.parse_args()
    run(args.go, args.receipt, args.without_race, args.phase)
