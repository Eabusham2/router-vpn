#!/usr/bin/env python3
"""Require connected imported-SS candidate timing through the original full path.

Every positive first proves its complete encrypted path, then uses the actual
NodeChainCandidatePlan.NewMeasurementContext for fifty destination handshakes.
This is component evidence; the host/kernel boundary remains separately owned.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load('connected_imported_ss_prefix_source', 'test_desktop_node_chain_ss_prefix.py')
NODE = BASE.NODE
TRAFFIC = 'TestRouterVPNConnectedImportedSSCandidates'
REFUSAL = 'TestRouterVPNConnectedImportedSSCandidateRefusals'
MODES = ('wg', 'awg2-fast', 'awg2-strong')
CASES = tuple(f'{mode}/{count}/{position}' for mode in MODES for count in (2, 6) for position in range(count))
FAULTS = ('wrong-intermediate-key', 'wrong-middle-key', 'wrong-final-identity', 'selected-dns-failure',
          'catalog-change', 'network-change', 'native-retired', 'cancel-held-close')
CASE_ENV = 'ROUTERVPN_CONNECTED_IMPORTED_CANDIDATE_CASE'
FAULT_ENV = 'ROUTERVPN_CONNECTED_IMPORTED_CANDIDATE_FAULT'
TEMPLATE = 'node_chain_imported_candidates_peer_test.go.tmpl'
NATIVE_TEMPLATE = 'protocol/routervpnamnezia/routervpn_desktop_node_chain_imported_candidates_peer_test.go'
OWNER_ROOT = 'TestRouterVPNNodeChainImportedSSPrefixMTUOriginalOwners'
OWNER_TEMPLATE = 'routervpn_node_chain_imported_prefix_test.go'
OWNER_CASES = (OWNER_ROOT, *(OWNER_ROOT+'/'+str(count)+'-'+fault for count in (2, 6)
    for fault in ('candidate', 'rollback', 'prefix', 'middle', 'final', 'resolver', 'cancel', 'stale-owner')))
GATES = ('deploy/test_connected_imported_ss_candidates.py',
         'deploy/test_connected_imported_ss_candidates_runner.py',
         'deploy/test_linux_node_host_tun.py', 'deploy/build-native-runtime.py',
         'deploy/test_mobile_multihop_groups.py',
         'deploy/test_desktop_node_chain_ss_prefix_contract.py',
         '.github/workflows/ss-node-chain-prefix.yml', '.github/workflows/release-candidate.yml')
REQUIRED = (NATIVE_TEMPLATE, OWNER_TEMPLATE,
            'experimental/libbox/routervpn/mobilemultihop/node_chain_candidates.go',
            'experimental/libbox/routervpn/mobilemultihop/node_chain_imported_owners.go',
            'experimental/libbox/routervpn/mobilemultihop/node_chain_runtime.go')


def phases():
    result = []
    for case in CASES:
        mode, count, position = case.split('/')
        result.append({'name': case, 'root': TRAFFIC, 'environment': {CASE_ENV: case},
                       'verdicts': [TRAFFIC, TRAFFIC + '/' + case.replace('/', '-')],
                       'mode': mode, 'prefixes': int(count), 'position': int(position), 'samples': 50})
    result += [{'name': fault, 'root': REFUSAL, 'environment': {FAULT_ENV: fault},
                'verdicts': [REFUSAL, REFUSAL + '/' + fault]} for fault in FAULTS]
    return result


def check_verdict(output, phase):
    if phase not in phases():
        raise ValueError('Connected imported candidate phase is not original')
    NODE.require_native_verdicts(output, phase['verdicts'], 'connected complete imported-SS candidate')
    marker = 'CONNECTED_IMPORTED_CANDIDATE_RECEIPT '
    records = [line.split(marker, 1)[1].strip() for line in output.splitlines() if marker in line]
    expected = []
    if phase['root'] == TRAFFIC:
        expected = [f"count={phase['prefixes']} position={phase['position']} samples=50 closed=50 released=1 complete_ready=true selected_dns=true joined=true"]
    if records != expected:
        raise ValueError('Connected candidate omitted its complete proof, fifty sockets or joined ownership')


def checked_sources(source):
    source, records = BASE.checked_sources(source)
    if NODE.PREP.PEER_TEMPLATES.get(TEMPLATE) != NATIVE_TEMPLATE:
        raise ValueError('Connected imported candidate template is not canonically owned')
    if (source / NATIVE_TEMPLATE).read_bytes() != (ROOT / 'mobile/desktop' / TEMPLATE).read_bytes():
        raise ValueError('Connected imported candidate template differs from shipping source')
    owner = source / OWNER_TEMPLATE
    if owner.read_bytes() != (ROOT / 'mobile/chain/imported_prefix_box_test.go.tmpl').read_bytes() or f'func {OWNER_ROOT}(' not in owner.read_text():
        raise ValueError('Connected candidate lost the original actual Box/manager ownership controls')
    for relative in REQUIRED:
        path = source / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('Connected candidate original dependency missing: ' + relative)
        records[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    for relative in GATES:
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('Connected candidate required gate missing: ' + relative)
        records['gate/' + relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, records


def execute_peer(image, source, captured):
    source, inputs = checked_sources(source)
    image = Path(image)
    identity = NODE.retained_binary(image)
    completed = []
    for phase in phases():
        if NODE.retained_binary(image) != identity or checked_sources(source)[1] != inputs:
            raise ValueError('Connected candidate source or original image changed before phase')
        env = dict(captured)
        env.pop(CASE_ENV, None)
        env.pop(FAULT_ENV, None)
        env.update(phase['environment'])
        status, output = NODE.run([str(image), '-test.v', '-test.count=1', '-test.timeout=90s',
                                   '-test.run=^' + phase['root'] + '$'], cwd=source, env=env, timeout=100)
        print(output, end='' if output.endswith('\n') else '\n', flush=True)
        if status:
            raise ValueError('Connected imported candidate native phase failed: ' + phase['name'])
        check_verdict(output, phase)
        if NODE.retained_binary(image) != identity or checked_sources(source)[1] != inputs:
            raise ValueError('Connected candidate source or original image changed during phase')
        completed.append({**phase, 'image_sha256': identity[-1], 'output_sha256': hashlib.sha256(output.encode()).hexdigest()})
    if len(completed) != 32:
        raise ValueError('Connected candidate omitted required complete-path inventory')
    return {'schema': 1, 'gate': 'connected-imported-ss-candidates', 'source_files': inputs,
            'image_sha256': identity[-1], 'phases': completed,
            'scope': 'actual-full-chain-encrypted-component',
            'native_observation': 'explicit-component-session-boundary',
            'installed_host_accepted': False, 'kernel_tun_accepted': False}


def execute(source, go='go', *, env=None):
    if platform.system() != 'Linux':
        raise ValueError('Connected imported candidate native execution requires Linux')
    source, before = checked_sources(source)
    compiler, captured, _ = NODE.selected_compiler(go, source, dict(os.environ if env is None else env))
    if captured.get('CGO_ENABLED', '1') != '1' or captured.get('GOOS', 'linux') != 'linux':
        raise ValueError('Connected candidate gate cannot cross-compile or disable CGO')
    captured['CGO_ENABLED'] = '1'
    with tempfile.TemporaryDirectory(prefix='routervpn-connected-ss-candidate-') as directory:
        image = Path(directory) / 'peer.test'
        status, output = NODE.run([compiler, 'test', '-c', '-race', '-p=1', '-mod=readonly',
                                   '-tags=' + ','.join(NODE.TAGS), '-ldflags=-checklinkname=0',
                                   '-o', image, './protocol/routervpnamnezia'], cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError('Connected candidate native compilation failed:\n' + output[-24000:])
        if checked_sources(source)[1] != before:
            raise ValueError('Connected candidate sources changed during compilation')
        return execute_peer(image, source, captured)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    print(json.dumps(execute(args.source, args.go), sort_keys=True))


if __name__ == '__main__':
    main()
