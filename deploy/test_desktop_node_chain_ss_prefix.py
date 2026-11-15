#!/usr/bin/env python3
"""Require every encrypted SS2022 prefix position from six exact-source units.

This additive component gate leaves the original two installed-host preflight
phases untouched. It does not establish kernel TUN or installed-host acceptance.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load('ss_prefix_canonical', 'test_desktop_node_chain_openvpn_prefix.py')
ORIGINAL_SS = load('ss_prefix_original_host', 'test_linux_node_host_tun.py')
HOST, NODE, BUILD, IDENTITY = BASE.HOST, BASE.NODE, BASE.BUILD, BASE.IDENTITY
prepared_native = BASE.prepared_native
SUITE = 'ss-prefix-native'
MODES = ('wg', 'awg2-fast', 'awg2-strong')
FORMS = ('literal', 'hostname')
METHODS = {'wg': '2022-blake3-aes-128-gcm', 'awg2-fast': '2022-blake3-aes-256-gcm', 'awg2-strong': '2022-blake3-chacha20-poly1305'}
UNITS = tuple((mode, form) for mode in MODES for form in FORMS)
TRAFFIC = 'TestRouterVPNDesktopNodeChainImportedSSPrefixTraffic'
REFUSAL = 'TestRouterVPNDesktopNodeChainImportedSSPrefixRefusal'
FAULTS = ('wrong-intermediate-key', 'omit-last-prefix', 'wrong-middle-key',
          'wrong-final-identity', 'selected-dns-failure', 'wrong-transport-dns')
CASE_ENV = 'ROUTERVPN_IMPORTED_SS_PREFIX_CASE'
REFUSAL_ENV = 'ROUTERVPN_IMPORTED_SS_PREFIX_REFUSAL'
TEMPLATE = 'node_chain_imported_prefix_test.go.tmpl'
NATIVE_TEMPLATE = 'protocol/routervpnamnezia/routervpn_desktop_node_chain_imported_prefix_test.go'
GATES = ('deploy/test_desktop_node_chain_ss_prefix.py',
         'deploy/test_desktop_node_chain_ss_prefix_runner.py',
         '.github/workflows/ss-node-chain-prefix.yml', '.github/workflows/release-candidate.yml',
         'deploy/focused_source_identity.py',
         'deploy/test_desktop_node_chain_ss_prefix_contract.py',
         'deploy/test_desktop_node_chain_ss_prefix_contract_runner.py',
         'deploy/test_reference_udp_lifetime.py', 'mobile/amnezia/desktop_reference_test.go.tmpl',
         'deploy/test_focused_multihop_clocks.py', 'deploy/test_desktop_node_physical.py',
         'deploy/test_desktop_node_chain_openvpn_prefix.py', 'deploy/test_linux_node_host_tun.py',
         'deploy/test_ios_node_chain_imported_capture.py', 'deploy/test_ios_node_chain_imported_profiles.py',
         'android/test_android_node_chain_imported_runtime.py')
REQUIRED = (NATIVE_TEMPLATE,
    'experimental/libbox/routervpn/mobilemultihop/node_chain_imported.go',
    'experimental/libbox/routervpn/mobilemultihop/node_chain_imported_owners.go',
    'experimental/libbox/routervpn/mobilemultihop/node_chain_socks_runtime.go',
    'experimental/libbox/routervpn/mobilemultihop/node_chain_measurement.go')


def unit_phases(mode, form):
    if (mode, form) not in UNITS:
        raise ValueError('SS2022 prefix unit is outside the captured mode/form matrix')
    phases = []
    for count in (2, 6):
        for group in range((count + 2) // 2):
            value = f'{mode}/{form}/{count}/{group}'
            name = value.replace('/', '-')
            phases.append({'name': name, 'selection': '^' + TRAFFIC + '$',
                           'environment': {CASE_ENV: value},
                           'verdicts': [TRAFFIC, TRAFFIC + '/' + name],
                           'nodes': count + 2, 'positions': [group * 2, group * 2 + 1], 'samples': 50, 'method': METHODS[mode]})
    if (mode, form) == ('awg2-strong', 'hostname'):
        phases += [{'name': 'refusal-' + fault, 'selection': '^' + REFUSAL + '$',
                    'environment': {REFUSAL_ENV: fault},
                    'verdicts': [REFUSAL, REFUSAL + '/' + fault]} for fault in FAULTS]
    return phases


def validator_identity():
    records = BASE.validator_identity()
    for relative in GATES:
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('SS2022 prefix validator lost a required source: ' + relative)
        records[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def checked_sources(source):
    source, records = BASE.checked_sources(source)
    if NODE.PREP.PEER_TEMPLATES.get(TEMPLATE) != NATIVE_TEMPLATE:
        raise ValueError('SS2022 prefix encrypted peer is not canonically registered')
    if (source / NATIVE_TEMPLATE).read_bytes() != (ROOT / 'mobile/desktop' / TEMPLATE).read_bytes():
        raise ValueError('SS2022 prefix native template changed from shipping source')
    for relative in REQUIRED:
        path = source / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('SS2022 prefix original native dependency missing: ' + relative)
        records[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    records.update({'gate/' + key: value for key, value in validator_identity().items()})
    return source, records


def execute_peer(image, source, captured, mode, form):
    phases = unit_phases(mode, form)
    identity, sources = NODE.retained_binary(image), checked_sources(source)[1]
    completed = []
    for phase in phases:
        if NODE.retained_binary(image) != identity or checked_sources(source)[1] != sources:
            raise ValueError('SS2022 prefix image or source changed before phase')
        env = dict(captured)
        env.pop(CASE_ENV, None)
        env.pop(REFUSAL_ENV, None)
        env.update(phase['environment'])
        status, output = NODE.run([image, '-test.run=' + phase['selection'], '-test.count=1',
                                  '-test.timeout=180s', '-test.v'], cwd=source, env=env, timeout=190)
        print(output, end='' if output.endswith('\n') else '\n', flush=True)
        if status:
            raise ValueError('SS2022 prefix native phase failed: ' + phase['name'])
        NODE.require_native_verdicts(output, phase['verdicts'], 'SS2022 prefix ' + phase['name'])
        if NODE.retained_binary(image) != identity or checked_sources(source)[1] != sources:
            raise ValueError('SS2022 prefix image or source changed during phase')
        completed.append({**phase, 'output_sha256': hashlib.sha256(output.encode()).hexdigest(),
                          'image_sha256': identity[-1]})
    return completed


def execute(source, mode, form, go='go', *, env=None):
    unit_phases(mode, form)
    if platform.system() != 'Linux':
        raise ValueError('SS2022 prefix execution requires its actual Linux host')
    source, before = checked_sources(source)
    compiler, captured, architecture = NODE.selected_compiler(go, source, dict(os.environ if env is None else env))
    if captured.get('CGO_ENABLED', '1') != '1' or captured.get('GOOS', 'linux') != 'linux':
        raise ValueError('SS2022 prefix cannot disable CGO or cross-compile its execution')
    captured['CGO_ENABLED'] = '1'
    with tempfile.TemporaryDirectory(prefix='routervpn-ss-prefix-image-') as directory:
        image = Path(directory) / 'peer.test'
        command = [compiler, 'test', '-c', '-race', '-p=1', '-mod=readonly',
                   '-tags=' + ','.join(NODE.TAGS), '-ldflags=-checklinkname=0', '-o', image,
                   './protocol/routervpnamnezia']
        status, output = NODE.run(command, cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError('SS2022 prefix image compilation failed:\n' + output[-24000:])
        if checked_sources(source)[1] != before:
            raise ValueError('SS2022 prefix source changed during compilation')
        identity = NODE.retained_binary(image)
        phases = execute_peer(image, source, captured, mode, form)
        if NODE.retained_binary(image) != identity or checked_sources(source)[1] != before:
            raise ValueError('SS2022 prefix compiled owner changed during execution')
        return {'schema': 1, 'gate': 'encrypted-ss-prefix-unit', 'mode': mode, 'form': form,
                'target': 'linux/' + architecture, 'pins': {'sing-box': BUILD.PIN, 'xray': BUILD.POLICY.XRAY.XRAY_PIN},
                'validator': validator_identity(), 'source_files': before, 'image_sha256': identity[-1],
                'phases': phases, 'scope': 'encrypted-reference-component',
                'installed_host_accepted': False, 'kernel_tun_accepted': False}



def published_identity(source_checkout, required_commit):
    return IDENTITY.capture_identity(source=source_checkout, validator=ROOT, source_sha=required_commit,
        base_sha=required_commit, suite=SUITE, repository=os.environ.get('GITHUB_REPOSITORY'),
        workflow_ref=os.environ.get('GITHUB_REF'))


def standalone(mode, form, go, required_commit, receipt, source_checkout):
    unit_phases(mode, form)
    if platform.system() != 'Linux':
        raise ValueError('SS2022 prefix standalone requires Linux')
    selection = published_identity(source_checkout, required_commit)
    repository = HOST.repository_identity(required_commit)
    if repository is None:
        raise ValueError('SS2022 prefix standalone requires an exact source commit')
    receipt = HOST.new_receipt_path(receipt)
    if receipt is None:
        raise ValueError('SS2022 prefix requires its durable unit receipt')
    compiler, captured, _ = NODE.selected_compiler(go, ROOT, dict(os.environ))
    if captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('SS2022 prefix requires native CGO')
    captured['CGO_ENABLED'] = '1'
    with prepared_native(compiler, captured) as (source, workspace):
        result = execute(source, mode, form, str(compiler), env=captured)
    if HOST.repository_identity(required_commit) != repository:
        raise ValueError('SS2022 prefix repository changed during execution')
    if published_identity(source_checkout, required_commit) != selection:
        raise ValueError('SS2022 prefix source/validator selection changed')
    result['selection'] = selection
    result['repository'] = repository
    HOST.publish_receipt(receipt, result, workspace)
    return result


def require_digest(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('SS2022 prefix receipt has an invalid source/image digest')


def check_receipt(receipt, repository, selection):
    if not isinstance(receipt, dict) or type(receipt.get('schema')) is not int or receipt['schema'] != 1:
        raise ValueError('SS2022 prefix receipt schema changed')
    mode, form = receipt.get('mode'), receipt.get('form')
    expected = unit_phases(mode, form)
    if (receipt.get('gate') != 'encrypted-ss-prefix-unit' or receipt.get('repository') != repository or
            receipt.get('selection') != selection or receipt.get('validator') != validator_identity() or receipt.get('target') != 'linux/amd64' or
            receipt.get('pins') != {'sing-box': BUILD.PIN, 'xray': BUILD.POLICY.XRAY.XRAY_PIN} or
            receipt.get('scope') != 'encrypted-reference-component' or receipt.get('installed_host_accepted') is not False or
            receipt.get('kernel_tun_accepted') is not False):
        raise ValueError('SS2022 prefix receipt lost its exact source, validator or scope')
    require_digest(receipt.get('image_sha256'))
    sources = receipt.get('source_files')
    if not isinstance(sources, dict) or not set((*BASE.ORIGINAL.REQUIRED, *BASE.REQUIRED, *REQUIRED)).issubset(sources):
        raise ValueError('SS2022 prefix receipt omitted its original source closure')
    for key, value in sources.items():
        if not isinstance(key, str) or not key:
            raise ValueError('SS2022 prefix source name changed')
        require_digest(value)
    for key, value in validator_identity().items():
        if sources.get('gate/' + key) != value:
            raise ValueError('SS2022 prefix source closure borrowed a different validator')
    phases = receipt.get('phases')
    if not isinstance(phases, list) or len(phases) != len(expected):
        raise ValueError('SS2022 prefix receipt omitted required native phases')
    for phase, wanted in zip(phases, expected):
        if not isinstance(phase, dict) or set(phase) != set(wanted) | {'output_sha256', 'image_sha256'}:
            raise ValueError('SS2022 prefix native phase shape changed')
        if any(phase.get(key) != value or type(phase.get(key)) is not type(value) for key, value in wanted.items()):
            raise ValueError('SS2022 prefix native phase belongs to another original path')
        if 'nodes' in wanted and (type(phase['nodes']) is not int or type(phase['samples']) is not int or
                any(type(position) is not int for position in phase['positions'])):
            raise ValueError('SS2022 prefix native measurement positions require exact integers')
        if phase['image_sha256'] != receipt['image_sha256']:
            raise ValueError('SS2022 prefix native phase borrowed another compiled image')
        require_digest(phase['output_sha256'])
    return (mode, form)


def strict_receipt(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 << 20:
        raise ValueError('SS2022 receipt is not a bounded original file')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('SS2022 receipt repeats an object field')
            result[key] = value
        return result
    def bad_constant(_):
        raise ValueError('SS2022 receipt contains a non-JSON numeric value')
    return json.loads(path.read_text(), object_pairs_hook=unique, parse_constant=bad_constant)


def contracts_identity(path, repository, selection, source_checkout):
    contracts = load('ss_prefix_aggregate_contracts', 'test_desktop_node_chain_ss_prefix_contract.py')
    receipt = strict_receipt(path)
    sources = contracts.check_receipt(receipt, repository, selection, contracts.CORE.snapshot(source_checkout))
    return sources, hashlib.sha256(Path(path).read_bytes()).hexdigest()


def aggregate(paths, required_commit, source_checkout, contracts_receipt):
    selection = published_identity(source_checkout, required_commit)
    repository = HOST.repository_identity(required_commit)
    if repository is None or len(paths) != 6:
        raise ValueError('SS2022 prefix aggregate requires six exact-source units')
    contract_sources, contract_digest = contracts_identity(contracts_receipt, repository, selection, source_checkout)
    units, source = {}, None
    for path in paths:
        path = Path(path)
        receipt = strict_receipt(path)
        unit = check_receipt(receipt, repository, selection)
        if unit in units:
            raise ValueError('SS2022 prefix aggregate duplicated a unit')
        if source is not None and receipt['source_files'] != source:
            raise ValueError('SS2022 prefix units were prepared from different source bytes')
        source = receipt['source_files']
        if any(contract_sources.get(key) != value for key, value in source.items()):
            raise ValueError('SS2022 encrypted and Box contracts borrowed different native source')
        units[unit] = {'receipt_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                       'image_sha256': receipt['image_sha256'], 'phases': len(receipt['phases'])}
    if set(units) != set(UNITS) or sum(item['phases'] for item in units.values()) != 42:
        raise ValueError('SS2022 prefix aggregate lost a required encrypted path/refusal')
    if HOST.repository_identity(required_commit) != repository or published_identity(source_checkout, required_commit) != selection:
        raise ValueError('SS2022 prefix aggregate source changed during validation')
    return {'schema': 1, 'gate': 'encrypted-ss-prefix-complete', 'repository': repository,
            'selection': selection, 'validator': validator_identity(), 'source_files': source,
            'units': {mode + '/' + form: units[(mode, form)] for mode, form in UNITS},
            'positive_phases': 36, 'refusal_phases': 6, 'phases': 42,
            'contracts_receipt_sha256': contract_digest,
            'scope': 'encrypted-reference-component', 'installed_host_accepted': False, 'kernel_tun_accepted': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=MODES)
    parser.add_argument('--form', choices=FORMS)
    parser.add_argument('--go', default='go')
    parser.add_argument('--require-commit', required=True)
    parser.add_argument('--source-checkout', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--aggregate', type=Path)
    parser.add_argument('--contracts', type=Path)
    args = parser.parse_args()
    if args.aggregate is not None:
        if args.mode is not None or args.form is not None or args.contracts is None:
            parser.error('aggregate requires contracts and cannot select a single unit')
        result = aggregate(sorted(args.aggregate.glob('*.json')), args.require_commit, args.source_checkout, args.contracts)
        path = HOST.new_receipt_path(args.receipt)
        with path.open('x', encoding='utf-8') as output:
            json.dump(result, output, indent=2, sort_keys=True)
            output.write('\n')
    else:
        if args.mode is None or args.form is None or args.contracts is not None:
            parser.error('native execution requires one complete mode/form unit')
        standalone(args.mode, args.form, args.go, args.require_commit, args.receipt, args.source_checkout)
