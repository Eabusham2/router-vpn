#!/usr/bin/env python3
"""Independent paired Start Layers on the exact Darwin imported literal SS trio.

Real installed controller, inherited child, PF/utun and encrypted SS relay are
required. HTTP administration authentication and direct test worker launch are
fixture adapters; this receipt does not certify remote Linux packet carriers.
"""
from pathlib import Path
from collections import Counter
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

ORIGINAL = load('imported_layers_original_gate', 'test_macos_imported_execution_host.py')
BASE, EXTERNAL, BUILD, CONTROLLER, PROJECTOR = ORIGINAL.BASE, ORIGINAL.EXTERNAL, ORIGINAL.BUILD, ORIGINAL.CONTROLLER, ORIGINAL.PROJECTOR
FLAG = 'ROUTERVPN_DARWIN_IMPORTED_EXECUTION_LAYERS_HOST_ACCEPTANCE'
TEST = 'TestMacOSImportedTrioExecutionLayersNative'
LAYER_SOURCE = 'cmd/client/desktop_imported_execution_layers_darwin_native_test.go'
PEER_TEMPLATE = 'mobile/desktop/node_chain_imported_execution_layers_peer_test.go.tmpl'
PEER_TARGET = 'protocol/routervpnamnezia/routervpn_imported_execution_layers_peer_test.go'
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
VECTORS = (
 ('awg2-fast-off-aes-auto-server','awg2-fast',LAYERS[0],LAYERS[1],'auto','server',''),
 ('awg2-strong-off-xor-auto-local','awg2-strong',LAYERS[0],LAYERS[2],'auto','local',''),
 ('awg2-fast-aes-off-auto-local','awg2-fast',LAYERS[1],LAYERS[0],'auto','local',''),
 ('awg2-strong-aes-aes-server','awg2-strong',LAYERS[1],LAYERS[1],'server','server',''),
 ('wg-aes-xor-auto-server','wg',LAYERS[1],LAYERS[2],'auto','server',''),
 ('awg2-strong-xor-off-auto-server','awg2-strong',LAYERS[2],LAYERS[0],'auto','server',''),
 ('wg-xor-aes-auto-local','wg',LAYERS[2],LAYERS[1],'auto','local',''),
 ('awg2-fast-xor-xor-server','awg2-fast',LAYERS[2],LAYERS[2],'server','server',''),
 ('wg-entry-aes-wrong-key','wg',LAYERS[1],LAYERS[0],'server','server','entry-layer-key'),
 ('awg2-fast-entry-xor-wrong-key','awg2-fast',LAYERS[2],LAYERS[0],'server','server','entry-layer-key'),
 ('awg2-strong-entry-xor-wrong-whitening','awg2-strong',LAYERS[2],LAYERS[0],'server','server','entry-whitening'),
 ('wg-final-aes-wrong-key','wg',LAYERS[0],LAYERS[1],'server','server','final-layer-key'),
 ('awg2-fast-final-xor-wrong-key','awg2-fast',LAYERS[0],LAYERS[2],'server','server','final-layer-key'),
 ('awg2-strong-final-xor-wrong-whitening','awg2-strong',LAYERS[0],LAYERS[2],'server','server','final-whitening'),
)
CASES = tuple(row[0] for row in VECTORS)
SOURCES = (*ORIGINAL.SOURCES, LAYER_SOURCE, PEER_TEMPLATE,
 'mobile/desktop/node_imported_peer_linux_test.go.tmpl', 'mobile/desktop/node_chain_imported_test.go.tmpl',
 'cmd/client/desktop_node_chain_imported_execution_layers_test.go',
 'deploy/test_macos_imported_execution_layers_host.py', 'deploy/test_macos_imported_execution_layers_host_runner.py')
SOURCE_TESTS = {'TestDesktopDarwinImportedTrioIndependentLayers': tuple(
 f'{mode}/{entry}/{final}/{choice}' for mode in ('wg','awg2-fast','awg2-strong')
 for entry in LAYERS for final in LAYERS for choice in ('server','auto'))}


def case_inventory(source=None):
    ORIGINAL.case_inventory()
    source = (ROOT/LAYER_SOURCE).read_text() if source is None else source
    match = re.search(r'var macOSImportedExecutionLayerCases = \[\]macOSImportedExecutionLayerCase\{(.*?)\n\}', source, re.S)
    if not match:
        raise ValueError('Missing independent layer inventory')
    rows = tuple(tuple(re.findall(r'"([^"\n]*)"', row)) for row in re.findall(r'\{([^{}]+)\}', match[1]))
    if rows != VECTORS or re.sub(r'\{[^{}]+\}|[\s,]', '', match[1]):
        raise ValueError('Independent layer inventory differs from exact original pairs')
    for anchor in ('macOSImportedExecutionCheckLayers(', 'macOSImportedExecutionLogLayers(',
                   'entry.AuthUDP == 0', 'last.AuthTCP == 0', 'observed.Final.DNSQueries == 0'):
        if anchor not in source:
            raise ValueError('Missing actual encrypted layer boundary: '+anchor)
    return CASES


def receipt(case):
    if case not in CASES: raise ValueError('Unknown independent layer case')
    name, mode, entry, final, requested, winner, fault = VECTORS[CASES.index(case)]
    return (f'DARWIN_IMPORTED_EXECUTION_RECEIPT case={name} requested={requested} winner={winner}'
            f' negative={str(bool(fault)).lower()} restored={str(not fault).lower()}'
            ' native_joined=true relay_joined=true aliases_retired=true')


def strict_pairs(values):
    result = {}
    for key, value in values:
        if key in result: raise ValueError('Duplicate original layer observation')
        result[key] = value
    return result


def check_observation(value, case):
    row=VECTORS[CASES.index(case)]
    _, _, entry, final, _, _, fault=row
    fields={'case','entry','final','fault','layers','launches','entry_packets','entry_proofs','middle_public','final_proofs','dns'}
    if not isinstance(value,dict) or set(value)!=fields or (value['case'],value['entry'],value['final'],value['fault'])!=(case,entry,final,fault):
        raise ValueError('Layer counters borrowed another source or case')
    for key in fields-{'case','entry','final','fault','layers'}:
        if type(value[key]) is not int or value[key]<0: raise ValueError('Invalid layer counter')
    layers=value['layers']; keys={'entry','final','final_transport'} | ({'entry_transport'} if entry!='off' else set())
    if not isinstance(layers,dict) or set(layers)!=keys or layers['entry']!=entry or layers['final']!=final:
        raise ValueError('Layer owner or independent choice absent')
    def transport(record):
        names={'method','address','physical_tcp','physical_udp','streams','packets','public_replies','auth_tcp','auth_udp'}
        if not isinstance(record,dict) or set(record)!=names or record['method']!='2022-blake3-aes-256-gcm':
            raise ValueError('Wrong captured layer transport')
        if not isinstance(record['address'],str) or not re.fullmatch(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[1-9][0-9]{0,4}',record['address']):
            raise ValueError('Missing original layer address')
        if any(type(record[k]) is not int or record[k]<0 for k in names-{'method','address'}):
            raise ValueError('Invalid transport counters')
        return record
    last=transport(layers['final_transport'])
    if entry!='off':
        first=transport(layers['entry_transport'])
        if first['physical_udp']<=0: raise ValueError('No original entry ciphertext')
        if fault.startswith('entry-'):
            if first['auth_udp']<=0 or first['packets']!=0 or any(value[k]!=0 for k in ('launches','entry_packets','entry_proofs','middle_public','final_proofs','dns')):
                raise ValueError('Entry authentication refusal not proved')
            return
        if first['packets']<=0 or first['auth_udp']!=0: raise ValueError('Entry layer did not decrypt')
    if any(value[k]<=0 for k in ('launches','entry_packets','entry_proofs','middle_public')):
        raise ValueError('Missing original entry or imported public proof')
    if last['physical_tcp']<=0: raise ValueError('Missing final ciphertext')
    if fault.startswith('final-'):
        if last['auth_tcp']<=0 or last['streams']!=0 or value['final_proofs']!=0 or value['dns']!=0:
            raise ValueError('Final authentication refusal not proved')
    elif last['streams']<=0 or last['auth_tcp']!=0 or value['final_proofs']<=0 or value['dns']<=0:
        raise ValueError('Final identity or selected DNS missing')


def check_verdict(output, case):
    if case not in CASES: raise ValueError('Unknown independent layer case')
    BASE.check_authority_verdict(output,selected=(TEST,(TEST,TEST+'/'+case)))
    active=complete=False; receipts=[]; observations=[]
    for line in output.splitlines():
        if line=='=== RUN   '+TEST+'/'+case: active=True
        if re.match(r'\s*--- PASS: ',line): complete=True
        if 'DARWIN_IMPORTED_EXECUTION_LAYERS' in line:
            match=re.fullmatch(r'\s+desktop_imported_execution_layers_darwin_native_test.go:\d+: DARWIN_IMPORTED_EXECUTION_LAYERS (.*)',line)
            if not match or not active or complete: raise ValueError('Layer observation outside original case')
            try: value=json.loads(match[1],object_pairs_hook=strict_pairs)
            except (TypeError,json.JSONDecodeError) as error: raise ValueError('Malformed layer observation') from error
            check_observation(value,case); observations.append(value)
        if 'DARWIN_IMPORTED_EXECUTION_RECEIPT' in line:
            match=re.fullmatch(r'\s+desktop_imported_execution_darwin_native_test.go:\d+: (DARWIN_IMPORTED_EXECUTION_RECEIPT .*)',line)
            if not match or not active or complete: raise ValueError('Layer receipt outside original case')
            receipts.append(match[1])
    if receipts!=[receipt(case)] or len(observations)!=1: raise ValueError('Missing exact original layer ownership receipt')


def source_identity(core):
    value=ORIGINAL.source_identity(core)
    for name in SOURCES: value['application'][name]=EXTERNAL.sha(ROOT/name)
    preparer=load('layer_source_preparer','prepare-desktop-external.py')
    copies=preparer.darwin_node_chain_peer_copies()
    expected={PEER_TARGET:(ROOT/PEER_TEMPLATE).read_bytes()}
    for template in ('node_imported_peer_linux_test.go.tmpl','node_chain_imported_test.go.tmpl'):
        expected[preparer.PEER_TEMPLATES[template]]=(ROOT/'mobile/desktop'/template).read_bytes()
        target=preparer.DARWIN_NODE_CHAIN_PEERS[template]; expected[target]=copies[target]
    for name,raw in expected.items():
        digest=EXTERNAL.sha(Path(core)/name)
        if digest!=hashlib.sha256(raw).hexdigest(): raise ValueError('Layer provider source changed: '+name)
        value['peer'][name]=digest
    return value


def required_host(environment):
    if environment.get(FLAG) != '1' or 'HOMEVPN_MTU_BENCH_FAKE' in environment:
        raise ValueError('Imported execution requires explicit disposable Darwin admission')
    captured = dict(environment)
    captured[EXTERNAL.FLAG] = "1"
    return EXTERNAL.required_host(captured)


def execute(bundle, source=None, go='go', environment=None, *, required_commit=None, receipt_file=None):
    environment = dict(os.environ if environment is None else environment)
    target, uid = required_host(environment)
    repository = BASE.repository_identity(required_commit)
    if receipt_file is not None and repository is None:
        raise ValueError('Durable imported execution receipt requires exact published commit')
    case_inventory()
    compiler, captured = CONTROLLER.UID.compiler_toolchain(ROOT, go, environment)
    captured['CGO_ENABLED'] = '1'
    bundle = Path(bundle).resolve()
    original = BUILD.reuse(bundle, target, env=captured)
    original_hash, policy = EXTERNAL.sha(bundle/'NATIVE-RUNTIME.json'), BUILD.digest()
    python, sudo = CONTROLLER.discover_python(uid), CONTROLLER.UID.privilege_tool()
    with tempfile.TemporaryDirectory(prefix='routervpn-imported-execution-') as temporary:
        work = Path(temporary).resolve()
        work.chmod(0o755)
        core = Path(source).resolve() if source else EXTERNAL.prepared_peer_source(work, captured)
        before = source_identity(core)
        race_compiler, race_environment = CONTROLLER.UID.RACE.capture(core, compiler, captured)
        # Executes actual extracted alias ownership and mutation witnesses before
        # any host alias/keychain/PF state is touched by the native fixture.
        alias = load('imported_execution_alias_controls', 'test_macos_imported_execution_alias.py')
        alias_receipt = alias.execute(root=ROOT, go=str(race_compiler))
        runner = load('imported_execution_peer_close_controls', 'test_macos_imported_execution_host_runner.py')
        peer_close = runner.execute_peer_close_controls(ROOT, str(race_compiler), race_environment)
        signed = work/'sealed-bundle'
        shutil.copytree(bundle, signed, symlinks=True)
        subprocess.run([os.sys.executable, str(ROOT/'deploy/seal-native-runtime.py'), str(signed), target], cwd=ROOT, env=captured, check=True, timeout=300)
        BUILD.reuse(signed, target, env=captured)
        signed_hash = EXTERNAL.sha(signed/'NATIVE-RUNTIME.json')
        controller, peer = work/'controller.test', work/'peer.test'
        for command, cwd in (
            ([str(race_compiler), 'test', '-race', '-c', '-mod=readonly', '-tags=routervpn_controller_privileged', '-o', str(controller), './cmd/client'], ROOT),
            ([str(race_compiler), 'test', '-race', '-c', '-mod=readonly', '-tags='+BASE.PEER_TAGS, '-ldflags=-checklinkname=0', '-o', str(peer), './protocol/routervpnamnezia'], core),
        ):
            subprocess.run(command, cwd=cwd, env=race_environment, check=True, timeout=300)
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', '--identifier', 'routervpn.fixture.imported.execution.controller', str(controller)], check=True, timeout=30)
        controller.chmod(0o755); peer.chmod(0o755)
        images = dict(controller=EXTERNAL.sha(controller), peer=EXTERNAL.sha(peer))
        source_outputs = {}
        for root, leaves in SOURCE_TESTS.items():
            result = subprocess.run([str(controller), '-test.v', '-test.count=1', '-test.timeout=120s', '-test.run=^'+root+'$'], cwd=ROOT, env=race_environment, check=True, timeout=130, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            print(result.stdout, end='', flush=True)
            BASE.check_authority_verdict(result.stdout, selected=(root, (root, *(root+'/'+leaf for leaf in leaves))))
            source_outputs[root] = hashlib.sha256(result.stdout.encode()).hexdigest()
        outputs = {}
        for case in CASES:
            if source_identity(core) != before or BUILD.digest() != policy or any(EXTERNAL.sha(path) != images[name] for name, path in (('controller', controller), ('peer', peer))):
                raise ValueError('Imported execution source or images changed before native admission')
            command = ['/usr/bin/env', 'ROUTERVPN_MACOS_CONTROLLER_PRIVILEGE_FIXTURE=1',
                       'ROUTERVPN_MACOS_FIXTURE_UID='+str(uid), 'ROUTERVPN_MACOS_FIXTURE_SOURCE='+str(ROOT),
                       'ROUTERVPN_MACOS_FIXTURE_PYTHON='+str(Path(python).absolute()),
                       'ROUTERVPN_MACOS_NODE_CHAIN_PEER='+str(peer), 'ROUTERVPN_MACOS_NODE_CHAIN_PEER_SHA256='+images['peer'],
                       'ROUTERVPN_MACOS_EXTERNAL_BUNDLE='+str(signed), 'ROUTERVPN_MACOS_EXTERNAL_BUNDLE_SHA256='+signed_hash,
                       'GORACE=atexit_sleep_ms=0', str(controller), '-test.v', '-test.count=1', '-test.timeout=240s', '-test.run=^'+TEST+'$/^'+case+'$']
            if sudo:
                command = [sudo, '-n', '--', *command]
            output = CONTROLLER.reported_run(command, cwd=ROOT, env=captured, timeout=250, sudo=sudo)
            print(output, end='', flush=True)
            check_verdict(output, case)
            outputs[case] = hashlib.sha256(output.encode()).hexdigest()
        if (source_identity(core) != before or BUILD.digest() != policy or BASE.repository_identity(required_commit) != repository or
            any(EXTERNAL.sha(path) != images[name] for name, path in (('controller', controller), ('peer', peer))) or
            BUILD.reuse(bundle, target, env=captured) != original or EXTERNAL.sha(bundle/'NATIVE-RUNTIME.json') != original_hash or
            EXTERNAL.sha(signed/'NATIVE-RUNTIME.json') != signed_hash):
            raise ValueError('Imported execution lost final original source/image/bundle identity')
        value = dict(schema=1, gate='darwin-imported-trio-execution-layers', target=target, native=True,
                     repository=repository, source_sha256=policy, bundle_sha256=original_hash,
                     sealed_bundle_sha256=signed_hash, validation_toolchain=CONTROLLER.UID.RACE.TOOLCHAIN,
                     images=images, sources=before, cases=list(CASES), completed=list(outputs), outputs=outputs,
                     source_outputs=source_outputs, alias_controls=alias_receipt, peer_close_controls=peer_close,
                     scope='literal-imported-trio-independent-paired-layers-public-server-compare-native-pf-utun',
                     administration='fixture-authenticated-private-http', worker_launch='fixture-direct-original-image',
                     remote_linux_packet_carrier=False)
        if receipt_file is not None:
            BASE.write_receipt(receipt_file, value)
        print('Native Darwin imported execution acceptance: '+json.dumps(value, sort_keys=True, separators=(',', ':')), flush=True)
        return value

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--go', default=os.environ.get('GO', 'go'))
    parser.add_argument('--require-commit')
    parser.add_argument('--receipt', type=Path)
    options = parser.parse_args()
    execute(options.bundle, options.source, options.go, required_commit=options.require_commit, receipt_file=options.receipt)
