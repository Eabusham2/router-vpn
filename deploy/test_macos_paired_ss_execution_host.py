#!/usr/bin/env python3
"""Explicit disposable-Darwin paired two-node Server/Compare acceptance.

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

BASE = load('paired_ss_execution_original_host', 'test_macos_node_chain_host.py')
EXTERNAL, BUILD, CONTROLLER = BASE.EXTERNAL, BASE.BUILD, BASE.CONTROLLER
PROJECTOR = load('imported_execution_test_projection', 'prepare-desktop-imported-execution-test.py')
FLAG = 'ROUTERVPN_DARWIN_PAIRED_SS_EXECUTION_HOST_ACCEPTANCE'
TEST = 'TestMacOSPairedSSExecutionNative'
CASES = ('wg-server', 'awg2-fast-server', 'awg2-strong-server',
         'wg-auto-local', 'awg2-fast-auto-local', 'awg2-strong-auto-local',
         'wg-auto-server', 'awg2-fast-auto-server', 'awg2-strong-auto-server',
         'wg-wrong-public', 'wg-wrong-final', 'wg-failed-dns', 'wg-replaced-source', 'wg-wrong-final-key')
PEER_TEMPLATE = 'mobile/desktop/node_chain_paired_ss_execution_peer_test.go.tmpl'
PEER_TARGET = 'protocol/routervpnamnezia/routervpn_paired_ss_execution_peer_test.go'
SOURCES = ('deploy/test_macos_paired_ss_execution_host.py', 'deploy/test_macos_paired_ss_execution_host_runner.py',
           'deploy/test_macos_imported_execution_alias.py', 'deploy/test_macos_imported_execution_alias_runner.py',
           'deploy/prepare-desktop-imported-execution-test.py', 'deploy/prepare-desktop-external.py', PEER_TEMPLATE,
           'cmd/client/desktop_paired_ss_execution_darwin_native_test.go',
           'cmd/client/desktop_imported_execution_alias_darwin_test.go',
           'cmd/client/desktop_node_chain_imported_execution_platform.go',
           'cmd/client/desktop_node_chain_imported_execution_platform_test.go',
           'cmd/client/desktop_node_chain_execution_product.go', 'cmd/client/profile_public_view.go',
           'cmd/client/multihop_native_routes.go', 'client/macos/RouterVPNConnectionProfiles.swift',
           'deploy/native_multihop_audit.py',
           'cmd/client/desktop_node_chain_imported_execution_darwin_prefix_test.go',
           'cmd/client/desktop_node_chain_imported_prefix_execution_test.go',
           'modes/kill-switch-platform.py', 'modes/test_darwin_owned_pf.py')
PARENT = load('paired_ss_execution_parent', 'test_desktop_paired_ss_execution_controller.py')
SOURCE_TESTS = {**PARENT.SOURCE, **PARENT.DARWIN}
SOURCES += ('cmd/client/desktop_node_chain_paired_ss_execution.go',
            'cmd/client/desktop_node_chain_paired_ss_execution_test.go',
            'cmd/client/desktop_node_chain_paired_ss_execution_darwin_test.go',
            'cmd/client/controller_privilege_darwin_native_test.go',
            'cmd/client/desktop_imported_execution_darwin_native_test.go',
            'mobile/desktop/node_chain_peer_linux_test.go.tmpl',
            'mobile/desktop/node_external_ss_entry_test.go.tmpl',
            'mobile/desktop/node_chain_imported_execution_peer_test.go.tmpl',
            'internal/mobilemultihop/node_chain_server_carrier_other.go')


def case_inventory(source=None):
    source = source if source is not None else (ROOT/SOURCES[7]).read_text()
    match = re.search(r'var macOSPairedSSExecutionCases = \[\]string\{([^}]+)\}', source)
    if match is None or tuple(re.findall(r'"([a-z0-9-]+)"', match[1])) != CASES or re.sub(r'"[a-z0-9-]+"|\s|,', '', match[1]):
        raise ValueError('Imported execution lost its exact native inventory')
    for anchor in ('a.nativeMultihopConnect(w, r)', 'macOSImportedExecutionObserve(r.Context(), a)',
                   'a.speedLabSuspendPrevious(snapshot, false)', 'a.speedLabRestoreTemporary(snapshot)',
                   'reflect.DeepEqual(after.Comparison, before.Comparison)', 'aliases.Close(ctx, peer.close)'):
        if source.count(anchor) != 1:
            raise ValueError('Imported execution lost original public/proof/restore/cleanup boundary: '+anchor)
    return CASES


def receipt(case):
    if case not in CASES:
        raise ValueError('Unknown imported execution case')
    auto = '-auto-' in case
    negative = case in CASES[9:12] or case == 'wg-wrong-final-key'
    restored = case in CASES[:9]
    return ('DARWIN_PAIRED_SS_EXECUTION_RECEIPT case='+case+' requested='+('auto' if auto else 'server')+
            ' winner='+('local' if case.endswith('-auto-local') else 'server')+
            ' negative='+str(negative).lower()+' restored='+str(restored).lower()+
            ' native_joined=true relay_joined=true aliases_retired=true')


def check_verdict(output, case):
    if case not in CASES:
        raise ValueError('Unknown imported execution case')
    BASE.check_authority_verdict(output, selected=(TEST, (TEST, TEST+'/'+case)))
    lines = output.splitlines()
    expected = receipt(case)
    records, observations = [], []
    active, complete = False, False
    for line in lines:
        if line == '=== RUN   '+TEST+'/'+case:
            active = True
        if re.match(r'\s*--- PASS: ', line):
            complete = True
        if 'DARWIN_PAIRED_SS_EXECUTION_COUNTERS' in line:
            match = re.fullmatch(r'\s+desktop_paired_ss_execution_darwin_native_test.go:\d+: DARWIN_PAIRED_SS_EXECUTION_COUNTERS (.*)', line)
            if not match or not active or complete:
                raise ValueError('Imported counters are outside the original running case')
            def pairs(values):
                result = {}
                for key, value in values:
                    if key in result:
                        raise ValueError('Duplicated imported native counter')
                    result[key] = value
                return result
            try:
                value = json.loads(match[1], object_pairs_hook=pairs)
            except (TypeError, json.JSONDecodeError) as error:
                raise ValueError('Malformed imported native counters') from error
            expected_keys = {'case', 'launches', 'entry_raw_udp', 'entry_proofs', 'final_raw_tcp', 'final_tcp', 'final_proofs', 'dns', 'auth_tcp'}
            if not isinstance(value, dict) or set(value) != expected_keys or value['case'] != case:
                raise ValueError('Imported native counters borrowed a different source/case')
            for key in expected_keys-{'case'}:
                minimum = 0 if key in ('final_raw_tcp', 'final_tcp', 'final_proofs', 'dns', 'auth_tcp') else 1
                if type(value[key]) is not int or value[key] < minimum:
                    raise ValueError('Imported native boundary has no actual encrypted counter: '+key)
            if case == 'wg-wrong-final-key':
                if value['final_raw_tcp'] <= 0 or value['auth_tcp'] <= 0 or any(value[key] != 0 for key in ('final_tcp','final_proofs','dns')):
                    raise ValueError('Wrong final key did not reach original authentication refusal')
            elif any(value[key] <= 0 for key in ('final_raw_tcp', 'final_tcp', 'final_proofs')):
                raise ValueError('Paired execution failed before actual final private proof')
            if case == 'wg-wrong-final' and value['dns'] != 0:
                raise ValueError('Wrong final identity reached DNS')
            if case not in (*CASES[9:12], 'wg-wrong-final-key') and value['dns'] <= 0:
                raise ValueError('Paired execution omitted selected DNS')
            observations.append(value)
        if 'DARWIN_PAIRED_SS_EXECUTION_RECEIPT' in line:
            match = re.fullmatch(r'\s+desktop_paired_ss_execution_darwin_native_test.go:\d+: (DARWIN_PAIRED_SS_EXECUTION_RECEIPT .*)', line)
            if not match or not active or complete:
                raise ValueError('Imported execution receipt is outside its original running case')
            records.append(match[1])
    if records != [expected] or len(observations) != 1:
        raise ValueError('Imported execution lacks exact public, restoration and joined ownership receipt')


def source_identity(core):
    value = BASE.source_identity(core)
    for name in (*SOURCES, *PROJECTOR.SOURCES):
        value['application'][name] = EXTERNAL.sha(ROOT/name)
    expected = {**PROJECTOR.copies(), PEER_TARGET: (ROOT/PEER_TEMPLATE).read_bytes()}
    for name, raw in expected.items():
        digest = EXTERNAL.sha(Path(core)/name)
        if digest != hashlib.sha256(raw).hexdigest():
            raise ValueError('Imported execution generated source differs from actual shipping owner: '+name)
        value['peer'][name] = digest
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
        value = dict(schema=1, gate='darwin-paired-ss-direct-execution', target=target, native=True,
                     repository=repository, source_sha256=policy, bundle_sha256=original_hash,
                     sealed_bundle_sha256=signed_hash, validation_toolchain=CONTROLLER.UID.RACE.TOOLCHAIN,
                     images=images, sources=before, cases=list(CASES), completed=list(outputs), outputs=outputs,
                     source_outputs=source_outputs, alias_controls=alias_receipt, peer_close_controls=peer_close,
                     scope='paired-wg-awg-ss-two-node-off-layer-public-server-compare-native-pf-utun',
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
