#!/usr/bin/env python3
"""Explicit disposable-Darwin typed CONNECT trio Server/Compare acceptance.

Real installed controller, inherited child, PF/utun and authenticated CONNECT/UoT relay are
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

BASE = load('imported_execution_original_host', 'test_macos_node_chain_host.py')
EXTERNAL, BUILD, CONTROLLER = BASE.EXTERNAL, BASE.BUILD, BASE.CONTROLLER
PROJECTOR = load('imported_execution_test_projection', 'prepare-desktop-imported-execution-test.py')
FLAG = 'ROUTERVPN_DARWIN_CONNECT_EXECUTION_HOST_ACCEPTANCE'
TEST = 'TestMacOSCONNECTTrioExecutionNative'
CASES = ('http-wg-server', 'http-awg-fast-auto-local', 'http-awg-strong-auto-server', 'https-awg-strong-server', 'https-wg-auto-local', 'https-awg-fast-auto-server', 'http-wrong-auth', 'https-wrong-auth', 'https-tls-name', 'http-wrong-public', 'https-wrong-final', 'https-failed-dns', 'http-replaced-source', 'https-held-cleanup')
ENTRY_LAYERS = {case: ('aes-256-gcm' if case in ('http-awg-fast-auto-local','https-awg-strong-server') else 'aes-256-gcm+xor-whitening' if case in ('http-awg-strong-auto-server','https-wg-auto-local') else 'off') for case in CASES}
PEER_TEMPLATE = 'mobile/desktop/node_chain_connect_execution_peer_test.go.tmpl'
PEER_TARGET = 'protocol/routervpnamnezia/routervpn_connect_execution_peer_test.go'
SOURCES = ('deploy/test_macos_connect_execution_host.py', 'deploy/test_macos_connect_execution_host_runner.py',
           'deploy/test_macos_imported_execution_alias.py', 'deploy/test_macos_imported_execution_alias_runner.py',
           'deploy/prepare-desktop-imported-execution-test.py', 'deploy/prepare-desktop-external.py', PEER_TEMPLATE,
           'cmd/client/desktop_connect_execution_darwin_native_test.go',
           'cmd/client/desktop_imported_execution_alias_darwin_test.go',
           'cmd/client/desktop_node_chain_imported_execution.go',
           'cmd/client/desktop_macos_connect_execution_process_arguments.go',
           'cmd/client/desktop_macos_connect_execution_process_arguments_test.go',
           'cmd/client/desktop_node_chain_execution_product.go', 'cmd/client/profile_public_view.go',
           'cmd/client/multihop_native_routes.go', 'client/macos/RouterVPNConnectionProfiles.swift',
           'deploy/native_multihop_audit.py', 'deploy/test_native_shipping_audit_gates.py',
           'cmd/client/controller_privilege_darwin_native_test.go',
           'cmd/client/desktop_imported_execution_darwin_native_test.go',
           'mobile/desktop/node_chain_imported_execution_peer_test.go.tmpl',
           'mobile/desktop/node_chain_connect_peer_test.go.tmpl',
           'mobile/desktop/node_imported_connect_entry_test.go.tmpl',
           'cmd/client/desktop_node_chain_connect_execution_product_test.go',
           'cmd/client/desktop_node_chain_connect_execution_profile_test.go')
SOURCE_TESTS = {'TestMacOSCONNECTExecutionProcessArgumentsRetainTypedPreparation': ('auto', 'server'), 'TestMacOSCONNECTExecutionProcessArgumentsRefuseSourceAndOwnerSubstitution': ('CONNECT', 'SOCKS', 'config', 'equal-copy-physical', 'equal-copy-preparation', 'execution-as-physical', 'generic-preparation', 'linux', 'nil-physical', 'nil-preparation', 'ordinary', 'prefix', 'session', 'source', 'unknown', 'windows')}

SOURCE_TESTS.update({
    'TestDesktopCONNECTTrioExecutionSelectionBounds': tuple(
        f'{protocol}/{mode}/{choice}' for protocol in ('http-connect', 'https-connect')
        for mode in ('wg', 'awg2-fast', 'awg2-strong') for choice in ('server', 'auto')),
    'TestDesktopCONNECTTrioExecutionSavedProfileRetainsSource': tuple(
        f'{protocol}/{choice}' for protocol in ('http-connect', 'https-connect')
        for choice in ('server', 'auto')),
})

def case_inventory(source=None):
    source = source if source is not None else (ROOT/'cmd/client/desktop_connect_execution_darwin_native_test.go').read_text()
    match = re.search(r'var macOSCONNECTExecutionCases = \[\]string\{([^}]+)\}', source)
    if match is None or tuple(re.findall(r'"([a-z0-9-]+)"', match[1])) != CASES or re.sub(r'"[a-z0-9-]+"|\s|,', '', match[1]):
        raise ValueError('Imported execution lost its exact native inventory')
    for anchor in ('a.nativeMultihopConnect(w, r)', 's.Current(ctx)', 'h.readReadyLocked(ctx, false)',
                   'a.speedLabSuspendPrevious(snapshot, false)', 'a.speedLabRestoreTemporary(snapshot)',
                   'reflect.DeepEqual(after.Ready.Progress.Comparison.Winner, before.Ready.Progress.Comparison.Winner)', 'aliases.Close(ctx, peer.close)',
                   'a.disconnect(result, request)', 'retained != owner', 'original.gate <- struct{}{}',
                   'restoreLaunches != expectedLaunches', 'len(result.Measurements) != 0',
                   'len(result.Measurements) != 2', 'math.Abs(*m.ScoreMS-(m.LastNodeMS/2+m.ExternalMS/2))'):
        if source.count(anchor) != 1:
            raise ValueError('Imported execution lost original public/proof/restore/cleanup boundary: '+anchor)
    return CASES


def peer_inventory(source=None):
    source = source if source is not None else (ROOT/PEER_TEMPLATE).read_text()
    anchors = ('mobilemultihop.NewNodeChainCONNECTSource(configure.LocalSource)',
               'mobilemultihop.NewNodeChainCONNECTServerPolicy(string(suffixRaw))',
               'peer.paired.final.streamRouter = UOT.NewRouter(',
               'desktopStartImportedCONNECTPeerAt(', 'runner := &importedExecutionRunner{',
               'request.Layers.Final != "off"', 'request.Layers.validate(request.Peer)',
               'proxyCapture.Username != request.Username', 'proxyCapture.Password != request.Password',
               'proxyCapture.TLSServerName != expectedName', 'policy.NativeCarrierRequired()',
               'layers.entryProvider(t, layerRequest, peer, local)', 'provider.awaitCertificateRefusal(ctx)',
               'router.streams.Load() != 0')
    for anchor in anchors:
        if source.count(anchor)!=1:raise ValueError('CONNECT execution lost original peer boundary: '+anchor)
    if 'mobilemultihop.NewNodeChainServerPolicy(' in source or 'mobilemultihop.NewNodeChain(configure.LocalSource)' in source:
        raise ValueError('Typed CONNECT peer borrowed generic parser authority')
    return anchors


def receipt(case):
    if case not in CASES:
        raise ValueError('Unknown CONNECT execution case')
    auto = '-auto-' in case
    negative = case in CASES[6:12]
    restored = case in CASES[:6]
    return ('DARWIN_CONNECT_EXECUTION_RECEIPT case='+case+' requested='+('auto' if auto else 'server')+
            ' winner='+('local' if case.endswith('-auto-local') else 'server')+
            ' negative='+str(negative).lower()+' restored='+str(restored).lower()+
            ' cleanup_retry='+str(case=='https-held-cleanup').lower()+
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
        if 'DARWIN_CONNECT_EXECUTION_COUNTERS' in line:
            match = re.fullmatch(r'\s+desktop_connect_execution_darwin_native_test.go:\d+: DARWIN_CONNECT_EXECUTION_COUNTERS (.*)', line)
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
            expected_keys = {'case','launches','entry_raw_udp','entry_tcp','entry_proofs',
                             'middle_raw_tcp','middle_tcp','middle_public','final_raw_tcp','final_tcp','final_proofs','dns',
                             'middle_raw_udp','final_raw_udp','auth_refusals','tls_refusals','open_streams','entry_layer','entry_layer_packets','entry_layer_ciphertext','entry_layer_auth','restore_launches','comparison_trials'}
            if not isinstance(value,dict) or set(value)!=expected_keys or value['case']!=case:
                raise ValueError('CONNECT native counters changed original identity')
            for key in expected_keys-{'case','entry_layer'}:
                if type(value[key]) is not int or value[key]<0:
                    raise ValueError('CONNECT counter is not a nonnegative actual integer')
            expected_trials = 2 if '-auto-' in case else 0
            expected_restore = int(case in CASES[:6] and not case.endswith('auto-local'))
            if value['comparison_trials'] != expected_trials or value['restore_launches'] != expected_restore:
                raise ValueError('CONNECT replaced original comparison or reran retained choice')
            if value['entry_layer']!=ENTRY_LAYERS[case] or value['entry_layer_auth']!=0:
                raise ValueError('CONNECT entry layer source/authentication changed')
            if ENTRY_LAYERS[case]=='off':
                if value['entry_layer_packets']!=0 or value['entry_layer_ciphertext']!=0:raise ValueError('Off borrowed native layer counters')
            elif value['entry_layer_packets']<=0 or value['entry_layer_ciphertext']<=0:
                raise ValueError('CONNECT original layered prefix omitted actual encrypted packets')
            if any(value[key]<=0 for key in ('launches','entry_raw_udp','entry_tcp','entry_proofs','middle_raw_tcp')):
                raise ValueError('CONNECT failed before its captured encrypted prefix/worker/proxy')
            if any(value[key]!=0 for key in ('middle_raw_udp','final_raw_udp','open_streams')):
                raise ValueError('CONNECT retained an open stream or acquired raw UDP authority')
            if case in ('http-wrong-auth','https-wrong-auth','https-tls-name'):
                expected_refusal='tls_refusals' if case=='https-tls-name' else 'auth_refusals'
                other_refusal='auth_refusals' if case=='https-tls-name' else 'tls_refusals'
                if value[expected_refusal]<=0 or value[other_refusal]!=0 or any(value[key]!=0 for key in ('middle_tcp','middle_public','final_proofs','dns')):
                    raise ValueError('CONNECT negative did not reach its original authentication boundary')
            else:
                if value['auth_refusals']!=0 or value['tls_refusals']!=0 or value['middle_tcp']<=0 or value['middle_public']<=0:
                    raise ValueError('CONNECT path lost authenticated public predecessor')
                if case=='http-wrong-public':
                    if value['final_proofs']!=0 or value['dns']!=0:raise ValueError('wrong public source acquired final proof')
                elif case=='https-wrong-final':
                    if value['final_raw_tcp']<=0 or value['final_tcp']!=0 or value['final_proofs']!=0 or value['dns']!=0:raise ValueError('wrong final key escaped original encrypted boundary')
                elif any(value[key]<=0 for key in ('final_raw_tcp','final_tcp','final_proofs','dns')):
                    raise ValueError('CONNECT omitted original final proof/selected DNS')
            observations.append(value)
        if 'DARWIN_CONNECT_EXECUTION_RECEIPT' in line:
            match = re.fullmatch(r'\s+desktop_connect_execution_darwin_native_test.go:\d+: (DARWIN_CONNECT_EXECUTION_RECEIPT .*)', line)
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
    peer_inventory()
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
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', '--identifier', 'routervpn.fixture.connect.execution.controller', str(controller)], check=True, timeout=30)
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
        value = dict(schema=1, gate='darwin-connect-trio-execution', target=target, native=True,
                     repository=repository, source_sha256=policy, bundle_sha256=original_hash,
                     sealed_bundle_sha256=signed_hash, validation_toolchain=CONTROLLER.UID.RACE.TOOLCHAIN,
                     images=images, sources=before, cases=list(CASES), completed=list(outputs), outputs=outputs,
                     source_outputs=source_outputs, alias_controls=alias_receipt, peer_close_controls=peer_close,
                     scope='literal-authenticated-http-https-trio-public-server-compare-native-pf-utun',
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
