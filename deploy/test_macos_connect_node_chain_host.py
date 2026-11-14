#!/usr/bin/env python3
"""Installed CONNECT host gate; original37 and SOCKS8 precede22 actual HTTP(S) cases."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('connect_host_original', ROOT/'deploy/test_macos_node_chain_host.py')
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
socks_spec = importlib.util.spec_from_file_location('connect_host_socks', ROOT/'deploy/test_macos_socks_node_chain_host.py')
SOCKS = importlib.util.module_from_spec(socks_spec)
socks_spec.loader.exec_module(SOCKS)
BUILD, CONTROLLER, EXTERNAL = BASE.BUILD, BASE.CONTROLLER, BASE.EXTERNAL
PEER_TAGS = BASE.PEER_TAGS
TEST = 'TestMacOSRetainedNodeChainCONNECTNativeHost'
FLAG = 'ROUTERVPN_DARWIN_CONNECT_NODE_CHAIN_HOST_ACCEPTANCE'
AUTHORITY_TEST = 'TestDesktopDarwinInstalledCONNECTNodeChainFixtureKeepsOriginalSources'
AUTHORITY_CASES = (AUTHORITY_TEST, *(AUTHORITY_TEST+'/'+name for name in ('http-wg','http-awg-fast','http-awg-strong','https-wg','https-awg-fast','https-awg-strong')))
AUTHORITY_SOURCE = 'cmd/client/desktop_node_chain_connect_darwin_native_test.go'
SOURCE_CONTROL = 'installed source changed original CONNECT credential or invented paired assets'
CASES = (
    'node-chain-http-connect-wg-connect',
    'node-chain-http-connect-awg-fast-connect',
    'node-chain-http-connect-awg-strong-connect',
    'node-chain-http-connect-wg-wrong-middle-key',
    'node-chain-http-connect-wg-wrong-middle-user',
    'node-chain-http-connect-wg-wrong-middle-public',
    'node-chain-http-connect-wg-final-dns-failure',
    'node-chain-http-connect-wg-final-node-failure',
    'node-chain-http-connect-wg-middle-source',
    'node-chain-http-connect-wg-prefix-lost',
    'node-chain-https-connect-wg-connect',
    'node-chain-https-connect-awg-fast-connect',
    'node-chain-https-connect-awg-strong-connect',
    'node-chain-https-connect-wg-wrong-middle-key',
    'node-chain-https-connect-wg-wrong-middle-user',
    'node-chain-https-connect-wg-wrong-middle-public',
    'node-chain-https-connect-wg-final-dns-failure',
    'node-chain-https-connect-wg-final-node-failure',
    'node-chain-https-connect-wg-middle-source',
    'node-chain-https-connect-wg-prefix-lost',
    'node-chain-https-connect-wg-tls-name',
    'node-chain-https-connect-wg-tls-trust',
)
MEASUREMENT_CASES = tuple(case for case in CASES if case.endswith(("-connect", "-middle-source", "-prefix-lost")))
FIFTY_RECEIPT = "actual installed Darwin CONNECT fifty: all three original members returned fifty samples and retained exact durable receipts"
STREAMS_RECEIPT = "actual installed Darwin CONNECT streams: original authenticated TCP owners joined before controller release"
SOURCES = (
    'deploy/test_macos_connect_node_chain_host.py', 'deploy/test_macos_connect_node_chain_host_runner.py',
    'cmd/client/connection_profile_node_chain.go', 'cmd/client/desktop_macos_process_arguments.go',
    'cmd/client/desktop_macos_process_arguments_test.go', 'cmd/client/desktop_native_workspace.go',
    'cmd/client/desktop_node_chain_darwin.go', 'cmd/client/desktop_node_chain_darwin_baseline.go',
    'cmd/client/desktop_node_chain_darwin_native_test.go', 'cmd/client/desktop_node_chain_darwin_peer_native_test.go',
    'cmd/client/desktop_node_chain_imported_darwin_native_test.go', 'cmd/client/desktop_node_chain_dispatch.go',
    'cmd/client/desktop_node_chain_launch.go', 'cmd/client/desktop_node_chain_measurement.go',
    'cmd/client/desktop_node_chain_policy_dispatch.go', AUTHORITY_SOURCE,
    'cmd/client/desktop_node_chain_darwin_test.go', 'cmd/client/desktop_node_chain_connect_darwin_test.go',
    'cmd/client/desktop_node_chain_connect_darwin_baseline_test.go',
    'cmd/client/desktop_node_mtu.go', 'cmd/client/desktop_node_mtu_darwin.go', 'cmd/client/mtu_node_chain_snapshot.go',
    'cmd/client/multihop_node_chain_capture.go', 'cmd/client/multihop_node_chain_selection.go',
    'cmd/client/multihop_node_chain_connect_capture.go', 'cmd/client/multihop_node_chain_connect_selection.go',
    'cmd/client/multihop_node_chain_connect_selection_test.go', 'cmd/client/ordered_candidate_prefix_source.go',
    'cmd/client/desktop_external_darwin_peer_native_test.go', 'mobile/chain/connect_reference_test.go.tmpl',
    'cmd/client/startup_node_chain.go', 'mobile/desktop/node_chain_connect_peer_test.go.tmpl',
)
PARENT_TESTS = {
    'TestDesktopCONNECTParentRetainsExactTypedAuthority': ('wg', 'awg2-fast', 'awg2-strong'),
    'TestDesktopCONNECTParentRejectsSubstitution': ('missing-source', 'foreign-source', 'ordinary-policy', 'changed-member', 'changed-source', 'changed-scope', 'changed-input', 'changed-config'),
    'TestDesktopCONNECTParentReadyUsesTypedParser': ('ordinary-kind', 'foreign-transfer', 'foreign-source', 'foreign-dns'),
    'TestConnectionProfileOrderedCONNECTCompleteTransactions': ('wg', 'awg2-fast', 'awg2-strong'),
    'TestDesktopCONNECTParentMeasurementRequiresPublicMiddle': (),
    'TestDesktopCONNECTParentLastRetainsPrivateDigest': (),
    'TestDesktopMacOSCONNECTBaselineRetainsExactFamily': tuple(policy+'/'+phase for policy in ('on-connect','always') for phase in ('active','held','retired')),
    'TestDesktopMacOSCONNECTRetirementRequiresOriginalNativeAcknowledgment': (),
    'TestDesktopMacOSCONNECTRetirementRejectsForeignPolicy': (),
}
repository_identity, write_receipt = BASE.repository_identity, BASE.write_receipt


def case_inventory():
    source = (ROOT/AUTHORITY_SOURCE).read_text()
    match = re.search(r'var macOSNodeChainCONNECTHostCases = \[\]string\{([^}]+)\}', source)
    if match is None or tuple(re.findall(r'"([a-z0-9-]+)"', match[1])) != CASES or re.sub(r'"[a-z0-9-]+"|\s|,', '', match[1]):
        raise ValueError('Installed CONNECT source lost its exact22 cases')
    BASE.case_inventory()
    SOCKS.case_inventory()
    if len(BASE.CASES) != 37 or len(SOCKS.CASES) != 8 or len(set(CASES)) != 22 or not set(CASES).isdisjoint((*BASE.CASES, *SOCKS.CASES)):
        raise ValueError('Installed CONNECT gate lost original37, SOCKS8 or typed22')
    return CASES


def required_host(environment):
    if environment.get(FLAG) != '1':
        raise ValueError('Installed CONNECT host requires explicit disposable acceptance')
    return SOCKS.required_host(environment)


def source_identity(core):
    identity = SOCKS.source_identity(core)
    for name in SOURCES:
        identity['application'][name] = EXTERNAL.sha(ROOT/name)
    return identity


def check_verdict(output, case):
    BASE.check_verdict(output, case, test=TEST, cases=CASES, mtu_cases=(), measurement_cases=MEASUREMENT_CASES)
    receipts = [match[1] for line in output.splitlines() if (match := re.match(r'^\s+[^ ]+\.go:[0-9]+: (.*)$', line))]
    if receipts.count(FIFTY_RECEIPT) != (1 if case in MEASUREMENT_CASES else 0) or receipts.count(STREAMS_RECEIPT) != 1:
        raise ValueError('Installed CONNECT case lost actual fifty or joined TCP owner receipt')
    if any(value.startswith('actual installed Darwin CONNECT ') and value not in (FIFTY_RECEIPT, STREAMS_RECEIPT) for value in receipts):
        raise ValueError('Installed CONNECT case borrowed another native receipt')


def check_authority_verdict(output):
    BASE.check_authority_verdict(output, selected=(AUTHORITY_TEST, AUTHORITY_CASES))



def execute_parent_controls(controller, digest, environment):
    outputs = []
    for root, leaves in PARENT_TESTS.items():
        if EXTERNAL.sha(controller) != digest:
            raise ValueError('Retained parent controls replaced original controller image')
        result = subprocess.run([str(controller), '-test.v', '-test.count=1', '-test.timeout=60s', '-test.run=^'+root+'$'],
                                cwd=ROOT, env=environment, check=True, timeout=70, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(result.stdout, end='' if result.stdout.endswith('\n') else '\n', flush=True)
        BASE.check_authority_verdict(result.stdout, selected=(root, (root, *(root+'/'+leaf for leaf in leaves))))
        outputs.append(result.stdout)
    if EXTERNAL.sha(controller) != digest:
        raise ValueError('Retained parent controls changed original controller image')
    return ''.join(outputs)


def execute_typed_authority(controller, digest, environment):
    if EXTERNAL.sha(controller) != digest:
        raise ValueError('Typed authority lost original controller image')
    result = subprocess.run([str(controller), '-test.v', '-test.count=1', '-test.timeout=30s', '-test.run=^'+AUTHORITY_TEST+'$'],
                            cwd=ROOT, env=environment, check=True, timeout=40, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end='' if result.stdout.endswith('\n') else '\n', flush=True)
    check_authority_verdict(result.stdout)
    if EXTERNAL.sha(controller) != digest:
        raise ValueError('Typed authority replaced original image')
    return result.stdout


def check_source_control(output, returncode):
    BASE.check_hysteria_control_verdict(output, returncode, selected=(AUTHORITY_TEST, AUTHORITY_CASES, Path(AUTHORITY_SOURCE).name, SOURCE_CONTROL))


def execute_typed_control(compiler, work, environment):
    original = ROOT/AUTHORITY_SOURCE
    source, before = original.read_text(), EXTERNAL.sha(original)
    needle = 'Password: password'
    if source.count(needle) != 1:
        raise ValueError('Typed original credential control seam changed')
    directory = Path(work)/'connect-source-control'
    directory.mkdir(mode=0o700)
    changed, overlay, image = directory/'source.go', directory/'overlay.json', directory/'controller.test'
    changed.write_text(source.replace(needle, 'Password: password + "-uncaptured"', 1))
    overlay.write_text(json.dumps({'Replace': {str(original.resolve()): str(changed.resolve())}}))
    subprocess.run([str(compiler), 'test', '-race', '-c', '-mod=readonly', '-tags=routervpn_controller_privileged',
                    '-overlay='+str(overlay), '-o', str(image), './cmd/client'], cwd=ROOT, env=environment, check=True, timeout=300)
    digest = EXTERNAL.sha(image)
    result = subprocess.run([str(image), '-test.v', '-test.count=1', '-test.timeout=30s', '-test.run=^'+AUTHORITY_TEST+'$'],
                            cwd=ROOT, env=environment, check=False, timeout=40, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end='' if result.stdout.endswith('\n') else '\n', flush=True)
    check_source_control(result.stdout, result.returncode)
    if EXTERNAL.sha(image) != digest or EXTERNAL.sha(original) != before:
        raise ValueError('Typed negative control replaced original image or source')
    return dict(image_sha256=digest, output_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(), cases=list(AUTHORITY_CASES), witness=SOURCE_CONTROL)


def execute(bundle, source=None, go='go', environment=None, *, required_commit=None, receipt_file=None):
    environment = dict(os.environ if environment is None else environment)
    target, uid = required_host(environment)
    repository = repository_identity(required_commit)
    if receipt_file is not None and repository is None:
        raise ValueError('Native ordered durable receipt must name its exact tested commit')
    cases = (*BASE.case_inventory(), *SOCKS.case_inventory(), *case_inventory())
    compiler, captured = CONTROLLER.UID.compiler_toolchain(ROOT, go, environment)
    captured['CGO_ENABLED'] = '1'
    bundle = Path(bundle).resolve()
    original = BUILD.reuse(bundle, target, env=captured)
    original_hash = EXTERNAL.sha(bundle/'NATIVE-RUNTIME.json')
    policy = BUILD.digest()
    python = CONTROLLER.discover_python(uid)
    sudo = CONTROLLER.UID.privilege_tool()
    with tempfile.TemporaryDirectory(prefix='routervpn-macos-node-chain-') as temporary:
        work = Path(temporary).resolve()
        work.chmod(0o755)
        core = Path(source).resolve() if source else EXTERNAL.prepared_peer_source(work, captured)
        before = source_identity(core)
        signed = work/'sealed-bundle'
        shutil.copytree(bundle, signed, symlinks=True)
        subprocess.run([os.sys.executable, str(ROOT/'deploy/seal-native-runtime.py'), str(signed), target],
                       cwd=ROOT, env=captured, check=True, timeout=300)
        BUILD.reuse(signed, target, env=captured)
        signed_hash = EXTERNAL.sha(signed/'NATIVE-RUNTIME.json')
        race_compiler, race_environment = CONTROLLER.UID.RACE.capture(core, compiler, captured)
        controller, peer = work/'controller.test', work/'peer.test'
        commands = (
            ([str(race_compiler), 'test', '-race', '-c', '-mod=readonly', '-tags=routervpn_controller_privileged',
              '-o', str(controller), './cmd/client'], ROOT),
            ([str(race_compiler), 'test', '-race', '-c', '-mod=readonly', '-tags='+PEER_TAGS,
              '-ldflags=-checklinkname=0', '-o', str(peer), './protocol/routervpnamnezia'], core),
        )
        for command, cwd in commands:
            subprocess.run(command, cwd=cwd, env=race_environment, check=True, timeout=300)
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none',
                        '--identifier', 'routervpn.fixture.ordered.controller', str(controller)], check=True, timeout=30)
        controller.chmod(0o755)
        peer.chmod(0o755)
        identities = dict(controller=EXTERNAL.sha(controller), peer=EXTERNAL.sha(peer))
        for root in (BASE.TEST, SOCKS.TEST, TEST):
            listing = subprocess.run([str(controller), '-test.list=^'+root+'$'], env=captured, cwd=ROOT, check=True, timeout=30, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
            if listing.strip() != root:
                raise ValueError('Compiled native image omitted original or typed installed root')
        if source_identity(core) != before or BUILD.digest() != policy:
            raise ValueError('Native ordered source changed during compilation')
        socks_parent_output = SOCKS.execute_parent_controls(controller, identities['controller'], captured)
        parent_output = execute_parent_controls(controller, identities['controller'], captured)
        authority_output = BASE.execute_authority(controller, identities['controller'], captured)
        hysteria_authority_output = BASE.execute_authority(controller, identities['controller'], captured, hysteria=True)
        hysteria_control = BASE.execute_hysteria_control(race_compiler, work, race_environment)
        socks_authority_output = SOCKS.execute_typed_authority(controller, identities['controller'], captured)
        socks_control = SOCKS.execute_typed_control(race_compiler, work, race_environment)
        typed_authority_output = execute_typed_authority(controller, identities['controller'], captured)
        typed_control = execute_typed_control(race_compiler, work, race_environment)
        completed, output_digest = [], hashlib.sha256((socks_parent_output+parent_output+authority_output+hysteria_authority_output+socks_authority_output+typed_authority_output).encode())
        for case in cases:
            test_root = TEST if case in CASES else SOCKS.TEST if case in SOCKS.CASES else BASE.TEST
            command = ['/usr/bin/env', 'ROUTERVPN_MACOS_CONTROLLER_PRIVILEGE_FIXTURE=1',
                       'ROUTERVPN_MACOS_FIXTURE_UID='+str(uid), 'ROUTERVPN_MACOS_FIXTURE_SOURCE='+str(ROOT),
                       'ROUTERVPN_MACOS_FIXTURE_PYTHON='+str(Path(python).absolute()),
                       'ROUTERVPN_MACOS_NODE_CHAIN_PEER='+str(peer), 'ROUTERVPN_MACOS_NODE_CHAIN_PEER_SHA256='+identities['peer'],
                       'ROUTERVPN_MACOS_EXTERNAL_BUNDLE='+str(signed), 'ROUTERVPN_MACOS_EXTERNAL_BUNDLE_SHA256='+signed_hash,
                       'GORACE=atexit_sleep_ms=0', str(controller), '-test.run=^'+test_root+'$/^'+case+'$',
                       '-test.v', '-test.count=1', '-test.timeout=240s']
            if sudo:
                command = [sudo, '-n', '--', *command]
            output = CONTROLLER.reported_run(command, cwd=ROOT, env=captured, timeout=270, sudo=sudo)
            print(output, end='', flush=True)
            (check_verdict if case in CASES else SOCKS.check_verdict if case in SOCKS.CASES else BASE.check_verdict)(output, case)
            completed.append(case)
            output_digest.update(output.encode())
            if EXTERNAL.sha(controller) != identities['controller'] or EXTERNAL.sha(peer) != identities['peer']:
                raise ValueError('Native ordered execution replaced an original signed image')
        if tuple(completed) != cases or source_identity(core) != before or BUILD.digest() != policy:
            raise ValueError('Native ordered acceptance omitted a case or changed original sources')
        if BUILD.reuse(bundle, target, env=captured) != original or EXTERNAL.sha(bundle/'NATIVE-RUNTIME.json') != original_hash:
            raise ValueError('Native ordered acceptance changed original delivered bundle')
        if EXTERNAL.sha(signed/'NATIVE-RUNTIME.json') != signed_hash:
            raise ValueError('Native ordered acceptance changed its captured signed copy')
        if repository_identity(required_commit) != repository:
            raise ValueError('Native ordered acceptance changed its exact source commit or tree')
        receipt_value = dict(schema=1, gate='installed-darwin-ordered-connect-host', scope='installed-controller-actual-connect-and-original37-socks8-preservation', public_darwin_admission='closed',
                             target=target, validation_toolchain=CONTROLLER.UID.RACE.TOOLCHAIN, repository=repository, source_sha256=policy, bundle_sha256=original_hash,
                             sealed_bundle_sha256=signed_hash, images=identities, cases=list(CASES), original_cases=list(BASE.CASES), socks_cases=list(SOCKS.CASES), completed=list(completed),
                             sources=before, authority_cases=list(BASE.AUTHORITY_CASES),
                             authority_output_sha256=hashlib.sha256(authority_output.encode()).hexdigest(),
                             hysteria_authority_cases=list(BASE.HYSTERIA_AUTHORITY_CASES),
                             hysteria_authority_output_sha256=hashlib.sha256(hysteria_authority_output.encode()).hexdigest(),
                             hysteria_source_control=hysteria_control,
                             parent_cases=[name for root, leaves in PARENT_TESTS.items() for name in (root, *(root+'/'+leaf for leaf in leaves))],
                             parent_output_sha256=hashlib.sha256(parent_output.encode()).hexdigest(),
                             socks_parent_cases=[name for root, leaves in SOCKS.PARENT_TESTS.items() for name in (root, *(root+'/'+leaf for leaf in leaves))],
                             socks_parent_output_sha256=hashlib.sha256(socks_parent_output.encode()).hexdigest(),
                             socks_authority_cases=list(SOCKS.AUTHORITY_CASES), socks_authority_output_sha256=hashlib.sha256(socks_authority_output.encode()).hexdigest(), socks_source_control=socks_control,
                             typed_authority_cases=list(AUTHORITY_CASES),
                             typed_authority_output_sha256=hashlib.sha256(typed_authority_output.encode()).hexdigest(), typed_source_control=typed_control,
                             output_sha256=output_digest.hexdigest(), native=True)
    if work.exists() or work.is_symlink():
        raise ValueError('Native ordered acceptance did not retire its exact compilation workspace')
    if receipt_file is not None:
        write_receipt(receipt_file, receipt_value)
    print('Native Darwin ordered host acceptance: '+json.dumps(receipt_value, sort_keys=True, separators=(',', ':')), flush=True)
    return receipt_value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--source')
    parser.add_argument('--go', default='go')
    parser.add_argument('--require-commit')
    parser.add_argument('--receipt')
    args = parser.parse_args()
    execute(args.bundle, args.source, args.go, required_commit=args.require_commit, receipt_file=args.receipt)
