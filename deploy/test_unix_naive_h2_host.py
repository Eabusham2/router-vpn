#!/usr/bin/env python3
"""Required real installed Naive H2 host phase for Linux and macOS.

The original retained controller, completed native bundle, authenticated peer,
physical policy, selected DNS, private proof, MTU and joined retirement execute
on the matching native host. Existing host phases and deadlines are unchanged.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('unix_naive_h2_'+name, ROOT/'deploy'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PLAN = load('unix_naive_h2_cases')
LINUX = load('test_linux_node_host_tun')
LINUX_TOOLS = load('test_linux_connect_execution_host')
MAC = load('test_macos_paired_node_host')
BUILD = LINUX.BUILD
FLAG = 'ROUTERVPN_UNIX_NAIVE_H2_HOST_ACCEPTANCE'
INVENTORY_ROOT = 'TestDesktopUnixNaiveH2NativeInventory'
PEER_PRIVATE_ROOT = 'TestRouterVPNDesktopNodeNaiveH2PrivatePolicy'
COMPONENT_ROOTS = {
    'TestDesktopUnixNaiveH2PrivateFixtureRefusesSubstitution': ('original', 'quic', 'uot-disabled', 'uot-version', 'endpoint', 'port', 'username', 'password', 'trust-disabled', 'trust-insecure', 'sni', 'certificate-path', 'missing-ca', 'extra-source', 'extra-outbound', 'foreign-final'),
    'TestDesktopUnixNaiveH2PeerReceiptRefusesForeignLower': ('original', 'raw-udp', 'protocol-udp-lower', 'foreign-address', 'foreign-base', 'outer-source', 'borrowed-source', 'websocket', 'mux'),
}
SOURCES = (
    'deploy/unix_naive_h2_cases.py', 'deploy/test_unix_naive_h2_host.py',
    'deploy/test_unix_naive_h2_host_runner.py', '.github/workflows/unix-naive-h2-host.yml',
    '.github/workflows/release-candidate.yml',
    'internal/mobilemultihop/desktop_node_admission.go',
    'cmd/client/desktop_node_connection_linux.go', 'modes/kill-switch-platform.py', 'modes/kill-switch.py',
    'cmd/client/desktop_node_naive_h2_fixture_native_test.go',
    'cmd/client/desktop_node_naive_h2_fixture_contract_native_test.go',
    'cmd/client/desktop_node_naive_h2_linux_tun_native_test.go',
    'cmd/client/desktop_node_naive_h2_darwin_native_test.go',
    'mobile/desktop/node_naive_peer_test.go.tmpl', 'mobile/desktop/node_layer_peer_test.go.tmpl',
    'mobile/desktop/node_router_peer_test.go.tmpl', 'mobile/desktop/node_hysteria2_peer_test.go.tmpl',
)


def required_host(environment):
    if environment.get(FLAG) != '1' or environment.get('HOMEVPN_MTU_BENCH_FAKE'):
        raise ValueError('Naive H2 phase requires explicit real disposable native acceptance')
    system = platform.system()
    if system == 'Linux':
        target = LINUX_TOOLS.required_host({**environment, LINUX_TOOLS.FLAG: '1'})
        return target, None
    if system == 'Darwin':
        return MAC.required_host({**environment, MAC.FLAG: '1'})
    raise ValueError('Naive H2 retained Unix phase requires its matching native host')


def source_identity(core, target):
    value = LINUX.checked_sources(core)[1] if target.startswith('linux/') else MAC.source_identity(core)
    value = dict(value)
    for name in SOURCES:
        path = ROOT/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Naive H2 native phase lost its original source: '+name)
        value['naive/'+name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return value


def check_inventory(output, target):
    LINUX.NODE.require_native_verdicts(output, (INVENTORY_ROOT,), 'compiled installed Naive H2 inventory')
    records = re.findall(r'(?m)^\s+desktop_node_naive_h2_(?:linux_tun|darwin)_native_test.go:\d+: compiled installed Naive H2 cases: (.+)$', output)
    expected = PLAN.LINUX_CASES if target.startswith('linux/') else PLAN.DARWIN_CASES
    if len(records) != 1 or tuple(json.loads(records[0])) != expected:
        raise ValueError('Compiled Naive H2 host omitted or changed its exact native inventory')


def component_checks(controller, captured, target):
    outputs = {}
    for root, leaves in ((INVENTORY_ROOT, ()), *COMPONENT_ROOTS.items()):
        result = subprocess.run([str(controller), '-test.run=^'+root+'$', '-test.v', '-test.count=1', '-test.timeout=30s'],
                                cwd=ROOT, env=captured, check=True, timeout=40, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(result.stdout, end='', flush=True)
        if root == INVENTORY_ROOT:
            check_inventory(result.stdout, target)
        else:
            LINUX.NODE.require_native_verdicts(result.stdout, (root, *(root+'/'+leaf for leaf in leaves)), 'Naive H2 fixture source contracts')
        outputs[root] = hashlib.sha256(result.stdout.encode()).hexdigest()
    return outputs


def peer_private_checks(peer, core, installed, captured, target):
    # The separate pinned inbound and actual outgoing Box execute H2 and UoT.
    # The component's kernel/TUN are explicit modeled boundaries. macOS uses
    # its installed signed native engine below; its static Cronet composition
    # is not replaced by a fabricated dynamic-loader proof.
    if not target.startswith('linux/'):
        return {}
    library = installed/BUILD.library_name(target)
    original = BUILD.regular(library, BUILD.MAX_LIBRARY)
    environment = dict(captured, ROUTERVPN_NODE_CRONET_LIBRARY=str(library),
                       ROUTERVPN_NODE_CRONET_SHA256=hashlib.sha256(original).hexdigest(),
                       ROUTERVPN_NODE_CRONET_BYTES=str(len(original)))
    result = subprocess.run([str(peer), '-test.run=^'+PEER_PRIVATE_ROOT+'$', '-test.v', '-test.count=1', '-test.timeout=90s'],
                            cwd=core, env=environment, check=True, timeout=100, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end='', flush=True)
    LINUX.NODE.require_native_verdicts(result.stdout, (PEER_PRIVATE_ROOT, *(PEER_PRIVATE_ROOT+'/'+layer for layer in ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening'))), 'actual Naive H2 private proof, selected DNS, benchmark and retirement')
    if BUILD.regular(library, BUILD.MAX_LIBRARY) != original:
        raise ValueError('Naive H2 component changed the exact packaged Cronet library')
    return {PEER_PRIVATE_ROOT: hashlib.sha256(result.stdout.encode()).hexdigest()}


def execute(bundle, source=None, go='go', environment=None, *, required_commit=None, receipt_file=None):
    environment = dict(os.environ if environment is None else environment)
    target, uid = required_host(environment)
    repository = MAC.repository_identity(required_commit)
    if repository is None:
        raise ValueError('Naive H2 installed acceptance requires an exact published commit')
    system = target.split('/')[0]
    if system == 'linux':
        compiler, captured = LINUX_TOOLS.selected_compiler(go, environment, target)
    else:
        compiler, captured = MAC.CONTROLLER.UID.compiler_toolchain(ROOT, go, environment)
    captured['CGO_ENABLED'] = '1'
    bundle = Path(bundle).resolve()
    original = BUILD.reuse(bundle, target, env=captured)
    bundle_hash = MAC.EXTERNAL.sha(bundle/'NATIVE-RUNTIME.json')
    policy = BUILD.digest()
    cases = PLAN.LINUX_CASES if system == 'linux' else PLAN.DARWIN_CASES
    root = PLAN.LINUX_TEST if system == 'linux' else PLAN.DARWIN_TEST
    with tempfile.TemporaryDirectory(prefix='routervpn-unix-naive-h2-host-') as temporary:
        work = Path(temporary).resolve()
        work.chmod(0o755)
        core = Path(source).resolve() if source else LINUX_TOOLS.prepared_source(work, captured, compiler)
        before = source_identity(core, target)
        installed = bundle
        if system == 'darwin':
            installed = work/'sealed-bundle'
            shutil.copytree(bundle, installed, symlinks=True)
            subprocess.run([sys.executable, str(ROOT/'deploy/seal-native-runtime.py'), str(installed), target], cwd=ROOT, env=captured, check=True, timeout=300)
            BUILD.reuse(installed, target, env=captured)
            compiler, captured = MAC.CONTROLLER.UID.RACE.capture(core, compiler, captured)
        installed_hash = MAC.EXTERNAL.sha(installed/'NATIVE-RUNTIME.json')
        controller, peer = work/'controller.test', work/'peer.test'
        tags = ','.join(LINUX.NODE.TAGS) if system == 'linux' else MAC.PEER_TAGS
        for command, cwd in (
            ([str(compiler), 'test', '-race', '-c', '-mod=readonly', '-tags=routervpn_controller_privileged', '-o', str(controller), './cmd/client'], ROOT),
            ([str(compiler), 'test', '-race', '-c', '-mod=readonly', '-tags='+tags, '-ldflags=-checklinkname=0', '-o', str(peer), './protocol/routervpnamnezia'], core),
        ):
            subprocess.run(command, cwd=cwd, env=captured, check=True, timeout=300)
        if system == 'darwin':
            subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', '--identifier', 'routervpn.fixture.naive-h2.controller', str(controller)], check=True, timeout=30)
        controller.chmod(0o755)
        peer.chmod(0o755)
        whitening, whitening_hash = LINUX.NODE.build_layer_reference(compiler, work, captured, ['-race'])
        images = {str(path): LINUX.CHILD.image_identity(path) for path in (controller, peer, whitening)}
        if images[str(whitening)][-1] != whitening_hash:
            raise ValueError('Naive H2 Start Layer changed its captured shipping relay')
        listing = subprocess.run([str(controller), '-test.list=^'+root+'$'], cwd=ROOT, env=captured, check=True, timeout=30, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
        if listing.strip() != root:
            raise ValueError('Compiled controller omitted its real Naive H2 host root')
        component_outputs = component_checks(controller, captured, target)
        peer_outputs = peer_private_checks(peer, core, installed, captured, target)
        if source_identity(core, target) != before or BUILD.digest() != policy:
            raise ValueError('Naive H2 original source changed during compilation')
        outputs = {}
        if system == 'linux':
            sudo = LINUX.GUARD.UID.privilege_tool()
        else:
            sudo = MAC.CONTROLLER.UID.privilege_tool()
            python = MAC.CONTROLLER.discover_python(uid)
        for case in cases:
            if system == 'linux':
                command = [sys.executable, str(ROOT/'deploy/test_linux_node_host_tun.py'), '--namespace-test-binary', str(controller), '--peer-binary', str(peer),
                           '--bundle', str(installed), '--namespace-test-sha256', images[str(controller)][-1], '--peer-sha256', images[str(peer)][-1],
                           '--bundle-sha256', installed_hash, '--case', case, '--whitening-binary', str(whitening), '--whitening-sha256', whitening_hash]
                if sudo:
                    command = [sudo, '-n', '--', *command]
                output = LINUX.GUARD.UID.run(command, cwd=ROOT, env=captured, timeout=LINUX.installed_case_timeout(case), sudo=sudo)
            else:
                command = ['/usr/bin/env', 'ROUTERVPN_MACOS_CONTROLLER_PRIVILEGE_FIXTURE=1', 'ROUTERVPN_MACOS_FIXTURE_UID='+str(uid),
                           'ROUTERVPN_MACOS_FIXTURE_SOURCE='+str(ROOT), 'ROUTERVPN_MACOS_FIXTURE_PYTHON='+str(Path(python).absolute()),
                           'ROUTERVPN_MACOS_PAIRED_NODE_PEER_BINARY='+str(peer), 'ROUTERVPN_MACOS_PAIRED_NODE_PEER_SHA256='+images[str(peer)][-1],
                           'ROUTERVPN_MACOS_PAIRED_NODE_WHITENING_BINARY='+str(whitening), 'ROUTERVPN_MACOS_PAIRED_NODE_WHITENING_SHA256='+whitening_hash,
                           'ROUTERVPN_MACOS_EXTERNAL_BUNDLE='+str(installed), 'ROUTERVPN_MACOS_EXTERNAL_BUNDLE_SHA256='+installed_hash,
                           'GORACE=atexit_sleep_ms=0', str(controller), '-test.run=^'+root+'$/'+('/'.join('^'+re.escape(part)+'$' for part in case.split('/'))),
                           '-test.v', '-test.count=1', '-test.timeout=240s']
                if sudo:
                    command = [sudo, '-n', '--', *command]
                output = MAC.CONTROLLER.reported_run(command, cwd=ROOT, env=captured, timeout=270, sudo=sudo)
            print(output, end='', flush=True)
            PLAN.check_verdict(output, system, case)
            outputs[case] = hashlib.sha256(output.encode()).hexdigest()
            if any(LINUX.CHILD.image_identity(Path(path)) != identity for path, identity in images.items()):
                raise ValueError('Naive H2 native execution replaced an original image')
        if tuple(outputs) != cases or source_identity(core, target) != before or BUILD.digest() != policy or MAC.repository_identity(required_commit) != repository or BUILD.reuse(bundle, target, env=captured) != original or MAC.EXTERNAL.sha(bundle/'NATIVE-RUNTIME.json') != bundle_hash or MAC.EXTERNAL.sha(installed/'NATIVE-RUNTIME.json') != installed_hash:
            raise ValueError('Naive H2 acceptance omitted an original case or changed source, bundle or commit')
        result = dict(schema=1, gate='installed-unix-naive-h2-host', target=target, native=True, repository=repository,
                      validation_toolchain=BUILD.TOOLCHAIN, source_sha256=policy, bundle_sha256=bundle_hash,
                      installed_bundle_sha256=installed_hash, images=images, sources=before, cases=list(cases),
                      completed=list(outputs), outputs=outputs, component_outputs=component_outputs,
                      peer_outputs=peer_outputs,
                      scope='original-installed-controller-TLS-H2-UoT-selected-DNS-physical-policy-proof-MTU-restore-retirement',
                      physical_device_acceptance=False, private_deployment=False)
    if work.exists() or work.is_symlink():
        raise ValueError('Naive H2 native phase failed to retire its owned workspace')
    if receipt_file is not None:
        MAC.write_receipt(receipt_file, result)
    print('Native Unix Naive H2 host acceptance: '+json.dumps(result, sort_keys=True, separators=(',', ':')), flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--source')
    parser.add_argument('--go', default=os.environ.get('GO', 'go'))
    parser.add_argument('--require-commit', required=True)
    parser.add_argument('--receipt', required=True)
    args = parser.parse_args()
    execute(args.bundle, args.source, args.go, required_commit=args.require_commit, receipt_file=args.receipt)
