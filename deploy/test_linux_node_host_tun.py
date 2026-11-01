#!/usr/bin/env python3
"""Prove the installed Linux host against its completed native bundle and real TUN.

The actual protected controller uses its ordinary bundle verifier, original
FD-based engine launcher, durable transaction, selected DNS/MTU readiness and
private Router proof. Separately compiled WireGuard and SS2022 peers and the
exact shipping whitening relay exercise the captured graphs; each peer serves a
distinct same-identity direct-LAN control. Each case owns a private namespace.
No fixture verifier, public admission override or created device is permitted.
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
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHILD = load('linux_installed_host_child', 'test_linux_node_child_tun.py')
TRANSACTION = load('linux_installed_host_transaction', 'test_linux_node_transaction.py')
BUILD, NODE, GUARD = CHILD.BUILD, CHILD.NODE, CHILD.GUARD
WIREGUARD_CASES = tuple('wg-' + case for case in ('public-connect', 'home-lan', 'wrong-key', 'resolver-failure', 'wrong-node',
                                                'active-network-change', 'cancelled-proof', 'restore-sealed', 'always',
                                                'cover-connect', 'cover-restore'))
MTU_CASES = ('mtu-rollback', 'mtu-commit', 'mtu-stale-profile', 'mtu-stale-network', 'mtu-hold', 'mtu-retire-undrained')
OFF_CASES = ('public-off', 'public-off-save-retry')
WHITENING_CASES = ('layer-whitening-connect', 'layer-whitening-wrong-key', 'layer-whitening-resolver-failure', 'layer-whitening-cover-restore')
LAYER_CASES = ('layer-aes-connect', 'layer-aes-restore', *WHITENING_CASES)
PUBLIC_CASES = ('public-connect', 'cover-connect', 'cover-replies-lost', *OFF_CASES, 'layer-aes-connect', 'layer-whitening-connect', 'wg-public-connect', 'wg-cover-connect')
RESTORE_CASES = ('restore-sealed', 'cover-restore', 'layer-aes-restore', 'layer-whitening-cover-restore', 'wg-restore-sealed', 'wg-cover-restore')
COVER_CASES = ('cover-connect', 'cover-replies-lost', 'cover-wrong-node', 'cover-no-replies', 'cover-restore', 'layer-whitening-cover-restore', 'wg-cover-connect', 'wg-cover-restore')
ACTIVE_CASES = ('active-request-ended', 'cancel-adoption', 'active-profile-change', 'active-network-change', 'active-command-change', 'wg-active-network-change', *MTU_CASES, *RESTORE_CASES, *PUBLIC_CASES)
CASES = tuple(dict.fromkeys(('on-connect', 'home-lan', 'wrong-node', 'resolver-failure', 'wrong-key', 'stale-ready', 'cancelled-proof',
         'replaced-host', 'request-ended', 'shutdown', 'always', *ACTIVE_CASES, 'cover-wrong-node', 'cover-no-replies',
         'layer-whitening-wrong-key', 'layer-whitening-resolver-failure', *WIREGUARD_CASES)))
NAMESPACE_ENVIRONMENT = ('ROUTERVPN_NODE_OUTER_NETNS_ID', 'ROUTERVPN_NODE_HOST_BUNDLE', 'ROUTERVPN_NODE_HOST_BUNDLE_SHA256',
                         'ROUTERVPN_NODE_HOST_PEER_BINARY', 'ROUTERVPN_NODE_HOST_PEER_SHA256',
                         'ROUTERVPN_NODE_HOST_WHITENING_BINARY', 'ROUTERVPN_NODE_HOST_WHITENING_SHA256')


def checked_sources(source):
    source, native = CHILD.checked_sources(source)
    app = TRANSACTION.checked_sources()
    for name in ('ui.html', 'logical_ui.js'):
        path = ROOT / 'cmd/client' / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Installed Linux host lost an actual embedded application input')
        app['cmd/client/' + name] = hashlib.sha256(path.read_bytes()).hexdigest()
    catalog = ROOT / 'configs/client/modes.json'
    if catalog.is_symlink() or not catalog.is_file():
        raise ValueError('Installed public Connect lost its actual runtime catalog')
    app['configs/client/modes.json'] = hashlib.sha256(catalog.read_bytes()).hexdigest()
    required = {'cmd/client/desktop_node_host_linux_tun_native_test.go', 'cmd/client/desktop_node_host_linux_tun_peer_native_test.go',
                'cmd/client/desktop_node_host_linux_ready.go', 'cmd/client/desktop_node_host_linux_proof.go',
                'cmd/client/desktop_node_host_linux_active.go',
                'cmd/client/desktop_node_mtu_view_linux.go', 'cmd/client/desktop_node_mtu_view_linux_tun_native_test.go',
                'cmd/client/desktop_node_dns_linux.go', 'cmd/client/desktop_node_dns_other.go',
                'cmd/client/desktop_node_dns_linux_test.go', 'cmd/client/dns_proof.go',
                'cmd/client/desktop_node_mtu_linux.go', 'cmd/client/desktop_node_mtu_linux_tun_native_test.go',
                'cmd/client/desktop_node_session_linux.go',
                'cmd/client/desktop_node_restore_linux.go', 'cmd/client/desktop_node_restore_linux_tun_native_test.go',
                'cmd/client/desktop_node_connection_linux.go', 'cmd/client/desktop_node_connection_linux_tun_native_test.go',
                'cmd/client/desktop_node_start_layer_linux_tun_native_test.go',
                'cmd/client/desktop_node_wireguard_linux_tun_native_test.go',
                'cmd/client/profile_protection_platform_linux.go', 'cmd/client/desktop_node_protection_off_linux.go',
                'cmd/client/desktop_node_protection_off_linux_tun_native_test.go',
                'cmd/client/bundled_native.go', 'cmd/client/operation_guard.go'}
    if not required.issubset(app):
        raise ValueError('Installed Linux host gate lost its real verifier, startup, proof or retained native ownership')
    records = {'native/' + name: digest for name, digest in native.items()}
    records.update({'app/' + name: digest for name, digest in app.items()})
    for path in NODE.layer_reference_sources():
        if path.is_symlink() or not path.is_file():
            raise ValueError('Installed Linux Start Layer lost its shipping whitening peer source')
        records['reference/' + path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ('test_linux_node_host_tun.py', 'test_linux_node_host_tun_runner.py', 'build-native-runtime.py'):
        path = ROOT / 'deploy' / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Installed Linux host gate lost its original source boundary')
        records['gate/' + name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, records


def bundle_identity(directory, target, env=None):
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink() or any(parent.is_symlink() for parent in directory.parents):
        raise ValueError('Installed host requires an original absolute complete native bundle')
    receipt = BUILD.reuse(directory, target, env=env)
    records = {}
    for name in sorted((*receipt['files'], 'NATIVE-RUNTIME.json')):
        path = directory / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o6022:
            raise ValueError('Installed host bundle lost its original regular payload')
        records[name] = {'bytes': info.st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    return receipt, records


def check_verdict(output, case=None):
    cases = CASES if case is None else (case,)
    if any(value not in CASES for value in cases) or '--- FAIL:' in output or '--- SKIP:' in output:
        raise ValueError('Installed Linux host did not complete its actual native acceptance')
    prefix = '--- PASS: TestDesktopLinuxGuardianKernelNodeHostTUN'
    if prefix + ' (' not in output:
        raise ValueError('Installed Linux host omitted its actual native group')
    for value in cases:
        if prefix + '/' + value + ' (' not in output or 'verified installed host native lifecycle: ' + value + '\n' not in output.replace('\r\n', '\n'):
            raise ValueError('Installed Linux host omitted its actual complete owned lifecycle: ' + value)
        if value in ACTIVE_CASES and 'verified installed host active lifetime: ' + value + '\n' not in output.replace('\r\n', '\n'):
            raise ValueError('Installed Linux host omitted its actual activation, request completion and native lifetime: ' + value)
        if value in ('active-request-ended', *PUBLIC_CASES) and 'verified installed host retained DNS observation: ' + value + '\n' not in output.replace('\r\n', '\n'):
            raise ValueError('Installed Linux host omitted its actual retained session DNS consumer: ' + value)
        if value in MTU_CASES and 'verified installed host original MTU lease: ' + value + '\n' not in output.replace('\r\n', '\n'):
            raise ValueError('Installed Linux host omitted its original actual MTU lease: ' + value)
        if (value in ('active-request-ended', *PUBLIC_CASES) or value.startswith('mtu-')) and 'verified installed host live MTU status: ' + value + '\n' not in output.replace('\r\n', '\n'):
            raise ValueError('Installed Linux host omitted its current interface MTU status: ' + value)
        if value in RESTORE_CASES and 'verified installed host sealed temporary restoration: ' + value + '\n' not in output.replace('\r\n', '\n'):
            raise ValueError('Installed Linux host omitted its frozen execution, live MTU and fresh native restoration: ' + value)
        if value in PUBLIC_CASES and 'verified installed host public Connect and Disconnect: ' + value + '\n' not in output.replace('\r\n', '\n'):
            raise ValueError('Installed Linux host omitted its real public Connect and Disconnect composition: ' + value)
        if value in COVER_CASES and 'verified installed host native cover: ' + value + '\n' not in output.replace('\r\n', '\n'):
            raise ValueError('Installed Linux host omitted its captured native cover activation/failure/retirement: ' + value)
        if value in OFF_CASES and 'verified installed host saved Linux protection Off: ' + value + '\n' not in output.replace('\r\n', '\n'):
            raise ValueError('Installed Linux host omitted its exact Always retention, saved-policy Off and native release: ' + value)
        if value in LAYER_CASES and 'verified installed host captured Start Layer: ' + value + '\n' not in output.replace('\r\n', '\n'):
            raise ValueError('Installed Linux host omitted its exact cipher, outer physical authority and Start Layer lifecycle: ' + value)
        if value in WIREGUARD_CASES and 'verified installed host plain WireGuard: ' + value + '\n' not in output.replace('\r\n', '\n'):
            raise ValueError('Installed Linux host omitted its exact UDP WireGuard peer and native owned lifecycle: ' + value)


def namespace_test(binary, peer, bundle, image_sha256, peer_sha256, bundle_sha256, case, *, whitening=None, whitening_sha256=None):
    if case not in CASES:
        raise ValueError('Installed Linux host has no such captured native scenario')
    if CHILD.image_identity(binary)[-1] != image_sha256 or CHILD.image_identity(peer)[-1] != peer_sha256:
        raise ValueError('Installed Linux host lost an exact compiled image')
    if whitening is None:
        if case in WHITENING_CASES or whitening_sha256 is not None:
            raise ValueError('Installed Linux whitening requires its captured shipping relay image')
    elif CHILD.image_identity(whitening)[-1] != whitening_sha256:
        raise ValueError('Installed Linux whitening lost its exact shipping relay image')
    bundle = Path(bundle)
    if not bundle.is_absolute() or bundle.is_symlink() or any(parent.is_symlink() for parent in bundle.parents) or re.fullmatch('[0-9a-f]{64}', bundle_sha256 or '') is None:
        raise ValueError('Installed Linux host lost its captured native bundle directory')
    receipt = bundle / 'NATIVE-RUNTIME.json'
    info = receipt.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o6022 or not 0 < info.st_size <= 32768 or hashlib.sha256(receipt.read_bytes()).hexdigest() != bundle_sha256:
        raise ValueError('Installed Linux host lost its exact complete bundle receipt')
    current = os.stat('/proc/self/ns/net')
    values = dict(zip(NAMESPACE_ENVIRONMENT, (str(current.st_dev) + ':' + str(current.st_ino), str(bundle), bundle_sha256,
                                             str(peer), peer_sha256, str(whitening) if whitening is not None else '', whitening_sha256 or '')))
    previous = {name: os.environ.get(name) for name in values}
    os.environ.update(values)
    try:
        return GUARD.namespace_test(Path(binary), 'NodeHostTUN/' + case, image_sha256)
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def missing_binding_source(original):
    needle = 'return bindDesktopLinuxNodeProofSocket(ctx, actualNetwork, raw, live)'
    if original.count(needle) != 1:
        raise ValueError('Installed-host missing-binding control lost its exact shipping proof call')
    return original.replace(needle, 'return nil // compiled negative control: omit the original TUN binding')


def check_missing_binding_control(status, output):
    if status == 0 or '--- SKIP:' in output or '--- FAIL: TestDesktopLinuxGuardianKernelNodeHostTUN/home-lan (' not in output or \
            'installed Router proof used the direct LAN response or bypassed its exact encrypted graph' not in output:
        raise ValueError('Installed host did not reject its actual compiled missing-TUN-binding defect for the intended direct-LAN counter mismatch')


def missing_binding_control(workspace, peer, bundle, compiler, captured, peer_sha256, bundle_sha256, sudo):
    # A distinct controller image omits only the shipping proof's kernel bind.
    # The complete native bundle, original host lifecycle and same-node direct
    # LAN responder stay unchanged; failure must occur at the traffic counter.
    module = workspace / 'missing-tun-binding'
    module.mkdir()
    for name in ('go.mod', 'go.sum'):
        path = ROOT / name
        if path.exists():
            shutil.copyfile(path, module / name)
    shutil.copytree(ROOT / 'cmd/client', module / 'cmd/client')
    shutil.copytree(ROOT / 'internal', module / 'internal')
    changed = module / 'cmd/client/desktop_node_host_linux_proof.go'
    changed.write_text(missing_binding_source(changed.read_text()), encoding='utf-8')
    binary = module / 'controller.test'
    status, output = NODE.run([compiler, 'test', '-c', '-race', '-mod=readonly', '-tags=routervpn_controller_privileged',
                               '-o', binary, './cmd/client'], cwd=module, env=captured, timeout=300)
    if status:
        raise ValueError('Actual installed-host missing-binding control did not compile:\n' + output[-16384:])
    identity = CHILD.image_identity(binary)
    command = [sys.executable, str(Path(__file__).resolve()), '--namespace-test-binary', str(binary), '--peer-binary', str(peer),
               '--bundle', str(bundle), '--namespace-test-sha256', identity[-1], '--peer-sha256', peer_sha256,
               '--bundle-sha256', bundle_sha256, '--case', 'home-lan']
    if sudo is not None:
        command = [sudo, '-n', '--', *command]
    try:
        output = GUARD.UID.run(command, cwd=ROOT, env=captured, timeout=150, sudo=sudo)
        status = 0
    except subprocess.CalledProcessError as failure:
        status, output = failure.returncode, failure.output.decode('utf-8', errors='replace')
    check_missing_binding_control(status, output)
    if CHILD.image_identity(binary) != identity:
        raise ValueError('Installed-host negative control changed its original compiled image')
    print(output, end='' if output.endswith('\n') else '\n')
    print('Compiled missing-TUN-binding control rejected by the independent encrypted/direct Router counters.')
    return {'name': 'missing-tun-binding', 'bytes': identity[2], 'sha256': identity[-1],
            'changed_source_sha256': hashlib.sha256(changed.read_bytes()).hexdigest(), 'output_sha256': hashlib.sha256(output.encode()).hexdigest()}


def execute(source, bundle, go='go', *, env=None, receipt_path=None):
    if platform.system() != 'Linux':
        raise ValueError('Installed Linux host acceptance requires its matching native Linux host')
    source, before = checked_sources(source)
    captured = dict(os.environ if env is None else env, GOWORK='off')
    if captured.get('GOOS', 'linux') != 'linux' or captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('Installed Linux host acceptance requires its actual native CGO host')
    compiler, captured, architecture = NODE.selected_compiler(go, source, captured)
    captured['CGO_ENABLED'] = '1'
    bundle = Path(bundle).absolute()
    receipt, payloads = bundle_identity(bundle, 'linux/' + architecture, captured)
    receipt_path = CHILD.new_receipt_path(receipt_path)
    sudo = GUARD.UID.privilege_tool()
    with tempfile.TemporaryDirectory(prefix='routervpn-linux-installed-host-') as temporary:
        workspace = Path(temporary).resolve()
        binary, peer = workspace / 'controller.test', workspace / 'peer.test'
        commands = (([compiler, 'test', '-c', '-race', '-mod=readonly', '-tags=routervpn_controller_privileged', '-o', binary, './cmd/client'], ROOT),
                    ([compiler, 'test', '-c', '-race', '-mod=readonly', '-tags=' + ','.join(NODE.TAGS), '-ldflags=-checklinkname=0',
                      '-o', peer, './protocol/routervpnamnezia'], source))
        for command, cwd in commands:
            status, output = NODE.run(command, cwd=cwd, env=captured, timeout=300)
            if status:
                raise ValueError('Actual installed host or encrypted peer compilation failed:\n' + output[-16384:])
        whitening, whitening_sha256 = NODE.build_layer_reference(compiler, workspace, captured, ['-race'])
        identities = {path: CHILD.image_identity(path) for path in (binary, peer, whitening)}
        if identities[whitening][-1] != whitening_sha256:
            raise ValueError('Shipping whitening relay changed after its original build')
        if checked_sources(source)[1] != before or bundle_identity(bundle, 'linux/' + architecture, captured) != (receipt, payloads):
            raise ValueError('Installed Linux host source or completed bundle changed during compilation')
        logs = []
        for case in CASES:
            command = [sys.executable, str(Path(__file__).resolve()), '--namespace-test-binary', str(binary), '--peer-binary', str(peer),
                       '--bundle', str(bundle), '--namespace-test-sha256', identities[binary][-1], '--peer-sha256', identities[peer][-1],
                       '--bundle-sha256', payloads['NATIVE-RUNTIME.json']['sha256'], '--case', case,
                       '--whitening-binary', str(whitening), '--whitening-sha256', whitening_sha256]
            if sudo is not None:
                command = [sudo, '-n', '--', *command]
            output = GUARD.UID.run(command, cwd=ROOT, env=captured, timeout=150, sudo=sudo)
            check_verdict(output, case)
            logs.append(output)
            print(output, end='' if output.endswith('\n') else '\n')
        output = '\n'.join(logs)
        check_verdict(output)
        defect = missing_binding_control(workspace, peer, bundle, compiler, captured, identities[peer][-1],
                                         payloads['NATIVE-RUNTIME.json']['sha256'], sudo)
        if checked_sources(source)[1] != before or bundle_identity(bundle, 'linux/' + architecture, captured) != (receipt, payloads) or any(
                CHILD.image_identity(path) != identity for path, identity in identities.items()):
            raise ValueError('Installed Linux host changed its original source, engine bundle or compiled test images')
        result = {'schema': 1, 'gate': 'installed-linux-node-host', 'scope': 'completed-native-bundle-tun-router-proof-and-retirement',
                  'target': 'linux/' + architecture, 'toolchain': BUILD.TOOLCHAIN, 'policy_sha256': receipt['policy_sha256'],
                  'pins': {'sing-box': BUILD.PIN, 'xray': BUILD.POLICY.XRAY.XRAY_PIN}, 'source_files': before,
                  'source_sha256': hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                  'native_bundle': payloads,
                  'artifacts': {name: {'bytes': identities[path][2], 'sha256': identities[path][-1]} for name, path in
                                (('installed-controller-test', binary), ('independent-wg-and-ss2022-peers', peer), ('shipping-whitening-relay', whitening))},
                  'cases': list(CASES), 'compiled_negative_controls': [defect], 'output_sha256': hashlib.sha256(output.encode()).hexdigest()}
    CHILD.publish_receipt(receipt_path, result, workspace)
    print('Actual installed Linux host, complete bundle, selected TUN/DNS/MTU, routed Router identity, retained activation after request completion and durable joined retirement passed.')
    print('Physical devices, off-LAN interoperability, restart recovery and other graph families remain separate acceptance boundaries.')
    print(json.dumps({name: result[name] for name in ('gate', 'target', 'policy_sha256', 'source_sha256', 'output_sha256')}, sort_keys=True))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, nargs='?')
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--namespace-test-binary', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--peer-binary', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--namespace-test-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--peer-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--whitening-binary', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--whitening-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--bundle-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--case', choices=CASES, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.namespace_test_binary is not None:
        if args.source is not None or args.receipt is not None or args.peer_binary is None:
            parser.error('native namespace entry requires only its original compiled artifacts and scenario')
        raise SystemExit(namespace_test(args.namespace_test_binary, args.peer_binary, args.bundle, args.namespace_test_sha256,
                                       args.peer_sha256, args.bundle_sha256, args.case,
                                       whitening=args.whitening_binary, whitening_sha256=args.whitening_sha256))
    if args.source is None or any(value is not None for value in (args.peer_binary, args.namespace_test_sha256, args.peer_sha256,
                                                               args.whitening_binary, args.whitening_sha256, args.bundle_sha256, args.case)):
        parser.error('the full gate requires its exact prepared source and completed native bundle')
    try:
        execute(args.source, args.bundle, args.go, receipt_path=args.receipt)
    except subprocess.CalledProcessError as error:
        # The existing runner already joined this original failed child.
        # Preserve its failure while exposing the bounded native cause.
        if error.output:
            sys.stderr.write(error.output[-32768:].decode('utf-8', errors='replace'))
        raise


if __name__ == '__main__':
    main()
