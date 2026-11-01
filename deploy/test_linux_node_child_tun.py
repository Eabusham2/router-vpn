#!/usr/bin/env python3
"""Execute the actual generated Linux command with TUN, SS2022 and selected DNS.

Both exact compiled images run in the existing isolated guardian namespaces.
The independent encrypted peer uses its own network namespace. The matching
host must provision its real TUN device; this gate neither creates nor fakes it.
App Router API proof, durable app settlement and device acceptance remain separate.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
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


CONTROL = load('linux_child_tun_control', 'test_linux_node_child_control.py')
NODE, GUARD = CONTROL.NODE, CONTROL.GUARD
BUILD = load('linux_child_tun_build', 'build-native-runtime.py')
TAGS = (*CONTROL.TAGS, 'routervpn_linux_node_tun')
CASES = ('on-connect', 'always', 'captured-mtu', 'mtu-rollback', 'resolver-failure', 'wrong-key')


def checked_sources(source):
    source, records = CONTROL.checked_sources(source)
    required = {
        'cmd/sing-box/routervpn_node_command_control_linux_tun_native_test.go',
        'cmd/sing-box/routervpn_node_command_run_linux.go',
        'cmd/sing-box/routervpn_mtu_node.go',
        'protocol/routervpnamnezia/routervpn_desktop_node_layer_peer_test.go',
        'protocol/routervpnamnezia/desktop_reference_test.go',
        'routervpn_desktop_node_box_linux_lifecycle.go',
        'routervpn/desktoppt/node_physical_linux.go',
    }
    if not required.issubset(records):
        raise ValueError('Generated Linux TUN command lost its exact command, native source or existing encrypted peer')
    for name in ('test_linux_node_child_tun.py', 'test_linux_node_child_tun_runner.py'):
        path = ROOT / 'deploy' / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Generated Linux TUN command lost its actual native gate')
        records['gate/' + name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, records


def image_identity(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('Linux TUN acceptance requires an absolute compiled artifact')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o6022 or not info.st_mode & 0o111 or not 0 < info.st_size <= 512 << 20:
        raise ValueError('Linux TUN acceptance lost its owned compiled executable')
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, hashlib.sha256(path.read_bytes()).hexdigest())


def check_verdict(output, *, peer_only=False):
    if '--- FAIL:' in output or '--- SKIP:' in output:
        raise ValueError('Generated Linux TUN command failed or skipped actual native acceptance')
    group = 'NodeChildCommandPeer' if peer_only else 'NodeChildCommandTUN'
    prefix = '--- PASS: TestDesktopLinuxGuardianKernel' + group
    suffixes = ('',) if peer_only else ('', *('/' + case for case in CASES))
    for suffix in suffixes:
        if prefix + suffix + ' (' not in output:
            raise ValueError('Generated Linux TUN command omitted its required boundary: ' + group + suffix)


def namespace_test(binary, peer, expected_sha256, peer_sha256, *, peer_only=False):
    # Capture the original outer namespace before the guardian runner enters
    # its private user/network/PID/mount namespaces. The existing peer is only
    # copied under the new private /opt by its exact native test owner.
    if image_identity(binary)[-1] != expected_sha256 or image_identity(peer)[-1] != peer_sha256:
        raise ValueError('Generated Linux TUN acceptance lost an exact compiled image')
    current = os.stat('/proc/self/ns/net')
    values = {
        'ROUTERVPN_NODE_OUTER_NETNS_ID': str(current.st_dev) + ':' + str(current.st_ino),
        'ROUTERVPN_NODE_TUN_PEER_BINARY': str(peer),
        'ROUTERVPN_NODE_TUN_PEER_SHA256': peer_sha256,
    }
    previous = {name: os.environ.get(name) for name in values}
    os.environ.update(values)
    try:
        return GUARD.namespace_test(Path(binary), 'NodeChildCommandPeer' if peer_only else 'NodeChildCommandTUN', expected_sha256)
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def new_receipt_path(receipt_path):
    if receipt_path is None:
        return None
    receipt_path = Path(receipt_path).absolute()
    if receipt_path.exists() or receipt_path.is_symlink() or not receipt_path.parent.is_dir():
        raise ValueError('Linux TUN receipt requires a new owned file')
    return receipt_path


def publish_receipt(receipt_path, result, retired_workspace):
    if retired_workspace.exists() or retired_workspace.is_symlink():
        raise ValueError('Linux TUN owned workspace cleanup was not acknowledged')
    if receipt_path is not None:
        with receipt_path.open('x', encoding='utf-8') as output:
            json.dump(result, output, sort_keys=True, indent=2)
            output.write('\n')


def repository_identity(required_commit):
    if required_commit is None:
        return None
    if re.fullmatch('[0-9a-f]{40}', required_commit) is None:
        raise ValueError('Linux TUN requires an exact source commit')
    def git(*arguments):
        return subprocess.check_output(['git', *arguments], cwd=ROOT, text=True, timeout=30).strip()
    commit, tree = git('rev-parse', '--verify', 'HEAD'), git('rev-parse', '--verify', 'HEAD^{tree}')
    if commit != required_commit or re.fullmatch('[0-9a-f]{40}', tree) is None:
        raise ValueError('Linux TUN repository does not match its required source commit')
    # GitHub runs the exact checked-out project. Preparation writes only to
    # its owned temporary workspace; a receipt cannot hide tracked edits.
    git('diff', '--no-ext-diff', '--quiet', 'HEAD', '--')
    if git('ls-files', '--others', '--exclude-standard', '--', 'mobile', 'internal', 'deploy', 'configs', 'cmd', 'server', 'go.mod', 'go.sum'):
        raise ValueError('Linux TUN source includes unpublished project inputs')
    return {'repository': 'Eabusham2/router-vpn', 'commit': commit, 'tree': tree}


def execute(source, go='go', *, env=None, peer_only=False, receipt_path=None):
    if platform.system() != 'Linux':
        raise ValueError('Generated Linux TUN command requires its matching native Linux host')
    source, before = checked_sources(source)
    captured = dict(os.environ if env is None else env, GOWORK='off')
    if captured.get('GOOS', 'linux') != 'linux':
        raise ValueError('Generated Linux TUN acceptance cannot run a cross-compiled fixture')
    sudo = GUARD.UID.privilege_tool()
    compiler, captured, architecture = NODE.selected_compiler(go, source, captured)
    if captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('Generated Linux TUN acceptance requires its native CGO host')
    captured['CGO_ENABLED'] = '1'
    receipt_path = new_receipt_path(receipt_path)
    with tempfile.TemporaryDirectory(prefix='routervpn-linux-child-tun-') as temporary:
        directory = Path(temporary).resolve()
        binary, peer = directory / 'child.test', directory / 'peer.test'
        for path, package, tags in ((binary, './cmd/sing-box', TAGS), (peer, './protocol/routervpnamnezia', NODE.TAGS)):
            GUARD.UID.run([compiler, 'test', '-c', '-race', '-mod=readonly', '-tags=' + ','.join(tags),
                           '-ldflags=-checklinkname=0', '-o', path, package],
                          cwd=source, env=captured, timeout=600)
        if checked_sources(source)[1] != before:
            raise ValueError('Generated Linux TUN source changed during its two actual compilations')
        identities = {path: image_identity(path) for path in (binary, peer)}
        command = [sys.executable, str(Path(__file__).resolve()), '--namespace-test-binary', str(binary),
                   '--peer-binary', str(peer), '--namespace-test-sha256', identities[binary][-1], '--peer-sha256', identities[peer][-1]]
        if peer_only:
            command.append('--peer-only')
        if sudo is not None:
            command = [sudo, '-n', '--', *command]
        output = GUARD.UID.run(command, cwd=ROOT, env=captured, timeout=150, sudo=sudo)
        check_verdict(output, peer_only=peer_only)
        if any(image_identity(path) != identity for path, identity in identities.items()) or checked_sources(source)[1] != before:
            raise ValueError('Generated Linux TUN source or original executable changed during native verification')
        print(output, end='' if output.endswith('\n') else '\n')
        if peer_only:
            print('Existing encrypted peer and captured child profiles passed; TUN and generated-command acceptance were not run.')
        else:
            print('Actual generated Linux command, selected DNS, encrypted TUN traffic, MTU rollback and pre-ACK TUN close passed; app Router proof and device acceptance remain separate.')
        result = {
            'schema': 1, 'gate': 'generated-linux-node-child',
            'scope': 'peer-prerequisite' if peer_only else 'generated-command-tun',
            'target': 'linux/' + architecture, 'toolchain': BUILD.TOOLCHAIN,
            'pins': {'sing-box': BUILD.PIN, 'xray': BUILD.POLICY.XRAY.XRAY_PIN},
            'source_files': before,
            'source_sha256': hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'artifacts': {role: {'bytes': identities[path][2], 'sha256': identities[path][-1]}
                          for role, path in (('generated-command-test', binary), ('independent-ss2022-peer', peer))},
            'cases': ['peer-prerequisite'] if peer_only else list(CASES),
            'output_sha256': hashlib.sha256(output.encode()).hexdigest(),
        }
    publish_receipt(receipt_path, result, directory)
    return result


def standalone(go='go', *, peer_only=False, receipt_path=None, required_commit=None):
    if platform.system() != 'Linux':
        raise ValueError('Standalone Linux TUN acceptance requires actual Linux')
    repository = repository_identity(required_commit)
    compiler, captured, _ = NODE.selected_compiler(go, ROOT, dict(os.environ))
    if captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('Standalone Linux TUN acceptance cannot disable native CGO')
    captured['CGO_ENABLED'] = '1'
    receipt_path = new_receipt_path(receipt_path)
    previous = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix='routervpn-linux-child-core-') as temporary:
        workspace = Path(temporary)
        source, xray = workspace / 'core', workspace / 'xray'
        try:
            os.environ.clear()
            os.environ.update(captured)
            BUILD.checkout(source, 'https://github.com/SagerNet/sing-box.git', BUILD.PIN)
            BUILD.checkout(xray, 'https://github.com/XTLS/Xray-core.git', BUILD.POLICY.XRAY.XRAY_PIN)
            BUILD.pristine(source, BUILD.PIN)
            BUILD.pristine(xray, BUILD.POLICY.XRAY.XRAY_PIN)
            BUILD.POLICY.prepare_native(source, xray)
            BUILD.PERFORMANCE.prepare(source)
            BUILD.OPENVPN.prepare(source)
            BUILD.EXTERNAL.prepare(source, go=str(compiler), env=captured)
            BUILD.BUFFERS.prepare(source)
            BUILD.run([compiler, 'mod', 'tidy'], cwd=source, env=captured)
            BUILD.run([compiler, 'mod', 'verify'], cwd=source, env=captured)
            BUILD.POLICY.AMNEZIA.verify(source)
            result = execute(source, str(compiler), env=captured, peer_only=peer_only)
        finally:
            os.environ.clear()
            os.environ.update(previous)
    if repository_identity(required_commit) != repository:
        raise ValueError('Linux TUN repository changed during native acceptance')
    result['repository'] = repository
    publish_receipt(receipt_path, result, workspace)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, nargs='?')
    parser.add_argument('--go', default='go')
    parser.add_argument('--peer-only', action='store_true', help='explicitly verify only the existing peer/profile prerequisite, without claiming TUN acceptance')
    parser.add_argument('--standalone', action='store_true', help='prepare both pinned native sources in an owned temporary workspace')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--require-commit', help='require the clean project checkout to retain this exact commit before and after standalone acceptance')
    parser.add_argument('--namespace-test-binary', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--namespace-test-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--peer-binary', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--peer-sha256', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.namespace_test_binary is not None:
        if (args.source is not None or args.peer_binary is None or args.namespace_test_sha256 is None or args.peer_sha256 is None or
                args.standalone or args.receipt is not None or args.require_commit is not None):
            parser.error('native acceptance requires both original compiled artifacts and their exact digests')
        raise SystemExit(namespace_test(args.namespace_test_binary, args.peer_binary, args.namespace_test_sha256, args.peer_sha256, peer_only=args.peer_only))
    if args.namespace_test_sha256 is not None or args.peer_binary is not None or args.peer_sha256 is not None:
        parser.error('compiled artifacts belong only to the owned namespace invocation')
    if args.standalone and args.source is not None or not args.standalone and (args.source is None or args.require_commit is not None):
        parser.error('provide the exact prepared source or --standalone; --require-commit belongs to standalone preparation')
    try:
        if args.standalone:
            standalone(args.go, peer_only=args.peer_only, receipt_path=args.receipt, required_commit=args.require_commit)
        else:
            execute(args.source, args.go, peer_only=args.peer_only, receipt_path=args.receipt)
    except subprocess.CalledProcessError as error:
        if error.output:
            output = error.output[-32768:]
            sys.stderr.write(output if isinstance(output, str) else output.decode('utf-8', errors='replace'))
        raise
