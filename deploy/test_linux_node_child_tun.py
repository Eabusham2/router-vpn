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
    if not peer_only:
        for case in CASES:
            if 'verified original TUN retirement: ' + case + '\n' not in output.replace('\r\n', '\n'):
                raise ValueError('Generated Linux TUN command omitted its authenticated, acknowledged and joined retirement: ' + case)


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


# The diagnostic compiler changes logging only in an owned Go overlay. Its
# result can never satisfy acceptance or publish a release receipt.
RECEIPT_DIAGNOSTIC_REASONS = (
    ('unique-addition', 'native Linux routing call has no unique owned addition'),
    ('inventory-changed', 'native Linux routing inventory changed during its own add'),
    ('inventory-before', 'native Linux route before inventory:'),
    ('inventory-before', 'native Linux rule before inventory:'),
    ('inventory-after', 'native Linux route after inventory:'),
    ('inventory-after', 'native Linux rule after inventory:'),
    ('missing-inventory', 'native Linux routing call has no complete before/after readback'),
    ('duplicate-object', 'native Linux routing call duplicated an existing object'),
    ('duplicate-object', 'native TUN routing call reused an earlier object'),
    ('missing-object', 'native Linux receipt lost its successful routing object'),
    ('unrelated-route', 'native Linux TUN has an unrelated route'),
    ('wrong-constructor', 'network receipt requires the original native TUN constructor'),
    ('missing-interface', 'network receipt lost its current native interface'),
    ('missing-interface', 'native Linux routing receipt lost its original TUN'),
    ('uncaptured-address', 'network receipt observed an uncaptured TUN address'),
    ('missing-address', 'network receipt lost a configured TUN address'),
    ('changed-interface', 'native TUN changed while capturing its routing receipt'),
    ('interrupted-inventory', 'native Linux routing dump was interrupted'),
    ('unknown-inventory', 'native Linux routing dump contains an unknown result'),
    ('inventory-bound', 'native Linux route inventory exceeded its bound'),
)
RECEIPT_DIAGNOSTIC_PREFIX = 'NODE-MTU-DIAGNOSTIC '


def receipt_diagnostic_output(output):
    text = output.decode('utf-8', errors='replace') if isinstance(output, bytes) else output or ''
    reasons = '|'.join(sorted({'reader-missing', 'unclassified', *(code for code, _ in RECEIPT_DIAGNOSTIC_REASONS)}))
    patterns = (
        r'receipt reason=(' + reasons + r') generation=[0-9]+ reader=[0-9]+ index=[0-9]+ mtu=[0-9]+',
        r'delta kind=(route|rule) index=[0-9]+ added=[0-9]+ removed=[0-9]+',
        r'added kind=(route|rule) family=[0-9]+ index=[0-9]+ table=[0-9]+ priority=[0-9]+ flags=[0-9]+ destination=(default4|default6|linklocal6|multicast6|other)',
    )
    result = []
    for line in text.splitlines():
        # The Go parent prefixes its first joined-child line with a test
        # filename. Retain only the strictly parsed diagnostic suffix.
        offset = line.find(RECEIPT_DIAGNOSTIC_PREFIX)
        if offset < 0:
            continue
        line = line[offset:].strip()
        if len(line) > 512:
            continue
        message = line.removeprefix(RECEIPT_DIAGNOSTIC_PREFIX)
        if any(re.fullmatch(pattern, message) for pattern in patterns):
            result.append(line)
        if len(result) == 64:
            break
    return '\n'.join(result)


def receipt_diagnostic_overlay(source, workspace):
    replacements, records = {}, {}
    def transform(relative, edits, appendix=''):
        original = source / relative
        if original.is_symlink() or not original.is_file():
            raise ValueError('Native receipt diagnostics lost a regular source input')
        raw = original.read_text(encoding='utf-8')
        changed = raw
        for before, after in edits:
            if changed.count(before) != 1:
                raise ValueError('Native receipt diagnostic insertion no longer matches its exact source')
            changed = changed.replace(before, after, 1)
        target = workspace / original.name
        with target.open('x', encoding='utf-8') as output:
            output.write(changed + appendix)
        replacements[str(original)] = str(target)
        records[relative] = {'source': hashlib.sha256(raw.encode()).hexdigest(),
                             'diagnostic': hashlib.sha256(target.read_bytes()).hexdigest()}
    labels = '\n'.join('\t\t{' + json.dumps(prefix) + ', ' + json.dumps(code) + '},'
                       for code, prefix in RECEIPT_DIAGNOSTIC_REASONS)
    helper = '''
func routerVPNNodeMTUDiagnosticReason(message string) string {
    for _, known := range []struct{ prefix, code string }{
LABELS
    } {
        if strings.HasPrefix(message, known.prefix) { return known.code }
    }
    return "unclassified"
}
func routerVPNNodeMTUReceiptDiagnostic(record routerVPNNodeMTURecord, reason string) {
    fmt.Fprintf(os.Stderr, "NODE-MTU-DIAGNOSTIC receipt reason=%s generation=%d reader=%d index=%d mtu=%d\\n", reason, record.Generation, record.Reader, record.Index, record.MTU)
}
'''.replace('LABELS', labels)
    transform('cmd/sing-box/routervpn_network_command.go', (
        ('import (\n', 'import (\n\t"fmt"\n\t"os"\n\t"strings"\n'),
        ('\tif !ok {\n\t\treturn "", nil\n\t}\n\traw, err := reader.RouterVPNDesktopNetworkReceipt()',
         '\tif !ok {\n\t\trouterVPNNodeMTUReceiptDiagnostic(owner.record, "reader-missing")\n\t\treturn "", nil\n\t}\n\traw, err := reader.RouterVPNDesktopNetworkReceipt()'),
        ('\tif err != nil {\n\t\treturn "", nil\n\t}\n\treceipt, err := desktopnetwork.ParseDesktopNetworkReceipt(raw)',
         '\tif err != nil {\n\t\trouterVPNNodeMTUReceiptDiagnostic(owner.record, routerVPNNodeMTUDiagnosticReason(err.Error()))\n\t\treturn "", nil\n\t}\n\treceipt, err := desktopnetwork.ParseDesktopNetworkReceipt(raw)'),
    ), helper)
    delta = '''
func routervpnLinuxMTUDiagnostic(kind string, index int, added, removed []DesktopNetworkObject) {
    fmt.Fprintf(os.Stderr, "NODE-MTU-DIAGNOSTIC delta kind=%s index=%d added=%d removed=%d\\n", kind, index, len(added), len(removed))
    for i, object := range added {
        if i == 8 { break }
        destination := "other"
        switch object.Destination {
        case "0.0.0.0/0": destination = "default4"
        case "::/0": destination = "default6"
        case "fe80::/64": destination = "linklocal6"
        case "ff00::/8": destination = "multicast6"
        }
        fmt.Fprintf(os.Stderr, "NODE-MTU-DIAGNOSTIC added kind=%s family=%d index=%d table=%d priority=%d flags=%d destination=%s\\n", object.Kind, object.Family, object.Index, object.Table, object.Priority, object.Flags, destination)
    }
}
'''
    changed_inventory = '\t\t\tt.routervpnNetworkFailure(fmt.Errorf("native Linux routing inventory changed during its own add (kind=%s removed=%d added=%d)", kind, len(removed), len(added)))'
    unique_addition = '\t\tt.routervpnNetworkFailure(errors.New("native Linux routing call has no unique owned addition"))'
    transform('routervpn-desktop-tun/routervpn_sing_tun_network_linux.go', (
        ('\t"net"\n', '\t"net"\n\t"os"\n'),
        (changed_inventory, '\t\t\troutervpnLinuxMTUDiagnostic(kind, t.routervpnOwnedIndex, added, removed)\n' + changed_inventory),
        (unique_addition, '\t\troutervpnLinuxMTUDiagnostic(kind, t.routervpnOwnedIndex, added, removed)\n' + unique_addition),
    ), delta)
    overlay = workspace / 'overlay.json'
    with overlay.open('x', encoding='utf-8') as output:
        json.dump({'Replace': replacements}, output, sort_keys=True)
    return overlay, records


def native_receipt_diagnostics(source, compiler, captured, workspace, peer, identities, before, sudo):
    def verify_originals():
        if checked_sources(source)[1] != before or any(image_identity(path) != identity for path, identity in identities.items()):
            raise ValueError('Native receipt diagnostics lost its original source or executable capture')
    verify_originals()
    with tempfile.TemporaryDirectory(prefix='receipt-diagnostic-', dir=workspace) as temporary:
        directory = Path(temporary)
        overlay, records = receipt_diagnostic_overlay(source, directory)
        overlay_paths = [overlay, *(Path(path) for path in json.loads(overlay.read_text())['Replace'].values())]
        overlay_identities = {path: NODE.retained_binary(path) for path in overlay_paths}
        def verify_diagnostic_source():
            verify_originals()
            if any(NODE.retained_binary(path) != identity for path, identity in overlay_identities.items()):
                raise ValueError('Native receipt diagnostic overlay changed from its exact captured source')
        verify_diagnostic_source()
        diagnostic = directory / 'diagnostic.test'
        GUARD.UID.run([compiler, 'test', '-c', '-race', '-mod=readonly', '-tags=' + ','.join(TAGS),
                       '-ldflags=-checklinkname=0', '-overlay=' + str(overlay), '-o', diagnostic, './cmd/sing-box'],
                      cwd=source, env=captured, timeout=120)
        verify_diagnostic_source()
        identity = image_identity(diagnostic)
        command = [sys.executable, str(Path(__file__).resolve()), '--namespace-test-binary', str(diagnostic),
                   '--peer-binary', str(peer), '--namespace-test-sha256', identity[-1], '--peer-sha256', identities[peer][-1]]
        if sudo is not None:
            command = [sudo, '-n', '--', *command]
        status = 0
        try:
            output = GUARD.UID.run(command, cwd=ROOT, env=captured, timeout=150, sudo=sudo)
        except subprocess.CalledProcessError as error:
            status, output = error.returncode, error.output
        finally:
            verify_diagnostic_source()
            if image_identity(diagnostic) != identity:
                raise ValueError('Native receipt diagnostic executable changed during its owned run')
        safe = receipt_diagnostic_output(output)
        print('Bounded native receipt diagnostics completed; original mandatory failure retained. Diagnostic status: ' + str(status))
        print('Diagnostic overlay SHA256: ' + hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest())
        print('Diagnostic executable SHA256: ' + identity[-1])
        if safe:
            print(safe)
        else:
            print('No allowlisted native receipt cause was observed in this diagnostic run.')


def run_native_acceptance(command, *, captured, sudo, peer_only, diagnose):
    try:
        return GUARD.UID.run(command, cwd=ROOT, env=captured, timeout=150, sudo=sudo)
    except subprocess.CalledProcessError as original:
        output = original.output.decode('utf-8', errors='replace') if isinstance(original.output, bytes) else original.output or ''
        if not peer_only and 'generated MTU owner omitted its exact current native routing receipt' in output and 'original namespace child joined' in output:
            try:
                diagnose()
            except BaseException as diagnostic:
                # Failure diagnostics are never an alternate verdict. Avoid
                # echoing arbitrary compiler/runtime text or configuration.
                print('Native receipt diagnostics unavailable (' + type(diagnostic).__name__ + '); original failure retained.')
        raise


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
        output = run_native_acceptance(command, captured=captured, sudo=sudo, peer_only=peer_only,
                                       diagnose=lambda: native_receipt_diagnostics(source, compiler, captured, directory,
                                                                                   peer, identities, before, sudo))
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
