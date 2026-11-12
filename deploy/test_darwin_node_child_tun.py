#!/usr/bin/env python3
"""Run the actual generated ordered Darwin child on an explicit disposable host.

The real inherited macosprocess capture, signed images, PF/socket guardians,
utun, encrypted WG/AWG/SS peers, selected DNS, every-node proof, native MTU
replacement/rollback and authenticated joined Stop are mandatory. Public app
admission, installed UI, release delivery and device acceptance remain separate.
"""
from pathlib import Path
from collections import Counter
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
FLAG = 'ROUTERVPN_DARWIN_NODE_CHILD_ACCEPTANCE'
HARNESS = 'TestRouterVPNNodeChainDarwinNativeHarness'
NATIVE = 'TestRouterVPNNodeChainDarwinNativeCommand'
CASES = ('wg-three', 'mixed-four', 'captured-mtu', 'mtu-rollback', 'wrong-middle-key',
         'wrong-middle-proof', 'final-dns-failure', 'foreign-mtu-session')
EXPECTED = (HARNESS, NATIVE, *(NATIVE+'/'+case for case in CASES))
TAGS = ('with_wireguard', 'with_gvisor', 'with_quic', 'with_utls', 'with_openvpn',
        'with_naive_outbound', 'with_purego', 'routervpn_darwin_external_host',
        'routervpn_darwin_node_chain', 'routervpn_darwin_node_child_tun')


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NODE = load('darwin_child_native_sources', 'test_desktop_node_physical.py')
UID = load('darwin_child_native_uid', 'test_desktop_socket_uid.py')
BUILD = load('darwin_child_native_build', 'build-native-runtime.py')


def digest(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Darwin child source is not its original regular file')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_sources(source):
    source, records = NODE.checked_sources(Path(source))
    required = {
        'cmd/sing-box/routervpn_node_chain_command_darwin_native_test.go',
        'cmd/sing-box/routervpn_node_chain_command.go',
        'cmd/sing-box/routervpn_node_chain_run_darwin.go',
        'cmd/sing-box/routervpn_node_chain_control_darwin.go',
        'cmd/sing-box/routervpn_node_chain_retirement_darwin.go',
        'cmd/sing-box/routervpn_node_chain_command_runtime.go',
        'cmd/sing-box/routervpn_mtu_node.go',
        'routervpn/macosprocess/bootstrap_darwin.go',
        'routervpn/macosprocess/capture_darwin.go',
        'routervpn/macosprocess/node_chain_transfer.go',
        *NODE.PREP.DARWIN_NODE_CHAIN_PEERS.values(),
        'protocol/routervpnamnezia/routervpn_desktop_node_peer_network_test.go',
        'routervpn_desktop_node_chain_box_darwin.go',
        'routervpn/desktoppt/node_chain_physical_darwin.go',
    }
    if not required.issubset(records):
        raise ValueError('Darwin child omitted an actual generated owner or independent encrypted peer')
    for name in ('test_darwin_node_child_tun.py', 'test_darwin_node_child_tun_runner.py'):
        records['gate/'+name] = digest(ROOT/'deploy'/name)
    return source, records


def required_host(environment):
    if platform.system() != 'Darwin' or environment.get(FLAG) != '1':
        raise ValueError('Darwin PF/utun/keychain acceptance requires explicit disposable native opt-in')
    arch = {'x86_64': 'amd64', 'arm64': 'arm64'}.get(platform.machine())
    if arch is None or environment.get('GOOS', 'darwin') != 'darwin' or environment.get('GOARCH', arch) != arch:
        raise ValueError('Darwin child requires the actual matching native architecture')
    uid = int(environment.get('SUDO_UID', '0')) if os.getuid() == 0 else os.getuid()
    if not 0 < uid < 2**32-1 or environment.get('CGO_ENABLED', '1') != '1':
        raise ValueError('Darwin child requires native CGO and its original unprivileged build UID')
    return arch, uid


def selected_compiler(go, source, environment):
    compiler, captured = UID.compiler_toolchain(source, go, environment)
    host = json.loads(UID.run([compiler, 'env', '-json', 'GOVERSION', 'GOHOSTOS', 'GOHOSTARCH'], cwd=source, env=captured, timeout=30))
    arch, _ = required_host(environment)
    if host != {'GOVERSION': 'go1.26.3', 'GOHOSTOS': 'darwin', 'GOHOSTARCH': arch}:
        raise ValueError('Darwin child requires the exact native Go 1.26.3 compiler')
    captured.update(GOOS='darwin', GOARCH=arch, CGO_ENABLED='1', GOFLAGS='', GOWORK='off',
                    PATH=str(compiler.parent)+os.pathsep+captured.get('PATH', os.defpath))
    return compiler, captured


def image_identity(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('Darwin native image must be an absolute original artifact')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o6022 or not info.st_mode & 0o111 or not 0 < info.st_size <= 512 << 20:
        raise ValueError('Darwin native image lost its bounded regular executable')
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, digest(path))


def check_verdict(output):
    if not isinstance(output, str) or len(output.encode()) > 8 << 20:
        raise ValueError('Darwin child has no bounded native verdict')
    runs, passes, receipts = Counter(), Counter(), Counter()
    for line in output.replace('\r\n', '\n').splitlines():
        if re.search(r'--- (?:FAIL|SKIP):|WARNING: DATA RACE|panic:|fatal error:', line):
            raise ValueError('Darwin child failed, skipped or raced its native boundary')
        match = re.fullmatch(r'\s*=== RUN\s+(\S+)', line)
        if match:
            name = match[1]
            parent = HARNESS if name == NATIVE else NATIVE if name.startswith(NATIVE+'/') else None
            if (name not in EXPECTED or runs[name] or passes[name]
                    or parent is not None and (runs[parent] != 1 or passes[parent])):
                raise ValueError('Darwin child ran an unknown or repeated native case')
            runs[name] += 1
        match = re.fullmatch(r'\s*--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)', line)
        if match:
            name = match[1]
            if name not in EXPECTED or runs[name] != 1 or passes[name]:
                raise ValueError('Darwin child passed an unrun or repeated native case')
            if name == HARNESS:
                if any(passes[child] != 1 for child in EXPECTED if child != HARNESS):
                    raise ValueError('Darwin harness passed before all original child reports completed')
            else:
                if runs[HARNESS] != 1 or passes[HARNESS]:
                    raise ValueError('Darwin child reported outside its original active harness')
                if name == NATIVE:
                    # Go prints a parent PASS before its buffered subtest PASS
                    # lines. All actual case work and joined receipts must
                    # already exist; their terminal reports may follow it.
                    if (receipts != Counter(CASES)
                            or any(runs[NATIVE+'/'+case] != 1 for case in CASES)):
                        raise ValueError('Darwin child passed before all original native joins')
                elif receipts[name[len(NATIVE)+1:]] != 1:
                    raise ValueError('Darwin child passed without its original retirement')
            passes[name] += 1
        match = re.search(r'verified original Darwin child retirement: (\S+)$', line)
        if match:
            case = match[1]
            if (case not in CASES or receipts[case] or runs[NATIVE+'/'+case] != 1
                    or passes[NATIVE+'/'+case] or passes[NATIVE] or passes[HARNESS]):
                raise ValueError('Darwin child changed its authenticated retirement inventory')
            receipts[case] += 1
    if runs != Counter(EXPECTED) or passes != Counter(EXPECTED) or receipts != Counter(CASES):
        raise ValueError('Darwin child omitted a required native case or original joined retirement')


def repository_identity(commit):
    if commit is None:
        return None
    if re.fullmatch('[0-9a-f]{40}', commit) is None:
        raise ValueError('Darwin native receipt requires an exact source commit')
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=ROOT, text=True, timeout=30).strip()
    if git('rev-parse', 'HEAD') != commit:
        raise ValueError('Darwin native checkout differs from its required commit')
    tree = git('rev-parse', 'HEAD^{tree}')
    if re.fullmatch('[0-9a-f]{40}', tree) is None:
        raise ValueError('Darwin native checkout lacks its exact tree')
    git('diff', '--quiet', 'HEAD', '--')
    if git('ls-files', '--others', '--exclude-standard', '--', 'mobile', 'internal', 'deploy', 'cmd', 'configs', 'go.mod', 'go.sum'):
        raise ValueError('Darwin native receipt cannot include unpublished inputs')
    return dict(repository='Eabusham2/router-vpn', commit=commit, tree=tree)


def receipt_path(path):
    if path is None:
        return None
    path = Path(path).absolute()
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise ValueError('Darwin native receipt requires a new owned file')
    return path


def publish_receipt(path, result, workspace):
    if workspace.exists() or workspace.is_symlink():
        raise ValueError('Darwin native build workspace did not retire')
    if path is not None:
        with path.open('x', encoding='utf-8') as output:
            json.dump(result, output, indent=2, sort_keys=True)
            output.write('\n')


def native_fixture_compile(compiler, image, package):
    # The installed fixture signs exact copies of these original race images.
    # Omit only linker symbols/DWARF so codesign does not rewrite debug data
    # unrelated to native acceptance within its unchanged ten-second bound.
    return [compiler, 'test', '-c', '-race', '-mod=readonly', '-tags='+','.join(TAGS),
            '-ldflags=-checklinkname=0 -s -w', '-o', image, package]


def execute(source, go='go', *, environment=None):
    environment = dict(os.environ if environment is None else environment)
    arch, uid = required_host(environment)
    source, before = checked_sources(source)
    compiler, captured = selected_compiler(go, source, environment)
    sudo = UID.privilege_tool()
    with tempfile.TemporaryDirectory(prefix='routervpn-darwin-node-child-') as temporary:
        work = Path(temporary).resolve()
        work.chmod(0o755)
        child, peer = work/'child.test', work/'peer.test'
        for image, package in ((child, './cmd/sing-box'), (peer, './protocol/routervpnamnezia')):
            UID.run(native_fixture_compile(compiler, image, package), cwd=source, env=captured, timeout=600)
            image.chmod(0o755)
        if checked_sources(source)[1] != before:
            raise ValueError('Darwin native sources changed while compiling original images')
        identities = {path: image_identity(path) for path in (child, peer)}
        command = ['/usr/bin/env', FLAG+'=1', 'ROUTERVPN_DARWIN_NODE_CHILD_UID='+str(uid),
                   'ROUTERVPN_DARWIN_NODE_CHILD_SHA256='+identities[child][-1],
                   'ROUTERVPN_DARWIN_NODE_CHAIN_PEER='+str(peer),
                   'ROUTERVPN_DARWIN_NODE_CHAIN_PEER_SHA256='+identities[peer][-1],
                   'GORACE=atexit_sleep_ms=0', str(child), '-test.run=^'+HARNESS+'$',
                   '-test.v', '-test.count=1', '-test.timeout=930s']
        if sudo:
            command = [sudo, '-n', '--', *command]
        output = UID.run(command, cwd=ROOT, env=captured, timeout=960, sudo=sudo)
        print(output, end='' if output.endswith('\n') else '\n')
        check_verdict(output)
        if checked_sources(source)[1] != before or any(image_identity(path) != value for path, value in identities.items()):
            raise ValueError('Darwin native acceptance changed its original sources or images')
        result = dict(schema=1, gate='generated-darwin-ordered-child', scope='generated-command-utun',
                      target='darwin/'+arch, toolchain=BUILD.TOOLCHAIN,
                      pins={'sing-box': BUILD.PIN, 'xray': BUILD.POLICY.XRAY.XRAY_PIN},
                      source_files=before, source_sha256=hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                      artifacts={role: {'bytes': identities[path][2], 'sha256': identities[path][-1]}
                                 for role, path in (('generated-child-test', child), ('independent-ordered-peer', peer))},
                      cases=list(CASES), output_sha256=hashlib.sha256(output.encode()).hexdigest())
    if work.exists():
        raise ValueError('Darwin native acceptance did not retire its compilation workspace')
    return result


def standalone(go='go', *, environment=None, receipt=None, required_commit=None):
    environment = dict(os.environ if environment is None else environment)
    required_host(environment)
    repository = repository_identity(required_commit)
    path = receipt_path(receipt)
    compiler, captured = selected_compiler(go, ROOT, environment)
    previous = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix='routervpn-darwin-child-core-') as temporary:
        workspace = Path(temporary).resolve()
        core, xray = workspace/'core', workspace/'xray'
        try:
            os.environ.clear(); os.environ.update(captured)
            BUILD.checkout(core, 'https://github.com/SagerNet/sing-box.git', BUILD.PIN)
            BUILD.checkout(xray, 'https://github.com/XTLS/Xray-core.git', BUILD.POLICY.XRAY.XRAY_PIN)
            BUILD.pristine(core, BUILD.PIN); BUILD.pristine(xray, BUILD.POLICY.XRAY.XRAY_PIN)
            BUILD.POLICY.prepare_native(core, xray)
            BUILD.PERFORMANCE.prepare(core); BUILD.OPENVPN.prepare(core)
            BUILD.EXTERNAL.prepare(core, go=str(compiler), env=captured); BUILD.BUFFERS.prepare(core)
            BUILD.run([compiler, 'mod', 'tidy'], cwd=core, env=captured)
            BUILD.run([compiler, 'mod', 'verify'], cwd=core, env=captured)
            BUILD.POLICY.AMNEZIA.verify(core)
            result = execute(core, str(compiler), environment=captured)
        finally:
            os.environ.clear(); os.environ.update(previous)
    if repository_identity(required_commit) != repository:
        raise ValueError('Darwin source checkout changed during native acceptance')
    result['repository'] = repository
    publish_receipt(path, result, workspace)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, nargs='?')
    parser.add_argument('--standalone', action='store_true')
    parser.add_argument('--go', default=os.environ.get('GO', 'go'))
    parser.add_argument('--require-commit')
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    if args.standalone == (args.source is not None) or not args.standalone and (args.receipt or args.require_commit):
        parser.error('provide exact prepared source or --standalone; receipt/commit require standalone')
    try:
        if args.standalone:
            standalone(args.go, receipt=args.receipt, required_commit=args.require_commit)
        else:
            execute(args.source, args.go)
    except subprocess.CalledProcessError as failure:
        if failure.output:
            raw = failure.output[-32768:]
            sys.stderr.write(raw if isinstance(raw, str) else raw.decode('utf-8', errors='replace'))
        raise
