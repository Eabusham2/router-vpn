#!/usr/bin/env python3
"""Require the shipping ordered Server worker against independent encrypted peers.

The fixture opens only original private namespace handles. It uses real WG/AWG
and SS2022 engines, original selected DNS, authenticated SOCKS/UoT2, and joined
native stop. Missing native privileges are a failure, never a mocked success.
"""
from pathlib import Path
import argparse
import ast
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

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

BUILD = load('server_encrypted_build', 'build-native-runtime.py')
NODE = load('server_encrypted_original_peer', 'test_desktop_node_physical.py')
UID = load('server_encrypted_owned_process', 'test_desktop_socket_uid.py')
WORKER = load('server_encrypted_worker', 'test_server_node_chain_native.py')
CASES = ('wg', 'awg-fast', 'awg-strong', 'mixed-three', 'wrong-first-key', 'wrong-middle-key',
         'wrong-ss-key', 'wrong-awg-parameters', 'wrong-node', 'failed-selected-dns',
         'wrong-public-trust', 'cancel-prefix', 'admission-restrictions', 'joined-active-udp')
NEGATIVE = frozenset(case for case in CASES if case.startswith('wrong-') or case in ('failed-selected-dns', 'cancel-prefix'))
MODES = {case: ('wg', 'wg') for case in CASES}
MODES.update({'awg-fast': ('wg', 'awg2-fast'), 'wrong-awg-parameters': ('wg', 'awg2-fast'),
              'awg-strong': ('awg2-strong', 'wg'), 'mixed-three': ('wg', 'awg2-fast', 'awg2-strong')})
# Preserve the exact ordinary peer package's registered transport closure.
# Native PQ execution is neither tagged nor selected by this WG/AWG gate.
TAGS = NODE.TAGS
if 'routervpn_native_pq' in TAGS or 'routervpn_pq_traffic_test' in TAGS:
    raise ValueError('Encrypted Server ordinary gate acquired a foreign native diagnostic')
TEMPLATE = 'mobile/server_chain_acceptance/encrypted_linux_test.go.tmpl'
TARGET = 'cmd/sing-box/routervpn_server_chain_encrypted_linux_test.go'
OWNER = 'routervpn-server-encrypted-test-source.json'
NATIVE = 'TestServerChainEncryptedNative'
SOURCE = 'TestServerChainEncryptedSourceInventory'
RECEIPT_FIELDS = {'modes', 'case', 'capture_sha256', 'source_sha256', 'prefixes', 'ready', 'retired', 'selected_dns',
                  'final_tcp', 'final_udp', 'peer_joined', 'worker_joined'}


def run(*arguments, **options):
    try:
        return UID.run(*arguments, **options)
    except subprocess.CalledProcessError as error:
        raw = error.output or b''
        if isinstance(raw, bytes):
            raw = raw[-16384:].decode('utf-8', errors='replace')
        else:
            raw = raw[-16384:]
        if raw:
            sys.stderr.write('Original encrypted Server compiler/native failure (bounded tail):\n'+raw+'\n')
            sys.stderr.flush()
        raise


def image_identity(path):
    path = Path(path)
    info = path.lstat()
    if not path.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o6022 or not info.st_mode & 0o111 or not 0 < info.st_size <= 512 << 20:
        raise ValueError('Encrypted Server lost an original compiled image')
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, hashlib.sha256(path.read_bytes()).hexdigest())


def install_fixture(core):
    core = Path(core)
    if core.is_symlink() or subprocess.check_output(['git', '-C', str(core), 'rev-parse', 'HEAD'], text=True).strip() != BUILD.PIN:
        raise ValueError('Encrypted Server requires the original pinned core')
    target, record, template = core/TARGET, core/OWNER, ROOT/TEMPLATE
    if any(path.is_symlink() for path in (template, target, record, target.parent)):
        raise ValueError('Encrypted Server source contains a linked owner')
    raw = template.read_bytes()
    if not raw.startswith(b'//go:build linux && !android && routervpn_server_chain_acceptance\n\npackage main\n'):
        raise ValueError('Encrypted Server fixture changed its native test selector')
    if record.exists():
        old = json.loads(record.read_text())
        if old.get('schema') != 1 or old.get('target') != TARGET or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != old.get('sha256'):
            raise ValueError('Encrypted Server generated fixture was changed')
    elif target.exists() and target.read_bytes() != raw:
        raise ValueError('Encrypted Server target is unowned')
    target.write_bytes(raw)
    record.write_text(json.dumps({'schema': 1, 'target': TARGET, 'sha256': hashlib.sha256(raw).hexdigest()}, sort_keys=True)+'\n')


def checked_sources(core):
    core, records = NODE.checked_sources(Path(core))
    WORKER.verify_sources(core)
    for path in WORKER.PREP.inputs():
        records['server/'+path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for target, raw in WORKER.PREP.copies().items():
        if (core/target).is_symlink() or (core/target).read_bytes() != raw:
            raise ValueError('Encrypted Server lost actual shipping worker bytes')
        records['generated/'+target] = hashlib.sha256(raw).hexdigest()
    required = ('node_wg_peer_test.go.tmpl', 'node_awg_peer_test.go.tmpl', 'node_imported_peer_linux_test.go.tmpl', 'node_chain_peer_linux_test.go.tmpl')
    for name in required:
        destination = NODE.PREP.PEER_TEMPLATES[name]
        if (core/destination).read_bytes() != (ROOT/'mobile/desktop'/name).read_bytes():
            raise ValueError('Encrypted Server peer was projected or substituted')
    if (core/TARGET).is_symlink() or (core/TARGET).read_bytes() != (ROOT/TEMPLATE).read_bytes():
        raise ValueError('Encrypted Server native fixture is not the original source')
    for name in (TEMPLATE, 'deploy/test_server_node_chain_encrypted.py', 'deploy/test_server_node_chain_encrypted_runner.py', '.github/workflows/server-node-chain-encrypted.yml'):
        path = ROOT/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Encrypted Server lost required gate input')
        records['acceptance/'+name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return core, records


def check_verdict(output, case, *, source_only=False):
    if case not in CASES and not source_only:
        raise ValueError('Unknown encrypted Server case')
    root = SOURCE if source_only else NATIVE
    expected = {root, *(root+'/'+name for name in (CASES if source_only else (case,)))}
    runs, passes, receipts = set(), set(), []
    root_passed = False
    for line in output.splitlines():
        stripped = line.strip()
        if '--- FAIL:' in line or '--- SKIP:' in line or 'WARNING: DATA RACE' in line or 'panic:' in line:
            raise ValueError('Encrypted Server native test failed, skipped or raced')
        match = re.fullmatch(r'=== RUN\s+(\S+)', stripped)
        if match:
            name = match[1]
            if root_passed or name not in expected or name in runs or name != root and root not in runs:
                raise ValueError('Encrypted Server started unexpected or late work')
            runs.add(name)
        match = re.fullmatch(r'--- PASS: (\S+) \([0-9.]+s\)', stripped)
        if match:
            name = match[1]
            if name not in expected or name not in runs or name in passes:
                raise ValueError('Encrypted Server has unmatched/duplicate PASS')
            if name == root:
                # Go buffers child PASS reports after the parent PASS. Native
                # work and original-retirement receipt must already exist.
                if runs != expected or not source_only and len(receipts) != 1:
                    raise ValueError('Encrypted Server parent passed before original retirement')
                root_passed = True
            passes.add(name)
        if 'ENCRYPTED_SERVER_RECEIPT ' in line:
            if source_only or root_passed or root+'/'+case not in runs or root+'/'+case in passes:
                raise ValueError('Encrypted Server emitted a late or foreign receipt')
            raw = line.split('ENCRYPTED_SERVER_RECEIPT ', 1)[1]
            pairs = []
            value = json.loads(raw, object_pairs_hook=lambda entries: pairs.extend(key for key, _ in entries) or dict(entries))
            if value.get('modes') != list(MODES[case]):
                raise ValueError('Encrypted Server receipt downgraded an original native cipher')
            if set(value) != RECEIPT_FIELDS or len(pairs) != len(set(pairs)) or value['case'] != case or type(value['prefixes']) is not int or value['prefixes'] != (3 if case == 'mixed-three' else 2):
                raise ValueError('Encrypted Server receipt identity/inventory changed')
            if any(value[name] is not True for name in ('retired', 'worker_joined', 'peer_joined')):
                raise ValueError('Encrypted Server omitted original joined cleanup')
            if any(not isinstance(value[name], str) or re.fullmatch('[0-9a-f]{64}', value[name]) is None for name in ('capture_sha256', 'source_sha256')):
                raise ValueError('Encrypted Server lost source/capture identity')
            ready = case not in NEGATIVE
            if value['ready'] is not ready or value['selected_dns'] is not ready or any(type(value[key]) is not int or value[key] < 0 for key in ('final_tcp', 'final_udp')):
                raise ValueError('Encrypted Server changed its required success/refusal verdict')
            if ready and (value['final_tcp'] <= 0 or value['final_udp'] <= 0):
                raise ValueError('Encrypted Server omitted real final encrypted traffic')
            receipts.append(value)
    if runs != expected or passes != expected or not root_passed or (len(receipts) != (0 if source_only else 1)) or not re.search(r'^PASS\r?$', output, re.M):
        raise ValueError('Encrypted Server omitted an exact required verdict')
    return receipts[0] if receipts else {'source_cases': list(CASES)}



def namespace_program(source_sha256):
    """Transfer only sealed stdlib namespace code across the private UID boundary.

    Namespace root maps to outer root, not the runner account. It must not
    reopen the runner's private checkout or import repository modules there.
    The exact source hash was already captured by checked_sources before build.
    """
    path = Path(__file__).resolve()
    if path.is_symlink() or not path.is_file():
        raise ValueError('Encrypted Server lost original namespace source')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != source_sha256:
        raise ValueError('Encrypted Server namespace source changed after capture')
    tree = ast.parse(raw, filename=str(path))
    projected = ast.parse('from pathlib import Path\nimport hashlib\nimport os\nimport platform\nimport re\nimport stat\nimport subprocess\nimport sys\n').body
    for name, captured in (('CASES', CASES), ('NATIVE', NATIVE)):
        definitions = [node for node in tree.body if isinstance(node, ast.Assign)
                       and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                       and node.targets[0].id == name]
        if len(definitions) != 1 or ast.literal_eval(definitions[0].value) != captured:
            raise ValueError('Encrypted Server namespace changed original case inventory')
        projected.append(definitions[0])
    for name in ('image_identity', 'inside_namespace'):
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
        if len(functions) != 1 or functions[0].decorator_list:
            raise ValueError('Encrypted Server namespace lost an original required function')
        projected.append(functions[0])
    projected.extend(ast.parse("""
if __name__ == '__main__':
    if len(sys.argv) != 8:
        raise ValueError('Encrypted Server namespace requires exact original arguments')
    sys.exit(inside_namespace(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]),
        {'driver': sys.argv[4], 'peer': sys.argv[5], 'worker': sys.argv[6]}, sys.argv[7]))
""").body)
    return ast.unparse(ast.Module(body=projected, type_ignores=[]))


def inside_namespace(driver, peer, worker, identities, case):
    if platform.system() != 'Linux' or os.geteuid() != 0 or case not in CASES:
        raise ValueError('Encrypted Server needs its isolated native Linux root')
    for role, path in (('driver', driver), ('peer', peer), ('worker', worker)):
        if image_identity(path)[-1] != identities[role]:
            raise ValueError('Encrypted Server namespace lost a compiled image')
    original = os.environ.get('ROUTERVPN_SERVER_CHAIN_OUTER_NETNS')
    current = os.stat('/proc/self/ns/net')
    if not original or original == f'{current.st_dev}:{current.st_ino}':
        raise ValueError('Encrypted Server refused the original host network namespace')
    # Every mutation is below the newly owned mount/network/PID namespaces.
    subprocess.run(['mount', '--make-rprivate', '/'], check=True, timeout=5)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run'], check=True, timeout=5)
    commands = (
        ('link', 'set', 'lo', 'up'), ('netns', 'add', 'rvpn-peer'),
        ('link', 'add', 'rvpn-test', 'type', 'veth', 'peer', 'name', 'rvpn-peer'),
        ('link', 'set', 'rvpn-peer', 'netns', 'rvpn-peer'),
        ('addr', 'add', '192.168.210.1/30', 'dev', 'rvpn-test'), ('link', 'set', 'rvpn-test', 'up'),
        ('route', 'add', 'default', 'via', '192.168.210.2', 'dev', 'rvpn-test'),
        ('netns', 'exec', 'rvpn-peer', 'ip', 'link', 'set', 'lo', 'up'),
        ('netns', 'exec', 'rvpn-peer', 'ip', 'addr', 'add', '192.168.210.2/30', 'dev', 'rvpn-peer'),
        ('netns', 'exec', 'rvpn-peer', 'ip', 'link', 'set', 'rvpn-peer', 'up'))
    for command in commands:
        subprocess.run(['ip', *command], check=True, timeout=5)
    env = dict(os.environ, ROUTERVPN_SERVER_CHAIN_NATIVE_NS='1', ROUTERVPN_SERVER_CHAIN_PEER=str(peer),
               ROUTERVPN_SERVER_CHAIN_PEER_SHA256=identities['peer'], ROUTERVPN_SERVER_CHAIN_IMAGE=str(worker),
               ROUTERVPN_SERVER_CHAIN_IMAGE_SHA256=identities['worker'], GORACE='atexit_sleep_ms=0')
    try:
        result = subprocess.run([str(driver), '-test.run=^'+NATIVE+'$/^'+re.escape(case)+'$', '-test.v', '-test.count=1', '-test.timeout=90s'], env=env, timeout=105)
    finally:
        subprocess.run(['ip', 'netns', 'delete', 'rvpn-peer'], check=True, timeout=5)
    return result.returncode


def repository_identity(required):
    if required is None:
        return None
    if re.fullmatch('[0-9a-f]{40}', required) is None:
        raise ValueError('Encrypted Server requires an exact source commit')
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=ROOT, text=True, timeout=30).strip()
    if git('rev-parse', 'HEAD') != required:
        raise ValueError('Encrypted Server source commit changed')
    git('diff', '--quiet', 'HEAD', '--')
    if git('ls-files', '--others', '--exclude-standard', '--', 'mobile', 'internal', 'deploy', 'cmd', '.github', 'go.mod', 'go.sum'):
        raise ValueError('Encrypted Server source includes unpublished inputs')
    return {'commit': required, 'tree': git('rev-parse', 'HEAD^{tree}')}


def execute(core, go='go', *, env=None, receipt=None, compile_only=False):
    if platform.system() != 'Linux':
        raise ValueError('Encrypted Server requires actual Linux')
    captured = dict(os.environ if env is None else env, GOWORK='off')
    if captured.get('GOOS', 'linux') != 'linux' or captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('Encrypted Server forbids cross-host or non-race acceptance')
    captured['CGO_ENABLED'] = '1'
    install_fixture(core)
    core, before = checked_sources(core)
    compiler, captured = UID.compiler_toolchain(core, go, captured)
    architecture = run([compiler, 'env', 'GOARCH'], cwd=core, env=captured).strip()
    if architecture not in ('amd64', 'arm64'):
        raise ValueError('Encrypted Server architecture is not required native inventory')
    receipt = Path(receipt).absolute() if receipt else None
    if receipt and (receipt.exists() or receipt.is_symlink() or not receipt.parent.is_dir()):
        raise ValueError('Encrypted Server receipt requires a new owned path')
    with tempfile.TemporaryDirectory(prefix='routervpn-server-encrypted-') as temporary:
        workspace = Path(temporary).resolve()
        workspace.chmod(0o755)  # Test images contain no private lease input.
        driver, peer, worker = workspace/'acceptance.test', workspace/'peer.test', workspace/'sing-box'
        common = ['-race', '-mod=readonly', '-p=1', '-tags='+','.join(TAGS), '-ldflags=-checklinkname=0']
        print('Compiling original shipping Server CLI', flush=True)
        run([compiler, 'build', *common, '-o', worker, './cmd/sing-box'], cwd=core, env=captured, timeout=600)
        print('Compiling unchanged independent encrypted peer', flush=True)
        run([compiler, 'test', '-c', *common, '-o', peer, './protocol/routervpnamnezia'], cwd=core, env=captured, timeout=600)
        driver_flags = [arg if not arg.startswith('-tags=') else arg+',routervpn_server_chain_acceptance' for arg in common]
        print('Compiling actual encrypted acceptance driver', flush=True)
        run([compiler, 'test', '-c', *driver_flags, '-o', driver, './cmd/sing-box'], cwd=core, env=captured, timeout=600)
        images = {role: image_identity(path) for role, path in (('driver', driver), ('peer', peer), ('worker', worker))}
        if checked_sources(core)[1] != before:
            raise ValueError('Encrypted Server source changed during compilation')
        source_output = run([driver, '-test.run=^'+SOURCE+'$', '-test.v', '-test.count=1', '-test.timeout=60s'], cwd=core, env=captured, timeout=75)
        check_verdict(source_output, None, source_only=True)
        print(source_output, end='')
        verdicts = []
        if not compile_only:
            sudo = UID.privilege_tool()
            original = os.stat('/proc/self/ns/net')
            native_env = dict(captured, TMPDIR='/tmp', ROUTERVPN_SERVER_CHAIN_OUTER_NETNS=f'{original.st_dev}:{original.st_ino}')
            program = namespace_program(before['acceptance/deploy/test_server_node_chain_encrypted.py'])
            for case in CASES:
                command = ['unshare', '--user', '--map-root-user', '--mount', '--net', '--pid', '--fork', '--mount-proc',
                           sys.executable, '-I', '-c', program, str(driver), str(peer), str(worker),
                           images['driver'][-1], images['peer'][-1], images['worker'][-1], case]
                if sudo:
                    command = [sudo, '-n', '--preserve-env=ROUTERVPN_SERVER_CHAIN_OUTER_NETNS', '--', *command]
                output = run(command, cwd=workspace, env=native_env, timeout=125, sudo=sudo)
                verdicts.append(check_verdict(output, case)); print(output, end='')
        if checked_sources(core)[1] != before or any(image_identity(path) != images[role] for role, path in (('driver', driver), ('peer', peer), ('worker', worker))):
            raise ValueError('Encrypted Server original source/image changed during acceptance')
        result = {'schema': 1, 'gate': 'ordered-server-encrypted', 'scope': 'compile-and-source-only' if compile_only else 'actual-encrypted-server-worker',
                  'target': 'linux/'+architecture, 'pin': BUILD.PIN, 'source_files': before,
                  'source_sha256': hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                  'images': {role: {'sha256': identity[-1], 'bytes': identity[2]} for role, identity in images.items()},
                  'required_cases': list(CASES), 'cases': verdicts}
    if workspace.exists():
        raise ValueError('Encrypted Server compilation workspace did not retire')
    if receipt:
        if compile_only:
            raise ValueError('Compile-only verification cannot publish native acceptance receipt')
        with receipt.open('x', encoding='utf-8') as output:
            json.dump(result, output, indent=2, sort_keys=True); output.write('\n')
    return result


def standalone(go='go', *, receipt=None, required_commit=None):
    repository = repository_identity(required_commit)
    compiler, captured = UID.compiler_toolchain(ROOT, go, dict(os.environ))
    old = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix='routervpn-server-encrypted-core-') as temporary:
        workspace = Path(temporary); core, xray = workspace/'core', workspace/'xray'
        try:
            os.environ.clear(); os.environ.update(captured)
            BUILD.checkout(core, 'https://github.com/SagerNet/sing-box.git', BUILD.PIN)
            BUILD.checkout(xray, 'https://github.com/XTLS/Xray-core.git', BUILD.POLICY.XRAY.XRAY_PIN)
            BUILD.pristine(core, BUILD.PIN); BUILD.pristine(xray, BUILD.POLICY.XRAY.XRAY_PIN)
            BUILD.POLICY.prepare_native(core, xray)
            BUILD.PERFORMANCE.prepare(core); BUILD.OPENVPN.prepare(core)
            BUILD.EXTERNAL.prepare(core, go=str(compiler), env=captured); BUILD.BUFFERS.prepare(core)
            BUILD.run([compiler, 'mod', 'tidy'], cwd=core, env=captured); BUILD.run([compiler, 'mod', 'verify'], cwd=core, env=captured)
            BUILD.POLICY.AMNEZIA.verify(core)
            result = execute(core, str(compiler), env=captured)
        finally:
            os.environ.clear(); os.environ.update(old)
    if repository_identity(required_commit) != repository or workspace.exists():
        raise ValueError('Encrypted Server original repository/workspace did not remain owned')
    result['repository'] = repository
    if receipt:
        path = Path(receipt).absolute()
        if path.exists() or path.is_symlink() or not path.parent.is_dir():
            raise ValueError('Encrypted Server receipt requires an unused owned path')
        with path.open('x', encoding='utf-8') as output:
            json.dump(result, output, indent=2, sort_keys=True); output.write('\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path); parser.add_argument('--go', default='go'); parser.add_argument('--standalone', action='store_true')
    parser.add_argument('--compile-only', action='store_true'); parser.add_argument('--receipt', type=Path); parser.add_argument('--require-commit')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    for role in ('driver', 'peer', 'worker'):
        parser.add_argument('--'+role, type=Path, help=argparse.SUPPRESS); parser.add_argument('--'+role+'-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--case', choices=CASES, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside:
        sys.exit(inside_namespace(args.driver, args.peer, args.worker, {role: getattr(args, role+'_sha256') for role in ('driver', 'peer', 'worker')}, args.case))
    if args.standalone and not args.core and not args.compile_only:
        result = standalone(args.go, receipt=args.receipt, required_commit=args.require_commit)
    elif args.core and not args.standalone and not args.require_commit:
        result = execute(args.core, args.go, receipt=args.receipt, compile_only=args.compile_only)
    else:
        parser.error('use --standalone with required commit, or --core [--compile-only]')
    print(json.dumps({key: value for key, value in result.items() if key != 'source_files'}, sort_keys=True))
