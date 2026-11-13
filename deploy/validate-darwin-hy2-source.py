#!/usr/bin/env python3
"""Validate the installed HY2 fixture adoption without claiming kernel acceptance."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
SUITE = 'darwin-hy2'
ROOTS = (
    'TestDesktopDarwinInstalledImportedNodeChainFixtureKeepsOriginalSources',
    'TestDesktopDarwinInstalledHysteriaNodeChainFixtureKeepsOriginalSources',
)
IMPORTED = (ROOTS[0], *(ROOTS[0]+'/'+name for name in ('custom-wg', 'custom-awg-fast', 'custom-awg-strong')))
HYSTERIA = (ROOTS[1], *(ROOTS[1]+'/'+name for name in ('wg-wg', 'awg-fast-awg-strong', 'awg-strong-awg-fast')))
AUTHORITY = IMPORTED + HYSTERIA
ENCRYPTED_ROOT = 'TestRouterVPNDesktopNodeChainHysteriaFinalTraffic'
ENCRYPTED = (ENCRYPTED_ROOT, *(ENCRYPTED_ROOT+'/'+pair+suffix
    for pair in ('wg--wg', 'awg2-fast--awg2-strong', 'awg2-strong--awg2-fast')
    for suffix in ('', *('/'+case for case in (
        'complete-private-public-proof', 'final-selected-dns', 'final-password', 'final-sni',
        'final-trust', 'final-mask', 'prefix-key', 'final-route', 'dns-route',
        'held-cancel-join', 'stop-drains-final-socket')))))
HELPER = 'cmd/client/desktop_node_chain_hysteria_darwin_native_test.go'
PEER_TEMPLATE = 'mobile/desktop/node_chain_hysteria_final_test.go.tmpl'
PEER_PROJECTION = 'protocol/routervpnamnezia/routervpn_node_chain_hysteria_final_darwin_test.go'
MASK_BEFORE = '"password": mask'
MASK_AFTER = '"password": mask + "-uncaptured"'
MASK_WITNESS = 'compiled installed final substituted TLS, password, Salamander or packet prefix'
HEX40 = re.compile(r'[0-9a-f]{40}')


CLIENT_PACKAGE = 'router-vpn/cmd/client'
MASK_CASES = AUTHORITY[-4:]
CAPTURE_ROOT = 'TestDesktopDarwinHysteriaReferencePhysicalCapture'
REFERENCE_ROOT = 'TestRouterVPNDesktopNodeChainDarwinReferenceCapture'
REFERENCE_CASES = (REFERENCE_ROOT, *(REFERENCE_ROOT+'/'+name for name in
    ('missing-reference', 'foreign-address', 'linux-pair', 'source-address')))
CAPTURE_MARKER = 'ROUTERVPN_DARWIN_NODE_CHAIN_CAPTURED_IPV4='


def execute(command, cwd, env, log, timeout):
    # Reuse the trusted fixed validator's original process-family join.
    spec = importlib.util.spec_from_file_location('focused_hy2_process',
                                                 ROOT/'deploy/test_focused_multihop_clocks.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.execute(list(map(str, command)), cwd, env, log, timeout)



def captured_reference_address(text, require_verdicts):
    require_verdicts(text, (CAPTURE_ROOT,), 'original Darwin physical capture')
    lines = [line for line in text.splitlines() if CAPTURE_MARKER in line]
    if len(lines) != 1:
        raise ValueError('Darwin reference needs one original physical address receipt')
    match = re.fullmatch(r'\s+desktop_node_chain_hysteria_darwin_native_test\.go:[0-9]+: '
                         + re.escape(CAPTURE_MARKER) + r'([^\s]+)', lines[0])
    if match is None:
        raise ValueError('Darwin reference physical receipt lost its original test source')
    value = match.group(1)
    address = ipaddress.IPv4Address(value)
    if str(address) != value or address.is_unspecified or address.is_loopback or address.is_link_local \
            or address.is_multicast or value == '255.255.255.255':
        raise ValueError('Darwin reference lacks a captured unicast physical IPv4')
    return value


def reference_command(image, root, sudo, address=None):
    if sudo not in (None, '/usr/bin/sudo') or sudo is None and os.geteuid() != 0:
        raise ValueError('Darwin reference lost its original privilege tool')
    if root not in (CAPTURE_ROOT, REFERENCE_ROOT, ENCRYPTED_ROOT):
        raise ValueError('Darwin reference selected a foreign execution root')
    values = ['PATH=/usr/bin:/bin:/usr/sbin:/sbin', 'GORACE=atexit_sleep_ms=0',
              'ROUTERVPN_DARWIN_NODE_CHAIN_REFERENCE=1']
    if root == CAPTURE_ROOT:
        if address is not None:
            raise ValueError('Physical discovery must not borrow an existing address')
        values.append('ROUTERVPN_DARWIN_NODE_CHAIN_CAPTURE=1')
    else:
        if not isinstance(address, str):
            raise ValueError('Darwin reference requires its captured physical address')
        parsed = ipaddress.IPv4Address(address)
        if str(parsed) != address or parsed.is_unspecified or parsed.is_loopback or parsed.is_link_local \
                or parsed.is_multicast or address == '255.255.255.255':
            raise ValueError('Darwin reference requires a captured unicast IPv4')
        values.append('ROUTERVPN_DARWIN_NODE_CHAIN_ADDRESS='+address)
    seconds = 90 if root == ENCRYPTED_ROOT else 30
    command = ['/usr/bin/env', '-i', *values, str(image), '-test.run=^'+root+'$',
               '-test.count=1', '-test.timeout='+str(seconds)+'s', '-test.v']
    return ([sudo, '-n', '--'] if sudo else []) + command


def execute_privileged(gate, command, cwd, env, log, timeout, sudo):
    # The existing native runner owns privilege-aware cleanup of this exact
    # process group. Its timeout/failed-join exception can never become PASS.
    try:
        output = gate.CONTROLLER.UID.run(command, cwd=cwd, env=env, timeout=timeout, sudo=sudo)
        code = 0
    except subprocess.CalledProcessError as error:
        output, code = error.output or b'', error.returncode
    except BaseException as error:
        log.write_text(str(error)+'\n')
        raise
    if isinstance(output, bytes):
        output = output.decode('utf-8', errors='replace')
    log.write_text(output)
    return code, False, True

def require_mask_verdict(text, status):
    if status != 1 or any(token in text for token in ('WARNING: DATA RACE', 'panic:', 'fatal error:', '[build failed]')):
        raise ValueError('Salamander control had a signal, panic, build failure or unexpected exit')
    expected, started, ended, witnesses = set(MASK_CASES), set(), set(), {}
    package_started, terminal = False, False
    package_output = ''
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError) as error:
            raise ValueError('Salamander control has unframed output') from error
        if not isinstance(event, dict) or event.get('Package') != CLIENT_PACKAGE or terminal:
            raise ValueError('Salamander control has foreign, late or malformed events')
        action, test = event.get('Action'), event.get('Test')
        if 'Test' in event and (not isinstance(test, str) or not test):
            raise ValueError('Salamander control lost its exact test identity')
        if not isinstance(action, str):
            raise ValueError('Salamander control has no original event action')
        if action != 'output' and 'Output' in event:
            raise ValueError('Salamander control attached output to a non-output event')
        if test is None:
            if action == 'start':
                if package_started or started:
                    raise ValueError('Salamander control repeated its package start')
                package_started = True
            elif action == 'output':
                if not package_started or not isinstance(event.get('Output'), str) or MASK_WITNESS in event['Output']:
                    raise ValueError('Salamander package output borrowed an original leaf witness')
                package_output += event['Output']
            elif action == 'fail':
                if not package_started or started != expected or ended != expected:
                    raise ValueError('Salamander control has an incomplete package terminal')
                terminal = True
            else:
                raise ValueError('Salamander control has an unexpected package event')
            continue
        if not package_started or test not in expected:
            raise ValueError('Salamander control used a foreign or unstarted test')
        if action == 'run':
            if test in started or test in ended:
                raise ValueError('Salamander control repeated a test start')
            if test != MASK_CASES[0] and (MASK_CASES[0] not in started or MASK_CASES[0] in ended):
                raise ValueError('Salamander cipher leaf lost its active original root')
            started.add(test)
        elif action == 'output':
            if test not in started or test in ended or not isinstance(event.get('Output'), str):
                raise ValueError('Salamander witness lacks its active original leaf')
            if test == MASK_CASES[0] and MASK_WITNESS in event['Output']:
                raise ValueError('Salamander root borrowed an original leaf witness')
            witnesses[test] = witnesses.get(test, '') + event['Output']
        elif action == 'fail':
            if test not in started or test in ended:
                raise ValueError('Salamander failure lacks its unique original start')
            if test == MASK_CASES[0] and not set(MASK_CASES[1:]).issubset(ended):
                raise ValueError('Salamander root failed before all original cipher leaves')
            ended.add(test)
        else:
            raise ValueError('Salamander control has a mixed or unexpected test action')
    if not package_started or not terminal or started != expected or ended != expected:
        raise ValueError('Salamander control omitted an original package, root or cipher leaf')
    if MASK_WITNESS in package_output or MASK_WITNESS in witnesses.get(MASK_CASES[0], ''):
        raise ValueError('Salamander witness occurred outside its original cipher leaf')
    if any(witnesses.get(leaf, '').count(MASK_WITNESS) != 1 for leaf in MASK_CASES[1:]):
        raise ValueError('Salamander control lost the intended witness in an original cipher leaf')


def load_gate(source):
    spec = importlib.util.spec_from_file_location('focused_darwin_hy2_candidate',
                                                source/'deploy/test_macos_node_chain_host.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(source, *args):
    return subprocess.check_output(['git', '-C', str(source), *args], text=True, timeout=20).strip()


def selection(source, source_sha, output):
    if not HEX40.fullmatch(source_sha):
        raise ValueError('Exact candidate commit is required')
    metadata_file = output.parent/'selection.json'
    if metadata_file.is_symlink() or not metadata_file.is_file():
        raise ValueError('Original trusted selection metadata is missing')
    metadata = json.loads(metadata_file.read_text())
    if metadata.get('schema') != 1 or metadata.get('suite') != SUITE or metadata.get('source_sha') != source_sha \
            or metadata.get('validation_scope') != 'read-only-source-candidate':
        raise ValueError('HY2 validation selection changed its original suite or candidate')
    for name in ('validator_sha', 'validator_tree', 'base_sha', 'base_tree', 'source_sha', 'source_tree'):
        if not isinstance(metadata.get(name), str) or not HEX40.fullmatch(metadata[name]):
            raise ValueError('HY2 selection lost exact Git identities')
    if git(source, 'rev-parse', 'HEAD') != source_sha or git(source, 'rev-parse', 'HEAD^{tree}') != metadata['source_tree'] \
            or git(source, 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError('Candidate checkout differs from original clean selection')
    if git(ROOT, 'rev-parse', 'HEAD') != metadata['validator_sha'] \
            or git(ROOT, 'rev-parse', 'HEAD^{tree}') != metadata['validator_tree']:
        raise ValueError('Trusted validator differs from original selection')
    return metadata, metadata_file.read_bytes()


def image_identity(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise ValueError('Compiled image is not its original regular file')
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest())


def prepare(gate, work, env):
    # Same pinned provider and exact Darwin build-tag projections as the native gate.
    return gate.EXTERNAL.prepared_peer_source(work, env)


def validate(source, source_sha, output, go='go'):
    if platform.system() != 'Darwin':
        raise ValueError('Actual Darwin encrypted reference target is required')
    source, output = Path(source).resolve(strict=True), Path(output).absolute()
    if output.is_symlink() or output.exists() or source == output or source in output.parents:
        raise ValueError('Validation output must be fresh and outside candidate source')
    metadata, original_selection = selection(source, source_sha, output)
    output.mkdir(mode=0o700)
    gate = load_gate(source)
    if tuple(gate.AUTHORITY_CASES) != IMPORTED or tuple(gate.HYSTERIA_AUTHORITY_CASES) != HYSTERIA:
        raise ValueError('HY2 adoption lost its complete original 4 plus new 4 authority inventory')
    if len(gate.BUILD.EXTERNAL.darwin_node_chain_peer_copies()) != 7:
        raise ValueError('HY2 adoption lost its exact seven original Darwin projections')
    if tuple(gate.CASES[:28]) != tuple(gate.ORIGINAL_CASES) or len(gate.CASES) != 37 or len(gate.MEASUREMENT_CASES) != 24:
        raise ValueError('HY2 adoption changed its original installed case prerequisites')
    env = dict(os.environ, CGO_ENABLED='1', GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='',
               GOMAXPROCS='2', GOGC='100', GOMEMLIMIT='2GiB')
    # Preparers invoke the same pinned compiler through their existing go calls.
    executable = Path(go).resolve() if os.path.sep in go else None
    if executable is not None:
        env['PATH'] = str(executable.parent)+os.pathsep+env.get('PATH', '')
    receipt = dict(schema=1, suite=SUITE, selection=metadata,
                   scope='source-authority-and-encrypted-reference-only',
                   installed_native_accepted=False, phases=[])
    def run(name, command, cwd, captured, timeout, *, privileged=False):
        started = time.monotonic()
        try:
            if privileged:
                status, timed_out, joined = execute_privileged(gate, command, cwd, captured, output/(name+'.log'), timeout, sudo)
            else:
                status, timed_out, joined = execute(command, cwd, captured, output/(name+'.log'), timeout)
            text = (output/(name+'.log')).read_text(errors='replace')
        except Exception as error:
            log = output/(name+'.log')
            text = (log.read_text(errors='replace') if log.exists() else '')+'\n'+str(error)
            log.write_text(text)
            receipt['phases'].append(dict(name=name, command=list(map(str, command)), timeout=timeout,
                                          seconds=time.monotonic()-started, error=type(error).__name__))
            (output/'progress.json').write_text(json.dumps(receipt, indent=2)+'\n')
            raise
        (output/(name+'.log')).write_text(text)
        receipt['phases'].append(dict(name=name, command=list(map(str, command)), timeout=timeout,
                                      seconds=time.monotonic()-started, status=status,
                                      timed_out=timed_out, process_group_joined=joined,
                                      output_sha256=hashlib.sha256(text.encode()).hexdigest()))
        (output/'progress.json').write_text(json.dumps(receipt, indent=2)+'\n')
        if timed_out or not joined:
            raise RuntimeError('Original validation process group timed out or did not join')
        return status, text
    with tempfile.TemporaryDirectory(prefix='routervpn-focused-hy2-', dir=output.parent) as temporary:
        work = Path(temporary)
        compiler, captured = gate.CONTROLLER.UID.compiler_toolchain(source, go, env)
        captured['CGO_ENABLED'] = '1'
        captured['PATH'] = str(Path(compiler).parent)+os.pathsep+captured.get('PATH', '')
        original_environment = dict(os.environ)
        try:
            os.environ.update(captured)
            core = prepare(gate, work, captured)
        finally:
            os.environ.clear()
            os.environ.update(original_environment)
        before = gate.source_identity(core)
        if HELPER not in before['application'] or PEER_PROJECTION not in before['peer']:
            raise ValueError('HY2 native projection or original installed helper is absent')
        projections = gate.BUILD.EXTERNAL.darwin_node_chain_peer_copies()
        if PEER_PROJECTION not in projections or (core/PEER_PROJECTION).read_bytes() != projections[PEER_PROJECTION]:
            raise ValueError('HY2 original Darwin projection changed')
        policy = gate.BUILD.digest()
        architecture = {'x86_64': 'amd64', 'arm64': 'arm64'}.get(platform.machine())
        if architecture is None or captured.get('GOOS', 'darwin') != 'darwin' or captured.get('GOARCH', architecture) != architecture:
            raise ValueError('HY2 reference cannot execute a foreign architecture')
        receipt.update(target='darwin/'+architecture, toolchain=gate.BUILD.TOOLCHAIN, compiler=str(compiler),
                       resource_limits=dict(parallel_packages=1, GOMAXPROCS=2, GOGC=100, GOMEMLIMIT='2GiB'), source_files=before,
                       source_sha256=hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest())
        controller, peer = work/'controller.test', work/'peer.test'
        status, text = run('controller-build', [compiler, 'test', '-c', '-race', '-p=1', '-mod=readonly',
            '-tags=routervpn_controller_privileged', '-o', str(controller), './cmd/client'], source, captured, 300)
        if status:
            raise ValueError('Actual installed controller image failed to compile')
        controller_identity = image_identity(controller)
        for name, root, expected in (('imported-authority', ROOTS[0], IMPORTED), ('hysteria-authority', ROOTS[1], HYSTERIA)):
            status, text = run(name, [str(controller), '-test.v', '-test.count=1', '-test.timeout=30s',
                '-test.run=^'+root+'$'], source, captured, 40)
            if status:
                raise ValueError('Actual installed source authority failed')
            gate.EXTERNAL.NODE.require_native_verdicts(text, expected, 'focused original Darwin source authority')
        helper = source/HELPER
        raw = helper.read_text()
        if raw.count(MASK_BEFORE) != 1:
            raise ValueError('Original captured Salamander source-control seam changed')
        mutated = raw.replace(MASK_BEFORE, MASK_AFTER, 1)
        if mutated == raw:
            raise ValueError('Salamander control did not change the captured source')
        replacement, overlay = work/'uncaptured-mask.go', work/'uncaptured-mask-overlay.json'
        replacement.write_text(mutated)
        overlay.write_text(json.dumps({'Replace': {str(helper): str(replacement)}}))
        mutated_image = work/'source-mask-control.test'
        status, text = run('source-mask-build', [compiler, 'test', '-race', '-c', '-p=1', '-mod=readonly',
            '-tags=routervpn_controller_privileged', '-overlay='+str(overlay),
            '-o', str(mutated_image), './cmd/client'], source, captured, 300)
        if status:
            raise ValueError('Original source-mask control failed to compile')
        mutated_identity = image_identity(mutated_image)
        status, text = run('source-mask-control', [compiler, 'tool', 'test2json', '-t', '-p', CLIENT_PACKAGE,
            str(mutated_image), '-test.v', '-test.count=1', '-test.timeout=30s',
            '-test.run=^'+ROOTS[1]+'$'], source, captured, 40)
        require_mask_verdict(text, status)
        if image_identity(mutated_image) != mutated_identity:
            raise ValueError('Source-mask control replaced its captured image')
        status, text = run('peer-build', [compiler, 'test', '-c', '-race', '-p=1', '-mod=readonly',
            '-tags='+gate.PEER_TAGS, '-ldflags=-checklinkname=0', '-o', str(peer),
            './protocol/routervpnamnezia'], core, captured, 600)
        if status:
            raise ValueError('Actual complete Darwin encrypted reference image failed to compile')
        peer_identity = image_identity(peer)
        sudo = gate.CONTROLLER.UID.privilege_tool()
        status, text = run('reference-physical-capture', reference_command(controller, CAPTURE_ROOT, sudo),
                           source, captured, 40, privileged=True)
        if status:
            raise ValueError('Original Darwin physical capture failed')
        address = captured_reference_address(text, gate.EXTERNAL.NODE.require_native_verdicts)
        receipt['reference_capture'] = dict(address=address, root=CAPTURE_ROOT, privilege_tool=sudo,
                                            authority='reference-peer-only')
        status, text = run('reference-address-authority', reference_command(peer, REFERENCE_ROOT, sudo, address),
                           core, captured, 40, privileged=True)
        if status:
            raise ValueError('Original Darwin reference address authority failed')
        gate.EXTERNAL.NODE.require_native_verdicts(text, REFERENCE_CASES, 'original Darwin reference address authority')
        status, text = run('encrypted-hysteria-final', reference_command(peer, ENCRYPTED_ROOT, sudo, address),
                           core, captured, 100, privileged=True)
        if status:
            raise ValueError('Actual original encrypted HY2 reference failed')
        gate.EXTERNAL.NODE.require_native_verdicts(text, ENCRYPTED, 'focused original encrypted HY2 reference')
        if gate.source_identity(core) != before or gate.BUILD.digest() != policy or image_identity(controller) != controller_identity \
                or image_identity(peer) != peer_identity or helper.read_text() != raw:
            raise ValueError('HY2 validation changed original source or compiled image identity')
        if selection(source, source_sha, output)[1] != original_selection:
            raise ValueError('HY2 validation replaced its original source selection')
        receipt.update(authority_cases=list(AUTHORITY), encrypted_cases=list(ENCRYPTED), reference_cases=list(REFERENCE_CASES),
                       mask_control=dict(witness=MASK_WITNESS, mutated_sha256=hashlib.sha256(mutated.encode()).hexdigest()),
                       images={name: dict(bytes=identity[2], sha256=identity[-1]) for name, identity in
                               (('controller', controller_identity), ('source-mask-control', mutated_identity), ('encrypted-peer', peer_identity))})
    receipt['completed'] = True
    (output/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    result = validate(args.source, args.source_sha, args.output, args.go)
    print(json.dumps({key: result[key] for key in ('suite', 'scope', 'target', 'completed', 'installed_native_accepted')}, sort_keys=True))


if __name__ == '__main__':
    main()
