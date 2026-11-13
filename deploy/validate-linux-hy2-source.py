#!/usr/bin/env python3
"""Validate the installed HY2 fixture adoption without claiming kernel acceptance."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
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
SUITE = 'linux-hy2'
ROOTS = (
    'TestDesktopLinuxInstalledNodeChainFixtureKeepsCompiledAuthority',
    'TestDesktopLinuxInstalledImportedNodeChainFixtureKeepsOriginalSources',
    'TestDesktopLinuxInstalledPrefixCandidateFixtureKeepsClosedAuthority',
    'TestDesktopLinuxInstalledHysteriaNodeChainFixtureKeepsOriginalSources',
)
AUTHORITY = (
    ROOTS[0], *(ROOTS[0]+'/'+name for name in (
        '3-nodes', '4-nodes', 'awg-fast-wg-3-nodes', 'wg-awg-strong-3-nodes',
        'awg-strong-awg-fast-3-nodes', 'wg-awg-fast-awg-strong-4-nodes',
        'awg-fast-awg-strong-wg-4-nodes', 'awg-strong-wg-awg-fast-4-nodes')),
    ROOTS[1], *(ROOTS[1]+'/'+name for name in ('custom-wg', 'custom-awg-fast', 'custom-awg-strong')),
    ROOTS[2], *(ROOTS[2]+'/'+name for name in ('wg', 'awg-fast', 'awg-strong')),
    ROOTS[3], *(ROOTS[3]+'/'+name for name in ('wg-wg', 'awg-fast-awg-strong', 'awg-strong-awg-fast')),
)
ENCRYPTED_ROOT = 'TestRouterVPNDesktopNodeChainHysteriaFinalTraffic'
ENCRYPTED = (ENCRYPTED_ROOT, *(ENCRYPTED_ROOT+'/'+pair+suffix
    for pair in ('wg--wg', 'awg2-fast--awg2-strong', 'awg2-strong--awg2-fast')
    for suffix in ('', *('/'+case for case in (
        'complete-private-public-proof', 'final-selected-dns', 'final-password', 'final-sni',
        'final-trust', 'final-mask', 'prefix-key', 'final-route', 'dns-route',
        'held-cancel-join', 'stop-drains-final-socket')))))
HELPER = 'cmd/client/desktop_node_chain_linux_hysteria_tun_native_test.go'
PEER_TEMPLATE = 'mobile/desktop/node_chain_hysteria_final_test.go.tmpl'
PEER_PROJECTION = 'protocol/routervpnamnezia/routervpn_desktop_node_chain_hysteria_final_test.go'
MASK_BEFORE = '"password": mask'
MASK_AFTER = '"password": mask + "-uncaptured"'
MASK_WITNESS = 'compiled installed final substituted TLS, password, Salamander or packet prefix'
HEX40 = re.compile(r'[0-9a-f]{40}')


CLIENT_PACKAGE = 'router-vpn/cmd/client'
MASK_CASES = AUTHORITY[-4:]


def execute(command, cwd, env, log, timeout):
    # Reuse the trusted fixed validator's original process-family join.
    spec = importlib.util.spec_from_file_location('focused_hy2_process',
                                                 ROOT/'deploy/test_focused_multihop_clocks.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.execute(list(map(str, command)), cwd, env, log, timeout)


def require_mask_verdict(text, status):
    if status != 1 or any(token in text for token in ('WARNING: DATA RACE', 'panic:', 'fatal error:', '[build failed]')):
        raise ValueError('Salamander control had a signal, panic, build failure or unexpected exit')
    expected, started, ended, witnesses = set(MASK_CASES), set(), set(), {}
    terminal = False
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        action, test, package = event.get('Action'), event.get('Test'), event.get('Package')
        if action in ('skip', 'build-fail'):
            raise ValueError('Salamander control skipped a test or failed to build')
        if test:
            if package != CLIENT_PACKAGE or test not in expected or terminal:
                raise ValueError('Salamander control used a foreign or late test')
            if action == 'run':
                if test in started or test in ended:
                    raise ValueError('Salamander control repeated a test start')
                if test != MASK_CASES[0] and (MASK_CASES[0] not in started or MASK_CASES[0] in ended):
                    raise ValueError('Salamander cipher leaf lost its active original root')
                started.add(test)
            elif action == 'output':
                if test not in started or test in ended:
                    raise ValueError('Salamander witness lacks its active original leaf')
                witnesses[test] = witnesses.get(test, '') + event.get('Output', '')
            elif action == 'fail':
                if test not in started or test in ended:
                    raise ValueError('Salamander failure lacks its unique original start')
                if test == MASK_CASES[0] and not set(MASK_CASES[1:]).issubset(ended):
                    raise ValueError('Salamander root failed before all original cipher leaves')
                ended.add(test)
            else:
                raise ValueError('Salamander control has a mixed or unexpected test action')
        elif action in ('pass', 'fail', 'skip'):
            if package != CLIENT_PACKAGE or action != 'fail' or terminal or ended != expected:
                raise ValueError('Salamander control has an incomplete or foreign package terminal')
            terminal = True
    if not terminal or started != expected or ended != expected:
        raise ValueError('Salamander control omitted an original root or cipher leaf')
    if any(witnesses.get(leaf, '').count(MASK_WITNESS) != 1 for leaf in MASK_CASES[1:]):
        raise ValueError('Salamander control lost the intended witness in an original cipher leaf')


def load_gate(source):
    spec = importlib.util.spec_from_file_location('focused_linux_hy2_candidate',
                                                source/'deploy/test_linux_node_host_tun.py')
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


def prepare(gate, source, xray, env):
    gate.BUILD.checkout(source, 'https://github.com/SagerNet/sing-box.git', gate.BUILD.PIN)
    gate.BUILD.checkout(xray, 'https://github.com/XTLS/Xray-core.git', gate.BUILD.POLICY.XRAY.XRAY_PIN)
    gate.BUILD.prepare_native_sources(source, xray, env)


def validate(source, source_sha, output, go='go'):
    if platform.system() != 'Linux':
        raise ValueError('Actual Linux encrypted reference target is required')
    source, output = Path(source).resolve(strict=True), Path(output).absolute()
    if output.is_symlink() or output.exists() or source == output or source in output.parents:
        raise ValueError('Validation output must be fresh and outside candidate source')
    metadata, original_selection = selection(source, source_sha, output)
    output.mkdir(mode=0o700)
    gate = load_gate(source)
    if tuple(gate.NODE_CHAIN_HOST_AUTHORITY_CASES) != AUTHORITY or tuple(gate.HYSTERIA_FINAL.VERDICTS) != ENCRYPTED:
        raise ValueError('HY2 adoption lost its complete 21/37 required inventory')
    env = dict(os.environ, CGO_ENABLED='1', GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='',
               GOMAXPROCS='2', GOGC='100', GOMEMLIMIT='2GiB')
    # Preparers invoke the same pinned compiler through their existing go calls.
    executable = Path(go).resolve() if os.path.sep in go else None
    if executable is not None:
        env['PATH'] = str(executable.parent)+os.pathsep+env.get('PATH', '')
    receipt = dict(schema=1, suite=SUITE, selection=metadata,
                   scope='source-authority-and-encrypted-reference-only',
                   installed_native_accepted=False, phases=[])
    def run(name, command, cwd, captured, timeout):
        started = time.monotonic()
        try:
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
        core, xray = work/'core', work/'xray'
        original_environment = dict(os.environ)
        try:
            # Existing preparation helpers also contain inherited subprocess calls.
            os.environ.update(env)
            prepare(gate, core, xray, env)
        finally:
            os.environ.clear()
            os.environ.update(original_environment)
        _, before = gate.checked_sources(core)
        if 'app/'+HELPER not in before or 'native/'+PEER_PROJECTION not in before \
                or (core/PEER_PROJECTION).read_bytes() != (source/PEER_TEMPLATE).read_bytes():
            raise ValueError('HY2 native projection or original installed helper is absent')
        compiler, captured, architecture = gate.NODE.selected_compiler(go, core, env)
        captured['CGO_ENABLED'] = '1'
        receipt.update(target='linux/'+architecture, toolchain=gate.BUILD.TOOLCHAIN, compiler=str(compiler),
                       resource_limits=dict(parallel_packages=1, GOMAXPROCS=2, GOGC=100, GOMEMLIMIT='2GiB'), source_files=before,
                       source_sha256=hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest())
        controller, peer = work/'controller.test', work/'peer.test'
        status, text = run('controller-build', [compiler, 'test', '-c', '-race', '-p=1', '-mod=readonly',
            '-tags=routervpn_controller_privileged', '-o', str(controller), './cmd/client'], source, captured, 300)
        if status:
            raise ValueError('Actual installed controller image failed to compile')
        controller_identity = image_identity(controller)
        status, text = run('controller-authority', [str(controller), '-test.v', '-test.timeout=30s',
            '-test.run=^('+'|'.join(ROOTS)+')$'], source, captured, 40)
        if status:
            raise ValueError('Actual installed source authority failed')
        gate.NODE.require_native_verdicts(text, AUTHORITY, 'focused installed HY2 complete source authority')
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
        status, text = run('source-mask-control', [compiler, 'test', '-race', '-p=1', '-mod=readonly', '-json',
            '-tags=routervpn_controller_privileged', '-overlay='+str(overlay), '-run=^'+ROOTS[3]+'$',
            '-count=1', '-timeout=30s', './cmd/client'], source, captured, 300)
        require_mask_verdict(text, status)
        status, text = run('peer-build', [compiler, 'test', '-c', '-race', '-p=1', '-mod=readonly',
            '-tags='+','.join(gate.NODE.TAGS), '-ldflags=-checklinkname=0', '-o', str(peer),
            './protocol/routervpnamnezia'], core, captured, 600)
        if status:
            raise ValueError('Actual complete encrypted reference image failed to compile')
        peer_identity = image_identity(peer)
        status, text = run('encrypted-hysteria-final', [str(peer), '-test.run=^'+ENCRYPTED_ROOT+'$',
            '-test.count=1', '-test.timeout=90s', '-test.v'], core, captured, 100)
        if status:
            raise ValueError('Actual original encrypted HY2 reference failed')
        gate.NODE.require_native_verdicts(text, ENCRYPTED, 'focused original encrypted HY2 reference')
        if gate.checked_sources(core)[1] != before or image_identity(controller) != controller_identity \
                or image_identity(peer) != peer_identity or helper.read_text() != raw:
            raise ValueError('HY2 validation changed original source or compiled image identity')
        if selection(source, source_sha, output)[1] != original_selection:
            raise ValueError('HY2 validation replaced its original source selection')
        receipt.update(authority_cases=list(AUTHORITY), encrypted_cases=list(ENCRYPTED),
                       mask_control=dict(witness=MASK_WITNESS, mutated_sha256=hashlib.sha256(mutated.encode()).hexdigest()),
                       images={name: dict(bytes=identity[2], sha256=identity[-1]) for name, identity in
                               (('controller', controller_identity), ('encrypted-peer', peer_identity))})
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
