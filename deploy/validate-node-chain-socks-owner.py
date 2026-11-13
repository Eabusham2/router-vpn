#!/usr/bin/env python3
"""Validate a dormant SOCKS middle's original encrypted Box/association owner."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
SUITE = 'socks-owner'
PACKAGE = 'github.com/sagernet/sing-box/protocol/routervpnamnezia'
ROOTS = ('TestRouterVPNNodeSOCKSMiddleEncryptedOwnership',
         'TestRouterVPNNodeSOCKSMiddleOriginalFactoryAndRefusals')
MODES = ('wg', 'awg2-fast', 'awg2-strong')
LEAVES = ('closed-source-and-native-capture', 'encrypted-private-public', 'selected-dns',
          'invalidated-association-keeps-box-close')
REFUSALS = ('password', 'auth-downgrade', 'relay-domain', 'late-original-factory')
ENCRYPTED = (ROOTS[0], *(ROOTS[0]+'/'+mode+suffix for mode in MODES
                       for suffix in ('', *('/'+leaf for leaf in LEAVES))))
FACTORY = (ROOTS[1], *(ROOTS[1]+'/'+leaf for leaf in REFUSALS))
VERDICTS = (*ENCRYPTED, *FACTORY)
ORIGINAL_ROOT = 'TestRouterVPNDesktopImportedWGSSPeerTraffic'
ORIGINAL = (ORIGINAL_ROOT, *(ORIGINAL_ROOT+'/'+leaf for leaf in (
    'entry-public-only', 'strict-public-tls', 'paired-final-proof', 'final-public-proof',
    'dns-final-refusal-restore', 'entry-cannot-bypass-final-dns', 'entry-cannot-bypass-final-health',
    'wrong-final-key', 'wrong-node-restored', 'wrong-public-restored', 'mtu-authenticated-final',
    'cover-drop-restored', 'authenticated-final-throughput', 'wrong-entry-key')))
OWNER = 'mobile/chain/socks_owner.go.tmpl'
OWNER_PROJECTION = 'protocol/routervpnnodesocks/socks_owner.go'
PROJECTIONS = {
    OWNER: OWNER_PROJECTION,
    'mobile/desktop/node_chain_socks_middle_test.go.tmpl':
        'protocol/routervpnamnezia/routervpn_desktop_node_chain_socks_middle_test.go',
    'mobile/desktop/node_imported_peer_linux_test.go.tmpl':
        'protocol/routervpnamnezia/routervpn_desktop_node_imported_peer_linux_test.go',
}
CONTROLS = (
    dict(name='original-association-join',
         before='for _, op := range all { o.closeErr = errors.Join(o.closeErr, op.close()) }',
         after='_ = all // causal omission of original association join',
         root=ROOTS[0], cases=ENCRYPTED, leaf=LEAVES[3],
         witness='original Box close escaped held invalidated SOCKS control reader'),
    dict(name='late-factory-join', before='<-s.constructed',
         after='// causal omission of original native factory join',
         root=ROOTS[1], cases=FACTORY, leaf='late-original-factory',
         witness='original Box abandoned late native SOCKS factory'),
    dict(name='original-source-owner', before=' || original != o.capture.source',
         after='', root=ROOTS[0], cases=ENCRYPTED, leaf=LEAVES[0],
         witness='foreign reconstructed source gained original native owner'),
)
HEX40 = re.compile(r'[0-9a-f]{40}')


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


# Use the already tested trusted preparation/process/image helpers, not a second
# native pipeline. The candidate still supplies its exact shipping preparers.
COMMON = module('socks_owner_trusted_common', ROOT/'deploy/validate-linux-hy2-source.py')
execute = COMMON.execute
git = COMMON.git
image_identity = COMMON.image_identity
load_gate = COMMON.load_gate
prepare = COMMON.prepare


def selection(source, source_sha, output):
    if not HEX40.fullmatch(source_sha):
        raise ValueError('Exact SOCKS owner candidate commit is required')
    path = output.parent/'selection.json'
    if path.is_symlink() or not path.is_file():
        raise ValueError('Original trusted owner selection is missing')
    raw = path.read_bytes()
    record = json.loads(raw)
    if record.get('schema') != 1 or record.get('suite') != SUITE or record.get('source_sha') != source_sha \
            or record.get('validation_scope') != 'read-only-source-candidate':
        raise ValueError('SOCKS owner selection changed original suite or candidate')
    for field in ('validator_sha', 'validator_tree', 'base_sha', 'base_tree', 'source_sha', 'source_tree'):
        if not isinstance(record.get(field), str) or not HEX40.fullmatch(record[field]):
            raise ValueError('SOCKS owner selection lost exact Git identities')
    if git(source, 'rev-parse', 'HEAD') != source_sha \
            or git(source, 'rev-parse', 'HEAD^{tree}') != record['source_tree'] \
            or git(source, 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError('SOCKS owner checkout differs from original clean selection')
    if git(ROOT, 'rev-parse', 'HEAD') != record['validator_sha'] \
            or git(ROOT, 'rev-parse', 'HEAD^{tree}') != record['validator_tree']:
        raise ValueError('SOCKS owner validator differs from original trusted selection')
    return record, raw


def checked_sources(gate, source, core):
    _, records = gate.NODE.checked_sources(core)
    records = dict(records)
    for original, projected in PROJECTIONS.items():
        template, native = source/original, core/projected
        if template.is_symlink() or native.is_symlink() or not template.is_file() or not native.is_file() \
                or native.read_bytes() != template.read_bytes():
            raise ValueError('SOCKS owner lost exact native projection: '+projected)
        records['owner/'+projected] = hashlib.sha256(native.read_bytes()).hexdigest()
    for relative in ('dns/transport/conn_pool.go', 'dns/transport/multiplexer.go',
                     'dns/transport/udp.go', 'protocol/socks/outbound.go'):
        native = core/relative
        original = COMMON.subprocess.check_output(
            ['git', 'show', gate.BUILD.PIN+':'+relative], cwd=core, timeout=20)
        if native.is_symlink() or native.read_bytes() != original:
            raise ValueError('SOCKS owner changed its original pinned caller: '+relative)
        records['owner-pinned/'+relative] = hashlib.sha256(original).hexdigest()
    packet = module('socks_owner_packet_capture', source/'deploy/prepare-sing-packet-concurrency.py')
    packet.verify(core)
    for path in sorted((core/packet.COPY).rglob('*')):
        if path.is_symlink():
            raise ValueError('SOCKS owner sing association copy contains a link')
        if path.is_file():
            records['owner-sing/'+path.relative_to(core/packet.COPY).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    # The owner remains absent from ordinary registration; a private captured
    # registry is the only native construction seam exercised by this gate.
    registry = (core/'include/registry.go').read_text()
    if 'routervpnnodesocks' in registry:
        raise ValueError('Dormant SOCKS owner gained ordinary registry admission')
    return records


def required_failures(control):
    leaves = tuple(case for case in control['cases'] if case.endswith('/'+control['leaf']))
    failed = set(leaves)
    for leaf in leaves:
        parent = leaf
        while '/' in parent:
            parent = parent.rsplit('/', 1)[0]
            failed.add(parent)
    return set(leaves), failed


def require_control(text, status, control):
    if status != 1 or any(token in text for token in
            ('WARNING: DATA RACE', 'panic:', 'fatal error:', '[build failed]', 'signal:')):
        raise ValueError('SOCKS owner control had an unrelated process, build or race failure')
    expected = set(control['cases'])
    leaves, failures = required_failures(control)
    started, ended, witnesses = set(), set(), {}
    package_started = terminal = False
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError as error:
            raise ValueError('SOCKS owner control contains unframed output') from error
        if not isinstance(event, dict):
            raise ValueError('SOCKS owner control contains a non-event')
        action, test, package = event.get('Action'), event.get('Test'), event.get('Package')
        if action == 'build-output':
            if started or package_started or terminal or event.get('ImportPath') != PACKAGE+'.test' \
                    or not isinstance(event.get('Output'), str):
                raise ValueError('SOCKS owner control has foreign or late build output')
            continue
        if package != PACKAGE or terminal or action in ('skip', 'build-fail'):
            raise ValueError('SOCKS owner control has foreign, late or skipped records')
        if test:
            if test not in expected or not package_started:
                raise ValueError('SOCKS owner control used a foreign test or lost package start')
            if action == 'run':
                if test in started or test in ended:
                    raise ValueError('SOCKS owner control repeated a test')
                ancestors = test.split('/')
                for count in range(1, len(ancestors)):
                    parent = '/'.join(ancestors[:count])
                    if parent not in started or parent in ended:
                        raise ValueError('SOCKS owner control lost its active original ancestor')
                started.add(test)
            elif action == 'output':
                if test not in started or test in ended or not isinstance(event.get('Output'), str):
                    raise ValueError('SOCKS owner witness lost its active original test')
                witnesses[test] = witnesses.get(test, '') + event['Output']
            elif action in ('pass', 'fail'):
                wanted = 'fail' if test in failures else 'pass'
                children = {name for name in expected if name.startswith(test+'/')}
                if action != wanted or test not in started or test in ended or not children.issubset(ended):
                    raise ValueError('SOCKS owner control has wrong, repeated or early verdict')
                ended.add(test)
            else:
                raise ValueError('SOCKS owner control has unexpected test action')
        elif action == 'start':
            if package_started or started:
                raise ValueError('SOCKS owner control repeated package start')
            package_started = True
        elif action == 'output':
            if not package_started or not isinstance(event.get('Output'), str):
                raise ValueError('SOCKS owner package output lost its original start')
            if control['witness'] in event['Output']:
                raise ValueError('SOCKS owner witness moved outside its original leaf')
        elif action == 'fail':
            if not package_started or started != expected or ended != expected:
                raise ValueError('SOCKS owner control omitted original siblings')
            terminal = True
        else:
            raise ValueError('SOCKS owner control has unexpected package action')
    if not terminal or started != expected or ended != expected:
        raise ValueError('SOCKS owner control omitted original root or leaves')
    for test, output in witnesses.items():
        count = output.count(control['witness'])
        if count != (1 if test in leaves else 0):
            raise ValueError('SOCKS owner control lost its exact original leaf witness')
    if any(test not in witnesses for test in leaves):
        raise ValueError('SOCKS owner control omitted an original failure witness')


def validate(source, source_sha, output, go='go'):
    if platform.system() != 'Linux':
        raise ValueError('Actual encrypted Linux reference target is required')
    source, output = Path(source).resolve(strict=True), Path(output).absolute()
    if output.is_symlink() or output.exists() or source == output or source in output.parents:
        raise ValueError('Owner validation output must be fresh and outside source')
    metadata, original_selection = selection(source, source_sha, output)
    output.mkdir(mode=0o700)
    gate = load_gate(source)
    env = dict(os.environ, CGO_ENABLED='1', GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='',
               GOMAXPROCS='2', GOGC='100', GOMEMLIMIT='2GiB')
    executable = Path(go).resolve() if os.path.sep in go else None
    if executable is not None:
        env['PATH'] = str(executable.parent)+os.pathsep+env.get('PATH', '')
    receipt = dict(schema=1, suite=SUITE, selection=metadata, scope='encrypted-box-owner-only',
                   installed_native_accepted=False, public_native_admission=False, phases=[])
    def run(name, command, cwd, captured, timeout):
        command = list(map(str, command))
        started = time.monotonic()
        log = output/(name+'.log')
        try:
            status, timed_out, joined = execute(command, cwd, captured, log, timeout)
            text = log.read_text(errors='replace')
        except Exception as error:
            text = (log.read_text(errors='replace') if log.exists() else '')+'\n'+str(error)
            log.write_text(text)
            receipt['phases'].append(dict(name=name, command=command, timeout=timeout,
                seconds=time.monotonic()-started, error=type(error).__name__))
            (output/'progress.json').write_text(json.dumps(receipt, indent=2)+'\n')
            raise
        receipt['phases'].append(dict(name=name, command=command, timeout=timeout,
            seconds=time.monotonic()-started, status=status, timed_out=timed_out,
            process_group_joined=joined, output_sha256=hashlib.sha256(text.encode()).hexdigest()))
        (output/'progress.json').write_text(json.dumps(receipt, indent=2)+'\n')
        if timed_out or not joined:
            raise RuntimeError('Original owner validation process timed out or did not join')
        return status, text
    with tempfile.TemporaryDirectory(prefix='routervpn-focused-socks-owner-', dir=output.parent) as temporary:
        work = Path(temporary)
        core, xray = work/'core', work/'xray'
        inherited = dict(os.environ)
        try:
            os.environ.update(env)
            prepare(gate, core, xray, env)
        finally:
            os.environ.clear()
            os.environ.update(inherited)
        before = checked_sources(gate, source, core)
        compiler, captured, architecture = gate.NODE.selected_compiler(go, core, env)
        captured['CGO_ENABLED'] = '1'
        receipt.update(target='linux/'+architecture, toolchain=gate.BUILD.TOOLCHAIN,
            compiler=str(compiler), source_files=before,
            source_sha256=hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            resource_limits=dict(parallel_packages=1, GOMAXPROCS=2, GOGC=100, GOMEMLIMIT='2GiB'))
        image = work/'socks-owner.test'
        flags = ['-race', '-p=1', '-mod=readonly', '-tags='+','.join(gate.NODE.TAGS), '-ldflags=-checklinkname=0']
        status, text = run('encrypted-owner-build', [compiler, 'test', '-c', *flags, '-o', image,
            './protocol/routervpnamnezia'], core, captured, 600)
        if status:
            raise ValueError('Actual encrypted SOCKS owner image failed to compile')
        original_image = image_identity(image)
        status, text = run('encrypted-owner-baseline', [image, '-test.run=^('+'|'.join(ROOTS)+')$',
            '-test.count=1', '-test.timeout=90s', '-test.v'], core, captured, 100)
        if status:
            raise ValueError('Actual encrypted SOCKS owner baseline failed')
        gate.NODE.require_native_verdicts(text, VERDICTS, 'original encrypted SOCKS middle owner')
        status, text = run('original-undecorated-peer', [image, '-test.run=^'+ORIGINAL_ROOT+'$',
            '-test.count=1', '-test.timeout=90s', '-test.v'], core, captured, 100)
        if status:
            raise ValueError('Original undecorated encrypted WG/SS peer failed')
        gate.NODE.require_native_verdicts(text, ORIGINAL, 'original undecorated encrypted WG/SS peer')
        original = (core/OWNER_PROJECTION).read_text()
        results = []
        for control in CONTROLS:
            if original.count(control['before']) != 1:
                raise ValueError('Original SOCKS owner causal seam changed: '+control['name'])
            changed = original.replace(control['before'], control['after'], 1)
            if changed == original:
                raise ValueError('SOCKS owner control did not change original source')
            replacement, overlay = work/(control['name']+'.go'), work/(control['name']+'.json')
            replacement.write_text(changed)
            overlay.write_text(json.dumps({'Replace': {str(core/OWNER_PROJECTION): str(replacement)}}))
            status, text = run(control['name'], [compiler, 'test', *flags, '-json', '-overlay='+str(overlay),
                '-run=^'+control['root']+'$', '-count=1', '-timeout=90s', './protocol/routervpnamnezia'],
                core, captured, 600)
            require_control(text, status, control)
            results.append(dict(name=control['name'], cases=list(control['cases']),
                failed_cases=sorted(required_failures(control)[1]), witness=control['witness'],
                mutated_sha256=hashlib.sha256(changed.encode()).hexdigest()))
        if checked_sources(gate, source, core) != before or image_identity(image) != original_image \
                or selection(source, source_sha, output)[1] != original_selection:
            raise ValueError('SOCKS owner validation changed original sources, image or selection')
        receipt.update(cases=list(VERDICTS), original_peer_cases=list(ORIGINAL), controls=results,
                       image=dict(bytes=original_image[2], sha256=original_image[-1]))
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
    print(json.dumps({key: result[key] for key in
        ('suite', 'scope', 'target', 'completed', 'installed_native_accepted', 'public_native_admission')},
        sort_keys=True))


if __name__ == '__main__':
    main()
