#!/usr/bin/env python3
"""Prove ordinary schema6 through actual encrypted providers and native Box.

The canonical TUN/interface and first physical loopback mapping are explicit
component fixtures. All native graphs, encrypted peers, exact original public
routes and selected DNS execute shipping code; this is not installed acceptance.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import re
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PEER_PACKAGE = 'github.com/sagernet/sing-box/protocol/routervpnamnezia'
BOX_PACKAGE = 'github.com/sagernet/sing-box'
PEER_TEMPLATE = 'mobile/chain_component/multiple_imported_test.go.tmpl'
MIXED_CANDIDATE_TEMPLATE = 'mobile/chain_component/mixed_local_candidates_test.go.tmpl'
MIXED_CANDIDATE_ROOT = 'TestRouterVPNMixedLocalCandidateMeasurements'
MIXED_CANDIDATES = ('9-2-7-wg-connected-original', '16-2-14-awg2-strong-closed-original',
                    '16-9-8-wg-connected-original', '16-9-8-wg-closed-original',
                    '9-2-7-awg2-fast-connected-late-catalog', '16-2-14-wg-closed-cancel-close',
                    '16-2-14-awg2-strong-connected-wrong-late-key',
                    '5-1-2-wg-connected-original', '5-1-2-awg2-fast-closed-original',
                    '8-2-5-awg2-strong-connected-original', '5-1-3-wg-closed-original',
                    '5-1-3-wg-connected-late-catalog', '5-1-2-wg-closed-cancel-close',
                    '5-1-3-wg-connected-wrong-interior-key', '5-1-3-wg-closed-wrong-private-id',
                    '10-1-8-wg-closed-original', '12-2-9-awg2-fast-connected-original',
                    '9-1-1-awg2-fast-closed-hostname', '9-1-7-awg2-fast-connected-hostname')
MIXED_TEMPLATE = 'mobile/chain_component/mixed_local_traffic_test.go.tmpl'
MIXED_ROOT = 'TestRouterVPNMixedLocalEncryptedTraffic'
PAIRED_INTERIOR_ROOT = 'TestRouterVPNPairedStreamInterior'
PAIRED_INTERIOR = ('original', 'wrong-interior-key', 'wrong-key-3', 'wrong-final', 'consecutive', 'deep-roles', 'deep-late-key')
MIXED = tuple(f'{count}-{mode}-{packets}-{outcome}' for count in (9, 16)
              for mode, packets in (('wg', 2), ('awg2-fast', 1), ('awg2-strong', 2))
              for outcome in ('traffic', 'late-key')) + tuple('9-awg2-fast-1-'+outcome for outcome in
                  ('hostname','hostname-collision','hostname-nxdomain','hostname-rebind','hostname-late-key'))
BOX_TEMPLATE = 'mobile/chain/multiple_imported_box_test.go.tmpl'
BOX_TARGET = 'routervpn_node_chain_multiple_imported_test.go'
PEER_TARGET = 'protocol/routervpnamnezia/routervpn_multiple_imported_component_test.go'
POSITIVE_ROOT = 'TestRouterVPNMultipleImportedEncryptedLocal'
NEGATIVE_ROOT = 'TestRouterVPNMultipleImportedEncryptedRefusals'
THROUGHPUT_ROOT = 'TestRouterVPNMultipleImportedExtendedThroughput'
THROUGHPUT = ('extended-nine', 'extended-sixteen')
BOX_POSITIVE = 'TestRouterVPNMultipleImportedPublicRouteOriginalOwners'
BOX_NEGATIVE = 'TestRouterVPNMultipleImportedPublicRouteRefusals'
POSITIVE = tuple('/'.join((mode, layout, layer))
                 for mode in ('wg', 'awg2-fast', 'awg2-strong')
                 for layout in ('adjacent', 'separated', 'paired-suffix', 'maximum-sparse', 'maximum-public')
                 for layer in (('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
                               if layout in ('adjacent', 'maximum-sparse') else ('off',))) + tuple(
                     'custom-entry/'+layer for layer in ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening'))
POSITIVE += ('wg/extended-nine/off', 'wg/extended-sixteen/off')
NEGATIVE = ('late-key-extended-nine', 'late-key-extended-sixteen', 'wrong-key-1', 'wrong-key-3', 'wrong-public-1', 'wrong-public-3',
            'wrong-final', 'selected-dns', 'cancel-second-public', 'retired-outer',
            'native-closed', 'foreign-source', 'public-dns-drift', 'final-layer-key', 'final-whitening') + tuple('custom-entry/'+fault for fault in (
                'wrong-key-0','wrong-public-0','wrong-key-1','wrong-public-1','wrong-final','selected-dns'))
BOX_CASES = {BOX_POSITIVE: ('adjacent', 'separated', 'maximum'),
             BOX_NEGATIVE: ('equal-source', 'copied-source', 'copied-route-owner', 'nil-original',
                            'foreign-observation', 'omitted-position', 'swapped-positions',
                            'changed-source-hash', 'changed-position', 'changed-ipv6',
                            'missing-prefix', 'retired-outer-owner')}
CONTROL = dict(root=BOX_NEGATIVE, leaf='equal-source', target='routervpn_node_chain.go',
               before='r.source == nil || r.source != r.originalSource ||',
               after='r.source == nil ||', witness='changed original public source retained route authority')
FATAL = ('panic:', 'fatal error:', 'test timed out', 'WARNING: DATA RACE')
JOIN_FAILURES = ('did not join', 'failed retirement', 'retirement failed', 'join deadline')


def load(name):
    spec = importlib.util.spec_from_file_location('multiple_imported_'+name, ROOT/'deploy'/name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SELECTED_ROOT = 'TestOriginalExtendedSelectedExecution'
SELECTED_CASES = tuple(f'{count}-{mode}-{action}' for count in (9, 16)
                       for mode, action in (('server', 'latency'), ('server', 'throughput'),
                                            ('auto', 'local'), ('auto', 'server')))
CONTINUOUS = '16-server-latency'
PARTS = tuple(f'16-server-latency-{first}-{first+3}' for first in range(1, 17, 4))
SELECTED_CASES += PARTS + tuple(f'{count}-{path}-response' for count in (9, 16)
                                for path in ('server', 'auto-local', 'auto-server'))


def awg_selected_cases(entry):
    cases = tuple(f'{count}-{entry}-{phase}' for count in (9, 16)
                  for phase in ('server-server', 'auto-local', 'auto-server', 'mtu', 'server-throughput'))
    return cases + (f'9-{entry}-server-latency',) + tuple(
        f'16-{entry}-server-latency-{first}-{first+3}' for first in range(1, 17, 4))


FAST_SELECTED_CASES = awg_selected_cases('awg2-fast')
STRONG_SELECTED_CASES = awg_selected_cases('awg2-strong')
AWG_SELECTED_CASES = FAST_SELECTED_CASES + STRONG_SELECTED_CASES
SELECTED_CASES += AWG_SELECTED_CASES

SELECTED_TEMPLATES = (
    'mobile/chain_component/extended_execution_client_test.go.tmpl',
    'mobile/chain_component/extended_execution_peer_test.go.tmpl',
    'mobile/server_chain_component/extended_execution_test.go.tmpl',
)


def selected_marker(leaf):
    if leaf in AWG_SELECTED_CASES:
        entry = 'awg2-fast' if leaf in FAST_SELECTED_CASES else 'awg2-strong'
        count, tail = leaf.split(f'-{entry}-')
        first, last, samples, transferred, response_samples = 0, 0, 0, 0, 0
        mode, winner = 'server', 'server'
        if tail in ('server-server', 'auto-local', 'auto-server'):
            mode, winner = tail.split('-')
            response_samples = 6
        elif tail == 'server-throughput':
            transferred = int(count)*(16 << 20)
        elif tail.startswith('server-latency'):
            positions = tail.removeprefix('server-latency').strip('-')
            first, last = map(int, positions.split('-')) if positions else (1, int(count))
            samples = (last-first+1)*50
        elif tail != 'mtu':
            raise ValueError('Unknown original AWG2 selected phase')
        return (f'QUALIFIED_SELECTED_NATIVE nodes={count} execution={mode} winner={winner} samples={samples} bytes={transferred} '
                f'first={first} last={last} response_samples={response_samples} entry_mode={entry} parameters_current=true')
    count, mode, action, *positions = leaf.split('-')
    first, last = (map(int, positions) if positions else (1, int(count))) if action == 'latency' else (0, 0)
    winner = 'server' if mode == 'server' else action
    samples = (last-first+1)*50 if action == 'latency' else 0
    transferred = int(count)*(16 << 20) if action == 'throughput' else 0
    response_samples = 6 if leaf.endswith('-response') else 0
    return f'QUALIFIED_SELECTED_NATIVE nodes={count} execution={mode} winner={winner} samples={samples} bytes={transferred} first={first} last={last} response_samples={response_samples}'


PEER_CASES = {PAIRED_INTERIOR_ROOT: PAIRED_INTERIOR, MIXED_CANDIDATE_ROOT: MIXED_CANDIDATES, MIXED_ROOT: MIXED, SELECTED_ROOT: SELECTED_CASES, POSITIVE_ROOT: POSITIVE, NEGATIVE_ROOT: NEGATIVE, THROUGHPUT_ROOT: THROUGHPUT}


def inventory():
    return {**PEER_CASES, **BOX_CASES}


def expected(root, leaf=None):
    cases = inventory().get(root)
    if cases is None or leaf is not None and leaf not in cases:
        raise ValueError('Uncaptured independent imported native case')
    if root in PEER_CASES and leaf is None:
        raise ValueError('Encrypted imported cases require their original bounded leaf')
    return {name: 1 for name in (root, *(root+'/'+case.replace('/', '_') for case in ((leaf,) if leaf else cases)))}


def selector(root, leaf=None):
    expected(root, leaf)
    return '/'.join('^'+re.escape(part)+'$' for part in (root+'/'+leaf.replace('/', '_') if leaf else root).split('/'))


def receipt(output, package):
    helper = load('test_desktop_native_root_phases.py')
    helper.PACKAGE = package
    return helper.load_receipt().complete_receipt(output)


def verdict(output, root, leaf=None):
    package = PEER_PACKAGE if root in PEER_CASES else BOX_PACKAGE
    rows, runs, passed, failed, terminal = receipt(output, package)
    required = expected(root, leaf)
    if terminal != 'pass' or failed or runs != required or passed != required:
        raise ValueError('Independent imported native inventory omitted, duplicated or failed a required case')
    if any(any(marker in row.get('Output', '') for marker in (*FATAL, *JOIN_FAILURES)) for row in rows):
        raise ValueError('Independent imported native receipt contains a fatal or unjoined result')
    if root == POSITIVE_ROOT and leaf in ('wg/extended-nine/off', 'wg/extended-sixteen/off'):
        count = 9 if leaf == 'wg/extended-nine/off' else 16
        name = root+'/'+leaf.replace('/', '_')
        marker = f'QUALIFIED_LATENCY_HISTORY nodes={count} receipts={count} samples={count*50}'
        emitted = [row.get('Output', '').strip() for row in rows if row.get('Test') == name and 'QUALIFIED_LATENCY_HISTORY' in row.get('Output', '')]
        if len(emitted) != 1 or not emitted[0].endswith(marker):
            raise ValueError('Missing complete original per-member encrypted latency history')
    if root == MIXED_CANDIDATE_ROOT:
        capture = re.fullmatch(r'(5|8|9|10|12|16)-(1|2|9)-(1|2|3|5|7|8|9|14)-(wg|awg2-fast|awg2-strong)-(connected|closed)-(original|hostname|late-catalog|cancel-close|wrong-late-key|wrong-interior-key|wrong-private-id)', leaf)
        count, packets, position, mode, scope, outcome = capture.groups()
        samples = 50 if outcome in ('original', 'hostname') else 0
        marker = f'MIXED_CANDIDATE_NATIVE nodes={count} packets={packets} position={position} scope={scope} outcome={outcome} samples={samples} joined=true'
        witnesses = [row.get('Output', '').strip() for row in rows if row.get('Test') == root+'/'+leaf and 'MIXED_CANDIDATE_NATIVE' in row.get('Output', '')]
        if len(witnesses) != 1 or not witnesses[0].endswith(marker):
            raise ValueError('Mixed candidate lost its original prefix, measurement or cleanup receipt')
    if root == MIXED_ROOT:
        name = root+'/'+leaf
        match = re.fullmatch(r'(9|16)-(wg|awg2-fast|awg2-strong)-([1-9]+)-(traffic|late-key|hostname(?:-collision|-nxdomain|-rebind|-late-key)?)', leaf)
        count, mode, packets, outcome = match.groups()
        size = 8 << 20 if outcome in ('traffic', 'hostname', 'hostname-rebind') else 0
        marker = f'MIXED_LOCAL_NATIVE nodes={count} packets={packets} mode={mode} outcome={outcome} down={size} up={size} joined=true'
        witnesses = [row.get('Output', '').strip() for row in rows if row.get('Test') == name and 'MIXED_LOCAL_NATIVE' in row.get('Output', '')]
        if len(witnesses) != 1 or not witnesses[0].endswith(marker):
            raise ValueError('Mixed Local native receipt changed the original source, ciphertext outcome, transfer bytes or retirement')
    if root == THROUGHPUT_ROOT:
        count = 9 if leaf == 'extended-nine' else 16
        size = 8 << 20
        name = root+'/'+leaf
        marker = f'QUALIFIED_ORIGINAL_THROUGHPUT nodes={count} bytes_per_direction={size} bytes_total={2*count*size}'
        emitted = [row.get('Output', '').strip() for row in rows if row.get('Test') == name and 'QUALIFIED_ORIGINAL_THROUGHPUT nodes=' in row.get('Output', '')]
        if len(emitted) != 1 or not emitted[0].endswith(marker):
            raise ValueError('Missing complete original encrypted per-member throughput')
    if root == SELECTED_ROOT:
        name = root+'/'+leaf
        markers = [row.get('Output', '').strip() for row in rows if row.get('Test') == name
                   and 'QUALIFIED_SELECTED_NATIVE' in row.get('Output', '')]
        if len(markers) != 1 or not markers[0].endswith(selected_marker(leaf)):
            raise ValueError('Missing original selected native route, frozen winner or encrypted bytes')
        if leaf in AWG_SELECTED_CASES:
            entry = 'awg2-fast' if leaf in FAST_SELECTED_CASES else 'awg2-strong'
            expected_client = f'QUALIFIED_SELECTED_CLIENT_AWG entry={entry} parameters_current=true other_mode_refused=true'
            clients = [row.get('Output', '').strip() for row in rows if row.get('Test') == name
                       and 'QUALIFIED_SELECTED_CLIENT_AWG' in row.get('Output', '')]
            if len(clients) != 1 or not clients[0].endswith(expected_client):
                raise ValueError('Missing live selected AWG client parameter readback or alternate-mode refusal')
        if leaf in AWG_SELECTED_CASES and leaf.endswith('-mtu'):
            count = leaf.split('-')[0]
            entry = 'awg2-fast' if leaf in FAST_SELECTED_CASES else 'awg2-strong'
            mtu_marker = 'STRONG_SELECTED_MTU' if entry == 'awg2-strong' else 'FAST_SELECTED_MTU'
            expected_mtu = f'{mtu_marker} nodes={count} configured=1280 ceiling=1500 lease_paused=true missing_reader_refused=true'
            mtu = [row.get('Output', '').strip() for row in rows if row.get('Test') == name and '_SELECTED_MTU' in row.get('Output', '')]
            if len(mtu) != 1 or not mtu[0].endswith(expected_mtu):
                raise ValueError('Missing original selected Fast MTU pause or native-reader refusal')
    return len(required)


def rejected(output):
    rows, runs, passed, failed, terminal = receipt(output, BOX_PACKAGE)
    return (terminal == 'fail' and not passed
            and runs == expected(CONTROL['root'], CONTROL['leaf']) and failed == runs
            and any(CONTROL['witness'] in row.get('Output', '') for row in rows)
            and not any(any(marker in row.get('Output', '') for marker in (*FATAL, *JOIN_FAILURES)) for row in rows))


def bounded_control(command, core, env):
    # Join the exact process group even if test2json's child misses its Go bound.
    process = subprocess.Popen([str(value) for value in command], cwd=core, env=env,
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        output, error = process.communicate(timeout=135)
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise
    return process.returncode, output, error


def execute(core, target, tags, env, runner, *, strong_diagnostic=False):
    if (target not in ('linux/amd64', 'linux/arm64')
            or (env.get('GOOS'), env.get('GOARCH')) != tuple(target.split('/'))
            or env.get('CGO_ENABLED') != '1' or 'with_wireguard' not in tags.split(',')):
        raise ValueError('Independent imported proof requires its actual Linux native race target')
    core, captured = Path(core).resolve(), dict(env)
    helpers = load('test_desktop_native_root_phases.py')
    owner = load('test_node_chain_openvpn_execution_owner.py')
    peers = load('prepare-desktop-external.py')
    native = load('prepare-mobile-node-chain.py')
    template_bytes = {path: (ROOT/path).read_bytes() for path in (PEER_TEMPLATE, MIXED_TEMPLATE, MIXED_CANDIDATE_TEMPLATE, BOX_TEMPLATE, *SELECTED_TEMPLATES)}
    worker = load('prepare-server-node-chain.py')
    worker_sources = {name: raw for name, raw in worker.copies().items()
                      if name.startswith('cmd/sing-box/routervpn_server_chain_') and not name.endswith('_test.go')}

    def verify():
        owner.verify(core, desktop=True)  # Exact canonical shared, Box and manager source, no OpenVPN authority.
        if any((core/name).is_symlink() or (core/name).read_bytes() != raw for name, raw in worker_sources.items()):
            raise ValueError('Independent imported worker differs from its original prepared source')
        if native.TEMPLATES.get(Path(BOX_TEMPLATE).name) != BOX_TARGET:
            raise ValueError('Independent imported Box test lost canonical mapping')
        for name, relative in peers.PEER_TEMPLATES.items():
            actual = core/relative
            if actual.is_symlink() or not actual.is_file() or actual.read_bytes() != (ROOT/'mobile/desktop'/name).read_bytes():
                raise ValueError('Independent imported proof changed its original provider helpers')
        if (core/BOX_TARGET).read_bytes() != template_bytes[BOX_TEMPLATE]:
            raise ValueError('Independent imported Box proof changed its prepared source')
        if any((ROOT/path).read_bytes() != raw for path, raw in template_bytes.items()):
            raise ValueError('Independent imported test source changed')

    verify()
    source_sha = helpers.source_digest(core)
    with tempfile.TemporaryDirectory(prefix='routervpn-multiple-imported-') as directory:
        workspace = Path(directory)
        projection = workspace/'multiple_imported_component_test.go'
        projection.write_bytes(template_bytes[PEER_TEMPLATE])
        overlay = workspace/'peer.json'
        replacement = {str(core/PEER_TARGET): str(projection)}
        for template in (MIXED_TEMPLATE, MIXED_CANDIDATE_TEMPLATE, *SELECTED_TEMPLATES):
            name = Path(template).name.removesuffix('.tmpl')
            replacement[str(core/'protocol/routervpnamnezia'/name)] = str(ROOT/template)
        # The external Go test package imports the same WG peer package as the
        # shipping worker registry. Retain the complete verified worker bodies
        # and their build tags, changing only their package for this test image.
        worker_tests = {}
        for name, raw in worker_sources.items():
            if raw.count(b'package main\n') != 1:
                raise ValueError('Unexpected original worker package')
            projected = raw.replace(b'package main\n', b'package routervpnamnezia_test\n', 1)
            target = Path(name).stem+'_test.go'
            file = workspace/target
            file.write_bytes(projected)
            worker_tests[file] = projected
            replacement[str(core/'protocol/routervpnamnezia'/target)] = str(file)
        overlay.write_text(json.dumps({'Replace': replacement}))
        original_overlay = overlay.read_bytes()
        base = ['go', 'test', '-c', '-race', '-p=1', '-mod=readonly', '-tags='+tags, '-ldflags=-checklinkname=0']
        images = {'peer': workspace/'peer.test', 'box': workspace/'box.test', 'continuous': workspace/'continuous.test'}
        identities = {}
        peer_receipts, box_receipts = {}, {}

        def unchanged():
            if (captured != env or helpers.source_digest(core) != source_sha
                    or projection.read_bytes() != template_bytes[PEER_TEMPLATE]
                    or overlay.read_bytes() != original_overlay
                    or any(path.read_bytes() != raw for path, raw in worker_tests.items())
                    or any(helpers.image_identity(images[name]) != identity for name, identity in identities.items())):
                raise ValueError('Independent imported proof changed captured source, image or environment')
            verify()

        def run_case(image, package, root, leaf, seconds, parent):
            unchanged()
            output = runner(['go', 'tool', 'test2json', '-p', package, '-t', image, '-test.v',
                             '-test.count=1', '-test.timeout='+str(seconds)+'s',
                             '-test.run='+selector(root, leaf)], cwd=core, env=captured, timeout=parent)
            count = verdict(output, root, leaf)
            unchanged()
            return count

        runner([*base, '-overlay='+str(overlay), '-o', images['peer'], './protocol/routervpnamnezia'],
               cwd=core, env=captured, timeout=300)
        identities['peer'] = helpers.image_identity(images['peer'])
        unchanged()
        listed = runner([images['peer'], '-test.list=^('+'|'.join(PEER_CASES)+')$'],
                        cwd=core, env=captured, timeout=60).strip().splitlines()
        if sorted(listed) != sorted(PEER_CASES):
            raise ValueError('Independent imported encrypted root discovery changed')
        if strong_diagnostic:
            if target != 'linux/amd64':
                raise ValueError('The topic-branch diagnostic requires its actual amd64 host')
            for leaf in STRONG_SELECTED_CASES:
                peer_receipts[leaf] = run_case(images['peer'], PEER_PACKAGE, SELECTED_ROOT, leaf, 90, 105)
                print('Completed original Strong worker case '+leaf, flush=True)
            unchanged()
            return dict(kind='diagnostic-original-strong-selected-v1', target=target, race=True,
                        source_sha256=source_sha, image_sha256=identities['peer'][1],
                        templates={path: hashlib.sha256(raw).hexdigest() for path, raw in template_bytes.items()},
                        worker_sources={name: hashlib.sha256(raw).hexdigest() for name, raw in worker_sources.items()},
                        encrypted=peer_receipts)
        # A user request measures one selected position. The race image measures
        # all 16 positions in four bounded invocations. The ordinary image also
        # retains all 800 original responses from one continuous generation.
        nonrace = [arg for arg in base if arg != '-race']
        runner([*nonrace, '-overlay='+str(overlay), '-o', images['continuous'], './protocol/routervpnamnezia'],
               cwd=core, env=captured, timeout=300)
        identities['continuous'] = helpers.image_identity(images['continuous'])
        if identities['continuous'][1] == identities['peer'][1]:
            raise ValueError('Continuous and race native images must differ')
        for root, cases in PEER_CASES.items():
            for leaf in cases:
                image = images['continuous'] if root == SELECTED_ROOT and leaf == CONTINUOUS else images['peer']
                peer_receipts[root+'/'+leaf] = run_case(image, PEER_PACKAGE, root, leaf, 90, 105)

        runner([*base, '-o', images['box'], '.'], cwd=core, env=captured, timeout=600)
        identities['box'] = helpers.image_identity(images['box'])
        unchanged()
        listed = runner([images['box'], '-test.list=^('+BOX_POSITIVE+'|'+BOX_NEGATIVE+')$'],
                        cwd=core, env=captured, timeout=60).strip().splitlines()
        if sorted(listed) != sorted(BOX_CASES):
            raise ValueError('Independent imported Box root discovery changed')
        for root in BOX_CASES:
            box_receipts[root] = run_case(images['box'], BOX_PACKAGE, root, None, 120, 135)

        raw = (core/CONTROL['target']).read_text()
        if raw.count(CONTROL['before']) != 1:
            raise ValueError('Original independent source-pointer control changed')
        mutant = workspace/'missing_original_source.go'
        mutant.write_text(raw.replace(CONTROL['before'], CONTROL['after'], 1))
        control_overlay = workspace/'control.json'
        control_overlay.write_text(json.dumps({'Replace': {str(core/CONTROL['target']): str(mutant)}}))
        control_image = workspace/'control.test'
        runner([*base, '-overlay='+str(control_overlay), '-o', control_image, '.'], cwd=core, env=captured, timeout=600)
        control_identity = helpers.image_identity(control_image)
        code, output, error = bounded_control(['go', 'tool', 'test2json', '-p', BOX_PACKAGE, '-t', control_image,
                                              '-test.v', '-test.count=1', '-test.timeout=120s',
                                              '-test.run='+selector(CONTROL['root'], CONTROL['leaf'])], core, captured)
        if code != 1 or error or not rejected(output) or helpers.image_identity(control_image) != control_identity:
            raise ValueError('Original independent source control lacked its exact failed witness\n'+output+error)
        print(output, end='', flush=True)
        unchanged()
        if set(peer_receipts) != {root+'/'+leaf for root, cases in PEER_CASES.items() for leaf in cases} or sum(box_receipts.values()) != 17:
            raise ValueError('Independent imported final inventory incomplete')
        result = dict(kind='native-multiple-imported-local-v1', target=target, source_sha256=source_sha,
                      templates={path: hashlib.sha256(raw).hexdigest() for path, raw in template_bytes.items()},
                      images={name: identity[1] for name, identity in identities.items()},
                      control_image_sha256=control_identity[1], race=True, encrypted=peer_receipts, continuous_nonrace=SELECTED_ROOT+'/'+CONTINUOUS,
                      selected_race_positions=list(PARTS),
                      box=box_receipts, controls=['equal-source'], installed_host_acceptance=False)
        print('Original multiple imported native proof: '+json.dumps(result, sort_keys=True), flush=True)
        return result
