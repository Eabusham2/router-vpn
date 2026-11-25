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
EXTERNAL_FINAL_TEMPLATE = 'mobile/chain_component/external_final_test.go.tmpl'
EXTERNAL_FINAL_ROOT = 'TestRouterVPNOrderedExternalFinalEncrypted'
EXTERNAL_FINAL_CASES = {
    'three-home': (3, 'home'), 'four-custom': (4, 'custom'),
    'nine-custom-fifty': (9, 'custom'), 'wrong-exit-key': (4, 'custom'),
    'wrong-public-exit': (3, 'home'), 'failed-selected-dns': (4, 'custom'),
    'fast-home': (3, 'home'), 'strong-custom-fifty': (9, 'custom'),
    'fast-wrong-entry': (3, 'home'), 'strong-wrong-entry': (3, 'custom'),
    'wg-aes-home': (3,'home'), 'wg-xor-custom': (4,'custom'),
    'fast-aes-custom': (4,'custom'), 'fast-xor-home': (3,'home'),
    'strong-aes-home': (3,'home'), 'strong-xor-custom-fifty': (9,'custom'),
    'wg-wrong-layer-key': (3,'home'), 'strong-wrong-whitening': (3,'custom'), 'fast-wrong-layer-target': (3,'home'),
}

PUBLIC_CANDIDATE_TEMPLATE = 'mobile/chain_component/external_final_candidates_test.go.tmpl'
PUBLIC_CANDIDATE_ROOT = 'TestRouterVPNExternalFinalPublicCandidates'
# Original source size, selected prefix position, completed fifty-response rounds.
PUBLIC_CANDIDATE_CASES = {
    'home-retained-suffix': (4, 1, 2), 'custom-retained-final': (3, 1, 2),
    'nine-late-import': (9, 7, 2), 'wrong-key': (4, 1, 0), 'wrong-exit': (4, 2, 0),
    'late-catalog': (4, 1, 0), 'cancel-close': (4, 2, 0),
    'fast-closed': (4, 1, 2), 'strong-connected': (3, 1, 2),
    'fast-xor-closed': (4,1,2), 'strong-aes-connected': (3,1,2),
}

EXTERNAL_ENTRY_LAYERS = {
    'wg-aes-home': ('wg','aes-256-gcm','original'), 'wg-xor-custom': ('wg','aes-256-gcm+xor-whitening','original'),
    'fast-aes-custom': ('awg2-fast','aes-256-gcm','original'), 'fast-xor-home': ('awg2-fast','aes-256-gcm+xor-whitening','original'),
    'strong-aes-home': ('awg2-strong','aes-256-gcm','original'), 'strong-xor-custom-fifty': ('awg2-strong','aes-256-gcm+xor-whitening','original'),
    'wg-wrong-layer-key': ('wg','aes-256-gcm','entry-layer-key'), 'strong-wrong-whitening': ('awg2-strong','aes-256-gcm+xor-whitening','entry-layer-whitening'),
    'fast-wrong-layer-target': ('awg2-fast','aes-256-gcm','entry-layer-target'),
    'fast-xor-closed': ('awg2-fast','aes-256-gcm+xor-whitening','original'), 'strong-aes-connected': ('awg2-strong','aes-256-gcm','original'),
}

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
LATER_HOSTNAME_ROOT = 'TestRouterVPNLaterHostnameLocal'
LATER_HOSTNAME_CASES = tuple(f'{count}-{mode}-{outcome}' for count in (4, 9)
                            for mode in ('wg', 'awg2-fast', 'awg2-strong')
                            for outcome in (('traffic', 'wrong-predecessor', 'wrong-dns-route', 'nxdomain',
                                             'suffix-collision', 'rebind', 'late-key') if mode == 'awg2-fast' else ('traffic',)))
LATER_HOSTNAME_CASES += ('9-wg-p7-rebind', '9-awg2-fast-p7-wrong-predecessor', '96-awg2-fast-p2-traffic', '96-awg2-strong-p94-traffic')
LATER_HOSTNAME_CANDIDATES = ('4-1-2-wg-closed-later-hostname', '4-1-2-awg2-fast-connected-later-hostname',
                             '9-1-2-awg2-strong-closed-later-hostname', '9-1-7-awg2-fast-connected-later-hostname',
                             '4-1-2-awg2-fast-closed-later-hostname-cancel-close', '9-1-7-awg2-fast-connected-later-hostname-late-catalog',
                             '96-1-2-wg-closed-later-hostname', '96-1-94-awg2-strong-closed-later-hostname-last')
MIXED_CANDIDATES += LATER_HOSTNAME_CANDIDATES
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

PRIVATE_STREAM_CASES = {
    '4-private-server-response': ('server', 'server', 'response'), '4-private-auto-local': ('auto', 'local', 'response'),
    '4-private-auto-server': ('auto', 'server', 'response'), '4-private-server-latency': ('server', 'server', 'latency'),
    '4-private-server-throughput': ('server', 'server', 'throughput'), '4-private-drain': ('server', 'server', 'drain'),
    **{'4-private-wrong-'+field: ('server', 'server', 'wrong-'+field) for field in ('key', 'identity', 'dns', 'public', 'exit')},
}

PRIVATE_DEPTH_CASES = {
    '5-private-2-server-server-response': (5, 2, 'server', 'server', 'response', 0, 0),
    '5-private-3-auto-local-response': (5, 3, 'auto', 'local', 'response', 0, 0),
    '5-private-2-auto-server-response': (5, 2, 'auto', 'server', 'response', 0, 0),
    '5-private-3-server-server-throughput': (5, 3, 'server', 'server', 'throughput', 0, 0),
    '5-private-2-server-server-drain': (5, 2, 'server', 'server', 'drain', 0, 0),
    '5-private-3-server-server-latency-1-5': (5, 3, 'server', 'server', 'latency', 1, 5),
    '9-private-4-server-server-response': (9, 4, 'server', 'server', 'response', 0, 0),
    '9-private-7-auto-local-response': (9, 7, 'auto', 'local', 'response', 0, 0),
    '9-private-4-auto-server-response': (9, 4, 'auto', 'server', 'response', 0, 0),
    '9-private-7-server-server-throughput': (9, 7, 'server', 'server', 'throughput', 0, 0),
    '9-private-4-server-server-drain': (9, 4, 'server', 'server', 'drain', 0, 0),
    '9-private-7-server-server-latency-1-9': (9, 7, 'server', 'server', 'latency', 1, 9),
    '16-private-2-server-server-response': (16, 2, 'server', 'server', 'response', 0, 0),
    '16-private-14-auto-local-response': (16, 14, 'auto', 'local', 'response', 0, 0),
    '16-private-2-auto-server-response': (16, 2, 'auto', 'server', 'response', 0, 0),
    '16-private-14-server-server-throughput': (16, 14, 'server', 'server', 'throughput', 0, 0),
    '16-private-2-server-server-drain': (16, 2, 'server', 'server', 'drain', 0, 0),
    '16-private-14-server-server-latency-1-4': (16, 14, 'server', 'server', 'latency', 1, 4),
    '16-private-14-server-server-latency-5-8': (16, 14, 'server', 'server', 'latency', 5, 8),
    '16-private-14-server-server-latency-9-12': (16, 14, 'server', 'server', 'latency', 9, 12),
    '16-private-14-server-server-latency-13-16': (16, 14, 'server', 'server', 'latency', 13, 16),
    '5-private-3-server-server-wrong-key': (5, 3, 'server', 'server', 'wrong-key', 0, 0),
    '9-private-4-server-server-wrong-public': (9, 4, 'server', 'server', 'wrong-public', 0, 0),
    '9-private-7-server-server-wrong-dns': (9, 7, 'server', 'server', 'wrong-dns', 0, 0),
    '16-private-14-server-server-wrong-identity': (16, 14, 'server', 'server', 'wrong-identity', 0, 0),
    '16-private-2-server-server-wrong-exit': (16, 2, 'server', 'server', 'wrong-exit', 0, 0),
}

def private_case(leaf):
    if leaf in PRIVATE_DEPTH_CASES:
        return PRIVATE_DEPTH_CASES[leaf]
    mode, winner, action = PRIVATE_STREAM_CASES[leaf]
    first, last = (1, 4) if action == 'latency' else (0, 0)
    return 4, 2, mode, winner, action, first, last


PRIVATE_RESPONSE_FAULTS = ('original', 'wrong-candidate-key', 'forged-response', 'wrong-private-id',
                           'late-catalog', 'late-cancel', 'server-winner')
PRIVATE_RESPONSE_LAYOUTS = (
    ('3-local-private', 3, 0, PRIVATE_RESPONSE_FAULTS), ('4-local-private', 4, 2, PRIVATE_RESPONSE_FAULTS),
    ('9-local-private', 9, 7, ('original',)), ('16-local-private', 16, 14, ('original',)),
    ('4-imported-penultimate', 4, 0, PRIVATE_RESPONSE_FAULTS), ('9-imported-penultimate', 9, 0, ('original',)),
    ('16-imported-penultimate', 16, 0, ('original',)), ('5-paired-2-imported-penultimate', 5, 2, ('original',)),
    ('9-paired-4-imported-penultimate', 9, 4, ('original',)), ('16-paired-7-imported-penultimate', 16, 7, ('original',)),
)
PRIVATE_RESPONSE_SOURCES = {f'{name}-{fault}': (count, paired, fault) for name, count, paired, faults in PRIVATE_RESPONSE_LAYOUTS for fault in faults}
INTERMEDIATE_POSITIONS = {}
for count, position in ((3, 1), (4, 1), (9, 6), (16, 8), (16, 13)):
    faults = PRIVATE_RESPONSE_FAULTS + ('suffix-alias', 'changed-original-suffix') if count == 4 else ('original',)
    for fault in faults:
        leaf = f'{count}-imported-stop-{position}-{fault}'
        INTERMEDIATE_POSITIONS[leaf] = position
        PRIVATE_RESPONSE_SOURCES[leaf] = (count, 0, fault)
RECURSIVE_PRIVATE_POSITIONS = {}
for count, paired, stop in ((5, (2,), 1), (5, (2,), 2), (7, (2, 4), 3), (9, (2, 4), 4)):
    for fault in (('original', 'wrong-candidate-key', 'late-cancel', 'server-winner') if count == 7 else ('original',)):
        leaf = f'{count}-recursive-stop-{stop}-{fault}'
        INTERMEDIATE_POSITIONS[leaf] = stop
        RECURSIVE_PRIVATE_POSITIONS[leaf] = paired
        PRIVATE_RESPONSE_SOURCES[leaf] = (count, paired[0], fault)
AWG_RESPONSE_ENTRIES = {}
for entry in ('awg2-fast', 'awg2-strong'):
    for count, stop, paired in ((3, 1, ()), (5, 2, (2,)), (7, 4, (2, 4)), (8, 4, (2, 4)), (9, 3, (2, 4)), (16, 8, (2, 4))):
        faults = PRIVATE_RESPONSE_FAULTS + ('suffix-alias', 'changed-original-suffix') if count == 7 else ('original',)
        for fault in faults:
            leaf = f'{count}-{entry}-recursive-stop-{stop}-{fault}'
            AWG_RESPONSE_ENTRIES[leaf] = entry
            INTERMEDIATE_POSITIONS[leaf] = stop
            RECURSIVE_PRIVATE_POSITIONS[leaf] = paired
            PRIVATE_RESPONSE_SOURCES[leaf] = (count, paired[0] if paired else 0, fault)
PRIVATE_RESPONSE_CASES = tuple(PRIVATE_RESPONSE_SOURCES)


def response_position(leaf):
    return INTERMEDIATE_POSITIONS.get(leaf, PRIVATE_RESPONSE_SOURCES[leaf][0] - 2)


def reloaded_response_marker(leaf):
    if leaf not in INTERMEDIATE_POSITIONS:
        return RELOADED_PRIVATE_FINAL
    count = PRIVATE_RESPONSE_SOURCES[leaf][0]
    position = INTERMEDIATE_POSITIONS[leaf]
    if count == 3:
        return ('RELOADED_PRIVATE_DRAFT nodes=4 schema=6 inserted=2 suffix=1 saved=false '
                'requested=auto winner=local original_final=true private=true dns=true application=true joined=true')
    return (f'RELOADED_PRIVATE_INTERMEDIATE nodes={count+1} inserted={position+1} suffix={count-position-1} '
            'requested=auto winner=local original_final=true private=true dns=true application=true joined=true')


def suffix_refusal_marker(leaf):
    count, _, fault = PRIVATE_RESPONSE_SOURCES[leaf]
    position = response_position(leaf)
    if fault == 'suffix-alias':
        return f'PRIVATE_RESPONSE_SUFFIX_ALIAS position={position} alias={position+1} distinct_private=true refused=true'
    if fault == 'changed-original-suffix':
        return f'PRIVATE_RESPONSE_CHANGED_SUFFIX position={position} final={count-1} accepted=50 ready=false joined=true'
    return None


def private_response_source_marker(leaf):
    count, paired, _ = PRIVATE_RESPONSE_SOURCES[leaf]
    positions = RECURSIVE_PRIVATE_POSITIONS.get(leaf, (paired,) if paired else ())
    role = 'paired' if response_position(leaf) in positions else 'imported'
    private = ','.join(map(str, positions)) or 'none'
    return f"PRIVATE_RESPONSE_SOURCE nodes={count} schema={2 if count == 3 else 6} position={response_position(leaf)} role={role} paired={private}"


SELECTED_CASES += PRIVATE_RESPONSE_CASES
RELOADED_PRIVATE_FINAL = 'RELOADED_PRIVATE_FINAL requested=auto winner=local original_prefix=true private=true dns=true application=true joined=true'

SELECTED_TEMPLATES = (
    'mobile/server_chain_component/private_stream_process_test.go.tmpl',
    'mobile/chain_component/extended_execution_client_test.go.tmpl',
    'mobile/chain_component/extended_execution_peer_test.go.tmpl',
    'mobile/server_chain_component/extended_execution_test.go.tmpl',
)


def selected_marker(leaf):
    if leaf in PRIVATE_RESPONSE_CASES:
        winner = 'server' if leaf.endswith('server-winner') else 'local'
        count = leaf.split('-', 1)[0]
        marker = f'QUALIFIED_SELECTED_NATIVE nodes={count} execution=auto winner={winner} samples=0 bytes=0 first={INTERMEDIATE_POSITIONS.get(leaf, 0)} last=0 response_samples=0'
        if leaf in AWG_RESPONSE_ENTRIES:
            marker += f' entry_mode={AWG_RESPONSE_ENTRIES[leaf]} parameters_current=true'
        return marker
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


PEER_CASES = {LATER_HOSTNAME_ROOT: LATER_HOSTNAME_CASES, PAIRED_INTERIOR_ROOT: PAIRED_INTERIOR, MIXED_CANDIDATE_ROOT: MIXED_CANDIDATES, MIXED_ROOT: MIXED, SELECTED_ROOT: SELECTED_CASES, POSITIVE_ROOT: POSITIVE, NEGATIVE_ROOT: NEGATIVE, THROUGHPUT_ROOT: THROUGHPUT}


PEER_CASES[EXTERNAL_FINAL_ROOT] = tuple(EXTERNAL_FINAL_CASES)
PEER_CASES[PUBLIC_CANDIDATE_ROOT] = tuple(PUBLIC_CANDIDATE_CASES)


def inventory():
    return {**PEER_CASES, **BOX_CASES}


def expected(root, leaf=None):
    cases = inventory().get(root)
    if root == SELECTED_ROOT and (leaf in PRIVATE_STREAM_CASES or leaf in PRIVATE_DEPTH_CASES):
        cases = (*PRIVATE_STREAM_CASES, *PRIVATE_DEPTH_CASES)
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


def verdict(output, root, leaf=None, *, worker_digest=None):
    package = PEER_PACKAGE if root in PEER_CASES else BOX_PACKAGE
    rows, runs, passed, failed, terminal = receipt(output, package)
    required = expected(root, leaf)
    if terminal != 'pass' or failed or runs != required or passed != required:
        raise ValueError('Independent imported native inventory omitted, duplicated or failed a required case')
    if any(any(marker in row.get('Output', '') for marker in (*FATAL, *JOIN_FAILURES)) for row in rows):
        raise ValueError('Independent imported native receipt contains a fatal or unjoined result')
    if root in (EXTERNAL_FINAL_ROOT, PUBLIC_CANDIDATE_ROOT) and leaf in EXTERNAL_ENTRY_LAYERS:
        mode, layer, fault = EXTERNAL_ENTRY_LAYERS[leaf]
        marker = f'EXTERNAL_PACKET_LAYER mode={mode} layer={layer} fault={fault} udp_on_original=true complete={str(fault == "original").lower()}'
        witnesses = [row.get('Output', '').strip() for row in rows if row.get('Test') == root+'/'+leaf and 'EXTERNAL_PACKET_LAYER' in row.get('Output', '')]
        if len(witnesses) != 1 or not witnesses[0].endswith(marker):
            raise ValueError('Missing original packet entry layer physical UDP, exact credentials, or failure boundary')
    if root in (EXTERNAL_FINAL_ROOT, PUBLIC_CANDIDATE_ROOT) and leaf.startswith(('fast-', 'strong-')):
        mode = 'awg2-fast' if leaf.startswith('fast-') else 'awg2-strong'
        mismatch = 'true' if leaf.endswith('wrong-entry') else 'false'
        marker = f'AWG_EXTERNAL_ENTRY case={leaf} mode={mode} mismatch={mismatch} readback=true'
        emitted = [row.get('Output', '').strip() for row in rows if row.get('Test') == root+'/'+leaf and 'AWG_EXTERNAL_ENTRY' in row.get('Output', '')]
        client_marker = f'QUALIFIED_SELECTED_CLIENT_AWG entry={mode} parameters_current=true other_mode_refused=true'
        clients = [row.get('Output', '').strip() for row in rows
                   if row.get('Test') == root+'/'+leaf and 'QUALIFIED_SELECTED_CLIENT_AWG' in row.get('Output', '')]
        if len(clients) != (2 if root == PUBLIC_CANDIDATE_ROOT else 1) or not all(line.endswith(client_marker) for line in clients):
            raise ValueError('Missing original live client AmneziaWG parameter readback')
        if len(emitted) != 1 or not emitted[0].endswith(marker):
            raise ValueError('Missing original AmneziaWG device parameter readback')
        if root == EXTERNAL_FINAL_ROOT and leaf in ('fast-home', 'strong-custom-fifty'):
            refusal = f'SELECTED_PRIVATE_AWG_REFUSALS entry={mode} original_peer=true wrong_key=true wrong_header=true joined=true'
            observed = [row.get('Output', '').strip() for row in rows
                        if row.get('Test') == root+'/'+leaf and 'SELECTED_PRIVATE_AWG_REFUSALS' in row.get('Output', '')]
            if len(observed) != 1 or not observed[0].endswith(refusal):
                raise ValueError('Missing same-peer AWG credential refusals after the original client joined')
    if root == PUBLIC_CANDIDATE_ROOT:
        count, position, rounds = PUBLIC_CANDIDATE_CASES[leaf]
        marker = f'PUBLIC_CANDIDATE case={leaf} nodes={count} position={position} rounds={rounds} samples={50*rounds} retained=true joined=true'
        emitted = [row.get('Output', '').strip() for row in rows if row.get('Test') == root+'/'+leaf and 'PUBLIC_CANDIDATE' in row.get('Output', '')]
        if len(emitted) != 1 or not emitted[0].endswith(marker):
            raise ValueError('Missing enrolled encrypted public candidate or complete original retirement')
    if root == EXTERNAL_FINAL_ROOT:
        count, dns = EXTERNAL_FINAL_CASES[leaf]
        marker = f"QUALIFIED_EXTERNAL_FINAL case={leaf} nodes={count} dns={dns} owner_joined=true private_exit_calls=0"
        lines = [row.get('Output', '').strip().split('QUALIFIED_', 1)[-1] for row in rows if row.get('Test') == root+'/'+leaf and 'QUALIFIED_' in row.get('Output', '')]
        if lines.count(marker.removeprefix('QUALIFIED_')) != 1 or sum(line.startswith('EXTERNAL_FINAL') for line in lines) != 1:
            raise ValueError('Missing original encrypted external-final receipt')
        if leaf in ('nine-custom-fifty', 'strong-custom-fifty', 'strong-xor-custom-fifty') and lines.count('LATENCY_HISTORY nodes=9 receipts=9 samples=450') != 1:
            raise ValueError('Missing per-position external-final response history')
    if root == POSITIVE_ROOT and leaf in ('wg/extended-nine/off', 'wg/extended-sixteen/off'):
        count = 9 if leaf == 'wg/extended-nine/off' else 16
        name = root+'/'+leaf.replace('/', '_')
        marker = f'QUALIFIED_LATENCY_HISTORY nodes={count} receipts={count} samples={count*50}'
        emitted = [row.get('Output', '').strip() for row in rows if row.get('Test') == name and 'QUALIFIED_LATENCY_HISTORY' in row.get('Output', '')]
        if len(emitted) != 1 or not emitted[0].endswith(marker):
            raise ValueError('Missing complete original per-member encrypted latency history')
    if root == MIXED_CANDIDATE_ROOT:
        capture = re.fullmatch(r'(4|5|8|9|10|12|16|96)-(1|2|9)-(1|2|3|5|7|8|9|14|94)-(wg|awg2-fast|awg2-strong)-(connected|closed)-(original|hostname|later-hostname(?:-cancel-close|-late-catalog|-last)?|late-catalog|cancel-close|wrong-late-key|wrong-interior-key|wrong-private-id)', leaf)
        count, packets, position, mode, scope, outcome = capture.groups()
        samples = 50 if outcome in ('original', 'hostname', 'later-hostname', 'later-hostname-last') else 0
        marker = f'MIXED_CANDIDATE_NATIVE nodes={count} packets={packets} position={position} scope={scope} outcome={outcome} samples={samples} joined=true'
        witnesses = [row.get('Output', '').strip() for row in rows if row.get('Test') == root+'/'+leaf and 'MIXED_CANDIDATE_NATIVE' in row.get('Output', '')]
        if len(witnesses) != 1 or not witnesses[0].endswith(marker):
            raise ValueError('Mixed candidate lost its original prefix, measurement or cleanup receipt')
    if root == LATER_HOSTNAME_ROOT:
        count, mode, position, outcome = re.fullmatch(r'(4|9|96)-(wg|awg2-fast|awg2-strong)-(?:p(2|7|94)-)?(.+)', leaf).groups()
        position = position or '2'
        queried = 'false' if outcome in ('wrong-predecessor', 'wrong-dns-route') else 'true'
        size = 8 << 20 if outcome in ('traffic', 'rebind') else 0
        marker = f'LATER_HOSTNAME_NATIVE nodes={count} mode={mode} outcome={outcome} position={position} resolver_reached={queried} down={size} up={size} joined=true'
        witnessed = [row.get('Output', '').strip() for row in rows if row.get('Test') == root+'/'+leaf and 'LATER_HOSTNAME_NATIVE' in row.get('Output', '')]
        if len(witnessed) != 1 or not witnessed[0].endswith(marker):
            raise ValueError('Later hostname lost the actual saved resolver, original transfer or teardown receipt')
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
    if root == SELECTED_ROOT and (leaf in PRIVATE_STREAM_CASES or leaf in PRIVATE_DEPTH_CASES):
        lines = [row.get('Output', '').strip() for row in rows if row.get('Test') == root+'/'+leaf]
        def unique(marker):
            matches = [line.split(marker, 1)[1] for line in lines if marker in line]
            if len(matches) != 1:
                raise ValueError('Missing or duplicate private stream witness '+marker)
            return matches[0]
        count, position, mode, winner, action, first, last = private_case(leaf)
        wanted = 2 if (mode, winner) == ('auto', 'server') else 1
        def workers(marker):
            found = [line.split(marker, 1)[1] for line in lines if marker in line]
            parsed = [re.fullmatch(r'pid=([1-9][0-9]*) source=([0-9a-f]{64}) capture=([0-9a-f]{64}) image=([0-9a-f]{64})', ident) for ident in found]
            if len(parsed) != wanted or not all(parsed):
                raise ValueError('Separate native process inventory changed')
            pids, sources, captures, images = map(set, zip(*(v.groups() for v in parsed)))
            if len(pids) != wanted or len(captures) != wanted or len(sources) != 1 or images != {worker_digest}:
                raise ValueError('Separate native process reused a trial or changed image')
            return found
        started, joined = workers('SEPARATE_NATIVE_CHILD '), workers('SEPARATE_NATIVE_JOINED ')
        retained = [line[line.index('SEPARATE_NATIVE_'):] for line in lines if 'SEPARATE_NATIVE_CHILD ' in line or 'SEPARATE_NATIVE_JOINED ' in line]
        required_order = [witness for ident in started for witness in ('SEPARATE_NATIVE_CHILD '+ident, 'SEPARATE_NATIVE_JOINED '+ident)]
        if started != joined or retained != required_order:
            raise ValueError('Separate native process source, image or joined OS identity changed')
        rejected = action.startswith('wrong-')
        samples = {'response': 6, 'latency': (last-first+1)*50}.get(action, 0)
        transferred = count * (16 << 20) if action == 'throughput' else 0
        result = f'nodes={count} private={position} mode={mode} winner={winner} operation={action} rejected={str(rejected).lower()} samples={samples} bytes={transferred} first={first} last={last}'
        if unique('SELECTED_PRIVATE_STREAM_NATIVE ') != result:
            raise ValueError('Selected private stream proof, outcome, samples or transferred bytes changed')
        if not rejected and unique('PRIVATE_STREAM_OWNER ') != 'foreign_peer_session_epoch_refused=true':
            raise ValueError('Selected private stream lost its live ownership controls')
        if action == 'drain' and unique('PRIVATE_STREAM_DRAIN ') != 'cancelled_delete_retained=true replacement_refused=true original_joined=true':
            raise ValueError('Selected private stream lost its held child teardown control')
    elif root == SELECTED_ROOT:
        name = root+'/'+leaf
        markers = [row.get('Output', '').strip() for row in rows if row.get('Test') == name
                   and 'QUALIFIED_SELECTED_NATIVE' in row.get('Output', '')]
        if len(markers) != 1 or not markers[0].endswith(selected_marker(leaf)):
            raise ValueError('Missing original selected native route, frozen winner or encrypted bytes')
        if leaf in PRIVATE_RESPONSE_CASES:
            count, _, fault = PRIVATE_RESPONSE_SOURCES[leaf]
            source = private_response_source_marker(leaf)
            sources = [row.get('Output', '').strip() for row in rows if row.get('Test') == name and 'PRIVATE_RESPONSE_SOURCE' in row.get('Output', '')]
            if len(sources) != 1 or not sources[0].endswith(source):
                raise ValueError('Missing original selected response source roles')
            samples = 50 if fault == 'original' else 0
            witness = f'SELECTED_PRIVATE_RESPONSE fault={fault} samples={samples} joined=true'
            matches = [row.get('Output', '').strip() for row in rows if row.get('Test') == name
                       and 'SELECTED_PRIVATE_RESPONSE' in row.get('Output', '')]
            if len(matches) != 1 or not matches[0].endswith(witness):
                raise ValueError('Missing original private candidate, exact challenge count, or joined refusal')
            prefix_receipts = [row.get('Output', '').strip() for row in rows if row.get('Test') == name
                               and 'PRIVATE_RESPONSE_PREFIX' in row.get('Output', '')]
            position = response_position(leaf)
            prefix = f'PRIVATE_RESPONSE_PREFIX nodes={count} position={position} prefixes={position+1} authenticated=50'
            if (samples and (len(prefix_receipts) != 1 or not prefix_receipts[0].endswith(prefix))) or (not samples and prefix_receipts):
                raise ValueError('Missing original packet and SS2022 prefix response witnesses')
            reloaded = [row.get('Output', '').strip() for row in rows if row.get('Test') == name and 'RELOADED_PRIVATE_' in row.get('Output','')]
            if (fault == 'original' and (len(reloaded) != 1 or not reloaded[0].endswith(reloaded_response_marker(leaf)))) or (fault != 'original' and reloaded):
                raise ValueError('Missing loaded Compare private final, original prefix, DNS, application traffic or joined close')
            refusal = suffix_refusal_marker(leaf)
            suffix_witnesses = [row.get('Output', '').strip() for row in rows if row.get('Test') == name and
                                any(marker in row.get('Output', '') for marker in ('PRIVATE_RESPONSE_SUFFIX_ALIAS', 'PRIVATE_RESPONSE_CHANGED_SUFFIX'))]
            if (refusal and (len(suffix_witnesses) != 1 or not suffix_witnesses[0].endswith(refusal))) or (not refusal and suffix_witnesses):
                raise ValueError('Missing the untouched original suffix refusal')

        if leaf in AWG_SELECTED_CASES or leaf in AWG_RESPONSE_ENTRIES:
            entry = AWG_RESPONSE_ENTRIES.get(leaf) or ('awg2-fast' if leaf in FAST_SELECTED_CASES else 'awg2-strong')
            expected_client = f'QUALIFIED_SELECTED_CLIENT_AWG entry={entry} parameters_current=true other_mode_refused=true'
            clients = [row.get('Output', '').strip() for row in rows if row.get('Test') == name
                       and 'QUALIFIED_SELECTED_CLIENT_AWG' in row.get('Output', '')]
            expected_count = 2 if leaf in AWG_RESPONSE_ENTRIES and PRIVATE_RESPONSE_SOURCES[leaf][2] == 'original' else 1
            if len(clients) != expected_count or not all(line.endswith(expected_client) for line in clients):
                raise ValueError('Missing live selected AWG client parameter readback or alternate-mode refusal')
        if leaf in AWG_RESPONSE_ENTRIES and PRIVATE_RESPONSE_SOURCES[leaf] == (5, 2, 'original'):
            expected_refusal = f'SELECTED_PRIVATE_AWG_REFUSALS entry={AWG_RESPONSE_ENTRIES[leaf]} original_peer=true wrong_key=true wrong_header=true joined=true'
            refusals = [r.get('Output', '').strip() for r in rows if r.get('Test') == name and 'SELECTED_PRIVATE_AWG_REFUSALS' in r.get('Output', '')]
            if len(refusals) != 1 or not refusals[0].endswith(expected_refusal):
                raise ValueError('Missing encrypted AWG original peer key and handshake header refusal')
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


def execute(core, target, tags, env, runner, *, strong_diagnostic=False, private_stream_diagnostic=False, private_depth_diagnostic=False, later_hostname_diagnostic=False, private_response_diagnostic=False):
    private_cases = (*PRIVATE_STREAM_CASES, *PRIVATE_DEPTH_CASES) if private_depth_diagnostic else PRIVATE_STREAM_CASES
    if sum((strong_diagnostic, private_stream_diagnostic, private_depth_diagnostic, later_hostname_diagnostic, private_response_diagnostic)) > 1:
        raise ValueError("A native proof requires one diagnostic family")
    if (target not in ('linux/amd64', 'linux/arm64')
            or (env.get('GOOS'), env.get('GOARCH')) != tuple(target.split('/'))
            or env.get('CGO_ENABLED') != '1' or 'with_wireguard' not in tags.split(',')):
        raise ValueError('Independent imported proof requires its actual Linux native race target')
    if (strong_diagnostic or later_hostname_diagnostic) and target != 'linux/amd64':
        raise ValueError('The topic-branch diagnostic requires its actual amd64 host')
    if (private_stream_diagnostic or private_depth_diagnostic) and target != 'linux/amd64':
        raise ValueError('The separate private-stream diagnostic requires its actual amd64 host')
    if private_response_diagnostic and target != 'linux/amd64':
        raise ValueError('Private response diagnostic requires the native amd64 host')
    core, captured = Path(core).resolve(), dict(env)
    helpers = load('test_desktop_native_root_phases.py')
    owner = load('test_node_chain_openvpn_execution_owner.py')
    peers = load('prepare-desktop-external.py')
    native = load('prepare-mobile-node-chain.py')
    template_bytes = {path: (ROOT/path).read_bytes() for path in (PEER_TEMPLATE, MIXED_TEMPLATE, MIXED_CANDIDATE_TEMPLATE, EXTERNAL_FINAL_TEMPLATE, PUBLIC_CANDIDATE_TEMPLATE, BOX_TEMPLATE, *SELECTED_TEMPLATES)}
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
        for template in (MIXED_TEMPLATE, MIXED_CANDIDATE_TEMPLATE, EXTERNAL_FINAL_TEMPLATE, PUBLIC_CANDIDATE_TEMPLATE, *SELECTED_TEMPLATES):
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
            test_filename = Path(name).stem+'_test.go'
            file = workspace/test_filename
            file.write_bytes(projected)
            worker_tests[file] = projected
            replacement[str(core/'protocol/routervpnamnezia'/test_filename)] = str(file)
        overlay.write_text(json.dumps({'Replace': replacement}))
        original_overlay = overlay.read_bytes()
        base = ['go', 'test', '-c', '-race', '-p=1', '-mod=readonly', '-tags='+tags, '-ldflags=-checklinkname=0']
        images = {'peer': workspace/'peer.test', 'box': workspace/'box.test', 'continuous': workspace/'continuous.test'}
        identities = {}
        peer_receipts, box_receipts = {}, {}
        if private_stream_diagnostic or private_depth_diagnostic:
            images['worker'] = Path(captured['ROUTERVPN_PRIVATE_STREAM_IMAGE'])
            identities['worker'] = helpers.image_identity(images['worker'])
            if identities['worker'][1] != captured['ROUTERVPN_PRIVATE_STREAM_SHA256']:
                raise ValueError('Compiled production worker provenance changed')

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
            count = verdict(output, root, leaf, worker_digest=captured.get('ROUTERVPN_PRIVATE_STREAM_SHA256'))
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
            for leaf in STRONG_SELECTED_CASES:
                peer_receipts[leaf] = run_case(images['peer'], PEER_PACKAGE, SELECTED_ROOT, leaf, 90, 105)
                print('Completed original Strong worker case '+leaf, flush=True)
            unchanged()
            return dict(kind='diagnostic-original-strong-selected-v1', target=target, race=True,
                        source_sha256=source_sha, image_sha256=identities['peer'][1],
                        templates={path: hashlib.sha256(raw).hexdigest() for path, raw in template_bytes.items()},
                        worker_sources={name: hashlib.sha256(raw).hexdigest() for name, raw in worker_sources.items()},
                        encrypted=peer_receipts)
        if private_response_diagnostic:
            public_receipts = {leaf: run_case(images['peer'], PEER_PACKAGE, PUBLIC_CANDIDATE_ROOT, leaf, 90, 105)
                               for leaf in PUBLIC_CANDIDATE_CASES}
            external_final_receipts = {}
            for leaf in EXTERNAL_FINAL_CASES:
                external_final_receipts[leaf] = run_case(images['peer'], PEER_PACKAGE, EXTERNAL_FINAL_ROOT, leaf, 90, 105)
            for leaf in PRIVATE_RESPONSE_CASES:
                peer_receipts[leaf] = run_case(images['peer'], PEER_PACKAGE, SELECTED_ROOT, leaf, 90, 105)
            unchanged()
            return dict(kind='diagnostic-compare-local-private-response-v1', target=target, race=True,
                        public_candidate_encrypted=public_receipts,
                        public_candidate_fixture_sha256=hashlib.sha256(template_bytes[PUBLIC_CANDIDATE_TEMPLATE]).hexdigest(),
                        external_final_encrypted=external_final_receipts,
                        external_final_fixture_sha256=hashlib.sha256(template_bytes[EXTERNAL_FINAL_TEMPLATE]).hexdigest(),
                        source_sha256=source_sha, image_sha256=identities['peer'][1],
                        worker_sources={name: hashlib.sha256(raw).hexdigest() for name, raw in worker_sources.items()},
                        encrypted=peer_receipts)
        if private_stream_diagnostic or private_depth_diagnostic:
            for leaf in private_cases:
                peer_receipts[SELECTED_ROOT+'/'+leaf] = run_case(images['peer'], PEER_PACKAGE, SELECTED_ROOT, leaf, 90, 105)
                print('Completed separate private-stream worker case '+leaf, flush=True)
            unchanged()
            return dict(kind='native-selected-private-depth-v1' if private_depth_diagnostic else 'native-selected-private-stream-v1', target=target, source_sha256=source_sha,
                        templates={path: hashlib.sha256(raw).hexdigest() for path, raw in template_bytes.items()},
                        images={name: identity[1] for name, identity in identities.items()}, race=True,
                        encrypted=peer_receipts, installed_host_acceptance=False)
        if later_hostname_diagnostic:
            for root, cases in ((LATER_HOSTNAME_ROOT, LATER_HOSTNAME_CASES), (MIXED_CANDIDATE_ROOT, LATER_HOSTNAME_CANDIDATES)):
                for leaf in cases:
                    peer_receipts[root+'/'+leaf] = run_case(images['peer'], PEER_PACKAGE, root, leaf, 90, 105)
            unchanged()
            result = dict(kind='native-later-hostname-local-diagnostic-v1', target=target, source_sha256=source_sha,
                          templates={path: hashlib.sha256(raw).hexdigest() for path, raw in template_bytes.items()},
                          images={'peer': identities['peer'][1]}, race=True, encrypted=peer_receipts, installed_host_acceptance=False)
            print('Original later hostname native proof: '+json.dumps(result, sort_keys=True), flush=True)
            return result
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
