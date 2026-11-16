#!/usr/bin/env python3
"""Execute actual typed desktop candidate mailboxes; kernel/packet models explicit."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'github.com/sagernet/sing-box'
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
TAGS = 'with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego'
ADMISSION = ('generic-request', 'generic-source', 'generic-live', 'ready-kind', 'ready-reader', 'ready-network',
             'source-object', 'config-bytes', 'inventory-bytes', 'capture', 'state', 'box-owner',
             'mtu-active', 'throughput', 'measurement-hold')
DRAIN = ('cancel-drain', 'catalog-aba', 'retirement-drain', 'replacement-state', 'request-inode', 'inventory-inode')
PREFIX = 'TestRouterVPNDesktop'
CASES = {
    'cmd/sing-box': {
        PREFIX+'SOCKSConnectedCandidatesFifty': ('3', '4', '8'),
        PREFIX+'CONNECTConnectedCandidatesFifty': tuple(f'{family}-{count}' for family in ('http', 'https') for count in (3, 4, 8)),
        **{PREFIX+family+'ConnectedCandidatesRejectsAdmission': ADMISSION for family in ('SOCKS', 'CONNECT')},
        **{PREFIX+family+'ConnectedCandidatesRetainsDrain': DRAIN for family in ('SOCKS', 'CONNECT')},
    },
    '.': {
        PREFIX+'NodeChainSOCKSPhysicalActualBox': (),
        PREFIX+'NodeChainCONNECTPhysicalActualBox': (),
        PREFIX+'NodeChainSOCKSPhysicalRejectsGraphDrift': ('middle-user', 'middle-password', 'middle-detour', 'final-detour', 'dns', 'physical-source', 'mtu', 'interface'),
        PREFIX+'NodeChainCONNECTPhysicalRejectsGraphDrift': ('middle-user', 'middle-password', 'middle-detour', 'final-detour', 'final-carrier', 'dns', 'physical-source', 'mtu', 'interface'),
    },
}
TEMPLATES = {
    **{name: 'cmd/sing-box/routervpn_'+name+'.go' for name in (
        'node_chain_socks_candidates', 'node_chain_connect_candidates',
        'node_chain_socks_candidates_test', 'node_chain_connect_candidates_test',
        'node_chain_socks_runtime', 'node_chain_connect_runtime',
        'node_chain_socks_measurement', 'node_chain_connect_measurement',
        'node_chain_socks_mtu', 'node_chain_connect_mtu',
        'node_chain_socks_construction', 'node_chain_connect_construction',
        'node_chain_socks_construction_test', 'node_chain_connect_construction_test',
        'node_chain_command_test', 'node_chain_candidates_test', 'mtu_node', 'mtu_test', 'external')},
    **{name: 'routervpn_desktop_'+name+'.go' for name in (
        'node_chain_socks_box_physical', 'node_chain_connect_box_physical',
        'node_chain_socks_box_physical_test', 'node_chain_connect_box_physical_test')},
}
SHARED = ('node_chain_typed_connected_candidates.go', 'node_chain_socks_runtime.go', 'node_chain_connect_runtime.go')
GENERIC_REFUSAL = '''\tfor _, name := range []string{"node-chain-candidate-request.json", "node-chain-candidate-source.json", "node-chain-candidate-live.json"} {
\t\tif _, err := owner.files.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
\t\t\treturn routerVPNExternalFailure
\t\t}
\t}
'''
JOIN_REFUSAL = '''\tif op.service != nil {
\t\tif err := op.service.CloseContext(ctx); err != nil {
\t\t\treturn err
\t\t}
\t}
\tif owner.measurementHold.Load() {
\t\treturn routerVPNExternalFailure
\t}
'''
CONTROLS = (
    ('generic-mailbox', 'cmd/sing-box/routervpn_node_chain_socks_measurement.go', GENERIC_REFUSAL, '',
     PREFIX+'SOCKSConnectedCandidatesRejectsAdmission', 'generic-request',
     'typed candidate admitted a foreign source, Ready, Box, or activity owner'),
    ('typed-ready', 'cmd/sing-box/routervpn_node_chain_connect_candidates.go',
     ' || owner.candidateRequestCurrent(ctx, request) != nil', ' || false',
     PREFIX+'CONNECTConnectedCandidatesRejectsAdmission', 'ready-reader',
     'typed candidate admitted a foreign source, Ready, Box, or activity owner'),
    ('original-drain', 'cmd/sing-box/routervpn_node_chain_socks_candidates.go', JOIN_REFUSAL, '',
     PREFIX+'SOCKSConnectedCandidatesRetainsDrain', 'replacement-state',
     'typed failed close lost old operation or touched replacement state'),
)


def load(name):
    spec = importlib.util.spec_from_file_location('typed_connected_'+name.replace('-', '_'), ROOT/'deploy'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Reuse the existing strict Go JSON event decoder. These are new required
# inventories, not a second permissive parser or source-marker acceptance.
PARSER = load('test_desktop_socks_execution_child')


def names(roots):
    return {name for root, children in roots.items() for name in (root, *(root+'/'+child for child in children))}


def positive_phases():
    result = []
    for package, roots in CASES.items():
        for root, children in roots.items():
            if root.endswith('Fifty'):
                for child in children:
                    result.append((root+'/'+child, package, {root: (child,)}))
            else:
                result.append((root, package, {root: children}))
    return tuple(result)


def selection(roots):
    if len(roots) != 1:
        raise ValueError('each typed native phase must retain one exact root')
    root, children = next(iter(roots.items()))
    result = '^'+re.escape(root)+'$'
    if children:
        result += '/^('+'|'.join(re.escape(child) for child in children)+')$'
    return result


def verdict(raw, code, package, roots):
    if package not in CASES or not roots or any(root not in CASES[package] or not set(children) <= set(CASES[package][root]) for root, children in roots.items()):
        raise ValueError('foreign typed native inventory')
    for line in raw.splitlines():
        strict_event(line)
    return PARSER.verdict(raw, code, package, roots)


def partition_verdict(results):
    phases = positive_phases()
    if len(results) != len(phases):
        raise ValueError('typed native phase inventory incomplete')
    union = {package: set() for package in CASES}
    for result, (label, package, roots) in zip(results, phases):
        if result[0] != label:
            raise ValueError('typed native phase reordered, repeated or substituted')
        records = verdict(result[1], result[2], package, roots)
        union[package].update(row['Test'] for row in records)
    if union != {package: names(roots) for package, roots in CASES.items()}:
        raise ValueError('typed native complete inventory missing')
    return union


def strict_event(line):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate typed native event key')
            result[key] = value
        return result
    row = json.loads(line, object_pairs_hook=unique)
    if not isinstance(row, dict):
        raise ValueError('invalid typed native event')
    return row


def control_verdict(raw, code, root, child, witness):
    if code != 1:
        raise ValueError('typed native omission was not an ordinary assertion failure')
    wanted, leaf = MODULE+'/cmd/sing-box', root+'/'+child
    expected, ran, failed = {root, leaf}, set(), set()
    started = finished = seen = False
    diagnostics = 0
    abort = re.compile(r'panic:|fatal error:|runtime: out of memory|signal:|\bSIG(?:ABRT|BUS|FPE|ILL|KILL|QUIT|SEGV|TERM)\b|test timed out|\[build failed\]|build (?:failed|aborted)|compile(?:r)?:|link:|exit status [2-9]', re.IGNORECASE)
    for line in raw.splitlines():
        row = strict_event(line)
        action, test, output = row.get('Action'), row.get('Test'), row.get('Output', '')
        if not isinstance(output, str) or abort.search(output):
            raise ValueError('typed omission aborted outside its original assertion')
        if action == 'build-output':
            if (set(row) != {'Action', 'ImportPath', 'Output'} or row['ImportPath'] != wanted+'.test' or started or
                    not isinstance(output, str) or not output or 'DATA RACE' in output):
                raise ValueError('invalid typed omission linker diagnostics')
            diagnostics += len(output.encode())
            if diagnostics > 65536:
                raise ValueError('typed omission diagnostics exceeded original bound')
            continue
        if row.get('Package') != wanted or finished or not isinstance(output, str) or 'DATA RACE' in output:
            raise ValueError('foreign, late or racing typed omission')
        if action == 'start' and not test and not started:
            started = True
        elif action == 'run' and started and test in expected and test not in ran and (test == root or root in ran and root not in failed):
            ran.add(test)
        elif action == 'output' and started and (not test or test in ran and test not in failed):
            if test == leaf and witness in output:
                seen = True
        elif action == 'fail' and test in ran and test not in failed and (test != root or leaf in failed):
            failed.add(test)
        elif action == 'fail' and not test and started and seen and ran == failed == expected:
            finished = True
        else:
            raise ValueError('typed omission did not fail only at its exact executed witness')
    if not finished or not seen or failed != expected:
        raise ValueError('typed omission execution or witness missing')
    return True


def command(go, tags, race, package, roots, overlay=None):
    result = [go, 'test', '-json', *(['-race'] if race else []), '-mod=readonly', '-p=1', '-count=1',
              '-timeout=150s', '-tags='+tags, '-ldflags=-checklinkname=0']
    if overlay is not None:
        result.append('-overlay='+str(overlay))
    return result+['.' if package == '.' else './'+package, '-run', selection(roots)]


def source_identity(core):
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=core, text=True).strip() != PIN:
        raise ValueError('typed candidate gate requires the original pinned native core')
    result = {}
    for template, destination in TEMPLATES.items():
        original = ROOT/'mobile/desktop'/(template+'.go.tmpl')
        actual = core/destination
        if actual.is_symlink() or not actual.is_file() or actual.read_bytes() != original.read_bytes():
            raise ValueError('typed candidate gate lost exact shipping template: '+template)
        result[destination] = hashlib.sha256(actual.read_bytes()).hexdigest()
    prep = load('prepare-desktop-external')
    for name in SHARED:
        relative = 'experimental/libbox/routervpn/mobilemultihop/'+name
        expected = prep.relocated_shared_source((ROOT/'internal/mobilemultihop'/name).read_bytes())
        actual = core/relative
        if actual.is_symlink() or not actual.is_file() or actual.read_bytes() != expected:
            raise ValueError('typed candidate gate lost original shared owner: '+name)
        result[relative] = hashlib.sha256(expected).hexdigest()
    return result


def execute(core, go, tags, race=True, phase='baselines'):
    before = source_identity(core)
    env = dict(os.environ)
    env.setdefault('GOMAXPROCS', '2'); env.setdefault('GOGC', '50'); env.setdefault('GOMEMLIMIT', '1800MiB')
    if phase == 'baselines':
        began, results = time.monotonic(), []
        for label, package, roots in positive_phases():
            remaining = 900-(time.monotonic()-began)
            if remaining <= 0:
                raise ValueError('typed native baseline exceeded its finite aggregate bound')
            run = subprocess.run(command(go, tags, race, package, roots), cwd=core, env=env, text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=min(600, remaining))
            try:
                records = verdict(run.stdout, run.returncode, package, roots)
            except (ValueError, TypeError):
                print(run.stdout, flush=True)
                raise
            results.append((label, run.stdout, run.returncode))
            for row in records:
                print(json.dumps(row, separators=(',', ':')), flush=True)
            print('Typed connected candidate native phase PASS:', label, len(records), 'records', flush=True)
        union = partition_verdict(results)
        print('Typed connected candidate native complete inventory PASS:', sum(map(len, union.values())), 'unique records', flush=True)
    elif phase == 'controls':
        for label, relative, old, new, root, child, witness in CONTROLS:
            target = core/relative
            original = target.read_text()
            if original.count(old) != 1:
                raise ValueError('typed candidate omission boundary changed: '+label)
            with tempfile.TemporaryDirectory(prefix='routervpn-typed-connected-control-') as directory:
                changed, overlay = Path(directory)/target.name, Path(directory)/'overlay.json'
                changed.write_text(original.replace(old, new, 1))
                overlay.write_text(json.dumps({'Replace': {str(target): str(changed)}}))
                run = subprocess.run(command(go, tags, race, 'cmd/sing-box', {root: (child,)}, overlay), cwd=core,
                                     env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
            try:
                control_verdict(run.stdout, run.returncode, root, child, witness)
            except (ValueError, TypeError):
                print(run.stdout, flush=True)
                raise
            if target.read_text() != original:
                raise ValueError('typed omission changed the original source')
            print('Typed connected candidate compiled omission refused:', label, flush=True)
    else:
        raise ValueError('unknown typed connected candidate phase')
    if source_identity(core) != before:
        raise ValueError('typed candidate source changed during required native execution')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', required=True, type=Path)
    parser.add_argument('--go', default='go')
    parser.add_argument('--tags', default=TAGS)
    parser.add_argument('--without-race', action='store_true')
    parser.add_argument('--phase', required=True, choices=('baselines', 'controls'))
    args = parser.parse_args()
    execute(args.core.resolve(), args.go, args.tags, not args.without_race, args.phase)
