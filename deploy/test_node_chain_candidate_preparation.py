#!/usr/bin/env python3
"""Require the pinned native prefix-purpose inventory and causal refusals.

Real managers, gate/ingress, source compiler, private HTTP, candidate TCP and
daemon callback/close ownership execute. The TUN, physical monitor and encrypted
packet transport remain explicit fixtures, not device-path acceptance.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'github.com/sagernet/sing-box'
ROOTS = {
    PACKAGE: {
        'TestRouterVPNNodeChainCandidatePreparationNativeClosedPrefixAndFifty': ('wg', 'awg2-fast', 'awg2-strong'),
        'TestRouterVPNNodeChainCandidatePreparationNativeRejectsActualGraph': ('mtu', 'rule', 'key'),
        'TestRouterVPNNodeChainCandidatePreparationNativeKeepsExactGate': (),
        'TestRouterVPNNodeChainCandidatePreparationNativeDeniedInputRetainsRetirement': ('held', 'failed-close'),
    },
    PACKAGE+'/experimental/libbox': {
        'TestRouterNodeChainBridgeCandidatePreparationSourceAndIdentity': ('source-only', 'instance', 'generation', 'lifetime', 'retired'),
        'TestRouterNodeChainBridgeCandidatePreparationCatalogCloseRetainsCallback': (),
        'TestRouterNodeChainBridgeCandidatePreparationStartupJoinIsMandatory': (),
        'TestRouterNodeChainBridgeCandidatePreparationCatalogChangeIsSticky': (),
        'TestRouterNodeChainBridgeCandidatePreparationNativeLookupKeepsDeadline': (),
        'TestRouterNodeChainBridgeCandidatePreparationRunChecksOriginalCatalog': (),
        'TestRouterNodeChainBridgeCandidatePreparationLaunchIsExact': ('noncanonical', 'unknown', 'kind', 'source', 'position', 'inventory'),
    },
}
CONTROLS = (
    ('denied native input join', 'routervpn_node_chain_candidate_preparation.go',
     '\tif err := e.control.Close(ctx); err != nil {\n\t\treturn err\n\t}\n', '', '.',
     'TestRouterVPNNodeChainCandidatePreparationNativeDeniedInputRetainsRetirement/held', 'unjoined denied input allowed native prefix retirement'),
    ('startup catalog', 'experimental/libbox/routervpn_node_chain_candidate_preparation.go',
     '\tif err := m.CandidateInventoryCurrentContext(observe, m.prep.CaptureSHA256()); err != nil {\n\t\tend()\n\t\treturn err\n\t}\n', '', './experimental/libbox',
     'TestRouterNodeChainBridgeCandidatePreparationRunChecksOriginalCatalog', 'startup bypassed original catalog before prefix native acquisition'),
    ('actual graph', 'routervpn_node_chain_candidate_preparation.go',
     'err != nil || routerVPNNodeChainExecutionOptionsDigest(s.ctx, options) != s.routerVPNNodeChainExecutionOptions', 'err != nil', '.',
     'TestRouterVPNNodeChainCandidatePreparationNativeRejectsActualGraph/mtu', 'changed actual prefix graph acquired preparation'),
    ('closed ingress', 'routervpn_node_chain_candidate_preparation.go',
     'return false, e.nativeCurrent(ctx)', 'return true, e.nativeCurrent(ctx)', '.',
     'TestRouterVPNNodeChainCandidatePreparationNativeClosedPrefixAndFifty/wg', 'prepared candidate purpose opened native DNS ingress'),
    ('exact destination', 'routervpn_node_chain_candidate_preparation.go',
     ' || !e.prep.AllowsDial(tag, address)', '', '.',
     'TestRouterVPNNodeChainCandidatePreparationNativeClosedPrefixAndFifty/wg', 'native candidate dial bypassed selected prefix'),
    ('exact daemon instance', 'experimental/libbox/routervpn_node_chain_candidate_preparation.go',
     'actual != state.instance || ', '(actual != state.instance && false) || ', './experimental/libbox',
     'TestRouterNodeChainBridgeCandidatePreparationSourceAndIdentity/instance', 'prefix bridge accepted changed native owner'),
    ('catalog callback join', 'experimental/libbox/routervpn_node_chain_candidate_preparation.go',
     '\tif err := m.joinCatalog(ctx); err != nil {\n\t\treturn err\n\t}\n', '', './experimental/libbox',
     'TestRouterNodeChainBridgeCandidatePreparationCatalogCloseRetainsCallback', 'unjoined catalog callback allowed native retirement'),
    ('startup join', 'experimental/libbox/routervpn_node_chain_candidate_preparation.go',
     '\tselect {\n\tcase <-state.done:\n\tcase <-ctx.Done():\n\t\treturn ctx.Err()\n\t}\n', '', './experimental/libbox',
     'TestRouterNodeChainBridgeCandidatePreparationStartupJoinIsMandatory', 'pending original startup allowed native retirement'),
    ('sticky catalog', 'experimental/libbox/routervpn_node_chain_candidate_preparation.go',
     'if call.digest != m.inventorySHA {', 'if false {', './experimental/libbox',
     'TestRouterNodeChainBridgeCandidatePreparationCatalogChangeIsSticky', 'changed catalog retained candidate preparation'),
)


def expected(package):
    return {root+suffix for root, children in ROOTS[package].items()
            for suffix in ('', *('/'+child for child in children))}


def verdict(raw, code):
    if code:
        raise ValueError('native prefix preparation command failed')
    started, finished = set(), set()
    runs, passes = {p: set() for p in ROOTS}, {p: set() for p in ROOTS}
    for line in raw.splitlines():
        row = json.loads(line)
        package, action, name = row.get('Package'), row.get('Action'), row.get('Test')
        if package not in ROOTS or package in finished or action in ('skip', 'fail') or 'DATA RACE' in row.get('Output', ''):
            raise ValueError('foreign, late, skipped, failed or racing prefix verdict')
        if name:
            if package not in started or name not in expected(package):
                raise ValueError('unstarted or unexpected prefix test')
            if action == 'run':
                if name in runs[package] or any(name.startswith(parent+'/') for parent in passes[package]):
                    raise ValueError('duplicate or late prefix test')
                runs[package].add(name)
            elif action == 'pass':
                if name not in runs[package] or name in passes[package] or any(child.startswith(name+'/') and child not in passes[package] for child in runs[package]):
                    raise ValueError('unrun, duplicate or incomplete prefix pass')
                passes[package].add(name)
            elif action not in ('output', 'pause', 'cont'):
                raise ValueError('unexpected prefix test event')
        elif action == 'start':
            if package in started:
                raise ValueError('duplicate prefix package')
            started.add(package)
        elif action == 'pass':
            if package not in started or runs[package] != expected(package) or passes[package] != runs[package]:
                raise ValueError('incomplete prefix inventory')
            finished.add(package)
        elif action != 'output':
            raise ValueError('unexpected prefix package event')
    if finished != set(ROOTS):
        raise ValueError('missing original prefix package')
    return sum(len(values) for values in passes.values())


def command(go, packages, selection, overlay=None):
    args = [go, 'test', '-json', '-race', '-mod=readonly', '-p=1', '-count=1', '-timeout=150s',
            '-ldflags=-checklinkname=0', '-tags=with_quic,with_wireguard,with_gvisor']
    if overlay is not None:
        args += ['-overlay', str(overlay)]
    return args+packages+['-run', selection]


def execute(core, go):
    # The shipping preparers verify exact old ownership before updating any
    # generated source; they never accept an unknown/changed native artifact.
    for name in ('prepare-mobile-node-chain', 'prepare-node-chain-execution-owner'):
        spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/(name+'.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.prepare(core)
    for path in sorted((ROOT/'internal/mobilemultihop').glob('node_chain_candidate_preparation*.go')):
        source = path.read_text().replace('"router-vpn/internal/', '"'+PACKAGE+'/experimental/libbox/routervpn/')
        if (core/'experimental/libbox/routervpn/mobilemultihop'/path.name).read_text() != source:
            raise ValueError('native prefix gate has stale shared policy source')
    env = dict(os.environ, GOMAXPROCS='2', GOGC='20', GOMEMLIMIT='768MiB')
    selected = '^('+'|'.join(name for roots in ROOTS.values() for name in roots)+')$'
    baseline = subprocess.run(command(go, ['.', './experimental/libbox'], selected), cwd=core, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900)
    try:
        count = verdict(baseline.stdout, baseline.returncode)
    except (ValueError, TypeError):
        print(baseline.stdout, flush=True)
        raise
    print('PASS native prefix preparation inventory:', count, flush=True)
    with tempfile.TemporaryDirectory(prefix='prefix-causal-') as directory:
        for label, relative, before, after, package, name, witness in CONTROLS:
            original = core/relative
            raw = original.read_text()
            if raw.count(before) != 1:
                raise ValueError('prefix causal boundary changed: '+label)
            mutant = Path(directory)/'mutant.go'
            mutant.write_text(raw.replace(before, after, 1))
            overlay = Path(directory)/'overlay.json'
            overlay.write_text(json.dumps({'Replace': {str(original.resolve()): str(mutant)}}))
            result = subprocess.run(command(go, [package], '^'+name+'$', overlay), cwd=core, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            if result.returncode == 0 or not any(row.get('Action') == 'fail' and row.get('Test') == name for row in rows) or not any(row.get('Test') == name and witness in row.get('Output', '') for row in rows):
                print(result.stdout, flush=True)
                raise ValueError('prefix causal control lost its exact witness: '+label)
            if original.read_text() != raw:
                raise ValueError('native prefix source changed during control')
            print('PASS native prefix causal control:', label, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    execute(args.vendor.resolve(), args.go)
