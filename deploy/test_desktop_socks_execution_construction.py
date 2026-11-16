#!/usr/bin/env python3
"""Require the distinct native SOCKS desktop construction and its owner control.

The actual option registries, typed captures and source policies execute here.
No TUN, kernel permit, encrypted route or live application readiness is claimed.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'cmd/sing-box'
PREFIX = 'TestRouterVPNDesktopSOCKSExecutionConstruction'
CASES = {
    PREFIX+'KeepsPrivateContext': tuple(target+'/'+setting for target in ('linux', 'windows', 'darwin') for setting in ('server', 'auto')),
    PREFIX+'RefusesReplacement': ('copy', 'preparation', 'physical', 'source', 'policy', 'context', 'capture', 'registry', 'config', 'receipt', 'cancelled', 'nil-caller'),
}
TAGS = 'with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego'
TEMPLATE = 'node_chain_socks_execution_construction.go.tmpl'
NATIVE = 'cmd/sing-box/routervpn_node_chain_socks_execution_construction.go'
spec = importlib.util.spec_from_file_location('socks_construction_receipt', ROOT/'deploy/test_mobile_node_chain_execution.py')
RECEIPT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RECEIPT)


def expected():
    return {name for root, children in CASES.items() for name in (root, *(root+'/'+child for child in children))}


def verdict(raw, code):
    records = RECEIPT.verdict(raw, code, {PACKAGE: set(CASES)})
    if {json.loads(record)['Test'] for record in records} != expected():
        raise ValueError('desktop SOCKS construction omitted an original case')
    return records


def command(go, tags, race, selection, overlay=None):
    result = [go, 'test', '-json', *(['-race'] if race else []), '-mod=readonly', '-p=1', '-count=1', '-timeout=120s', '-tags='+tags, '-ldflags=-checklinkname=0']
    if overlay is not None:
        result.append('-overlay='+str(overlay))
    return result+['./'+PACKAGE, '-run', selection]


def execute(core, go, tags, race=True):
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=core, text=True).strip() != '1ac1a339cb1223e9c70eae14c44411c75033c02d':
        raise ValueError('desktop SOCKS construction requires the pinned original core')
    for template, destination in ((TEMPLATE, NATIVE), ('node_chain_socks_execution_construction_test.go.tmpl', NATIVE.removesuffix('.go')+'_test.go')):
        target = core/destination
        if target.is_symlink() or not target.is_file() or target.read_bytes() != (ROOT/'mobile/desktop'/template).read_bytes():
            raise ValueError('desktop SOCKS construction lost its exact prepared template')
    env = dict(os.environ)
    env.setdefault('GOMAXPROCS', '2')
    env.setdefault('GOGC', '50')
    env.setdefault('GOMEMLIMIT', '1800MiB')
    run = subprocess.run(command(go, tags, race, '^('+ '|'.join(CASES)+')$'), cwd=core, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    try:
        records = verdict(run.stdout, run.returncode)
    except (ValueError, TypeError):
        print(run.stdout, flush=True)
        raise
    for record in records:
        print(record, flush=True)
    print('Native desktop SOCKS construction:', len(CASES), 'roots,', len(records), 'PASS records', flush=True)
    target = core/NATIVE
    original = target.read_text()
    before = 'c.self != c || '
    if original.count(before) != 1:
        raise ValueError('desktop SOCKS original-owner boundary changed')
    with tempfile.TemporaryDirectory(prefix='routervpn-socks-construction-control-') as directory:
        changed, overlay = Path(directory)/target.name, Path(directory)/'overlay.json'
        changed.write_text(original.replace(before, '', 1))
        overlay.write_text(json.dumps({'Replace': {str(target): str(changed)}}))
        test = PREFIX+'RefusesReplacement'
        selection = '^'+re.escape(test)+'$/^copy$'
        run = subprocess.run(command(go, tags, race, selection, overlay), cwd=core, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    events = []
    for line in run.stdout.splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            pass
    witness = 'execution child admitted a copied or replaced construction'
    if (run.returncode == 0 or not any(row.get('Action') == 'run' and row.get('Test') == test for row in events) or
            not any(row.get('Action') == 'fail' and row.get('Test') == test for row in events) or
            not any(row.get('Action') == 'output' and row.get('Test') == test+'/copy' and witness in row.get('Output', '') for row in events) or
            any('DATA RACE' in row.get('Output', '') for row in events) or target.read_text() != original):
        print(run.stdout, flush=True)
        raise ValueError('desktop SOCKS original-owner causal witness missing')
    print('Causal desktop SOCKS construction refusal PASS: copied original construction', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--tags', default=TAGS)
    parser.add_argument('--without-race', action='store_true')
    args = parser.parse_args()
    execute(args.core.resolve(), args.go, args.tags, not args.without_race)
