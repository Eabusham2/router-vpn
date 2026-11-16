#!/usr/bin/env python3
"""Require captured SOCKS final layers and real encrypted suffix components.

This gate does not claim installed kernel or public application acceptance.
Original three-node SOCKS server phases run independently with their old limits.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
TAGS = 'with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego'
SHARED = 'experimental/libbox/routervpn/mobilemultihop'
NATIVE = 'protocol/routervpnamnezia'
MODES = ('wg', 'awg2-fast', 'awg2-strong')
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
CASES = {
    SHARED: {
        'TestNodeChainSOCKSServerIndependentFinalLayers': tuple(mode+'/'+layer for mode in MODES for layer in LAYERS),
        'TestNodeChainSOCKSServerLayerAuthorityRefusals': ('foreign-final', 'copied-scope', 'final-type', 'uot', 'password', 'layer', 'detour'),
    },
    NATIVE: {
        'TestRouterVPNLayeredSOCKSServerEncryptedFinal': tuple(mode+'/'+layer for mode, layer in zip(MODES, LAYERS)),
        'TestRouterVPNLayeredSOCKSServerRefusesChangedFinal': ('layer-key', 'whitening', 'final-route', 'final-identity', 'final-token', 'selected-dns', 'cancelled'),
    },
}
OWNER = 'protocol/routervpnnodesocks/socks_server_owner.go'
CONTROL_ROOT = 'TestRouterVPNLayeredSOCKSServerEncryptedFinal'
CONTROL_LEAF = CONTROL_ROOT+'/awg2-strong/aes-256-gcm+xor-whitening'
CONTROL_ANCHOR = '\tfinalType := "shadowsocks"\n'
CONTROL_INSERT = '\tif proofs[1].StartLayer != "off" { return nil, errCapture }\n'
CONTROL_WITNESS = 'native original capture'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT/'deploy'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RECEIPT = load('test_desktop_socks_execution_child')


def command(go, tags, package, roots, overlay=None):
    value = [go, 'test', '-json', '-race', '-p=1', '-mod=readonly', '-count=1', '-timeout=120s',
             '-tags='+tags, '-ldflags=-checklinkname=0']
    if overlay is not None:
        value.append('-overlay='+str(overlay))
    return value+['./'+package, '-run', '^('+'|'.join(map(re.escape, roots))+')$']


def source_contents(core):
    relay = load('prepare-relay-core')
    expected = {}
    for name in ('node_chain_server.go', 'node_chain_socks_server.go', 'node_chain_socks_server_layers_test.go'):
        raw = relay.OBSERVATION.rewrite((ROOT/'internal/mobilemultihop'/name).read_bytes())
        for package in relay.AMNEZIA.POLICY_PACKAGES:
            raw = raw.replace(('"router-vpn/internal/'+package+'"').encode(),
                              ('"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+package+'"').encode())
        expected[SHARED+'/'+name] = raw
    expected[OWNER] = (ROOT/'mobile/chain/socks_server_owner.go.tmpl').read_bytes()
    prep = load('prepare-desktop-external')
    generated = {}
    prep.write = lambda vendor, relative, raw: generated.__setitem__(relative, raw)
    prep.copy_encrypted_peer_templates(core)
    target = NATIVE+'/routervpn_desktop_node_chain_socks_server_test.go'
    expected[target] = generated[target]
    return expected


def checked_sources(core):
    receipt = {}
    for relative, raw in source_contents(core).items():
        actual = core/relative
        if actual.is_symlink() or not actual.is_file() or actual.read_bytes() != raw:
            raise ValueError('layered SOCKS gate lost original prepared source: '+relative)
        receipt[relative] = hashlib.sha256(raw).hexdigest()
    return receipt


def control_verdict(raw, code):
    if code != 1:
        raise ValueError('original Off-only guard did not reject layered final')
    expected = {CONTROL_ROOT, CONTROL_LEAF}
    ran, failed, witnessed = set(), set(), 0
    started = finished = False
    for line in raw.splitlines():
        row = json.loads(line)
        if not isinstance(row, dict) or row.get('Package') != RECEIPT.MODULE+'/'+NATIVE or finished:
            raise ValueError('foreign layered SOCKS causal event')
        action, test = row.get('Action'), row.get('Test')
        output = row.get('Output', '')
        if not isinstance(output, str) or any(x in output for x in ('DATA RACE', 'panic:', 'build failed')):
            raise ValueError('unrelated layered SOCKS causal failure')
        if action == 'start' and not test and not started:
            started = True
        elif action == 'run' and started and test in expected and test not in ran and (test == CONTROL_ROOT or CONTROL_ROOT in ran):
            ran.add(test)
        elif action == 'fail' and test in ran and test not in failed and (test != CONTROL_ROOT or CONTROL_LEAF in failed):
            failed.add(test)
        elif action == 'fail' and not test and started and ran == failed == expected:
            finished = True
        elif action == 'output' and started and (not test or test in ran and test not in failed):
            witnessed += int(test == CONTROL_LEAF and CONTROL_WITNESS in output)
        else:
            raise ValueError('missing, duplicate or unrelated layered SOCKS causal event')
    if not finished or witnessed != 1:
        raise ValueError('layered SOCKS causal witness missing')


def execute(core, go, tags):
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=core, text=True).strip() != PIN:
        raise ValueError('layered SOCKS requires original pinned core')
    source = checked_sources(core)
    env = dict(os.environ)
    env.setdefault('GOMAXPROCS', '2'); env.setdefault('GOGC', '50'); env.setdefault('GOMEMLIMIT', '1800MiB')
    for package, roots in CASES.items():
        run = subprocess.run(command(go, tags, package, roots), cwd=core, env=env, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        print(run.stdout, end='', flush=True)
        records = RECEIPT.verdict(run.stdout, run.returncode, package, roots)
        print('Captured layered SOCKS', package, len(records), 'PASS records', flush=True)
        if checked_sources(core) != source:
            raise ValueError('layered SOCKS source changed during acceptance')
    target = core/OWNER
    original = target.read_text()
    if original.count(CONTROL_ANCHOR) != 1:
        raise ValueError('original final-layer boundary changed')
    with tempfile.TemporaryDirectory(prefix='routervpn-socks-final-control-') as directory:
        changed, overlay = Path(directory)/target.name, Path(directory)/'overlay.json'
        changed.write_text(original.replace(CONTROL_ANCHOR, CONTROL_INSERT+CONTROL_ANCHOR, 1))
        overlay.write_text(json.dumps({'Replace': {str(target): str(changed)}}))
        args = command(go, tags, NATIVE, (CONTROL_ROOT,), overlay)
        args[-1] = '^'+CONTROL_ROOT+'$/^awg2-strong$/^aes-256-gcm\\+xor-whitening$'
        run = subprocess.run(args, cwd=core, env=env, text=True, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=600)
    print(run.stdout, end='', flush=True)
    control_verdict(run.stdout, run.returncode)
    if checked_sources(core) != source:
        raise ValueError('layered SOCKS counterfactual changed original source')
    print('Original Off-only native guard rejection witnessed; original source retained', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--tags', default=TAGS)
    args = parser.parse_args()
    execute(args.core.resolve(), args.go, args.tags)
