#!/usr/bin/env python3
"""Run the native selected-runtime latency and throughput mailbox components."""
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


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


ORIGINAL = load('selected_latency_original_native_gate', 'test_desktop_openvpn_execution_child.py')
FIXTURE = load('selected_latency_original_fixture', 'prepare-desktop-selected-latency-test.py')
PREFIX = 'TestRouterVPNDesktopSelectedLatency'
ROOTS = {
    'TestRouterVPNDesktopSelectedThroughputResultOwnership': ('foreign-destination', 'same-bytes-replacement'),
    'TestRouterVPNDesktopSelectedPrivateResponse': ('server-server', 'auto-local', 'auto-server'),
    'TestRouterVPNDesktopSelectedPathThroughput': ('server-server', 'auto-local', 'auto-server'),
    'TestRouterVPNDesktopSelectedThroughputIncompleteAndCancelled': ('truncated-final', 'cancel-in-flight'),
    PREFIX+'HTTP50Server': (),
    PREFIX+'HTTP50CompareLocal': (),
    PREFIX+'HTTP50CompareServer': (),
    PREFIX+'CancelledBeforeStart': (),
    PREFIX+'RequestGrammar': ('ordinary', 'throughput', 'zero-generation', 'fraction', 'negative-position', 'foreign-node', 'capture-null', 'selected-object', 'missing', 'unknown', 'duplicate'),
    PREFIX+'OriginalOwners': ('copied-measurement', 'original-source-inode', 'capture-inode', 'capture-bytes', 'selected-epoch', 'native-reader', 'foreign-ready', 'foreign-selection'),
    PREFIX+'RejectsSyntheticController': (),
    PREFIX+'FreshProofAssociation': ('prefix-position', 'prefix-profile', 'prefix-kind', 'prefix-label', 'prefix-proof', 'prefix-length', 'response-zero', 'response-nan', 'response-inf', 'reader', 'epoch', 'generation', 'network', 'source', 'config', 'winner', 'final-score', 'heartbeat-backwards'),
}
CONTROLS = (
    ('cmd/sing-box/routervpn_node_chain_execution_measurement.go', 'op.issued.current(files) != nil || f.info != nil', 'f.info != nil', 'TestRouterVPNDesktopSelectedThroughputResultOwnership', 'same-bytes-replacement', 'substituted result retired the original throughput request'),
    ('cmd/sing-box/routervpn_node_chain_execution_latency.go', 'm.owner.measurement.Load() != m || ', '', PREFIX+'OriginalOwners', 'copied-measurement', 'selected facade admitted substituted original owner or capture'),
    ('cmd/sing-box/routervpn_node_chain_execution_measurement.go', ' || request.Selected != m.capture.Selected', '', PREFIX+'OriginalOwners', 'foreign-selection', 'selected facade admitted substituted original owner or capture'),
)
TEMPLATES = ('node_chain_execution_latency', 'node_chain_execution_measurement', 'node_chain_execution_latency_test', 'node_chain_execution_mtu', 'node_chain_execution_runtime', 'node_chain_execution_run_darwin', 'node_command_run_linux', 'mtu_node')


def verify(core):
    identity = {'original_native': ORIGINAL.verify(core)}
    for name in TEMPLATES:
        source = ROOT/'mobile/desktop'/(name+'.go.tmpl')
        target = core/'cmd/sing-box'/('routervpn_'+name+'.go')
        if target.is_symlink() or not target.is_file() or target.read_bytes() != source.read_bytes():
            raise ValueError('selected latency lost actual shipping source: '+name)
        identity[str(target.relative_to(core))] = hashlib.sha256(target.read_bytes()).hexdigest()
    for relative, raw in FIXTURE.copies().items():
        target = core/relative
        if target.is_symlink() or not target.is_file() or target.read_bytes() != raw:
            raise ValueError('selected latency original component projection changed')
        identity[relative] = hashlib.sha256(raw).hexdigest()
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def command(go, tags, race, selection, overlay=None):
    tags = ','.join(dict.fromkeys([*tags.split(','), FIXTURE.TAG]))
    return ORIGINAL.CHILD.command(go, tags, race, 'cmd/sing-box', selection, overlay)


def build_command(go, tags, race, image, overlay=None):
    tags = ','.join(dict.fromkeys([*tags.split(','), FIXTURE.TAG]))
    return [go, 'test', '-c', *(['-race'] if race else []), '-mod=readonly', '-p=1', '-tags='+tags,
            '-ldflags=-checklinkname=0', *(['-overlay='+str(overlay)] if overlay else []), '-o', str(image), './cmd/sing-box']


def run_command(go, image, selection):
    return [go, 'tool', 'test2json', '-p', ORIGINAL.CHILD.MODULE+'/cmd/sing-box', '-t', str(image),
            '-test.v', '-test.count=1', '-test.timeout=120s', '-test.run='+selection]


def compile_image(core, go, tags, race, image, env, overlay=None):
    build = subprocess.run(build_command(go, tags, race, image, overlay), cwd=core, env=env, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    print(build.stdout, end='', flush=True)
    if build.returncode or image.is_symlink() or not image.is_file():
        raise ValueError('actual selected latency image did not compile')
    return hashlib.sha256(image.read_bytes()).hexdigest()


def execute(core, go, tags, race=True, phase='baselines'):
    source = verify(core)
    env = dict(os.environ)
    env.setdefault('GOMAXPROCS', '2'); env.setdefault('GOGC', '50'); env.setdefault('GOMEMLIMIT', '1800MiB')
    if phase == 'baselines':
        # Disjoint whole roots preserve 120s test / 600s compiler bounds.
        # Retest performs a second real50 on the same selected measurement.
        with tempfile.TemporaryDirectory(prefix='selected-latency-baseline-') as directory:
            image = Path(directory)/'selected.test'
            checksum = compile_image(core, go, tags, race, image, env)
            for root, children in ROOTS.items():
                if verify(core) != source or hashlib.sha256(image.read_bytes()).hexdigest() != checksum:
                    raise ValueError('selected latency original source/image changed before component')
                result = subprocess.run(run_command(go, image, '^'+root+'$'), cwd=core, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=135)
                print(result.stdout, end='', flush=True)
                records = ORIGINAL.CHILD.verdict(result.stdout, result.returncode, 'cmd/sing-box', {root: children})
                if verify(core) != source or hashlib.sha256(image.read_bytes()).hexdigest() != checksum:
                    raise ValueError('selected latency source/image changed during actual component')
                print('Selected runtime measurement component PASS:', root, len(records), checksum, flush=True)
    elif phase == 'controls':
        for relative, before, after, root, child, witness in CONTROLS:
            target = core/relative
            raw = target.read_text()
            if raw.count(before) != 1:
                raise ValueError('selected latency original causal anchor changed')
            with tempfile.TemporaryDirectory(prefix='selected-latency-control-') as directory:
                directory = Path(directory)
                changed, overlay = directory/target.name, directory/'overlay.json'
                changed.write_text(raw.replace(before, after, 1))
                overlay.write_text(json.dumps({'Replace': {str(target): str(changed)}}))
                selection = '^'+root+'$/^'+re.escape(child)+'$'
                image = directory/'selected-control.test'
                checksum = compile_image(core, go, tags, race, image, env, overlay)
                result = subprocess.run(run_command(go, image, selection), cwd=core, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=135)
                if hashlib.sha256(image.read_bytes()).hexdigest() != checksum:
                    raise ValueError('selected latency causal image changed during execution')
            print(result.stdout, end='', flush=True)
            if not ORIGINAL.rejected(result.stdout, result.returncode, root, child, witness) or verify(core) != source:
                raise ValueError('selected latency actual causal witness missing')
            print('Selected runtime measurement original-owner causal PASS:', root+'/'+child, flush=True)
    else:
        raise ValueError('unknown selected latency phase')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--tags', default=ORIGINAL.CHILD.TAGS)
    parser.add_argument('--without-race', action='store_true')
    parser.add_argument('--phase', choices=('baselines', 'controls'), required=True)
    args = parser.parse_args()
    execute(args.core.resolve(), args.go, args.tags, not args.without_race, args.phase)
