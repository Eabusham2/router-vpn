#!/usr/bin/env python3
"""Topic-branch Linux amd64 qualification using the shipping prepared source and encrypted worker."""
import argparse
import importlib.util
import hashlib
import json
import os
import platform
import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'linux/amd64'


def load(filename):
    spec = importlib.util.spec_from_file_location('private_stream_' + filename.replace('-', '_'), ROOT / 'deploy' / (filename + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def precondition(stage, depth=False):
    source = ROOT / 'internal/mobilemultihop/node_chain_multiple_imported_execution.go'
    captured = source.read_text()
    guard = 'return c.selectedPrivateStreamPosition() > 0'
    if captured.count(guard) != 1:
        raise ValueError('Original private-stream refusal can no longer be reproduced')
    prior = 'return len(c.nodes) == 4 && c.selectedPrivateStreamPosition() == 2' if depth else 'return false'
    old = stage / 'packet-intermediates-only.go'
    old.write_text(captured.replace(guard, prior))
    overlay = stage / 'packet-intermediates-only.json'
    overlay.write_text(json.dumps({'Replace': {str(source): str(old)}}))
    package = './internal/mobilemultihop'
    root = 'TestSelectedPairedStreamDepth' if depth else 'TestSelectedPairedStreamOriginal'
    cases = ('5', '9', '16') if depth else ('server', 'auto')
    command = ['go', 'test', '-p=1', '-count=1', '-json', '-run', '^'+root+'$/^('+'|'.join(cases)+')$']
    refused = subprocess.run([*command, '-overlay='+str(overlay), package], cwd=ROOT, capture_output=True, text=True, timeout=1200)
    rows = [json.loads(line) for line in refused.stdout.splitlines()]
    for child in cases:
        name = root+'/'+child
        if (refused.returncode != 1 or not any(row.get('Test') == name and row.get('Action') == 'fail' for row in rows)
                or not any(row.get('Test') == name and 'typed original preparation' in row.get('Output', '') for row in rows)):
            raise ValueError('Original private-stream refusal lacked its targeted witness for '+name+'\n'+(refused.stdout+refused.stderr)[-4096:])
    subprocess.run(['go', 'test', '-p=1', '-count=1', '-run', '^TestSelectedPairedStream', package],
                   cwd=ROOT, check=True, timeout=1200)

def encrypted(stage, depth=False):
    build = load('build-native-runtime')
    native = load('test_node_chain_multiple_imported_native')
    env = build.environment(TARGET, compiler=True)
    if build.run(['go', 'env', 'GOVERSION', 'GOHOSTOS', 'GOHOSTARCH'], env=env).splitlines() != [build.TOOLCHAIN, 'linux', 'amd64']:
        raise ValueError('Encrypted diagnostic requires the pinned compiler on the actual native target')
    archive = stage / 'desktop-pq'
    pq = build.PQ.verify(archive, TARGET)
    core, xray = stage / 'selected-private-stream-core', stage / 'selected-private-stream-xray'
    build.checkout(core, 'https://github.com/SagerNet/sing-box.git', build.PIN)
    build.checkout(xray, 'https://github.com/XTLS/Xray-core.git', build.POLICY.XRAY.XRAY_PIN)
    build.pristine(core, build.PIN)
    build.pristine(xray, build.POLICY.XRAY.XRAY_PIN)
    build.prepare_native_sources(core, xray, env)
    tags = ','.join(build.tags(TARGET))
    env['CGO_LDFLAGS'] = shlex.join(['-L'+str(archive), *pq['native_static_libs']])
    # The canonical peer image retains its own five-minute compile limit.
    # A cold hosted runner first compiles the production registry dependencies.
    build.run(['go', 'build', '-race', '-p=2', '-mod=readonly', '-tags='+tags, '-ldflags=-checklinkname=0',
               '-o', str(stage/'warm-sing-box'), './cmd/sing-box'], cwd=core, env=env, timeout=2400)
    worker = stage / 'warm-sing-box'
    with worker.open('rb') as image:
        original = hashlib.file_digest(image, 'sha256').hexdigest()
    env['ROUTERVPN_PRIVATE_STREAM_IMAGE'] = str(worker)
    env['ROUTERVPN_PRIVATE_STREAM_SHA256'] = original
    receipt = native.execute(core, TARGET, tags, env, build.run, private_stream_diagnostic=not depth, private_depth_diagnostic=depth)
    cases = (*native.PRIVATE_STREAM_CASES, *native.PRIVATE_DEPTH_CASES) if depth else native.PRIVATE_STREAM_CASES
    required = {native.SELECTED_ROOT+'/'+leaf for leaf in cases}
    if (receipt['target'] != TARGET or set(receipt['encrypted']) != required or len(required) != (37 if depth else 11)
            or set(receipt['encrypted'].values()) != {2} or receipt['images']['worker'] != original
            or build.PQ.verify(archive, TARGET) != pq):
        raise ValueError('Diagnostic lost its private stream, separate worker or original archive')
    sha = build.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT)
    if os.environ.get('GITHUB_SHA', sha) != sha:
        raise ValueError('Runner SHA does not match the checked-out source')
    receipt.update(commit=sha, sing_box_commit=build.PIN, xray_commit=build.POLICY.XRAY.XRAY_PIN, desktop_pq=pq)
    name = 'selected-private-depth.json' if depth else 'selected-private-stream.json'
    (stage / name).write_text(json.dumps(receipt, sort_keys=True)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('precondition', 'encrypted'))
    parser.add_argument('stage', type=Path)
    parser.add_argument('--depth', action='store_true', help='qualify the depth diagnostic branch')
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() not in ('amd64', 'x86_64'):
        parser.error('requires native Linux amd64')
    if args.phase == 'precondition':
        precondition(args.stage.resolve(), args.depth)
    else:
        encrypted(args.stage.resolve(), args.depth)
