#!/usr/bin/env python3
"""Topic-branch Linux amd64 qualification using the shipping prepared source and encrypted worker."""
import argparse
import importlib.util
import json
import os
import platform
import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'linux/amd64'


def load(filename):
    spec = importlib.util.spec_from_file_location('strong_' + filename.replace('-', '_'), ROOT / 'deploy' / (filename + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def precondition(stage):
    test_path = ROOT / 'internal/mobilemultihop/node_chain_extended_awg_selected.go'
    source = test_path.read_text()
    candidate = '(c.proofs[0].Mode != "awg2-fast" && c.proofs[0].Mode != "awg2-strong")'
    original = 'c.proofs[0].Mode != "awg2-fast"'
    if source.count(candidate) != 1:
        raise ValueError('Original Fast-only native refusal can no longer be reproduced')
    old = stage / 'fast-only.go'
    old.write_text(source.replace(candidate, original))
    overlay = stage / 'fast-only.json'
    overlay.write_text(json.dumps({'Replace': {str(test_path): str(old)}}))
    package = './internal/mobilemultihop'
    command = ['go', 'test', '-json', '-p=1', '-count=1', '-run', '^TestNodeChainExtendedAWGSelectedOriginalPlatforms$/^awg2-strong$/^9$/^server$/^android$']
    refused = subprocess.run([*command, '-overlay='+str(overlay), package], cwd=ROOT, capture_output=True, text=True, timeout=1200)
    rows = [json.loads(line) for line in refused.stdout.splitlines()]
    case = 'TestNodeChainExtendedAWGSelectedOriginalPlatforms/awg2-strong/9/server/android'
    if (refused.returncode != 1 or not any(row.get('Action') == 'fail' and row.get('Test') == case for row in rows)
            or not any(row.get('Test') == case and 'typed original preparation ordered execution lost its original path' in row.get('Output', '') for row in rows)):
        raise ValueError('Original classifier did not refuse the captured Strong family at the required witness\n'
                         + (refused.stdout + refused.stderr)[-4096:])
    subprocess.run(['go', 'test', '-p=1', '-count=1', '-timeout=12m', '-run',
                    '^Test(NodeChainExtendedAWGSelectedOriginal|MixedExtendedLocalSourceMTUAndBoundaries|ExtendedStreamSelectionsRoundTripForExplicitExecution|ExtendedImportedDescriptorPreservesPacketEntry)',
                    './internal/common', './internal/multihoprelay', package], cwd=ROOT, check=True, timeout=1200)


def encrypted(stage):
    build = load('build-native-runtime')
    native = load('test_node_chain_multiple_imported_native')
    env = build.environment(TARGET, compiler=True)
    if build.run(['go', 'env', 'GOVERSION', 'GOHOSTOS', 'GOHOSTARCH'], env=env).splitlines() != [build.TOOLCHAIN, 'linux', 'amd64']:
        raise ValueError('Encrypted diagnostic requires the pinned compiler on the actual native target')
    archive = stage / 'desktop-pq'
    pq = build.PQ.verify(archive, TARGET)
    core, xray = stage / 'strong-core', stage / 'strong-xray'
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
    receipt = native.execute(core, TARGET, tags, env, build.run, strong_diagnostic=True)
    if (set(receipt['encrypted']) != set(native.STRONG_SELECTED_CASES) or len(receipt['encrypted']) != 15
            or build.PQ.verify(archive, TARGET) != pq):
        raise ValueError('Diagnostic lost a Strong case or its original native archive')
    sha = build.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT)
    if os.environ.get('GITHUB_SHA', sha) != sha:
        raise ValueError('Runner SHA does not match the checked-out source')
    receipt.update(commit=sha, sing_box_commit=build.PIN, xray_commit=build.POLICY.XRAY.XRAY_PIN, desktop_pq=pq)
    (stage / 'strong-selected.json').write_text(json.dumps(receipt, sort_keys=True)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('precondition', 'encrypted'))
    parser.add_argument('stage', type=Path)
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() not in ('amd64', 'x86_64'):
        parser.error('requires native Linux amd64')
    if args.phase == 'precondition':
        precondition(args.stage.resolve())
    else:
        encrypted(args.stage.resolve())
