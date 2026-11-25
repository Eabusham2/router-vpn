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
    source = 'internal/mobilemultihop/node_chain_execution_candidates.go'
    original = subprocess.check_output(['git','show','37513fa6b4725332825c27fa5fa9c60e4e795313:'+source], cwd=ROOT)
    projection = stage / 'original-selected-candidate-plan.go'
    projection.write_bytes(original)
    overlay = stage / 'original-selected-candidate-plan.json'
    overlay.write_text(json.dumps({'Replace': {str(ROOT/source): str(projection)}}))
    command = ['go','test','-p=1','-count=1','-run','^TestNodeChainCompareLocalImportedResponseCandidate$','./internal/mobilemultihop']
    refused = subprocess.run(command[:-1]+['-overlay='+str(overlay),command[-1]],cwd=ROOT,capture_output=True,text=True,timeout=900)
    if refused.returncode != 1 or 'original Compare Local winner refused its three-member response candidate' not in refused.stdout:
        raise ValueError('Missing the original selected Local witness: '+(refused.stdout+refused.stderr)[-2000:])
    subprocess.run(command, cwd=ROOT, check=True, timeout=900)


def encrypted(stage):
    build = load('build-native-runtime')
    native = load('test_node_chain_multiple_imported_native')
    env = build.environment(TARGET, compiler=True)
    if build.run(['go', 'env', 'GOVERSION', 'GOHOSTOS', 'GOHOSTARCH'], env=env).splitlines() != [build.TOOLCHAIN, 'linux', 'amd64']:
        raise ValueError('Encrypted diagnostic requires the pinned compiler on the actual native target')
    archive = stage / 'desktop-pq'
    pq = build.PQ.verify(archive, TARGET)
    core, xray = stage / 'private-response-core', stage / 'private-response-xray'
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
    receipt = native.execute(core, TARGET, tags, env, build.run, private_response_diagnostic=True)
    if (set(receipt['encrypted']) != set(native.PRIVATE_RESPONSE_CASES) or len(receipt['encrypted']) != 7
            or build.PQ.verify(archive, TARGET) != pq):
        raise ValueError('Diagnostic lost a private response case or its original native archive')
    sha = build.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT)
    if os.environ.get('GITHUB_SHA', sha) != sha:
        raise ValueError('Runner SHA does not match the checked-out source')
    receipt.update(commit=sha, sing_box_commit=build.PIN, xray_commit=build.POLICY.XRAY.XRAY_PIN, desktop_pq=pq)
    (stage / 'selected-private-response.json').write_text(json.dumps(receipt, sort_keys=True)+'\n')


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
