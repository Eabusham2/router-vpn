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
    spec = importlib.util.spec_from_file_location('later_host_' + filename.replace('-', '_'), ROOT / 'deploy' / (filename + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def precondition(stage):
    source = ROOT / 'internal/mobilemultihop/node_chain_extended_mixed.go'
    captured = source.read_text()
    bounded = 'if packets != 1 || imports != last-packets {'
    if captured.count(bounded) != 1:
        raise ValueError('Original packet-predecessor refusal can no longer be reproduced')
    old = stage / 'first-hostname-only.go'
    old.write_text(captured.replace(bounded, 'if hostnamePosition != packets {'))
    overlay = stage / 'first-hostname-only.json'
    overlay.write_text(json.dumps({'Replace': {str(source): str(old)}}))
    package = './internal/mobilemultihop'
    root = 'TestMixedLocalHostnameKeepsSavedResolverAndAllSuffixSockets'
    command = ['go', 'test', '-p=1', '-count=1', '-json', '-run', '^'+root+'$/^(4|9)$']
    refused = subprocess.run([*command, '-overlay='+str(overlay), package], cwd=ROOT, capture_output=True, text=True, timeout=1200)
    rows = [json.loads(line) for line in refused.stdout.splitlines()]
    for count in (4, 9):
        name = root+'/'+str(count)
        if (refused.returncode != 1 or not any(row.get('Test') == name and row.get('Action') == 'fail' for row in rows)
                or not any(row.get('Test') == name and 'original later hostname after its independent literal stream failed' in row.get('Output', '') for row in rows)):
            raise ValueError('Original first-stream restriction lacked its refusal for '+name+'\n'+(refused.stdout+refused.stderr)[-4096:])
    depth_root = 'TestLaterHostnameDepthAndPredecessor'
    old.write_text(captured.replace(bounded,
        'if packets != 1 || hostnamePosition != 2 || imports != last-packets || (len(nodes) != 4 && len(nodes) != 9) {'))
    depth_command = ['go','test','-p=1','-count=1','-json','-run','^'+depth_root+'$/^(9|96)$/^hostname-(2|7|94)$']
    refused = subprocess.run([*depth_command,'-overlay='+str(overlay),package],cwd=ROOT,capture_output=True,text=True,timeout=1200)
    rows = [json.loads(line) for line in refused.stdout.splitlines()]
    for suffix in ('9/hostname-7','96/hostname-2','96/hostname-94'):
        name = depth_root+'/'+suffix
        if (refused.returncode != 1 or not any(row.get('Test')==name and row.get('Action')=='fail' for row in rows)
                or not any(row.get('Test')==name and 'complete original later hostname failed' in row.get('Output','') for row in rows)):
            raise ValueError('Missing original bounded later-hostname refusal for '+name)
    subprocess.run(['go','test','-p=1','-count=1','-timeout=8m','-run','^'+depth_root+'$',package],cwd=ROOT,check=True,timeout=900)
    subprocess.run(['go', 'test', '-p=1', '-count=1', '-run', '^Test(MixedLocalHostname|NodeChainHostnameExecution|NodeChainImportedHostname)', package],
                   cwd=ROOT, check=True, timeout=1200)


def encrypted(stage):
    build = load('build-native-runtime')
    native = load('test_node_chain_multiple_imported_native')
    env = build.environment(TARGET, compiler=True)
    if build.run(['go', 'env', 'GOVERSION', 'GOHOSTOS', 'GOHOSTARCH'], env=env).splitlines() != [build.TOOLCHAIN, 'linux', 'amd64']:
        raise ValueError('Encrypted diagnostic requires the pinned compiler on the actual native target')
    archive = stage / 'desktop-pq'
    pq = build.PQ.verify(archive, TARGET)
    core, xray = stage / 'later-hostname-core', stage / 'later-hostname-xray'
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
    receipt = native.execute(core, TARGET, tags, env, build.run, later_hostname_diagnostic=True)
    required = {root+'/'+leaf for root, cases in ((native.LATER_HOSTNAME_ROOT, native.LATER_HOSTNAME_CASES),
                                                 (native.MIXED_CANDIDATE_ROOT, native.LATER_HOSTNAME_CANDIDATES)) for leaf in cases}
    if (receipt['target'] != TARGET or set(receipt['encrypted']) != required or len(required) != 30
            or set(receipt['encrypted'].values()) != {2} or build.PQ.verify(archive, TARGET) != pq):
        raise ValueError('Diagnostic lost a later hostname case, target or original archive')
    sha = build.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT)
    if os.environ.get('GITHUB_SHA', sha) != sha:
        raise ValueError('Runner SHA does not match the checked-out source')
    receipt.update(commit=sha, sing_box_commit=build.PIN, xray_commit=build.POLICY.XRAY.XRAY_PIN, desktop_pq=pq)
    (stage / 'later-hostname.json').write_text(json.dumps(receipt, sort_keys=True)+'\n')


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
