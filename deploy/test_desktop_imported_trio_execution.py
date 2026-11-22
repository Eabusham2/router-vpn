#!/usr/bin/env python3
"""Require actual imported-SS Box ownership; encrypted/device I/O is separate."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'github.com/sagernet/sing-box'
PREFIX = 'TestRouterVPNDesktopImported'
CASES = {
    'TrioExecutionNativeAdoptionAndRestore': tuple(mode+'/'+requested for mode in ('wg', 'awg2-fast', 'awg2-strong') for requested in ('server', 'auto')),
    'TrioExecutionPhysicalPolicy': tuple(target+'/'+requested for target in ('linux', 'windows') for requested in ('server', 'auto')),
    'TrioExecutionRejectsChangedNativeGraph': ('middle-key', 'middle-endpoint', 'selected-dns', 'entry-key', 'cancel'),
    'PrefixExecutionNativeAdoption': tuple(mode+'/'+str(count)+'/'+requested for mode in ('wg','awg2-fast','awg2-strong') for count in (2,6) for requested in ('server','auto')),
    'PrefixExecutionRejectsChangedNativeGraph': ('middle-key','middle-endpoint','earlier-key','earlier-detour','selected-dns','cancel'),
}
GENERATED = {
    'mobile/desktop/node_chain_execution_imported_test.go.tmpl': 'routervpn_desktop_node_chain_execution_imported_test.go',
    'mobile/chain/execution_box_test.go.tmpl': 'routervpn_node_chain_execution_test.go',
    'mobile/chain/execution_box.go.tmpl': 'routervpn_node_chain_execution.go',
    'mobile/desktop/node_chain_box_physical.go.tmpl': 'routervpn_desktop_node_chain_box_physical.go',
}

def expected():
    return {PREFIX+root+suffix for root, children in CASES.items() for suffix in ('', *('/'+child for child in children))}

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

BUILDER = load('imported_trio_native_builder', 'build-native-runtime.py')
PREP = load('imported_trio_native_preparation', 'prepare-desktop-external.py')

def verdict(raw, code):
    if code != 0:
        raise ValueError('imported execution native command failed')
    BUILDER.verify_imported_native_verdicts(raw, PACKAGE, expected())
    return {'tests': len(expected()), 'scope': 'actual Box/managers/adoption/restore and closed physical construction; encrypted prefixes, privileged TUN and DNS I/O are explicit fixture boundaries'}

def verify(core):
    core = PREP.checked_vendor(core)
    copies = PREP.pt_copies()
    for source, generated in GENERATED.items():
        copies[generated] = (ROOT/source).read_bytes()
    for relative, expected_bytes in copies.items():
        path = core/relative
        if path.is_symlink() or not path.is_file() or path.read_bytes() != expected_bytes:
            raise ValueError('prepared imported execution source differs: '+relative)
    # Retain the complete original native Go/module tree, not merely these
    # fixture roots. Upstream pinned/prepared identity remains the builder's
    # authority; this digest detects replacement during compilation/execution.
    rows = []
    for path in sorted(core.rglob('*')):
        if path.is_file() and (path.suffix == '.go' or path.name in ('go.mod','go.sum')):
            if path.is_symlink():
                raise ValueError('native source became a symlink')
            rows.append((path.relative_to(core).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()))
    if not rows:
        raise ValueError('native prepared source closure is empty')
    for relative in ('deploy/test_desktop_imported_trio_execution.py', 'deploy/build-native-runtime.py', 'deploy/prepare-desktop-external.py'):
        path = ROOT/relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('original native gate source is absent')
        rows.append(('shipping/'+relative, hashlib.sha256(path.read_bytes()).hexdigest()))
    return hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()

def run(core, go='go', tags='with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego', receipt=None, without_race=False):
    core = Path(core).resolve()
    source = verify(core)
    executable = shutil.which(go)
    if not executable:
        raise ValueError('selected Go compiler is unavailable')
    environment = dict(os.environ, GOTOOLCHAIN=BUILDER.TOOLCHAIN)
    environment.pop('GOROOT', None)
    target = BUILDER.native_host_target()
    if target not in ('linux/amd64','linux/arm64','windows/amd64','windows/arm64') or without_race != (target == 'windows/arm64'):
        raise ValueError('native imported execution requires its original Windows/Linux host and supported race mode')
    if environment.get('GOOS', target.split('/')[0]) != target.split('/')[0] or environment.get('GOARCH', target.split('/')[1]) != target.split('/')[1]:
        raise ValueError('native execution cannot use a cross-compiled host')
    executable, environment = BUILDER.capture_native_test_compiler(executable, target, environment)
    selection = '^'+PREFIX+'('+'|'.join(CASES)+')$'
    with tempfile.TemporaryDirectory(prefix='routervpn-imported-trio-') as directory:
        binary = Path(directory)/('native.test.exe' if target.startswith('windows/') else 'native.test')
        compile_command = [executable, 'test', '-c', *([] if without_race else ['-race']), '-p=1', '-mod=readonly', '-ldflags=-checklinkname=0', '-tags='+tags, '-o', str(binary), '.']
        subprocess.run(compile_command, cwd=core, env=environment, check=True, timeout=900)
        image = hashlib.sha256(binary.read_bytes()).hexdigest()
        if verify(core) != source:
            raise ValueError('native source changed during original compilation')
        command = [executable, 'tool', 'test2json', '-p', PACKAGE, str(binary), '-test.v=test2json', '-test.timeout=120s', '-test.run='+selection]
        completed = subprocess.run(command, cwd=core, env=environment, capture_output=True, text=True, timeout=135)
        print(completed.stdout, end='')
        if completed.stderr:
            print(completed.stderr, end='')
        if receipt:
            Path(str(receipt)+'.jsonl').write_text(completed.stdout)
        result = verdict(completed.stdout, completed.returncode)
        if verify(core) != source or hashlib.sha256(binary.read_bytes()).hexdigest() != image:
            raise ValueError('original native source/image changed during execution')
    result.update(schema=1, source_sha256=source, image_sha256=image, target=target, race=not without_race, compile_command=compile_command, command=command, output_sha256=hashlib.sha256(completed.stdout.encode()).hexdigest())
    if receipt:
        Path(receipt).write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    print(json.dumps(result, sort_keys=True))
    return result

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--tags', default='with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--without-race', action='store_true', help='Required only on native Windows ARM64')
    args = parser.parse_args()
    run(args.core, args.go, args.tags, args.receipt, args.without_race)
