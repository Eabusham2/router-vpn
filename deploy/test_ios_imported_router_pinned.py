#!/usr/bin/env python3
"""Parse eleven actual Swift-built imported-entry graphs in pinned Libbox.

This is an executable host/compiler composition gate, not a device traffic test.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PARENT = 'TestRouterImportedEntryAppleNativeGraphs'
PACKAGE = 'github.com/sagernet/sing-box/experimental/libbox'
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
NAMES = {a+'--'+b+'--2022-blake3-aes-256-gcm.json' for a in LAYERS for b in LAYERS} | {
    'off--off--2022-blake3-aes-128-gcm.json', 'off--off--2022-blake3-chacha20-poly1305.json'}


def digest():
    paths = {Path(__file__).resolve(), ROOT/'ios/RouterVPN/prepare-libbox.sh', ROOT/'go.mod'}
    for directory, pattern in [('ios/RouterVPN/App', '*.swift'), ('ios/RouterVPN/PacketTunnel', '*.swift'), ('internal', '*.go'), ('mobile', '*.go'), ('mobile', '*.tmpl')]:
        paths.update((ROOT/directory).rglob(pattern))
    paths.update((ROOT/'deploy').glob('test_ios_*.py'))
    paths.update((ROOT/'deploy').glob('prepare-mobile-*.py'))
    paths.add(ROOT/'android/test_android_multihop_graph.py')
    paths.update((ROOT/'deploy/testfixtures').rglob('*.go'))
    result = hashlib.sha256()
    for path in sorted(paths):
        result.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes())
    return result.hexdigest()


def require_matrix(root):
    if root.is_symlink() or not root.is_dir() or {p.name for p in root.iterdir()} != NAMES:
        raise ValueError('Apple imported matrix must contain exactly eleven original host graphs')
    for name in NAMES:
        info = (root/name).lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 4*1024*1024:
            raise ValueError('Apple imported graph is not an owned bounded regular file: '+name)


def require_verdicts(raw):
    expected = {PARENT} | {PARENT+'/'+name for name in NAMES}
    completed = []
    package_passes = 0
    for line in raw.splitlines():
        event = json.loads(line)
        if event.get('Package') != PACKAGE:
            raise ValueError('Unexpected native package in Apple imported proof')
        action, test = event.get('Action'), event.get('Test')
        if action in ('skip', 'fail'):
            raise ValueError('Native Apple imported proof skipped or failed')
        if action == 'pass':
            if test:
                completed.append(test)
            else:
                package_passes += 1
    if len(completed) != 12 or set(completed) != expected or package_passes != 1:
        raise ValueError('Native Apple imported proof requires all twelve exact passing verdicts')


def run(vendor):
    vendor = vendor.resolve(strict=True)
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('Apple imported proof requires the pinned native core')
    reader = vendor/'experimental/libbox/routervpn_imported_entry_native_test.go'
    if reader.is_symlink() or reader.read_bytes() != (ROOT/'mobile/routervpn_imported_entry_native_test.go.tmpl').read_bytes():
        raise ValueError('Apple imported native reader differs from shipping input')
    spec = importlib.util.spec_from_file_location('apple_host_environment', ROOT/'deploy/test_ios_composite_multihop_pinned.py')
    host = importlib.util.module_from_spec(spec); spec.loader.exec_module(host)
    env = host.host_environment()
    for key in tuple(env):
        if key.startswith('ROUTERVPN_IOS_'):
            env.pop(key)
    before = digest()
    with tempfile.TemporaryDirectory(prefix='routervpn-apple-imported-') as temporary:
        graphs = Path(temporary)/'graphs'; graphs.mkdir()
        env.update(ROUTERVPN_IOS_IMPORTED_ROUTER_ONLY='1', ROUTERVPN_IOS_IMPORTED_ROUTER_GRAPHS=str(graphs),
                   ROUTERVPN_REQUIRE_IOS_IMPORTED_ROUTER_GRAPHS='1')
        subprocess.run([sys.executable, str(ROOT/'deploy/test_ios_tor_profile.py')], cwd=ROOT, env=env, check=True, timeout=420)
        require_matrix(graphs)
        result = subprocess.run(['go', 'test', '-json', '-mod=readonly', '-ldflags=-checklinkname=0',
            '-tags', 'with_quic,with_wireguard,with_gvisor', './experimental/libbox', '-run', '^'+PARENT+'$',
            '-count=1', '-timeout=180s'], cwd=vendor, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
        if result.returncode:
            print(result.stdout+result.stderr, file=sys.stderr)
            raise ValueError('Pinned native Apple imported graph execution failed')
        require_verdicts(result.stdout)
        if before != digest():
            raise ValueError('Apple imported source changed during its executable proof')
    print('Apple imported Router: eleven actual Swift graph exports parsed by pinned Libbox; twelve exact native verdicts passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path)
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(digest())
    elif args.vendor:
        run(args.vendor)
    else:
        parser.error('--vendor or --digest is required')


if __name__ == '__main__':
    main()
