#!/usr/bin/env python3
"""Validate shipping Android graphs with the exact prepared native Libbox parser.

No VPN starts. Java composes actual session graphs with generated fixture keys;
the native CheckConfig entrypoint constructs and closes them without Start.
"""
from __future__ import annotations
import argparse
import hashlib
import itertools
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
JAVA_NAMES = ('AndroidMultihopController', 'NativeSingBoxController',
              'AndroidProfileSelection', 'AndroidNumericAddress',
              'AndroidNativeProfilePolicy', 'AndroidWireGuardLibboxPolicy',
              'AndroidStartLayer')


def inputs() -> list[Path]:
    java = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'
    return [Path(__file__).resolve(), ROOT / 'android/test_android_multihop_graph.py',
            ROOT / 'mobile/routervpn_multihop_native_test.go.tmpl',
            *[java / (name + '.java') for name in JAVA_NAMES]]


def digest() -> str:
    h = hashlib.sha256()
    for path in inputs():
        h.update(str(path.relative_to(ROOT)).encode() + b'\0' + path.read_bytes())
    return h.hexdigest()


def require_fixture_matrix(root: Path) -> None:
    expected = set()
    for entry, exit_mode, execution in itertools.product(
            ('shadowsocks', 'hysteria2'),
            ('wg', 'awg2-fast', 'awg2-strong', 'shadowsocks', 'hysteria2'),
            ('local', 'server', 'auto')):
        folder = root / f'{entry}-{exit_mode}-{execution}'
        if not folder.is_dir() or folder.is_symlink():
            raise ValueError('Missing or unsafe generated fixture directory: ' + folder.name)
        for name in ('sing-box.json', 'planned.json') + (('trust.pem',) if exit_mode == 'hysteria2' else ()):
            path = folder / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 4 * 1024 * 1024:
                raise ValueError('Missing, empty, oversized or unsafe generated fixture: ' + str(path))
            expected.add(path.relative_to(root))
    actual, directories = set(), set()
    for path in root.rglob('*'):
        info = path.lstat()
        relative = path.relative_to(root)
        if stat.S_ISREG(info.st_mode):
            actual.add(relative)
        elif stat.S_ISDIR(info.st_mode):
            directories.add(relative)
        else:
            raise ValueError('Generated matrix contains an unsafe entry: ' + str(relative))
    if actual != expected or directories != {Path(path.parts[0]) for path in expected}:
        raise ValueError('Generated graph matrix has missing or unowned entries')


def run(vendor: Path) -> None:
    vendor = vendor.resolve(strict=True)
    revision = subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != PIN:
        raise ValueError('Native core differs from the shipping immutable pin')
    native_test = vendor / 'experimental/libbox/routervpn_multihop_native_test.go'
    if native_test.is_symlink() or native_test.read_bytes() != (ROOT / 'mobile/routervpn_multihop_native_test.go.tmpl').read_bytes():
        raise ValueError('Native fixture reader is absent or differs from the application source')
    env = dict(os.environ, GOTOOLCHAIN='go1.26.3')
    # These are host executables even when launched during an Android build.
    for key in ('GOOS', 'GOARCH'):
        env[key] = subprocess.check_output(['go', 'env', 'GOHOST' + key[2:]], text=True, env=env).strip()
    with tempfile.TemporaryDirectory(prefix='routervpn-native-android-graphs-') as temp:
        fixtures = Path(temp) / 'fixtures'
        fixtures.mkdir()
        env['ROUTERVPN_ANDROID_GRAPH_FIXTURES'] = str(fixtures)
        env['ROUTERVPN_REQUIRE_ANDROID_GRAPH_FIXTURES'] = '1'
        subprocess.run([sys.executable, str(ROOT / 'android/test_android_multihop_graph.py')],
                       cwd=ROOT, env=env, check=True, timeout=180)
        require_fixture_matrix(fixtures)
        subprocess.run(['go', 'test', '-ldflags=-checklinkname=0',
                        '-tags', 'with_quic,with_wireguard,with_gvisor',
                        './experimental/libbox', '-run', '^TestRouterMultihopAndroidGeneratedGraphs$',
                        '-count=1', '-timeout=120s', '-v'], cwd=vendor, env=env, check=True, timeout=600)
    print('All 60 shipping Android graphs passed the pinned native parser; negative schema controls rejected.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', nargs='?', type=Path)
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(digest())
    elif args.vendor:
        run(args.vendor)
    else:
        parser.error('prepared native vendor or --digest required')
