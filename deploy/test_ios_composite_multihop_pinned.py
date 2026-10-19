#!/usr/bin/env python3
"""Check actual generated Swift composite graphs in the exact native registry.

This is a host configuration gate: CheckConfig constructs and closes the real
native graph without starting a VPN or connecting to any fixture peer.
"""
from __future__ import annotations
import argparse
import hashlib
import itertools
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
MODES = ('max-tls-wg', 'max-tls-awg', 'max-quic-wg', 'max-quic-awg',
         'wg', 'awg2-fast', 'shadowsocks', 'hysteria2', 'ss-v2ray', 'split', 'max')
LAYERS = (('off', 'off'), ('aes-256-gcm', 'aes-256-gcm+xor-whitening'),
          ('aes-256-gcm+xor-whitening', 'aes-256-gcm'))


def inputs() -> list[Path]:
    app = ROOT/'ios/RouterVPN/App'
    tunnel = ROOT/'ios/RouterVPN/PacketTunnel'
    return [Path(__file__).resolve(),
            ROOT/'deploy/test_ios_composite_multihop_pinned_contract.py',
            ROOT/'deploy/test_ios_composite_multihop.py', ROOT/'deploy/test_ios_max_multihop.py',
            ROOT/'deploy/test_ios_pq_selection.py', ROOT/'deploy/test_ios_native_base_selection.py',
            ROOT/'deploy/testfixtures/composite/main.go',
            ROOT/'mobile/routervpn_multihop_native_test.go.tmpl',
            ROOT/'ios/RouterVPN/prepare-libbox.sh',
            *[app/(name+'.swift') for name in ('Models', 'IOSDNSRuntimePolicy', 'IOSNativeXrayProfile',
                                              'IOSNativePQProfile', 'IOSMultihopStartLayer', 'IOSRuntimeSelection')],
            *[tunnel/(name+'.swift') for name in ('PacketTunnelProvider', 'RouterVPNMultihopGraph',
                                                 'RouterVPNMTUPolicy', 'IOSStartLayer')]]


def digest() -> str:
    result = hashlib.sha256()
    for path in inputs():
        result.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes())
    return result.hexdigest()


def case_names() -> set[str]:
    composite = {'ss-v2ray', 'split', 'max'}
    return {'-'.join((entry, exit_mode, first, last, execution))+'.json'
            for entry, exit_mode, (first, last), execution in itertools.product(
                MODES, MODES, LAYERS, ('local', 'server', 'auto'))
            if entry in composite or exit_mode in composite}


def require_matrix(root: Path) -> None:
    names = case_names()
    if len(names) != 513 or not root.is_dir() or root.is_symlink() or {p.name for p in root.iterdir()} != names:
        raise ValueError('Apple composite matrix must contain exactly 513 owned Swift graphs')
    for name in names:
        path = root/name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 4*1024*1024:
            raise ValueError('Generated composite graph is missing, empty, oversized or unsafe: '+name)


def host_environment() -> dict[str, str]:
    env = dict(os.environ, GOTOOLCHAIN='go1.26.3', CGO_ENABLED='1', PYTHONDONTWRITEBYTECODE='1')
    for key in ('GOOS', 'GOARCH'):
        env[key] = subprocess.check_output(['go', 'env', 'GOHOST'+key[2:]], text=True, env=env).strip()
    if platform.system() == 'Darwin':
        # Xcode calls this while targeting iphoneos. Neither host Swift nor the
        # actual native parser may inherit an iOS sysroot, compiler or flags.
        env['SDKROOT'] = subprocess.check_output(['xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True).strip()
        if not Path(env['SDKROOT']).is_dir():
            raise ValueError('macOS host SDK is unavailable')
        for name, compiler in (('CC', 'clang'), ('CXX', 'clang++')):
            env[name] = subprocess.check_output(['xcrun', '--sdk', 'macosx', '--find', compiler], text=True).strip()
        for name in ('IPHONEOS_DEPLOYMENT_TARGET', 'TVOS_DEPLOYMENT_TARGET', 'WATCHOS_DEPLOYMENT_TARGET',
                     'XROS_DEPLOYMENT_TARGET', 'CGO_CFLAGS', 'CGO_CPPFLAGS', 'CGO_CXXFLAGS', 'CGO_LDFLAGS'):
            env.pop(name, None)
    return env


def run(vendor: Path) -> None:
    vendor = vendor.resolve(strict=True)
    revision = subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != PIN:
        raise ValueError('Native core differs from the immutable shipping pin')
    reader = vendor/'experimental/libbox/routervpn_multihop_native_test.go'
    if reader.is_symlink() or reader.read_bytes() != (ROOT/'mobile/routervpn_multihop_native_test.go.tmpl').read_bytes():
        raise ValueError('Native fixture reader is absent or differs from the application source')
    before = digest()
    env = host_environment()
    with tempfile.TemporaryDirectory(prefix='routervpn-native-apple-composite-') as temp:
        fixtures = Path(temp)/'graphs'; fixtures.mkdir()
        env['ROUTERVPN_IOS_COMPOSITE_GRAPHS'] = str(fixtures)
        env['ROUTERVPN_REQUIRE_IOS_COMPOSITE_GRAPHS'] = '1'
        subprocess.run([sys.executable, str(ROOT/'deploy/test_ios_composite_multihop.py')],
                       cwd=ROOT, env=env, check=True, timeout=420)
        require_matrix(fixtures)
        subprocess.run(['go', 'test', '-mod=readonly', '-ldflags=-checklinkname=0',
                        '-tags', 'with_quic,with_wireguard,with_gvisor', './experimental/libbox',
                        '-run', '^TestRouterMultihopAppleCompositeGeneratedGraphs$', '-count=1', '-timeout=180s'],
                       cwd=vendor, env=env, check=True, timeout=600)
        if before != digest():
            raise ValueError('Apple composite source changed during its host/native proof')
    print('Exact pinned Libbox accepted 513 shipping Swift composite graphs and rejected 513 missing-engine mutations')


def main() -> None:
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
