#!/usr/bin/env python3
"""Exercise the actual paired OpenVPN relay over loopback mTLS and Start Layers."""
from pathlib import Path
import argparse
import importlib.util
import os
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'


def load(name):
    spec = importlib.util.spec_from_file_location('external_openvpn_' + name.replace('-', '_'), ROOT/'deploy'/name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(core):
    # This is an executable host gate even when called after a mobile target
    # build. Do not inherit an iPhone SDK or Android/ARM cross-compile settings.
    for name in ('GOOS', 'GOARCH', 'CC', 'CXX', 'CGO_CFLAGS', 'CGO_LDFLAGS'):
        os.environ.pop(name, None)
    if platform.system() == 'Darwin':
        os.environ['SDKROOT'] = subprocess.check_output(['xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True).strip()
        for name in ('IPHONEOS_DEPLOYMENT_TARGET', 'TVOS_DEPLOYMENT_TARGET', 'WATCHOS_DEPLOYMENT_TARGET', 'XROS_DEPLOYMENT_TARGET'):
            os.environ.pop(name, None)
    core = Path(core).resolve()
    if subprocess.check_output(['git', '-C', str(core), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('External OpenVPN native test requires the exact pinned disposable core')
    load('prepare-relay-core.py').prepare(core)
    load('prepare-mobile-whitening.py').prepare(core)
    load('mobile_openvpn_close_policy.py').prepare(core)
    load('prepare-mobile-openvpn.py').prepare(core)
    load('prepare-mobile-strategy.py').prepare(core, mobile=False)
    # A standalone pinned checkout has not yet materialized the production
    # preparation's newly pinned native module closure.
    subprocess.run(['go', 'mod', 'tidy'], cwd=core, check=True, timeout=180)
    tests = {}
    sources = {
        'experimental/libbox/routervpn_openvpn_native_test.go': 'mobile/routervpn_openvpn_native_test.go.tmpl',
        'experimental/libbox/routervpn_openvpn_external_native_test.go': 'mobile/routervpn_openvpn_external_native_test.go.tmpl',
        'protocol/routervpnwhitening/start_layer_whitening_fixture.go': 'mobile/applexray/start_layer_whitening_fixture.go.tmpl',
    }
    for relative, source in sources.items():
        path = core/relative
        content = (ROOT/source).read_bytes()
        if path.is_symlink() or path.exists() and (not path.is_file() or path.read_bytes() != content):
            raise ValueError('External OpenVPN native test destination has another owner')
        tests[path] = (content, path.exists())
    try:
        for path, (content, _) in tests.items():
            path.write_bytes(content)
        with tempfile.TemporaryDirectory(prefix='router-external-openvpn-native-') as temporary:
            binary = Path(temporary)/'start-layer-relay'
            subprocess.run(['go', 'build', '-buildvcs=false', '-o', str(binary), './cmd/start-layer-relay'], cwd=ROOT, check=True, timeout=120)
            environment = dict(os.environ, ROUTER_VPN_WHITENING_TEST_BINARY=str(binary))
            subprocess.run(['go', 'test', '-race', '-count=1', '-timeout=180s', '-ldflags=-checklinkname=0',
                            '-tags', 'with_openvpn,with_wireguard,with_quic,with_gvisor,routervpn_start_layer_integration', './experimental/libbox',
                            '-run', '^TestRouterOpenVPNNativeExternal', '-v'], cwd=core, env=environment, check=True, timeout=240)
    finally:
        for path, (content, existed) in tests.items():
            if not existed and path.is_file() and not path.is_symlink() and path.read_bytes() == content:
                path.unlink()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, required=True)
    run(parser.parse_args().core)
