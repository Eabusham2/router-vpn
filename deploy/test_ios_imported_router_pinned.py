#!/usr/bin/env python3
"""Parse 346 actual Swift-built imported-entry graphs in pinned Libbox.

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
CONNECT_LAYER_PARENT = 'TestRouterImportedCONNECTAppleLayerGraphs'
PROXY_XRAY_PARENT = 'TestRouterImportedProxyRealityAppleGraphs'
CONNECT_XRAY_PARENT = 'TestRouterImportedCONNECTRealityAppleGraphs'
PACKAGE = 'github.com/sagernet/sing-box/experimental/libbox'
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
NAMES = {a+'--'+b+'--2022-blake3-aes-256-gcm.json' for a in LAYERS for b in LAYERS} | {
    'off--off--2022-blake3-aes-128-gcm.json', 'off--off--2022-blake3-chacha20-poly1305.json'} | {
    'hysteria2--'+a+'--'+b+'.json' for a in LAYERS for b in LAYERS}
PROXY_NAMES = set(NAMES)
NAMES = NAMES | {'final-hysteria2--'+name for name in NAMES}
NAMES |= {'final-'+mode+'--'+name for mode in ('wg','awg2-fast','awg2-strong') for name in PROXY_NAMES}
NAMES |= {'packet-'+kind+'--final-'+final+'--'+entry_layer+'--'+final_layer+'.json'
          for kind in ('wireguard', 'amneziawg') for final in ('shadowsocks', 'hysteria2', 'wg', 'awg2-fast', 'awg2-strong')
          for entry_layer in LAYERS for final_layer in LAYERS}

NAMES |= {"socks5--final-"+mode+".json" for mode in ("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong","reality-vision")}
# Keep all established final-only and entry-only layer labels distinct
# from the remaining both-enabled combinations; never duplicate cases.
NAMES |= {"socks5--final-"+mode+"--"+final+".json"
          for mode in ("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong","reality-vision") for final in LAYERS[1:]}
NAMES |= {"socks5--final-"+mode+"--entry-"+entry+".json"
          for mode in ("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong","reality-vision") for entry in LAYERS[1:]}
NAMES |= {"socks5--final-"+mode+"--"+entry+"--"+final+".json"
          for mode in ("shadowsocks","hysteria2","wg","awg2-fast","awg2-strong","reality-vision")
          for entry in LAYERS for final in LAYERS if (entry,final) != ("off","off")
          and entry != "off" and final != "off"}

NAMES |= {"connect--"+p+"--"+m+"--"+d+".json" for p in ("http-connect","https-connect") for m in ("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305") for d in ("home","custom")}
NAMES |= {"openvpn--"+transport+"--final-"+mode+"--"+entry+"--"+final+".json"
          for transport in ("tcp", "udp")
          for mode in ("shadowsocks", "hysteria2", "wg", "awg2-fast", "awg2-strong")
          for entry in LAYERS for final in LAYERS}

CONNECT_LAYER_NAMES = {p+'--'+entry+'--'+final+'--'+dns+'.json'
                       for p in ('http-connect','https-connect') for entry in LAYERS[1:]
                       for final in ('plain','off',*LAYERS[1:]) for dns in ('home','custom')}
PROXY_XRAY_NAMES = {kind+'--reality-vision--'+entry+'--'+final+'.json'
                    for kind in ('shadowsocks','hysteria2') for entry in LAYERS for final in LAYERS}

CONNECT_XRAY_NAMES = {kind+'--reality-vision--'+entry+'--'+final+'.json'
                      for kind in ('http-connect','https-connect') for entry in LAYERS for final in LAYERS}


def digest():
    paths = {Path(__file__).resolve(), ROOT/'ios/RouterVPN/prepare-libbox.sh', ROOT/'go.mod', ROOT/'deploy/ios_test_crypto_bridge.py'}
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


def require_matrix(root, names=NAMES):
    if root.is_symlink() or not root.is_dir() or {p.name for p in root.iterdir()} != names:
        raise ValueError('Apple imported matrix must contain exactly '+str(len(names))+' original host graphs')
    for name in names:
        info = (root/name).lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 4*1024*1024:
            raise ValueError('Apple imported graph is not an owned bounded regular file: '+name)


def require_verdicts(raw, parent=PARENT, names=NAMES):
    expected = {parent} | {parent+'/'+name for name in names}
    completed = []
    package_passes = 0
    for line in raw.splitlines():
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError('Malformed native Apple imported event')
        action, test = event.get('Action'), event.get('Test')
        # go test -json interleaves BuildEvents and TestEvents. Successful
        # compiler/linker diagnostics use ImportPath, not Package, and cannot
        # provide any of the required native test or package verdicts.
        if action == 'build-output':
            if (set(event) != {'ImportPath', 'Action', 'Output'} or
                    not isinstance(event['ImportPath'], str) or not event['ImportPath'].strip() or
                    not isinstance(event['Output'], str) or not event['Output']):
                raise ValueError('Malformed native Apple imported build output')
            continue
        if action == 'build-fail':
            raise ValueError('Native Apple imported build failed')
        if event.get('Package') != PACKAGE:
            raise ValueError('Unexpected native package in Apple imported proof')
        if action in ('skip', 'fail'):
            raise ValueError('Native Apple imported proof skipped or failed')
        if action == 'pass':
            if test:
                completed.append(test)
            else:
                package_passes += 1
    if len(completed) != len(expected) or set(completed) != expected or package_passes != 1:
        raise ValueError('Native Apple imported proof requires all '+str(len(expected))+' exact passing verdicts for '+parent)



def run_connect_reality(vendor, workspace, env):
    graphs = workspace/'connect-reality'
    graphs.mkdir()
    roles = ('ROUTERVPN_APPLE_CONNECT_LAYER_FIXTURES', 'ROUTERVPN_APPLE_IMPORTED_PROXY_XRAY_FIXTURES',
             'ROUTERVPN_APPLE_IMPORTED_CONNECT_XRAY_FIXTURES', 'ROUTERVPN_REQUIRE_IMPORTED_PROXY_XRAY_FIXTURES')
    child = {key:value for key,value in env.items() if not key.startswith('ROUTERVPN_IOS_') and key not in roles}
    child.update(ROUTERVPN_APPLE_IMPORTED_CONNECT_XRAY_FIXTURES=str(graphs),
                 ROUTERVPN_REQUIRE_IMPORTED_CONNECT_XRAY_FIXTURES='1')
    subprocess.run([sys.executable,str(ROOT/'deploy/test_ios_tor_profile.py')],
                   cwd=ROOT,env=child,check=True,timeout=420)
    require_matrix(graphs, CONNECT_XRAY_NAMES)
    original = {name:(graphs/name).read_bytes() for name in CONNECT_XRAY_NAMES}
    result = subprocess.run(['go','test','-json','-mod=readonly','-ldflags=-checklinkname=0',
        '-tags','with_quic,with_wireguard,with_gvisor,with_openvpn','./experimental/libbox',
        '-run','^'+CONNECT_XRAY_PARENT+'$','-count=1','-timeout=180s'],
        cwd=vendor,env=child,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=600)
    if result.returncode:
        print(result.stdout+result.stderr,file=sys.stderr)
        raise ValueError('Pinned native Apple CONNECT REALITY graph execution failed')
    require_verdicts(result.stdout, CONNECT_XRAY_PARENT, CONNECT_XRAY_NAMES)
    require_matrix(graphs, CONNECT_XRAY_NAMES)
    if any((graphs/name).read_bytes()!=raw for name,raw in original.items()):
        raise ValueError('Actual Swift CONNECT REALITY source changed during native parsing')
    return original


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
        if key.startswith('ROUTERVPN_IOS_') or key in ('ROUTERVPN_APPLE_CONNECT_LAYER_FIXTURES', 'ROUTERVPN_APPLE_IMPORTED_PROXY_XRAY_FIXTURES', 'ROUTERVPN_APPLE_IMPORTED_CONNECT_XRAY_FIXTURES'):
            env.pop(key)
    before = digest()
    with tempfile.TemporaryDirectory(prefix='routervpn-apple-imported-') as temporary:
        graphs = Path(temporary)/'graphs'; graphs.mkdir()
        env.update(ROUTERVPN_IOS_IMPORTED_ROUTER_ONLY='1', ROUTERVPN_IOS_IMPORTED_ROUTER_GRAPHS=str(graphs),
                   ROUTERVPN_REQUIRE_IOS_IMPORTED_ROUTER_GRAPHS='1')
        subprocess.run([sys.executable, str(ROOT/'deploy/test_ios_tor_profile.py')], cwd=ROOT, env=env, check=True, timeout=420)
        require_matrix(graphs)
        result = subprocess.run(['go', 'test', '-json', '-mod=readonly', '-ldflags=-checklinkname=0',
            '-tags', 'with_quic,with_wireguard,with_gvisor,with_openvpn', './experimental/libbox', '-run', '^'+PARENT+'$',
            '-count=1', '-timeout=180s'], cwd=vendor, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
        if result.returncode:
            print(result.stdout+result.stderr, file=sys.stderr)
            raise ValueError('Pinned native Apple imported graph execution failed')
        require_verdicts(result.stdout)
        # CONNECT entry-layer captures have their own inventory and native
        # verdicts. They cannot replace any primary imported graph receipt.
        layer_graphs = Path(temporary)/'connect-layers'; layer_graphs.mkdir()
        layer_env = {k:v for k,v in env.items() if not k.startswith('ROUTERVPN_IOS_')}
        layer_env.update(ROUTERVPN_APPLE_CONNECT_LAYER_FIXTURES=str(layer_graphs),
                         ROUTERVPN_REQUIRE_IOS_IMPORTED_ROUTER_GRAPHS='1')
        subprocess.run([sys.executable, str(ROOT/'deploy/test_ios_tor_profile.py')], cwd=ROOT, env=layer_env, check=True, timeout=420)
        require_matrix(layer_graphs, CONNECT_LAYER_NAMES)
        layer_result = subprocess.run(['go', 'test', '-json', '-mod=readonly', '-ldflags=-checklinkname=0',
            '-tags', 'with_quic,with_wireguard,with_gvisor,with_openvpn', './experimental/libbox', '-run', '^'+CONNECT_LAYER_PARENT+'$',
            '-count=1', '-timeout=180s'], cwd=vendor, env=layer_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
        if layer_result.returncode:
            print(layer_result.stdout+layer_result.stderr, file=sys.stderr)
            raise ValueError('Pinned native Apple CONNECT layer graph execution failed')
        require_verdicts(layer_result.stdout, CONNECT_LAYER_PARENT, CONNECT_LAYER_NAMES)
        proxy_graphs = Path(temporary)/'proxy-reality'; proxy_graphs.mkdir()
        proxy_env = {k:v for k,v in env.items() if not k.startswith('ROUTERVPN_IOS_')}
        proxy_env.update(ROUTERVPN_APPLE_IMPORTED_PROXY_XRAY_FIXTURES=str(proxy_graphs),
                         ROUTERVPN_REQUIRE_IMPORTED_PROXY_XRAY_FIXTURES='1')
        subprocess.run([sys.executable, str(ROOT/'deploy/test_ios_tor_profile.py')], cwd=ROOT, env=proxy_env, check=True, timeout=420)
        require_matrix(proxy_graphs, PROXY_XRAY_NAMES)
        original_proxy = {name:(proxy_graphs/name).read_bytes() for name in PROXY_XRAY_NAMES}
        proxy_result = subprocess.run(['go', 'test', '-json', '-mod=readonly', '-ldflags=-checklinkname=0',
            '-tags', 'with_quic,with_wireguard,with_gvisor,with_openvpn', './experimental/libbox', '-run', '^'+PROXY_XRAY_PARENT+'$',
            '-count=1', '-timeout=180s'], cwd=vendor, env=proxy_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
        if proxy_result.returncode:
            print(proxy_result.stdout+proxy_result.stderr, file=sys.stderr)
            raise ValueError('Pinned native Apple proxy REALITY graph execution failed')
        require_verdicts(proxy_result.stdout, PROXY_XRAY_PARENT, PROXY_XRAY_NAMES)
        require_matrix(proxy_graphs, PROXY_XRAY_NAMES)
        if any((proxy_graphs/name).read_bytes()!=raw for name,raw in original_proxy.items()):
            raise ValueError('Actual Swift proxy REALITY source changed during native parsing')
        run_connect_reality(vendor, Path(temporary), env)
        if before != digest():
            raise ValueError('Apple imported source changed during its executable proof')
    print('Apple imported Router: '+str(len(NAMES))+' primary, 32 separate CONNECT layer, 18 separate proxy REALITY and 18 separate CONNECT REALITY Swift graph exports parsed by pinned Libbox; '+str(len(NAMES)+1)+', 33, 19 and 19 exact native verdicts passed')


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
