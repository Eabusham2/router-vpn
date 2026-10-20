#!/usr/bin/env python3
"""Build the pinned native AWG endpoint as an owned desktop sing-box CLI.

The ordinary installed sing-box is never modified. This exact-source bundle is
selected only for a graph containing an imported native AmneziaWG endpoint.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('desktop_amnezia', ROOT/'deploy/prepare-relay-core.py')
POLICY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(POLICY)
PIN = POLICY.CORE
VERSION = '1.14.1'
TOOLCHAIN = 'go1.26.3'
TAGS = 'with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn'
TARGETS = tuple(system+'/'+arch for system in ('linux', 'darwin', 'windows') for arch in ('amd64', 'arm64'))
MAX_BINARY = 160*1024*1024

def run(command, *, cwd=None, env=None):
    return subprocess.check_output(command, cwd=cwd, env=env, text=True, timeout=600).strip()

def digest():
    value = hashlib.sha256()
    for path in list(dict.fromkeys([Path(__file__).resolve(), *POLICY.inputs()])):
        value.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes())
    return value.hexdigest()

def marker(policy):
    return VERSION+'-routervpn-amnezia.'+policy

def environment(target):
    if target not in TARGETS:
        raise ValueError('Unsupported native AmneziaWG desktop target')
    system, arch = target.split('/')
    env = os.environ.copy()
    env.update(GOTOOLCHAIN=TOOLCHAIN, GOWORK='off', GOFLAGS='', CGO_ENABLED='0', GOOS=system, GOARCH=arch,
               GOAMD64='v1', GOARM64='v8.0', GOSUMDB='sum.golang.org')
    return env

def regular(path, maximum):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError('Invalid native AmneziaWG package input: '+str(path))
    return path.read_bytes()

def check_target(binary, target, env):
    metadata = run(['go', 'version', '-m', str(binary)], env=env)
    system, arch = target.split('/')
    for required in ('GOOS='+system, 'GOARCH='+arch, 'CGO_ENABLED=0', TOOLCHAIN,
                     'github.com/amnezia-vpn/amneziawg-go/v3\t'+POLICY.AMNEZIA.VERSION):
        if required not in metadata:
            raise ValueError('Native AmneziaWG build metadata differs: '+required)

def reuse(destination, target, policy, env):
    binary = destination/('sing-box-amnezia.exe' if target.startswith('windows/') else 'sing-box-amnezia')
    raw = regular(binary, MAX_BINARY)
    receipt = json.loads(regular(destination/'AMNEZIA-RUNTIME.json', 8192))
    expected = {'schema_version': 1, 'runtime': 'sing-box-amnezia', 'version': VERSION,
                'upstream_revision': PIN, 'amnezia_version': POLICY.AMNEZIA.VERSION,
                'amnezia_sum': POLICY.AMNEZIA.SUM, 'policy_sha256': policy, 'target': target,
                'toolchain': TOOLCHAIN, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    if receipt != expected or marker(policy).encode() not in raw:
        raise ValueError('Native AmneziaWG bundle differs from its exact source policy')
    for name in ('SING-BOX-LICENSE', 'AMNEZIA-LICENSE'):
        regular(destination/name, 128*1024)
    check_target(binary, target, env)
    return receipt

def fetch_source(path):
    run(['git', 'init', str(path)])
    run(['git', '-C', str(path), 'remote', 'add', 'origin', 'https://github.com/SagerNet/sing-box.git'])
    run(['git', '-C', str(path), 'fetch', '--depth=1', 'origin', PIN])
    run(['git', '-C', str(path), 'checkout', '--detach', 'FETCH_HEAD'])

def build(target, destination, source=None):
    env, policy = environment(target), digest()
    destination = Path(destination).absolute()
    if destination.is_symlink():
        raise ValueError('Refusing a linked native engine destination')
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_dir() and any(destination.iterdir()):
        reuse(destination, target, policy, env)
        print('Reused verified native AmneziaWG '+target, flush=True)
        return destination
    with tempfile.TemporaryDirectory(prefix='.amnezia-build-', dir=destination.parent) as temp:
        temp = Path(temp)
        if source is None:
            source = temp/'source'
            fetch_source(source)
        source = Path(source).resolve()
        # Existing prepare() verifies the exact core, adds the same upstream
        # AWG endpoint/registry and copies only Router VPN-owned packages.
        POLICY.prepare(source)
        # The same native AWG regression suite includes authenticated Start
        # Layer transport tests; retain its real adapter and shared package.
        POLICY.WHITENING.prepare(source)
        if run(['go', 'env', 'GOVERSION'], env=env) != TOOLCHAIN:
            raise ValueError('Incorrect pinned Go compiler')
        run(['go', 'mod', 'tidy'], cwd=source, env=env)
        run(['go', 'mod', 'verify'], cwd=source, env=env)
        POLICY.AMNEZIA.verify(source)
        stage = temp/'bundle'
        stage.mkdir()
        binary = stage/('sing-box-amnezia.exe' if target.startswith('windows/') else 'sing-box-amnezia')
        ldflags = '-s -w -buildid= -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version='+marker(policy)
        run(['go', 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-tags='+TAGS,
             '-ldflags='+ldflags, '-o', str(binary), './cmd/sing-box'], cwd=source, env=env)
        check_target(binary, target, env)
        raw = regular(binary, MAX_BINARY)
        receipt = {'schema_version': 1, 'runtime': 'sing-box-amnezia', 'version': VERSION,
                   'upstream_revision': PIN, 'amnezia_version': POLICY.AMNEZIA.VERSION,
                   'amnezia_sum': POLICY.AMNEZIA.SUM, 'policy_sha256': policy, 'target': target,
                   'toolchain': TOOLCHAIN, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        (stage/'AMNEZIA-RUNTIME.json').write_text(json.dumps(receipt, sort_keys=True, indent=2)+'\n')
        (stage/'SING-BOX-LICENSE').write_bytes(regular(source/'LICENSE', 128*1024))
        (stage/'AMNEZIA-LICENSE').write_bytes(regular(source/'routervpn-amnezia-LICENSE.txt', 128*1024))
        binary.chmod(0o755)
        reuse(stage, target, policy, env)
        if destination.exists():
            destination.rmdir()
        os.replace(stage, destination)
    print('Built native AmneziaWG '+target+' '+policy, flush=True)
    return destination

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', choices=TARGETS)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--source', type=Path, help='existing disposable exact-pinned source checkout')
    args = parser.parse_args()
    build(args.target, args.destination, args.source)
