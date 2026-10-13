#!/usr/bin/env python3
"""Link server-only protocol ownership into a disposable pinned native core.

The shared endpoint and key lifecycle are unchanged. Android/iOS continue to
use their owned JNI/Swift factory; this recipe is only for the server CLI.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

PQ = load('server_pq_endpoint', 'prepare-mobile-pq.py')
BIND = load('server_pq_bind', 'mobile_wireguard_bind_policy.py')
COPIES = {
    'mobile/pq/native_factory.go.tmpl': 'protocol/routervpnpq/native_factory.go',
    'mobile/rosenpass/routervpn_pq_host.c': 'protocol/routervpnpq/routervpn_pq_host.c',
    'mobile/rosenpass/routervpn_pq_host.h': 'protocol/routervpnpq/routervpn_pq_host.h',
    'mobile/rosenpass/routervpn_rosenpass.h': 'protocol/routervpnpq/routervpn_rosenpass.h',
}
C_TAG = b'//go:build cgo && routervpn_native_pq\n\n'


def inputs():
    return list(dict.fromkeys([Path(__file__).resolve()] + PQ.inputs() + BIND.inputs()
        + [ROOT/p for p in COPIES]
        + list(sorted((ROOT/'mobile/rosenpass').glob('Cargo.*')))
        + list(sorted((ROOT/'mobile/rosenpass/src').rglob('*.rs')))))


def digest():
    result = hashlib.sha256()
    for source in inputs():
        result.update(str(source.relative_to(ROOT)).encode()+b'\0'+source.read_bytes())
    return result.hexdigest()


def prepare(vendor):
    vendor = vendor.resolve()
    if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip() != PQ.CORE:
        raise ValueError('Server PQ requires the exact pinned native core')
    if not (vendor/'go.mod').read_text().startswith('module github.com/sagernet/sing-box\n'):
        raise ValueError('Not the disposable server core')
    prepared = {}
    # Do not overwrite an unknown native implementation, even in a build tree.
    for source, destination in COPIES.items():
        data = (ROOT/source).read_bytes()
        if destination.endswith('.c'):
            data = C_TAG+data
        path = vendor/destination
        if path.is_symlink() or not path.resolve().is_relative_to(vendor):
            raise ValueError('Server PQ destination escaped its checkout')
        if path.exists() and (not path.is_file() or path.read_bytes() != data):
            raise ValueError('Unexpected existing server PQ implementation')
        prepared[path] = data
    PQ.prepare(vendor)
    BIND.prepare(vendor)
    for path, data in prepared.items():
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)
    print('Server PQ native factory source:',digest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor',type=Path,nargs='?')
    parser.add_argument('--digest',action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(digest())
    elif args.vendor:
        prepare(args.vendor)
    else:
        parser.error('vendor or --digest required')
