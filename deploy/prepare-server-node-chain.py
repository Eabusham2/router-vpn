#!/usr/bin/env python3
"""Install the original no-TUN ordered Server worker in the pinned relay core.

The shared compiler is supplied by prepare-relay-core's exact package closure.
This preparer owns only its named worker/Box files; it never starts a listener.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
OWNER = 'routervpn-server-node-chain-source.json'
PREFIXES = ('cmd/sing-box/routervpn_server_chain_', 'routervpn_server_chain_')


def inputs():
    return sorted([Path(__file__).resolve(), ROOT/'deploy/test_server_node_chain_preparation.py',
                   ROOT/'deploy/test_server_node_chain_native.py', ROOT/'deploy/test_server_node_chain_native_runner.py',
                   *sorted((ROOT/'mobile/server_chain').glob('*.tmpl')),
                   *sorted((ROOT/'internal/mobilemultihop').glob('node_chain_server*.go')),
                   *sorted((ROOT/'internal/multihoprelay').glob('node_chain_*.go'))])


def digest():
    result = hashlib.sha256()
    for path in inputs():
        if path.is_symlink() or not path.is_file():
            raise ValueError('Changed ordered Server source closure')
        result.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+path.read_bytes())
    return result.hexdigest()


def copies():
    content = {}
    for path in sorted((ROOT/'mobile/server_chain').glob('*.tmpl')):
        if path.is_symlink() or not path.is_file():
            raise ValueError('Linked ordered Server source')
        name = path.name.removesuffix('.tmpl')
        prefix = 'routervpn_server_chain_' if name.startswith('box') else 'cmd/sing-box/routervpn_server_chain_'
        raw = path.read_bytes()
        if not raw.startswith(b'package box\n' if name.startswith('box') else b'package main\n'):
            raise ValueError('Changed ordered Server package boundary')
        content[prefix+name] = raw
    required = {'cmd/sing-box/routervpn_server_chain_command.go',
                'cmd/sing-box/routervpn_server_chain_native.go',
                'cmd/sing-box/routervpn_server_chain_front.go',
                'routervpn_server_chain_box.go',
                'cmd/sing-box/routervpn_server_chain_front_test.go',
                'cmd/sing-box/routervpn_server_chain_command_test.go',
                'cmd/sing-box/routervpn_server_chain_native_test.go',
                'cmd/sing-box/routervpn_server_chain_resources.go',
                'cmd/sing-box/routervpn_server_chain_resources_test.go'}
    if not required.issubset(content):
        raise ValueError('Incomplete ordered Server native owner')
    return content


def destination(vendor, name):
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts or not name.startswith(PREFIXES):
        raise ValueError('Foreign ordered Server ownership path')
    path = vendor/relative
    current = vendor
    for part in relative.parts:
        current = current/part
        if current.is_symlink():
            raise ValueError('Linked ordered Server generated target')
    return path


def prepare(vendor):
    if vendor.is_symlink():
        raise ValueError('Ordered Server requires an unlinked pinned checkout')
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != CORE:
        raise ValueError('Ordered Server requires the exact pinned native core')
    if not (vendor/'go.mod').read_bytes().startswith(b'module github.com/sagernet/sing-box\n'):
        raise ValueError('Wrong ordered Server native module')
    content = copies()
    owner = vendor/OWNER
    if owner.is_symlink():
        raise ValueError('Linked ordered Server ownership record')
    previous = {}
    if owner.exists():
        record = json.loads(owner.read_text())
        if record.get('schema') != 1 or record.get('core') != CORE or not isinstance(record.get('files'), dict):
            raise ValueError('Invalid ordered Server ownership record')
        previous = record['files']
    for name, expected in previous.items():
        path = destination(vendor, name)
        if not isinstance(expected, str) or len(expected) != 64 or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Changed ordered Server generated source')
    for name, raw in content.items():
        path = destination(vendor, name)
        if path.exists() and name not in previous and (not path.is_file() or path.read_bytes() != raw):
            raise ValueError('Unowned ordered Server generated source')
    source_sha = digest()  # All validation completes before any destination write.
    for name, raw in content.items():
        path = destination(vendor, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    for name in set(previous)-set(content):
        destination(vendor, name).unlink()
    owner.write_text(json.dumps(dict(schema=1, core=CORE, source_sha256=source_sha,
        files={name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(content.items())}), indent=2, sort_keys=True)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path, nargs='?')
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(digest())
    elif args.vendor:
        prepare(args.vendor)
    else:
        parser.error('vendor or --digest required')
