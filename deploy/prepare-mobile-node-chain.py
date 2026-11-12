#!/usr/bin/env python3
"""Bind ordered node proofs to the actual pinned native Box and network owner."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
OWNER = 'routervpn-node-chain-source.json'
TEMPLATES = {
    'box.go.tmpl': 'routervpn_node_chain.go',
    'box_test.go.tmpl': 'routervpn_node_chain_test.go',
    'network_context.go.tmpl': 'route/routervpn_node_chain.go',
    'network_context_test.go.tmpl': 'route/routervpn_node_chain_test.go',
    'bridge.go.tmpl': 'experimental/libbox/routervpn_node_chain.go',
    'bridge_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_test.go',
    'lifecycle.go.tmpl': 'experimental/libbox/routervpn_node_chain_lifecycle.go',
    'lifecycle_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_lifecycle_test.go',
    'mtu.go.tmpl': 'experimental/libbox/routervpn_node_chain_mtu.go',
    'candidates.go.tmpl': 'experimental/libbox/routervpn_node_chain_candidates.go',
    'candidates_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_candidates_test.go',
    'measurement.go.tmpl': 'experimental/libbox/routervpn_node_chain_measurement.go',
    'measurement_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_measurement_test.go',
}


def inputs():
    return [Path(__file__).resolve(), *sorted((ROOT/'mobile/chain').glob('*.tmpl'))]


def digest():
    result = hashlib.sha256()
    for path in inputs():
        result.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+path.read_bytes())
    return result.hexdigest()


def replace_owned(source, before, after, count=1):
    """Accept the complete owned edit or its exact preimage; never partial state."""
    if source.count(after) == count and source.count(before) == count:
        # Each replacement deliberately retains its original anchor.
        return source
    if source.count(before) != count or after in source:
        raise ValueError('ordered native chain preparation boundary changed')
    return source.replace(before, after)


def box_source(source):
    source = source.replace('\r\n', '\n')
    for before, added, neighbors in (
        ('type Box struct {\n', '\trouterVPNNodeChainOptions string\n',
         ('\trouterVPNExternalOptions string\n', '\trouterVPNTorOptions string\n', '\trouterVPNNodeOptions string\n')),
        ('func New(options Options) (*Box, error) {\n', '\tchainOptionsDigest := routerVPNNodeChainOptionsDigest(options.Context, options.Options)\n',
         ('\texternalOptionsDigest := routerVPNExternalOptionsDigest(options.Context, options.Options)\n',
          '\ttorOptionsSnapshot := routerVPNTorOptionsSnapshot(options.Context, options.Options)\n',
          '\tnodeOptionsDigest := routerVPNNodeOptionsDigest(options.Context, options.Options)\n')),
        ('\treturn &Box{\n', '\t\trouterVPNNodeChainOptions: chainOptionsDigest,\n',
         ('\t\trouterVPNExternalOptions: externalOptionsDigest,\n', '\t\trouterVPNTorOptions: torOptionsSnapshot,\n',
          '\t\trouterVPNNodeOptions: nodeOptionsDigest,\n')),
    ):
        # Later native Tor/external preparation owns adjacent snapshot lines.
        # Accept only those exact neighbors, without adding a second chain
        # field or moving any other constructor/lifecycle statement.
        if added in source:
            pattern = re.escape(before)+'(?:'+'|'.join(re.escape(line) for line in neighbors)+')*'+re.escape(added)
            if source.count(added) != 1 or len(re.findall(pattern, source)) != 1:
                raise ValueError('ordered native graph snapshot moved outside its construction boundary')
        else:
            source = replace_owned(source, before, before+added)
    if source.count('routerVPNNodeChainOptions') != 3 or source.count('chainOptionsDigest') != 2:
        raise ValueError('unexpected ordered native graph snapshot')
    return source.encode()


def network_source(source):
    source = source.replace('\r\n', '\n')
    if '\t"sync/atomic"\n' not in source or '\tstarted                  atomic.Bool\n' not in source:
        raise ValueError('ordered native chain requires the existing atomic lifecycle preparation')
    source = replace_owned(source, 'type NetworkManager struct {\n',
                           'type NetworkManager struct {\n\trouterVPNNodeChainGeneration atomic.Uint64\n')
    before, after = '.RegisterCallback(nm.notifyInterfaceUpdate)', '.RegisterCallback(nm.routerVPNNodeChainInterfaceUpdate)'
    if source.count(after) == 2 and before not in source:
        pass
    elif source.count(before) == 2 and after not in source:
        source = source.replace(before, after)
    else:
        raise ValueError('ordered native network callback ownership changed')
    if source.count('routerVPNNodeChainGeneration') != 1 or source.count('routerVPNNodeChainInterfaceUpdate') != 2:
        raise ValueError('unexpected ordered native network generation')
    return source.encode()


def destination(vendor, relative):
    path = vendor/relative
    if any(parent.is_symlink() for parent in (path, *path.parents)) or not path.resolve().is_relative_to(vendor):
        raise ValueError('linked ordered native chain source target')
    return path


def prepare(vendor, *, mobile=True):
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('ordered native chain requires the exact pinned native core')
    box = destination(vendor, 'box.go')
    network = destination(vendor, 'route/network.go')
    before_box, before_network = box.read_bytes(), network.read_bytes()
    derived_box, derived_network = box_source(before_box.decode()), network_source(before_network.decode())
    owner = destination(vendor, OWNER)
    previous = {}
    if owner.exists():
        if not owner.is_file() or owner.stat().st_size > 64*1024:
            raise ValueError('invalid ordered native chain ownership file')
        record = json.loads(owner.read_bytes())
        if not isinstance(record, dict) or set(record) != {'schema', 'core', 'files'} or record['schema'] != 1 or record['core'] != PIN or not isinstance(record['files'], dict):
            raise ValueError('invalid ordered native chain ownership record')
        previous = record['files']
        for relative, checksum in previous.items():
            if relative not in TEMPLATES.values() or not isinstance(checksum, str) or len(checksum) != 64 or any(c not in '0123456789abcdef' for c in checksum):
                raise ValueError('ordered native chain cannot own another source')
            path = destination(vendor, relative)
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
                raise ValueError('changed owned ordered native chain source')
    content = {}
    for template, relative in TEMPLATES.items():
        if not mobile and relative.startswith('experimental/libbox/'):
            continue
        source = ROOT/'mobile/chain'/template
        if not source.is_file():
            raise ValueError('missing ordered native chain source: '+template)
        path = destination(vendor, relative)
        content[path] = source.read_bytes()
        if path.exists() and (not path.is_file() or relative not in previous and path.read_bytes() != content[path]):
            raise ValueError('refusing to overwrite changed ordered native chain source')
    if box.read_bytes() != before_box or network.read_bytes() != before_network:
        raise ValueError('ordered native chain input changed during preparation')
    for path, value in content.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    box.write_bytes(derived_box)
    network.write_bytes(derived_network)
    owned = dict(previous)
    owned.update({path.relative_to(vendor).as_posix(): hashlib.sha256(value).hexdigest() for path, value in content.items()})
    owner.write_text(json.dumps({'schema': 1, 'core': PIN, 'files': owned}, sort_keys=True, separators=(',', ':'))+'\n')
    print('Owned ordered native node chain source:', digest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path, nargs='?')
    parser.add_argument('--desktop', action='store_true')
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(digest())
    elif args.vendor:
        prepare(args.vendor, mobile=not args.desktop)
    else:
        parser.error('vendor or --digest required')
