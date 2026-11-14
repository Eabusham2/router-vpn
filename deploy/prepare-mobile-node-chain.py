#!/usr/bin/env python3
"""Bind ordered node proofs to the actual pinned native Box and network owner."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
_binding_spec=importlib.util.spec_from_file_location("native_connect_binding",ROOT/"deploy/native_connect_binding.py")
CONNECT_BINDING=importlib.util.module_from_spec(_binding_spec)
_binding_spec.loader.exec_module(CONNECT_BINDING)
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
OWNER = 'routervpn-node-chain-source.json'
TEMPLATES = {
    'socks_owner.go.tmpl': 'protocol/routervpnnodesocks/socks_owner.go',
    'socks_owner_close_test.go.tmpl': 'protocol/routervpnnodesocks/socks_owner_close_test.go',
    'socks_scope.go.tmpl': 'protocol/routervpnnodesocks/socks_scope.go',
    'socks_box.go.tmpl': 'routervpn_node_chain_socks.go',
    'socks_mtu_box.go.tmpl': 'routervpn_node_chain_socks_mtu.go',
    'socks_mtu_box_test.go.tmpl': 'routervpn_node_chain_socks_mtu_test.go',
    'socks_server.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_server.go',
    'socks_bridge.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks.go',
    'socks_lifecycle.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_lifecycle.go',
    'socks_measurement.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_measurement.go',
    'socks_mtu.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_mtu.go',
    'socks_mtu_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_mtu_test.go',
    'socks_bridge_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_test.go',
    'socks_lifecycle_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_lifecycle_test.go',
    'socks_measurement_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_measurement_test.go',
    'socks_native_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_native_test.go',
    'socks_close_native_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_close_test.go',
    'socks_run_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_socks_run_test.go',
    'candidate_preparation.go.tmpl': 'experimental/libbox/routervpn_node_chain_candidate_preparation.go',
    'candidate_preparation_test.go.tmpl': 'experimental/libbox/routervpn_node_chain_candidate_preparation_test.go',
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
    return [*CONNECT_BINDING.inputs(), Path(__file__).resolve(), ROOT/'deploy/test_node_chain_candidate_preparation.py',
            ROOT/'deploy/test_node_chain_candidate_preparation_runner.py',
            *sorted((ROOT/'mobile/chain').glob('*.tmpl'))]


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


def box_close_binding(source, *, bind):
    """Only the complete exact constructor-return wrapper may coexist."""
    plain = '\treturn &Box{\n'
    bound = '\treturn routerVPNNodeSOCKSBind(&Box{\n'
    plain_tail = '\n\t}, nil\n}'
    bound_tail = '\n\t}), nil\n}'
    if 'routerVPNNodeSOCKSBind' in source:
        if source.count(bound) != 1 or source.count('routerVPNNodeSOCKSBind') != 1:
            raise ValueError('ordered SOCKS acquired Box binding changed')
        start = source.index(bound)
        end = source.find(bound_tail, start)
        if end < 0 or source.find('\nfunc ', start, end) != -1:
            raise ValueError('ordered SOCKS acquired Box binding tail changed')
        source = source[:end]+source[end:].replace(bound_tail, plain_tail, 1)
        source = source.replace(bound, plain, 1)
    if not bind:
        return source
    if source.count(plain) != 1:
        raise ValueError('ordered SOCKS acquired Box constructor changed')
    start = source.index(plain)
    end = source.find(plain_tail, start)
    if end < 0 or source.find('\nfunc ', start, end) != -1:
        raise ValueError('ordered SOCKS acquired Box constructor tail changed')
    source = source[:end]+source[end:].replace(plain_tail, bound_tail, 1)
    return source.replace(plain, bound, 1)


def box_source(source):
    source, connect_bound = CONNECT_BINDING.strip(source.replace('\r\n', '\n'))
    source = box_close_binding(source, bind=False)
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
    guard_before = '\tchainOptionsDigest := routerVPNNodeChainOptionsDigest(options.Context, options.Options)\n'
    guard = ('\tif err := routerVPNNodeSOCKSOptions(options.Context, options.Options); err != nil {\n'
             '\t\treturn nil, err\n\t}\n')
    execution_snapshot = '\tchainExecutionOptionsDigest := routerVPNNodeChainExecutionOptionsDigest(options.Context, options.Options)\n'
    # The original execution preparer adds exactly this immutable digest after
    # the chain digest. Desktop -> mobile preparation must retain that owned
    # neighbor without inserting another guard or allowing native work before it.
    if execution_snapshot in source and source.count(execution_snapshot) != 1:
        raise ValueError('ordered SOCKS native execution neighbor duplicated')
    if 'routerVPNNodeSOCKSOptions' in source:
        pattern = re.escape(guard_before)+'(?:'+re.escape(execution_snapshot)+')?'+re.escape(guard)
        if source.count('routerVPNNodeSOCKSOptions') != 1 or source.count(guard) != 1 or len(re.findall(pattern, source)) != 1:
            raise ValueError('ordered SOCKS native guard moved or duplicated')
    else:
        anchor = guard_before
        if execution_snapshot in source:
            anchor += execution_snapshot
        if source.count(anchor) != 1:
            raise ValueError('ordered SOCKS native guard lost its construction boundary')
        source = source.replace(anchor, anchor+guard, 1)
    if source.count('routerVPNNodeChainOptions') != 3 or source.count('chainOptionsDigest') != 2:
        raise ValueError('unexpected ordered native graph snapshot')
    source = box_close_binding(source, bind=True)
    if connect_bound:
        source = CONNECT_BINDING.bind(source)
    return source.encode()


def command_source(vendor, source):
    """Keep the pinned public constructor and extract its infallible body."""
    relative = 'experimental/libbox/command_server.go'
    original = subprocess.check_output(['git', '-C', str(vendor), 'show', PIN+':'+relative]).decode().replace('\r\n', '\n')
    source = source.replace('\r\n', '\n')
    signature = 'func NewCommandServer(handler CommandServerHandler, platformInterface PlatformInterface) (*CommandServer, error) {\n'
    if original.count(signature) != 1:
        raise ValueError('original native command constructor moved')
    start = original.index(signature)
    end = original.index('\n}\n', start)+2
    method = original[start:end]
    before = signature+'\tctx := baseContext(platformInterface)\n'
    after = (signature+'\treturn newCommandServerWithContext(handler, platformInterface, baseContext(platformInterface)), nil\n}\n\n'
        'func newCommandServerWithContext(handler CommandServerHandler, platformInterface PlatformInterface, ctx context.Context) *CommandServer {\n')
    if method.count(before) != 1 or method.count('\treturn server, nil\n') != 1:
        raise ValueError('original native command factory is no longer infallible')
    rewritten = method.replace(before, after, 1).replace('\treturn server, nil\n', '\treturn server\n', 1)
    expected = original[:start]+rewritten+original[end:]
    if source not in (original, expected):
        raise ValueError('original native command constructor differs from its complete owned projection')
    return expected.encode()


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
    command = destination(vendor, 'experimental/libbox/command_server.go') if mobile else None
    before_command = command.read_bytes() if command is not None else None
    derived_command = command_source(vendor, before_command.decode()) if command is not None else None
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
    if box.read_bytes() != before_box or network.read_bytes() != before_network or (command is not None and command.read_bytes() != before_command):
        raise ValueError('ordered native chain input changed during preparation')
    for path, value in content.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    box.write_bytes(derived_box)
    network.write_bytes(derived_network)
    if command is not None:
        command.write_bytes(derived_command)
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
