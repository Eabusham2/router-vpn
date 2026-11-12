#!/usr/bin/env python3
"""Install the closed-by-default ordered application outbound in the pinned core.

This preparer owns only its protocol and two exact registry additions. Existing
provider-strategy preparation supplies the bounded native manager observation.
The Box/TUN dispatch adapter is a separate required integration: a route.final
outbound alone cannot gate application DNS consumed by earlier hijack rules.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
OWNER = 'routervpn-node-chain-execution-gate-source.json'
TEMPLATES = {name: 'protocol/routervpnchaingate/'+name.removesuffix('.tmpl') for name in ('gate.go.tmpl', 'flow.go.tmpl', 'gate_test.go.tmpl')}
PREREQUISITES = {
    'adapter/routervpn_observation.go': 'mobile/strategy/observation.go.tmpl',
    'adapter/outbound/routervpn_observation.go': 'mobile/strategy/outbound_context.go.tmpl',
    'adapter/endpoint/routervpn_observation.go': 'mobile/strategy/endpoint_context.go.tmpl',
}
IMPORT = '\t"github.com/sagernet/sing-box/protocol/routervpnchaingate"\n'
REGISTER = '\troutervpnchaingate.RegisterOutbound(registry)\n'
COMPOSITE_IMPORT = '\t"github.com/sagernet/sing-box/protocol/routervpncomposite"\n'


def inputs():
    return [Path(__file__).resolve(), *(ROOT/'mobile/chain_gate'/name for name in sorted(TEMPLATES)), *(ROOT/name for name in sorted(PREREQUISITES.values()))]


def digest():
    result = hashlib.sha256()
    for source in inputs():
        result.update(source.relative_to(ROOT).as_posix().encode()+b'\0'+source.read_bytes())
    return result.hexdigest()


def destination(vendor, relative):
    path = vendor/relative
    if any(parent.is_symlink() for parent in (path, *path.parents)) or not path.resolve().is_relative_to(vendor):
        raise ValueError('linked ordered application gate destination')
    return path


def registry_source(source):
    declaration = 'func OutboundRegistry() *outbound.Registry {\n'
    if source.count(declaration) != 1 or source.count('import (\n') != 1:
        raise ValueError('ordered gate native registry declaration changed')
    body = source[source.index(declaration):source.index('\n}\n', source.index(declaration))+1]
    imports = source[source.index('import (\n'):source.index('\n)', source.index('import (\n'))+1]
    if '\tgroup.RegisterSelector(registry)\n' not in body or '\t"github.com/sagernet/sing-box/protocol/group"\n' not in imports:
        raise ValueError('ordered gate anchor left original registry')
    for before, addition in (
        ('\t"github.com/sagernet/sing-box/protocol/group"\n', IMPORT),
        ('\tgroup.RegisterSelector(registry)\n', REGISTER),
    ):
        if source.count(before) != 1:
            raise ValueError('ordered gate native registry anchor changed')
        if addition in source:
            # Mobile preparation later installs the composite at the same
            # import anchor. Its exact single import is the only permitted
            # neighbour; registration still belongs immediately to Selector.
            placed = before+addition in source
            if addition == IMPORT:
                placed = before+addition in imports or (
                    source.count(COMPOSITE_IMPORT) == 1 and
                    before+COMPOSITE_IMPORT+addition in imports)
            if source.count(addition) != 1 or not placed:
                raise ValueError('ordered gate registry addition moved or duplicated')
        else:
            source = source.replace(before, before+addition)
    if source.count('routervpnchaingate') != 2:
        raise ValueError('unexpected ordered application gate registration')
    return source.encode()


def prepare(vendor):
    if any(path.is_symlink() for path in (vendor, *vendor.parents)):
        raise ValueError('linked ordered application gate checkout')
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('ordered application gate requires the exact pinned native core')
    for relative, template in PREREQUISITES.items():
        source = ROOT/template
        target = destination(vendor, relative)
        if source.is_symlink() or not source.is_file() or not target.is_file() or target.read_bytes() != source.read_bytes():
            raise ValueError('ordered application gate requires original bounded native observation: '+relative)
    registry = destination(vendor, 'include/registry.go')
    original = registry.read_bytes()
    derived = registry_source(original.decode())
    manifest = destination(vendor, OWNER)
    previous = {}
    if manifest.exists():
        if not manifest.is_file() or manifest.stat().st_size > 16384:
            raise ValueError('invalid ordered gate ownership record')
        record = json.loads(manifest.read_bytes())
        if not isinstance(record, dict) or set(record) != {'schema', 'core', 'files'} or record['schema'] != 1 or record['core'] != PIN or not isinstance(record['files'], dict) or set(record['files']) != set(TEMPLATES.values()):
            raise ValueError('invalid ordered gate ownership inventory')
        previous = record['files']
        for relative, checksum in previous.items():
            target = destination(vendor, relative)
            if not isinstance(checksum, str) or len(checksum) != 64 or any(c not in '0123456789abcdef' for c in checksum) or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != checksum:
                raise ValueError('modified original ordered gate source')
    values = {}
    for template, relative in TEMPLATES.items():
        source = ROOT/'mobile/chain_gate'/template
        if source.is_symlink() or not source.is_file():
            raise ValueError('missing original ordered gate template')
        target = destination(vendor, relative)
        values[target] = source.read_bytes()
        if target.exists() and (not target.is_file() or relative not in previous and target.read_bytes() != values[target]):
            raise ValueError('foreign ordered application gate source')
    directory = destination(vendor, 'protocol/routervpnchaingate')
    if directory.exists() and any(path not in values for path in directory.iterdir()):
        raise ValueError('undeclared ordered application gate source')
    if registry.read_bytes() != original:
        raise ValueError('ordered gate registry changed during preparation')
    for target, raw in values.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    registry.write_bytes(derived)
    manifest.write_text(json.dumps({'schema': 1, 'core': PIN, 'files': {path.relative_to(vendor).as_posix(): hashlib.sha256(raw).hexdigest() for path, raw in values.items()}}, sort_keys=True, separators=(',', ':'))+'\n')
    print('Owned ordered application gate source:', digest())


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
