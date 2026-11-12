#!/usr/bin/env python3
"""Prepare owned ordered execution admission on the exact pinned native core."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
OWNER = 'routervpn-node-chain-execution-source.json'
TEMPLATES = {
    'execution_ingress.go.tmpl': 'route/routervpn_node_chain_ingress.go',
    'execution_selector.go.tmpl': 'protocol/group/routervpn_node_chain_execution.go',
    'execution_selector_test.go.tmpl': 'protocol/group/routervpn_node_chain_execution_test.go',
    'execution_ingress_test.go.tmpl': 'route/routervpn_node_chain_ingress_test.go',
    'execution_tun_test.go.tmpl': 'protocol/tun/routervpn_node_chain_ingress_test.go',
}


def inputs():
    gate_path = ROOT/'deploy/prepare-node-chain-execution-gate.py'
    spec = importlib.util.spec_from_file_location('routervpn_execution_gate_inputs', gate_path)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    return list(dict.fromkeys([Path(__file__).resolve(), ROOT/'deploy/prepare-mobile-external-policy.py', *(ROOT/'mobile/chain'/name for name in sorted(TEMPLATES)), *gate.inputs()]))


def digest():
    value = hashlib.sha256()
    for path in inputs():
        value.update(path.relative_to(ROOT).as_posix().encode()+b'\0'+path.read_bytes())
    return value.hexdigest()


def replace_owned(source, before, after):
    if source.count(after) == 1 and source.count(before) == after.count(before):
        return source
    if source.count(before) != 1 or after in source:
        raise ValueError('ordered execution admission boundary changed')
    return source.replace(before, after, 1)


def router_source(source):
    source = source.replace('\r\n', '\n')
    source = replace_owned(source, '\t"context"\n', '\t"context"\n\t"sync/atomic"\n')
    source = replace_owned(source, 'type Router struct {\n',
        'type Router struct {\n\trouterVPNNodeChainGated bool\n\trouterVPNNodeChainIngress atomic.Pointer[RouterVPNNodeChainIngress]\n\trouterVPNNodeChainGate atomic.Pointer[routerVPNNodeChainGate]\n')
    source = replace_owned(source, '\treturn &Router{\n',
        '\treturn &Router{\n\t\trouterVPNNodeChainGated: options.Final == routerVPNNodeChainApplicationTag,\n')
    source = replace_owned(source, '\tcase adapter.StartStateInitialize:\n',
        '\tcase adapter.StartStateInitialize:\n\t\tif err := r.routerVPNPrepareNodeChainIngress(); err != nil { return err }\n')
    if source.count('routerVPNNodeChainGated') != 2 or source.count('routerVPNNodeChainIngress atomic.Pointer') != 1 or source.count('routerVPNNodeChainGate atomic.Pointer') != 1 or source.count('routerVPNPrepareNodeChainIngress()') != 1:
        raise ValueError('partial ordered Router admission source')
    return source.encode()


def route_source(source):
    source = source.replace('\r\n', '\n')
    for name in ('RouteConnection', 'RouteConnectionEx', 'RoutePacketConnection', 'RoutePacketConnectionEx', 'PreMatch'):
        source = replace_owned(source, f'func (r *Router) {name}(', f'func (r *Router) routerVPN{name}Ungated(')
    return source.encode()


def dns_source(source):
    return replace_owned(source.replace('\r\n', '\n'), 'func (r *Router) HijackDNSPacket(', 'func (r *Router) routerVPNHijackDNSPacketUngated(').encode()


TUN_DISPATCH_BEFORE = 'func (t *Inbound) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {\n'
TUN_DISPATCH_AFTER = TUN_DISPATCH_BEFORE+'\tif gated, ok := t.router.(interface{ RouterVPNNodeChainGated() bool }); ok && gated.RouterVPNNodeChainGated() {\n\t\treturn adapter.JudgeFlow(t.router, t.tag, C.TypeTun, network, source, destination, firstPacket)\n\t}\n'


def tun_source(source):
    source = replace_owned(source.replace('\r\n', '\n'), TUN_DISPATCH_BEFORE, TUN_DISPATCH_AFTER)
    if source.count('RouterVPNNodeChainGated()') != 2:
        raise ValueError('partial ordered TUN dispatch source')
    return source.encode()


def selector_source(source):
    source = source.replace('\r\n', '\n')
    if source.count('func (s *Selector) routerVPNSelectOutboundLocked(') != 1:
        raise ValueError('ordered execution requires original captured selector commit')
    source = replace_owned(source, '\t"sync"\n', '\t"sync"\n\t"sync/atomic"\n')
    source = replace_owned(source, 'type Selector struct {\n',
        'type Selector struct {\n\trouterVPNNodeChainSelection common.TypedValue[*routerVPNNodeChainSelection]\n\trouterVPNNodeChainEpoch atomic.Uint64\n')
    source = replace_owned(source, 'func (s *Selector) All() []string {\n\treturn s.tags\n}',
        'func (s *Selector) All() []string {\n\tif owned := s.routerVPNNodeChainSelection.Load(); owned != nil {\n\t\treturn append([]string(nil), owned.tags...)\n\t}\n\treturn append([]string(nil), s.tags...)\n}')
    source = replace_owned(source,
        '\tif s.selected.Swap(detour) == detour {\n\t\treturn true\n\t}\n',
        '\tif s.selected.Load() == detour {\n\t\treturn true\n\t}\n\ts.routerVPNNodeChainEpoch.Add(1)\n\ts.selected.Swap(detour)\n\ts.routerVPNNodeChainEpoch.Add(1)\n')
    if source.count('routerVPNNodeChainSelection common.TypedValue') != 1 or source.count('routerVPNNodeChainEpoch atomic.Uint64') != 1 or source.count('routerVPNNodeChainEpoch.Add(1)') != 2:
        raise ValueError('partial ordered selector admission source')
    return source.encode()


def target(vendor, relative):
    path = vendor/relative
    if any(item.is_symlink() for item in (path, *path.parents)) or not path.resolve().is_relative_to(vendor):
        raise ValueError('linked ordered execution source')
    return path


def verify_owned_templates(vendor, *, current=True):
    owner = target(vendor, OWNER)
    if not owner.is_file() or owner.stat().st_size > 65536:
        raise ValueError('missing ordered execution source owner')
    record = json.loads(owner.read_bytes())
    if not isinstance(record, dict) or set(record) != {'schema', 'core', 'files'} or record['schema'] != 1 or record['core'] != PIN or not isinstance(record['files'], dict) or set(record['files']) != set(TEMPLATES.values()):
        raise ValueError('invalid ordered execution source inventory')
    for template, relative in TEMPLATES.items():
        source = ROOT/'mobile/chain'/template
        path = target(vendor, relative)
        raw = source.read_bytes()
        if source.is_symlink() or not path.is_file() or record['files'][relative] != hashlib.sha256(path.read_bytes()).hexdigest() or current and path.read_bytes() != raw:
            raise ValueError('changed original ordered execution source')
    return record


def verify_current_templates(vendor):
    return verify_owned_templates(vendor)


def check_original_selection(vendor):
    spec = importlib.util.spec_from_file_location('routervpn_execution_original_selection', ROOT/'deploy/prepare-mobile-external-policy.py')
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    policy.check_selection_sources(vendor, preparing=True)


def prepare(vendor):
    if any(path.is_symlink() for path in (vendor, *vendor.parents)):
        raise ValueError('linked ordered execution checkout')
    vendor = vendor.resolve()
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('ordered execution requires the pinned native core')
    if not (vendor/'go.mod').read_text().startswith('module github.com/sagernet/sing-box\n'):
        raise ValueError('ordered execution requires the original native module')
    check_original_selection(vendor)
    edits = {'route/router.go': router_source, 'route/route.go': route_source, 'route/dns.go': dns_source, 'protocol/tun/inbound.go': tun_source, 'protocol/group/selector.go': selector_source}
    before = {name: target(vendor, name).read_bytes() for name in edits}
    derived = {name: fn(before[name].decode()) for name, fn in edits.items()}
    previous = {}
    owner = target(vendor, OWNER)
    if owner.exists():
        if not owner.is_file() or owner.stat().st_size > 65536:
            raise ValueError('invalid ordered execution source owner')
        record = json.loads(owner.read_bytes())
        if not isinstance(record, dict) or set(record) != {'schema', 'core', 'files'} or record['schema'] != 1 or record['core'] != PIN or not isinstance(record['files'], dict) or set(record['files']) != set(TEMPLATES.values()):
            raise ValueError('invalid ordered execution source receipt')
        previous = record['files']
        for name, checksum in previous.items():
            if name not in TEMPLATES.values() or not isinstance(checksum, str) or len(checksum) != 64 or any(ch not in '0123456789abcdef' for ch in checksum):
                raise ValueError('ordered execution source owner widened')
            path = target(vendor, name)
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
                raise ValueError('ordered execution source changed outside its owner')
    templates = {name: (ROOT/'mobile/chain'/template).read_bytes() for template, name in TEMPLATES.items()}
    for name, raw in templates.items():
        path = target(vendor, name)
        if path.exists() and (not path.is_file() or name not in previous and path.read_bytes() != raw):
            raise ValueError('refusing unowned ordered execution source overwrite')
    if any(target(vendor, name).read_bytes() != raw for name, raw in before.items()):
        raise ValueError('ordered execution input changed during preparation')
    for name, raw in {**derived, **templates}.items():
        path = target(vendor, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    owner.write_text(json.dumps({'schema': 1, 'core': PIN, 'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in templates.items()}}, sort_keys=True, separators=(',', ':'))+'\n')
    print('Owned ordered execution admission source:', digest())


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
