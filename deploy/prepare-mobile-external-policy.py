#!/usr/bin/env python3
"""Bind external DNS/entry/exit proofs to the exact pinned native Box."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
_graphs_spec = importlib.util.spec_from_file_location('routervpn_external_graphs', ROOT/'deploy/test_mobile_external_graphs.py')
GRAPHS = importlib.util.module_from_spec(_graphs_spec)
_graphs_spec.loader.exec_module(GRAPHS)

SELECTION_REPLACEMENTS = {
    'protocol/group/selector.go': (
        ('\t"net"\n', '\t"net"\n\t"sync"\n'),
        ('\ttags                         []string\n', '\trouterVPNSelectionAccess     sync.Mutex\n\ttags                         []string\n'),
        ('func (s *Selector) SelectOutbound(tag string) bool {\n',
         'func (s *Selector) SelectOutbound(tag string) bool {\n'
         '\ts.routerVPNSelectionAccess.Lock()\n\tdefer s.routerVPNSelectionAccess.Unlock()\n'
         '\treturn s.routerVPNSelectOutboundLocked(tag, func() { s.interruptGroup.Interrupt(s.interruptExternalConnections) }, func() {\n'
         '\t\tif s.history != nil { s.history.NotifyUpdated() }\n\t})\n}\n\n'
         'func (s *Selector) routerVPNSelectOutboundLocked(tag string, interrupt, notify func()) bool {\n'),
        ('\ts.interruptGroup.Interrupt(s.interruptExternalConnections)\n\tif s.history != nil {\n\t\ts.history.NotifyUpdated()\n\t}\n',
         '\tinterrupt()\n\tnotify()\n'),
    ),
    'common/interrupt/group.go': (
        ('\tvar toDelete []*list.Element[*groupConnItem]\n',
         '\tg.routerVPNInterruptLocked(interruptExternalConnections)\n}\n\n'
         'func (g *Group) routerVPNInterruptLocked(interruptExternalConnections bool) {\n'
         '\tvar toDelete []*list.Element[*groupConnItem]\n'),
    ),
}

def selection_sources(vendor):
    """Exact pinned sources and their complete owned selector transforms."""
    values = {}
    for relative, replacements in SELECTION_REPLACEMENTS.items():
        original = subprocess.check_output(['git', '-C', str(vendor), 'show', PIN+':'+relative])
        source = original.decode()
        for before, after in replacements:
            if source.count(before) != 1: raise ValueError('pinned native selection boundary changed: ' + relative)
            source = source.replace(before, after, 1)
        values[relative] = (original, source.encode())
    return values

def check_selection_sources(vendor, *, preparing=False):
    for relative, (_, expected) in selection_sources(vendor).items():
        expected = composed_selection_source(vendor, relative, expected, current=not preparing)
        path = vendor / relative
        if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
            raise ValueError('changed native selection commit: ' + relative)

def execution_preparer():
    spec = importlib.util.spec_from_file_location('routervpn_execution_selector_owner', ROOT/'deploy/prepare-node-chain-execution.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def composed_selection_source(vendor, relative, expected, *, current=True):
    if relative != 'protocol/group/selector.go':
        return expected
    execution = execution_preparer()
    owner = execution.target(vendor.resolve(), execution.OWNER)
    if owner.exists():
        # Only the complete current owned extension may coexist with this
        # exact original commit. Never strip unknown lines to make an audit pass.
        execution.verify_owned_templates(vendor.resolve(), current=current)
        return execution.selector_source(expected.decode())
    return expected


def inputs():
    return list(dict.fromkeys([Path(__file__).resolve(), ROOT/'deploy/test_mobile_external_pinned.sh'] + sorted((ROOT/'mobile/externalpolicy').glob('*.tmpl')) + GRAPHS.inputs() + execution_preparer().inputs()))

def digest():
    value=hashlib.sha256()
    for source in inputs():
        value.update(str(source.relative_to(ROOT)).encode()+b'\0'+source.read_bytes())
    return value.hexdigest()

def prepare(vendor, *, mobile=True):
    vendor=vendor.resolve()
    if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=PIN:
        raise ValueError('external proof requires the exact pinned native core')
    path=vendor/'box.go'
    if path.is_symlink():raise ValueError('linked native external policy boundary')
    source=path.read_text()
    box_return = '\treturn &Box{\n'
    if 'routerVPNNodeSOCKSBind' in source:
        box_return = '\treturn routerVPNNodeSOCKSBind(&Box{\n'
        if source.count(box_return) != 1 or source.count('routerVPNNodeSOCKSBind') != 1:
            raise ValueError('native external configuration has a foreign acquired Box binding')
    for before,after in (
        ('type Box struct {\n','type Box struct {\n\trouterVPNExternalOptions string\n'),
        ('func New(options Options) (*Box, error) {\n','func New(options Options) (*Box, error) {\n\texternalOptionsDigest := routerVPNExternalOptionsDigest(options.Context, options.Options)\n'),
        (box_return, box_return+'\t\trouterVPNExternalOptions: externalOptionsDigest,\n'),
        ('\trouterVPNExternalOptions string\n', '\trouterVPNExternalOptions string\n\trouterVPNTorOptions string\n'),
        ('\texternalOptionsDigest := routerVPNExternalOptionsDigest(options.Context, options.Options)\n', '\texternalOptionsDigest := routerVPNExternalOptionsDigest(options.Context, options.Options)\n\ttorOptionsSnapshot := routerVPNTorOptionsSnapshot(options.Context, options.Options)\n'),
        ('\t\trouterVPNExternalOptions: externalOptionsDigest,\n', '\t\trouterVPNExternalOptions: externalOptionsDigest,\n\t\trouterVPNTorOptions: torOptionsSnapshot,\n'),
    ):
        if after in source:continue
        if source.count(before)!=1:raise ValueError('native external configuration capture boundary changed')
        source=source.replace(before,after,1)
    path.write_text(source)
    # Both preparation and execution prove the full pinned commit body. A
    # partial or foreign patch cannot erase cache/interrupt/history semantics.
    for relative, (original, expected) in selection_sources(vendor).items():
        path = vendor / relative
        composed = composed_selection_source(vendor, relative, expected, current=False)
        accepted = (original, expected) if composed == expected else (composed,)
        if path.is_symlink() or path.read_bytes() not in accepted:
            raise ValueError('changed native selection commit: ' + relative)
        path.write_bytes(composed)
    for name, relative in {
        'selector_context.go': 'protocol/group/routervpn_selector_context.go',
        'interrupt_context.go': 'common/interrupt/routervpn_selector_context.go',
        'history_context.go': 'common/urltest/routervpn_selector_context.go',
        'selection_context_test.go': 'routervpn_external_selection_context_test.go',
    }.items():
        path = vendor / relative
        if path.is_symlink(): raise ValueError('linked native selection context')
        path.write_bytes((ROOT/'mobile/externalpolicy'/(name+'.tmpl')).read_bytes())
    (vendor/'routervpn_external_observation_test.go').write_bytes((ROOT/'mobile/externalpolicy/observation_test.go.tmpl').read_bytes())
    for name in ('box.go','box_test.go'):
        template=ROOT/'mobile/externalpolicy'/(name+'.tmpl')
        (vendor/('routervpn_external_policy'+('_test' if name.endswith('_test.go') else '')+'.go')).write_bytes(template.read_bytes())
    if mobile:
        (vendor/'routervpn_tor_comparison_capture.go').write_bytes((ROOT/'mobile/externalpolicy/tor_comparison.go.tmpl').read_bytes())
        (vendor/'routervpn_tor_comparison_capture_test.go').write_bytes((ROOT/'mobile/externalpolicy/tor_comparison_test.go.tmpl').read_bytes())
        (vendor/'routervpn_tor_server_test.go').write_bytes((ROOT/'mobile/externalpolicy/tor_server_test.go.tmpl').read_bytes())
        (vendor/'routervpn_tor_padding_capture_test.go').write_bytes((ROOT/'mobile/externalpolicy/tor_padding_test.go.tmpl').read_bytes())
        for name in ('external', 'external_test', 'tor', 'tor_test'):
            (vendor/'experimental/libbox'/('routervpn_mtu_'+name+'.go')).write_bytes((ROOT/'mobile/mtu'/(name+'.go.tmpl')).read_bytes())
        (vendor/'experimental/libbox/routervpn_external_policy_bridge_test.go').write_bytes((ROOT/'mobile/externalpolicy/bridge_test.go.tmpl').read_bytes())
        (vendor/'experimental/libbox/routervpn_external_policy_graph_test.go').write_bytes((ROOT/'mobile/externalpolicy/graph_test.go.tmpl').read_bytes())
    for source, target in (
        ('lease_cleanup.go', 'routervpn_external_lease_cleanup.go'),
        ('lease_cleanup_test.go', 'routervpn_external_lease_cleanup_test.go'),
        ('measurement.go', 'routervpn_external_measurement.go'),
        ('measurement_test.go', 'routervpn_external_measurement_test.go'),
        ('tor_measurement.go', 'routervpn_tor_measurement.go'),
        ('dns_measurement.go', 'routervpn_dns_measurement.go'),
        ('dns_measurement_test.go', 'routervpn_dns_measurement_test.go'),
        ('dns_dial.go', 'routervpn_dns_dial.go'),
        ('dns_dial_test.go', 'routervpn_dns_dial_test.go'),
        ('mtu.go', 'routervpn_external_mtu.go'),
        ('mtu_test.go', 'routervpn_external_mtu_test.go'),
        ('openvpn_remote_test.go', 'routervpn_external_openvpn_remote_test.go'),
        ('openvpn_bridge_test.go', 'routervpn_external_openvpn_bridge_test.go'),
        ('tor_mtu.go', 'routervpn_tor_mtu.go'),
        ('tor_padding.go', 'routervpn_tor_padding_capture.go'),
        ('tor_mtu_test.go', 'routervpn_tor_mtu_test.go'),
    ):
        (vendor/target).write_bytes((ROOT/'mobile/externalpolicy'/(source+'.tmpl')).read_bytes())
    fixture = vendor/'testdata/routervpn-external-openvpn-mapped.json'
    if fixture.is_symlink() or fixture.parent.is_symlink():
        raise ValueError('linked native OpenVPN test capture')
    fixture.parent.mkdir(exist_ok=True)
    fixture.write_bytes((ROOT/'deploy/fixtures/external-openvpn-multihost-client.json').read_bytes())

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor',type=Path,nargs='?')
    parser.add_argument('--digest',action='store_true')
    args=parser.parse_args()
    if args.digest:print(digest())
    elif args.vendor:prepare(args.vendor)
    else:parser.error('vendor or --digest required')
