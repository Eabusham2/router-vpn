#!/usr/bin/env python3
"""Owned native Router/TUN DNS admission and selector-epoch component tests.

--vendor executes ordinary race tests in three pinned native packages. It does
not start a TUN, privileged host, system route, or native PQ diagnostic.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREP = load('execution_preparer_tests', 'deploy/prepare-node-chain-execution.py')
POLICY = load('execution_original_selector_tests', 'deploy/prepare-mobile-external-policy.py')
GATE = load('execution_gate_verdict_tests', 'deploy/test_node_chain_execution_gate.py')
PACKAGES = {
    'protocol/group': 'execution_selector_test.go.tmpl',
    'route': 'execution_ingress_test.go.tmpl',
    'protocol/tun': 'execution_tun_test.go.tmpl',
}


def inventory():
    result = {}
    for package, template in PACKAGES.items():
        names = re.findall(r'^func (TestRouterVPNExecution\w+)\(t \*testing.T\)', (ROOT/'mobile/chain'/template).read_text(), re.M)
        if not names or len(names) != len(set(names)):
            raise ValueError('invalid ordered execution native test inventory')
        result['github.com/sagernet/sing-box/'+package] = set(names)
    return result


def verdict(raw, code, expected):
    if code != 0:
        raise ValueError('native execution helper command failed')
    grouped = {package: [] for package in expected}
    for line in raw.splitlines():
        event = json.loads(line)
        if not isinstance(event, dict) or event.get('Package') not in grouped:
            raise ValueError('foreign native execution package')
        grouped[event['Package']].append(line)
    previous = GATE.PACKAGE
    records = []
    try:
        for package, names in expected.items():
            GATE.PACKAGE = package
            records.extend(GATE.verdict('\n'.join(grouped[package]), code, names))
    finally:
        GATE.PACKAGE = previous
    return records


CONTROLS = (
    ('selected pointer epoch', 'protocol/group/selector.go', '\ts.routerVPNNodeChainEpoch.Add(1)\n\ts.selected.Swap(detour)\n\ts.routerVPNNodeChainEpoch.Add(1)\n', '\ts.selected.Swap(detour)\n', 'protocol/group', 'TestRouterVPNExecutionSelectorEpochAndCallbacks', 'actual native swap did not advance epoch', 1),
    ('transition readback', 'protocol/group/routervpn_node_chain_execution.go', 'if epoch == 0 || epoch&1 != 0 {', 'if epoch == 0 {', 'protocol/group', 'TestRouterVPNExecutionSelectorEpochAndCallbacks', 'partially published selection was observable', 1),
    ('initial local epoch', 'protocol/group/routervpn_node_chain_execution.go', '\ts.routerVPNNodeChainEpoch.Add(1)\n', '', 'protocol/group', 'TestRouterVPNExecutionSelectorAdmission/local', 'initial selected epoch missing', 2),
    ('original config readback', 'protocol/group/routervpn_node_chain_execution.go', 'owned.config != config', 'false', 'protocol/group', 'TestRouterVPNExecutionSelectorReadbackRetainsCapture/config', 'native selector readback accepted substituted capture', 1),
    ('untracked DNS callback', 'route/routervpn_node_chain_ingress.go', 'if r.routerVPNNodeChainGated {\n\t\treturn\n\t}', '', 'route', 'TestRouterVPNExecutionIngressRejectsFastDNSButKeepsProof/closed', 'untracked DNS fast callback reached original resolver', 1),
    ('TUN address shortcut', 'protocol/tun/inbound.go', '\tif gated, ok := t.router.(interface{ RouterVPNNodeChainGated() bool }); ok && gated.RouterVPNNodeChainGated() {\n\t\treturn adapter.JudgeFlow(t.router, t.tag, C.TypeTun, network, source, destination, firstPacket)\n\t}\n', '', 'protocol/tun', 'TestRouterVPNExecutionTUNDNSAddressCannotBypass/pending', 'native TUN DNS shortcut bypassed original tracked admission', 1),
    ('PreMatch pending refusal', 'route/routervpn_node_chain_ingress.go', 'return adapter.PreMatchResult{Action: adapter.PreMatchDrop}', 'return adapter.PreMatchResult{Action: adapter.PreMatchContinue}', 'route', 'TestRouterVPNExecutionIngressDefaultDeny/tcp/direct', 'pending PreMatch bypassed owned dispatch', 1),
    ('original inbound pointer', 'route/routervpn_node_chain_ingress.go', 'inbounds[0] != o.inbound', 'false', 'route', 'TestRouterVPNExecutionIngressCurrentRetainsNativePointers/inbound', 'native ingress pointer replacement accepted', 1),
    ('early failed-close retention', 'route/routervpn_node_chain_ingress.go', 'release, err := gate.RetireInbound(raw)', 'release := raw.Close\n\tvar err error', 'route', 'TestRouterVPNExecutionIngressRetainsFailedEarlyClose/tcp', 'failed early input close lost original gate receipt', 1),
    ('constructor default-deny', 'route/router.go', 'routerVPNNodeChainGated: options.Final == routerVPNNodeChainApplicationTag,', 'routerVPNNodeChainGated: false,', 'protocol/tun', 'TestRouterVPNExecutionTUNDNSAddressCannotBypass/pending', 'native TUN DNS shortcut bypassed original tracked admission', 1),
    ('pre-DNS Router dispatch', 'route/routervpn_node_chain_ingress.go', 'owned, release, err := r.routerVPNTrackIngress(ctx, conn, metadata)', 'owned, release, err := ctx, (func() error)(nil), error(nil)', 'route', 'TestRouterVPNExecutionIngressAdmissionPrecedesDNSRead', 'closed DNS read before original admission', 4),
)


def command(go, package=None, selected=None):
    result = [go, 'test', '-json', '-race', '-p=1', '-count=1', '-timeout=120s']
    result += ['./'+package] if package else ['./'+name for name in PACKAGES]
    result += ['-run', '^'+selected.replace('/', '$/^')+'$' if selected else '^TestRouterVPNExecution']
    return result


def execute(vendor, go):
    PREP.prepare(vendor)
    POLICY.check_selection_sources(vendor)
    environment = dict(os.environ, GOMAXPROCS='1')
    result = subprocess.run(command(go), cwd=vendor, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    expected = inventory()
    try:
        records = verdict(result.stdout, result.returncode, expected)
    except (ValueError, TypeError):
        print(result.stdout)
        raise
    for line in records:
        print(line)
    print('Actual ordered execution helpers:', sum(map(len, expected.values())), 'roots,', len(records), 'PASS receipts, all three native packages under race')
    for label, relative, before, after, package, selected, witness, count in CONTROLS:
        target = vendor/relative
        original = target.read_bytes()
        source = original.decode()
        if source.count(before) != count:
            raise ValueError('ordered execution causal boundary changed: '+label)
        try:
            target.write_text(source.replace(before, after))
            result = subprocess.run(command(go, package, selected), cwd=vendor, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
            events = []
            for line in result.stdout.splitlines():
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
            parent = selected.split('/')[0]
            reached = any(e.get('Action') == 'run' and e.get('Test') == parent for e in events)
            failed = any(e.get('Action') == 'fail' and e.get('Test') == parent for e in events)
            causal = any(e.get('Action') == 'output' and e.get('Test', '').startswith(parent) and witness in e.get('Output', '') for e in events)
            if result.returncode == 0 or not reached or not failed or not causal or any('DATA RACE' in e.get('Output', '') for e in events):
                print(result.stdout)
                raise ValueError('ordered execution causal witness missing: '+label+' / '+witness)
            print('Causal ordered execution refusal PASS:', label, '/', witness)
        finally:
            target.write_bytes(original)
    PREP.verify_current_templates(vendor)
    POLICY.check_selection_sources(vendor)


# These are explicit source-shape fixtures, not a compiled/native substitute.
# Native acceptance above reads the actual pinned Git sources and managers.
ROUTER = 'package route\nimport (\n\t"context"\n)\ntype Router struct {\n}\nfunc NewRouter() {\n\treturn &Router{\n\t}\n}\nfunc Start() {\n\tcase adapter.StartStateInitialize:\n}\n'
ROUTES = '\n'.join('func (r *Router) '+name+'() {}' for name in ('RouteConnection','RouteConnectionEx','RoutePacketConnection','RoutePacketConnectionEx','PreMatch'))+'\n'
DNS = 'func (r *Router) HijackDNSPacket() {}\n'
TUN = 'func (t *Inbound) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {\n\treturn oldShortcut\n}\n'
SELECTOR = 'package group\nimport (\n\t"sync"\n)\ntype Selector struct {\n}\nfunc (s *Selector) All() []string {\n\treturn s.tags\n}\nfunc (s *Selector) routerVPNSelectOutboundLocked(tag string, interrupt, notify func()) bool {\n\tif s.selected.Swap(detour) == detour {\n\t\treturn true\n\t}\n\tcache()\n\tinterrupt()\n\tnotify()\n}\n'
SOURCES = {'route/router.go':ROUTER,'route/route.go':ROUTES,'route/dns.go':DNS,'protocol/tun/inbound.go':TUN,'protocol/group/selector.go':SELECTOR}


class Preparation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.vendor = Path(self.temp.name)/'core'; self.vendor.mkdir()
        (self.vendor/'go.mod').write_text('module github.com/sagernet/sing-box\n')
        for relative, text in SOURCES.items():
            path = self.vendor/relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
        self.pin = patch.object(PREP.subprocess,'check_output',return_value=PREP.PIN+'\n'); self.pin.start(); self.addCleanup(self.pin.stop)
        self.original = patch.object(PREP,'check_original_selection',side_effect=lambda vendor: POLICY.check_selection_sources(vendor,preparing=True)); self.original.start(); self.addCleanup(self.original.stop)
        self.selection = patch.object(POLICY,'selection_sources',return_value={'protocol/group/selector.go':(SELECTOR.encode(),SELECTOR.encode())}); self.selection.start(); self.addCleanup(self.selection.stop)

    def test_complete_idempotent_owned_composition(self):
        PREP.prepare(self.vendor)
        before={p.relative_to(self.vendor):p.read_bytes() for p in self.vendor.rglob('*') if p.is_file()}
        PREP.prepare(self.vendor);POLICY.check_selection_sources(self.vendor);PREP.verify_current_templates(self.vendor)
        self.assertEqual(before,{p.relative_to(self.vendor):p.read_bytes() for p in self.vendor.rglob('*') if p.is_file()})
        self.assertEqual(set(json.loads((self.vendor/PREP.OWNER).read_bytes())['files']),set(PREP.TEMPLATES.values()))

    def test_original_baseline_retained_before_owned_extension(self):
        POLICY.check_selection_sources(self.vendor)
        self.assertEqual(POLICY.composed_selection_source(self.vendor,'protocol/group/selector.go',SELECTOR.encode()),SELECTOR.encode())

    def test_unknown_selector_edit_refused_before_publication(self):
        path=self.vendor/'protocol/group/selector.go';path.write_text(SELECTOR+'\n// unknown native change\n')
        with self.assertRaisesRegex(ValueError,'changed native selection commit'):PREP.prepare(self.vendor)
        self.assertFalse((self.vendor/PREP.OWNER).exists())

    def test_composed_selector_unknown_or_missing_extension_refused(self):
        PREP.prepare(self.vendor);path=self.vendor/'protocol/group/selector.go';original=path.read_bytes()
        for raw in (SELECTOR.encode(),original+b'\n// foreign\n',original.replace(b's.routerVPNNodeChainEpoch.Add(1)',b'foreignEpoch()',1)):
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                with self.assertRaisesRegex(ValueError,'changed native selection commit'):POLICY.check_selection_sources(self.vendor)
        path.write_bytes(original)

    def test_modified_helper_cannot_authorize_composed_selector(self):
        PREP.prepare(self.vendor)
        path=self.vendor/PREP.TEMPLATES['execution_selector.go.tmpl'];path.write_bytes(path.read_bytes()+b'\n// foreign\n')
        with self.assertRaises(ValueError):POLICY.check_selection_sources(self.vendor)

    def test_full_owner_inventory_required(self):
        PREP.prepare(self.vendor);path=self.vendor/PREP.OWNER;record=json.loads(path.read_bytes());record['files'].pop(next(iter(record['files'])));path.write_text(json.dumps(record))
        with self.assertRaises(ValueError):PREP.prepare(self.vendor)
        with self.assertRaises(ValueError):POLICY.check_selection_sources(self.vendor)

    def test_symlink_root_and_target(self):
        linked=Path(self.temp.name)/'link';linked.symlink_to(self.vendor,target_is_directory=True)
        with self.assertRaises(ValueError):PREP.prepare(linked)
        path=self.vendor/'route/router.go';path.unlink();path.symlink_to(self.vendor/'go.mod')
        with self.assertRaises(ValueError):PREP.prepare(self.vendor)

    def test_wrong_core_and_module(self):
        with patch.object(PREP.subprocess,'check_output',return_value='0'*40+'\n'),self.assertRaises(ValueError):PREP.prepare(self.vendor)
        (self.vendor/'go.mod').write_text('module foreign\n')
        with self.assertRaises(ValueError):PREP.prepare(self.vendor)

    def test_strict_transforms_keep_original_callback_order(self):
        for source,transform in ((ROUTER,PREP.router_source),(ROUTES,PREP.route_source),(DNS,PREP.dns_source),(TUN,PREP.tun_source),(SELECTOR,PREP.selector_source)):
            with self.subTest(transform=transform.__name__):
                result=transform(source).decode();self.assertEqual(transform(result),result.encode())
        result=PREP.selector_source(SELECTOR).decode()
        self.assertIn('\tcache()\n\tinterrupt()\n\tnotify()\n',result)
        self.assertEqual(result.count('s.selected.Swap(detour)'),1)
        self.assertEqual(result.count('s.routerVPNNodeChainEpoch.Add(1)'),2)

    def test_partial_native_transforms_refused(self):
        for source,transform in ((ROUTER.replace('type Router struct {\n','type Router struct {\n\trouterVPNNodeChainGated bool\n'),PREP.router_source),(SELECTOR.replace('type Selector struct {\n','type Selector struct {\n\trouterVPNNodeChainEpoch atomic.Uint64\n'),PREP.selector_source),(TUN+'\n// RouterVPNNodeChainGated()\n',PREP.tun_source)):
            with self.subTest(transform=transform.__name__),self.assertRaises(ValueError):transform(source)

    def test_input_closure_includes_gate_and_all_helpers(self):
        values=set(POLICY.inputs())
        self.assertIn(ROOT/'deploy/prepare-node-chain-execution.py',values)
        self.assertIn(ROOT/'deploy/prepare-node-chain-execution-gate.py',values)
        self.assertIn(ROOT/'mobile/chain_gate/gate.go.tmpl',values)
        self.assertTrue({ROOT/'mobile/chain'/name for name in PREP.TEMPLATES}.issubset(values))


class Receipts(unittest.TestCase):
    def test_all_three_packages_required(self):
        expected={'one':{'TestA'},'two':{'TestB'},'three':{'TestC'}}
        events=[]
        for package,names in expected.items():
            name=next(iter(names));events.extend([{'Package':package,'Action':'start'},{'Package':package,'Action':'run','Test':name},{'Package':package,'Action':'pass','Test':name},{'Package':package,'Action':'pass'}])
        raw='\n'.join(json.dumps(event) for event in events)
        self.assertEqual(len(verdict(raw,0,expected)),3)
        for changed,code in ((events[:-1],0),(events[:-4],0),(events,1),(events+[{'Package':'foreign','Action':'pass'}],0)):
            with self.subTest(changed=changed,code=code),self.assertRaises(ValueError):verdict('\n'.join(json.dumps(event) for event in changed),code,expected)

    def test_failure_skip_race_duplicate_and_absent_receipts(self):
        expected={'one':{'TestA'}}
        for events in ([{'Package':'one','Action':'skip'}],[{'Package':'one','Action':'fail'}],[{'Package':'one','Action':'output','Output':'WARNING: DATA RACE'}],[{'Package':'one','Action':'run','Test':'TestA'}]*2,[{'Package':'one','Action':'pass'}]):
            with self.subTest(events=events),self.assertRaises(ValueError):verdict('\n'.join(json.dumps(e) for e in events),0,expected)

    def test_complete_native_command_and_causal_inventory(self):
        args=command('go');self.assertIn('-race',args);self.assertIn('-timeout=120s',args)
        self.assertTrue({'./route','./protocol/group','./protocol/tun'}.issubset(args))
        self.assertEqual(args[-1],'^TestRouterVPNExecution')
        self.assertEqual(len(inventory()),3);self.assertEqual(len(CONTROLS),11)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--vendor',type=Path);parser.add_argument('--go',default='go');args=parser.parse_args()
    suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(Preparation),unittest.defaultTestLoader.loadTestsFromTestCase(Receipts)])
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():raise SystemExit(1)
    if args.vendor:execute(args.vendor.resolve(),args.go)
