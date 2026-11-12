#!/usr/bin/env python3
"""Strict source preparation and real native protocol component acceptance.

With --vendor, executes only protocol/routervpnchaingate under the race detector
and causal source controls. It never starts a TUN, native host, or PQ diagnostic.
The vendor must already have the original provider-strategy observation helpers.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'github.com/sagernet/sing-box/protocol/routervpnchaingate'


def load(path):
    spec = importlib.util.spec_from_file_location('execution_gate_preparer', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREP = load(ROOT/'deploy/prepare-node-chain-execution-gate.py')


def roots():
    source = (ROOT/'mobile/chain_gate/gate_test.go.tmpl').read_text()
    names = re.findall(r'^func (TestRouterVPNChainGate\w+)\(t \*testing.T\)', source, re.M)
    if not names or len(names) != len(set(names)):
        raise ValueError('ordered gate test inventory is missing or repeated')
    return set(names)


def verdict(raw, code, expected):
    if code != 0:
        raise ValueError('ordered application gate command failed')
    seen, passed, records = set(), set(), []
    package_pass = False
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError) as error:
            raise ValueError('non-JSON native component verdict') from error
        if not isinstance(event, dict) or event.get('Package') != PACKAGE:
            raise ValueError('foreign native component verdict')
        action, name = event.get('Action'), event.get('Test')
        if action in ('fail', 'skip') or 'DATA RACE' in event.get('Output', ''):
            raise ValueError('failed, skipped or racing native component')
        if package_pass:
            raise ValueError('native component event after final package PASS')
        if name:
            parent = name.split('/')[0]
            if parent not in expected:
                raise ValueError('unexpected native component test')
            if action == 'run':
                if name in seen or any(name == previous or name.startswith(previous+'/') for previous in passed):
                    raise ValueError('duplicate or late native component run')
                seen.add(name)
            elif action == 'pass':
                if name not in seen or name in passed or any(child.startswith(name+'/') and child not in passed for child in seen):
                    raise ValueError('missing run, duplicate PASS or incomplete child')
                passed.add(name)
                records.append(line)
            elif action not in ('output', 'pause', 'cont'):
                raise ValueError('unexpected named native component action')
        elif action == 'pass':
            if not expected.issubset(passed) or seen != passed:
                raise ValueError('missing original native component receipt')
            package_pass = True
        elif action not in ('start', 'output'):
            raise ValueError('unexpected native package action')
    if not package_pass or not expected.issubset(passed) or seen != passed:
        raise ValueError('incomplete native component verdict')
    return records


CONTROLS = (
    ('bounded terminal ledger lock', 'gate.go', 'if err := adapter.RouterVPNLockContext(ctx, &g.mu); err != nil {\n\t\treturn State{}, err\n\t}', 'g.mu.Lock()', 'ClosedLedgerKeepsCallerDeadline', 'closed ledger waited beyond original caller deadline'),
    ('terminal closed gate receipt', 'gate.go', ' || !g.closed || g.open || g.dials != 0 || len(g.flows) != 0 || g.draining != 0 {',
     ' || g.open || g.dials != 0 || len(g.flows) != 0 || g.draining != 0 {', 'ClosedLedgerRequiresTerminalOwner/revoked', 'nonterminal or foreign gate acquired closed receipt'),
    ('late terminal denied input', 'gate.go', ' || g.control != c || !g.closed || g.open || g.dials != 0 || len(g.flows) != 0 || g.draining != 0 {',
     ' || g.control != c || !g.closed || g.open || g.dials != 0 || g.draining != 0 {', 'ClosedLedgerRetainsLateDeniedClose', 'historical gate close hid a late unjoined input'),
    ('retired receipt cannot admit traffic', 'gate.go', 'if ctx.Err() != nil || g.open || g.dials != 0 || len(g.flows) != 0 || g.draining != 0 {', 'if ctx.Err() != nil || g.dials != 0 || len(g.flows) != 0 || g.draining != 0 {', 'RetiredReceiptKeepsOriginalCleanup/source', 'retirement receipt accepted open admission'),
    ('retired receipt requires joined original close', 'gate.go', 'if ctx.Err() != nil || g.open || g.dials != 0 || len(g.flows) != 0 || g.draining != 0 {', 'if ctx.Err() != nil || g.open || g.dials != 0 || g.draining != 0 {', 'RetiredReceiptRejectsUnjoinedClose', 'retirement receipt accepted unjoined original close'),
    ('copied control', 'gate.go', 'if g.control != c {', 'if false {', 'ClosedAndBoundOnce', 'copied control opened gate'),
    ('closed admission', 'gate.go', 'if ctx.Err() != nil || g.ctx.Err() != nil || !g.open || g.closed {', 'if ctx.Err() != nil || g.ctx.Err() != nil || g.closed {', 'ClosedAfterRevoke', 'closed gate reached downstream'),
    ('original selector pointer', 'gate.go', 'if !found || value != selector {', 'if !found {', 'OriginalPointersAndGuard/selector', 'replaced original owner still observed'),
    ('original gate pointer', 'gate.go', 'if !found || value != g {', 'if !found {', 'OriginalPointersAndGuard/gate', 'replaced original owner still observed'),
    ('original source guard', 'gate.go', 'if err := guard(ctx); err != nil {\n\t\treturn err\n\t}', 'if err := ctx.Err(); err != nil {\n\t\treturn err\n\t}', 'OriginalPointersAndGuard/guard', 'replaced original owner still observed'),
    ('post-dial original guard', 'gate.go', 'if dialErr == nil {\n\t\tdialErr = g.current(ctx)\n\t}', '', 'SourceChangesDuringDial', 'post-dial original guard was skipped'),
    ('failed original close', 'flow.go', 'if err == nil {\n\t\t\tdelete(g.flows, f)', 'if true {\n\t\t\tdelete(g.flows, f)', 'FailedCloseRetained', 'failed original close was discarded'),
    ('late original return', 'gate.go', '\tvar f *flow\n', '\tdialErr = nil // causal fault: publish a retired original\n\tvar f *flow\n', 'LateDialRetirement', 'late dial escaped original closed epoch'),
    ('native lifetime cancellation', 'gate.go', 'context.AfterFunc(ctx, func() { _ = g.Close() })', '', 'TerminalAndCancelledOwner/cancelled', 'native lifetime cancellation failed actual close'),
    ('closed revoke admission epoch', 'gate.go', '\tg.generation++\n\tif g.open {\n', '\tif g.open {\n', 'ClosedRevokeRetiresPendingOpen', 'closed revoke did not retire pending open'),
    ('post-guard bind pointer', 'gate.go', '\tif err := current(ctx); err != nil {\n\t\treturn nil, err\n\t}\n\tif err := g.nativeCurrent(ctx); err != nil {\n\t\treturn nil, err\n\t}', '\tif err := current(ctx); err != nil {\n\t\treturn nil, err\n\t}', 'BindRechecksOriginalSelector', 'bind accepted selector replaced during owner observation'),
    ('denied inbound release', 'gate.go', 'return denied, release, errors.Join(err, cleanupErr)', 'return denied, nil, errors.Join(err, cleanupErr, func() error { _ = release; return nil }())', 'DeniedInboundRetainsRelease/closed', 'denied input lost original cleanup handle'),
    ('late denied inbound release', 'gate.go', 'return native, f.Close, err', 'return native, nil, err', 'DeniedInboundRetainsRelease/post-guard', 'denied input lost original cleanup handle'),
    ('original dial cancellation', 'gate.go', '\t\tg.cancel()\n', '', 'RevokeCancelsOriginalDial', 'revoke did not cancel original native dial'),
)


def command(go, selected=None):
    result = [go, 'test', '-json', '-race', '-p=1', '-count=1', '-timeout=120s', './protocol/routervpnchaingate']
    if selected is not None:
        result.extend(['-run', '^TestRouterVPNChainGate' + selected.replace('/', '$/^') + '$'])
    return result


def execute(vendor, go):
    PREP.prepare(vendor)
    environment = dict(os.environ, GOMAXPROCS='1')
    run = subprocess.run(command(go), cwd=vendor, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    try:
        records = verdict(run.stdout, run.returncode, roots())
    except ValueError:
        print(run.stdout)
        raise
    for record in records:
        print(record)
    print(f'Actual native ordered gate: {len(roots())} roots, {len(records)} test PASS receipts; race detector enabled')
    for label, file, before, after, selected, witness in CONTROLS:
        target = vendor/'protocol/routervpnchaingate'/file
        original = target.read_bytes()
        source = original.decode()
        if source.count(before) != 1:
            raise ValueError('causal gate boundary changed: '+label)
        try:
            target.write_text(source.replace(before, after, 1))
            run = subprocess.run(command(go, selected), cwd=vendor, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
            events = []
            for line in run.stdout.splitlines():
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
            parent = 'TestRouterVPNChainGate'+selected.split('/')[0]
            reached = any(e.get('Action') == 'run' and e.get('Test') == parent for e in events)
            failed = any(e.get('Action') == 'fail' and e.get('Test') == parent for e in events)
            causal = any(e.get('Action') == 'output' and e.get('Test', '').startswith(parent) and witness in e.get('Output', '') for e in events)
            if run.returncode == 0 or not reached or not failed or not causal or any('DATA RACE' in e.get('Output', '') for e in events):
                print(run.stdout)
                raise ValueError('causal gate witness missing: '+label+' / '+witness)
            print('Causal native gate refusal PASS:', label, '/', witness)
        finally:
            target.write_bytes(original)
    PREP.prepare(vendor)  # exact restored source ownership, not mutant state


class Preparation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/'repo'
        self.vendor = Path(self.temp.name)/'core'
        for source in PREP.inputs():
            target = self.root/source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        self.prep = load(self.root/'deploy/prepare-node-chain-execution-gate.py')
        self.vendor.mkdir()
        for relative, template in self.prep.PREREQUISITES.items():
            target = self.vendor/relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((self.root/template).read_bytes())
        target = self.vendor/'include/registry.go'
        target.parent.mkdir()
        target.write_text('package include\nimport (\n\t"github.com/sagernet/sing-box/protocol/group"\n)\nfunc OutboundRegistry() *outbound.Registry {\n\tgroup.RegisterSelector(registry)\n\treturn registry\n}\n')
        self.pin = patch.object(self.prep.subprocess, 'check_output', return_value=self.prep.PIN+'\n')
        self.pin.start()
        self.addCleanup(self.pin.stop)

    def test_exact_idempotent_inventory(self):
        self.prep.prepare(self.vendor)
        before = {p.relative_to(self.vendor): p.read_bytes() for p in self.vendor.rglob('*') if p.is_file()}
        self.prep.prepare(self.vendor)
        self.assertEqual(before, {p.relative_to(self.vendor): p.read_bytes() for p in self.vendor.rglob('*') if p.is_file()})
        self.assertEqual(set(json.loads((self.vendor/self.prep.OWNER).read_bytes())['files']), set(self.prep.TEMPLATES.values()))

    def test_wrong_core(self):
        with patch.object(self.prep.subprocess, 'check_output', return_value='f'*40+'\n'), self.assertRaises(ValueError): self.prep.prepare(self.vendor)

    def test_original_observation_required(self):
        for relative in self.prep.PREREQUISITES:
            with self.subTest(relative=relative):
                path = self.vendor/relative; raw = path.read_bytes(); path.write_bytes(raw+b'\n// foreign\n')
                with self.assertRaises(ValueError): self.prep.prepare(self.vendor)
                path.write_bytes(raw)

    def test_changed_owned_source(self):
        self.prep.prepare(self.vendor)
        target = self.vendor/next(iter(self.prep.TEMPLATES.values()))
        target.write_text('package changed\n')
        with self.assertRaises(ValueError): self.prep.prepare(self.vendor)

    def test_foreign_source(self):
        target = self.vendor/next(iter(self.prep.TEMPLATES.values()))
        target.parent.mkdir(parents=True); target.write_text('package foreign\n')
        with self.assertRaises(ValueError): self.prep.prepare(self.vendor)

    def test_undeclared_source(self):
        self.prep.prepare(self.vendor)
        (self.vendor/'protocol/routervpnchaingate/foreign.go').write_text('package routervpnchaingate\n')
        with self.assertRaises(ValueError): self.prep.prepare(self.vendor)

    def test_symlink(self):
        (self.vendor/'protocol').mkdir()
        (self.vendor/'protocol/routervpnchaingate').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): self.prep.prepare(self.vendor)

    def test_registry_boundary(self):
        path = self.vendor/'include/registry.go'
        source = path.read_text()
        for broken in (source.replace('group.RegisterSelector', 'group.Foreign'), source+self.prep.REGISTER, source+self.prep.IMPORT, source.replace('func OutboundRegistry()', 'func InboundRegistry()')):
            with self.subTest(broken=broken):
                path.write_text(broken)
                with self.assertRaises(ValueError): self.prep.prepare(self.vendor)
        path.write_text(source)

    def test_incomplete_owner_inventory(self):
        self.prep.prepare(self.vendor)
        path = self.vendor/self.prep.OWNER
        record = json.loads(path.read_bytes()); record['files'].pop(next(iter(record['files'])))
        path.write_text(json.dumps(record))
        with self.assertRaises(ValueError): self.prep.prepare(self.vendor)

    def test_current_template_update_requires_original_output(self):
        self.prep.prepare(self.vendor)
        source = self.root/'mobile/chain_gate/gate.go.tmpl'
        source.write_bytes(source.read_bytes()+b'\n// legitimate source revision\n')
        self.prep.prepare(self.vendor)
        self.assertEqual(source.read_bytes(), (self.vendor/'protocol/routervpnchaingate/gate.go').read_bytes())


def stream(events):
    return '\n'.join(json.dumps(dict(Package=PACKAGE, **e)) for e in events)


class Verdict(unittest.TestCase):
    def setUp(self):
        self.events = [dict(Action='start'), dict(Action='run', Test='TestA'), dict(Action='run', Test='TestA/leaf'), dict(Action='pass', Test='TestA/leaf'), dict(Action='pass', Test='TestA'), dict(Action='pass')]

    def test_real_receipt_projection(self):
        self.assertEqual(len(verdict(stream(self.events), 0, {'TestA'})), 2)

    def test_missing_skipped_failed_race_and_nonzero(self):
        for action in ('skip', 'fail'):
            with self.subTest(action=action):
                events = [dict(e) for e in self.events]; events[3]['Action'] = action
                with self.assertRaises(ValueError): verdict(stream(events), 0, {'TestA'})
        for events, code, expected in ((self.events, 1, {'TestA'}), (self.events, 0, {'TestA','TestMissing'}), (self.events[:-1], 0, {'TestA'}), (self.events[:2]+[dict(Action='output',Output='WARNING: DATA RACE')]+self.events[2:],0,{'TestA'})):
            with self.subTest(events=events, code=code, expected=expected), self.assertRaises(ValueError): verdict(stream(events),code,expected)

    def test_duplicate_foreign_late_and_unrun_pass(self):
        streams = [self.events[:3]+[self.events[2]]+self.events[3:], self.events[:4]+[self.events[3]]+self.events[4:], [self.events[0], self.events[1], self.events[4], *self.events[2:4], self.events[5]], [self.events[0], *self.events[3:]], self.events+[dict(Action='output',Output='late')]]
        for events in streams:
            with self.subTest(events=events), self.assertRaises(ValueError): verdict(stream(events),0,{'TestA'})
        with self.assertRaises(ValueError): verdict(stream(self.events).replace(PACKAGE,'foreign'),0,{'TestA'})

    def test_retains_actual_race_and_complete_package(self):
        args = command('go')
        self.assertIn('-race',args); self.assertIn('-timeout=120s',args); self.assertNotIn('-run',args)
        self.assertEqual(args[-1], './protocol/routervpnchaingate')
        self.assertEqual(len(CONTROLS),19)
        self.assertTrue(all(control[-1] for control in CONTROLS))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(Preparation), unittest.defaultTestLoader.loadTestsFromTestCase(Verdict)])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    if args.vendor:
        execute(args.vendor.resolve(), args.go)
