#!/usr/bin/env python3
"""Execute the original command retry coordinator and guarded source projection.

The Go cases use explicit modeled native callbacks, real contexts and joined
goroutines. They do not claim privileged TUN/netlink or packaged acceptance.
"""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('command_retirement_projection', ROOT/'deploy/prepare-desktop-command-retirement.py')
PROJECTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROJECTION)
CASES = (
    'TestRouterVPNCommandRetirementLegacyAttemptKeepsOriginalBudget',
    *('TestRouterVPNCommandRetirementLegacyAttemptKeepsOriginalBudget/'+name for name in (
        'settled-retry', 'cancelled-owner', 'unbounded-owner', 'expired-owner')),
    'TestRouterVPNCommandRetirementRejectsUnboundedAndCancelledRequests',
    'TestRouterVPNCommandRetirementJoinsOriginalLateCallback',
    'TestRouterVPNCommandRetirementRejectsSuccessAfterCancellation',
    'TestRouterVPNCommandRetirementRequiresExplicitRetry',
    'TestRouterVPNCommandRetirementShutdownDominatesReload',
    'TestRouterVPNCommandRetirementInvalidRequestCannotEnterOwner',
    'TestRouterVPNCommandRetirementShutdownDominatesReload/hangup',
    'TestRouterVPNCommandRetirementShutdownDominatesReload/interrupt',
    'TestRouterVPNCommandRetirementShutdownDominatesReload/terminated',
)
NATIVE_CASES = (
    'TestRouterVPNRawCommandOriginalStartupDeadline',
    *('TestRouterVPNRawCommandOriginalStartupDeadline/'+name for name in (
        'cli-bound', 'shorter-caller', 'expired')),
    'TestRouterVPNRawCommandNativeStartupAndRetirement',
    'TestRouterVPNRawCommandNativePartialConstructionRetirement',
    'TestRouterVPNRawCommandNativePartialDependenciesRetention',
    'TestRouterVPNRawCommandNativePartialDependenciesRetention/external',
    'TestRouterVPNRawCommandNativePartialDependenciesRetention/tor',
    'TestRouterVPNRawCommandOptionsRetirementScope',
    'TestRouterVPNRawCommandNativePartialConstructionRetirement/missing-certificate',
    'TestRouterVPNRawCommandNativePartialConstructionRetirement/invalid-key-pair',
    *('TestRouterVPNRawCommandOptionsRetirementScope/'+name for name in (
        'empty', 'ordinary-mixed', 'tun-default', 'tun-system-stack', 'tun-gvisor-stack', 'tun-mixed-stack',
        'whole-process-namespace-config', 'tun-missing-options', 'tun-wrong-options', 'tun-typed-nil',
        'tun-per-inbound-netns', 'tun-auto-redirect', 'tun-platform', 'bridge-outbound',
        'wireguard-userspace', 'wireguard-system', 'wireguard-typed-nil', 'wireguard-wrong-options',
        'openvpn-client-userspace', 'openvpn-client-system', 'openvpn-client-typed-nil', 'openvpn-client-wrong-options',
        'openvpn-server-userspace', 'openvpn-server-system', 'openvpn-server-typed-nil', 'openvpn-server-wrong-options',
        'openconnect-userspace', 'openconnect-system', 'openconnect-typed-nil', 'openconnect-wrong-options',
        'tailscale-userspace', 'tailscale-system', 'tailscale-typed-nil', 'tailscale-wrong-options',
    )),
)


class CommandProjectionTests(unittest.TestCase):
    def test_dispatch_is_exact_and_idempotent(self):
        original = b'package main\nfunc run() error {\n\treturn nil\n}\n'
        expected = original.replace(PROJECTION.ANCHOR, PROJECTION.DISPATCH, 1)
        self.assertEqual(PROJECTION.run_dispatch(original), expected)
        self.assertEqual(PROJECTION.run_dispatch(expected), expected)

    def test_duplicate_or_partial_entry_is_refused(self):
        for invalid in (b'package main\n', PROJECTION.ANCHOR*2,
                        PROJECTION.ANCHOR+b'routerVPNRunOwnedCommand()',
                        PROJECTION.DISPATCH+b'routerVPNRunOwnedCommand()'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                PROJECTION.run_dispatch(invalid)

    def test_linked_destination_does_not_touch_foreign_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            foreign = root/'foreign'
            foreign.write_text('untouched')
            vendor = root/'vendor'
            (vendor/'cmd/sing-box').mkdir(parents=True)
            (vendor/'cmd/sing-box/cmd_run.go').symlink_to(foreign)
            with self.assertRaises(ValueError):
                PROJECTION.prepare(vendor)
            self.assertEqual(foreign.read_text(), 'untouched')

    def test_complete_projection_retains_non_linux_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            vendor = Path(directory)
            (vendor/'cmd/sing-box').mkdir(parents=True)
            source = vendor/'cmd/sing-box/cmd_run.go'
            original = b'package main\nfunc run() error {\n\treturn nil\n}\n'
            source.write_bytes(original)
            PROJECTION.prepare(vendor)
            first = {p.name: p.read_bytes() for p in (vendor/'cmd/sing-box').glob('*.go')}
            PROJECTION.prepare(vendor)
            self.assertEqual(first, {p.name: p.read_bytes() for p in (vendor/'cmd/sing-box').glob('*.go')})
            self.assertEqual(set(first), {'cmd_run.go', *(('routervpn_'+name.removesuffix('.tmpl')) for name in PROJECTION.TEMPLATES)})
            self.assertIn(b'//go:build !linux', first['routervpn_command_run_other.go'])
            self.assertIn(b'return false, nil', first['routervpn_command_run_other.go'])

    def test_native_inventory_includes_selected_original_roots(self):
        selected = {
            name
            for template in (*PROJECTION.TEMPLATES, 'external_retirement_linux_test.go.tmpl')
            for name in re.findall(
                r'^func (TestRouterVPN(?:CommandRetirement|RawCommand)\w+)\(t \*testing\.T\)',
                (ROOT/'mobile/desktop'/template).read_text(), re.MULTILINE)
        }
        self.assertTrue(selected)
        self.assertEqual(selected, {name for name in (*CASES, *NATIVE_CASES) if '/' not in name})

    def test_verdict_requires_every_original_parent_and_leaf_once(self):
        rows = [{'Action': action, 'Test': name} for name in (*CASES, *NATIVE_CASES) for action in ('run', 'pass')]
        rows.append({'Action': 'pass'})
        raw = lambda values: '\n'.join(json.dumps(value) for value in values)
        check_verdict(raw(rows), (*CASES, *NATIVE_CASES))
        for index in range(len(rows)):
            for broken in (rows[:index]+rows[index+1:], rows+[rows[index]]):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    check_verdict(raw(broken), (*CASES, *NATIVE_CASES))
        for action in ('skip', 'fail', 'build-fail'):
            with self.assertRaises(ValueError):
                check_verdict(raw(rows+[{'Action': action, 'Test': NATIVE_CASES[0]}]), (*CASES, *NATIVE_CASES))
        for broken in (rows[1:2]+rows[:1]+rows[2:], rows+[{'Action': 'run', 'Test': 'TestForeignResult'}],
                       rows+[{'Action': 'output', 'Output': 'WARNING: DATA RACE'}]):
            with self.assertRaises(ValueError):
                check_verdict(raw(broken), (*CASES, *NATIVE_CASES))


def check_verdict(raw, required=CASES):
    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    for event in events:
        if event.get('Action') in ('fail', 'skip', 'build-fail') or 'DATA RACE' in event.get('Output', ''):
            raise ValueError('Command retirement failed or skipped a required case')
    observed = {event['Test'] for event in events if 'Test' in event}
    if observed != set(required):
        raise ValueError('Command retirement changed its required parent/leaf inventory')
    for name in required:
        started = [i for i, event in enumerate(events) if event.get('Action') == 'run' and event.get('Test') == name]
        passed = [i for i, event in enumerate(events) if event.get('Action') == 'pass' and event.get('Test') == name]
        if len(started) != 1 or len(passed) != 1 or started[0] >= passed[0]:
            raise ValueError('Missing/duplicate/out-of-order command retirement verdict: '+name)
    if len([e for e in events if e.get('Action') == 'pass' and 'Test' not in e]) != 1:
        raise ValueError('Command retirement package did not finish successfully')


def execute(go):
    with tempfile.TemporaryDirectory(prefix='routervpn-command-retirement-') as directory:
        root = Path(directory)
        (root/'go.mod').write_text('module routervpncommandretirement\n\ngo 1.24.13\n')
        for name in ('command_retirement_linux.go.tmpl', 'command_retirement_linux_test.go.tmpl'):
            (root/name.removesuffix('.tmpl')).write_bytes((ROOT/'mobile/desktop'/name).read_bytes())
        result = subprocess.run([go, 'test', '-race', '-p=2', '-json', '-count=1', '.'], cwd=root,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        if result.returncode:
            raise RuntimeError(result.stdout+'\n'+result.stderr)
        check_verdict(result.stdout)
        print(result.stdout, end='', flush=True)


def execute_native(go, core, tags):
    core = Path(core).resolve()
    for name in (*PROJECTION.TEMPLATES, 'external_retirement_linux_test.go.tmpl'):
        actual = core/'cmd/sing-box'/('routervpn_'+name.removesuffix('.tmpl'))
        if actual.is_symlink() or actual.read_bytes() != (ROOT/'mobile/desktop'/name).read_bytes():
            raise ValueError('Native command test requires the exact current template: '+name)
    run_source = (core/'cmd/sing-box/cmd_run.go').read_bytes()
    if PROJECTION.DISPATCH not in run_source or PROJECTION.run_dispatch(run_source) != run_source:
        raise ValueError('Native run omitted the original command dispatch')
    command = [go, 'test', '-race', '-p=2', '-mod=readonly', '-json', '-ldflags=-checklinkname=0']
    if tags:
        command.append('-tags='+tags)
    command += ['./cmd/sing-box', '-run', '^TestRouterVPN(CommandRetirement|RawCommand)', '-count=1', '-timeout=30s']
    result = subprocess.run(command, cwd=core, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=120)
    if result.returncode:
        raise RuntimeError(result.stdout+'\n'+result.stderr)
    check_verdict(result.stdout, (*CASES, *NATIVE_CASES))
    print(result.stdout, end='', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default=os.environ.get('GO', 'go'))
    parser.add_argument('--native-core', type=Path)
    parser.add_argument('--tags', default='')
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CommandProjectionTests)
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
        raise SystemExit(1)
    if args.native_core:
        execute_native(args.go, args.native_core, args.tags)
    else:
        execute(args.go)
