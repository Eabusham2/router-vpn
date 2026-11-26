#!/usr/bin/env python3
"""Source and synthetic-verdict refusal controls; never native acceptance."""
from pathlib import Path
import ast
import importlib.util
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('unix_naive_h2_host_gate', ROOT/'deploy/test_unix_naive_h2_host.py')
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)
P = G.PLAN
WORKFLOW = '.github/workflows/unix-naive-h2-host.yml'
INPUTS = ('deploy/unix_naive_h2_cases.py', 'deploy/test_unix_naive_h2_host.py',
          'deploy/test_unix_naive_h2_host_runner.py', WORKFLOW)


def job(source, name):
    found = re.findall(r'(?ms)^  '+re.escape(name)+r':\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)', source)
    if len(found) != 1:
        raise ValueError('Naive H2 phase lost its unique required job')
    return found[0]


def block(source, marker):
    if source.count(marker) != 1:
        raise ValueError('Naive H2 phase lost a unique required step: '+marker.strip())
    return source.split(marker, 1)[1].split('      - ', 1)[0]


def workflow(source, release, builder):
    if source.count('on:\n  workflow_call:\n\n') != 1:
        raise ValueError('Naive H2 phase lost its no-input reusable workflow')
    host = job(source, 'host')
    header, steps = host.split('    steps:\n', 1)
    expected = (
        '          - {os: linux, arch: amd64, runner: ubuntu-24.04}',
        '          - {os: linux, arch: arm64, runner: ubuntu-24.04-arm}',
        '          - {os: darwin, arch: amd64, runner: macos-15-intel}',
        '          - {os: darwin, arch: arm64, runner: macos-15}',
    )
    if any(header.count(value) != 1 for value in expected) or len(re.findall(r'(?m)^          - ', header)) != 4 or '    timeout-minutes: 120\n' not in header or re.search(r'(?m)^\s*(?:if|continue-on-error):', header):
        raise ValueError('Naive H2 phase changed its four matching hosts or finite budget')
    if re.search(r'(?m)^\s*continue-on-error:', steps) or re.findall(r'(?m)^\s*if: (.*)$', steps) != ["matrix.os == 'linux'"]:
        raise ValueError('Required Naive H2 native execution was skipped or made optional')
    checkout = block(steps, '      - uses: actions/checkout@v4\n')
    if checkout != '        with:\n          persist-credentials: false\n':
        raise ValueError('Naive H2 phase must check out the current caller source')
    preparation = block(steps, '      - name: Install real Linux namespace and native build tools\n')
    if preparation != '''        if: matrix.os == 'linux'
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends build-essential git iproute2 nftables util-linux uidmap sudo passwd
          test -c /dev/net/tun
''':
        raise ValueError('Naive H2 phase lost actual namespace, firewall or TUN prerequisites')
    download = block(steps, '      - uses: actions/download-artifact@v4\n')
    if download != '''        with:
          name: RouterVPN-native-runtime-${{ matrix.os }}-${{ matrix.arch }}-${{ github.sha }}
          path: ${{ runner.temp }}/naive-h2-host-bundle
''':
        raise ValueError('Naive H2 phase borrowed a foreign native bundle')
    native = block(steps, '      - name: Require actual H2, selected DNS, protection, MTU, restoration and retirement\n')
    if native != '''        timeout-minutes: 110
        env:
          ROUTERVPN_UNIX_NAIVE_H2_HOST_ACCEPTANCE: '1'
          ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}
          ROUTERVPN_NAIVE_HOST_RECEIPT: ${{ runner.temp }}/naive-h2-host-${{ matrix.os }}-${{ matrix.arch }}.json
          CGO_ENABLED: '1'
        run: python3 deploy/test_unix_naive_h2_host.py --bundle "$RUNNER_TEMP/naive-h2-host-verified" --require-commit "$ROUTERVPN_EXPECTED_SOURCE" --receipt "$ROUTERVPN_NAIVE_HOST_RECEIPT"
''':
        raise ValueError('Naive H2 phase omitted unfiltered actual native execution or its exact receipt')
    for anchor in (
        '        run: python3 deploy/test_unix_naive_h2_host_runner.py\n',
        '        run: python3 deploy/native-runtime-bundle.py extract \'${{ matrix.os }}/${{ matrix.arch }}\' "$RUNNER_TEMP/naive-h2-host-bundle/native-${{ matrix.os }}-${{ matrix.arch }}.tar.gz" "$RUNNER_TEMP/naive-h2-host-verified"\n',
        '          name: RouterVPN-Naive-H2-native-host-${{ matrix.os }}-${{ matrix.arch }}-${{ github.sha }}\n',
        '          path: ${{ runner.temp }}/naive-h2-host-${{ matrix.os }}-${{ matrix.arch }}.json\n',
        '          if-no-files-found: error\n',
    ):
        if steps.count(anchor) != 1:
            raise ValueError('Naive H2 phase lost exact extraction, source or publication boundary')
    call = job(release, 'unix-naive-h2-host')
    if re.findall(r'(?m)^    needs: (.*)$', call) != ['native-runtimes'] or re.findall(r'(?m)^    uses: (.*)$', call) != ['./'+WORKFLOW] or re.search(r'(?m)^\s*(?:if|continue-on-error|with):', call):
        raise ValueError('Naive H2 phase is not a required current-run native consumer')
    needs = re.search(r'(?m)^    needs: \[([^\n]+)\]$', job(release, 'aggregate'))
    if needs is None or [name.strip() for name in needs[1].split(',')].count('unix-naive-h2-host') != 1:
        raise ValueError('Authoritative aggregate omitted Naive H2 native acceptance')
    if any(builder.count("ROOT/'"+name+"'") != 1 for name in INPUTS):
        raise ValueError('Native bundle source identity omitted the Naive H2 gate')


class UnixNaiveH2HostContracts(unittest.TestCase):
    def complete(self, target, case):
        root = P.LINUX_TEST if target == 'linux' else P.DARWIN_TEST
        return '\n'.join(['=== RUN   '+root, '=== RUN   '+root+'/'+case,
            *('    desktop_node_host_native_test.go:1: '+receipt for receipt in P.receipts(target, case)),
            '--- PASS: '+root+' (1.0s)', '    --- PASS: '+root+'/'+case+' (1.0s)', 'PASS'])+'\n'

    def test_exact_new_cases_leave_original_native_phases_intact(self):
        self.assertEqual(len(P.LINUX_CASES), 48)
        self.assertEqual(len(P.DARWIN_CASES), 36)
        self.assertEqual(len(G.MAC.case_inventory()), 69)
        self.assertFalse(set(P.LINUX_CASES) & set(G.LINUX.CASES))
        self.assertFalse(set(P.DARWIN_CASES) & set(G.MAC.CASES))
        for target, cases in (('linux', P.LINUX_CASES), ('darwin', P.DARWIN_CASES)):
            self.assertEqual(len(cases), len(set(cases)))
            for case in cases:
                P.check_verdict(self.complete(target, case), target, case)

    def test_every_original_receipt_is_required_once(self):
        for target, cases in (('linux', P.LINUX_CASES), ('darwin', P.DARWIN_CASES)):
            for case in cases:
                valid = self.complete(target, case)
                for receipt in P.receipts(target, case):
                    line = '    desktop_node_host_native_test.go:1: '+receipt+'\n'
                    for changed in (valid.replace(line, ''), valid.replace(line, line+line), valid.replace(receipt, receipt+'-borrowed')):
                        with self.subTest(target=target, case=case, receipt=receipt), self.assertRaises(ValueError):
                            P.check_verdict(changed, target, case)

    def test_skip_failure_partial_and_foreign_execution_cannot_pass(self):
        for target, case in (('linux', P.LINUX_CASES[0]), ('darwin', P.DARWIN_CASES[0])):
            valid = self.complete(target, case)
            root = P.LINUX_TEST if target == 'linux' else P.DARWIN_TEST
            for changed in (valid.replace('--- PASS:', '--- SKIP:', 1), valid.replace('--- PASS:', '--- FAIL:', 1), valid+'WARNING: DATA RACE\n', valid.replace('=== RUN   '+root+'\n', ''), valid+'PASS\n', valid.replace(root+'/'+case, root+'/foreign'), valid.replace('PASS\n', '')):
                with self.assertRaises(ValueError):
                    P.check_verdict(changed, target, case)

    def test_compiled_inventory_is_not_a_source_count_or_prior_receipt(self):
        for target, cases, filename in (('linux/amd64', P.LINUX_CASES, 'linux_tun'), ('darwin/arm64', P.DARWIN_CASES, 'darwin')):
            root = G.INVENTORY_ROOT
            raw = json.dumps(cases, separators=(',', ':'))
            valid = '=== RUN   '+root+'\n    desktop_node_naive_h2_'+filename+'_native_test.go:1: compiled installed Naive H2 cases: '+raw+'\n--- PASS: '+root+' (0.0s)\nPASS\n'
            G.check_inventory(valid, target)
            for changed in (valid.replace(raw, json.dumps(cases[:-1])), valid.replace(raw, json.dumps(cases+cases[:1])), valid.replace('compiled installed Naive H2 cases:', 'historical cases:')):
                with self.assertRaises(ValueError):
                    G.check_inventory(changed, target)

    def test_retained_unix_admission_keeps_h3_and_unproved_families_closed(self):
        tree = ast.parse((ROOT/'modes/kill-switch-platform.py').read_text())
        modes = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == '_NODE_MODES' for target in node.targets)]
        self.assertEqual(modes, [('wg', 'awg2-fast', 'awg2-strong', 'shadowsocks', 'hysteria2', 'ss-v2ray', 'naive-h2', 'reality-vision', 'reality-pq-vision', 'reality-xhttp')])
        source = (ROOT/'internal/mobilemultihop/desktop_node_admission.go').read_text()
        unix = source.split('func DesktopLinuxNodePhysicalGraphSupported', 1)[1].split('\n}', 1)[0]
        self.assertIn('mode != "naive-h2"', unix)
        self.assertNotIn('"naive-h3"', unix)

    def test_native_gate_requires_real_host_and_exact_source(self):
        for env in ({}, {G.FLAG: '0'}, {G.FLAG: '1', 'HOMEVPN_MTU_BENCH_FAKE': '1'}):
            with self.assertRaises(ValueError):
                G.required_host(env)
        self.assertEqual(len(G.COMPONENT_ROOTS), 2)
        self.assertEqual(sum(map(len, G.COMPONENT_ROOTS.values())), 25)
        for name in G.SOURCES:
            self.assertTrue((ROOT/name).is_file(), name)

if __name__ == '__main__':
    unittest.main()
