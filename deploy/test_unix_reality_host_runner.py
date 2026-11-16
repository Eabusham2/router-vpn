#!/usr/bin/env python3
"""Source and synthetic-verdict refusal controls; never native acceptance."""
from pathlib import Path
import ast
import importlib.util
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('unix_reality_host_gate', ROOT/'deploy/test_unix_reality_host.py')
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)
P = G.PLAN
WORKFLOW = '.github/workflows/unix-reality-host.yml'
INPUTS = ('deploy/unix_reality_cases.py', 'deploy/test_unix_reality_host.py',
          'deploy/test_unix_reality_host_runner.py', WORKFLOW)


SOURCE_FAULTS = ('original', 'endpoint', 'port', 'mode', 'missing-xray', 'extra-source',
                 'foreign-final', 'wrapper-listener', 'xray-listener', 'user', 'reality-key',
                 'duplicate-field', 'extra-outbound', 'physical-wrapper')
RECEIPT_FAULTS = ('original', 'raw-udp', 'protocol-udp-lower', 'foreign-address', 'foreign-base',
                  'borrowed-source', 'foreign-layer', 'outer-source', 'websocket', 'mux',
                  'tls-http', 'negative-counter', 'missing-source')
COMPONENT_ROOTS = {
    'TestDesktopUnixREALITYPrivateFixtureRefusesSubstitution': tuple(mode+'/'+fault for mode in P.MODES for fault in SOURCE_FAULTS),
    'TestDesktopUnixREALITYPrivateFixtureMutatesOnlyNamedCredential': tuple(mode+'/'+action for mode in P.MODES for action in (
        'wrong-key', 'wrong-user', 'wrong-server-name', 'wrong-short-id',
        *(('wrong-pq-key',) if mode != 'reality-vision' else ()),
        *(('wrong-path',) if mode == 'reality-xhttp' else ()))),
    'TestDesktopUnixREALITYPeerReceiptRefusesForeignLower': tuple(layer+'/'+fault for layer in P.LAYERS for fault in RECEIPT_FAULTS),
}


def job(source, name):
    found = re.findall(r'(?ms)^  '+re.escape(name)+r':\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)', source)
    if len(found) != 1:
        raise ValueError('REALITY phase lost its unique required job')
    return found[0]


def block(source, marker):
    if source.count(marker) != 1:
        raise ValueError('REALITY phase lost a unique required step: '+marker.strip())
    return source.split(marker, 1)[1].split('      - ', 1)[0]


def workflow(source, release, builder):
    if source.count('on:\n  workflow_call:\n\n') != 1:
        raise ValueError('REALITY phase lost its no-input reusable workflow')
    if any(re.search(r'(?m)^\s*[\"\'][^\n]*:', text) or re.search(r'(?m)^\s*<<:', text) for text in (source, release)):
        raise ValueError('REALITY literal workflow cannot hide conditional mapping keys')
    if source.count("env:\n  PYTHONDONTWRITEBYTECODE: '1'\n\n") != 1:
        raise ValueError('REALITY source capture permits ignored bytecode mutations')
    host = job(source, 'host')
    header, steps = host.split('    steps:\n', 1)
    expected = (
        '          - {os: linux, arch: amd64, runner: ubuntu-24.04}',
        '          - {os: linux, arch: arm64, runner: ubuntu-24.04-arm}',
        '          - {os: darwin, arch: amd64, runner: macos-15-intel}',
        '          - {os: darwin, arch: arm64, runner: macos-15}',
    )
    matrix = header.split('      matrix:\n', 1)[1]
    expected_matrix = (
        '        os: [linux, darwin]\n'
        '        arch: [amd64, arm64]\n'
        '        mode: [reality-vision, reality-pq-vision, reality-xhttp]\n'
        '        include:\n' + ''.join(line+'\n' for line in expected))
    if matrix != expected_matrix:
        raise ValueError('REALITY matrix is not the exact twelve mandatory target/mode partitions')
    dimensions = ('        os: [linux, darwin]\n', '        arch: [amd64, arm64]\n', '        mode: [reality-vision, reality-pq-vision, reality-xhttp]\n')
    if any(header.count(value) != 1 for value in (*expected,*dimensions)) or len(re.findall(r'(?m)^          - ', header)) != 4 or '    timeout-minutes: 240\n' not in header or re.search(r'(?m)^\s*(?:if|continue-on-error):', header):
        raise ValueError('REALITY phase changed its four matching hosts or finite budget')
    if re.search(r'(?m)^\s*continue-on-error:', steps) or re.findall(r'(?m)^\s*if: (.*)$', steps) != ["matrix.os == 'linux'"]:
        raise ValueError('Required REALITY native execution was skipped or made optional')
    checkout = block(steps, '      - uses: actions/checkout@v4\n')
    if checkout != '        with:\n          persist-credentials: false\n':
        raise ValueError('REALITY phase must check out the current caller source')
    preparation = block(steps, '      - name: Install real Linux namespace and native build tools\n')
    if preparation != '''        if: matrix.os == 'linux'
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends build-essential git iproute2 nftables util-linux uidmap sudo passwd
          test -c /dev/net/tun
''':
        raise ValueError('REALITY phase lost actual namespace, firewall or TUN prerequisites')
    download = block(steps, '      - uses: actions/download-artifact@v4\n')
    if download != '''        with:
          name: RouterVPN-native-runtime-${{ matrix.os }}-${{ matrix.arch }}-${{ github.sha }}
          path: ${{ runner.temp }}/reality-host-bundle
''':
        raise ValueError('REALITY phase borrowed a foreign native bundle')
    native = block(steps, '      - name: Require actual REALITY, selected DNS, protection, MTU, restoration and retirement\n')
    if native != '''        timeout-minutes: 230
        env:
          ROUTERVPN_UNIX_REALITY_HOST_ACCEPTANCE: '1'
          ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}
          ROUTERVPN_REALITY_HOST_RECEIPT: ${{ runner.temp }}/reality-host-${{ matrix.os }}-${{ matrix.arch }}-${{ matrix.mode }}.json
          CGO_ENABLED: '1'
        run: python3 deploy/test_unix_reality_host.py --bundle "$RUNNER_TEMP/reality-host-verified" --require-commit "$ROUTERVPN_EXPECTED_SOURCE" --mode '${{ matrix.mode }}' --receipt "$ROUTERVPN_REALITY_HOST_RECEIPT"
''':
        raise ValueError('REALITY phase omitted unfiltered actual native execution or its exact receipt')
    for anchor in (
        '        run: python3 deploy/test_unix_reality_host_runner.py\n',
        '        run: python3 deploy/native-runtime-bundle.py extract \'${{ matrix.os }}/${{ matrix.arch }}\' "$RUNNER_TEMP/reality-host-bundle/native-${{ matrix.os }}-${{ matrix.arch }}.tar.gz" "$RUNNER_TEMP/reality-host-verified"\n',
        '          name: RouterVPN-REALITY-native-host-${{ matrix.os }}-${{ matrix.arch }}-${{ matrix.mode }}-${{ github.sha }}\n',
        '          path: ${{ runner.temp }}/reality-host-${{ matrix.os }}-${{ matrix.arch }}-${{ matrix.mode }}.json\n',
        '          if-no-files-found: error\n',
    ):
        if steps.count(anchor) != 1:
            raise ValueError('REALITY phase lost exact extraction, source or publication boundary')
    call = job(release, 'unix-reality-host')
    if re.findall(r'(?m)^    needs: (.*)$', call) != ['native-runtimes'] or re.findall(r'(?m)^    uses: (.*)$', call) != ['./'+WORKFLOW] or re.search(r'(?m)^\s*(?:if|continue-on-error|with):', call):
        raise ValueError('REALITY phase is not a required current-run native consumer')
    needs = re.search(r'(?m)^    needs: \[([^\n]+)\]$', job(release, 'aggregate'))
    if needs is None or [name.strip() for name in needs[1].split(',')].count('unix-reality-host') != 1:
        raise ValueError('Authoritative aggregate omitted REALITY native acceptance')
    if any(builder.count("ROOT/'"+name+"'") != 1 for name in INPUTS):
        raise ValueError('Native bundle source identity omitted the REALITY gate')


class UnixREALITYHostContracts(unittest.TestCase):
    def complete(self, target, case):
        root = P.LINUX_TEST if target == 'linux' else P.DARWIN_TEST
        return '\n'.join(['=== RUN   '+root, '=== RUN   '+root+'/'+case,
            *('    desktop_node_host_native_test.go:1: '+receipt for receipt in P.receipts(target, case)),
            '--- PASS: '+root+' (1.0s)', '    --- PASS: '+root+'/'+case+' (1.0s)', 'PASS'])+'\n'

    def test_exact_new_cases_leave_original_native_phases_intact(self):
        self.assertEqual(len(P.LINUX_CASES), 153)
        self.assertEqual(len(P.DARWIN_CASES), 117)
        self.assertEqual(len(G.MAC.case_inventory()), 69)
        self.assertFalse(set(P.LINUX_CASES) & set(G.LINUX.CASES))
        self.assertFalse(set(P.DARWIN_CASES) & set(G.MAC.CASES))
        for target, cases in (('linux', P.LINUX_CASES), ('darwin', P.DARWIN_CASES)):
            self.assertEqual(len(cases), len(set(cases)))
            for case in cases:
                P.check_verdict(self.complete(target, case), target, case)

    def test_all_mode_partitions_are_exact_disjoint_and_exhaustive(self):
        self.assertEqual(P.MODES, ('reality-vision','reality-pq-vision','reality-xhttp'))
        for target, full, sizes in (('linux',P.LINUX_CASES,(48,51,54)),('darwin',P.DARWIN_CASES,(36,39,42))):
            partitions=[P.mode_cases(target,mode) for mode in P.MODES]
            self.assertEqual(tuple(map(len,partitions)),sizes)
            self.assertEqual(tuple(case for part in partitions for case in part),full)
            self.assertEqual(sum(map(len,partitions)),len(set(full)))
        for target,mode in (('windows','reality-vision'),('linux','reality'),('darwin','all')):
            with self.assertRaises(ValueError):P.mode_cases(target,mode)

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
            valid = '=== RUN   '+root+'\n    desktop_node_reality_'+filename+'_native_test.go:1: compiled installed REALITY cases: '+raw+'\n--- PASS: '+root+' (0.0s)\nPASS\n'
            G.check_inventory(valid, target)
            for changed in (valid.replace(raw, json.dumps(cases[:-1])), valid.replace(raw, json.dumps(cases+cases[:1])), valid.replace('compiled installed REALITY cases:', 'historical cases:')):
                with self.assertRaises(ValueError):
                    G.check_inventory(changed, target)

    def test_retained_unix_admission_keeps_h3_and_unproved_families_closed(self):
        tree = ast.parse((ROOT/'modes/kill-switch-platform.py').read_text())
        modes = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == '_NODE_MODES' for target in node.targets)]
        self.assertEqual(modes, [('wg', 'awg2-fast', 'awg2-strong', 'shadowsocks', 'hysteria2', 'ss-v2ray', 'naive-h2', 'reality-vision', 'reality-pq-vision', 'reality-xhttp')])
        source = (ROOT/'internal/mobilemultihop/desktop_node_admission.go').read_text()
        unix = source.split('func DesktopLinuxNodePhysicalGraphSupported', 1)[1].split('\n}', 1)[0]
        self.assertTrue(all(mode in unix for mode in P.MODES))
        self.assertNotIn('"naive-h3"', unix)

    def test_native_gate_requires_real_host_and_exact_source(self):
        for env in ({}, {G.FLAG: '0'}, {G.FLAG: '1', 'HOMEVPN_MTU_BENCH_FAKE': '1'}):
            with self.assertRaises(ValueError):
                G.required_host(env)
        self.assertEqual(G.COMPONENT_ROOTS, COMPONENT_ROOTS)
        self.assertEqual(tuple(map(len, G.COMPONENT_ROOTS.values())), (42, 15, 39))
        for name in G.SOURCES:
            self.assertTrue((ROOT/name).is_file(), name)

    def test_source_contract_verdicts_require_every_original_leaf_once(self):
        # These are parser controls; the executor separately runs the captured
        # controller image and validates its actual 99 Go records.
        for root, leaves in COMPONENT_ROOTS.items():
            wanted = (root, *(root+'/'+leaf for leaf in leaves))
            lines = ['=== RUN   '+root]
            for leaf in leaves:
                lines.extend(('=== RUN   '+root+'/'+leaf, '    --- PASS: '+root+'/'+leaf+' (0.0s)'))
            lines.extend(('--- PASS: '+root+' (0.0s)', 'PASS'))
            valid = '\n'.join(lines)+'\n'
            G.LINUX.NODE.require_native_verdicts(valid, wanted, 'REALITY synthetic source contracts')
            for leaf in leaves:
                passed = '    --- PASS: '+root+'/'+leaf+' (0.0s)\n'
                for changed in (valid.replace(passed, ''), valid.replace(passed, passed+passed),
                                valid.replace(passed, passed.replace('PASS', 'FAIL')),
                                valid.replace(root+'/'+leaf, root+'/foreign', 1)):
                    with self.subTest(root=root, leaf=leaf), self.assertRaises(ValueError):
                        G.LINUX.NODE.require_native_verdicts(changed, wanted, 'REALITY synthetic source contracts')

    def test_required_native_workflow_and_bundle_source_identity(self):
        workflow((ROOT/WORKFLOW).read_text(), (ROOT/'.github/workflows/release-candidate.yml').read_text(), (ROOT/'deploy/build-native-runtime.py').read_text())

    def test_removed_host_borrowed_bundle_skipped_phase_and_filtered_case_are_rejected(self):
        source = (ROOT/WORKFLOW).read_text()
        release = (ROOT/'.github/workflows/release-candidate.yml').read_text()
        builder = (ROOT/'deploy/build-native-runtime.py').read_text()
        for old, new in (
            ('on:\n  workflow_call:\n\n', 'on:\n  workflow_call:\n    inputs:\n      case:\n        type: string\n\n'),
            ('          - {os: linux, arch: arm64, runner: ubuntu-24.04-arm}\n', ''),
            ('          - {os: darwin, arch: amd64, runner: macos-15-intel}\n', ''),
            ('  host:\n', '  host:\n    if: false\n'),
            ('        include:\n', '        exclude:\n          - {os: linux, mode: reality-vision}\n        include:\n'),
            ('  host:\n', '  host:\n    \"if\": false\n'),
            ('        mode: [reality-vision, reality-pq-vision, reality-xhttp]\n', '        mode: [reality-vision, reality-pq-vision]\n'),
            ("env:\n  PYTHONDONTWRITEBYTECODE: '1'\n\n", ''),
            ('          persist-credentials: false\n', '          persist-credentials: false\n          ref: historical\n'),
            ('          test -c /dev/net/tun\n', '          true\n'),
            ('build-essential git iproute2 nftables', 'build-essential git'),
            ('      - uses: actions/download-artifact@v4\n', '      - uses: actions/download-artifact@v4\n      - uses: actions/download-artifact@v4\n'),
            ('          path: ${{ runner.temp }}/reality-host-bundle\n', '          path: ${{ runner.temp }}/reality-host-bundle\n          run-id: 1234\n'),
            ('--receipt "$ROUTERVPN_REALITY_HOST_RECEIPT"', '--receipt "$ROUTERVPN_REALITY_HOST_RECEIPT" --case one'),
            ("ROUTERVPN_UNIX_REALITY_HOST_ACCEPTANCE: '1'", "ROUTERVPN_UNIX_REALITY_HOST_ACCEPTANCE: '0'"),
            ('          if-no-files-found: error', '          if-no-files-found: warn'),
        ):
            with self.subTest(anchor=old), self.assertRaises(ValueError):
                workflow(source.replace(old, new, 1), release, builder)
        changed_release = release.replace('unix-reality-host, ', '', 1)
        self.assertNotEqual(changed_release, release)
        with self.assertRaises(ValueError):
            workflow(source, changed_release, builder)
        for key in ('if: false', '"if": false', 'continue-on-error: true'):
            with self.subTest(caller=key), self.assertRaises(ValueError):
                workflow(source, release.replace('  unix-reality-host:\n', '  unix-reality-host:\n    '+key+'\n'), builder)
        for name in INPUTS:
            with self.subTest(input=name), self.assertRaises(ValueError):
                workflow(source, release, builder.replace("ROOT/'"+name+"'", "ROOT/'omitted'", 1))


if __name__ == '__main__':
    unittest.main()
