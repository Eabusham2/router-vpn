#!/usr/bin/env python3
"""Causal strict-receipt and caller-artifact controls for native Darwin prefixes."""
from pathlib import Path
import importlib.util
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/file)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module
G = load('prefix_native_gate', 'test_macos_node_candidate_prefix_host.py')
ORDINARY = load('prefix_original_native_gate_runner', 'test_macos_node_chain_host_runner.py')


def workflow_inventory(consumer, wrapper):
    ORDINARY.workflow_inventory((ROOT/'.github/workflows/darwin-node-host-tun.yml').read_text(), wrapper)
    if not isinstance(consumer, str) or len(consumer)>16384 or re.search(r'^\s*(?:if|continue-on-error|inputs|workflow_run):', consumer, re.M):
        raise ValueError('Prefix native workflow became optional or caller-replaceable')
    if consumer.count('on:\n  workflow_call:\n') != 1 or re.search(r'^  (?:workflow_dispatch|push|pull_request):', consumer, re.M):
        raise ValueError('Prefix consumer must use the same successful caller run')
    if re.findall(r'^  ([A-Za-z][\w-]*):', consumer.split('jobs:\n')[1], re.M) != ['prefix-host']:
        raise ValueError('Prefix consumer changed original job inventory')
    required = (
        '  group: darwin-node-prefix-host-tun-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}',
        '  cancel-in-progress: true', '    runs-on: ${{ matrix.runner }}', '    timeout-minutes: 120',
        '      fail-fast: false', '          - arch: amd64\n            runner: macos-15-intel',
        '          - arch: arm64\n            runner: macos-15',
        '        run: python3 deploy/test_macos_node_candidate_prefix_host_runner.py',
        '      - uses: actions/download-artifact@v4',
        '          name: RouterVPN-native-runtime-darwin-${{ matrix.arch }}-${{ github.sha }}',
        '          path: ${{ runner.temp }}/prefix-host-bundle',
        '        run: python3 deploy/native-runtime-bundle.py extract \'darwin/${{ matrix.arch }}\' "$RUNNER_TEMP/prefix-host-bundle/native-darwin-${{ matrix.arch }}.tar.gz" "$RUNNER_TEMP/prefix-host-verified"',
        '        timeout-minutes: 110', "          ROUTERVPN_DARWIN_NODE_PREFIX_HOST_ACCEPTANCE: '1'",
        '          ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}', "          CGO_ENABLED: '1'",
        '          ROUTERVPN_HOST_RECEIPT: ${{ runner.temp }}/darwin-node-prefix-host-${{ matrix.arch }}.json',
        '          name: RouterVPN-Darwin-selected-prefix-host-${{ matrix.arch }}-${{ github.sha }}',
        '          path: ${{ runner.temp }}/darwin-node-prefix-host-${{ matrix.arch }}.json',
        '          if-no-files-found: error',
    )
    if any(consumer.count(value)!=1 for value in required) or len(re.findall(r'^          - arch:', consumer, re.M))!=2:
        raise ValueError('Prefix workflow lost an exact native architecture, source or artifact boundary')
    if re.search(r'^\s*(?:run-id|repository|github-token|pattern|merge-multiple):', consumer, re.M):
        raise ValueError('Prefix workflow borrowed foreign or ambiguous artifacts')
    command='python3 deploy/test_macos_node_candidate_prefix_host.py --bundle "$RUNNER_TEMP/prefix-host-verified" --require-commit "$ROUTERVPN_EXPECTED_SOURCE" --receipt "$ROUTERVPN_HOST_RECEIPT"'
    commands=re.findall(r'^        run: \|\n((?:          [^\n]*\n)+)',consumer,re.M)
    if len(commands)!=1 or [line.strip() for line in commands[0].splitlines()]!=[command]:
        raise ValueError('Prefix workflow weakened its mandatory native invocation')


def private_callers(sources):
    allowed={
        'beginOrderedCandidateNativePreparationWithLifetime': {'cmd/client/ordered_candidate_preparation.go':1,'cmd/client/desktop_node_candidate_prefix_darwin_native_test.go':2},
        'captureOrderedCandidateNativePreparedViewScope': {'cmd/client/ordered_candidate_preparation_view.go':1,'cmd/client/desktop_node_candidate_prefix_darwin_native_test.go':2},
    }
    for symbol, expected in allowed.items():
        found={}
        for name,source in sources.items():
            calls=len(re.findall(r'(?<!func )\b'+symbol+r'\s*\(',source))
            if calls: found[name]=calls
        if found!=expected: raise ValueError('Private native admission acquired another production caller: '+symbol)
    fixture=sources['cmd/client/desktop_node_candidate_prefix_darwin_native_test.go']
    if not fixture.startswith('//go:build darwin && routervpn_controller_privileged\n'):
        raise ValueError('Private native admission fixture lost explicit installed build tag')


class NativePrefixGate(unittest.TestCase):
    def output(self, case):
        return '\n'.join(('=== RUN   '+G.TEST,'=== RUN   '+G.TEST+'/'+case,
            '    desktop_node_candidate_prefix_darwin_native_test.go:400: '+G.receipt(case),
            '--- PASS: '+G.TEST+' (1.0s)','    --- PASS: '+G.TEST+'/'+case+' (1.0s)','PASS'))+'\n'
    def authority(self):
        lines=['=== RUN   '+G.AUTHORITY_TEST]
        for child in G.AUTHORITY_CASES[1:]: lines+=['=== RUN   '+child,'    --- PASS: '+child+' (0.1s)']
        return '\n'.join(lines+['--- PASS: '+G.AUTHORITY_TEST+' (0.3s)','PASS'])+'\n'
    def test_exact_six_cases_and_four_source_records(self):
        self.assertEqual(G.case_inventory(),G.CASES)
        self.assertEqual(len(G.CASES),6); self.assertEqual(len(G.AUTHORITY_CASES),4)
        for case in G.CASES:G.check_verdict(self.output(case),case)
        G.check_authority_verdict(self.authority())
    def test_inventory_rejects_omission_duplication_reorder_and_computed_entry(self):
        source=(ROOT/'cmd/client/desktop_node_candidate_prefix_darwin_native_test.go').read_text()
        for replacement in ('','"wg-save", "wg-save",','"wg-cancel",','computed(),'):
            with self.subTest(replacement=replacement),self.assertRaises(ValueError):
                G.case_inventory(source.replace('"wg-save",',replacement,1))
    def test_every_case_requires_unique_run_pass_and_ownership_receipt(self):
        for case in G.CASES:
            original=self.output(case)
            for line in original.splitlines(keepends=True):
                for broken in (original.replace(line,'',1),original.replace(line,line+line,1)):
                    with self.subTest(case=case,line=line),self.assertRaises(ValueError):G.check_verdict(broken,case)
    def test_refuses_failed_skipped_racing_and_late_execution(self):
        original=self.output(G.CASES[0])
        for marker in ('--- FAIL: other (0.1s)','--- SKIP: other (0.1s)','WARNING: DATA RACE','panic: lost owner','fatal error: lost owner','FAIL','[build failed]','=== RUN   another'):
            with self.subTest(marker=marker),self.assertRaises(ValueError):G.check_verdict(marker+'\n'+original,G.CASES[0])
        with self.assertRaises(ValueError):G.check_verdict(original+'=== RUN   '+G.TEST+'\nPASS\n',G.CASES[0])
    def test_refuses_borrowed_receipt_or_unexecuted_authority(self):
        original=self.output(G.CASES[0])
        with self.assertRaises(ValueError):G.check_verdict(original.replace(G.receipt(G.CASES[0]),G.receipt(G.CASES[1])),G.CASES[0])
        for child in G.AUTHORITY_CASES:
            broken='\n'.join(line for line in self.authority().splitlines() if child not in line)+'\n'
            with self.subTest(child=child),self.assertRaises(ValueError):G.check_authority_verdict(broken)
    def test_authority_executes_original_captured_image_and_checks_after(self):
        class Result:stdout=self.authority()
        with patch.object(G.EXTERNAL,'sha',return_value='a'*64),patch.object(G.subprocess,'run',return_value=Result()) as run:
            G.execute_authority(Path('/captured/controller'),'a'*64,{})
            self.assertEqual(run.call_args.args[0][0],'/captured/controller')
            self.assertIn('-test.run=^'+G.AUTHORITY_TEST+'$',run.call_args.args[0])
            self.assertTrue(run.call_args.kwargs['check'])
        with patch.object(G.EXTERNAL,'sha',side_effect=['a'*64,'b'*64]),patch.object(G.subprocess,'run',return_value=Result()),self.assertRaises(ValueError):
            G.execute_authority(Path('/captured/controller'),'a'*64,{})
        with patch.object(G.EXTERNAL,'sha',return_value='b'*64),patch.object(G.subprocess,'run') as run,self.assertRaises(ValueError):
            G.execute_authority(Path('/captured/controller'),'a'*64,{})
        run.assert_not_called()
    def test_original_private_admission_caller_inventory_and_public_refusal(self):
        sources={str(p.relative_to(ROOT)):p.read_text() for p in (ROOT/'cmd/client').glob('*.go')}
        private_callers(sources)
        for symbol in ('beginOrderedCandidateNativePreparationWithLifetime','captureOrderedCandidateNativePreparedViewScope'):
            changed=dict(sources);changed['cmd/client/unapproved.go']='package main\nfunc bypass(){'+symbol+'(nil)}\n'
            with self.subTest(symbol=symbol),self.assertRaises(ValueError):private_callers(changed)
        negative=sources['cmd/client/ordered_candidate_prefix_unsupported_test.go']
        self.assertIn('func TestOrderedCandidatePrefixUnsupportedPlatformKeepsAdmissionClosed(',negative)
        self.assertIn('captureOrderedCandidatePreparedViewScope(',negative)
        self.assertIn('unsupported prefix public POST acquired native authority',negative)
        self.assertIn('unsupported prefix public catalog bypassed native gate',negative)
    def test_same_caller_workflow_and_ordinary_inventory_are_mandatory(self):
        consumer=(ROOT/'.github/workflows/darwin-node-prefix-host-tun.yml').read_text()
        wrapper=(ROOT/'.github/workflows/darwin-node-host-native.yml').read_text()
        workflow_inventory(consumer,wrapper)
        self.assertEqual(len(G.G.CASES),28);self.assertEqual(len(G.G.MEASUREMENT_CASES),19)
        for before,after in (
            ('runner: macos-15-intel','runner: ubuntu-latest'),('arch: arm64','arch: amd64'),
            ('${{ github.sha }}','old-source'),('timeout-minutes: 110','timeout-minutes: 200'),
            ('if-no-files-found: error','if-no-files-found: warn'),('workflow_call:','workflow_dispatch:'),
            ('      fail-fast: false','      fail-fast: true'),('    runs-on:','    if: always()\n    runs-on:'),
            ('          path: ${{ runner.temp }}/prefix-host-bundle','          run-id: 123\n          path: ${{ runner.temp }}/prefix-host-bundle'),
            (' --require-commit "$ROUTERVPN_EXPECTED_SOURCE"',''),
        ):
            with self.subTest(before=before),self.assertRaises(ValueError):workflow_inventory(consumer.replace(before,after,1),wrapper)
    def test_explicit_real_host_and_new_receipt_required(self):
        with self.assertRaises(ValueError):G.required_host({})
        with tempfile.TemporaryDirectory() as directory:
            receipt=Path(directory)/'receipt.json';G.write_receipt(receipt,{'schema':1})
            with self.assertRaises(ValueError):G.write_receipt(receipt,{'schema':1})
            linked=Path(directory)/'linked.json';linked.symlink_to(receipt)
            with self.assertRaises(ValueError):G.write_receipt(linked,{'schema':1})

if __name__=='__main__':unittest.main()
