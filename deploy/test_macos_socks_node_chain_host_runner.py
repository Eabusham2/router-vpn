#!/usr/bin/env python3
"""Fail-closed inventory and verdict checks for installed SOCKS native acceptance."""
from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('typed_installed_gate', ROOT/'deploy/test_macos_socks_node_chain_host.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class TypedInstalledGate(unittest.TestCase):
    def completed(self, case):
        lines = ['=== RUN   '+G.TEST, '=== RUN   '+G.TEST+'/'+case]
        if case in G.MEASUREMENT_CASES:
            lines.append('    desktop_node_chain_darwin_native_test.go:657: '+G.BASE.MEASUREMENT_RECEIPT)
        lines += ['    desktop_node_chain_darwin_native_test.go:570: actual sealed Darwin ordered host verified '+case+': original native transaction and intended proof boundary, complete captured identities, stopped acknowledgment, PF and utun retirement, controller join',
                  '--- PASS: '+G.TEST+' (2.00s)', '    --- PASS: '+G.TEST+'/'+case+' (2.00s)', 'PASS']
        return '\n'.join(lines)+'\n'

    def authority(self, fail=False):
        root=G.AUTHORITY_TEST
        lines=['=== RUN   '+root]
        for name in G.AUTHORITY_CASES[1:]:
            lines.append('=== RUN   '+name)
            if fail:
                lines.append('    '+Path(G.AUTHORITY_SOURCE).name+':85: '+G.SOURCE_CONTROL)
        verdict='FAIL' if fail else 'PASS'
        lines += ['--- '+verdict+': '+root+' (0.01s)']
        lines += ['    --- '+verdict+': '+name+' (0.00s)' for name in G.AUTHORITY_CASES[1:]]
        return '\n'.join([*lines,verdict])+'\n'

    def test_original_and_typed_inventory(self):
        self.assertEqual(G.case_inventory(), G.CASES)
        self.assertEqual(len(G.BASE.case_inventory()),37)
        self.assertEqual(len(G.CASES),8)
        self.assertTrue(set(G.BASE.CASES).isdisjoint(G.CASES))
        self.assertEqual(len(G.AUTHORITY_CASES),4)
        self.assertTrue(all((ROOT/name).is_file() for name in G.SOURCES))

    def test_each_complete_native_verdict(self):
        for case in G.CASES:
            with self.subTest(case=case):
                G.check_verdict(self.completed(case),case)

    def test_failure_skip_race_and_missing_measurement_rejected(self):
        case=G.CASES[0];text=self.completed(case)
        for changed in (text.replace('--- PASS:','--- SKIP:',1),text+'WARNING: DATA RACE\n',text.replace(G.BASE.MEASUREMENT_RECEIPT,'lost'),text.replace(G.TEST,G.BASE.TEST),text.replace(case,G.CASES[1]),text.replace('PASS\n','FAIL\n')):
            with self.assertRaises(ValueError):G.check_verdict(changed,case)

    def test_duplicate_and_missing_original_receipts_rejected(self):
        case=G.CASES[0];text=self.completed(case)
        receipt=next(line for line in text.splitlines() if 'host verified' in line)
        for changed in (text.replace(receipt,receipt+'\n'+receipt),text.replace(receipt,''),text.replace('=== RUN   '+G.TEST+'/'+case+'\n','')):
            with self.assertRaises(ValueError):G.check_verdict(changed,case)

    def test_negative_cannot_borrow_measurement(self):
        case=G.CASES[3]
        text=self.completed(case).replace('--- PASS:', '    desktop_node_chain_darwin_native_test.go:657: '+G.BASE.MEASUREMENT_RECEIPT+'\n--- PASS:',1)
        with self.assertRaises(ValueError):G.check_verdict(text,case)

    def test_complete_original_source_authority(self):
        G.check_authority_verdict(self.authority())
        G.check_source_control(self.authority(True),1)

    def test_compiled_control_requires_exact_failed_original_leaves(self):
        text=self.authority(True)
        for changed,code in ((text,0),(text.replace(G.SOURCE_CONTROL,'unrelated assertion',1),1),(text.replace('/awg2-strong','/foreign'),1),(text.replace('--- FAIL:','--- SKIP:',1),1),(text+'WARNING: DATA RACE\n',1)):
            with self.assertRaises(ValueError):G.check_source_control(changed,code)

    def test_authority_omission_and_foreign_root_rejected(self):
        text=self.authority()
        for changed in (text.replace('/awg2-fast','/foreign'),text.replace(G.AUTHORITY_TEST,G.BASE.AUTHORITY_TEST),text.replace('--- PASS:','--- SKIP:',1)):
            with self.assertRaises(ValueError):G.check_authority_verdict(changed)

    def test_public_admission_and_bounds_remain_original(self):
        source=(ROOT/'cmd/client/multihop_native_routes.go').read_text()
        self.assertIn('return retainedNativeMultihopSelected() && (runtime.GOOS == "windows" || runtime.GOOS == "linux")',source)
        gate=(ROOT/'deploy/test_macos_socks_node_chain_host.py').read_text()
        self.assertIn("'-test.timeout=240s'",gate)
        self.assertIn('timeout=270, sudo=sudo',gate)
        self.assertIn('(*BASE.case_inventory(), *case_inventory())',gate)
        self.assertIn("public_darwin_admission='closed'",gate)
        self.assertIn('BASE.execute_hysteria_control(race_compiler, work, race_environment)',gate)
        native=(ROOT/G.AUTHORITY_SOURCE).read_text()
        self.assertEqual(native.count('Password: password'),1)
        self.assertIn('macOSNodeChainNativeCase(t, scenario)',native)
        peer=(ROOT/'mobile/desktop/node_chain_socks_peer_test.go.tmpl').read_text()
        self.assertIn('nodeSOCKSRunPhysical(true)',peer)
        self.assertIn('len(relays.all)',peer)
        self.assertIn('delete(peer.paired.entry.rules, "udp/10.79.0.1:8388")',peer)


if __name__=='__main__':unittest.main()
