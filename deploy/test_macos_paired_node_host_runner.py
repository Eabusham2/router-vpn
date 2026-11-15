#!/usr/bin/env python3
"""Causal verdict and source controls for the actual paired Darwin host gate."""
from pathlib import Path
import importlib.util
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('paired_host_gate',ROOT/'deploy/test_macos_paired_node_host.py')
G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)
class PairedHostGate(unittest.TestCase):
    def complete(self,case):
        lines=['=== RUN   '+G.TEST,'=== RUN   '+G.TEST+'/'+case,
          '    desktop_node_host_darwin_native_test.go:1: '+G.receipt(case)]
        if case.endswith('/mtu-rollback'): lines+=['    desktop_node_host_darwin_mtu_native_test.go:1: '+G.MTU_RECEIPT]
        return '\n'.join(lines+['--- PASS: '+G.TEST+' (1.0s)','    --- PASS: '+G.TEST+'/'+case+' (1.0s)','PASS'])+'\n'
    def test_all_exact_cases(self):
        self.assertEqual(G.case_inventory(),G.CASES)
        self.assertEqual(len(G.CASES),69)
        self.assertEqual(len(set(G.CASES)),69)
        for case in G.CASES: G.check_verdict(self.complete(case),case)
    def test_native_proof_receipt_cannot_be_missing_duplicate_or_borrowed(self):
        for case in G.CASES:
            valid=self.complete(case); line='    desktop_node_host_darwin_native_test.go:1: '+G.receipt(case)+'\n'
            for bad in (valid.replace(line,''),valid.replace(line,line+line),valid.replace(G.receipt(case),G.receipt(G.CASES[-1] if case!=G.CASES[-1] else G.CASES[0])),valid.replace('--- PASS:','--- SKIP:',1),valid+'WARNING: DATA RACE\n',valid.replace('=== RUN   '+G.TEST+'\n',''),valid+'PASS\n'):
                with self.subTest(case=case),self.assertRaises(ValueError):G.check_verdict(bad,case)
    def test_actual_mtu_receipt_required_only_for_full_mtu_case(self):
        for case in G.CASES:
            valid=self.complete(case);line='    desktop_node_host_darwin_mtu_native_test.go:1: '+G.MTU_RECEIPT+'\n'
            bad=valid.replace(line,'') if case.endswith('/mtu-rollback') else valid.replace('--- PASS:',line+'--- PASS:',1)
            with self.subTest(case=case),self.assertRaises(ValueError):G.check_verdict(bad,case)
    def test_public_routes_and_inventory_cannot_be_comment_decoys(self):
        source=(ROOT/'cmd/client/desktop_node_host_darwin_native_test.go').read_text()
        for needle in ('mux.HandleFunc("/api/connect", a.connect)','mux.HandleFunc("/api/disconnect", a.disconnect)','registerMTURetestRoute(mux, a)','"mtu-rollback"','"awg2-strong", "shadowsocks"'):
            bad=source.replace(needle,'removedOriginalBoundary',1)+'\n// '+needle+'\n'
            with self.subTest(needle=needle),self.assertRaises(ValueError):G.case_inventory(bad)
    def test_platform_requires_explicit_real_acceptance(self):
        for environment in ({},{G.FLAG:'0'},{G.FLAG:'1','HOMEVPN_MTU_BENCH_FAKE':'1'}):
            with self.assertRaises(ValueError):G.required_host(environment)
if __name__=='__main__': unittest.main()
