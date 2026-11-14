#!/usr/bin/env python3
"""Fail-closed inventory and verdict checks for installed HTTP(S) CONNECT native acceptance."""
from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('typed_installed_gate', ROOT/'deploy/test_macos_connect_node_chain_host.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class TypedInstalledGate(unittest.TestCase):
    def completed(self, case):
        lines = ['=== RUN   '+G.TEST, '=== RUN   '+G.TEST+'/'+case]
        if case in G.MEASUREMENT_CASES:
            lines.append('    desktop_node_chain_darwin_native_test.go:657: '+G.BASE.MEASUREMENT_RECEIPT)
            lines.append('    desktop_node_chain_darwin_native_test.go:657: '+G.FIFTY_RECEIPT)
        lines.append('    desktop_node_chain_darwin_native_test.go:657: '+G.STREAMS_RECEIPT)
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
        self.assertEqual(len(G.SOCKS.case_inventory()),8)
        self.assertEqual(len(G.CASES),22)
        self.assertTrue(set(G.BASE.CASES).isdisjoint(G.CASES))
        self.assertEqual(len(G.AUTHORITY_CASES),7)
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
        for changed,code in ((text,0),(text.replace(G.SOURCE_CONTROL,'unrelated assertion',1),1),(text.replace('/https-awg-strong','/foreign'),1),(text.replace('--- FAIL:','--- SKIP:',1),1),(text+'WARNING: DATA RACE\n',1)):
            with self.assertRaises(ValueError):G.check_source_control(changed,code)

    def test_authority_omission_and_foreign_root_rejected(self):
        text=self.authority()
        for changed in (text.replace('/http-awg-fast','/foreign'),text.replace(G.AUTHORITY_TEST,G.BASE.AUTHORITY_TEST),text.replace('--- PASS:','--- SKIP:',1)):
            with self.assertRaises(ValueError):G.check_authority_verdict(changed)

    def test_public_admission_and_bounds_remain_original(self):
        source=(ROOT/'cmd/client/desktop_node_chain_connect_admission.go').read_text()
        self.assertIn('targetOS == "linux" || targetOS == "windows"',source)
        self.assertNotIn('targetOS == "darwin"',source)
        gate=(ROOT/'deploy/test_macos_connect_node_chain_host.py').read_text()
        self.assertIn("'-test.timeout=240s'",gate)
        self.assertIn('timeout=270, sudo=sudo',gate)
        self.assertIn('(*BASE.case_inventory(), *SOCKS.case_inventory(), *case_inventory())',gate)
        self.assertIn('SOCKS.execute_typed_control(race_compiler, work, race_environment)',gate)
        self.assertIn("public_darwin_admission='closed'",gate)
        self.assertIn('BASE.execute_hysteria_control(race_compiler, work, race_environment)',gate)
        native=(ROOT/G.AUTHORITY_SOURCE).read_text()
        self.assertEqual(native.count('Password: password'),1)
        self.assertIn('macOSNodeChainNativeCase(t, scenario)',native)
        peer=(ROOT/'mobile/desktop/node_chain_connect_peer_test.go.tmpl').read_text()
        self.assertIn('desktopNodeChainReferenceAddressPair(address, client)',peer)
        self.assertIn('OpenConnectStreams: router.streams.Load()',peer)
        self.assertIn('provider.awaitCertificateRefusal(ctx)',peer)
        self.assertIn('UOT.NewRouter(&desktopImportedCONNECTRouter',peer)
        self.assertIn('delete(peer.paired.entry.rules, "udp/10.79.0.1:8388")',peer)

    def test_connect_receipts_cannot_be_omitted_borrowed_or_repeated(self):
        for case in G.CASES:
            output=self.completed(case)
            markers=[G.STREAMS_RECEIPT]+([G.FIFTY_RECEIPT] if case in G.MEASUREMENT_CASES else [])
            for marker in markers:
                line=next(row for row in output.splitlines() if row.endswith(marker))
                for changed in (output.replace(line,''),output.replace(line,line+'\n'+line),output.replace(marker,'actual installed Darwin CONNECT foreign')):
                    with self.subTest(case=case,marker=marker),self.assertRaises(ValueError):G.check_verdict(changed,case)
        negative=G.CASES[3]
        output=self.completed(negative).replace('--- PASS:', '    source.go:1: '+G.FIFTY_RECEIPT+'\n--- PASS:',1)
        with self.assertRaises(ValueError):G.check_verdict(output,negative)

    def test_actual_proxy_source_and_final_uot_are_distinct(self):
        native=(ROOT/G.AUTHORITY_SOURCE).read_text()
        self.assertIn('source.Schema != 4',native)
        self.assertIn('nativecomposite.SSServiceAsset',native)
        self.assertNotIn('out["udp_over_tcp"] =',native)
        self.assertIn('"uot_version": 2',native)
        self.assertIn('raw := files["sing-box.json"]',native)
        self.assertIn('len(out) != 6',native)
        self.assertIn('CONNECTAuthRefusals == 0',native)
        self.assertIn('CONNECTTLSRefusals == 0',native)
        self.assertIn('middle.RawUDP != 0',native)
        self.assertIn('reply.Final.FinalRawUDP != 0',native)
        peer=(ROOT/'mobile/desktop/node_chain_connect_peer_test.go.tmpl').read_text()
        self.assertIn('ROUTERVPN_CONNECT_INSTALLED_REFERENCE',peer)
        self.assertIn('request.Paired.BenchmarkPort != 45998',peer)
        self.assertIn('ConnectServerName: serverName',peer)
        self.assertNotIn('SOCKS5',peer)


if __name__=='__main__':unittest.main()
