#!/usr/bin/env python3
"""Fail-closed inventory and receipt controls for the installed paired SS gate."""
from pathlib import Path
import importlib.util
import inspect
import json
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('paired_ss_host', ROOT/'deploy/test_macos_paired_ss_execution_host.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def output(case):
    counters = dict(case=case, launches=1, entry_raw_udp=1, entry_proofs=1,
                    final_raw_tcp=1, final_tcp=0 if case=='wg-wrong-final-key' else 1,
                    final_proofs=0 if case=='wg-wrong-final-key' else 1, auth_tcp=1 if case=='wg-wrong-final-key' else 0,
                    dns=0 if case in (*G.CASES[9:12],'wg-wrong-final-key') else 1)
    return '\n'.join(('=== RUN   '+G.TEST, '=== RUN   '+G.TEST+'/'+case,
        '    desktop_paired_ss_execution_darwin_native_test.go:400: DARWIN_PAIRED_SS_EXECUTION_COUNTERS '+json.dumps(counters),
        '    desktop_paired_ss_execution_darwin_native_test.go:401: '+G.receipt(case),
        '--- PASS: '+G.TEST+' (1.00s)', '    --- PASS: '+G.TEST+'/'+case+' (1.00s)', 'PASS', ''))


class PairedSSInstalledGate(unittest.TestCase):
    def test_exact_inventory_and_original_public_boundaries(self):
        self.assertEqual(G.case_inventory(), G.CASES)
        self.assertEqual(len(G.CASES), 14)
        self.assertEqual(G.SOURCE_TESTS, {**G.PARENT.SOURCE, **G.PARENT.DARWIN})
        source = (ROOT/G.SOURCES[7]).read_text()
        for marker in ('a.nativeMultihopConnect(w, r)', 'macOSImportedExecutionObserve(r.Context(), a)',
                       'a.speedLabSuspendPrevious(snapshot, false)', 'a.speedLabRestoreTemporary(snapshot)',
                       'reflect.DeepEqual(after.Comparison, before.Comparison)', 'aliases.Close(ctx, peer.close)'):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                G.case_inventory(source.replace(marker, 'omittedOriginal()', 1))
        with self.assertRaises(ValueError): G.case_inventory(source.replace('"wg-server", ', '', 1))
        original = (ROOT/'cmd/client/desktop_imported_execution_darwin_native_test.go').read_text()
        self.assertIn('s.Current(ctx)', original)
        self.assertIn('h.readReadyLocked(ctx, false)', original)

    def test_each_actual_receipt_and_counter(self):
        for case in G.CASES: G.check_verdict(output(case), case)
        for field in ('launches', 'entry_raw_udp', 'entry_proofs', 'final_raw_tcp', 'final_tcp', 'final_proofs', 'dns'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                G.check_verdict(output('wg-server').replace('"'+field+'": 1', '"'+field+'": 0'), 'wg-server')
        for field in ('native_joined=true', 'relay_joined=true', 'aliases_retired=true'):
            with self.assertRaises(ValueError): G.check_verdict(output('wg-server').replace(field, field.replace('true','false')), 'wg-server')
        with self.assertRaises(ValueError): G.check_verdict(output('wg-wrong-final').replace('"dns": 0','"dns": 1'),'wg-wrong-final')

    def test_wrong_key_requires_authentication_without_plaintext(self):
        raw = output('wg-wrong-final-key')
        for old,new in (('"auth_tcp": 1','"auth_tcp": 0'), ('"final_tcp": 0','"final_tcp": 1'),
                        ('"final_proofs": 0','"final_proofs": 1'), ('"dns": 0','"dns": 1')):
            with self.subTest(old=old), self.assertRaises(ValueError):
                G.check_verdict(raw.replace(old,new), 'wg-wrong-final-key')

    def test_missing_duplicate_foreign_or_failed_output_refused(self):
        raw=output('wg-server')
        for changed in (raw.replace(G.receipt('wg-server'),''), raw.replace('"launches": 1','"launches": 1, "launches": 1'),
                        raw.replace(G.receipt('wg-server'), G.receipt('awg2-fast-server')),
                        raw.replace('--- PASS:', '--- FAIL:',1), raw+'WARNING: DATA RACE\n', raw+'--- SKIP: skipped (0.1s)\n',
                        raw.replace('PASS\n','PASS\nPASS\n')):
            with self.assertRaises(ValueError): G.check_verdict(changed,'wg-server')

    def test_registered_exact_peer_and_portable_worker(self):
        preparer=G.load('paired_ss_preparer','prepare-desktop-external.py')
        with tempfile.TemporaryDirectory() as directory:
            core=Path(directory);preparer.copy_encrypted_peer_templates(core)
            self.assertEqual((core/G.PEER_TARGET).read_bytes(),(ROOT/G.PEER_TEMPLATE).read_bytes())
            self.assertEqual((core/G.PROJECTOR.TARGET).read_bytes(),G.PROJECTOR.copies()[G.PROJECTOR.TARGET])
        source=(ROOT/G.PEER_TEMPLATE).read_text()
        for marker in ('source.Schema != 1', 'len(source.Nodes) != 2', 'policy.NativeCarrierRequired()',
                       'desktopNodeChainPeerStartBoundsWithFinal(', 'mobilemultihop.NewNodeChainServerPolicy(',
                       'runner.joined()', 'manager.Close(ctx)', 'importedExecutionJoinHTTP(ctx, done, &serveError)',
                       'outbound.Password != request.Peer.FinalPassword'):
            self.assertIn(marker,source)
        self.assertNotIn('NodeChainPending, nil',source)

    def test_explicit_host_and_original_bounds(self):
        with patch.object(G.EXTERNAL.platform,'system',return_value='Linux'), self.assertRaises(ValueError):
            G.required_host({G.FLAG:'1'})
        for env in ({}, {G.FLAG:'0'}, {G.FLAG:'1','HOMEVPN_MTU_BENCH_FAKE':'1'}):
            with self.assertRaises(ValueError): G.required_host(env)
        source=inspect.getsource(G.execute)
        for marker in ('timeout=300', "'-test.timeout=120s'", "'-test.timeout=240s'", 'timeout=250',
                       'source_identity(core) != before', 'BASE.repository_identity(required_commit) != repository',
                       'alias.execute(root=ROOT, go=str(race_compiler))', 'execute_peer_close_controls(ROOT,'):
            self.assertIn(marker,source)

if __name__=='__main__': unittest.main()
