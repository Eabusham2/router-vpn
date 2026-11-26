#!/usr/bin/env python3
"""Finite source/projection/verdict controls for the actual Darwin host gate."""
from pathlib import Path
import importlib.util
import inspect
import json
import tempfile
import os
import subprocess
import hashlib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('imported_native_host_gate', ROOT/'deploy/test_macos_connect_execution_host.py')
GATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)


def output(case):
    root = GATE.TEST
    counters = dict(case=case,launches=1,restore_launches=int(case in GATE.CASES[:6] and not case.endswith('auto-local')),comparison_trials=2 if '-auto-' in case else 0,entry_raw_udp=1,entry_tcp=1,entry_proofs=1,
                    middle_raw_tcp=1,middle_tcp=1,middle_public=1,final_raw_tcp=1,final_tcp=1,final_proofs=1,dns=1,
                    middle_raw_udp=0,final_raw_udp=0,auth_refusals=0,tls_refusals=0,open_streams=0,entry_layer=GATE.ENTRY_LAYERS[case],entry_layer_packets=int(GATE.ENTRY_LAYERS[case]!='off'),entry_layer_ciphertext=int(GATE.ENTRY_LAYERS[case]!='off'),entry_layer_auth=0)
    if case in ('http-wrong-auth','https-wrong-auth','https-tls-name'):
        for key in ('middle_tcp','middle_public','final_raw_tcp','final_tcp','final_proofs','dns'):counters[key]=0
        counters['tls_refusals' if case=='https-tls-name' else 'auth_refusals']=1
    elif case=='http-wrong-public':
        for key in ('final_raw_tcp','final_tcp','final_proofs','dns'):counters[key]=0
    elif case=='https-wrong-final':
        for key in ('final_tcp','final_proofs','dns'):counters[key]=0
    return '\n'.join(('=== RUN   '+root, '=== RUN   '+root+'/'+case,
                      '    desktop_connect_execution_darwin_native_test.go:510: DARWIN_CONNECT_EXECUTION_COUNTERS '+json.dumps(counters),
                      '    desktop_connect_execution_darwin_native_test.go:511: '+GATE.receipt(case),
                      '--- PASS: '+root+' (1.00s)', '    --- PASS: '+root+'/'+case+' (1.00s)', 'PASS', ''))


class ImportedExecutionHostGate(unittest.TestCase):
    def test_exact_shipping_inventory(self):
        self.assertEqual(GATE.case_inventory(), GATE.CASES)
        self.assertEqual(len(GATE.CASES), 14)
        self.assertEqual(sum(1+len(x) for x in GATE.SOURCE_TESTS.values()), 38)
        for case in GATE.CASES:
            GATE.check_verdict(output(case), case)

    def test_retained_choice_never_reuses_stale_measurements_or_reranks(self):
        for case in GATE.CASES:
            for field in ('comparison_trials', 'restore_launches'):
                before = (2 if '-auto-' in case else 0) if field=='comparison_trials' else int(case in GATE.CASES[:6] and not case.endswith('auto-local'))
                with self.subTest(case=case,field=field),self.assertRaises(ValueError):
                    GATE.check_verdict(output(case).replace('"'+field+'": '+str(before),'"'+field+'": '+str(before+1)),case)
        source=(ROOT/GATE.SOURCES[7]).read_text()
        for anchor in ('restoreLaunches != expectedLaunches','len(result.Measurements) != 0','len(result.Measurements) != 2','math.Abs(*m.ScoreMS-(m.LastNodeMS/2+m.ExternalMS/2))'):
            with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                GATE.case_inventory(source.replace(anchor,'omitted_original_measurement',1))

    def test_actual_portable_product_inventory(self):
        expected = {
            'TestDesktopCONNECTTrioExecutionSelectionBounds': {f'{protocol}/{mode}/{choice}'
                for protocol in ('http-connect', 'https-connect')
                for mode in ('wg', 'awg2-fast', 'awg2-strong') for choice in ('server', 'auto')},
            'TestDesktopCONNECTTrioExecutionSavedProfileRetainsSource': {f'{protocol}/{choice}'
                for protocol in ('http-connect', 'https-connect') for choice in ('server', 'auto')},
        }
        for root, leaves in expected.items():
            self.assertEqual(set(GATE.SOURCE_TESTS[root]), leaves)
        self.assertNotIn('TestDesktopCONNECTTrioExecutionPublicConnectUsesOriginalChild', GATE.SOURCE_TESTS)
        self.assertNotIn('TestDesktopCONNECTTrioExecutionRestoreRetainsChosenSource', GATE.SOURCE_TESTS)

    def test_omitted_case_source(self):
        source = (ROOT/GATE.SOURCES[7]).read_text()
        with self.assertRaises(ValueError):
            GATE.case_inventory(source.replace('"http-wrong-public",', '', 1))

    def test_public_restore_proof_cleanup_anchors(self):
        source = (ROOT/GATE.SOURCES[7]).read_text()
        for anchor in ('a.nativeMultihopConnect(w, r)', 's.Current(ctx)', 'h.readReadyLocked(ctx, false)',
                       'a.speedLabSuspendPrevious(snapshot, false)', 'a.speedLabRestoreTemporary(snapshot)',
                       'reflect.DeepEqual(after.Ready.Progress.Comparison.Winner, before.Ready.Progress.Comparison.Winner)', 'aliases.Close(ctx, peer.close)'):
            with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                GATE.case_inventory(source.replace(anchor, 'omittedBoundary()', 1))

    def test_missing_duplicate_wrong_case_receipt(self):
        case = GATE.CASES[0]; original = output(case); marker = GATE.receipt(case)
        for changed in (original.replace(marker, ''), original.replace(marker, marker+'\n    desktop_connect_execution_darwin_native_test.go:512: '+marker),
                        original.replace(marker, GATE.receipt(GATE.CASES[1]))):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                GATE.check_verdict(changed, case)

    def test_each_ownership_field_is_required(self):
        for case in GATE.CASES:
            for field in ('native_joined=true', 'relay_joined=true', 'aliases_retired=true'):
                with self.subTest(case=case, field=field), self.assertRaises(ValueError):
                    GATE.check_verdict(output(case).replace(field, field.replace('true', 'false')), case)

    def test_actual_counter_omission_or_false_positive(self):
        original=output('http-wg-server')
        for field in ('launches','entry_raw_udp','entry_tcp','entry_proofs','middle_public','final_proofs','dns'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                GATE.check_verdict(original.replace('"'+field+'": 1', '"'+field+'": 0'), 'http-wg-server')
        for case, field in (('http-wrong-public','final_proofs'),('https-wrong-final','dns')):
            with self.subTest(case=case), self.assertRaises(ValueError):
                GATE.check_verdict(output(case).replace('"'+field+'": 0', '"'+field+'": 1'),case)
        with self.assertRaises(ValueError):
            GATE.check_verdict(original.replace('"launches": 1','"launches": 1, "launches": 1'), 'http-wg-server')

    def test_verdict_omission_duplicate_skip_fail(self):
        case=GATE.CASES[0]; original=output(case)
        for changed in (original.replace('    --- PASS: '+GATE.TEST+'/'+case+' (1.00s)\n',''),
                        original.replace('PASS\n','PASS\nPASS\n'), original+'--- SKIP: foreign (0.00s)\n',
                        original+'WARNING: DATA RACE\n', original.replace('--- PASS:', '--- FAIL:',1)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                GATE.check_verdict(changed,case)

    def test_receipt_cannot_follow_completion(self):
        case=GATE.CASES[0]; lines=output(case).splitlines(); receipt=lines.pop(3); lines.insert(-1,receipt)
        with self.assertRaises(ValueError):
            GATE.check_verdict('\n'.join(lines)+'\n',case)

    def test_own_host_flag_and_environment_not_mutated(self):
        environment={GATE.FLAG:'1'}; original=dict(environment)
        def required(value):
            self.assertEqual(value[GATE.EXTERNAL.FLAG], '1')
            return 'darwin/arm64', 501
        with patch.object(GATE.EXTERNAL,'required_host',side_effect=required):
            self.assertEqual(GATE.required_host(environment),('darwin/arm64',501))
        self.assertEqual(environment,original)
        for absent in ({}, {GATE.FLAG:'0'}, {GATE.EXTERNAL.FLAG:'1'}, {GATE.FLAG:'1', 'HOMEVPN_MTU_BENCH_FAKE':'1'}):
            with self.assertRaises(ValueError): GATE.required_host(absent)

    def test_foreign_platform_still_refused(self):
        with patch.object(GATE.EXTERNAL.platform,'system',return_value='Linux'), self.assertRaises(ValueError):
            GATE.required_host({GATE.FLAG:'1'})

    def test_alias_actual_api_and_before_mutations(self):
        alias=GATE.load('imported_alias_signature','test_macos_imported_execution_alias.py')
        inspect.signature(alias.execute).bind(root=ROOT, go='/captured/compiler')
        source=inspect.getsource(GATE.execute)
        self.assertIn('alias.execute(root=ROOT, go=str(race_compiler))',source)
        self.assertLess(source.index('alias.execute('), source.index("signed = work/'sealed-bundle'"))
        self.assertNotIn('alias.execute(go=str(race_compiler), environment=',source)

    def test_actual_shipping_process_projection(self):
        copies=GATE.PROJECTOR.copies()
        lease='protocol/routervpnamnezia/routervpn_imported_execution_native_lease_linux_test.go'
        self.assertEqual(set(copies),{GATE.PROJECTOR.TARGET,lease})
        self.assertTrue(copies[lease].startswith(b'//go:build linux && !android\n'))
        self.assertIn(b'func (s *nativeImportedAdmin) multihopNodeChainLease(',copies[lease])
        for missing in copies:
            with self.subTest(missing=missing), patch.object(GATE.PROJECTOR,'_project_sources',return_value={k:v for k,v in copies.items() if k!=missing}), self.assertRaises(ValueError):
                GATE.PROJECTOR.copies()
        with patch.object(GATE.PROJECTOR,'_project_sources',return_value={**copies,'unexpected.go':b'package routervpnamnezia'}), self.assertRaises(ValueError):
            GATE.PROJECTOR.copies()
        source=copies[GATE.PROJECTOR.TARGET].decode()
        for anchor in ('type importedExecutionProcess struct {', 'func (p *importedExecutionProcess) Stop(',
                       'func (s *importedExecutionAdmin) multihopNodeChainLease(',
                       'func captureImportedExecutionImage(path string)'):
            self.assertIn(anchor,source)
        self.assertIn('cmd/router-agent/multihop_node_chain_process.go',GATE.PROJECTOR.SOURCES)
        with self.assertRaises(ValueError): GATE.PROJECTOR.between('start start end','start','end')

    def test_registered_peer_and_process_writer(self):
        source=(ROOT/'deploy/prepare-desktop-external.py').read_text()
        self.assertIn('node_chain_connect_execution_peer_test.go.tmpl',source)
        self.assertIn('IMPORTED_EXECUTION_TEST.copies()',source)
        self.assertIn('*IMPORTED_EXECUTION_TEST.inputs()',source)
        preparer=GATE.load('imported_actual_desktop_writer','prepare-desktop-external.py')
        with tempfile.TemporaryDirectory() as temporary:
            core=Path(temporary)
            preparer.copy_encrypted_peer_templates(core)
            self.assertEqual((core/GATE.PEER_TARGET).read_bytes(), (ROOT/GATE.PEER_TEMPLATE).read_bytes())
            for target,original in GATE.PROJECTOR.copies().items():
                self.assertEqual((core/target).read_bytes(),original)
            before={str(path.relative_to(core)):path.read_bytes() for path in core.rglob('*.go')}
            preparer.copy_encrypted_peer_templates(core)
            self.assertEqual(before,{str(path.relative_to(core)):path.read_bytes() for path in core.rglob('*.go')})
        fixture=(ROOT/GATE.SOURCES[7]).read_text()
        self.assertIn('"sing-box-routervpn"',fixture)
        self.assertEqual(GATE.BUILD.binary_name('darwin/arm64'),'sing-box-routervpn')

    def test_partial_start_retains_original_cleanup_owner(self):
        source=(ROOT/GATE.SOURCES[7]).read_text()
        case=source[source.index('func macOSCONNECTExecutionNativeCase('):]
        self.assertLess(case.index('peer = &macOSCONNECTExecutionPeer{'),case.index('startMacOSCONNECTExecutionPeer(t, peer, mode, protocol, fault)'))
        self.assertLess(case.index('controllerJoined = false'),case.index('fixture.start()'))
        self.assertLess(case.index('macOSCONNECTExecutionJoinPartialController(cleanup, fixture)'),case.index('fixture.start()'))
        join=source[source.index('func macOSCONNECTExecutionJoinPartialController('):source.index('func macOSCONNECTExecutionNativeCase(')]
        for guard in ('os.SameFile(fixture.root, current)', 'fixture.supervisor.Process.Signal(syscall.SIGTERM)', 'case outcome := <-fixture.joined:', 'fixture.joined <- outcome', 'case <-peer.joined:', 'ownedDesktopLock(path, true)', 'case <-ctx.Done():'):
            self.assertIn(guard,join)
        self.assertLess(join.index('case outcome := <-fixture.joined:'),join.index('ownedDesktopLock(path, true)'))

        starter=source[source.index('func startMacOSCONNECTExecutionPeer('):source.index('func TestMacOSCONNECTTrioExecutionNative(')]
        self.assertLess(starter.index('p.peer ='),starter.index('peer.command.Start()'))
        self.assertLess(starter.index('p.started = true'),starter.index('p.exchange('))
        self.assertNotIn('StdoutPipe()',starter)
        self.assertNotIn('StdinPipe()',starter)
        self.assertIn('if !controllerJoined {',case)

    def test_source_compiler_and_native_deadlines_remain_separate(self):
        source=inspect.getsource(GATE.execute)
        for anchor in ("'-test.timeout=120s'", "timeout=130", "'-test.timeout=240s'", "timeout=250", "timeout=300", "CONTROLLER.UID.RACE.capture(core, compiler, captured)"):
            self.assertIn(anchor,source)
        self.assertEqual(source.count('for case in CASES:'),1)
        self.assertIn('BASE.repository_identity(required_commit) != repository',source)
        self.assertIn('source_identity(core) != before',source)


    def test_each_protocol_boundary_counter_is_required(self):
        for case,field in (('http-wrong-auth','auth_refusals'),('https-wrong-auth','auth_refusals'),('https-tls-name','tls_refusals')):
            with self.subTest(case=case),self.assertRaises(ValueError):
                GATE.check_verdict(output(case).replace('"'+field+'": 1','"'+field+'": 0'),case)
        for field in ('middle_raw_udp','final_raw_udp','open_streams'):
            with self.subTest(field=field),self.assertRaises(ValueError):
                GATE.check_verdict(output('http-wg-server').replace('"'+field+'": 0','"'+field+'": 1'),'http-wg-server')
    def test_both_protocols_and_all_choices_have_actual_positive_cases(self):
        self.assertEqual(tuple(GATE.CASES[:6]),('http-wg-server','http-awg-fast-auto-local','http-awg-strong-auto-server','https-awg-strong-server','https-wg-auto-local','https-awg-fast-auto-server'))
        for case in GATE.CASES[:6]:
            self.assertIn('restored=true',GATE.receipt(case))
        self.assertIn('cleanup_retry=true',GATE.receipt('https-held-cleanup'))
        with self.assertRaises(ValueError):GATE.check_verdict(output('https-held-cleanup').replace('cleanup_retry=true','cleanup_retry=false'),'https-held-cleanup')
    def test_peer_retains_original_connect_and_uot_factories(self):
        source=(ROOT/GATE.PEER_TEMPLATE).read_text()
        for anchor in ('mobilemultihop.NewNodeChainCONNECTSource(configure.LocalSource)', 'mobilemultihop.NewNodeChainCONNECTServerPolicy(string(suffixRaw))','desktopStartImportedCONNECTPeerAt(', 'peer.paired.final.streamRouter = UOT.NewRouter(', 'runner := &importedExecutionRunner{', 'provider.close()', 'router.streams.Load() != 0'):
            self.assertIn(anchor,source)
        self.assertNotIn('mobilemultihop.NewNodeChainServerPolicy(',source)
        self.assertNotIn('mobilemultihop.NewNodeChain(configure.LocalSource)',source)
    def test_held_cleanup_uses_original_public_transaction_and_retained_owner(self):
        source=(ROOT/GATE.SOURCES[7]).read_text()
        for anchor in ('original.enter(r.Context())','a.disconnect(result, request)','original.gate <- struct{}{}','retained != owner','retained.session.launch.chain.platform.host != original','context.DeadlineExceeded.Error()'):
            self.assertIn(anchor,source)

    def test_actual_entry_layers_are_independent_and_finite(self):
        self.assertEqual(tuple(GATE.ENTRY_LAYERS[c] for c in GATE.CASES[:6]),('off','aes-256-gcm','aes-256-gcm+xor-whitening','aes-256-gcm','aes-256-gcm+xor-whitening','off'))
        for case in GATE.CASES[:6]:
            for field in ('entry_layer_packets','entry_layer_ciphertext'):
                before=1 if GATE.ENTRY_LAYERS[case]!='off' else 0
                with self.subTest(case=case,field=field),self.assertRaises(ValueError):
                    GATE.check_verdict(output(case).replace('"'+field+'": '+str(before),'"'+field+'": '+str(1-before)),case)
        source=(ROOT/GATE.PEER_TEMPLATE).read_text()
        self.assertIn('request.Layers.Final != "off"',source)
        self.assertIn('layers.entryProvider(t, layerRequest, peer, local)',source)

    def test_each_peer_source_boundary_is_mandatory(self):
        source=(ROOT/GATE.PEER_TEMPLATE).read_text()
        for anchor in GATE.peer_inventory():
            with self.subTest(anchor=anchor),self.assertRaises(ValueError):
                GATE.peer_inventory(source.replace(anchor,'omitted_original_peer_boundary',1))

if __name__=='__main__':unittest.main()
