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
spec = importlib.util.spec_from_file_location('imported_native_host_gate', ROOT/'deploy/test_macos_imported_execution_host.py')
GATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)


def output(case):
    root = GATE.TEST
    counters = dict(case=case, launches=1, entry_raw_udp=1, entry_tcp=1, entry_proofs=1,
                    middle_raw_tcp=1, middle_tcp=1, middle_public=1, final_raw_tcp=1, final_tcp=1,
                    final_proofs=0 if case=='wg-wrong-public' else 1,
                    dns=0 if case in ('wg-wrong-public','wg-wrong-final') else 1)
    return '\n'.join(('=== RUN   '+root, '=== RUN   '+root+'/'+case,
                      '    desktop_imported_execution_darwin_native_test.go:510: DARWIN_IMPORTED_EXECUTION_COUNTERS '+json.dumps(counters),
                      '    desktop_imported_execution_darwin_native_test.go:511: '+GATE.receipt(case),
                      '--- PASS: '+root+' (1.00s)', '    --- PASS: '+root+'/'+case+' (1.00s)', 'PASS', ''))


class ImportedExecutionHostGate(unittest.TestCase):
    def test_exact_shipping_inventory(self):
        self.assertEqual(GATE.case_inventory(), GATE.CASES)
        self.assertEqual(len(GATE.CASES), 13)
        self.assertEqual(sum(1+len(x) for x in GATE.SOURCE_TESTS.values()), 40)
        for case in GATE.CASES:
            GATE.check_verdict(output(case), case)

    def test_omitted_case_source(self):
        source = (ROOT/GATE.SOURCES[7]).read_text()
        with self.assertRaises(ValueError):
            GATE.case_inventory(source.replace('"wg-wrong-public", ', '', 1))

    def test_public_restore_proof_cleanup_anchors(self):
        source = (ROOT/GATE.SOURCES[7]).read_text()
        for anchor in ('a.nativeMultihopConnect(w, r)', 's.Current(ctx)', 'h.readReadyLocked(ctx, false)',
                       'a.speedLabSuspendPrevious(snapshot, false)', 'a.speedLabRestoreTemporary(snapshot)',
                       'reflect.DeepEqual(after.Comparison, before.Comparison)', 'aliases.Close(ctx, peer.close)'):
            with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                GATE.case_inventory(source.replace(anchor, 'omittedBoundary()', 1))

    def test_missing_duplicate_wrong_case_receipt(self):
        case = GATE.CASES[0]; original = output(case); marker = GATE.receipt(case)
        for changed in (original.replace(marker, ''), original.replace(marker, marker+'\n    desktop_imported_execution_darwin_native_test.go:512: '+marker),
                        original.replace(marker, GATE.receipt(GATE.CASES[1]))):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                GATE.check_verdict(changed, case)

    def test_each_ownership_field_is_required(self):
        for case in GATE.CASES:
            for field in ('native_joined=true', 'relay_joined=true', 'aliases_retired=true'):
                with self.subTest(case=case, field=field), self.assertRaises(ValueError):
                    GATE.check_verdict(output(case).replace(field, field.replace('true', 'false')), case)

    def test_actual_counter_omission_or_false_positive(self):
        original=output('wg-server')
        for field in ('launches','entry_raw_udp','entry_tcp','entry_proofs','middle_public','final_proofs','dns'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                GATE.check_verdict(original.replace('"'+field+'": 1', '"'+field+'": 0'), 'wg-server')
        for case, field in (('wg-wrong-public','final_proofs'),('wg-wrong-final','dns')):
            with self.subTest(case=case), self.assertRaises(ValueError):
                GATE.check_verdict(output(case).replace('"'+field+'": 0', '"'+field+'": 1'),case)
        with self.assertRaises(ValueError):
            GATE.check_verdict(original.replace('"launches": 1','"launches": 1, "launches": 1'), 'wg-server')

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
        self.assertEqual(tuple(copies),(GATE.PROJECTOR.TARGET,))
        source=copies[GATE.PROJECTOR.TARGET].decode()
        for anchor in ('type importedExecutionProcess struct {', 'func (p *importedExecutionProcess) Stop(',
                       'func (s *importedExecutionAdmin) multihopNodeChainLease(',
                       'func captureImportedExecutionImage(path string)'):
            self.assertIn(anchor,source)
        self.assertIn('cmd/router-agent/multihop_node_chain_process.go',GATE.PROJECTOR.SOURCES)
        with self.assertRaises(ValueError): GATE.PROJECTOR.between('start start end','start','end')

    def test_registered_peer_and_process_writer(self):
        source=(ROOT/'deploy/prepare-desktop-external.py').read_text()
        self.assertIn('node_chain_imported_execution_peer_test.go.tmpl',source)
        self.assertIn('IMPORTED_EXECUTION_TEST.copies()',source)
        self.assertIn('*IMPORTED_EXECUTION_TEST.inputs()',source)
        preparer=GATE.load('imported_actual_desktop_writer','prepare-desktop-external.py')
        with tempfile.TemporaryDirectory() as temporary:
            core=Path(temporary)
            preparer.copy_encrypted_peer_templates(core)
            self.assertEqual((core/GATE.PEER_TARGET).read_bytes(), (ROOT/GATE.PEER_TEMPLATE).read_bytes())
            self.assertEqual((core/GATE.PROJECTOR.TARGET).read_bytes(), GATE.PROJECTOR.copies()[GATE.PROJECTOR.TARGET])
            before={str(path.relative_to(core)):path.read_bytes() for path in core.rglob('*.go')}
            preparer.copy_encrypted_peer_templates(core)
            self.assertEqual(before,{str(path.relative_to(core)):path.read_bytes() for path in core.rglob('*.go')})
        fixture=(ROOT/GATE.SOURCES[7]).read_text()
        self.assertIn('"sing-box-routervpn"',fixture)
        self.assertEqual(GATE.BUILD.binary_name('darwin/arm64'),'sing-box-routervpn')

    def test_partial_start_retains_original_cleanup_owner(self):
        source=(ROOT/GATE.SOURCES[7]).read_text()
        case=source[source.index('func macOSImportedExecutionNativeCase('):]
        self.assertLess(case.index('peer = &macOSImportedExecutionPeer{}'),case.index('startMacOSImportedExecutionPeer(t, peer, mode)'))
        self.assertLess(case.index('controllerJoined = false'),case.index('fixture.start()'))
        starter=source[source.index('func startMacOSImportedExecutionPeer('):source.index('func TestMacOSImportedTrioExecutionNative(')]
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


def execute_peer_close_controls(root=ROOT, go='go', environment=None):
    source = (Path(root)/GATE.SOURCES[7]).read_text()
    first = source.index('func (p *macOSImportedExecutionPeer) close(ctx context.Context) error {')
    last = source.index('func startMacOSImportedExecutionPeer(', first)
    body = source[first:last]
    peer_source=(Path(root)/GATE.PEER_TEMPLATE).read_text()
    first=peer_source.index('func importedExecutionJoinHTTP(')
    last=peer_source.index('func TestRouterVPNDesktopImportedExecutionReferenceProcess(',first)
    http_body=peer_source[first:last]
    body += http_body
    declaration = """package probe
import("bufio";"context";"encoding/json";"errors";"io";"os";"strings";"net/http")
type macOSNodeChainPeer struct{ input,output *os.File; reader *bufio.Reader; done chan struct{}; failure error }
type macOSImportedExecutionPeer struct{peer *macOSNodeChainPeer; started,joined,quitAttempted bool}
"""
    tests = r'''package probe
import("bufio";"context";"encoding/json";"os";"testing";"errors";"net/http")
func fixture(t *testing.T)(*macOSImportedExecutionPeer,*os.File,*os.File){t.Helper();ir,iw,e:=os.Pipe();if e!=nil{t.Fatal(e)};or,ow,e:=os.Pipe();if e!=nil{t.Fatal(e)};t.Cleanup(func(){ir.Close();iw.Close();or.Close();ow.Close()});return &macOSImportedExecutionPeer{started:true,peer:&macOSNodeChainPeer{input:iw,output:or,reader:bufio.NewReader(or),done:make(chan struct{})}},ir,ow}
func TestOriginalQuitRetry(t *testing.T){p,input,output:=fixture(t);ctx,cancel:=context.WithCancel(context.Background());cancel();if p.close(ctx)==nil||p.joined||!p.quitAttempted{t.Fatal("original quit attempt was not retained")};var command map[string]string;if json.NewDecoder(input).Decode(&command)!=nil||command["command"]!="quit"{t.Fatal("original shutdown command missing")};output.WriteString("{\"joined\":true}\nPASS\n");output.Close();close(p.peer.done);if e:=p.close(context.Background());e!=nil||!p.joined{t.Fatal("original joined retry failed",e)}}
func TestOriginalJoinReceipt(t *testing.T){p,_,output:=fixture(t);output.WriteString("{\"joined\":false}\nPASS\n");output.Close();close(p.peer.done);if p.close(context.Background())==nil||p.joined{t.Fatal("missing original joined receipt accepted")}}
func TestOriginalHTTPJoinRetry(t *testing.T){done:=make(chan struct{});original:=errors.New("original serve failure");close(done);for i:=0;i<2;i++{if err:=importedExecutionJoinHTTP(context.Background(),done,&original);!errors.Is(err,original){t.Fatal("original Serve failure lost across retry",err)}};normal:=error(http.ErrServerClosed);if e:=importedExecutionJoinHTTP(context.Background(),done,&normal);e!=nil{t.Fatal(e)};ctx,cancel:=context.WithCancel(context.Background());cancel();if !errors.Is(importedExecutionJoinHTTP(ctx,make(chan struct{}),&normal),context.Canceled)||!errors.Is(importedExecutionJoinHTTP(ctx,done,&normal),context.Canceled){t.Fatal("cancelled original HTTP join accepted")};var missing error;if importedExecutionJoinHTTP(context.Background(),done,&missing)==nil{t.Fatal("missing original Serve outcome accepted")}}

'''
    variants = {
        'shipping': (body, 'TestOriginal(QuitRetry|JoinReceipt|HTTPJoinRetry)', None),
        'lost-quit-attempt': (body.replace('p.quitAttempted = true', 'p.quitAttempted = false', 1), 'TestOriginalQuitRetry', 'original quit attempt was not retained'),
        'lost-serve-outcome': (body.replace('!errors.Is(*outcome, http.ErrServerClosed)', '!errors.Is(http.ErrServerClosed, http.ErrServerClosed)', 1), 'TestOriginalHTTPJoinRetry', 'original Serve failure lost across retry'),
        'lost-joined-receipt': (body.replace('!strings.Contains(string(raw), `"joined":true`)', 'false', 1), 'TestOriginalJoinReceipt', 'missing original joined receipt accepted'),
    }
    if len({v[0] for v in variants.values()}) != 4:
        raise ValueError('Original peer shutdown mutation seam changed')
    env = dict(os.environ if environment is None else environment)
    for key in ('GOOS','GOARCH','GOARM','GOAMD64'):
        env.pop(key,None)
    results = {}
    with tempfile.TemporaryDirectory(prefix='routervpn-peer-close-') as directory:
        work=Path(directory);(work/'go.mod').write_text('module probe\n\ngo 1.25.0\n')
        (work/'owner_test.go').write_text(tests)
        for name,(value,selector,witness) in variants.items():
            (work/'owner.go').write_text(declaration+value)
            image=work/(name+'.test')
            compiled=subprocess.run([str(go),'test','-c','-p=1','-o',str(image),'.'],cwd=work,env=env,check=False,timeout=300,capture_output=True,text=True)
            if compiled.returncode:
                raise ValueError('Peer shutdown '+name+' compilation failed: '+(compiled.stdout+compiled.stderr)[-16384:])
            actual=subprocess.run([str(image),'-test.v','-test.count=1','-test.timeout=15s','-test.run=^'+selector+'$'],cwd=work,env=env,timeout=20,capture_output=True,text=True)
            output=actual.stdout+actual.stderr
            if witness is None:
                if actual.returncode or output.count('--- PASS: TestOriginal')!=3 or not output.endswith('PASS\n'):
                    raise ValueError('Actual original peer shutdown controls failed: '+output)
            elif actual.returncode==0 or output.count(witness)!=1 or '--- FAIL: '+selector not in output or not output.endswith('FAIL\n'):
                raise ValueError('Peer shutdown mutation missed original ownership witness: '+output)
            if 'DATA RACE' in output or 'panic:' in output or 'SKIP' in output:
                raise ValueError('Peer shutdown emitted unrelated failure')
            results[name]=hashlib.sha256(output.encode()).hexdigest()
    if (Path(root)/GATE.SOURCES[7]).read_text()!=source or (Path(root)/GATE.PEER_TEMPLATE).read_text()!=peer_source:
        raise ValueError('Original peer shutdown source changed')
    return dict(scope='actual-peer-close-source-with-original-pipe-and-join-adapters', native=False, outputs=results, source_sha256=hashlib.sha256(source.encode()).hexdigest(), peer_source_sha256=hashlib.sha256(peer_source.encode()).hexdigest())

if __name__ == '__main__':
    unittest.main()
