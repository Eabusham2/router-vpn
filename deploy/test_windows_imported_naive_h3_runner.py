#!/usr/bin/env python3
"""Strict orchestration/receipt controls; these do not execute Windows WFP."""
from pathlib import Path
import copy
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('owned_imported_h3_windows', ROOT / 'deploy/test_windows_imported_naive_h3.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
ENV = {'GITHUB_REPOSITORY': 'owner/router', 'GITHUB_SHA': 'a' * 40,
       'GITHUB_RUN_ID': '1234', 'GITHUB_RUN_ATTEMPT': '2'}


def output(cases, verdict='PASS'):
    return '\n'.join('--- ' + verdict + ': ' + name + ' (0.01s)' for name in cases) + '\n' + verdict + '\n'


def native(architecture='amd64', cgo='0'):
    return {'format': GATE.NATIVE_FORMAT, 'scope': GATE.SCOPE, 'goos': 'windows',
            'architecture': architecture, 'cgo': cgo, 'race': cgo == '1' and architecture == 'amd64',
            'source_sha256': 'b' * 64, 'source_inventory_sha256': 'c' * 64,
            'compiled_roots': list(GATE.ROOTS), 'verdicts': list(GATE.REQUIRED), 'controls': [GATE.CONTROL],
            'executables': {'baseline': 'd' * 64, GATE.CONTROL: 'e' * 64},
            'library': {'sha256': 'f' * 64, 'bytes': 12345, 'target': 'windows/' + architecture},
            'physical_device_acceptance': False}


def receipt(architecture='amd64'):
    return {'format': GATE.FORMAT, **GATE.CI.context(ENV), 'native': native(architecture),
            'comparable_source_sha256': '1' * 64}


def sources(directory):
    for kind in GATE.KINDS:
        for first in GATE.LAYERS:
            for last in GATE.LAYERS:
                protocol = 'openvpn' if kind.startswith('openvpn-') else kind
                capture = {'protocol': protocol, 'profile': {'start_layer': first}}
                final = {'start_layer': last}
                graph = {'outbounds': [{'tag': 'exit-ss', 'type': 'naive', 'quic': True}]}
                if protocol == 'openvpn':
                    graph['endpoints'] = [{'tag': 'entry-wg', 'network': kind.removeprefix('openvpn-')}]
                value = ['{}', json.dumps(capture), 'naive-h3', '{}', json.dumps(final), '{}', '', '2' * 64, json.dumps(graph)]
                (directory / (kind + '--naive-h3--' + first + '--' + last + '.json')).write_text(json.dumps(value))


class ProtectedImportedH3Runner(unittest.TestCase):
    def test_exact_native_inventory_is_separate(self):
        self.assertEqual(len(GATE.CELLS), 63)
        self.assertEqual(len(GATE.REQUIRED), 88)
        self.assertEqual(len(set(GATE.REQUIRED)), 88)
        self.assertEqual(len(GATE.NATIVE.PHASES), 7)
        self.assertNotIn('imported-naive-h3', GATE.NATIVE.PHASES)
        leaves = []
        for _, required, budget in GATE.invocations():
            self.assertEqual(budget, 180)
            GATE.require_verdicts(0, output(required), required)
            leaves.extend(case for case in required if '/' in case)
        expected = [case for case in GATE.REQUIRED if '/' in case]
        self.assertCountEqual(leaves, expected)
        self.assertEqual(len(set(leaves)), len(leaves))
        executed_roots = {case for _, required, _ in GATE.invocations() for case in required if '/' not in case}
        self.assertEqual(executed_roots, set(GATE.ROOTS))

    def test_compiled_discovery_rejects_missing_tagged_and_unexecuted_roots(self):
        original = '\n'.join((*GATE.ROOTS, GATE.PEER)) + '\n'
        GATE.require_discovery(0, original)
        for output in ('', '\n'.join(GATE.ROOTS), original.replace(GATE.CANCELLATION + '\n', ''),
                       original + GATE.PREFIX + 'Unexecuted\n', original + GATE.RUNTIME + '\n',
                       original.replace(GATE.RUNTIME, 'diagnostic ' + GATE.RUNTIME), original + 'PASS\n'):
            with self.subTest(output=output), self.assertRaises(ValueError): GATE.require_discovery(0, output)
        with self.assertRaises(ValueError): GATE.require_discovery(1, original)

    def test_verdict_omission_duplicate_foreign_and_diagnostics_fail(self):
        required = (GATE.RUNTIME, GATE.RUNTIME + '/' + GATE.CELLS[0])
        good = output(required)
        bad = (output(required[:1]), good + good.splitlines()[1] + '\n',
               good + '--- PASS: Foreign (0.1s)\n', good.replace('--- PASS:', 'diagnostic --- PASS:', 1),
               good + '--- SKIP: foreign (0.1s)\n', good + 'WARNING: DATA RACE\n',
               good + 'panic: example\n', good + 'FAIL\n', 'ok package 1.0s\n')
        for value in bad:
            with self.subTest(output=value):
                with self.assertRaises(ValueError): GATE.require_verdicts(0, value, required)
        with self.assertRaises(ValueError): GATE.require_verdicts(1, good, required)

    def test_native_receipt_refuses_invented_or_missing_evidence(self):
        GATE.validate_native(native(), 'amd64')
        changes = ({'scope': 'constructor'}, {'goos': 'linux'}, {'architecture': 'arm64'},
                   {'cgo': 'unknown'}, {'race': True}, {'physical_device_acceptance': True},
                   {'verdicts': list(GATE.REQUIRED[:-1])}, {'verdicts': list(GATE.REQUIRED) + [GATE.REQUIRED[0]]},
                   {'controls': []}, {'compiled_roots': list(GATE.ROOTS[:-1])}, {'compiled_roots': [GATE.PEER, *GATE.ROOTS]},
                   {'source_sha256': 'g' * 64}, {'source_inventory_sha256': ''},
                   {'executables': {'baseline': 'd' * 64}},
                   {'library': {'sha256': 'f' * 64, 'bytes': True, 'target': 'windows/amd64'}},
                   {'library': {'sha256': 'f' * 64, 'bytes': 123, 'target': 'windows/arm64'}})
        for change in changes:
            with self.subTest(change=change):
                value = native(); value.update(change)
                with self.assertRaises(ValueError): GATE.validate_native(value, 'amd64')

    def test_original_inventory_checks_axes_wire_transport_and_regular_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); sources(root)
            original = GATE.inventory(root); self.assertEqual(len(original), 63)
            path = root / 'openvpn-tcp--naive-h3--off--off.json'; raw = path.read_text()
            value = json.loads(raw); graph = json.loads(value[8]); graph['endpoints'][0]['network'] = 'udp'; value[8] = json.dumps(graph)
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError): GATE.inventory(root)
            path.write_text(raw); value = json.loads(raw); value[2] = 'naive-h2'; path.write_text(json.dumps(value))
            with self.assertRaises(ValueError): GATE.inventory(root)
            path.write_text(raw); renamed = root / 'foreign.json'; path.rename(renamed)
            with self.assertRaises(ValueError): GATE.inventory(root)
            renamed.rename(path); self.assertEqual(GATE.inventory(root), original)

    def test_both_architectures_and_original_ci_context_are_required(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(GATE.CI, 'verify_checkout') as checkout, mock.patch('builtins.print'):
            root = Path(temporary)
            for arch in GATE.ARCHITECTURES:
                (root / GATE.filename(arch)).write_text(json.dumps(receipt(arch)))
            self.assertEqual(len(GATE.aggregate(root, 'success', env=ENV)), 2)
            self.assertEqual(checkout.call_count, 2)
            for status in ('failure', 'cancelled', 'skipped', ''):
                with self.assertRaises(ValueError): GATE.aggregate(root, status, env=ENV)
            arm = root / GATE.filename('arm64'); original = arm.read_text(); arm.unlink()
            with self.assertRaises(ValueError): GATE.aggregate(root, 'success', env=ENV)
            arm.write_text(original); value = json.loads(original); value['comparable_source_sha256'] = '3' * 64; arm.write_text(json.dumps(value))
            with self.assertRaises(ValueError): GATE.aggregate(root, 'success', env=ENV)
            for key, replacement in (('commit', 'b' * 40), ('run_id', '1235'), ('run_attempt', '3'), ('repository', 'foreign/repo')):
                value = json.loads(original); value[key] = replacement; arm.write_text(json.dumps(value))
                with self.subTest(field=key), self.assertRaises(ValueError): GATE.aggregate(root, 'success', env=ENV)

    def test_actual_windows_host_is_mandatory(self):
        with mock.patch.object(GATE.platform, 'system', return_value='Linux'), mock.patch.object(GATE, 'checked_sources') as check:
            with self.assertRaisesRegex(ValueError, 'actual elevated native Windows'): GATE.execute(ROOT)
            check.assert_not_called()

    def exercise(self, cgo, architecture, *, refusal=None):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'core'; source.mkdir()
            before = {'fixture': '7' * 64}; calls = []; overlays = []
            captured = {'CGO_ENABLED': cgo, 'GOOS': 'windows', 'GOARCH': architecture,
                        'ROUTERVPN_WINDOWS_IMPORTED_H3_PEER': '1', 'SHIPPING_CAPTURE': 'original'}
            def run(command, *, cwd, env, timeout):
                command = [str(v) for v in command]; calls.append((command, Path(cwd), dict(env), timeout))
                self.assertEqual(env['CGO_ENABLED'], cgo); self.assertEqual(env['SHIPPING_CAPTURE'], 'original')
                self.assertNotIn('ROUTERVPN_WINDOWS_IMPORTED_H3_PEER', env)
                if './internal/mobilemultihop' in command:
                    sources(Path(env['ROUTERVPN_IMPORTED_NAIVE_H3_FIXTURES']))
                    cases = (GATE.SHARED, *(GATE.SHARED + '/' + k + '/' + a + '/' + b for k in GATE.KINDS for a in GATE.LAYERS for b in GATE.LAYERS))
                    self.assertEqual(timeout, 180); self.assertIn('-timeout=60s', command)
                    return 0, output(cases)
                if '-c' in command:
                    image = Path(command[command.index('-o') + 1]); image.write_bytes(b'MZ modeled immutable image ' + image.parent.name.encode())
                    self.assertEqual(timeout, 600)
                    self.assertIn('-tags=' + ','.join((*GATE.BUILD.tags('windows/' + architecture), 'routervpn_windows_node_composition')), command)
                    self.assertEqual('-race' in command, cgo == '1' and architecture == 'amd64')
                    return (1, 'compile failed') if refusal == 'compile' else (0, '')
                if '-test.list=^' + GATE.PREFIX in command:
                    self.assertEqual(timeout, 30)
                    self.assertEqual(len(command), 2)
                    roots = (*GATE.ROOTS, GATE.PEER)
                    if refusal == 'tag-omitted': roots = tuple(root for root in roots if root != GATE.CANCELLATION)
                    if refusal == 'unexecuted-root': roots = (*roots, GATE.PREFIX + 'Unexecuted')
                    return 0, '\n'.join(roots) + '\n'
                expression = next(v.removeprefix('-test.run=') for v in command if v.startswith('-test.run='))
                if Path(command[0]).parent.name == GATE.CONTROL:
                    self.assertEqual(timeout, 75); self.assertIn('-test.timeout=60s', command)
                    if refusal == 'causal-pass': return 0, output((GATE.OWNERSHIP, GATE.OWNERSHIP + '/foreign-physical-root'))
                    if refusal == 'causal-panic': return 1, 'panic: intended?\n'
                    return 1, GATE.CONTROL_WITNESS + '\n' + output((GATE.OWNERSHIP + '/foreign-physical-root', GATE.OWNERSHIP), 'FAIL')
                selected = next(item for item in GATE.invocations() if item[0] == expression)
                self.assertEqual(timeout, selected[2] + 15)
                cases = selected[1][:-1] if refusal == 'missing-case' else selected[1]
                return 0, output(cases)
            def overlay(core, directory, mutation=None):
                self.assertEqual(core, source); overlays.append(mutation)
                result = directory / 'overlay.json'; result.write_text('{}'); return result
            def library(compiler, core, directory, env):
                path = directory / 'libcronet.dll'; path.write_bytes(b'actual staging boundary modeled')
                return path, path, 'f' * 64, path.stat().st_size
            with mock.patch.object(GATE.platform, 'system', return_value='Windows'), \
                 mock.patch.object(GATE.NATIVE.BOOT.IDENTITY.ctypes, 'windll', create=True) as system, \
                 mock.patch.object(GATE, 'checked_sources', return_value=(source, before)), \
                 mock.patch.object(GATE.NATIVE.BOOT.IDENTITY, 'selected_compiler', return_value=(Path('go.exe'), captured, architecture)), \
                 mock.patch.object(GATE.NATIVE.BOOT.IDENTITY, 'run', side_effect=run), \
                 mock.patch.object(GATE.NATIVE, 'overlay', side_effect=overlay), \
                 mock.patch.object(GATE.NATIVE, 'mutants', return_value=[None, None, ('captured-original-policy-defect',)]), \
                 mock.patch.object(GATE.NATIVE.NODE, 'stage_naive_library', side_effect=library), \
                 mock.patch.object(GATE.NATIVE.NODE, 'verify_naive_library') as verify, \
                 mock.patch('builtins.print'):
                system.shell32.IsUserAnAdmin.return_value = True
                result = GATE.execute(source, env=captured)
                self.assertEqual(result['source_sha256'], GATE.digest(before)); self.assertEqual(result['verdicts'], list(GATE.REQUIRED))
                self.assertEqual(overlays, [None, ('captured-original-policy-defect',)])
                verify.assert_called_once()
                self.assertEqual(len(calls), 1 + 2 + 1 + len(tuple(GATE.invocations())) + 1)
                return result

    def test_prepared_matching_host_retains_shipping_cgo_and_all_native_calls(self):
        for arch, cgo in (('amd64', '1'), ('amd64', '0'), ('arm64', '1'), ('arm64', '0')):
            with self.subTest(architecture=arch, cgo=cgo): self.exercise(cgo, arch)

    def test_real_pipeline_blocks_missing_positive_and_unproved_causal(self):
        for refusal in ('compile', 'tag-omitted', 'unexecuted-root', 'missing-case', 'causal-pass', 'causal-panic'):
            with self.subTest(refusal=refusal), self.assertRaises(ValueError): self.exercise('0', 'amd64', refusal=refusal)

    def test_preparer_keeps_both_new_fixtures_windows_only(self):
        copies = GATE.NATIVE.NODE.PREP.pt_copies()
        for name, target in GATE.TEMPLATES.items():
            raw = (ROOT / 'mobile/desktop' / name).read_bytes()
            self.assertTrue(raw.startswith(GATE.TAG)); self.assertEqual(copies[target], raw)
        self.assertIn('RouterVPNDesktopImportedPreparePhysicalOwned(policy)', (ROOT / 'mobile/desktop/node_imported_naive_h3_windows_test.go.tmpl').read_text())
        self.assertIn('DesktopWindowsNodeCompositionVerifyPrepared(ctx, target)', (ROOT / 'mobile/desktop/node_imported_naive_h3_windows_test.go.tmpl').read_text())

    def test_original_failed_peer_keeps_bounded_diagnostics_without_accepting_them(self):
        source = (ROOT / 'mobile/desktop/node_imported_naive_h3_windows_test.go.tmpl').read_text()
        peer = (ROOT / 'mobile/desktop/node_imported_naive_h3_windows_peer_test.go.tmpl').read_text()
        helper = 'func desktopImportedH3ReadReply' + source.split('func desktopImportedH3ReadReply', 1)[1].split('func (p *desktopImportedH3Reference) read()', 1)[0]
        parser = 'func desktopImportedH3Read(' + peer.split('func desktopImportedH3Read(', 1)[1].split('func desktopImportedH3LayerMode(', 1)[0]
        caller = source.split('func (p *desktopImportedH3Reference) read()', 1)[1].split('func (p *desktopImportedH3Reference) same(', 1)[0]
        self.assertIn('desktopImportedH3ReadReply(p.reader, &value, &p.diagnostics)', caller)
        self.assertIn('case <-time.After(12 * time.Second):', caller)
        self.assertLess(caller.index('p.cancel()'), caller.index('_ = p.output.Close()'))
        header = 'package peer\nimport("bufio";"bytes";"encoding/json";"errors";"io")\nconst desktopImportedH3PeerLimit = 2 << 20\n'
        cases = r'''package peer
import("bufio";"bytes";"errors";"io";"strings";"testing")
type reply struct{Schema int}
func TestActualPeerFailureRetainsCauseAndStillFails(t *testing.T){
 for _,first:=range []string{"--- FAIL: TestRouterVPNWindowsImportedNaiveH3Peer (0.01s)","{\"Schema\":1,\"foreign\":true}","{\"Schema\":1} {}"}{t.Run(first,func(t *testing.T){
  const cause="    peer.go:123: actual captured imported H3 OpenVPN provider failed: original refusal\nFAIL\n"
  var got reply;var diagnostic bytes.Buffer
  err:=desktopImportedH3ReadReply(bufio.NewReader(strings.NewReader(first+"\n"+cause)),&got,&diagnostic)
  if err==nil||diagnostic.String()!=cause{t.Fatalf("failed original peer was accepted or its cause lost: err=%v diagnostic=%q",err,diagnostic.String())}
 })}
}
func TestSuccessDoesNotConsumeAnotherOriginalAcknowledgement(t *testing.T){
 input:=bufio.NewReader(strings.NewReader("{\"Schema\":1}\n{\"Schema\":2}\n"));var got reply;var diagnostic bytes.Buffer
 if err:=desktopImportedH3ReadReply(input,&got,&diagnostic);err!=nil||got.Schema!=1||diagnostic.Len()!=0{t.Fatal("first original acknowledgement changed",err)}
 if err:=desktopImportedH3ReadReply(input,&got,&diagnostic);err!=nil||got.Schema!=2||diagnostic.Len()!=0{t.Fatal("next original acknowledgement consumed",err)}
 if err:=desktopImportedH3ReadReply(input,&got,&diagnostic);!errors.Is(err,io.EOF){t.Fatal("original EOF lost",err)}
}
func TestFailedPeerDiagnosticIsStrictlyBounded(t *testing.T){
 input:=bufio.NewReader(strings.NewReader("FAIL\n"+strings.Repeat("x",(64<<10)+23)));var got reply;var diagnostic bytes.Buffer
 err:=desktopImportedH3ReadReply(input,&got,&diagnostic)
 if err==nil||!strings.Contains(err.Error(),"diagnostic exceeded bound")||diagnostic.Len()!=64<<10{t.Fatal("unbounded or accepted failed peer diagnostic",err,diagnostic.Len())}
 rest,_:=io.ReadAll(input);if len(rest)!=23{t.Fatal("read beyond original diagnostic limit",len(rest))}
}
'''
        with tempfile.TemporaryDirectory(prefix='routervpn-h3-peer-diagnostic-') as directory:
            work = Path(directory)
            (work / 'go.mod').write_text('module routervpn-peer-diagnostic\n\ngo 1.26.3\n')
            target = work / 'peer.go'
            target.write_text(header + parser + helper)
            (work / 'peer_test.go').write_text(cases)
            command = [shutil.which('go') or 'go', 'test', '-count=1', '-timeout=10s', '.']
            result = subprocess.run(command, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout)
            changed = helper.replace('io.Copy(diagnostics, io.LimitReader(reader, limit))', 'io.Copy(io.Discard, io.LimitReader(reader, limit))')
            self.assertNotEqual(changed, helper)
            target.write_text(header + parser + changed)
            result = subprocess.run(command + ['-run', '^TestActualPeerFailureRetainsCauseAndStillFails$'], cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn('its cause lost', result.stdout)


    def test_native_openvpn_readiness_preserves_original_owner_and_caller(self):
        source = (ROOT / 'mobile/desktop/node_imported_naive_h3_windows_test.go.tmpl').read_text()
        helper = source.split('type desktopImportedH3OpenVPN interface {', 1)[1].split('func (f *desktopImportedH3WindowsFixture) awaitEntryReady', 1)[0]
        helper = 'type desktopImportedH3OpenVPN interface {' + helper
        proof = source.split('func (f *desktopImportedH3WindowsFixture) prove(', 1)[1].split('func (f *desktopImportedH3WindowsFixture) drain(', 1)[0]
        self.assertIn('context.WithTimeout(context.Background(), 15*time.Second)', proof)
        self.assertLess(proof.index('f.awaitEntryReady(ctx)'), proof.index('f.proofLane(ctx, true)'))
        self.assertEqual(proof.count('f.proofLane(ctx, true)'), 1)
        header = 'package readiness\nimport("context";"errors";"time";"router-vpn/internal/nativeopenvpn")\n'
        cases = r'''package readiness
import("context";"errors";"testing";"time";"router-vpn/internal/nativeopenvpn")
type endpoint struct { read func(context.Context)(nativeopenvpn.RemoteReceipt,uint32,error) }
func(e *endpoint)RouterVPNConnectedCapacityContext(ctx context.Context)(nativeopenvpn.RemoteReceipt,uint32,error){ return e.read(ctx) }
func capture()map[string]any{return map[string]any{"server":"203.0.113.24","server_port":float64(1194),"network":"tcp","mtu":float64(1400)}}
func receipt()nativeopenvpn.RemoteReceipt{return nativeopenvpn.RemoteReceipt{Remote:nativeopenvpn.Remote{Host:"203.0.113.24",Port:1194,Network:"tcp"},Generation:1,ConnectedAt:1700000000000}}
func TestOriginalPendingEndpointBecomesReadyBeforeProof(t *testing.T){
 for _,network:=range []string{"tcp","udp"}{t.Run(network,func(t *testing.T){
  ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
  queries,proofs:=0,0; original:=&endpoint{}; expected:=capture(); expected["network"]=network
  original.read=func(call context.Context)(nativeopenvpn.RemoteReceipt,uint32,error){
   if call!=ctx{t.Fatal("native observation lost original caller")};queries++
   if queries==1{return nativeopenvpn.RemoteReceipt{},0,nativeopenvpn.ErrRemotePending}
   r:=receipt();r.Network=network;return r,1400,nil
  }
  current:=func(call context.Context)(desktopImportedH3OpenVPN,error){if call!=ctx{t.Fatal("owner check lost caller")};return original,nil}
  err:=desktopImportedH3AwaitOpenVPN(ctx,original,current,expected)
  if err==nil{proofs++}
  if err!=nil||queries!=2||proofs!=1{t.Fatalf("proof admitted before native ready: queries=%d proofs=%d err=%v",queries,proofs,err)}
 })}
}
func TestReadinessRejectsChangedReceiptAndNativeFailure(t *testing.T){
 for _,fault:=range []string{"host","port","network","generation","timestamp","capacity","oversized-capacity","native-error"}{t.Run(fault,func(t *testing.T){
  reads:=0;actual:=errors.New("original provider authentication failure");original:=&endpoint{}
  original.read=func(context.Context)(nativeopenvpn.RemoteReceipt,uint32,error){reads++;r:=receipt();mtu:=uint32(1400)
   switch fault{case "host":r.Host="203.0.113.25";case "port":r.Port++;case "network":r.Network="udp";case "generation":r.Generation=0;case "timestamp":r.ConnectedAt=0;case "capacity":mtu--;case "oversized-capacity":mtu=65536;case "native-error":return r,mtu,actual};return r,mtu,nil}
  err:=desktopImportedH3AwaitOpenVPN(context.Background(),original,func(context.Context)(desktopImportedH3OpenVPN,error){return original,nil},capture())
  if err==nil||reads!=1{t.Fatalf("invalid readiness retried or adopted: reads=%d err=%v",reads,err)}
  if fault=="native-error"&&!errors.Is(err,actual){t.Fatal("native error cause lost",err)}
 })}
}
func TestReadinessRejectsCancellationAndEndpointReplacement(t *testing.T){
 for _,fault:=range []string{"cancel-before","cancel-read","cancel-pending","replace-before","replace-read","owner-error"}{t.Run(fault,func(t *testing.T){
  ctx,cancel:=context.WithCancel(context.Background());defer cancel()
  original,replacement:=&endpoint{},&endpoint{};var live desktopImportedH3OpenVPN=original
  reads:=0;actual:=errors.New("original owner retired")
  original.read=func(call context.Context)(nativeopenvpn.RemoteReceipt,uint32,error){reads++
   if fault=="cancel-read"||fault=="cancel-pending"{cancel()};if fault=="replace-read"{live=replacement}
   if fault=="cancel-pending"{return nativeopenvpn.RemoteReceipt{},0,nativeopenvpn.ErrRemotePending};return receipt(),1400,nil}
  if fault=="cancel-before"{cancel()};if fault=="replace-before"{live=replacement}
  current:=func(context.Context)(desktopImportedH3OpenVPN,error){if fault=="owner-error"{return nil,actual};return live,nil}
  err:=desktopImportedH3AwaitOpenVPN(ctx,original,current,capture())
  if err==nil{t.Fatal("retired original owner/caller admitted proof")}
  if fault=="cancel-before"||fault=="cancel-read"||fault=="cancel-pending"{if !errors.Is(err,context.Canceled){t.Fatal("caller cancellation lost",err)}}
  if fault=="owner-error"&&!errors.Is(err,actual){t.Fatal("owner error cause lost",err)}
  if (fault=="cancel-before"||fault=="replace-before"||fault=="owner-error")&&reads!=0{t.Fatal("retired owner was observed")}
 })}
}
func TestReadinessPendingObeysOriginalDeadline(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),25*time.Millisecond);defer cancel()
 original:=&endpoint{read:func(context.Context)(nativeopenvpn.RemoteReceipt,uint32,error){return nativeopenvpn.RemoteReceipt{},0,nativeopenvpn.ErrRemotePending}}
 err:=desktopImportedH3AwaitOpenVPN(ctx,original,func(context.Context)(desktopImportedH3OpenVPN,error){return original,nil},capture())
 if !errors.Is(err,context.DeadlineExceeded){t.Fatal("pending authentication did not retain proof deadline",err)}
}
'''
        with tempfile.TemporaryDirectory(prefix='routervpn-h3-readiness-') as directory:
            work = Path(directory)
            (work / 'go.mod').write_text('module router-vpn/h3-readiness\n\ngo 1.26.3\n\nrequire router-vpn v0.0.0\nreplace router-vpn => ' + json.dumps(ROOT.as_posix()) + '\n')
            target = work / 'readiness.go'
            target.write_text(header + helper)
            (work / 'readiness_test.go').write_text(cases)
            command = [shutil.which('go') or 'go', 'test', '-count=1', '-timeout=10s', '.']
            result = subprocess.run(command, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout)
            # No barrier: the same initial pending endpoint must fail before a
            # public proof is attempted. Do not retry that proof or its errors.
            changed = helper.replace('if !errors.Is(err, nativeopenvpn.ErrRemotePending) {', 'if err != nil {')
            self.assertNotEqual(changed, helper)
            target.write_text(header + changed)
            result = subprocess.run(command + ['-run', '^TestOriginalPendingEndpointBecomesReadyBeforeProof$'], cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn('proof admitted before native ready', result.stdout)


if __name__ == '__main__':
    unittest.main()
