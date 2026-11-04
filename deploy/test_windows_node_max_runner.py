#!/usr/bin/env python3
"""Check MAX runner scope, exact evidence and cleanup without network peers.

Subprocess models below exercise publication boundaries only. They cannot
establish native Windows, WFP, cryptographic or physical-device acceptance.
"""
from contextlib import ExitStack, contextmanager, nullcontext, redirect_stdout
from pathlib import Path
import importlib.util
import io
import json
import re
import os
import tempfile
import subprocess
import shutil
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('windows_complete_max_checks', ROOT / 'deploy/test_windows_node_max.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def failure(parent, case, witness):
    return witness + '\n--- FAIL: ' + parent + ' (0.01s)\n    --- FAIL: ' + parent + '/' + case + ' (0.01s)\nFAIL\n'


EXCHANGE_DIAGNOSTIC_HARNESS = r'''package routervpnamnezia
import("bytes";"context";"errors";"fmt";"io";"net";"strings";"syscall";"testing";"time")
var _,_,_ = fmt.Sprintf, syscall.Errno(0), io.EOF
var M = struct{ParseSocksaddr func(string)string}{func(s string)string{return s}}
type desktopNodePeerFixture struct{box *diagBox}
type diagBox struct{manager *diagManager}
func(b *diagBox)Outbound()*diagManager{return b.manager}
type diagManager struct{outbound *diagOutbound;found bool}
func(m *diagManager)Outbound(string)(*diagOutbound,bool){return m.outbound,m.found}
type diagOutbound struct{dial func(context.Context)(net.Conn,error)}
func(d *diagOutbound)DialContext(ctx context.Context,network,destination string)(net.Conn,error){return d.dial(ctx)}
type diagConn struct{writeErr,readErr error;reply []byte;closed bool;deadline bool;different bool}
func(c *diagConn)Write(p []byte)(int,error){if c.writeErr!=nil{return 0,c.writeErr};c.reply=append([]byte(nil),p...);if c.different{c.reply[0]^=1};return len(p),nil}
func(c *diagConn)Read(p []byte)(int,error){if c.readErr!=nil{return 0,c.readErr};return copy(p,c.reply),nil}
func(c *diagConn)Close()error{c.closed=true;return nil}
func(c *diagConn)LocalAddr()net.Addr{return &net.TCPAddr{}}
func(c *diagConn)RemoteAddr()net.Addr{return &net.TCPAddr{}}
func(c *diagConn)SetDeadline(time.Time)error{c.deadline=true;return nil}
func(c *diagConn)SetReadDeadline(time.Time)error{return nil}
func(c *diagConn)SetWriteDeadline(time.Time)error{return nil}
func fixture(c *diagConn,err error)*desktopNodePeerFixture{return &desktopNodePeerFixture{&diagBox{&diagManager{&diagOutbound{func(ctx context.Context)(net.Conn,error){if _,ok:=ctx.Deadline();!ok{panic("lost original request deadline")};return c,err}},true}}}}
func TestShippingExchangeDiagnosticStages(t *testing.T){
 secret:=errors.New("password=private-secret config=private-configuration private_key=private-material")
 for _,phase:=range []string{"dial","write","read"}{t.Run(phase,func(t *testing.T){
  conn:=&diagConn{};var dialErr error
  switch phase{case "dial":dialErr=secret;case "write":conn.writeErr=secret;case "read":conn.readErr=secret}
  err:=fixture(conn,dialErr).exchange("tcp")
  if err==nil||!strings.Contains(err.Error(),"phase="+phase){t.Fatal("original exchange cause lacks its bounded stage")}
  if !errors.Is(err,secret){t.Fatal("diagnostic lost original error identity")}
  for _,value:=range []string{"private-secret","private-configuration","private-material"}{if strings.Contains(err.Error(),value){t.Fatal("diagnostic exposed private input")}}
  if phase!="dial"&&(!conn.closed||!conn.deadline){t.Fatal("diagnostic bypassed original deadline or cleanup")}
 })}
}
func TestShippingExchangeDiagnosticCauseClassification(t *testing.T){
 for _,tc:=range []struct{cause error;want string}{{context.DeadlineExceeded,"deadline=true"},{context.Canceled,"canceled=true"},{io.EOF,"eof=true"},{&net.OpError{Op:"private-operation",Net:"private-network",Err:syscall.Errno(10022)},"native_errno=10022"}}{
  err:=fixture(&diagConn{},fmt.Errorf("password=private-secret: %w",tc.cause)).exchange("tcp")
  if err==nil||!strings.Contains(err.Error(),tc.want)||!errors.Is(err,tc.cause){t.Fatal("diagnostic lost original typed cause",tc.want)}
  if strings.Contains(err.Error(),"private-"){t.Fatal("typed cause leaked raw provider text")}
 }
}
func TestShippingExchangeDiagnosticSuccessAndPayload(t *testing.T){
 conn:=&diagConn{};if err:=fixture(conn,nil).exchange("tcp");err!=nil||!conn.closed||!conn.deadline{t.Fatal("diagnostics changed successful exchange lifecycle")}
 conn=&diagConn{different:true};err:=fixture(conn,nil).exchange("tcp");if err==nil||!strings.Contains(err.Error(),"phase=payload")||!conn.closed{t.Fatal("payload mismatch lost its stage or close")}
}
'''


class NativeTLSFrontAllocation(unittest.TestCase):
    def test_actual_listener_aliases_and_shipping_allocator_call(self):
        go = shutil.which('go')
        self.assertIsNotNone(go, 'actual retained TLS listener regression requires Go')
        stream = (ROOT / 'mobile/desktop/node_max_stream_test.go.tmpl').read_text()
        tls = (ROOT / 'mobile/desktop/node_max_tls_reference_test.go.tmpl').read_text()
        peer = (ROOT / 'mobile/desktop/node_max_peer_test.go.tmpl').read_text()
        self.assertIn('nodeMAXTLS(t, ip, middleDestination, basePort, middleAddress.String(), fault, hooks)', peer)
        helper = stream[stream.index('func nodeMAXTLSFront('):stream.index('func nodeMAXBoth(')]
        cases = stream[stream.index('func nodeMAXTLSFrontCases('):stream.index('func TestRouterVPNDesktopNodeMAXPortPair(')]
        allocation = tls[tls.index('\tfront, err :='):tls.index('\tbridge, err :=')]
        # Only the native allocation call is injected. The shipping call site,
        # exact reserved graph ports, retained socket checks and cleanup execute.
        def source(selected):
            return (r'''package front
import("errors";"net";"net/netip";"testing";"time")
func TestRetainedFront(t *testing.T){nodeMAXTLSFrontCases(t)}
func shippingFront(t *testing.T, ip netip.Addr, packetPort uint16, middle struct{Port uint16}, listen func(string,*net.TCPAddr)(*net.TCPListener,error))*net.TCPListener{
''' + selected.replace('net.ListenTCP', 'listen') + r'''
return front
}
func TestShippingTLSFrontAllocation(t *testing.T){
 ip:=netip.MustParseAddr("127.0.0.1"); calls:=0
 var original *net.TCPListener
 front:=shippingFront(t,ip,51820,struct{Port uint16}{31001},func(network string,address *net.TCPAddr)(*net.TCPListener,error){
  calls++;if calls==1{address=net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip,51822))}
  socket,err:=net.ListenTCP(network,address);if calls==1{original=socket};return socket,err
 });defer front.Close()
 if calls<2||calls>3||original==nil||original.SetDeadline(time.Now())==nil||front.Addr().(*net.TCPAddr).Port==51822{t.Fatal("shipping TLS fixture admitted its original KEM graph alias")}
}
''' + helper + cases)
        with tempfile.TemporaryDirectory(prefix='max-retained-tls-front-') as temporary:
            path = Path(temporary) / 'front_test.go'
            env = dict(os.environ, GOTOOLCHAIN='local')
            def execute(selected, selector):
                path.write_text(source(selected))
                command = captured_cleanup_test_command(go, path, env)
                command.insert(-1, '-run='+selector)
                return subprocess.run(command,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, timeout=60)
            baseline = execute(allocation, 'Test')
            self.assertEqual(baseline.returncode, 0, baseline.stdout)
            for case in ('packet', 'kem', 'middle', 'whitening', 'exhausted', 'foreign', 'missing', 'error'):
                self.assertIn('--- PASS: TestRetainedFront/tls-front-'+case+' (', baseline.stdout)
            self.assertIn('--- PASS: TestShippingTLSFrontAllocation (', baseline.stdout)
            self.assertNotIn('--- SKIP:', baseline.stdout)
            old = '\tfront, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))\n\tif err != nil { t.Fatal(err) }\n'
            negative = execute(old, '^TestShippingTLSFrontAllocation$')
            self.assertNotEqual(negative.returncode, 0, negative.stdout)
            self.assertIn('shipping TLS fixture admitted its original KEM graph alias', negative.stdout)
            self.assertNotIn('DATA RACE', negative.stdout)
            self.assertNotIn('panic:', negative.stdout)


class NativeFailureDiagnostics(unittest.TestCase):
    def test_long_native_failure_retains_early_cause_and_late_stack_with_byte_bound(self):
        output = 'EARLY_ORIGINAL_TEST_FAILURE\n' + ('middle goroutine evidence Ω\n' * 3000) + 'LATE_NATIVE_STACK\n'
        self.assertNotIn('EARLY_ORIGINAL_TEST_FAILURE', output[-16384:])
        actual = GATE.bounded_failure_output(output)
        self.assertIn('EARLY_ORIGINAL_TEST_FAILURE', actual)
        self.assertIn('LATE_NATIVE_STACK', actual)
        self.assertIn('[middle native diagnostic omitted]', actual)
        self.assertLessEqual(len(actual.encode('utf-8')), 16384)
        self.assertEqual(GATE.bounded_failure_output('short native error\n'), 'short native error\n')

    def test_native_diagnostics_remove_private_records_before_truncation(self):
        secrets = ('proxy-password-value', 'private-key-value', 'private-config-value', 'private-token-value', 'pem-private-value', 'url-password-value')
        output = ('EARLY_FAILURE\npassword=' + secrets[0] + '\nprivate_key=' + secrets[1] +
                  '\nProtocolFiles: ' + secrets[2] + '\n{"token":"' + secrets[3] + '"}\n' +
                  '-----BEGIN PRIVATE KEY-----\n' + secrets[4] + '\n-----END PRIVATE KEY-----\n' +
                  'dial https://user:' + secrets[5] + '@peer.invalid:443\n' + 'stack\n'*5000 + 'LATE_STACK\n')
        for limit in (128, 16384, 65536):
            actual = GATE.bounded_failure_output(output, limit)
            for secret in secrets:
                self.assertNotIn(secret, actual)
            self.assertIn('EARLY_FAILURE', actual)
            self.assertIn('LATE_STACK', actual)
            self.assertLessEqual(len(actual.encode()), limit)

    def test_diagnostic_formatting_never_changes_negative_verdict_or_deadline(self):
        parent, case, witness = 'TestRouterVPNDesktopNodeWindowsMAXForeignPredecessor', 'max-tls-wg', 'foreign MAX predecessor reached captured native admission'
        raw = failure(parent, case, witness)
        GATE.rejected_output(1, raw, parent, case, witness)
        for invalid in (raw.replace('FAIL\n', ''), raw + '\npanic: test timed out after 90s\n', raw + '\nDATA RACE\n'):
            GATE.bounded_failure_output(invalid)
            with self.assertRaises(ValueError):
                GATE.rejected_output(1, invalid, parent, case, witness)
        source = (ROOT / 'deploy/test_windows_node_max.py').read_text()
        self.assertIn("'-test.timeout=90s'", source)
        self.assertIn('timeout=105)', source)
        self.assertIn("bounded_failure_output(output)) from error", source)

    def test_exact_shipping_exchange_retains_safe_typed_cause_and_owned_cleanup(self):
        go = shutil.which('go')
        self.assertIsNotNone(go, 'The shipping exchange diagnostic regression requires Go')
        template = (ROOT / 'mobile/desktop/node_peer_test.go.tmpl').read_text()
        start = template.index('// desktopNodeExchangeDiagnostics')
        end = template.index('func TestRouterVPNDesktopNodeEncryptedPreReadyHandshake(', start)
        helper = template[start:end]
        self.assertIn('return f.exchangeWithin(2*time.Second, 2*time.Second, network, hosts...)', helper)
        consumer = (ROOT / 'mobile/desktop/node_layer_peer_windows_test.go.tmpl').read_text()
        consumer = consumer[consumer.index('func desktopNodeWFPLayerWrongCredential('):]
        self.assertIn('exchangeErr := f.exchange(network)', consumer)
        self.assertIn('t.Log("rejected encrypted exchange", exchangeErr', consumer)
        self.assertNotIn('native path", observed)', consumer)
        for original in ('observed.RawTCP == 0', 'observed.ProtocolTCP != 0', 'observed.ProtocolUDP != 0',
                         'fault != "aes-key" && observed.ProtocolRawTCP == 0', 'f.network.Current()'):
            self.assertIn(original, consumer)
        with tempfile.TemporaryDirectory(prefix='shipping-exchange-diagnostics-') as temporary:
            path = Path(temporary) / 'exchange_test.go'
            path.write_text(EXCHANGE_DIAGNOSTIC_HARNESS + '\n' + helper)
            env = dict(os.environ, GOTOOLCHAIN='local')
            result = subprocess.run([go, 'test', '-count=1', '-timeout=15s', '-v', str(path)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout)
        for case in ('Stages', 'CauseClassification', 'SuccessAndPayload'):
            self.assertIn('--- PASS: TestShippingExchangeDiagnostic' + case + ' (', result.stdout)
        self.assertNotIn('--- SKIP:', result.stdout)
        self.assertNotIn('private-secret', result.stdout)


CAPTURED_CLEANUP_HARNESS = r'''package mobiletor
import("context";"errors";"fmt";"reflect";"testing";"time")
type DesktopWindowsProtectionTarget struct{ ID string }
func(t DesktopWindowsProtectionTarget)Validate()error{if t.ID==""{return errors.New("no captured target")};return nil}
type cleanupTest struct{ callbacks []func(); errors []string }
func(t *cleanupTest)Helper(){}
func(t *cleanupTest)Cleanup(f func()){t.callbacks=append(t.callbacks,f)}
func(t *cleanupTest)Error(v ...any){t.errors=append(t.errors,fmt.Sprint(v...))}
func(t *cleanupTest)run(){for i:=len(t.callbacks)-1;i>=0;i--{t.callbacks[i]()}}
var calls []string
var current string
var partialErr, readErr, transactionErr, closeErr, absentErr error
func bounded(ctx context.Context){deadline,ok:=ctx.Deadline();if !ok||time.Until(deadline)>10*time.Second||time.Until(deadline)<=0{panic("cleanup lost its original live ten-second bound")}}
func DesktopWindowsNodeCompositionRetainedTarget(ctx context.Context)(DesktopWindowsProtectionTarget,error){bounded(ctx);calls=append(calls,"partial");return DesktopWindowsProtectionTarget{current},partialErr}
func DesktopWindowsNodeCompositionAppID()([]byte,error){calls=append(calls,"scope");return []byte("original-executable"),nil}
func readDesktopWindowsRetainedProtection(ctx context.Context,t DesktopWindowsProtectionTarget,scope []byte)error{bounded(ctx);calls=append(calls,"read:"+t.ID);if string(scope)!="original-executable"{panic("scope changed")};if t.ID!=current{return errors.New("foreign retained target")};return readErr}
type recovery struct{}
func newDesktopWindowsProtectionTransactionTarget(ctx context.Context,scope []byte,removeAlways bool,target *DesktopWindowsProtectionTarget)(*recovery,error){bounded(ctx);calls=append(calls,"transaction:"+target.ID);if string(scope)!="original-executable"||!removeAlways||target.ID!=current{panic("retirement widened captured authority")};return &recovery{},transactionErr}
func(*recovery)Close(ctx context.Context)error{bounded(ctx);calls=append(calls,"close");return closeErr}
func DesktopWindowsNodeCompositionAbsent(ctx context.Context)error{bounded(ctx);calls=append(calls,"absent");return absentErr}
func reset(){calls=nil;current="original";partialErr=nil;readErr=nil;transactionErr=nil;closeErr=nil;absentErr=nil}
func TestCapturedNativeCleanup(t *testing.T){
 for _,name:=range []string{"captured","foreign-newer","partial","missing","read-failure","transaction-failure","close-failure","absence-failure"}{t.Run(name,func(t *testing.T){
  reset();target:=DesktopWindowsProtectionTarget{"original"};var want []string;wantErrors:=0
  switch name{
  case "captured":want=[]string{"scope","read:original","transaction:original","close","absent"}
  case "foreign-newer":current="newer";want=[]string{"scope","read:original"};wantErrors=1
  case "partial":target.ID="";want=[]string{"partial","scope","read:original","transaction:original","close","absent"}
  case "missing":target.ID="";partialErr=errors.New("no original outcome");absentErr=errors.New("unknown retained policy");want=[]string{"partial","absent"};wantErrors=1
  case "read-failure":readErr=errors.New("incomplete original rules");want=[]string{"scope","read:original"};wantErrors=1
  case "transaction-failure":transactionErr=errors.New("late native failure");want=[]string{"scope","read:original","transaction:original","close"};wantErrors=1
  case "close-failure":closeErr=errors.New("native owner unjoined");want=[]string{"scope","read:original","transaction:original","close"};wantErrors=1
  case "absence-failure":absentErr=errors.New("native policy remains");want=[]string{"scope","read:original","transaction:original","close","absent"};wantErrors=1
  }
  fixture:=&cleanupTest{};nodePQWFPCleanup(fixture,&target);if len(calls)!=0||len(fixture.callbacks)!=1{t.Fatal("cleanup executed before registered Box retirement")};fixture.run()
  if !reflect.DeepEqual(calls,want)||len(fixture.errors)!=wantErrors{t.Fatalf("captured cleanup switched authority, lost independent readback or skipped joining: calls=%v errors=%v",calls,fixture.errors)}
  if name!="missing"&&target.ID!="original"{t.Fatal("cleanup replaced original target")}
 })}
}
'''


def captured_cleanup_test_command(go, path, env):
    # Execute the same cleanup cases on both native Windows architectures.
    # Go does not support race instrumentation on Windows ARM64; preserve it
    # on every other supported native host and reject cross-target execution.
    target = subprocess.check_output([go, 'env', 'GOHOSTOS', 'GOHOSTARCH', 'GOOS', 'GOARCH'],
                                     env=env, text=True, timeout=15).split()
    if (len(target) != 4 or target[:2] != target[2:] or
            target[0] not in ('linux', 'darwin', 'windows') or target[1] not in ('amd64', 'arm64')):
        raise ValueError('Captured cleanup regression requires a matching supported native Go target')
    race = [] if target[:2] == ['windows', 'arm64'] else ['-race']
    return [go, 'test', *race, '-count=1', '-timeout=15s', '-v', str(path)]


FOREIGN_ADMISSION_HARNESS = r'''package nativefixture
import("context";"errors";"fmt";"strings";"testing")
type capture struct{SourceSHA256 string}
type DesktopWindowsProtectionTarget struct{Capture capture;Policy,BaselineSHA256 string}
type NodePhysicalPrepared = DesktopWindowsProtectionTarget
type originalProfile struct{}
type foreignTest struct{cleanup []func();fatal string}
func(t *foreignTest)Helper(){}
func(t *foreignTest)Run(_ string,f func(*foreignTest)){f(t)}
func(t *foreignTest)Fatal(v ...any){t.fatal=fmt.Sprint(v...);panic(t)}
func(t *foreignTest)Cleanup(f func()){t.cleanup=append(t.cleanup,f)}
type notReady struct{}
func(notReady)Load()bool{return false}
type nativeTUN struct{ready notReady}
type nativeNetwork struct{}
func(*nativeNetwork)Current()bool{return false}
func(*nativeNetwork)SocketCurrent()bool{return false}
type nodePQWFPFixture struct{prepared DesktopWindowsProtectionTarget;admitted int;network *nativeNetwork;tun *nativeTUN;box *nativeBox;closed bool}
type nativeBox struct{fixture *nodePQWFPFixture;predecessor *DesktopWindowsProtectionTarget;admit func(context.Context,NodePhysicalPrepared)error}
var nodeMAXWFPModes []string
var rejectForeign bool
var nativeCurrent,cleanupTarget string
var fullOriginalProof,originalJoined,candidateJoined,foreignHandshake int
func DesktopWindowsNodeCompositionAbsent(context.Context)error{if nativeCurrent!=""{return errors.New("not absent")};return nil}
func DesktopWindowsNodeCompositionVerifyPrepared(_ context.Context,t DesktopWindowsProtectionTarget)error{if t.Capture.SourceSHA256!=nativeCurrent{return errors.New("wrong prepared native owner")};return nil}
func DesktopWindowsNodeCompositionVerifyRetained(_ context.Context,t DesktopWindowsProtectionTarget)error{if t.Capture.SourceSHA256!="original"||nativeCurrent!="original"{return errors.New("original retained policy changed")};return nil}
func nodePQWFPCleanup(t *foreignTest,target *DesktopWindowsProtectionTarget){t.Cleanup(func(){cleanupTarget=target.Capture.SourceSHA256;if cleanupTarget!=nativeCurrent{panic("cleanup switched original native target")};nativeCurrent=""})}
type nativeReference struct{}
func nodeMAXWFPStartReference(*foreignTest,string,string,string)*nativeReference{return &nativeReference{}}
func(*nativeReference)original(*foreignTest,string)*originalProfile{return &originalProfile{}}
func nodeMAXWFPBox(t *foreignTest,p *originalProfile,old *DesktopWindowsProtectionTarget,prepare bool)*nodePQWFPFixture{return nodeMAXWFPBoxWithAdmissionGuard(t,p,old,prepare,nil)}
func nodeMAXWFPBoxWithAdmissionGuard(t *foreignTest,_ *originalProfile,old *DesktopWindowsProtectionTarget,prepare bool,guard func(DesktopWindowsProtectionTarget)error)*nodePQWFPFixture{
 if !prepare{panic("lost native preparation")};f:=&nodePQWFPFixture{network:&nativeNetwork{},tun:&nativeTUN{}}
 f.box=&nativeBox{f,old,actualAdmission(f,guard)};t.Cleanup(func(){_ = f.close()});return f
}
func(b *nativeBox)RouterVPNStrategyStart()error{
 if b.predecessor!=nil&&rejectForeign{return errors.New("original production admission rejected foreign capture")}
 id:="original";if b.predecessor!=nil{id="candidate"}
 nativeCurrent=id
 if err:=b.admit(context.Background(),NodePhysicalPrepared{capture{id},"always","native-baseline"});err!=nil{return err}
 if b.predecessor!=nil{foreignHandshake++;return errors.New("unrelated second PQ exchange")}
 return nil
}
func(f *nodePQWFPFixture)start(t *foreignTest){if err:=f.box.RouterVPNStrategyStart();err!=nil{t.Fatal(err)}}
func(f *nodePQWFPFixture)close()error{if !f.closed{f.closed=true;if f.box.predecessor==nil{originalJoined++}else{candidateJoined++}};return nil}
func nodeMAXWFPRequireTraffic(t *foreignTest,f *nodePQWFPFixture,_ *nativeReference,_ [32]byte,_ bool){if f.admitted!=1||f.prepared.Capture.SourceSHA256!="original"{t.Fatal("lost original full traffic proof")};fullOriginalProof++}
func nodePQWFPDrain(t *foreignTest,f *nodePQWFPFixture)DesktopWindowsProtectionTarget{if err:=f.close();err!=nil{t.Fatal(err)};return f.prepared}
func invokeForeign(t *foreignTest){defer func(){if r:=recover();r!=nil&&r!=t{panic(r)}}();TestRouterVPNDesktopNodeWindowsMAXForeignPredecessor(t)}
func TestExactForeignAdmission(t *testing.T){
 for _,mode:=range []string{"max-tls-wg","max-quic-wg"}{for _,control:=range []string{"reject-before-admission","admission-guard-bypassed"}{t.Run(mode+"/"+control,func(t *testing.T){
  nodeMAXWFPModes=[]string{mode};rejectForeign=control=="reject-before-admission";nativeCurrent="";cleanupTarget=""
  fullOriginalProof,originalJoined,candidateJoined,foreignHandshake=0,0,0,0
  fixture:=&foreignTest{};invokeForeign(fixture)
  for i:=len(fixture.cleanup)-1;i>=0;i--{fixture.cleanup[i]()}
  if foreignHandshake!=0{t.Fatal("foreign candidate entered unrelated post-admission PQ handshake")}
  if fullOriginalProof!=1||originalJoined!=1||candidateJoined!=1||nativeCurrent!=""{t.Fatal("foreign rejection dropped original traffic, candidate join or native retirement")}
  if rejectForeign{if fixture.fatal!=""||cleanupTarget!="original"{t.Fatal("valid early rejection changed original retained owner",fixture.fatal,cleanupTarget)}}else{
   if fixture.fatal!="foreign MAX predecessor reached captured native admission"||cleanupTarget!="candidate"{t.Fatal("bypassed admission lost its exact witness or new captured cleanup target",fixture.fatal,cleanupTarget)}
  }
 })}}
}
'''


class CapturedNativeCleanup(unittest.TestCase):
    def test_exact_cleanup_keeps_original_target_and_independent_retirement(self):
        go = shutil.which('go')
        self.assertIsNotNone(go, 'The captured cleanup regression requires Go')
        source = (ROOT / 'mobile/desktop/node_pq_peer_windows_test.go.tmpl').read_text()
        helper = source[source.index('func nodePQWFPCleanup('):source.index('func nodePQWFPRequireBlocked(')]
        # Only cross-platform type boundaries are modeled. Execute the exact
        # cleanup and independent retirement control bodies, including errors.
        helper = helper.replace('t *testing.T', 't *cleanupTest').replace('mobiletor.', '')
        observer = (ROOT / 'deploy/fixtures/windows-node-physical/kernel_observer.go').read_text()
        retire = observer[observer.index('func DesktopWindowsNodeCompositionRetire('):observer.index('// This native test capture retains')]
        with tempfile.TemporaryDirectory(prefix='native-captured-cleanup-') as temporary:
            path = Path(temporary) / 'cleanup_test.go'
            path.write_text(CAPTURED_CLEANUP_HARNESS + '\n' + helper + '\n' + retire)
            env = dict(os.environ, GOTOOLCHAIN='local')
            result = subprocess.run(captured_cleanup_test_command(go, path, env),
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    env=env, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout)
        for case in ('captured', 'foreign-newer', 'partial', 'missing', 'read-failure',
                     'transaction-failure', 'close-failure', 'absence-failure'):
            self.assertIn('--- PASS: TestCapturedNativeCleanup/' + case + ' (', result.stdout)
        self.assertNotIn('--- SKIP:', result.stdout)

    def test_foreign_max_rejection_stops_at_exact_admission_and_retires_captured_candidate(self):
        template = (ROOT / 'mobile/desktop/node_max_peer_windows_test.go.tmpl').read_text()
        begin = template.index('\t\tadmit := func(ctx context.Context, prepared routervpndesktoppt.NodePhysicalPrepared) error {')
        end = template.index('\n\t\tif predecessor == nil {', begin)
        admission = template[begin:end].replace('\t\tadmit := func', 'admit := func')
        begin = template.index('func TestRouterVPNDesktopNodeWindowsMAXForeignPredecessor(')
        end = template.index('func TestRouterVPNDesktopNodeWindowsMAXMarkers(', begin)
        foreign = template[begin:end].replace('t *testing.T', 't *foreignTest')
        code = FOREIGN_ADMISSION_HARNESS + '\nfunc actualAdmission(f *nodePQWFPFixture, guard func(DesktopWindowsProtectionTarget) error) func(context.Context, NodePhysicalPrepared) error {\n' + admission + '\nreturn admit\n}\n' + foreign
        code = code.replace('mobiletor.', '').replace('routervpndesktoppt.', '')
        code = code.replace('TestRouterVPNDesktopNodeWindowsMAXForeignPredecessor(', 'shippingForeignPredecessor(')
        with tempfile.TemporaryDirectory(prefix='max-foreign-admission-') as temporary:
            path = Path(temporary) / 'admission_test.go'
            path.write_text(code)
            go = shutil.which('go')
            self.assertIsNotNone(go, 'Foreign native admission regression requires Go')
            env = dict(os.environ, GOTOOLCHAIN='local')
            result = subprocess.run(captured_cleanup_test_command(go, path, env), text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60, env=env)
        self.assertEqual(result.returncode, 0, result.stdout)
        for mode in ('max-tls-wg', 'max-quic-wg'):
            for control in ('reject-before-admission', 'admission-guard-bypassed'):
                self.assertIn('--- PASS: TestExactForeignAdmission/' + mode + '/' + control + ' (', result.stdout)
        self.assertNotIn('--- SKIP:', result.stdout)

    def test_cleanup_uses_race_on_supported_native_targets_and_executes_windows_arm64(self):
        for system in ('linux', 'darwin', 'windows'):
            for arch in ('amd64', 'arm64'):
                with self.subTest(system=system, arch=arch):
                    env = {'GOTOOLCHAIN': 'local'}
                    with patch('subprocess.check_output', return_value='\n'.join((system, arch, system, arch))) as observe:
                        command = captured_cleanup_test_command('captured-go', Path('cleanup_test.go'), env)
                    observe.assert_called_once_with(['captured-go', 'env', 'GOHOSTOS', 'GOHOSTARCH', 'GOOS', 'GOARCH'],
                                                    env=env, text=True, timeout=15)
                    race = [] if (system, arch) == ('windows', 'arm64') else ['-race']
                    self.assertEqual(command, ['captured-go', 'test', *race, '-count=1', '-timeout=15s', '-v', 'cleanup_test.go'])

    def test_windows_targets_execute_the_same_shipping_cleanup_cases(self):
        cases = ('captured', 'foreign-newer', 'partial', 'missing', 'read-failure',
                 'transaction-failure', 'close-failure', 'absence-failure')
        output = '\n'.join('--- PASS: TestCapturedNativeCleanup/'+case+' (0.01s)' for case in cases)
        for arch in ('amd64', 'arm64'):
            with self.subTest(arch=arch):
                def execute(command, **kwargs):
                    self.assertEqual(command[:2], ['captured-go', 'test'])
                    self.assertEqual('-race' in command, arch == 'amd64')
                    self.assertEqual(command[2:-1], (['-race'] if arch == 'amd64' else []) + ['-count=1', '-timeout=15s', '-v'])
                    self.assertEqual(kwargs['timeout'], 60)
                    self.assertEqual(kwargs['env']['GOTOOLCHAIN'], 'local')
                    source = Path(command[-1]).read_text()
                    self.assertIn('func nodePQWFPCleanup(', source)
                    self.assertIn('func DesktopWindowsNodeCompositionRetire(', source)
                    for case in cases:
                        self.assertIn('"'+case+'"', source)
                    return subprocess.CompletedProcess(command, 0, output)
                with patch('shutil.which', return_value='captured-go'), \
                     patch('subprocess.check_output', return_value='\n'.join(('windows', arch, 'windows', arch))), \
                     patch('subprocess.run', side_effect=execute) as run:
                    CapturedNativeCleanup('test_exact_cleanup_keeps_original_target_and_independent_retirement').test_exact_cleanup_keeps_original_target_and_independent_retirement()
                self.assertEqual(run.call_count, 1)

    def test_cleanup_rejects_foreign_or_incomplete_go_target(self):
        for target in ('windows\narm64\nwindows\namd64', 'linux\namd64\nwindows\namd64',
                       'windows\narm64', 'linux\n386\nlinux\n386', ''):
            with self.subTest(target=target), patch('subprocess.check_output', return_value=target), self.assertRaises(ValueError):
                captured_cleanup_test_command('captured-go', Path('cleanup_test.go'), {})


class MAXCommandRetirement(unittest.TestCase):
    def test_original_success_and_negative_wait_for_owned_completion(self):
        for status in (0, 7):
            owner = GATE.MAXCommandOwner()
            command, environment = [Path('captured.exe'), 'exact argument'], {'original': 'environment'}
            events = []
            def completed(arguments, **kwargs):
                self.assertEqual(arguments, ['captured.exe', 'exact argument'])
                self.assertEqual(kwargs, {'cwd': Path('captured-source'), 'env': environment, 'timeout': 105})
                self.assertFalse(owner.retired)
                events.append('original descendants joined')
                if status:
                    raise subprocess.CalledProcessError(status, arguments, output=b'original stdout\xff', stderr=b'original stderr\xfe')
                return subprocess.CompletedProcess(arguments, status, b'original stdout\xff', b'original stderr\xfe')
            with patch.object(GATE.REFERENCE.BUILD.BUILD_OWNER, 'run', side_effect=completed):
                result = owner.run(command, cwd=Path('captured-source'), env=environment, timeout=105)
            self.assertEqual(result, (status, 'original stdout\ufffdoriginal stderr\ufffd'))
            self.assertEqual(events, ['original descendants joined'])
            self.assertTrue(owner.retired)

    def test_unproved_owner_retains_both_workspaces_and_refuses_next_command(self):
        for fault in ('cleanup', 'bootstrap-timeout', 'foreign-status', 'foreign-success'):
            owner, workspaces = GATE.MAXCommandOwner(), []
            def failed(arguments, **kwargs):
                if fault == 'cleanup':
                    raise RuntimeError('original descendant failed to join')
                if fault == 'bootstrap-timeout':
                    raise subprocess.TimeoutExpired(['original-bootstrap'], 10)
                if fault == 'foreign-status':
                    raise subprocess.CalledProcessError(1, ['foreign'], output=b'', stderr=b'')
                return subprocess.CompletedProcess(['foreign'], 0, b'', b'')
            try:
                with patch.object(GATE.REFERENCE.BUILD.BUILD_OWNER, 'run', side_effect=failed), self.assertRaises(Exception):
                    with owner.workspace('max-original-source-') as source:
                        workspaces.append(source)
                        with owner.workspace('max-original-private-') as private:
                            workspaces.append(private)
                            (private/'original.test.exe').write_bytes(b'original image')
                            owner.run(['original.test.exe'], cwd=source, env={}, timeout=105)
                self.assertFalse(owner.retired)
                self.assertTrue(all(path.is_dir() for path in workspaces),'Unproved native owner deleted an original workspace')
                self.assertEqual((workspaces[1]/'original.test.exe').read_bytes(), b'original image')
                with self.assertRaisesRegex(RuntimeError, 'cannot replace an unjoined'):
                    owner.run(['new.exe'], cwd=workspaces[0], env={}, timeout=105)
            finally:
                for path in workspaces:
                    if path.exists():shutil.rmtree(path)

    def test_original_timeout_stays_failure_after_proved_join(self):
        owner = GATE.MAXCommandOwner()
        expired = subprocess.TimeoutExpired(['original.exe'], 105, output=b'original deadline', stderr=b'original stderr')
        with patch.object(GATE.REFERENCE.BUILD.BUILD_OWNER, 'run', side_effect=expired):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                with owner.workspace('max-joined-timeout-') as workspace:
                    owner.run(['original.exe'], cwd=workspace, env={}, timeout=105)
        self.assertIs(caught.exception, expired)
        self.assertTrue(owner.retired)
        self.assertFalse(workspace.exists())

    @unittest.skipUnless(os.name == 'nt', 'actual Windows file sharing and job APIs required')
    def test_actual_completed_control_joins_original_image_holder_before_unlink(self):
        # A command exits with its deliberate negative witness while a genuine
        # descendant still holds the original control image without delete sharing.
        child = r'''
import ctypes,os,sys,time
from pathlib import Path
kernel=ctypes.WinDLL('kernel32',use_last_error=True)
kernel.CreateFileW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p]
kernel.CreateFileW.restype=ctypes.c_void_p
handle=kernel.CreateFileW(sys.argv[1],0x80000000,0,None,3,0x80,None)
if handle in (None,ctypes.c_void_p(-1).value):raise ctypes.WinError(ctypes.get_last_error())
Path(sys.argv[2]).write_text('original descendant holds image')
time.sleep(120)
'''
        parent = r'''
import subprocess,sys,time
from pathlib import Path
child=subprocess.Popen([sys.executable,'-I','-S','-c',sys.argv[1],sys.argv[2],sys.argv[3]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
deadline=time.monotonic()+10
while not Path(sys.argv[3]).is_file():
    if time.monotonic()>=deadline:raise RuntimeError('original image holder did not start')
    time.sleep(.01)
print(sys.argv[4],flush=True)
sys.exit(7)
'''
        testcase, observed = self, []
        original_job = GATE.REFERENCE.BUILD.BUILD_OWNER.WindowsJob
        with tempfile.TemporaryDirectory(prefix='max-native-original-image-') as directory:
            root=Path(directory); image=root/'original-control.test.exe'; image.write_bytes(b'original bounded fixture image')
            foreign=subprocess.Popen([sys.executable,'-I','-S','-c','import sys; print("ready",flush=True); sys.stdin.buffer.read()'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                self.assertEqual(foreign.stdout.readline().strip(),b'ready')
                class ObservedJob(original_job):
                    def seal(job):
                        # Direct Popen completion alone cannot make this unlink
                        # succeed. Observe the actual sharing violation before
                        # original-job retirement, without changing its result.
                        with testcase.assertRaises(PermissionError) as caught:
                            image.unlink()
                        testcase.assertEqual(caught.exception.winerror,32)
                        observed.append('original image still held after command exit')
                        return super().seal()
                parent_test='TestRouterVPNDesktopNodeWindowsMAXTLS'
                case='max-tls-wg/off';witness='original test-only negative witness'
                command=[sys.executable,'-I','-S','-c',parent,child,str(image),str(root/'ready'),failure(parent_test,case,witness)]
                with patch.object(GATE.REFERENCE.BUILD.BUILD_OWNER,'WindowsJob',ObservedJob):
                    owner=GATE.MAXCommandOwner()
                    status,output=owner.run(command,cwd=root,env=dict(os.environ),timeout=15)
                self.assertEqual(status,7)
                GATE.rejected_output(status,output,parent_test,case,witness)
                self.assertEqual(observed,['original image still held after command exit'])
                self.assertTrue(owner.retired)
                image.unlink()
                self.assertFalse(image.exists())
                self.assertIsNone(foreign.poll(),'MAX cleanup killed an unrelated same-image process')
                print('Actual MAX command owner joined original image holder before immediate unlink; negative status and foreign process preserved',flush=True)
            finally:
                try:foreign.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    foreign.kill();foreign.communicate(timeout=10)


class MAXObservationCompilation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='max-observation-driver-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.files = (self.root / 'source.go', self.root / 'source_test.go')
        for path in self.files:
            path.write_text('package observer\n')
        self.environment = {'captured': 'environment'}
        self.calls = []
        self.binary = None

    def run_contract(self, operation):
        with patch.object(GATE.REFERENCE.BUILD.BUILD_OWNER, 'run', side_effect=operation), redirect_stdout(io.StringIO()):
            GATE.observation_contract(Path('captured-go'), self.root, self.environment, ['-race'],
                                      self.files, 'TestObservation', ('first', 'second'))

    def owned(self, command, **kwargs):
        args = [str(value) for value in command]
        self.calls.append((args, kwargs))
        self.assertIs(kwargs['env'], self.environment)
        self.assertEqual(kwargs['cwd'], self.root)
        if len(self.calls) == 1:
            self.assertEqual(args[1:4], ['test', '-c', '-mod=readonly'])
            self.assertIn('-race', args)
            self.assertEqual(kwargs['timeout'], 180)
            self.binary = Path(args[args.index('-o')+1])
            self.binary.write_bytes(b'captured compiled test')
            return subprocess.CompletedProcess(args, 0, b'', b'')
        self.assertEqual(args, [str(self.binary), '-test.run=^TestObservation$', '-test.count=1', '-test.timeout=30s', '-test.v'])
        self.assertEqual(kwargs['timeout'], 45)
        output = b'--- PASS: TestObservation (0.01s)\n--- PASS: TestObservation/first (0.01s)\n--- PASS: TestObservation/second (0.01s)\nPASS\n'
        return subprocess.CompletedProcess(args, 0, output, b'')

    def test_cold_compilation_is_separate_from_exact_bounded_execution(self):
        self.run_contract(self.owned)
        self.assertEqual(len(self.calls), 2)
        self.assertFalse(self.binary.parent.exists())

    def test_timeout_preserves_original_failure_and_blocks_later_execution(self):
        for stage in (1, 2):
            with self.subTest(stage=stage):
                self.calls = []
                failures = []
                def timed(command, **kwargs):
                    result = self.owned(command, **kwargs)
                    if len(self.calls) == stage:
                        failure = subprocess.TimeoutExpired(result.args, kwargs['timeout'], output=b'original bounded diagnostic')
                        failures.append(failure)
                        raise failure
                    return result
                with self.assertRaises(subprocess.TimeoutExpired) as caught:
                    self.run_contract(timed)
                self.assertIs(caught.exception, failures[0])
                self.assertEqual(len(self.calls), stage)
                self.assertFalse(self.binary.parent.exists())

    def test_unproved_cleanup_retains_workspace_and_original_timeout(self):
        failures = []
        def unjoined(command, **kwargs):
            result = self.owned(command, **kwargs)
            original = subprocess.TimeoutExpired(['python', '-I', '-S', 'owned-bootstrap'], kwargs['timeout'])
            failures.append(original)
            try:
                raise original
            except subprocess.TimeoutExpired:
                raise RuntimeError('captured native cleanup did not join')
        try:
            with self.assertRaises(ExceptionGroup) as caught:
                self.run_contract(unjoined)
            self.assertIs(caught.exception.exceptions[0], failures[0])
            self.assertIn('cleanup did not join', str(caught.exception.exceptions[1]))
            self.assertTrue(self.binary.is_file())
            self.assertEqual(len(self.calls), 1)
        finally:
            if self.binary is not None:
                shutil.rmtree(self.binary.parent)

    def test_bootstrap_join_timeout_is_not_original_command_retirement(self):
        def unjoined(command, **kwargs):
            self.owned(command, **kwargs)
            raise subprocess.TimeoutExpired(['python', '-I', '-S', 'owned-bootstrap'], 10)
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.run_contract(unjoined)
            self.assertTrue(self.binary.is_file())
        finally:
            if self.binary is not None:
                shutil.rmtree(self.binary.parent)

    def test_missing_verdict_and_changed_executable_or_sources_fail_closed(self):
        for fault in ('missing', 'executable', 'source'):
            with self.subTest(fault=fault):
                self.calls = []
                def changed(command, **kwargs):
                    result = self.owned(command, **kwargs)
                    if fault == 'source' and len(self.calls) == 1:
                        self.files[0].write_text('package changed\n')
                    if len(self.calls) == 2:
                        if fault == 'missing':
                            result.stdout = result.stdout.replace(b'--- PASS: TestObservation/second (0.01s)\n', b'')
                        if fault == 'executable':
                            self.binary.write_bytes(b'changed compiled test')
                    return result
                with self.assertRaises(ValueError):
                    self.run_contract(changed)
                self.assertEqual(len(self.calls), 1 if fault == 'source' else 2)
                self.assertFalse(self.binary.parent.exists())


class MAXNativeBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='max-native-source-check-')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name).resolve()
        self.source = self.work / 'core'
        self.original = {}
        files = {
            GATE.PREDICATE: 'internal/mobilemultihop/desktop_node_admission.go',
            'routervpn/mobiletor/desktop_socket_windows_policy.go': 'internal/mobiletor/desktop_socket_windows_policy.go',
            'routervpn/mobiletor/desktop_socket_windows_transfer.go': 'internal/mobiletor/desktop_socket_windows_transfer.go',
            'routervpn/desktoppt/node_physical_windows.go': 'mobile/desktop/node_physical_windows.go.tmpl',
            'routervpn/desktoppt/node_physical.go': 'mobile/desktop/node_physical.go.tmpl',
            GATE.PEER: GATE.PEER_TEMPLATE,
            'protocol/routervpnpq/node_max_peer_test.go': 'mobile/desktop/node_max_peer_test.go.tmpl',
        }
        for relative, real in files.items():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            self.original[relative] = (ROOT / real).read_bytes()
            if relative == GATE.PREDICATE and any(json.dumps(mode).encode() in self.original[relative] for mode in GATE.MODES):
                # Closed-source compatibility fixture only; shipping-positive
                # execution below retains its actual predicate unchanged.
                self.original[relative] = GATE.closed_predicate(self.original[relative].decode()).encode()
            path.write_bytes(self.original[relative])
        # The source-only tests deliberately suppress modeled subprocess output.
        self.output = io.StringIO()
        self.stdout = redirect_stdout(self.output)
        self.stdout.__enter__()
        self.addCleanup(self.stdout.__exit__, None, None, None)

    def directory(self, name):
        directory = self.work / name
        directory.mkdir()
        return directory

    def assert_native_scope(self, overlay):
        mapping = json.loads(overlay.read_text())['Replace']
        for relative, raw in self.original.items():
            self.assertEqual((self.source / relative).read_bytes(), raw)
        first = Path(mapping[str(self.source / 'routervpn/mobiletor/desktop_socket_windows_policy.go')]).read_text()
        second = Path(mapping[str(self.source / 'routervpn/mobiletor/desktop_socket_windows_transfer.go')]).read_text()
        self.assertIn('return desktopWindowsNodeCompositionConstruct(ctx, capture, options, nil, false)', first)
        self.assertIn('return desktopWindowsNodeCompositionConstruct(ctx, capture, options, predecessor, true)', second)
        return mapping

    def test_current_and_exact_four_family_overlay_keep_original_native_scope(self):
        closed = self.assert_native_scope(GATE.overlay(self.source, self.directory('closed'), prospective=False))
        opened = self.assert_native_scope(GATE.overlay(self.source, self.directory('opened'), prospective=True))
        self.assertNotIn(str(self.source / GATE.PREDICATE), closed)
        self.assertEqual(len(opened), len(closed)+1)
        raw = self.original[GATE.PREDICATE].decode()
        expected = raw.replace(GATE.PROSPECTIVE_BEFORE, GATE.PROSPECTIVE_AFTER, 1)
        actual = Path(opened[str(self.source / GATE.PREDICATE)]).read_text()
        self.assertEqual(actual, expected)
        self.assertEqual(set(GATE.MODES), {'max-quic-wg', 'max-quic-awg', 'max-tls-wg', 'max-tls-awg'})
        for mode in GATE.MODES:
            self.assertEqual(actual.count('"'+mode+'"'), 1)
        self.assertIn('startLayer != "aes-256-gcm+xor-whitening"', actual)
        self.assertIn('default:\n\t\treturn false', actual)
        for raw in (raw.replace(GATE.PROSPECTIVE_BEFORE, '\tswitch other {\n'),
                    raw.replace('func DesktopNodePhysicalGraphSupported', 'func other'),
                    expected, raw+'\n// "max-tls-awg"\n'):
            with self.assertRaises(ValueError):
                GATE.prospective_predicate(raw)

    def shipping_predicate(self):
        raw = GATE.prospective_predicate(self.original[GATE.PREDICATE].decode())
        self.original[GATE.PREDICATE] = raw.encode()
        (self.source / GATE.PREDICATE).write_bytes(self.original[GATE.PREDICATE])
        return raw

    def test_shipping_positive_and_native_scope_controls_leave_predicate_unchanged(self):
        scope = patch.object(GATE.MAX, 'mutations', return_value=())
        scope.start()
        self.addCleanup(scope.stop)
        raw = self.shipping_predicate()
        shipping = self.assert_native_scope(GATE.overlay(self.source, self.directory('shipping'), prospective=False))
        self.assertNotIn(str(self.source / GATE.PREDICATE), shipping)
        closed = self.assert_native_scope(GATE.overlay(self.source, self.directory('shipping-closed'), prospective=False, closed=True))
        self.assertEqual(set(closed) - set(shipping), {str(self.source / GATE.PREDICATE)})
        self.assertEqual(Path(closed[str(self.source / GATE.PREDICATE)]).read_text(), GATE.closed_predicate(raw))
        for original in shipping:
            self.assertEqual(Path(shipping[original]).read_bytes(), Path(closed[original]).read_bytes())
        mutations = GATE.mutations(self.source)
        self.assertEqual(len(mutations), 7)
        for mutation in mutations:
            selected = GATE.overlay(self.source, self.directory('shipping-' + mutation[0]), prospective=False, mutation=mutation)
            self.assertNotIn(str(self.source / GATE.PREDICATE), self.assert_native_scope(selected))

    def test_exact_max_closure_preserves_pq_admission_in_either_order(self):
        raw = self.original[GATE.PREDICATE].decode()
        if any(json.dumps(mode) in raw for mode in GATE.WPQ.PQ.MODES):
            raw = GATE.WPQ.closed_predicate(raw)
        own_case = GATE.PROSPECTIVE_AFTER[len(GATE.PROSPECTIVE_BEFORE):]
        pq_case = GATE.WPQ.PROSPECTIVE_AFTER[len(GATE.WPQ.PROSPECTIVE_BEFORE):]
        for cases in (own_case + pq_case, pq_case + own_case):
            combined = raw.replace(GATE.PROSPECTIVE_BEFORE, GATE.PROSPECTIVE_BEFORE + cases, 1)
            self.assertEqual(GATE.closed_predicate(combined), combined.replace(own_case, '', 1))
        opened = GATE.prospective_predicate(raw)
        for wrong in (raw, opened + '\n// "max-quic-wg"\n', opened.replace('"max-tls-awg"', '"other-max"'),
                      opened.replace(own_case, own_case.replace('return true', 'return false')),
                      opened.replace('func DesktopNodePhysicalGraphSupported', 'func unrelated')):
            with self.assertRaises(ValueError):
                GATE.closed_predicate(wrong)
        for kwargs in ({'prospective': True, 'closed': True},
                       {'prospective': False, 'closed': True, 'mutation': ('unrelated-control',)}):
            with self.assertRaisesRegex(ValueError, 'cannot alter native execution controls'):
                GATE.overlay(self.source, self.directory('conflict-' + str(len(kwargs))), **kwargs)

    def test_native_mutations_remain_scoped_and_cannot_replace_another_owner(self):
        with patch.object(GATE.MAX, 'mutations', return_value=()):
            controls = GATE.mutations(self.source)
            self.assertEqual(len(controls), 7)
            self.assertEqual({row[2].split('/')[0] for row in controls}, {'max-quic-wg', 'max-tls-wg', 'retained-middle-idle'})
            for mutation in controls:
                mapping = self.assert_native_scope(GATE.overlay(self.source, self.directory(mutation[0]), prospective=True, mutation=mutation))
                self.assertIn(str(self.source / GATE.PREDICATE), mapping)
                if mutation[0].startswith('ordinary-max-'):
                    raw = Path(mapping[str(self.source / mutation[4][1])]).read_text()
                    self.assertIn('p.pair("deny", family, 1, true, true)', raw)
            unowned = (*controls[0][:-1], ('routervpn/mobiletor/desktop_socket_windows_policy.go', 'package mobiletor\n'))
            with self.assertRaisesRegex(ValueError, 'exact compiled controls'):
                GATE.overlay(self.source, self.directory('unowned'), prospective=True, mutation=unowned)
        foreign = self.source / 'routervpn/mobiletor/desktop_socket_windows_node_composition_overlay.go'
        foreign.write_text('package mobiletor\n// retained another owner\n')
        with self.assertRaisesRegex(ValueError, 'Unowned Windows Node observer'):
            GATE.overlay(self.source, self.directory('foreign'), prospective=True)
        self.assertIn('retained another owner', foreign.read_text())

    def test_wrong_tuple_controls_observe_the_unchanged_live_lower_rejection(self):
        lower = 'routervpn/desktoppt/node_physical.go'
        for protocol, family, relative in (('tcp', 'TLS', 'protocol/routervpnxray/outbound.go'),
                                           ('udp', 'QUIC', 'protocol/hysteria2/outbound.go')):
            label = 'different-outer-' + protocol + '-tuple'
            parent = 'TestRouterVPNDesktopNodeCompleteMAX' + family
            case = 'max-' + family.lower() + '-wg/off'
            witness = GATE.MAX.tuple_witness(protocol)
            replacement = 'package captured\n// changed exact ' + protocol + ' tuple\n'
            control = (label, relative, parent, case, witness, replacement)
            with self.subTest(protocol=protocol), patch.object(GATE.MAX, 'mutations', return_value=(control,)):
                mutation = GATE.mutations(self.source)[0]
                selected = GATE.overlay(self.source, self.directory(label), prospective=True, mutation=mutation)
                mapping = self.assert_native_scope(selected)
                self.assertEqual(Path(mapping[str(self.source / relative)]).read_text(), replacement)
                observer = Path(mapping[str(self.source / lower)]).read_text()
                self.assertIn('!closed && !allowed && owner != nil && owner.SocketCurrent() && base == "' + protocol + '"', observer)
                self.assertIn('if closed || !allowed || owner == nil || !owner.SocketCurrent() {', observer)
                self.assertIn('println(' + json.dumps(witness) + ')', observer)
                self.assertEqual((self.source / lower).read_bytes(), self.original[lower])
                recorded = GATE.overlay_source_hashes(self.source, selected)
                self.assertEqual(recorded[lower], GATE.MAX.regular_digest(Path(mapping[str(self.source / lower)])))
                self.assertIn(relative, recorded)
                native_parent = GATE.native_parent(parent)
                actual = failure(native_parent, case, witness)
                GATE.rejected_output(1, actual, native_parent, case, witness)
                for unrelated in ('PQ transport write failed', 'protected PQ peer transport could not open', 'context deadline exceeded'):
                    with self.assertRaises(ValueError):
                        GATE.rejected_output(1, actual.replace(witness, unrelated), native_parent, case, witness)

    def test_ordinary_bypass_controls_require_captured_native_or_independent_delivery_denial(self):
        for protocol, family, relative, replacement in (
                ('tcp', 'TLS', 'protocol/routervpnxray/outbound.go',
                 'conn, err := (&net.Dialer{}).DialContext(cctx, N.NetworkTCP, b.server.String())'),
                ('udp', 'QUIC', 'protocol/hysteria2/outbound.go',
                 'Dialer:             func() N.Dialer { _ = outboundDialer; return N.SystemDialer }(),')):
            label, parent, case = 'uncaptured-outer-' + protocol, 'TestRouterVPNDesktopNodeCompleteMAX' + family, 'max-' + family.lower() + '-wg/off'
            control = (label, relative, parent, case, 'old generic witness', replacement)
            with self.subTest(protocol=protocol), patch.object(GATE.MAX, 'mutations', return_value=(control,)):
                mutation = GATE.mutations(self.source)[0]
                self.assertEqual(mutation[3], GATE.ordinary_witness(protocol))
                selected = GATE.overlay(self.source, self.directory(label), prospective=True, mutation=mutation)
                mapping = self.assert_native_scope(selected)
                observer = 'routervpn/mobiletor/desktop_socket_windows_max_control_overlay.go'
                body = Path(mapping[str(self.source / observer)]).read_text()
                self.assertEqual(body, GATE.ORDINARY_OBSERVER)
                self.assertIn('if !errors.Is(err, syscall.Errno(10013)) {', body)
                self.assertIn('before.Target != after.Target || before.Capture != after.Capture || before.Owner != after.Owner', body)
                self.assertIn('policy.Current(snapshot.Capture, snapshot.Owner)', body)
                self.assertIn('snapshot.Options.PrivateDestinations[0] != (DesktopWindowsSocketDestination{Network: network, Address: remote})', body)
                denial = body[body.index('func desktopMAXControlDenied('):body.index('type desktopMAXControlConn struct')]
                self.assertNotIn('timeout.Timeout()', denial)
                self.assertIn(observer, GATE.overlay_source_hashes(self.source, selected))
                if protocol == 'udp':
                    peer = Path(mapping[str(self.source / GATE.PEER)]).read_text()
                    self.assertIn('peer.mu.Lock()', peer)
                    self.assertIn('peer.source.digest() != peer.reply.SourceSHA256', peer)
                    self.assertIn('reply.Probe != nonce || reply.ProbeCount < 0', peer)
                    self.assertIn('peer.observeLocked(ctx, action+" "+nonce)', peer)
                    helper_path = 'protocol/routervpnpq/node_max_udp_control_test.go'
                    self.assertEqual(Path(mapping[str(self.source / helper_path)]).read_text(),
                                     GATE.PREFIX.decode().split('package ', 1)[0] +
                                     (GATE.UDP_CONTROL / 'udp_observation.go').read_text())
                else:
                    self.assertNotIn(str(self.source / GATE.PEER), mapping)
                witness = mutation[3]
                actual = failure(GATE.native_parent(parent), case, witness)
                GATE.rejected_output(1, actual, GATE.native_parent(parent), case, witness)
                for unrelated in ('actual PQ Node startup', 'context deadline exceeded', 'WSAETIMEDOUT', GATE.ordinary_witness('udp' if protocol == 'tcp' else 'tcp')):
                    with self.assertRaises(ValueError):
                        GATE.rejected_output(1, actual.replace(witness, unrelated), GATE.native_parent(parent), case, witness)
                owned = self.source / observer
                owned.write_text('package mobiletor\n// another retained owner\n')
                with self.assertRaisesRegex(ValueError, 'unowned source'):
                    GATE.overlay(self.source, self.directory(label + '-occupied'), prospective=True, mutation=mutation)
                owned.unlink()

    def test_later_invalid_observation_cannot_reuse_an_earlier_denial(self):
        parent, case = 'TestRouterVPNDesktopNodeWindowsMAXQUIC', 'max-quic-wg/off'
        witness = GATE.ordinary_witness('udp')
        valid = failure(parent, case, witness)
        for reason in ('independent-delivery-proof-failed', 'delivery-readback-rejected',
                       'missing-independent-reference', 'udp-captured-input-rejected',
                       'denial-readback-rejected', 'udp-dial-lost-captured-socket'):
            invalid = GATE.INVALID_ORDINARY + ' ' + reason + '\n'
            for output in (valid + invalid, invalid + valid):
                with self.subTest(reason=reason, before=output.startswith(invalid)):
                    with self.assertRaisesRegex(ValueError, 'invalidated its captured delivery evidence'):
                        GATE.rejected_output(1, output, parent, case, witness)

    def test_control_stage_diagnostics_never_replace_exact_native_denial(self):
        for protocol, family in (('tcp', 'TLS'), ('udp', 'QUIC')):
            parent = 'TestRouterVPNDesktopNodeWindowsMAX' + family
            case = 'max-' + family.lower() + '-wg/off'
            witness = GATE.ordinary_witness(protocol)
            for stage in ('ordinary-dial', 'ordinary-write', 'ordinary-read',
                          'native-readback-error', 'captured-policy-not-current',
                          'denial-readback-rejected'):
                diagnostic = ('MAX native ordinary control stage ' + stage + ' network ' + protocol +
                              ' error true errno 10013 timeout false')
                output = failure(parent, case, diagnostic)
                with self.subTest(protocol=protocol, stage=stage):
                    with self.assertRaisesRegex(ValueError, 'missed its exact executable rejection'):
                        GATE.rejected_output(1, output, parent, case, witness)
                    GATE.rejected_output(1, output.replace(diagnostic, diagnostic + '\n' + witness),
                                         parent, case, witness)

    def test_late_handshake_witness_requires_the_live_unready_native_lower(self):
        with patch.object(GATE.MAX, 'mutations', return_value=()):
            for control in GATE.mutations(self.source):
                if not control[0].startswith('late-max-handshake-'):
                    continue
                protocol = 'tcp' if control[0].endswith('tls') else 'udp'
                selected = GATE.overlay(self.source, self.directory(control[0]), prospective=True, mutation=control)
                mapping = self.assert_native_scope(selected)
                raw = Path(mapping[str(self.source / 'routervpn/desktoppt/node_physical.go')]).read_text()
                self.assertIn('!closed && allowed && owner != nil && owner.SocketCurrent() && !owner.Current() && base == "' + protocol + '"', raw)
                self.assertIn('snapshot.Capture == owner.brokerCapture()', raw)
                self.assertIn('if closed || !allowed || owner == nil || !owner.Current() {', raw)
                self.assertEqual(control[3], GATE.handshake_witness(protocol))
                for wrong in ('actual PQ Node startup', 'context deadline exceeded', GATE.handshake_witness('udp' if protocol == 'tcp' else 'tcp')):
                    with self.assertRaises(ValueError):
                        GATE.rejected_output(1, failure(control[1], control[2], wrong), control[1], control[2], control[3])

    def test_compiled_overlay_receipts_detect_changed_aliased_and_escaped_sources(self):
        selected = GATE.overlay(self.source, self.directory('overlay-receipt'), prospective=True)
        captured = GATE.overlay_source_hashes(self.source, selected)
        value = json.loads(selected.read_text())
        original, replacement = next(iter(value['Replace'].items()))
        path = Path(replacement)
        raw = path.read_bytes()
        path.write_bytes(raw + b'\n// changed compiled overlay\n')
        self.assertNotEqual(GATE.overlay_source_hashes(self.source, selected), captured)
        path.unlink()
        path.symlink_to(self.source / GATE.PREDICATE)
        with self.assertRaisesRegex(ValueError, 'captured regular file'):
            GATE.overlay_source_hashes(self.source, selected)
        path.unlink()
        path.write_bytes(raw)
        value['Replace'][str(self.work / 'foreign-owner.go')] = value['Replace'].pop(original)
        selected.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            GATE.overlay_source_hashes(self.source, selected)

    def test_every_native_graph_case_requires_real_unique_pass_evidence(self):
        self.assertEqual(sum(map(len, GATE.MAX.TRAFFIC.values())), 12)
        self.assertEqual(sum(map(len, GATE.MAX.CREDENTIALS.values())), 48)
        for family in GATE.MAX.FAMILIES:
            for suffix, cases in (('', GATE.MAX.TRAFFIC[family]), ('Credentials', GATE.MAX.CREDENTIALS[family])):
                parent = 'TestRouterVPNDesktopNodeWindowsMAX'+family+suffix
                complete = '\n'.join('--- PASS: '+value+' (1.00s)' for value in (parent, *(parent+'/'+case for case in cases)))+'\nPASS\n'
                GATE.MAX.required_output(0, complete, parent, cases)
                for case in cases:
                    marker = '--- PASS: '+parent+'/'+case+' (1.00s)'
                    for changed in (complete.replace(marker, 'fixture.go:42: '+marker), complete+marker+'\n'):
                        with self.assertRaisesRegex(ValueError, 'omitted or duplicated'):
                            GATE.MAX.required_output(0, changed, parent, cases)

    def test_missing_or_failed_startup_parser_cannot_reuse_graph_evidence(self):
        graph = 'TestRouterVPNDesktopNodeWindowsMAXTLS'
        complete = '\n'.join('--- PASS: ' + value + ' (0.01s)' for value in
                             (graph, *(graph + '/' + case for case in GATE.MAX.TRAFFIC['TLS'])))
        marker = '--- PASS: ' + GATE.STARTUP_RECORDS + ' (0.00s)'
        GATE.MAX.required_output(0, complete + '\n' + marker, GATE.STARTUP_RECORDS, ())
        for status, output in ((0, complete), (1, complete + '\n' + marker.replace('PASS', 'FAIL')),
                               (0, complete + '\n    fixture.go:1: ' + marker),
                               (0, complete + '\n' + marker + '\n' + marker)):
            with self.assertRaises(ValueError):
                GATE.MAX.required_output(status, output, GATE.STARTUP_RECORDS, ())

    def test_marker_prerequisite_requires_actual_authentication_boundary(self):
        self.assertEqual(GATE.MARKER_CASES, ('bounded-input', 'unarmed-and-wrong-owner', 'encrypted-fragments',
                                           'exact-armed-stream', 'marker-and-authentication', 'packet-authentication',
                                           'reference-failure-channel', 'retained-reference-readback', 'key-epoch-barrier', 'retained-middle-idle'))
        complete = '\n'.join('--- PASS: ' + value + ' (0.01s)' for value in
                             (GATE.MARKERS, *(GATE.MARKERS + '/' + case for case in GATE.MARKER_CASES))) + '\nPASS\n'
        GATE.MAX.required_output(0, complete, GATE.MARKERS, GATE.MARKER_CASES)
        for case in ('marker-and-authentication', 'packet-authentication', 'reference-failure-channel', 'retained-reference-readback', 'key-epoch-barrier', 'retained-middle-idle'):
            marker = '--- PASS: ' + GATE.MARKERS + '/' + case + ' (0.01s)'
            for status, output in ((0, complete.replace(marker, '')), (1, complete.replace(marker, marker.replace('PASS', 'FAIL'))),
                                   (0, complete.replace(marker, 'fixture.go:1: ' + marker)), (0, complete + marker + '\n')):
                with self.subTest(case=case), self.assertRaises(ValueError):
                    GATE.MAX.required_output(status, output, GATE.MARKERS, GATE.MARKER_CASES)

    def test_reference_lifetime_control_changes_only_the_actual_peer_cache(self):
        with patch.object(GATE.MAX, 'mutations', return_value=()):
            controls = GATE.mutations(self.source)
            selected = controls[-1]
            self.assertEqual(selected[:5], ('expired-reference-association', GATE.MARKERS,
                             'retained-middle-idle',
                             'MAX retained authenticated middle changed its owned UDP association', None))
            relative, replacement = selected[5]
            self.assertEqual(relative, 'protocol/routervpnpq/node_max_peer_test.go')
            actual = (self.source / relative).read_text()
            before = 'secret, int64(nodeMAXReferenceLifetime/time.Second), nodeMAXMiddleHandler{s, tcpRoutes}, nil)'
            after = 'secret, 10, nodeMAXMiddleHandler{s, tcpRoutes}, nil)'
            self.assertEqual(replacement, actual.replace(before, after, 1))
            self.assertIn('const nodeMAXReferenceLifetime = 240 * time.Second', actual)
            native = (ROOT / GATE.PEER_TEMPLATE).read_text()
            self.assertIn('context.WithTimeout(context.Background(), nodeMAXReferenceLifetime)', native)
            self.assertIn('"-test.timeout=235s"', native)
            self.assertIn('nodeMAXSS(t, nodeMAXUDP(t, ip), nil, secret,', native)
            self.assertIn('t.Run("retained-middle-idle", nodeMAXWFPRetainedMiddleIdle)', native)
            with self.assertRaisesRegex(ValueError, 'exact production boundary'):
                (self.source / relative).write_text(actual.replace(before, after))
                GATE.mutations(self.source)

    def test_compiled_control_requires_exact_failure_and_acknowledged_cleanup(self):
        parent, case, witness = 'TestMAX', 'max-tls-wg/aes-256-gcm+xor-whitening/middle-key', 'actual intended defect'
        output = failure(parent, case, witness)
        GATE.rejected_output(1, output, parent, case, witness)
        GATE.rejected_output(1, output.replace('\n', '\r\n'), parent, case, witness)
        for status, changed in ((0,output), (2,output), (-9,output), (1,output.replace(witness,'unrelated')),
                (1,output.replace(parent+'/'+case, parent+'/other')),
                (1,output+'--- FAIL: malformed failure\n'), (1,output+'--- FAIL: unrelated (0.01s)\n'),
                (1,output.replace('\nFAIL\n','\n')), (1,output+'fatal: unrelated failure'),
                (1,output+'--- SKIP: other (0.01s)'), (1,output+'DATA RACE'),
                *((1,output+message.upper()) for message in GATE.JOIN_FAILURES)):
            with self.subTest(status=status, changed=changed[-80:]):
                with self.assertRaises(ValueError):
                    GATE.rejected_output(status, changed, parent, case, witness)

    def test_authoritative_receipt_requires_the_exact_clean_commit(self):
        sha, tree = 'a'*40, 'b'*40
        def answer(commit=sha, status=''):
            def call(command, **kwargs):
                self.assertEqual(kwargs['cwd'], GATE.ROOT)
                return commit+'\n' if command[-1]=='HEAD^{commit}' else tree+'\n' if command[-1]=='HEAD^{tree}' else status
            return call
        with patch.object(GATE.subprocess,'check_output',side_effect=answer()):
            actual = GATE.repository_identity(sha)
            self.assertEqual(actual['commit'],sha)
            self.assertEqual(actual['tree'],tree)
            self.assertTrue(actual['clean'])
        for expected, reply in ((sha,answer('c'*40)), (sha,answer(status=' M cmd/client/main.go\n')),
                               (sha,answer(status='?? internal/other.go\n')), ('a'*8,answer()), (sha.upper(),answer())):
            with patch.object(GATE.subprocess,'check_output',side_effect=reply):
                with self.assertRaisesRegex(ValueError,'exact clean repository commit'):
                    GATE.repository_identity(expected)

    def test_native_source_closure_binds_actual_acl_helper_and_acceptance(self):
        dependencies = ('client/Protect-RouterVPN-Windows-PrivateRoot.ps1',
                        'client/test-windows-private-acl.ps1',
                        'deploy/build_pq_reference_fixture.py',
                        'deploy/test_pq_reference_preparation.py')
        with patch.object(GATE.MAX, 'checked_sources', return_value=(self.source, {})), \
             patch.object(GATE.WPQ, 'checked_sources', return_value=(self.source, {})):
            actual, records = GATE.checked_sources(self.source)
            self.assertEqual(actual, self.source)
            for relative in dependencies:
                self.assertEqual(records['windows-max/' + relative], GATE.MAX.regular_digest(ROOT / relative))
            # A source receipt cannot attest an alias to a different owner's
            # helper even when its current bytes happen to be identical.
            shadow = self.directory('aliased-reference-source')
            for relative in (GATE.PEER_TEMPLATE, 'deploy/test_windows_node_max.py',
                             'deploy/test_windows_node_max_runner.py', *dependencies):
                target = shadow / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            helper = shadow / dependencies[0]
            helper.unlink()
            helper.symlink_to(ROOT / dependencies[0])
            with patch.object(GATE, 'ROOT', shadow), self.assertRaisesRegex(ValueError, 'captured regular file'):
                GATE.checked_sources(self.source)

    def test_foreign_host_and_disabled_cgo_cannot_reach_a_native_operation(self):
        with patch.object(GATE.platform,'system',return_value='Linux'), patch.object(GATE,'checked_sources') as source:
            with self.assertRaisesRegex(ValueError,'actual elevated Windows'):
                GATE.execute(self.source,self.work/'pq',self.work/'cache')
            source.assert_not_called()
        for captured in ({'GOOS':'windows','CGO_ENABLED':'0'}, {'GOOS':'linux','CGO_ENABLED':'1'}):
            with patch.object(GATE.platform,'system',return_value='Windows'), \
                 patch.object(GATE.WFP.BOOT.IDENTITY.ctypes,'windll',create=True) as native, \
                 patch.object(GATE,'repository_identity',return_value={'commit':'a'*40}), \
                 patch.object(GATE,'checked_sources',return_value=(self.source,{})), \
                 patch.object(GATE.NODE,'selected_compiler',return_value=(Path('go'),captured,'amd64')), \
                 patch.object(GATE.REFERENCE.BUILD.PQ,'verify') as archive:
                native.shell32.IsUserAnAdmin.return_value=True
                with self.assertRaisesRegex(ValueError,'real CGO ABI'):
                    GATE.execute(self.source,self.work/'pq',self.work/'cache')
                archive.assert_not_called()

    def test_preexisting_receipts_and_unretired_workspaces_are_preserved(self):
        output=self.work/'receipt.json'
        output.write_text('retained original receipt')
        with self.assertRaisesRegex(ValueError,'new owned file'):
            GATE.WPQ.new_receipt_path(output)
        self.assertEqual(output.read_text(),'retained original receipt')
        missing=self.work/'new.json'
        owner=self.directory('retained-workspace')
        with self.assertRaisesRegex(ValueError,'cleanup was not acknowledged'):
            GATE.WPQ.publish_receipt(missing,{},owner)
        self.assertFalse(missing.exists())
        owner.rmdir()
        GATE.WPQ.publish_receipt(missing,{'joined':True},owner)
        self.assertTrue(json.loads(missing.read_text())['joined'])

    def test_closed_main_requires_explicit_prospective_before_native_actions(self):
        with patch.object(GATE.platform, 'system', return_value='Windows'), \
             patch.object(GATE.WFP.BOOT.IDENTITY.ctypes, 'windll', create=True) as native, \
             patch.object(GATE, 'repository_identity', return_value={'commit': 'a' * 40}), \
             patch.object(GATE, 'checked_sources', return_value=(self.source, {})), \
             patch.object(GATE.NODE, 'selected_compiler', return_value=(Path('go'), {'GOOS': 'windows', 'CGO_ENABLED': '1'}, 'arm64')), \
             patch.object(GATE.REFERENCE.BUILD.PQ, 'verify') as archive:
            native.shell32.IsUserAnAdmin.return_value = True
            with self.assertRaisesRegex(ValueError, 'exact shipping family'):
                GATE.execute(self.source, self.work / 'pq', self.work / 'cache')
            archive.assert_not_called()

    @contextmanager
    def execution_harness(self, receipt):
        # Native subprocesses and the separately tested generic 16-control
        # driver are modeled. The six native scope controls and exact reference
        # lifetime defect, case registration, overlays, hashes and cleanup run here.
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(GATE.MAX, 'mutations', return_value=()))
        state = {'closed_binary': None, 'compiled_overlays': {}, 'native_calls': [], 'removed_controls': []}
        state.update(dependency_events=[], process_commands=[], key_calls=0)
        controls = {item[0]: item for item in GATE.mutations(self.source)}
        cache = self.work / 'cache'
        timers = GATE.REFERENCE.BUILD.POLICY.AMNEZIA.TIMERS

        def timer_command(args, **kwargs):
            # Exercise the real plan/selected-source verifier; model only Go
            # metadata and the independently tested complete archive boundary.
            self.assertEqual(kwargs, {'cwd': self.source, 'env': state['dependency_env'], 'text': True})
            self.assertIs(kwargs['env'], state['dependency_env'])
            self.assertEqual(kwargs['env'], state['dependency_snapshot'])
            if args == [Path('go'), 'mod', 'edit', '-json']:
                state['dependency_events'].append('plan')
                replacements = [{'Old': {'Path': timers.MODULE, 'Version': timers.VERSION},
                                 'New': {'Path': './' + timers.COPY}}]
                if state.get('dependency_fault') == 'missing':
                    replacements = []
                elif state.get('dependency_fault') == 'foreign':
                    replacements[0]['New']['Path'] = './foreign-module'
                return json.dumps({'Require': [{'Path': timers.MODULE, 'Version': timers.VERSION}], 'Replace': replacements})
            if args == [Path('go'), 'list', '-m', '-mod=readonly', '-json', timers.MODULE]:
                state['dependency_events'].append('selection')
                selected = self.source / (timers.COPY if state.get('dependency_fault') != 'selected' else 'foreign-module')
                return json.dumps({'Path': timers.MODULE, 'Version': timers.VERSION, 'Dir': str(selected),
                                  'Replace': {'Path': './' + timers.COPY, 'Dir': str(selected)}})
            self.fail('Unexpected timer verifier command: ' + repr(args))

        def timer_tree(selected):
            self.assertEqual(selected, self.source / timers.COPY)
            self.assertEqual(state['dependency_events'], ['checksum', 'plan', 'selection'])
            state['dependency_events'].append('tree')
            if state.get('dependency_fault') == 'tree':
                raise ValueError('modeled pinned AWG tree rejection')

        def keys(target, _cache, path):
            self.assertEqual(state['dependency_events'], ['checksum', 'plan', 'selection', 'tree'])
            state['key_calls'] += 1
            path.mkdir(parents=True)
            (path / 'private-fixture-key').write_bytes(b'owned test-only key marker')
            generator = cache / GATE.REFERENCE.BUILD.PQ.TARGETS[target] / 'release/examples/native_keys.exe'
            generator.parent.mkdir(parents=True, exist_ok=True)
            generator.write_bytes(b'owned test-only key generator')

        def relay(_compiler, workspace, _env, _race):
            binary = workspace / 'relay.exe'
            binary.write_bytes(b'owned test-only relay')
            return binary, GATE.MAX.regular_digest(binary)

        def xray(_compiler, _source, workspace, _env, _race):
            binary = workspace / 'xray.exe'
            binary.write_bytes(b'owned test-only Xray')
            source = workspace / 'xray-source'
            source.mkdir()
            return binary, GATE.MAX.regular_digest(binary), source, {'test-only-xray': 'source'}

        def output(parent, cases=()):
            return '\n'.join('--- PASS: ' + name + ' (0.01s)' for name in (parent, *(parent + '/' + case for case in cases))) + '\n'

        def command(arguments, **kwargs):
            self.assertFalse(receipt.exists(), 'success receipt preceded native proof and private cleanup')
            args = [str(value) for value in arguments]
            state['process_commands'].append(args)
            if args[1:3] == ['mod', 'verify']:
                state['dependency_events'].append('checksum')
                state['dependency_env'] = kwargs['env']
                state['dependency_snapshot'] = dict(kwargs['env'])
                if state.get('dependency_fault') == 'checksum':
                    return 1, 'modeled original module checksum rejection'
                return 0, 'all modules verified\n'
            self.assertEqual(state['dependency_events'], ['checksum', 'plan', 'selection', 'tree'])
            if args[1:3] == ['test', '-c']:
                binary = Path(args[args.index('-o') + 1])
                if state['closed_binary'] is not None:
                    self.assertFalse(state['closed_binary'].exists(), 'closed-admission executable survived into positive compilation')
                selected = Path(next(value.removeprefix('-overlay=') for value in args if value.startswith('-overlay=')))
                mapping = json.loads(selected.read_text())['Replace']
                state['compiled_overlays'][binary.parent.name] = {Path(original).relative_to(self.source).as_posix(): Path(replacement).read_text()
                                                                for original, replacement in mapping.items()}
                binary.write_bytes(('owned test-only compiled ' + binary.parent.name).encode())
                if binary.parent.name.endswith('closed-capability'):
                    state['closed_binary'] = binary
                if 'on_compile' in state:
                    state['on_compile'](binary, selected)
                return 0, ''
            if args[1] == 'test':
                if str(GATE.UDP_CONTROL / 'udp_observation.go') in args:
                    if state.get('omit_udp_case'):
                        return 0, output(GATE.UDP_OBSERVATION, GATE.UDP_CASES[:-1]) + 'PASS\n'
                    return 0, output(GATE.UDP_OBSERVATION, GATE.UDP_CASES) + 'PASS\n'
                return 0, output('TestWindowsNodeObserverTransportPeer') + 'PASS\n'
            binary = Path(args[0])
            for previous in state['removed_controls']:
                self.assertFalse(previous.exists(), 'native mutants accumulated after their owned completion')
            state['native_calls'].append((args, kwargs['timeout']))
            if 'on_run' in state:
                state['on_run'](binary)
            if binary.parent.name in controls:
                state['removed_controls'].append(binary)
                _, parent, case, witness, _, _ = controls[binary.parent.name]
                return 1, failure(parent, case, witness)
            selector = next(value.removeprefix('-test.run=') for value in args if value.startswith('-test.run='))
            if selector.startswith('^Test(RealPinnedFactory'):
                self.assertIsNotNone(re.search(selector, GATE.PORT_PAIR), 'native MAX omitted retained port-pair execution')
                result = ''.join(output(parent, ('v2', 'v3') if parent == 'TestRealPinnedFactoryExchangeAndRekey' else ())
                                 for parent in GATE.MAX.PQ.NATIVE_CASES) + output(GATE.STARTUP_RECORDS)
                if state.get('failed_port_pair'):
                    return 1, result + '--- FAIL: ' + GATE.PORT_PAIR + ' (0.01s)\n'
                if not state.get('omit_port_pair'):
                    cases = GATE.PORT_PAIR_CASES[:-1] if state.get('omit_port_pair_leaf') else GATE.PORT_PAIR_CASES
                    result += output(GATE.PORT_PAIR, cases)
                return 0, result + 'PASS\n'
            parent = selector[1:-1]
            cases = {GATE.CLOSED: GATE.MODES, GATE.OPEN: (), GATE.MARKERS: GATE.MARKER_CASES,
                     GATE.SUCCESSION: tuple(mode + '/' + layer for mode in GATE.MODES for layer in GATE.LAYERS), GATE.FOREIGN: GATE.MODES}
            for family in GATE.MAX.FAMILIES:
                cases['TestRouterVPNDesktopNodeWindowsMAX' + family] = GATE.MAX.TRAFFIC[family]
                cases['TestRouterVPNDesktopNodeWindowsMAX' + family + 'Credentials'] = GATE.MAX.CREDENTIALS[family]
            result = output(parent, cases[parent]) + 'PASS\n'
            if parent == GATE.CLOSED and state.get('omit_closed_leaf'):
                result = result.replace('--- PASS: ' + parent + '/' + GATE.MODES[-1] + ' (0.01s)\n', '')
            return 0, result

        with stack:
            stack.enter_context(patch.object(GATE.platform, 'system', return_value='Windows'))
            native = stack.enter_context(patch.object(GATE.WFP.BOOT.IDENTITY.ctypes, 'windll', create=True))
            native.shell32.IsUserAnAdmin.return_value = True
            stack.enter_context(patch.object(GATE, 'repository_identity', return_value={'commit': 'a' * 40, 'clean': True}))
            stack.enter_context(patch.object(GATE, 'checked_sources', return_value=(self.source, {'test-model': 'source'})))
            stack.enter_context(patch.object(GATE.NODE, 'selected_compiler', return_value=(Path('go'), dict(os.environ, GOOS='windows', CGO_ENABLED='1'), 'arm64')))
            stack.enter_context(patch.object(GATE.MAX, 'tool_receipts', return_value={'test-only-tools': 'pinned'}))
            stack.enter_context(patch.object(GATE.MAX, 'dependency_receipt', return_value={'test-only-dependencies': 'pinned'}))
            stack.enter_context(patch.object(GATE.REFERENCE.BUILD.PQ, 'verify', return_value={'native_static_libs': []}))
            stack.enter_context(patch.object(timers.subprocess, 'check_output', side_effect=timer_command))
            stack.enter_context(patch.object(timers, 'verify_tree', side_effect=timer_tree))
            state['timer_verifier'] = stack.enter_context(patch.object(timers, 'verify', wraps=timers.verify))
            stack.enter_context(patch.object(GATE.REFERENCE, 'generate_keys', side_effect=keys))
            stack.enter_context(patch.object(GATE.REFERENCE, 'key_files', return_value={'test-only-key': 'unchanged'}))
            stack.enter_context(patch.object(GATE.REFERENCE, 'test_sources', side_effect=lambda _source: nullcontext()))
            stack.enter_context(patch.object(GATE.NODE, 'build_layer_reference', side_effect=relay))
            stack.enter_context(patch.object(GATE.NODE, 'build_xray_reference', side_effect=xray))
            stack.enter_context(patch.object(GATE.NODE, 'xray_reference_sources', return_value={'test-only-xray': 'source'}))
            stack.enter_context(patch.object(GATE.NODE, 'run', side_effect=AssertionError('MAX escaped its original command owner')))
            def owned_command(arguments, **kwargs):
                status, output = command(arguments, **kwargs)
                args = [str(value) for value in arguments]
                if status:
                    raise subprocess.CalledProcessError(status, args, output=output.encode(), stderr=b'')
                return subprocess.CompletedProcess(args, status, output.encode(), b'')
            stack.enter_context(patch.object(GATE.REFERENCE.BUILD.BUILD_OWNER, 'run', side_effect=owned_command))
            def observation(compiler, source, captured, race, files, parent, cases):
                status, output = command([compiler, 'test', *files], cwd=source, env=captured, timeout=45)
                GATE.MAX.required_output(status, output, parent, cases)
            stack.enter_context(patch.object(GATE, 'observation_contract', side_effect=observation))
            yield state

    def test_shipping_driver_requires_retired_closed_control_and_all_native_cases(self):
        raw = self.shipping_predicate()
        receipt = self.work / 'shipping-native-max.json'
        with self.execution_harness(receipt) as state:
            result = GATE.execute(self.source, self.work / 'pq', self.work / 'cache', receipt_path=receipt)
        self.assertEqual(result['public_admission'], 'shipping-predicate')
        self.assertIs(result['complete_inventory_proved'], True)
        self.assertEqual(result['receipt_kind'], 'complete-max')
        self.assertEqual(result['execution_suite'], 'complete')
        state['timer_verifier'].assert_called_once_with(self.source, Path('go'), env=state['dependency_env'])
        self.assertEqual(state['dependency_events'], ['checksum', 'plan', 'selection', 'tree'])
        self.assertFalse(result['prospective'])
        self.assertEqual(result['closed_admission_source'], 'exact-family-removed')
        self.assertEqual(result['closed_admission_control']['parent'], GATE.CLOSED)
        self.assertEqual(len(result['compiled_negative_controls']), 7)
        self.assertEqual(len(state['removed_controls']), 7)
        self.assertTrue(result['private_key_workspace_removed'])
        self.assertFalse(state['closed_binary'].exists())
        self.assertEqual(result['port_pair_case'], GATE.PORT_PAIR)
        self.assertEqual(result['port_pair_subcases'], GATE.PORT_PAIR_CASES)
        self.assertEqual(result['port_pair_output_sha256'], result['startup_record_output_sha256'])
        for name, mapping in state['compiled_overlays'].items():
            if name == 'shipping-closed-capability':
                self.assertEqual(mapping[GATE.PREDICATE], GATE.closed_predicate(raw))
            else:
                self.assertNotIn(GATE.PREDICATE, mapping)
        self.assertEqual((self.source / GATE.PREDICATE).read_text(), raw)
        self.assertEqual(json.loads(receipt.read_text()), json.loads(json.dumps(result)))
        reversal_deadlines, control_deadlines, marker_deadlines = [], [], []
        for args, outer_timeout in state['native_calls']:
            inner = int(next(value.removeprefix('-test.timeout=')[:-1] for value in args if value.startswith('-test.timeout=')))
            self.assertEqual(outer_timeout, inner + 15)
            if '-test.run=^' + GATE.SUCCESSION + '$' in args:
                reversal_deadlines.append((inner, outer_timeout))
            if '-test.run=^' + GATE.MARKERS + '$' in args:
                marker_deadlines.append((inner, outer_timeout))
            if Path(args[0]) in state['removed_controls']:
                control_deadlines.append((inner, outer_timeout))
        self.assertEqual(reversal_deadlines, [(3000, 3015)])
        self.assertEqual(marker_deadlines, [(30, 45)], 'Complete marker selection lost its unchanged aggregate bound')
        self.assertEqual(control_deadlines, [(90, 105)] * 7,
                         'The reversal aggregate changed an individual native control deadline')

    def test_unverified_timer_dependency_prevents_keys_native_work_and_receipt(self):
        for fault, witness in (('checksum', 'checksum verification failed'),
                               ('missing', 'unrelated or missing AWG timer replacement'),
                               ('foreign', 'unrelated or missing AWG timer replacement'),
                               ('selected', 'exact selected private AWG timer copy'),
                               ('tree', 'pinned AWG tree rejection')):
            receipt = self.work / ('timer-' + fault + '.json')
            with self.subTest(fault=fault), self.execution_harness(receipt) as state:
                state['dependency_fault'] = fault
                with self.assertRaisesRegex(ValueError, witness):
                    GATE.execute(self.source, self.work / 'pq', self.work / 'cache',
                                 prospective=True, receipt_path=receipt)
            self.assertFalse(receipt.exists())
            self.assertEqual(state['key_calls'], 0)
            self.assertEqual(state['native_calls'], [])
            self.assertEqual(state['compiled_overlays'], {})
            self.assertEqual(state['process_commands'], [['go', 'mod', 'verify']])
            if fault == 'checksum':
                state['timer_verifier'].assert_not_called()
            else:
                state['timer_verifier'].assert_called_once_with(self.source, Path('go'), env=state['dependency_env'])

    def test_missing_or_failed_pair_proof_prevents_native_receipt(self):
        for fault in ('omit_port_pair', 'omit_port_pair_leaf', 'failed_port_pair'):
            receipt = self.work / (fault + '.json')
            with self.subTest(fault=fault), self.execution_harness(receipt) as state:
                state[fault] = True
                with self.assertRaises(ValueError):
                    GATE.execute(self.source, self.work / 'pq', self.work / 'cache', prospective=True, receipt_path=receipt)
            self.assertFalse(receipt.exists())
            self.assertFalse(any('-test.run=^' + GATE.SUCCESSION + '$' in args for args, _ in state['native_calls']))

    def test_prospective_driver_preserves_unmodified_closed_prerequisite(self):
        receipt = self.work / 'prospective-native-max.json'
        with self.execution_harness(receipt) as state:
            result = GATE.execute(self.source, self.work / 'pq', self.work / 'cache', prospective=True, receipt_path=receipt)
        self.assertTrue(result['current_closed_admission_proved'])
        self.assertEqual(result['closed_admission_source'], 'unmodified')
        for name, mapping in state['compiled_overlays'].items():
            self.assertEqual(GATE.PREDICATE in mapping, name != 'unmodified-closed-capability')

    def test_missing_closed_leaf_blocks_positive_compilation_and_receipt(self):
        self.shipping_predicate()
        receipt = self.work / 'missing-closed-max.json'
        with self.execution_harness(receipt) as state:
            state['omit_closed_leaf'] = True
            with self.assertRaisesRegex(ValueError, 'omitted or duplicated'):
                GATE.execute(self.source, self.work / 'pq', self.work / 'cache', receipt_path=receipt)
        self.assertEqual(set(state['compiled_overlays']), {'shipping-closed-capability'})
        self.assertFalse(receipt.exists())

    def test_missing_udp_observation_case_blocks_native_compilation_and_receipt(self):
        self.shipping_predicate()
        receipt = self.work / 'missing-udp-observation.json'
        with self.execution_harness(receipt) as state:
            state['omit_udp_case'] = True
            with self.assertRaisesRegex(ValueError, 'omitted or duplicated'):
                GATE.execute(self.source, self.work / 'pq', self.work / 'cache', receipt_path=receipt)
        self.assertEqual(state['compiled_overlays'], {})
        self.assertFalse(receipt.exists())

    def test_changed_compile_or_execution_overlay_prevents_publication(self):
        for phase in ('compile', 'closed', 'positive', 'negative'):
            receipt = self.work / (phase + '-changed-max.json')
            def changed(binary, selected=None):
                applies = phase == 'compile' or phase == 'closed' and binary.parent.name == 'unmodified-closed-capability' or \
                    phase == 'positive' and binary.parent.name == 'native-composition' or phase == 'negative' and binary.parent.name == GATE.mutations(self.source)[0][0]
                if not applies:
                    return
                mapping = json.loads((selected or binary.parent / 'overlay.json').read_text())['Replace']
                path = Path(next(iter(mapping.values())))
                path.write_text(path.read_text() + '\n// changed after exact source capture\n')
            with self.subTest(phase=phase), self.execution_harness(receipt) as state:
                state['on_compile' if phase == 'compile' else 'on_run'] = changed
                with self.assertRaisesRegex(ValueError, 'overlay changed'):
                    GATE.execute(self.source, self.work / 'pq', self.work / 'cache', prospective=True, receipt_path=receipt)
            self.assertFalse(receipt.exists())

    def test_standalone_receipt_waits_for_source_workspace_cleanup(self):
        for fail in (False, True):
            with self.subTest(cleanup_failure=fail):
                receipt=self.work/('failed.json' if fail else 'joined.json')
                repository={'commit':'a'*40,'tree':'b'*40,'clean':True}
                native=GATE.REFERENCE.BUILD
                original=dict(os.environ)
                observed=[]
                original_cleanup=GATE.shutil.rmtree
                def cleanup(directory, *args, **kwargs):
                    result=original_cleanup(directory, *args, **kwargs)
                    if fail: raise OSError('owned source cleanup acknowledgment failed')
                    return result
                def modeled_execute(source,pq,cache,go,**kwargs):
                    self.assertTrue(source.parent.is_dir())
                    self.assertFalse(receipt.exists())
                    self.assertNotIn('receipt_path',kwargs)
                    self.assertEqual(kwargs['expected_sha'],'a'*40)
                    observed.append(source.parent)
                    return {'repository':repository,'private_key_workspace_removed':True}
                with ExitStack() as stack:
                    stack.enter_context(patch.object(GATE.platform,'system',return_value='Windows'))
                    windll=stack.enter_context(patch.object(GATE.WFP.BOOT.IDENTITY.ctypes,'windll',create=True))
                    windll.shell32.IsUserAnAdmin.return_value=True
                    stack.enter_context(patch.object(GATE.NODE,'selected_compiler',return_value=(Path('go'),{'PATH':os.defpath,'GOOS':'windows','CGO_ENABLED':'1'},'amd64')))
                    stack.enter_context(patch.object(GATE,'execute',side_effect=modeled_execute))
                    stack.enter_context(patch.object(GATE,'repository_identity',return_value=repository))
                    stack.enter_context(patch.object(GATE.shutil,'rmtree',side_effect=cleanup))
                    stack.enter_context(patch.object(native,'checkout',side_effect=lambda path,*args:path.mkdir()))
                    for owner,name in ((native,'pristine'),(native.PQ,'build'),(native.POLICY,'prepare_native'),
                            (native.PERFORMANCE,'prepare'),(native.OPENVPN,'prepare'),(native.EXTERNAL,'prepare'),
                            (native.BUFFERS,'prepare'),(native,'run'),(native.POLICY.AMNEZIA,'verify')):
                        stack.enter_context(patch.object(owner,name,return_value=None))
                    if fail:
                        with self.assertRaisesRegex(OSError,'cleanup acknowledgment'):
                            GATE.standalone(prospective=True,receipt_path=receipt,expected_sha='a'*40)
                    else:
                        GATE.standalone(prospective=True,receipt_path=receipt,expected_sha='a'*40)
                self.assertEqual(dict(os.environ),original)
                self.assertEqual(len(observed),1)
                self.assertFalse(observed[0].exists())
                self.assertEqual(receipt.exists(),not fail)
                if not fail:
                    self.assertTrue(json.loads(receipt.read_text())['standalone_source_workspace_removed'])

    def test_standalone_retains_source_and_private_image_after_unproved_native_join(self):
        receipt=self.work/'unjoined-standalone.json'
        native=GATE.REFERENCE.BUILD
        previous=dict(os.environ); observed=[]
        def modeled_execute(source,pq,cache,go,**kwargs):
            owner=kwargs.get('command_owner')
            self.assertIsInstance(owner,GATE.MAXCommandOwner,'Standalone lost its original shared command owner')
            observed.append(source.parent)
            with owner.workspace('max-unproved-private-') as private:
                observed.append(private)
                image=private/'original.test.exe';image.write_bytes(b'original image')
                owner.run([image],cwd=source,env={},timeout=105)
        try:
            with ExitStack() as stack:
                stack.enter_context(patch.object(GATE.platform,'system',return_value='Windows'))
                windll=stack.enter_context(patch.object(GATE.WFP.BOOT.IDENTITY.ctypes,'windll',create=True))
                windll.shell32.IsUserAnAdmin.return_value=True
                stack.enter_context(patch.object(GATE.NODE,'selected_compiler',return_value=(Path('go'),{'PATH':os.defpath,'GOOS':'windows','CGO_ENABLED':'1'},'amd64')))
                stack.enter_context(patch.object(GATE,'execute',side_effect=modeled_execute))
                stack.enter_context(patch.object(GATE.REFERENCE.BUILD.BUILD_OWNER,'run',side_effect=RuntimeError('original native join unproved')))
                stack.enter_context(patch.object(native,'checkout',side_effect=lambda path,*args:path.mkdir()))
                for owner,name in ((native,'pristine'),(native.PQ,'build'),(native.POLICY,'prepare_native'),
                        (native.PERFORMANCE,'prepare'),(native.OPENVPN,'prepare'),(native.EXTERNAL,'prepare'),
                        (native.BUFFERS,'prepare'),(native,'run'),(native.POLICY.AMNEZIA,'verify')):
                    stack.enter_context(patch.object(owner,name,return_value=None))
                with self.assertRaisesRegex(RuntimeError,'original native join unproved'):
                    GATE.standalone(prospective=True,receipt_path=receipt)
            self.assertEqual(dict(os.environ),previous)
            self.assertFalse(receipt.exists())
            self.assertEqual(len(observed),2)
            self.assertTrue(all(path.is_dir() for path in observed),'Unproved original command lost its source or private workspace')
            self.assertEqual((observed[1]/'original.test.exe').read_bytes(),b'original image')
        finally:
            for directory in observed:
                if directory.exists():shutil.rmtree(directory)

    def test_actual_preparation_bridge_preserves_failure_and_source_workspace(self):
        native=GATE.REFERENCE.BUILD
        for kind in ('join', 'status', 'timeout'):
            receipt=self.work/(kind+'-prepare.json'); roots=[]; previous=dict(os.environ)
            command=['captured-go','mod','tidy']
            error=(RuntimeError('actual preparation descendant join unproved') if kind=='join' else
                   subprocess.CalledProcessError(7,command,output=b'original preparation stdout',stderr=b'original preparation stderr') if kind=='status' else
                   subprocess.TimeoutExpired(command,1800,output=b'original preparation stdout',stderr=b'original preparation stderr'))
            def checkout(path,*args):
                path.mkdir()
                if not roots:roots.append(path.parent)
            def unjoined(arguments,**kwargs):
                self.assertEqual([str(x) for x in arguments],command)
                self.assertEqual(kwargs['timeout'],1800,'Preparation changed its original default command deadline')
                self.assertEqual(kwargs['cwd'],roots[0]/'core')
                raise error
            try:
                with ExitStack() as stack:
                    stack.enter_context(patch.object(GATE.platform,'system',return_value='Windows'))
                    windll=stack.enter_context(patch.object(GATE.WFP.BOOT.IDENTITY.ctypes,'windll',create=True))
                    windll.shell32.IsUserAnAdmin.return_value=True
                    stack.enter_context(patch.object(GATE.NODE,'selected_compiler',return_value=(Path('captured-go'),{'PATH':os.defpath,'GOOS':'windows','CGO_ENABLED':'1'},'amd64')))
                    # Only the OS selection is modeled. The actual preparation
                    # bridge still calls the actual retained-owner entrypoint.
                    stack.enter_context(patch.object(native,'os',type('NativeHost',(),{'name':'nt'})()))
                    stack.enter_context(patch.object(native.BUILD_OWNER,'run',side_effect=unjoined))
                    stack.enter_context(patch.object(native,'checkout',side_effect=checkout))
                    for owner,name in ((native,'pristine'),(native.PQ,'build'),(native.POLICY,'prepare_native'),
                            (native.PERFORMANCE,'prepare'),(native.OPENVPN,'prepare'),(native.EXTERNAL,'prepare'),
                            (native.BUFFERS,'prepare'),(native.POLICY.AMNEZIA,'verify')):
                        stack.enter_context(patch.object(owner,name,return_value=None))
                    execute=stack.enter_context(patch.object(GATE,'execute',side_effect=AssertionError('Native execution followed failed preparation')))
                    stack.enter_context(redirect_stdout(io.StringIO()))
                    with self.assertRaises(type(error)) as caught:
                        GATE.standalone(prospective=True,receipt_path=receipt)
                    self.assertIs(caught.exception,error,'Preparation replaced its original failure')
                    execute.assert_not_called()
                self.assertEqual(dict(os.environ),previous)
                self.assertFalse(receipt.exists())
                self.assertEqual(len(roots),1)
                self.assertTrue(roots[0].is_dir(),'Unproved preparation deleted its original source workspace')
                self.assertTrue((roots[0]/'core').is_dir())
            finally:
                for directory in roots:
                    if directory.exists():shutil.rmtree(directory)

    def test_registration_requires_same_sha_native_workflow_in_authoritative_aggregate(self):
        self.assertEqual(GATE.NODE.PREP.PEER_TEMPLATES['node_max_peer_windows_test.go.tmpl'],GATE.PEER)
        self.assertTrue((ROOT/GATE.PEER_TEMPLATE).read_bytes().startswith(GATE.PREFIX))
        workflow=(ROOT/'.github/workflows/windows-node-max-contract.yml').read_text()
        for target in ('windows/amd64','windows/arm64'):
            self.assertIn('target: '+target,workflow)
        self.assertIn('timeout-minutes: 110',workflow)
        self.assertIn('timeout-minutes: 90',workflow)
        self.assertIn('platform: [amd64, arm64]',workflow)
        selected = re.search(r'suite: \[([^\]]+)\]',workflow).group(1).split(', ')
        self.assertEqual(tuple(selected), GATE.EXECUTION_SUITES)
        self.assertEqual(len(tuple((target,suite) for target in ('amd64','arm64') for suite in selected)),10)
        for target in ('amd64','arm64'):
            self.assertEqual(workflow.count('- platform: '+target+'\n'),1)
        self.assertIn('fail-fast: false',workflow)
        self.assertNotIn('continue-on-error:',workflow)
        self.assertNotIn('exclude:',workflow)
        self.assertNotRegex(workflow,r'(?m)^    if:')
        self.assertIn("--suite '${{ matrix.suite }}'",workflow)
        self.assertIn('windows-node-max-${{ github.ref }}-${{ matrix.slug }}-${{ matrix.suite }}',workflow)
        shipping = (ROOT/'internal/mobilemultihop/desktop_node_admission.go').read_text()
        try:
            GATE.prospective_predicate(shipping)
        except ValueError:
            GATE.closed_predicate(shipping)
            self.assertIn('--standalone --sha $env:GITHUB_SHA --receipt',workflow)
        else:
            self.assertIn('--standalone --prospective --sha $env:GITHUB_SHA --receipt',workflow)
        self.assertIn('if-no-files-found: error',workflow)
        self.assertIn('name: windows-max-native-${{ matrix.slug }}-${{ matrix.suite }}-${{ github.sha }}',workflow)
        self.assertIn('routervpn-windows-max-${{ matrix.suite }}-receipt.json',workflow)
        self.assertIn('routervpn-max-native-toolchain-${{ matrix.suite }}',workflow)
        self.assertIn("go-version: '1.26.3'",workflow)
        self.assertIn("python deploy/setup-desktop-native-toolchain.py '${{ matrix.target }}'",workflow)
        self.assertIn('python deploy/test_pq_reference_preparation.py',workflow)
        for dependency in ('deploy/test_pq_reference_preparation.py',
                           'client/Protect-RouterVPN-Windows-PrivateRoot.ps1',
                           'client/test-windows-private-acl.ps1'):
            self.assertEqual(workflow.count("      - '"+dependency+"'"),2)
        acl = workflow.index('      - name: Private ACL readback in Windows PowerShell 5.1 and 7\n')
        toolchain = workflow.index('      - name: Select exact native Rust target and verified LLVM compiler\n')
        self.assertLess(acl, toolchain)
        acl_step = workflow[acl:toolchain]
        self.assertIn('timeout-minutes: 6', acl_step)
        self.assertIn('foreach ($shell in @($systemShell, $coreShell))', acl_step)
        self.assertIn('-File client/test-windows-private-acl.ps1', acl_step)
        self.assertIn("if ($LASTEXITCODE -ne 0) { throw 'Actual private ACL readback/failure controls failed' }", acl_step)
        release=(ROOT/'.github/workflows/release-candidate.yml').read_text()
        self.assertIn('  windows-complete-max:\n',release)
        self.assertIn('    uses: ./.github/workflows/windows-node-max-contract.yml',release)
        aggregate=release.split('\n  aggregate:\n',1)[1]
        self.assertIn('windows-complete-max',aggregate.split('\n    runs-on:',1)[0])
        builder=(ROOT/'deploy/build-native-runtime.py').read_text()
        for name in ('test_windows_node_max.py','test_windows_node_max_runner.py'):
            self.assertIn("ROOT/'deploy/"+name+"'",builder)
        # It runs in the required parallel native workflow, not again inside
        # the packaged runtime command with an unrelated aggregate deadline.
        self.assertNotIn("run([sys.executable, ROOT/'deploy/test_windows_node_max.py'",builder)

    def test_five_workloads_partition_every_family_transition_and_control_once(self):
        # Exercise the published 23-control inventory size, odd/even future
        # sizes and stable tuple identity; the generic sixteen production
        # mutations and seven WFP mutations have their own source tests above.
        for count in (7, 22, 23, 24):
            changes = tuple(('original-' + str(i), object()) for i in range(count))
            plans = [GATE.execution_plan(suite, changes) for suite in GATE.EXECUTION_SUITES]
            families = tuple(family for selected, _, _, _ in plans for family in selected)
            controls = tuple(change for _, _, _, selected in plans for change in selected)
            self.assertEqual(families, tuple(GATE.MAX.FAMILIES))
            self.assertEqual(controls, changes)
            self.assertEqual(len({item[0] for item in controls}), count)
            self.assertEqual(sum(plan[1] for plan in plans), 1)
            self.assertEqual(sum(plan[2] for plan in plans), 1)
            self.assertEqual([len(plan[3]) for plan in plans], [0, 0, 0, (count + 1) // 2, count // 2])
            self.assertEqual(GATE.execution_plan('complete', changes), (tuple(GATE.MAX.FAMILIES), True, True, changes))
            with self.assertRaisesRegex(ValueError, 'duplicate controls'):
                GATE.execution_plan('ownership-controls-1', (*changes, changes[0]))
        with self.assertRaisesRegex(ValueError, 'Unknown complete MAX execution suite'):
            GATE.execution_plan('ownership-controls-3', ())

    def test_every_partial_suite_runs_native_prerequisites_and_only_its_complete_workload(self):
        workload_parents, executed_controls = [], []
        expected_controls = None
        for suite in GATE.EXECUTION_SUITES:
            receipt = self.work / (suite + '.json')
            with self.execution_harness(receipt) as state:
                changes = GATE.mutations(self.source)
                expected_controls = [item[0] for item in changes]
                families, succession, foreign, controls = GATE.execution_plan(suite, changes)
                result = GATE.execute(self.source, self.work / 'pq', self.work / 'cache', prospective=True, receipt_path=receipt, suite=suite)
            self.assertEqual(result['schema'], 2)
            self.assertEqual(result['execution_suite'], suite)
            self.assertEqual(result['receipt_kind'], 'complete-max-required-suite')
            self.assertIs(result['complete_inventory_proved'], False)
            self.assertEqual(result['required_execution_suites'], GATE.EXECUTION_SUITES)
            self.assertEqual(result['traffic_cases'], {family:GATE.MAX.TRAFFIC[family] for family in families})
            self.assertEqual(result['credential_cases'], {family:GATE.MAX.CREDENTIALS[family] for family in families})
            self.assertEqual(result['succession_cases'], tuple(mode + '/' + layer for mode in GATE.MODES for layer in GATE.LAYERS) if succession else ())
            self.assertEqual(result['foreign_predecessor_cases'], GATE.MODES if foreign else ())
            self.assertEqual([control['name'] for control in result['compiled_negative_controls']], [item[0] for item in controls])
            self.assertEqual(result['native_abi_cases'], GATE.MAX.PQ.NATIVE_CASES)
            self.assertTrue(result['current_closed_admission_proved'])
            self.assertTrue(result['private_key_workspace_removed'])
            self.assertEqual(result['repository']['commit'], 'a' * 40)
            self.assertEqual(result['closed_admission_control']['parent'], GATE.CLOSED)
            self.assertTrue(result['startup_record_output_sha256'])
            self.assertEqual(json.loads(receipt.read_text()), json.loads(json.dumps(result)))
            for parent in (GATE.CLOSED, GATE.OPEN, GATE.MARKERS):
                self.assertEqual(sum(record['parent'] == parent for record in result['suites']), 1)
            workload_parents.extend(record['parent'] for record in result['suites'] if record['parent'] not in (GATE.CLOSED,GATE.OPEN,GATE.MARKERS))
            executed_controls.extend(control['name'] for control in result['compiled_negative_controls'])
            for args, outer_timeout in state['native_calls']:
                inner = int(next(value.removeprefix('-test.timeout=')[:-1] for value in args if value.startswith('-test.timeout=')))
                self.assertEqual(outer_timeout, inner + 15)
                selector = next(value.removeprefix('-test.run=') for value in args if value.startswith('-test.run='))
                if Path(args[0]) in state['removed_controls']:
                    self.assertEqual(inner,90)
                elif selector == '^' + GATE.SUCCESSION + '$':
                    self.assertEqual(inner,3000)
                elif selector.endswith('Credentials$'):
                    self.assertEqual(inner,1800)
                elif selector.startswith('^Test(RealPinnedFactory'):
                    self.assertEqual(inner,120)
                else:
                    expected = {GATE.OPEN:15,GATE.MARKERS:30}.get(selector[1:-1],600)
                    self.assertEqual(inner,expected)
        self.assertEqual(executed_controls,expected_controls)
        self.assertEqual(workload_parents,[parent for family in GATE.MAX.FAMILIES for parent in ('TestRouterVPNDesktopNodeWindowsMAX'+family,'TestRouterVPNDesktopNodeWindowsMAX'+family+'Credentials')] + [GATE.SUCCESSION,GATE.FOREIGN])
        self.assertEqual(len(set(workload_parents)),len(workload_parents))



if __name__ == '__main__':
    unittest.main()
