#!/usr/bin/env python3
"""Guard native Server component verdicts and required shipping integration."""
from pathlib import Path
import importlib.util
import json
import io
import contextlib
import sys
import os
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('server_chain_native_runner',ROOT/'deploy/test_server_node_chain_native.py')
RUN=importlib.util.module_from_spec(spec);spec.loader.exec_module(RUN)

def record(action,name=None,**fields):
 row=dict(Action=action,Package=RUN.PACKAGE,**fields)
 if name:row['Test']=name
 return row

def success():
 rows=[record('start')]
 for root in RUN.ROOTS:
  rows.append(record('run',root))
  for child in RUN.CHILDREN.get(root,()):rows += [record('run',root+'/'+child),record('pass',root+'/'+child)]
  rows.append(record('pass',root))
 rows.append(record('pass'));return rows

def output(rows):return '\n'.join(json.dumps(row) for row in rows)+'\n'

class NativeServerChainRunner(unittest.TestCase):
 def test_complete_exact_inventory(self):
  receipt=RUN.verdict(output(success()),0)
  self.assertEqual(receipt['roots'],21);self.assertEqual(receipt['executed_records'],len(RUN.EXPECTED));self.assertGreater(len(RUN.EXPECTED),60)
 def test_missing_leaf_cannot_pass(self):
  name=RUN.ROOTS[3]+'/prefix-uot';rows=[r for r in success() if r.get('Test')!=name]
  with self.assertRaises(ValueError):RUN.verdict(output(rows),0)
 def test_skip_duplicate_race_and_package_failure_refused(self):
  for mode in ('skip','duplicate','race','exit','package','unknown-root'):
   with self.subTest(mode=mode):
    rows=success();code=0
    if mode=='skip':rows.insert(-1,record('skip',RUN.ROOTS[0]))
    elif mode=='duplicate':rows.insert(-1,record('pass',RUN.ROOTS[0]))
    elif mode=='race':rows.insert(-1,record('output',RUN.ROOTS[0],Output='WARNING: DATA RACE'))
    elif mode=='exit':code=1
    elif mode=='package':rows.pop()
    else:rows.insert(-1,record('run','TestServerChainUninventoried'))
    with self.assertRaises(ValueError):RUN.verdict(output(rows),code)
 def test_compile_error_is_not_causal_rejection(self):
  name=RUN.ROOTS[4];rows=[record('output',Output='build failed'),record('fail')]
  self.assertFalse(RUN.rejected(output(rows),1,name,'failed native close was acknowledged'))
  with self.assertRaises(ValueError):RUN.rejected('# compile failed\n',1,name,'failed native close was acknowledged')
 def test_actual_child_keeps_tool_diagnostics_out_of_json_verdict(self):
  payload=output(success())
  with contextlib.redirect_stderr(io.StringIO()) as observed:
   result=RUN.execute_test([sys.executable,'-c','import sys;sys.stdout.write(sys.argv[1]);sys.stderr.write("go: downloading exact-module v1.0.0\\n")',payload],ROOT)
  self.assertEqual(result.returncode,0)
  self.assertEqual(result.stdout,payload)
  self.assertIn('go: downloading',observed.getvalue())
  self.assertEqual(RUN.verdict(result.stdout,result.returncode,result.stderr)['roots'],21)
  with self.assertRaises(ValueError):RUN.verdict(result.stdout,1,result.stderr)
  with self.assertRaises(ValueError):RUN.verdict(result.stdout,0,'WARNING: DATA RACE')
 def test_causal_control_requires_exact_test_and_witness(self):
  name=RUN.ROOTS[4];witness='failed native close was acknowledged';rows=[record('run',name),record('output',name,Output=witness),record('fail',name),record('fail')]
  self.assertTrue(RUN.rejected(output(rows),1,name,witness));self.assertFalse(RUN.rejected(output(rows),0,name,witness));self.assertFalse(RUN.rejected(output(rows),1,RUN.ROOTS[0],witness));self.assertFalse(RUN.rejected(output(rows),1,name,'unrelated failure'))
  self.assertFalse(RUN.rejected(output(rows),1,name,witness,'build failed'));self.assertFalse(RUN.rejected(output(rows),1,name,witness,'WARNING: DATA RACE'))
 def test_imported_resolver_inventory_and_original_refusals_are_required(self):
  self.assertEqual(RUN.ROOTS[15],'TestServerChainImportedBenchmarkChecksEverySelectedAnswer')
  for name in (RUN.ROOTS[3]+'/prefix-foreign-tuple',RUN.ROOTS[3]+'/prefix-uot',RUN.ROOTS[15]+'/private-after-good',RUN.ROOTS[15]+'/disabled-ipv6',RUN.ROOTS[13]+'/stop-retry'):
   with self.subTest(name=name):
    rows=[r for r in success() if r.get('Test')!=name]
    with self.assertRaises(ValueError):RUN.verdict(output(rows),0)
 def test_every_configured_dns_owner_record_is_required(self):
  for root in RUN.ROOTS[16:]:
   for name in (root,*(root+'/'+child for child in RUN.CHILDREN[root])):
    for action in ('run','pass'):
     with self.subTest(name=name,action=action):
      rows=[r for r in success() if not (r.get('Test')==name and r.get('Action')==action)]
      with self.assertRaises(ValueError):RUN.verdict(output(rows),0)
 def test_native_admission_cannot_omit_complete_dns_owner(self):
  source=(ROOT/'mobile/server_chain/native.go.tmpl').read_text()
  self.assertIn('n.dnsOwners, err = newRouterVPNServerChainDNSOwners(initialize, n, options.DNS)',source)
  observation=source.split('func (n *routerVPNServerChain) nativeCurrent(',1)[1].split('\nfunc ',1)[0]
  self.assertIn('if n.dnsOwners.current(ctx, n) != nil {\n\t\treturn false',observation)
  self.assertIn('resolver != n.dnsOwner',observation)
  self.assertIn('service.FromContext[adapter.DNSTransportManager](n.ctx) != n.dnsManager',observation)
 def test_front_final_retirement_inventory_cannot_be_omitted(self):
  root=RUN.ROOTS[20]
  self.assertEqual(root,'TestServerChainFrontRetirementJoinsBeforeFinalAcknowledgement')
  self.assertEqual(len(RUN.CHILDREN[root]),9)
  for name in (root,*(root+'/'+child for child in RUN.CHILDREN[root])):
   for action in ('run','pass'):
    with self.subTest(name=name,action=action):
     rows=[r for r in success() if not (r.get('Test')==name and r.get('Action')==action)]
     with self.assertRaises(ValueError):RUN.verdict(output(rows),0)
 def test_compiled_original_front_and_worker_retirement_order(self):
  # Compile exact shipping shutdown/ledger bodies with a standard-library
  # boundary fixture. This isolates retirement ordering, not encrypted native
  # transport: the same test is also mandatory in the real command package.
  def function(source,signature):
   self.assertEqual(source.count(signature),1)
   begin=source.index(signature)
   return source[begin:source.index('\n}\n',begin)+3]
  front=(ROOT/'mobile/server_chain/front.go.tmpl').read_text()
  native=(ROOT/'mobile/server_chain/native.go.tmpl').read_text()
  resources=(ROOT/'mobile/server_chain/resources.go.tmpl').read_text()
  tests=(ROOT/'mobile/server_chain/resources_test.go.tmpl').read_text()
  front_tests=(ROOT/'mobile/server_chain/front_test.go.tmpl').read_text()
  close=function(native,'func (n *routerVPNServerChain) Close(')
  methods='\n'.join(function(front,'func (f *routerVPNServerChainFront) '+name+'(')
                     for name in ('startListener','retain','release','releaseContext','Close','joinContext'))
  ledger=resources[resources.index('type routerVPNServerChainCloseAttempt struct'):]
  cases=tests[tests.index('type serverChainHeldClose struct'):]
  cases+='\n'+front_tests[front_tests.index('type serverChainOneCloseFailure struct'):front_tests.index('type serverChainLateConn struct')]
  program=r'''package main
import("context";"errors";"io";"net";"sync";"sync/atomic";"testing";"time")
var errServerChainFront=errors.New("original ordered front is unavailable")
type routerVPNServerChainFront struct{
 ctx context.Context;cancel context.CancelFunc;listener net.Listener
 mu sync.Mutex;enabled,retiring bool;originals map[io.Closer]bool
 workers sync.WaitGroup;accepted,joined,interrupted chan struct{}
 joinOnce sync.Once;closeGate chan struct{};stopInterrupt func()bool
}
// Protocol routing is outside this bounded ordering fixture. The listener,
// cancellation, worker joins and retained socket Close are original objects.
func(f *routerVPNServerChainFront) accept(){defer close(f.accepted);for{c,e:=f.listener.Accept();if e!=nil{return};_ = c.Close()}}
type frontFixture struct{front *routerVPNServerChainFront}
func newServerChainFrontFixture(t *testing.T)*frontFixture{
 t.Helper();ctx,cancel:=context.WithCancel(t.Context())
 listener,err:=net.Listen("tcp4","127.0.0.1:0");if err!=nil{t.Fatal(err)}
 f:=&routerVPNServerChainFront{ctx:ctx,cancel:cancel,originals:make(map[io.Closer]bool),accepted:make(chan struct{}),joined:make(chan struct{}),closeGate:make(chan struct{},1)}
 f.startListener(listener)
 t.Cleanup(func(){cancel();_ = listener.Close()})
 return &frontFixture{front:f}
}
// No native protocol/capture/Box substitute is exercised here. These nil
// constructor fields retain the complete original worker Close body.
type absentNative struct{}
func(*absentNative) CloseContext(context.Context)error{panic("unexpected native boundary")}
func(*absentNative) Close()error{panic("unexpected Box boundary")}
func(*absentNative) ServerConnectionRetirement(net.Conn)func(context.Context,net.Conn,error)error{panic("unexpected capture boundary")}
type routerVPNServerChain struct{
 ctx context.Context;cancel context.CancelFunc;front *routerVPNServerChainFront
 mu sync.Mutex;closed,closing,begun bool;closeGate,proofDone chan struct{}
 expiry *time.Timer;expiryWorkers sync.WaitGroup;expiryJoinOnce sync.Once;expiryJoined chan struct{}
 connectionsMu sync.Mutex;connections map[*routerVPNServerChainClose]bool
 connect,socks,box,carrier *absentNative;boxOnce sync.Once;boxDone chan struct{};boxError error
 carrierJoined,parentDone chan struct{};stopParent func()bool
}
func routerVPNServerChainAtStage(_ string,cause error)error{return cause}
METHODS
LEDGER
CLOSE
CASES
'''
  def replace_once(source,before,after):
   self.assertEqual(source.count(before),1)
   return source.replace(before,after,1)
  mutations=(
   ('original-order',methods,ledger,replace_once(close,'n.front.joinContext(ctx)','n.front.Close(ctx)'), 'joined original front prevented final retirement'),
   ('missing-front-join',methods,ledger,replace_once(close,'n.front.joinContext(ctx)','context.Background().Err()'), 'retirement preceded original front join'),
   ('missing-proof-join',methods,ledger,replace_once(close,'if begun {','if false && begun {'), 'retirement preceded original proof join'),
   ('missing-final-front-check',replace_once(methods,'if remaining != 0 {','if false && remaining != 0 {'),ledger,close, 'unproven front retirement was acknowledged'),
   ('ignored-receipt-failure',methods,replace_once(ledger,'if err := c.retire(ctx, original, failure); err != nil {','if err := c.retire(ctx, original, failure); false && err != nil {'),close, 'unproven front retirement was acknowledged'),
  )
  root=RUN.ROOTS[20];expected={root,*(root+'/'+child for child in RUN.CHILDREN[root]),RUN.ROOTS[4],*RUN.ROOTS[10:13]}
  with tempfile.TemporaryDirectory(prefix='server-front-retirement-order-') as directory:
   work=Path(directory);(work/'go.mod').write_text('module retirement\n\ngo 1.26\n')
   for label,m,l,c,witness in (('original',methods,ledger,close,None),*mutations):
    with self.subTest(variant=label):
     source=program.replace('METHODS',m).replace('LEDGER',l).replace('CLOSE',c).replace('CASES',cases)
     (work/'retirement_test.go').write_text(source)
     result=subprocess.run(['go','test','-json','-race','-count=1','-timeout=15s','.'],cwd=work,env=dict(os.environ,GORACE='atexit_sleep_ms=0'),capture_output=True,text=True,timeout=75)
     rows=[json.loads(line) for line in result.stdout.splitlines()]
     self.assertNotIn('build failed',result.stdout+result.stderr)
     self.assertNotIn('WARNING: DATA RACE',result.stdout+result.stderr)
     self.assertFalse(any(row.get('Action') in ('build-fail','skip') for row in rows))
     runs=[row.get('Test') for row in rows if row.get('Action')=='run']
     self.assertEqual(set(runs),expected,result.stdout+result.stderr)
     self.assertEqual(len(runs),len(expected))
     if witness is None:
      self.assertEqual(result.returncode,0,result.stdout+result.stderr)
      passes=[row.get('Test') for row in rows if row.get('Action')=='pass' and row.get('Test')]
      self.assertEqual(set(passes),expected)
      self.assertEqual(len(passes),len(expected))
      self.assertEqual(rows[-1].get('Action'),'pass')
     else:
      self.assertNotEqual(result.returncode,0)
      self.assertIn(witness,result.stdout+result.stderr)
      self.assertTrue(any(row.get('Action')=='fail' and row.get('Test')==root for row in rows))
      self.assertEqual(rows[-1].get('Action'),'fail')
 def test_compiled_original_uot_packet_retirement(self):
  # Real pinned UoT framing and loopback sockets exercise the exact shipping
  # packet/close ledger. The capture counterparty below models only its sealed
  # acknowledgement contract; encrypted ownership remains a native gate.
  resources=(ROOT/'mobile/server_chain/resources.go.tmpl').read_text()
  ledger=resources[resources.index('type routerVPNServerChainCloseAttempt struct'):]
  capture='owner.retire = n.connect.ServerConnectionRetirement(stream)'
  self.assertEqual(ledger.count(capture),1)
  program=r'''package retirement
import("context";"errors";"io";"net";"sync";"sync/atomic";"testing";"time"
 M "github.com/sagernet/sing/common/metadata"
 "github.com/sagernet/sing/common/uot")
var errServerChainFront=errors.New("original ordered front is unavailable")
type routerVPNServerChain struct{
 cancel context.CancelFunc;connectionsMu sync.Mutex
 connections map[*routerVPNServerChainClose]bool;connect *retirementCapture
}
// This explicit authority double rejects foreign originals/errors and requires
// the actual loopback reader join. It does not simulate encrypted acceptance.
type retirementCapture struct{
 original net.Conn;failure error;joined <-chan struct{};fault string
 captured,acknowledged atomic.Int32
}
func(c *retirementCapture) ServerConnectionRetirement(original net.Conn)func(context.Context,net.Conn,error)error{
 c.captured.Add(1)
 if original!=c.original||c.fault=="missing-receipt"{return nil}
 return func(ctx context.Context,observed net.Conn,failure error)error{
  c.acknowledged.Add(1)
  if ctx.Err()!=nil{return ctx.Err()}
  if observed!=c.original||c.fault=="foreign-original"{return errors.New("foreign original")}
  if failure!=c.failure||c.fault=="foreign-error"{return errors.New("foreign close error")}
  if c.fault=="unjoined-receipt"{return errors.New("unjoined original")}
  select{case <-c.joined:return nil;default:return errors.New("original peer not joined")}
 }
}
type protocolCloseConn struct{net.Conn;once sync.Once;failure error}
func(c *protocolCloseConn) Close()error{c.once.Do(func(){_ = c.Conn.Close()});return c.failure}
type packetOnly struct{net.PacketConn}
LEDGER
func TestOriginalUoTPacketRetirement(t *testing.T){
 for _,fault:=range []string{"joined","missing-receipt","foreign-original","foreign-error","unjoined-receipt"}{t.Run(fault,func(t *testing.T){
  listener,err:=net.Listen("tcp4","127.0.0.1:0");if err!=nil{t.Fatal(err)};defer listener.Close()
  joined:=make(chan struct{});peerResult:=make(chan error,1)
  go func(){defer close(joined);conn,err:=listener.Accept();if err!=nil{peerResult<-err;return};defer conn.Close()
   _ = conn.SetDeadline(time.Now().Add(3*time.Second))
   request,err:=uot.ReadRequest(conn);if err!=nil{peerResult<-err;return}
   packet:=uot.NewConn(conn,*request);buffer:=make([]byte,64)
   count,address,err:=packet.ReadFrom(buffer);if err!=nil{peerResult<-err;return}
   if string(buffer[:count])!="original selected DNS packet"{peerResult<-errors.New("foreign packet");return}
   if _,err=packet.WriteTo(buffer[:count],address);err!=nil{peerResult<-err;return}
   _,_,err=packet.ReadFrom(buffer);if !errors.Is(err,io.EOF){peerResult<-errors.New("original UoT reader did not close");return};peerResult<-nil
  }()
  conn,err:=net.DialTimeout("tcp4",listener.Addr().String(),time.Second);if err!=nil{t.Fatal(err)};defer conn.Close()
  _ = conn.SetDeadline(time.Now().Add(3*time.Second))
  failure:=errors.New("original front-owned protocol close failure")
  raw:=uot.NewLazyConn(&protocolCloseConn{Conn:conn,failure:failure},uot.Request{IsConnect:true,Destination:M.ParseSocksaddr("127.0.0.1:53")})
  authority:=&retirementCapture{original:raw,failure:failure,joined:joined,fault:fault}
  ownerContext,cancel:=context.WithCancel(context.Background());defer cancel()
  n:=&routerVPNServerChain{cancel:cancel,connect:authority}
  packet:=n.trackPacketConnection(raw)
  if packet==nil||packet.closeOwner.original!=raw{t.Fatal("original UoT packet owner replaced")}
  if fault=="joined"&&(authority.captured.Load()!=1||packet.closeOwner.retire==nil){t.Fatal("original UoT packet retirement authority omitted")}
  payload:=[]byte("original selected DNS packet")
  if _,err=packet.WriteTo(payload,M.ParseSocksaddr("127.0.0.1:53"));err!=nil{t.Fatal(err)}
  buffer:=make([]byte,64);count,_,err:=packet.ReadFrom(buffer)
  if err!=nil||string(buffer[:count])!=string(payload){t.Fatalf("actual UoT reply: %q %v",buffer[:count],err)}
  ctx,stop:=context.WithTimeout(context.Background(),time.Second);defer stop()
  if err=packet.CloseContext(ctx);err!=failure{t.Fatalf("trial close hid original failure: %v",err)}
  if ownerContext.Err()!=context.Canceled||authority.acknowledged.Load()!=0{t.Fatal("trial acquired final acknowledgement")}
  select{case <-joined:case <-ctx.Done():t.Fatal("original UoT peer did not join")}
  if err=<-peerResult;err!=nil{t.Fatal(err)}
  n.connectionsMu.Lock();retained:=n.connections[packet.closeOwner];n.connectionsMu.Unlock()
  if !retained{t.Fatal("trial failure discarded original ledger")}
  err=n.drainConnections(ctx)
  n.connectionsMu.Lock();remaining:=len(n.connections);n.connectionsMu.Unlock()
  if fault=="joined"{
   if err!=nil||remaining!=0||authority.acknowledged.Load()!=1{t.Fatalf("original UoT packet final retirement refused: %v remaining=%d",err,remaining)}
   if err=packet.CloseContext(ctx);err!=nil{t.Fatal("retired original repeated protocol error")}
  }else{
   if err==nil||!errors.Is(err,failure)||remaining!=1||packet.closeOwner.closed{t.Fatal("unproven UoT packet retirement acknowledged")}
   // A failed receipt retains this original owner for a later valid retry.
   authority.fault="joined";packet.closeOwner.retire=authority.ServerConnectionRetirement(raw)
   if err=n.drainConnections(ctx);err!=nil{t.Fatalf("retained original retry failed: %v",err)}
  }
 })}
 for _,kind:=range []string{"ordinary-udp","packet-only"}{t.Run(kind,func(t *testing.T){
  udp,err:=net.ListenPacket("udp4","127.0.0.1:0");if err!=nil{t.Fatal(err)};defer udp.Close()
  var original net.PacketConn=udp;if kind=="packet-only"{original=&packetOnly{udp}}
  authority:=&retirementCapture{}
  n:=&routerVPNServerChain{cancel:func(){},connect:authority}
  packet:=n.trackPacketConnection(original)
  if packet.closeOwner.retire!=nil{t.Fatal("ordinary packet acquired foreign retirement authority")}
  if kind=="packet-only"&&authority.captured.Load()!=0{t.Fatal("non-stream packet reached stream authority")}
  if err=n.drainConnections(context.Background());err!=nil{t.Fatal(err)}
 })}
}
'''
  program=program.replace('LEDGER',ledger)
  root='TestOriginalUoTPacketRetirement'
  children=('joined','missing-receipt','foreign-original','foreign-error','unjoined-receipt','ordinary-udp','packet-only')
  with tempfile.TemporaryDirectory(prefix='server-uot-packet-retirement-') as directory:
   work=Path(directory)
   (work/'go.mod').write_text('module retirement\n\ngo 1.26\n\nrequire github.com/sagernet/sing v0.9.4\n')
   for label,source in (('original',program),('missing-packet-authority',program.replace(capture,'_ = stream // omitted original packet authority',1))):
    with self.subTest(variant=label):
     (work/'retirement_test.go').write_text(source)
     selector='^'+root+'$'
     expected={root,*(root+'/'+child for child in children)}
     if label!='original':selector+='/^joined$';expected={root,root+'/joined'}
     result=subprocess.run(['go','test','-mod=mod','-json','-race','-p=1','-count=1','-timeout=15s','-run',selector,'.'],cwd=work,env=dict(os.environ,GORACE='atexit_sleep_ms=0'),capture_output=True,text=True,timeout=75)
     diagnostic=result.stdout+result.stderr
     self.assertNotIn('build failed',diagnostic);self.assertNotIn('WARNING: DATA RACE',diagnostic)
     rows=[json.loads(line) for line in result.stdout.splitlines()]
     self.assertFalse(any(row.get('Action') in ('build-fail','skip') for row in rows))
     runs=[row.get('Test') for row in rows if row.get('Action')=='run']
     self.assertEqual(set(runs),expected,diagnostic);self.assertEqual(len(runs),len(expected))
     if label=='original':
      self.assertEqual(result.returncode,0,diagnostic)
      passes=[row.get('Test') for row in rows if row.get('Action')=='pass' and row.get('Test')]
      self.assertEqual(set(passes),expected);self.assertEqual(len(passes),len(expected));self.assertEqual(rows[-1].get('Action'),'pass')
     else:
      self.assertEqual(result.returncode,1,diagnostic)
      self.assertIn('original UoT packet retirement authority omitted',diagnostic)
      failures=[row.get('Test') for row in rows if row.get('Action')=='fail' and row.get('Test')]
      self.assertEqual(set(failures),expected);self.assertEqual(len(failures),len(expected));self.assertEqual(rows[-1].get('Action'),'fail')
 def test_compiled_original_carrier_watcher_captures_cancellation_before_publication(self):
  source=(ROOT/'mobile/server_chain/native.go.tmpl').read_text()
  begin='\t\t\tn.carrierJoined = make(chan struct{})'
  end='\n\t\t\t}()'
  self.assertEqual(source.count(begin),1)
  start=source.index(begin);finish=source.index(end,start)+len(end)
  block=source[start:finish]
  capture='carrierDone, ownerDone := n.carrier.Done(), owned.Done()'
  self.assertEqual(block.count(capture),1)
  program=r'''package watcher
import("context";"testing";"time")
type carrier struct{done chan struct{}}
func(c *carrier) Done() <-chan struct{} {return c.done}
type native struct{ctx context.Context;carrier *carrier;carrierJoined chan struct{};cancel context.CancelFunc}
func start(n *native,owned context.Context){WATCHER}
type key struct{}
func TestOriginalCarrierWatcher(t *testing.T){
 for _,carrierStops:=range []bool{false,true}{for i:=0;i<32;i++{
  owned,cancel:=context.WithCancel(context.Background())
  n:=&native{ctx:owned,carrier:&carrier{done:make(chan struct{})},cancel:cancel}
  start(n,owned)
  // This is the real constructor's later typed registry-context publication.
  // Context values share the same original cancellation channel.
  n.ctx=context.WithValue(owned,key{},i)
  if carrierStops{close(n.carrier.done)}else{cancel()}
  select{case <-n.carrierJoined:case <-time.After(time.Second):cancel();t.Fatal("watcher did not join its original cancellation")}
  if owned.Err()!=context.Canceled{cancel();t.Fatal("carrier stopped without cancelling original owner")}
  cancel()
 }}
}
'''
  mutations=(
   ('original-ctx-read',block.replace(capture,'carrierDone := n.carrier.Done()').replace('case <-ownerDone:','case <-n.ctx.Done():'),'WARNING: DATA RACE'),
   ('missing-cancel',block.replace('n.cancel()','/* broken original cancellation */'),'carrier stopped without cancelling original owner'),
   ('missing-join',block.replace('defer close(n.carrierJoined)','/* broken original join */'),'watcher did not join its original cancellation'),
   ('foreign-owner',block.replace('owned.Done()','context.Background().Done()'),'watcher did not join its original cancellation'),
  )
  with tempfile.TemporaryDirectory(prefix='server-original-carrier-watch-') as directory:
   work=Path(directory);(work/'go.mod').write_text('module watcher\n\ngo 1.26\n')
   for label,body,witness in (('original',block,None),*mutations):
    with self.subTest(variant=label):
     (work/'watcher_test.go').write_text(program.replace('WATCHER',body))
     result=subprocess.run(['go','test','-json','-race','-count=1','-timeout=10s','.'],cwd=work,env=dict(os.environ,GORACE='atexit_sleep_ms=0'),capture_output=True,text=True,timeout=75)
     self.assertNotIn('build failed',result.stdout+result.stderr)
     rows=[json.loads(line) for line in result.stdout.splitlines()]
     self.assertFalse(any(row.get('Action') in ('build-fail','skip') for row in rows))
     test=[row for row in rows if row.get('Test')=='TestOriginalCarrierWatcher']
     self.assertEqual(sum(row.get('Action')=='run' for row in test),1)
     if witness is None:
      self.assertEqual(result.returncode,0,result.stdout+result.stderr)
      self.assertEqual(sum(row.get('Action')=='pass' for row in test),1)
      self.assertEqual(rows[-1].get('Action'),'pass')
      self.assertNotIn('WARNING: DATA RACE',result.stdout+result.stderr)
     else:
      self.assertNotEqual(result.returncode,0)
      self.assertIn(witness,result.stdout+result.stderr)
      self.assertEqual(sum(row.get('Action')=='fail' for row in test),1)
      self.assertEqual(rows[-1].get('Action'),'fail')

 def test_actual_shipping_gate_and_original_families_remain(self):
  docker=(ROOT/'deploy/router-agent.Dockerfile').read_text();workflow=(ROOT/'.github/workflows/native-xray-exits.yml').read_text()
  self.assertIn("./cmd/sing-box ./routervpn/servertor -run '^TestServerTor' -count=1 -timeout 90s",docker)
  self.assertIn('python3 /routervpn-source/deploy/test_server_node_chain_native.py --core /core',docker)
  self.assertIn('--receipt /routervpn-server-node-chain-native.json',docker)
  self.assertIn('python3 deploy/test_server_node_chain_preparation.py',workflow);self.assertIn('python3 deploy/test_server_node_chain_native_runner.py',workflow)
  self.assertIn("'deploy/test_server_node_chain_*.py'",workflow)
  self.assertIn('docker build --progress=plain -f deploy/router-agent.Dockerfile',workflow)

if __name__=='__main__':unittest.main()
