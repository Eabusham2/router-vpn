#!/usr/bin/env python3
"""Execute Darwin Off Close/create admission ordering on any Go race host.

The shipping methods and control mutex are extracted unchanged. The native
transport seam pauses an already admitted create before its transferred file is
recorded. Descriptor verification and every PF cleanup seam explicitly refuse;
this test proves operation ordering, never Darwin kernel acceptance or absence.
"""
from pathlib import Path
import argparse
import importlib.util
import os
import platform
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'internal/mobiletor/desktop_socket_darwin_policy.go'
OFF = ROOT / 'internal/mobiletor/desktop_socket_darwin_off.go'
BROKER = ROOT / 'internal/mobiletor/desktop_socket_broker.go'
HELPER = ROOT / 'internal/mobiletor/desktop_socket_darwin_helper.go'

HEADER = r'''package admission
import (
 "context"
 "errors"
 "net"
 "net/netip"
 "os"
 "os/exec"
 "strings"
 "sync"
 "sync/atomic"
 "syscall"
 "testing"
 "time"
)
const desktopSocketControlWait = 3*time.Second
var fixtureNativeRefusal = errors.New("fixture cannot certify native descriptor verification")
var fixtureCleanupRefusal = errors.New("fixture cannot certify native PF absence")
type DesktopSocketCapture struct{ Session string }
type DesktopSocketBinding struct{Owner string; LocalAddress netip.Addr}
type DesktopSocketCreation struct{ Capture DesktopSocketCapture; Binding DesktopSocketBinding; SocketID,Network string }
type desktopSocketPrebound struct{}
type DesktopSocketCreated struct{ Creation DesktopSocketCreation; File *os.File; prebound *desktopSocketPrebound }
type desktopDarwinRequest struct{ Operation string; Capture DesktopSocketCapture; Creation DesktopSocketCreation; Sequence uint64 }
type desktopDarwinReply struct{ Creation DesktopSocketCreation; Capture DesktopSocketCapture; Sequence uint64 }
type fixturePF struct{ calls,verifications atomic.Int32 }
func (f *fixturePF) close(context.Context) error { f.calls.Add(1); return fixtureCleanupRefusal }
func (f *fixturePF) allAbsent(context.Context) error { f.calls.Add(1); return fixtureCleanupRefusal }
type DesktopDarwinSocketPolicy struct {
 mu desktopSocketControlMutex
 offMu sync.Mutex
 offSockets map[string]*os.File
 offFailure error
 options fixtureOptions
 capture DesktopSocketCapture
 owner string
 closing atomic.Bool
 parentStop func()bool
 monitorDone,joined chan struct{}
 pf *fixturePF
 channel *net.UnixConn
 sequence uint64
 joinErr error
 entered,continueCreate chan struct{}
 transferred *os.File
}
type fixtureOptions struct{HostProtectionOff bool; originalBinding DesktopSocketBinding}
func (o fixtureOptions) binding(owner string,remote netip.AddrPort)(DesktopSocketBinding,error){if owner!=o.originalBinding.Owner||remote.Addr()!=o.originalBinding.LocalAddress{return DesktopSocketBinding{},fixtureNativeRefusal};return o.originalBinding,nil}
const DesktopSocketLimit=128
type fixtureAssociation struct{Binding DesktopSocketBinding}
type desktopDarwinGuardian struct{capture DesktopSocketCapture;owner string;options fixtureOptions;sockets map[string]*os.File;socks map[string]fixtureAssociation;pf *fixturePF;uid uint32}
var fixtureGuardRefusal=errors.New("original Off guard independently rejected")
var fixtureAllocationCalls atomic.Int32
func (f *fixturePF) verify(context.Context,bool)error{f.verifications.Add(1);return fixtureGuardRefusal}
func desktopDarwinSocketPair()(*net.UnixConn,*os.File,error){fixtureAllocationCalls.Add(1);return nil,nil,errors.New("forbidden creator allocation reached")}
func desktopSocketHex(s string,n int)bool{return len(s)==n&&strings.Trim(s,"0123456789abcdef")==""}
func desktopDarwinBindingEqual(a,b DesktopSocketBinding)bool{return a==b}
func (g *desktopDarwinGuardian) checkSOCKSControl(context.Context,fixtureAssociation)(int,int,error){return 0,0,fixtureNativeRefusal}
func (g *desktopDarwinGuardian) adoptCreatedSocket(context.Context,DesktopSocketCreation,*os.File)(*os.File,error){return nil,fixtureNativeRefusal}
func desktopDarwinExecutable()(string,error){return "",fixtureNativeRefusal}
func desktopDarwinReceive(*net.UnixConn,*desktopDarwinReply,uint32,uint32)(*os.File,error){return nil,fixtureNativeRefusal}
type fixtureObservation struct{}
func (fixtureObservation) enter(int,uint32){}
func desktopDarwinObserveReadback(context.Context,string,any)(fixtureObservation,func()){return fixtureObservation{},func(){}}
func desktopDarwinReadbackReporter(context.Context)any{return nil}
const (desktopNativeObservationPath=iota;desktopNativeObservationStart;desktopNativeObservationSend;desktopNativeObservationReceive;desktopNativeObservationAcknowledge;desktopNativeObservationWait;desktopNativeObservationAdopt)
func (p *DesktopDarwinSocketPolicy) Cancel(){p.closing.Store(true)}
func (p *DesktopDarwinSocketPolicy) Current(c DesktopSocketCapture,o string)bool{return !p.closing.Load()&&c==p.capture&&o==p.owner}
func (p *DesktopDarwinSocketPolicy) closeObservation(){}
func (p *DesktopDarwinSocketPolicy) call(context.Context,desktopDarwinRequest,*os.File,bool)(desktopDarwinReply,*os.File,error){return desktopDarwinReply{},nil,fixtureCleanupRefusal}
func desktopDarwinSend(*net.UnixConn,desktopDarwinRequest,*os.File)error{return fixtureCleanupRefusal}
func (p *DesktopDarwinSocketPolicy) callLocked(ctx context.Context,r desktopDarwinRequest,_ *os.File,_ bool)(desktopDarwinReply,*os.File,error){
 if r.Operation!="create" {return desktopDarwinReply{},nil,fixtureNativeRefusal}
 close(p.entered)
 select {case <-p.continueCreate:case <-ctx.Done():return desktopDarwinReply{},nil,ctx.Err()}
 return desktopDarwinReply{Creation:r.Creation},p.transferred,fixtureNativeRefusal
}
func (p *DesktopDarwinSocketPolicy) retainOffDescriptor(c DesktopSocketCreation,f *os.File)(*desktopSocketPrebound,error){
 p.offMu.Lock();defer p.offMu.Unlock()
 if f!=nil {p.offSockets[c.SocketID]=f}
 p.offFailure=fixtureNativeRefusal
 return nil,fixtureNativeRefusal
}
'''

TESTS = r'''
func TestActualDarwinOffGuardPrecedesCreator(t *testing.T){
 binding:=DesktopSocketBinding{Owner:"original-owner",LocalAddress:netip.MustParseAddr("192.0.2.10")}
 capture:=DesktopSocketCapture{"original"}
 for _,network:=range []string{"tcp","udp"}{t.Run(network,func(t *testing.T){
  fixtureAllocationCalls.Store(0)
  g:=&desktopDarwinGuardian{capture:capture,owner:binding.Owner,options:fixtureOptions{HostProtectionOff:true,originalBinding:binding},sockets:make(map[string]*os.File),pf:&fixturePF{}}
  request:=DesktopSocketCreation{Capture:capture,Binding:binding,SocketID:strings.Repeat("a",32),Network:network}
  file,err:=g.create(context.Background(),request)
  if file!=nil{file.Close();t.Fatal("rejected original guard transferred a descriptor")}
  if fixtureAllocationCalls.Load()!=0{t.Fatal("Off creator allocation preceded original independent guard refusal")}
  if !errors.Is(err,fixtureGuardRefusal)||g.pf.verifications.Load()!=1||len(g.sockets)!=0{t.Fatal("original guard refusal or ownership changed",err)}
 })}
}
func TestActualDarwinOffCloseJoinsAdmittedCreation(t *testing.T){
 for _,cancelWait:=range []bool{false,true}{t.Run(map[bool]string{false:"retains-transferred-owner",true:"cancelled-wait-does-not-retire"}[cancelWait],func(t *testing.T){
  reader,writer,err:=os.Pipe();if err!=nil{t.Fatal(err)};defer reader.Close();defer writer.Close()
  p:=&DesktopDarwinSocketPolicy{capture:DesktopSocketCapture{"original"},owner:"original-owner",offSockets:make(map[string]*os.File),pf:&fixturePF{},monitorDone:make(chan struct{}),joined:make(chan struct{}),entered:make(chan struct{}),continueCreate:make(chan struct{}),transferred:reader}
  p.options.HostProtectionOff=true
  // A joined monitor/guardian is deliberately insufficient to join the
  // original foreground create. Its received file has not yet been recorded.
  close(p.monitorDone);close(p.joined)
  creation:=DesktopSocketCreation{Capture:p.capture,SocketID:"original-socket"};creation.Binding.Owner=p.owner
  created:=make(chan error,1)
  go func(){reply,err:=p.createSocketAdmitted(context.Background(),creation);if reply.File!=reader||reply.Creation!=creation||!errors.Is(err,fixtureNativeRefusal){created<-errors.New("original transferred ownership/refusal changed");return};created<-nil}()
  released,creationJoined:=false,false;defer func(){if !released{close(p.continueCreate)};if !creationJoined{select{case <-created:case <-time.After(time.Second):t.Error("fixture did not join admitted creation")}}}()
  select{case <-p.entered:case <-time.After(time.Second):t.Fatal("create did not reach original admitted transport")}
  ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second);defer cancel()
  closed:=make(chan error,1);go func(){closed<-p.Close(ctx)}()
  limit:=time.NewTimer(time.Second);defer limit.Stop()
  // Observe the real FIFO mutex queue, not an assumed scheduling delay.
  for {
   p.mu.mu.Lock();queued:=len(p.mu.waiters)>0;p.mu.mu.Unlock()
   if queued{break}
   select{case err:=<-closed:t.Fatalf("Close bypassed original admitted create before ownership recording: %v (PF calls=%d)",err,p.pf.calls.Load());case <-limit.C:t.Fatal("Close never joined original admission");case <-time.After(time.Millisecond):}
  }
  if p.pf.calls.Load()!=0{t.Fatal("PF cleanup ran before original creation joined")}
  if cancelWait{
   cancel()
   select{case err:=<-closed:if !errors.Is(err,context.Canceled){t.Fatal("Close replaced caller cancellation",err)};case <-time.After(time.Second):t.Fatal("cancelled admission did not return")}
   if p.pf.calls.Load()!=0{t.Fatal("cancelled waiter mutated native cleanup")}
  }
  close(p.continueCreate);released=true
  select{case err:=<-created:creationJoined=true;if err!=nil{t.Fatal(err)};case <-time.After(time.Second):t.Fatal("original create did not finish after transport release")}
  if !cancelWait{
   select{case err:=<-closed:if err==nil||!strings.Contains(err.Error(),"original descriptor or unknown retirement"){t.Fatal("Close did not preserve transferred original owner",err)};case <-time.After(time.Second):t.Fatal("Close did not finish its ownership observation")}
  }
  // Retry may observe the original retained failure, never manufacture absence.
  if err:=p.Close(context.Background());err==nil||!strings.Contains(err.Error(),"original descriptor or unknown retirement"){t.Fatal("retry discarded retained original descriptor",err)}
  p.offMu.Lock();owned:=p.offSockets[creation.SocketID]==reader;p.offMu.Unlock()
  if !owned||p.pf.calls.Load()!=0{t.Fatal("cleanup changed original ownership or reached native mutation")}
  if reply,err:=p.createSocketAdmitted(context.Background(),creation);err==nil||reply.File!=nil{t.Fatal("closing source admitted a successor")}
 })}
}
'''


def method(source, signature):
    start = source.index(signature)
    end = source.index('\n}\n', start) + 3
    return source[start:end]


def execute(root: Path = ROOT, *, go='go', policy=None, off=None, count=1, mutations=True):
    root = Path(root).resolve()
    policy = Path(policy) if policy else root / POLICY.relative_to(ROOT)
    off = Path(off) if off else root / OFF.relative_to(ROOT)
    policy_source, off_source, broker_source = policy.read_text(), off.read_text(), (root / BROKER.relative_to(ROOT)).read_text()
    bodies = [method(policy_source, 'func (p *DesktopDarwinSocketPolicy) '+name+'(')
              for name in ('Close', 'createSocketAdmitted', 'admitControl')]
    bodies += [method(off_source, 'func (p *DesktopDarwinSocketPolicy) '+name+'(')
               for name in ('joinOffDescriptorCreation', 'offDescriptorsRetired')]
    bodies.append(method((root / HELPER.relative_to(ROOT)).read_text(), 'func (g *desktopDarwinGuardian) create('))
    start = broker_source.index('type desktopSocketControlMutex struct {')
    end = broker_source.index('func desktopSocketGrantControlled(', start)
    original = HEADER + broker_source[start:end] + '\n'.join(bodies) + TESTS
    variants = [('baseline', original, None)]
    if mutations:
        boundary = 'if err := p.joinOffDescriptorCreation(ctx); err != nil {\n\t\treturn err\n\t}'
        assert original.count(boundary) == 1, 'Darwin Off Close admission boundary changed'
        old = 'if !p.offDescriptorsRetired() { return errors.New("retained descriptor") }'
        variants.append(('old-unjoined-retirement', original.replace(boundary, old),
                         'Close bypassed original admitted create before ownership recording'))
        guard = 'if g.options.HostProtectionOff {\n\t\tif err := g.pf.verify(ctx, true); err != nil {\n\t\t\treturn nil, err\n\t\t}\n\t}'
        assert original.count(guard) == 1, 'Darwin Off creator guard boundary changed'
        variants.append(('missing-precreate-guard', original.replace(guard, ''),
                         'Off creator allocation preceded original independent guard refusal'))
    environment = dict(os.environ)
    if platform.system() == 'Darwin':
        spec = importlib.util.spec_from_file_location('darwin_off_race', root/'deploy/darwin_race_toolchain.py')
        race = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(race)
        go, environment = race.capture(root, go, environment)
    with tempfile.TemporaryDirectory(prefix='darwin-off-admission-', dir=root) as directory:
        directory = Path(directory)
        for label, source, witness in variants:
            (directory / 'admission_test.go').write_text(source)
            result = subprocess.run([go, 'test', '-p=1', '-race', '-v', './'+directory.name,
                                     '-run', '^TestActualDarwinOff(CloseJoinsAdmittedCreation|GuardPrecedesCreator)$',
                                     '-count='+str(count), '-timeout=30s'], cwd=root,
                                    env=environment, capture_output=True, text=True, timeout=120)
            output = result.stdout + result.stderr
            if witness:
                if result.returncode == 0 or witness not in output or re.search(r'panic:|fatal error:|WARNING: DATA RACE|\[build failed\]|fixture did not join', output):
                    raise AssertionError(label+': missing clean intended rejection\n'+output)
            elif (result.returncode != 0
                  or output.count('--- PASS: TestActualDarwinOffCloseJoinsAdmittedCreation (') != count
                  or output.count('--- PASS: TestActualDarwinOffCloseJoinsAdmittedCreation/') != count*2
                  or output.count('--- PASS: TestActualDarwinOffGuardPrecedesCreator (') != count
                  or output.count('--- PASS: TestActualDarwinOffGuardPrecedesCreator/') != count*2):
                raise AssertionError('Actual Darwin Off Close admission failed\n'+output)
            print('Darwin Off Close admission: '+label+' verified', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--count', type=int, default=1)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--policy', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--off', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    execute(args.root, go=args.go, policy=args.policy, off=args.off, count=args.count)
