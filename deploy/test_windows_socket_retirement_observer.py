#!/usr/bin/env python3
"""Execute the exact native observer and call gates with OS readback doubled.

This checks post-close observation, exact retained-grant classification, and
reader lifetime on a portable Go host.
The scoped Windows kernel/descriptor tests remain required independently.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OBSERVER = ROOT / 'deploy/fixtures/windows-node-physical/kernel_observer.go'


def function(source, signature):
    start = source.index(signature)
    end = source.index('\n}', start) + 2
    return source[start:end]


BOUNDARIES = r'''
package retirement
import (
 "bytes"
 "context"
 "encoding/hex"
 "errors"
 "net"
 "sync"
 "sync/atomic"
 "syscall"
 "time"
)
type target struct {capture, policy string; metadata []byte}
func (t target) matches(c, p string, m []byte) bool {return t.capture==c && t.policy==p && bytes.Equal(t.metadata,m)}
type grant struct {Capture,SocketID string; Binding struct{Owner string}}
type creation struct {SocketID string}
type permit struct {request grant}
type desktopWFPRule struct {Key string; ID uint64}
func desktopWindowsPermitKey(g grant)string{return g.SocketID}
func desktopSocketSOCKSControlMatches(a,b grant)bool{return a==b}
type native struct {closed bool}
func (n *native) SyscallConn()(syscall.RawConn,error){if n.closed{return nil,net.ErrClosed};return nil,nil}
type socket struct {mu sync.Mutex;closed bool}
type socketConnection struct {io *socket}
type socketRecord struct {creation creation;original,returned *native;connect *socketConnection}
type engine struct {handle uintptr;closed atomic.Bool;done chan struct{}}
func (e *engine) Absent(key string)error{if e!=observed.reader{return errors.New("read used production engine")};observed.filters=append(observed.filters,key);return observed.filterErr}
func (e *engine) Assert(rule desktopWFPRule)error{
 if e!=observed.reader||e.closed.Load(){return errors.New("grant read used production or closed engine")}
 observed.asserted=append(observed.asserted,rule)
 if observed.entered!=nil{close(observed.entered);<-observed.release}
 if rule!=observed.originalRule{return errors.New("grant read adopted replacement filter")}
 return observed.filterErr
}
func (e *engine) Close()error{if e.closed.CompareAndSwap(false,true){close(e.done)};return observed.closeErr}
type api struct{}
func (*api) endpointProperties(handle uintptr,id uint64)(int,[]byte,error){
 if handle!=observed.reader.handle || observed.reader.closed.Load(){return 0,nil,errors.New("read used closed production engine")}
 observed.endpoints=append(observed.endpoints,id)
 if observed.entered!=nil {close(observed.entered);<-observed.release}
 return 0,nil,observed.endpointErr
}
type DesktopSocketCapture struct {SessionID,SourceSHA256,NetworkID string}
type DesktopSocketKernelOwner struct {Kind,IdentitySHA256 string;Generation uint64;ProcessID uint32}
const DesktopSocketReadbackAge=3*time.Second
type DesktopWindowsSocketIdentity struct {ctx context.Context;cancel context.CancelFunc;gate chan struct{};closed bool;sockets map[string]*socketRecord;engine uintptr;api *api;capture DesktopSocketCapture;mu sync.Mutex;owner atomic.Pointer[DesktopSocketKernelOwner];current,closing atomic.Bool;observed atomic.Int64}
type DesktopWindowsSocketPolicy struct {
 ctx context.Context;gate chan struct{};retired atomic.Bool
 capture,owner string;metadata,fixtureScope []byte
 options struct{KillSwitchPolicy string}
 identity *DesktopWindowsSocketIdentity
 closed,locked,installed,baselineDone bool
 permits map[string]*permit;bindings map[string]creation;tunnel []bool
 baselineEngine *engine
}
func (p *DesktopWindowsSocketPolicy) assertBaseline()error{if !p.locked || p.baselineEngine.handle==0{return errors.New("Windows physical baseline has no native session lock")};return observed.activeErr}
type DesktopWindowsNodeSocketRetirement struct {
 policy *DesktopWindowsSocketPolicy;identity *DesktopWindowsSocketIdentity;target target;scope []byte
 creation creation;grant grant;rules []string;originalRules []desktopWFPRule;endpoints []uint64;original,returned *native;io *socket
}
var desktopWindowsNodeComposition struct{sync.Mutex;owner *DesktopWindowsSocketPolicy}
var desktopWindowsEndpointNotFound=errors.New("native endpoint absent")
var observed struct{
 originalRule desktopWFPRule;asserted []desktopWFPRule
 reader *engine;filterErr,endpointErr,openErr,closeErr,activeErr,retainedErr error
 target target;scope []byte;retained int;filters []string;endpoints []uint64;entered,release chan struct{}
}
func desktopWFPOpen(dynamic bool)(*engine,error){if dynamic{panic("observer requested mutation session")};return observed.reader,observed.openErr}
func readDesktopWindowsRetainedProtection(ctx context.Context,t target,scope []byte)error{
 observed.retained++
 if !t.matches(observed.target.capture,observed.target.policy,observed.target.metadata)||!bytes.Equal(scope,observed.scope){return errors.New("retained read adopted another baseline")}
 return observed.retainedErr
}
'''

TESTS = r'''
package retirement
import("context";"errors";"strings";"testing";"time")
func fixture(closed bool)*DesktopWindowsNodeSocketRetirement{
 observed.reader=&engine{handle:77,done:make(chan struct{})};observed.filterErr=nil;observed.endpointErr=desktopWindowsEndpointNotFound
 observed.openErr=nil;observed.closeErr=nil;observed.activeErr=nil;observed.retainedErr=nil;observed.retained=0;observed.filters=nil;observed.endpoints=nil;observed.entered=nil;observed.release=nil
 p:=&DesktopWindowsSocketPolicy{ctx:context.Background(),gate:make(chan struct{},1),capture:"source",owner:"owner",metadata:[]byte("exact baseline"),fixtureScope:[]byte("original executable"),closed:closed,locked:!closed,installed:true,baselineDone:closed,permits:map[string]*permit{},bindings:map[string]creation{},baselineEngine:&engine{}}
 p.gate<-struct{}{};p.options.KillSwitchPolicy="always"
 p.identity=&DesktopWindowsSocketIdentity{ctx:context.Background(),gate:make(chan struct{},1),closed:closed,sockets:map[string]*socketRecord{},api:&api{}}
 p.identity.gate<-struct{}{}
 if !closed{p.baselineEngine.handle=11;p.identity.engine=12}
 r:=&DesktopWindowsNodeSocketRetirement{policy:p,identity:p.identity,target:target{p.capture,p.options.KillSwitchPolicy,append([]byte(nil),p.metadata...)},scope:append([]byte(nil),p.fixtureScope...),creation:creation{"socket"},rules:[]string{"captured-filter"},endpoints:[]uint64{91},original:&native{true},returned:&native{true},io:&socket{closed:true}}
 r.grant.Capture=p.capture;r.grant.SocketID="socket";r.grant.Binding.Owner=p.owner
 desktopWindowsNodeComposition.owner=p;observed.target=r.target;observed.scope=append([]byte(nil),r.scope...)
 return r
}
func TestOriginalRetirementAfterPolicyAndIdentityClose(t *testing.T){
 for _,closed:=range []bool{false,true}{name:="active";if closed{name="closed"};t.Run(name,func(t *testing.T){r:=fixture(closed);if err:=r.RequireRetired(context.Background());err!=nil{t.Fatal("exact original retirement failed",closed,err)}
  if len(observed.filters)!=1||observed.filters[0]!="captured-filter"||len(observed.endpoints)!=1||observed.endpoints[0]!=91||!observed.reader.closed.Load(){t.Fatal("captured native evidence was not independently read and closed")}
  if closed&&observed.retained!=1||!closed&&observed.retained!=0{t.Fatal("wrong owner lifetime readback",observed.retained)}
 })}
}
func TestRetirementRejectsUnprovedAbsence(t *testing.T){
 tests:=map[string]func(*DesktopWindowsNodeSocketRetirement){
 "different policy":func(r *DesktopWindowsNodeSocketRetirement){desktopWindowsNodeComposition.owner=&DesktopWindowsSocketPolicy{}},
 "changed capture":func(r *DesktopWindowsNodeSocketRetirement){r.policy.capture="new"},
 "changed owner":func(r *DesktopWindowsNodeSocketRetirement){r.policy.owner="new"},
 "changed identity":func(r *DesktopWindowsNodeSocketRetirement){r.policy.identity=&DesktopWindowsSocketIdentity{}},
 "changed scope":func(r *DesktopWindowsNodeSocketRetirement){r.policy.fixtureScope=[]byte("new")},
 "changed metadata":func(r *DesktopWindowsNodeSocketRetirement){r.policy.metadata=[]byte("new")},
 "retained native lock":func(r *DesktopWindowsNodeSocketRetirement){r.policy.locked=true},
 "missing baseline":func(r *DesktopWindowsNodeSocketRetirement){r.policy.installed=false},
 "unfinished baseline":func(r *DesktopWindowsNodeSocketRetirement){r.policy.baselineDone=false},
 "retained tunnel":func(r *DesktopWindowsNodeSocketRetirement){r.policy.tunnel=[]bool{true}},
 "binding":func(r *DesktopWindowsNodeSocketRetirement){r.policy.bindings["socket"]=r.creation},
 "grant":func(r *DesktopWindowsNodeSocketRetirement){r.policy.permits["original"]=&permit{r.grant}},
 "native baseline mismatch":func(r *DesktopWindowsNodeSocketRetirement){observed.retainedErr=errors.New("kernel baseline replaced")},
 "unclosed identity":func(r *DesktopWindowsNodeSocketRetirement){r.identity.closed=false},
 "source record":func(r *DesktopWindowsNodeSocketRetirement){r.identity.sockets["socket"]=&socketRecord{}},
 "original descriptor":func(r *DesktopWindowsNodeSocketRetirement){r.original.closed=false},
 "returned descriptor":func(r *DesktopWindowsNodeSocketRetirement){r.returned.closed=false},
 "native IO":func(r *DesktopWindowsNodeSocketRetirement){r.io.closed=false},
 "filter":func(r *DesktopWindowsNodeSocketRetirement){observed.filterErr=errors.New("native filter remains")},
 "endpoint":func(r *DesktopWindowsNodeSocketRetirement){observed.endpointErr=nil},
 "lookup refused":func(r *DesktopWindowsNodeSocketRetirement){observed.endpointErr=errors.New("access denied")},
 "reader open":func(r *DesktopWindowsNodeSocketRetirement){observed.openErr=errors.New("reader open failed")},
 "reader close":func(r *DesktopWindowsNodeSocketRetirement){observed.closeErr=errors.New("reader close failed")},
 }
 for name,change:=range tests{t.Run(name,func(t *testing.T){r:=fixture(true);change(r);if err:=r.RequireRetired(context.Background());err==nil{t.Fatal("unproved native retirement accepted",name)}})}
 r:=fixture(false);r.policy.locked=false
 if err:=r.RequireRetired(context.Background());err==nil||!strings.Contains(err.Error(),"no native session lock"){t.Fatal("missing active lock became successful retirement",err)}
}
func grantFixture()*DesktopWindowsNodeSocketRetirement{
 r:=fixture(false)
 r.policy.bindings[r.creation.SocketID]=r.creation
 r.policy.permits[desktopWindowsPermitKey(r.grant)]=&permit{r.grant}
 observed.originalRule=desktopWFPRule{"captured-filter",42};observed.asserted=nil
 r.originalRules=[]desktopWFPRule{observed.originalRule}
 return r
}
func TestCompletedRefusalClassifiesExactRetainedGrant(t *testing.T){
 r:=grantFixture()
 retained,err:=r.RetainedGrant(context.Background())
 if !retained||err!=nil{t.Fatal("original retained grant not witnessed",retained,err)}
 if len(observed.asserted)!=1||observed.asserted[0]!=observed.originalRule||!observed.reader.closed.Load(){t.Fatal("missing independent exact native read and join")}
 // A completed socket-release mutant has already removed its grant. Its
 // unchanged generic witness must never count as a missing-revocation defect.
 r=grantFixture();delete(r.policy.permits,desktopWindowsPermitKey(r.grant))
 retained,err=r.RetainedGrant(context.Background())
 if retained||err!=nil||len(observed.asserted)!=0{t.Fatal("removed grant misclassified",retained,err)}
}
func joinedIOGrantFixture()*DesktopWindowsNodeSocketRetirement{
 r:=grantFixture();r.original.closed=false
 r.identity.sockets[r.creation.SocketID]=&socketRecord{r.creation,r.original,r.returned,&socketConnection{r.io}}
 return r
}
func TestJoinedIOClassifiesRetainedGrantBeforeProofCanComplete(t *testing.T){
 r:=joinedIOGrantFixture()
 retained,err:=r.RetainedGrantAfterIOClose(context.Background())
 if !retained||err!=nil{t.Fatal("joined native I/O did not expose exact retained grant before proof completion",retained,err)}
 if r.original.closed||!r.returned.closed||!r.io.closed||len(observed.asserted)!=1||observed.asserted[0]!=observed.originalRule||!observed.reader.closed.Load(){t.Fatal("classification changed original ownership or omitted independent exact filter read")}
 for _,name:=range []string{"native-io-pending","returned-descriptor-pending","grant-removed"}{t.Run(name,func(t *testing.T){
  r:=joinedIOGrantFixture()
  switch name{case "native-io-pending":r.io.closed=false;case "returned-descriptor-pending":r.returned.closed=false;case "grant-removed":delete(r.policy.permits,r.grant.SocketID)}
  retained,err:=r.RetainedGrantAfterIOClose(context.Background())
  if retained||err!=nil||len(observed.asserted)!=0{t.Fatal("unfinished native I/O or absent grant became a revocation defect",retained,err)}
 })}
}
func TestJoinedIOGrantRejectsChangedOriginalOwnership(t *testing.T){
 changes:=map[string]func(*DesktopWindowsNodeSocketRetirement){
 "missing-source":func(r *DesktopWindowsNodeSocketRetirement){delete(r.identity.sockets,r.creation.SocketID)},
 "changed-creation":func(r *DesktopWindowsNodeSocketRetirement){r.identity.sockets[r.creation.SocketID].creation=creation{"replacement"}},
 "changed-original":func(r *DesktopWindowsNodeSocketRetirement){r.identity.sockets[r.creation.SocketID].original=&native{}},
 "changed-returned":func(r *DesktopWindowsNodeSocketRetirement){r.identity.sockets[r.creation.SocketID].returned=&native{true}},
 "changed-io":func(r *DesktopWindowsNodeSocketRetirement){r.identity.sockets[r.creation.SocketID].connect=&socketConnection{&socket{closed:true}}},
 "missing-connection":func(r *DesktopWindowsNodeSocketRetirement){r.identity.sockets[r.creation.SocketID].connect=nil},
 "original-already-closed":func(r *DesktopWindowsNodeSocketRetirement){r.original.closed=true},
 "filter-read-failed":func(r *DesktopWindowsNodeSocketRetirement){observed.filterErr=errors.New("original filter not proved")},
 }
 for name,change:=range changes{t.Run(name,func(t *testing.T){r:=joinedIOGrantFixture();change(r);retained,err:=r.RetainedGrantAfterIOClose(context.Background());if retained&&err==nil||err==nil{t.Fatal("changed native ownership classified as exact revocation defect",retained,err)}})}
 r:=joinedIOGrantFixture();ctx,cancel:=context.WithCancel(context.Background());cancel()
 retained,err:=r.RetainedGrantAfterIOClose(ctx)
 if retained||!errors.Is(err,context.Canceled)||len(observed.asserted)!=0{t.Fatal("joined-I/O observation renewed canceled caller",retained,err)}
}
func TestRetainedGrantRejectsUnrelatedOrFailedEvidence(t *testing.T){
 tests:=map[string]func(*DesktopWindowsNodeSocketRetirement){
 "different policy":func(r *DesktopWindowsNodeSocketRetirement){desktopWindowsNodeComposition.owner=&DesktopWindowsSocketPolicy{}},
 "capture":func(r *DesktopWindowsNodeSocketRetirement){r.policy.capture="replacement"},
 "owner":func(r *DesktopWindowsNodeSocketRetirement){r.policy.owner="replacement"},
 "identity":func(r *DesktopWindowsNodeSocketRetirement){r.policy.identity=&DesktopWindowsSocketIdentity{}},
 "scope":func(r *DesktopWindowsNodeSocketRetirement){r.policy.fixtureScope=[]byte("replacement")},
 "target":func(r *DesktopWindowsNodeSocketRetirement){r.policy.metadata=[]byte("replacement")},
 "baseline":func(r *DesktopWindowsNodeSocketRetirement){observed.activeErr=errors.New("native baseline missing")},
 "binding absent":func(r *DesktopWindowsNodeSocketRetirement){delete(r.policy.bindings,r.creation.SocketID)},
 "binding changed":func(r *DesktopWindowsNodeSocketRetirement){r.policy.bindings[r.creation.SocketID]=creation{"replacement"}},
 "grant changed":func(r *DesktopWindowsNodeSocketRetirement){r.policy.permits[r.grant.SocketID].request.Capture="replacement"},
 "rules absent":func(r *DesktopWindowsNodeSocketRetirement){r.originalRules=nil},
 "rule changed":func(r *DesktopWindowsNodeSocketRetirement){r.originalRules[0].ID++},
 "filter absent":func(r *DesktopWindowsNodeSocketRetirement){observed.filterErr=errors.New("filter absent")},
 "reader open":func(r *DesktopWindowsNodeSocketRetirement){observed.openErr=errors.New("reader open refused")},
 "reader close":func(r *DesktopWindowsNodeSocketRetirement){observed.closeErr=errors.New("reader close failed")},
 }
 for name,change:=range tests{t.Run(name,func(t *testing.T){r:=grantFixture();change(r);retained,err:=r.RetainedGrant(context.Background());if retained&&err==nil{t.Fatal("unrelated evidence classified as exact retained grant")};if err==nil{t.Fatal("invalid observation became successful absence")}})}
 r:=grantFixture();ctx,cancel:=context.WithCancel(context.Background());cancel()
 retained,err:=r.RetainedGrant(ctx)
 if retained||!errors.Is(err,context.Canceled)||len(observed.asserted)!=0{t.Fatal("expired original deadline was not preserved",retained,err)}
}
func TestGrantObservationTimeoutRetainsEnteredIndependentReader(t *testing.T){
 r:=grantFixture();observed.entered=make(chan struct{});observed.release=make(chan struct{});reader:=observed.reader
 ctx,cancel:=context.WithCancel(context.Background());defer cancel();done:=make(chan error,1)
 go func(){retained,err:=r.RetainedGrant(ctx);if retained&&err==nil{err=errors.New("cancelled grant observation accepted")};done<-err}()
 select{case<-observed.entered:case<-time.After(time.Second):t.Fatal("grant query not entered")}
 cancel()
 select{case err:=<-done:if !errors.Is(err,context.Canceled){t.Fatal("caller cancellation lost",err)};case<-time.After(time.Second):t.Fatal("caller cancellation blocked")}
 if reader.closed.Load(){t.Fatal("timeout closed reader during entered grant query")}
 close(observed.release)
 select{case<-reader.done:case<-time.After(time.Second):t.Fatal("reader not closed after grant query joined")}
 <-r.policy.gate;r.policy.gate<-struct{}{}
}
func TestRetirementTimeoutRetainsEnteredIndependentReader(t *testing.T){
 r:=fixture(true);observed.entered=make(chan struct{});observed.release=make(chan struct{});reader:=observed.reader
 ctx,cancel:=context.WithCancel(context.Background());defer cancel();done:=make(chan error,1)
 go func(){done<-r.RequireRetired(ctx)}()
 select{case<-observed.entered:case<-time.After(time.Second):t.Fatal("endpoint query not entered")}
 cancel()
 select{case err:=<-done:if !errors.Is(err,context.Canceled){t.Fatal("caller cancellation was lost",err)};case<-time.After(time.Second):t.Fatal("caller cancellation was blocked")}
 if reader.closed.Load(){t.Fatal("timeout closed reader during its entered native query")}
 close(observed.release)
 select{case<-reader.done:case<-time.After(time.Second):t.Fatal("reader was not closed after native query joined")}
 <-r.identity.gate;r.identity.gate<-struct{}{}
 <-r.policy.gate;r.policy.gate<-struct{}{}
}
'''


def execute(observer=OBSERVER, identity_path=None):
    compiler = shutil.which('go')
    if not compiler:
        raise SystemExit('Go is required for the portable native observer control')
    source = Path(observer).read_text()
    policy = (ROOT / 'internal/mobiletor/desktop_socket_windows_policy.go').read_text()
    identity = Path(identity_path or ROOT / 'internal/mobiletor/desktop_socket_windows_identity.go').read_text()
    broker = (ROOT / 'internal/mobiletor/desktop_socket_broker.go').read_text()
    selected = [function(source, 'func (r *DesktopWindowsNodeSocketRetirement) originalClosed()'),
                function(source, 'func (r *DesktopWindowsNodeSocketRetirement) RequireRetired('),
                function(source, 'func (r *DesktopWindowsNodeSocketRetirement) RetainedGrant('),
                function(source, 'func (r *DesktopWindowsNodeSocketRetirement) RetainedGrantAfterIOClose('),
                function(source, 'func (r *DesktopWindowsNodeSocketRetirement) retainedGrant('),
                function(policy, 'func desktopWindowsPolicyCall['),
                function(identity, 'func (p *DesktopWindowsSocketIdentity) call('),
                function(identity, 'func desktopWindowsIdentityContextError('),
                function(identity, 'func (p *DesktopWindowsSocketIdentity) Current('),
                function(identity, 'func (p *DesktopWindowsSocketIdentity) Owner('),
                function(broker, 'func desktopSocketHex('),
                function(broker, 'func (o DesktopSocketKernelOwner) valid(')]
    with tempfile.TemporaryDirectory(prefix='windows-retirement-observer-') as temporary:
        folder = Path(temporary)
        (folder / 'go.mod').write_text('module retirement\n\ngo 1.24.0\n')
        (folder / 'observer.go').write_text(BOUNDARIES + '\n' + '\n\n'.join(selected))
        (folder / 'observer_test.go').write_text(TESTS)
        native_tests = (ROOT / 'internal/mobiletor/desktop_socket_windows_identity_current_test.go').read_text()
        prefix = '//go:build windows\n\npackage mobiletor\n'
        if not native_tests.startswith(prefix):
            raise ValueError('Native Windows identity context test boundary changed')
        (folder / 'identity_current_test.go').write_text(native_tests.replace(prefix, 'package retirement\n', 1))
        environment = dict(os.environ, GOWORK='off', GOFLAGS='')
        host_os, host_arch = subprocess.check_output(
            [compiler, 'env', 'GOHOSTOS', 'GOHOSTARCH'], env=environment, text=True, timeout=15).split()
        # Windows ARM64 has no Go race runtime. Execute the same controls there;
        # supported native CI hosts also retain race instrumentation.
        race = [] if (host_os, host_arch) == ('windows', 'arm64') else ['-race']
        environment.update(GOOS=host_os, GOARCH=host_arch, CGO_ENABLED='1' if race else '0')
        subprocess.run([compiler, 'test', *race, '-count=1', '-timeout=30s', '-v', '.'],
                       cwd=folder, env=environment, check=True, timeout=90)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--observer', type=Path, default=OBSERVER)
    parser.add_argument('--identity', type=Path)
    args = parser.parse_args()
    execute(args.observer, args.identity)
