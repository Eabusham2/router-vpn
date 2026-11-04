#!/usr/bin/env python3
"""Execute the exact native observer and call gates with OS readback doubled.

This checks post-close observation and reader lifetime on a portable Go host.
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
 "errors"
 "net"
 "sync"
 "sync/atomic"
 "syscall"
)
type target struct {capture, policy string; metadata []byte}
func (t target) matches(c, p string, m []byte) bool {return t.capture==c && t.policy==p && bytes.Equal(t.metadata,m)}
type grant struct {Capture,SocketID string; Binding struct{Owner string}}
type creation struct {SocketID string}
type permit struct {request grant}
type native struct {closed bool}
func (n *native) SyscallConn()(syscall.RawConn,error){if n.closed{return nil,net.ErrClosed};return nil,nil}
type socket struct {mu sync.Mutex;closed bool}
type engine struct {handle uintptr;closed atomic.Bool;done chan struct{}}
func (e *engine) Absent(key string)error{if e!=observed.reader{return errors.New("read used production engine")};observed.filters=append(observed.filters,key);return observed.filterErr}
func (e *engine) Close()error{if e.closed.CompareAndSwap(false,true){close(e.done)};return observed.closeErr}
type api struct{}
func (*api) endpointProperties(handle uintptr,id uint64)(int,[]byte,error){
 if handle!=observed.reader.handle || observed.reader.closed.Load(){return 0,nil,errors.New("read used closed production engine")}
 observed.endpoints=append(observed.endpoints,id)
 if observed.entered!=nil {close(observed.entered);<-observed.release}
 return 0,nil,observed.endpointErr
}
type DesktopWindowsSocketIdentity struct {ctx context.Context;gate chan struct{};closed bool;sockets map[string]bool;engine uintptr;api *api}
type DesktopWindowsSocketPolicy struct {
 ctx context.Context;gate chan struct{};retired atomic.Bool
 capture,owner string;metadata,fixtureScope []byte
 options struct{KillSwitchPolicy string}
 identity *DesktopWindowsSocketIdentity
 closed,locked,installed,baselineDone bool
 permits map[string]*permit;bindings map[string]bool;tunnel []bool
 baselineEngine *engine
}
func (p *DesktopWindowsSocketPolicy) assertBaseline()error{if !p.locked || p.baselineEngine.handle==0{return errors.New("Windows physical baseline has no native session lock")};return observed.activeErr}
type DesktopWindowsNodeSocketRetirement struct {
 policy *DesktopWindowsSocketPolicy;identity *DesktopWindowsSocketIdentity;target target;scope []byte
 creation creation;grant grant;rules []string;endpoints []uint64;original,returned *native;io *socket
}
var desktopWindowsNodeComposition struct{sync.Mutex;owner *DesktopWindowsSocketPolicy}
var desktopWindowsEndpointNotFound=errors.New("native endpoint absent")
var observed struct{
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
 p:=&DesktopWindowsSocketPolicy{ctx:context.Background(),gate:make(chan struct{},1),capture:"source",owner:"owner",metadata:[]byte("exact baseline"),fixtureScope:[]byte("original executable"),closed:closed,locked:!closed,installed:true,baselineDone:closed,permits:map[string]*permit{},bindings:map[string]bool{},baselineEngine:&engine{}}
 p.gate<-struct{}{};p.options.KillSwitchPolicy="always"
 p.identity=&DesktopWindowsSocketIdentity{ctx:context.Background(),gate:make(chan struct{},1),closed:closed,sockets:map[string]bool{},api:&api{}}
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
 "binding":func(r *DesktopWindowsNodeSocketRetirement){r.policy.bindings["socket"]=true},
 "grant":func(r *DesktopWindowsNodeSocketRetirement){r.policy.permits["original"]=&permit{r.grant}},
 "native baseline mismatch":func(r *DesktopWindowsNodeSocketRetirement){observed.retainedErr=errors.New("kernel baseline replaced")},
 "unclosed identity":func(r *DesktopWindowsNodeSocketRetirement){r.identity.closed=false},
 "source record":func(r *DesktopWindowsNodeSocketRetirement){r.identity.sockets["socket"]=true},
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


def execute(observer=OBSERVER):
    compiler = shutil.which('go')
    if not compiler:
        raise SystemExit('Go is required for the portable native observer control')
    source = Path(observer).read_text()
    policy = (ROOT / 'internal/mobiletor/desktop_socket_windows_policy.go').read_text()
    identity = (ROOT / 'internal/mobiletor/desktop_socket_windows_identity.go').read_text()
    selected = [function(source, 'func (r *DesktopWindowsNodeSocketRetirement) originalClosed()'),
                function(source, 'func (r *DesktopWindowsNodeSocketRetirement) RequireRetired('),
                function(policy, 'func desktopWindowsPolicyCall['),
                function(identity, 'func (p *DesktopWindowsSocketIdentity) call('),
                function(identity, 'func desktopWindowsIdentityContextError(')]
    with tempfile.TemporaryDirectory(prefix='windows-retirement-observer-') as temporary:
        folder = Path(temporary)
        (folder / 'go.mod').write_text('module retirement\n\ngo 1.24.0\n')
        (folder / 'observer.go').write_text(BOUNDARIES + '\n' + '\n\n'.join(selected))
        (folder / 'observer_test.go').write_text(TESTS)
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
    execute(parser.parse_args().observer)
