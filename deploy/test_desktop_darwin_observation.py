#!/usr/bin/env python3
"""Run the actual Darwin command adapter with modeled path/identity boundaries.

The command and observer are shipping source; real subprocess Start/Wait and
context cancellation execute here. This does not claim a Darwin PF verdict.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile


def execute(root):
    root = Path(root)
    compiler = shutil.which('go')
    if not compiler:
        raise RuntimeError('Go is required for the Darwin original command observation regression')
    sources = root/'internal/mobiletor'
    identity = (sources/'desktop_socket_darwin_identity.go').read_text()
    command = identity[identity.index('type desktopDarwinCommandBuffer struct'):identity.index('func desktopDarwinIdentityLock(')]
    owner = (sources/'desktop_socket_admission_observation.go').read_text()
    owner = owner[owner.index('func desktopSocketObservationOwner('):owner.index('func (s *desktopSocket) recordAdmissionLoss(')]
    observer = (sources/'desktop_socket_native_observation.go').read_text()
    pipe = (sources/'desktop_socket_darwin_observation.go').read_text().split('\n\n', 1)[1]
    fixture = (sources/'desktop_socket_darwin_guardian_test.go').read_text()
    start = fixture.index('func desktopDarwinKernelBroker(')
    broker = fixture[start:fixture.index('\nfunc desktopDarwinKernelTrace(', start)]
    start = fixture.index('func desktopDarwinKernelReadbackTrace(')
    trace = fixture[start:fixture.index('\nfunc ', start+1)]
    header = '''package mobiletor
import("bytes";"context";"fmt";"os";"os/exec";"path/filepath";"time";"errors")
var inspectPath func(string,bool)error
func desktopDarwinProtectedPath(path string, private bool)error{return inspectPath(path,private)}
func desktopPFEnterCommand(context.Context)(func(),error){return func(){},nil}
func desktopDarwinProcessAuthority(context.Context)[]*os.File{return nil}
'''
    types = '''package mobiletor
import("crypto/sha256";"fmt")
type DesktopSocketCapture struct{SessionID,SourceSHA256,NetworkID string}
type DesktopSocketKernelOwner struct{Kind,IdentitySHA256 string;Generation uint64;ProcessID uint32}
'''
    regression = r'''package mobiletor
import("context";"errors";"fmt";"os";"strings";"syscall";"testing";"time")
func TestActualDarwinCommandObservation(t *testing.T){
 // Native path ownership and the PF command-budget boundary are modeled;
 // the exact shipping command/observer and actual process lifecycle run.
 capture:=DesktopSocketCapture{"private-session","private-source","private-network"}
 owner:=DesktopSocketKernelOwner{"unix-isolated-uid","private-owner",7,41}
 originalContext,cancel:=context.WithCancel(context.Background());defer cancel()
 originalContext=desktopDarwinObserveRequest(originalContext,capture,owner,12,"probe")
 entered,release:=make(chan struct{}),make(chan struct{})
 inspectPath=func(path string,private bool)error{if path!="/bin/echo"||private{t.Error("command replaced original protected path")};close(entered);<-release;return nil}
 reader,writer,err:=desktopDarwinObservationPipe();if err!=nil{t.Fatal(err)}
 defer reader.Close();defer writer.Close()
 originalContext=context.WithValue(originalContext,desktopDarwinObservationOutputKey{},writer)
 result:=make(chan error,1)
 go func(){_,err:=desktopDarwinCommand(originalContext,"/bin/echo",nil,"secret-argument");result<-err}()
 <-entered
 // A newer request is deliberately available before cancellation. It cannot
 // relabel the original operation or provide its observation deadline.
 owner.Generation,owner.ProcessID=8,42
 replacement:=desktopDarwinObserveRequest(context.Background(),capture,owner,13,"grant")
 _=replacement
 cancel()
 var line string
 until:=time.Now().Add(time.Second)
 for line==""&&time.Now().Before(until){line=desktopDarwinReadbackMessages(reader);if line==""{time.Sleep(time.Millisecond)}}
 close(release)
 var returned error
 select{case returned=<-result:case <-time.After(time.Second):t.Fatal("original command did not join after its protected-path boundary returned")}
 if !errors.Is(returned,context.Canceled){t.Fatal("original command lost captured cancellation",returned)}
 wantOwner:=desktopSocketObservationOwner(capture,DesktopSocketKernelOwner{"unix-isolated-uid","private-owner",7,41},"")
 if !strings.Contains(line,fmt.Sprintf("owner=%x guardian=41 request=12 operation=probe command=1 kind=other phase=protected-path child=0",wantOwner)){
  t.Fatal("original in-flight command lost its bounded observation before cleanup",line)
 }
 for _,secret:=range []string{"private-session","private-source","private-network","private-owner","secret-argument"}{if strings.Contains(line,secret){t.Fatal("command observation disclosed raw private input")}}
 calls:=0;inspectPath=func(string,bool)error{calls++;return nil}
 _,err=desktopDarwinCommand(originalContext,"/bin/echo",nil,"cancelled")
 if !errors.Is(err,context.Canceled)||calls!=0{t.Fatal("pre-cancelled command entered execution",err,calls)}
 ctx:=desktopDarwinObserveRequest(context.Background(),capture,owner,14,"grant")
 output,err:=desktopDarwinCommand(ctx,"/bin/echo",nil,"actual-owned-command")
 if err!=nil||string(output)!="actual-owned-command\n"||calls!=1{t.Fatal("observation changed actual successful command",err,calls)}
 if _,err:=desktopDarwinCommand(ctx,"/bin/false",nil);err==nil{t.Fatal("observation changed actual native command failure")}
}
func TestDarwinObservationDropsFullPipe(t *testing.T){
 reader,writer,err:=desktopDarwinObservationPipe();if err!=nil{t.Fatal(err)}
 defer reader.Close();defer writer.Close()
 raw,err:=writer.SyscallConn();if err!=nil{t.Fatal(err)}
 full:=false
 if err:=raw.Control(func(fd uintptr){for i:=0;i<4096;i++{_,err:=syscall.Write(int(fd),make([]byte,512));if errors.Is(err,syscall.EAGAIN)||errors.Is(err,syscall.EWOULDBLOCK){full=true;break};if err!=nil{t.Error(err);break}}});err!=nil{t.Fatal(err)}
 if !full{t.Fatal("bounded original diagnostic pipe did not reach backpressure")}
 stderrRaw,err:=os.Stderr.SyscallConn();if err!=nil{t.Fatal(err)}
 flags:=func()uintptr{var value uintptr;stderrRaw.Control(func(fd uintptr){value,_,_=syscall.Syscall(syscall.SYS_FCNTL,fd,syscall.F_GETFL,0)});return value}
 before:=flags()
 ctx:=context.WithValue(context.Background(),desktopDarwinObservationOutputKey{},writer)
 report:=desktopDarwinReadbackReporter(ctx)
 joined:=make(chan struct{})
 go func(){report(desktopDarwinReadbackSnapshot{guardian:41,sequence:12,operation:"probe",kind:"pfctl"});close(joined)}()
 blocked:=false
 select{case <-joined:case <-time.After(time.Second):blocked=true}
 // Recover the deliberately blocking control before the causal assertion;
 // never leave a diagnostic goroutine or its original pipe owner detached.
 _=desktopDarwinReadbackMessages(reader)
 select{case <-joined:case <-time.After(time.Second):t.Fatal("original diagnostic write did not join after captured pipe recovery")}
 if flags()!=before{t.Fatal("diagnostic changed parent stderr flags")}
 if blocked{t.Fatal("diagnostic blocked original operation on full pipe")}
 reader.Close()
 report(desktopDarwinReadbackSnapshot{}) // Closed receiver is a bounded drop too.
 writer.Close()
 report(desktopDarwinReadbackSnapshot{}) // No borrowed descriptor after close.
}
'''
    marker = 'observation, finishObservation := desktopDarwinObserveReadback(ctx, filepath.Base(path), desktopDarwinReadbackReporter(ctx))'
    if command.count(marker) != 1:
        raise RuntimeError('Darwin command observation no longer has its exact captured wiring')
    write = '_ = raw.Control(func(fd uintptr) { _, _ = syscall.Write(int(fd), line) })'
    if pipe.count(write) != 1:
        raise RuntimeError('Darwin diagnostic output lost its one bounded write')
    variants = [('baseline', command, pipe, None),
                ('missing-original-observation', command.replace(marker,
                 'observation, finishObservation := (*desktopDarwinReadbackObservation)(nil), func() {}'),
                 pipe,
                 'original in-flight command lost its bounded observation before cleanup')]
    variants.append(('blocking-output', command, pipe.replace(write,
                     '_ = raw.Control(func(fd uintptr) { _ = syscall.SetNonblock(int(fd), false); _, _ = syscall.Write(int(fd), line) })'),
                     'diagnostic blocked original operation on full pipe'))
    with tempfile.TemporaryDirectory(prefix='darwin-command-observation-') as temporary:
        folder = Path(temporary)
        (folder/'observer.go').write_text(observer)
        (folder/'owner.go').write_text(types+owner)
        (folder/'observation_test.go').write_text(regression)
        for label, selected, selected_pipe, witness in variants:
            (folder/'command.go').write_text(header+selected)
            (folder/'pipe.go').write_text(selected_pipe)
            files = [str(folder/name) for name in ('command.go','observer.go','owner.go','pipe.go','observation_test.go')]
            result = subprocess.run([compiler,'test','-race','-v','-timeout=15s',*files],
                                    text=True,capture_output=True,timeout=120,
                                    env=dict(os.environ,GOTOOLCHAIN='local'))
            output = result.stdout+result.stderr
            if witness is None:
                required = ('TestActualDarwinCommandObservation', 'TestDarwinObservationDropsFullPipe')
                if result.returncode or any(output.count('--- PASS: '+name+' (') != 1 for name in required):
                    raise AssertionError(output)
            elif not result.returncode or witness not in output:
                raise AssertionError(output)
            if any(invalid in output for invalid in ('panic:','fatal error:','WARNING: DATA RACE','[build failed]','did not join')):
                raise AssertionError(output)
            print('Darwin original command observation: '+label+' verified',flush=True)
        # The failed native case first drains before the guardian's own
        # cancellation callback runs. Use the exact fixture cleanup stack and
        # real observer/pipe; model only the broker's independent retirement.
        # An expected original test failure remains a failure in both runs.
        fixture_header = r'''package mobiletor
import("context";"os";"syscall";"testing";"time")
type observedProcess struct{}
func(*observedProcess)Signal(os.Signal)error{return nil}
type DesktopDarwinSocketPolicy struct{capture DesktopSocketCapture;command struct{Process *observedProcess};observation *os.File}
type DesktopSocketBroker struct{closeOriginal func()}
var originalObservationBroker *DesktopSocketBroker
func NewDesktopSocketBroker(context.Context,DesktopSocketCapture,*DesktopDarwinSocketPolicy,func()bool)(*DesktopSocketBroker,error){return originalObservationBroker,nil}
func(b *DesktopSocketBroker)Close(context.Context)error{b.closeOriginal();return nil}
func desktopDarwinKernelTrace(t *testing.T,p *DesktopDarwinSocketPolicy,_ *DesktopSocketBroker){desktopDarwinKernelReadbackTrace(t,p,"first-loss")}
'''
        late_regression = r'''package mobiletor
import("context";"testing";"time")
func TestDarwinLateOriginalReadbackAfterFailedProbe(t *testing.T){
 reader,writer,err:=desktopDarwinObservationPipe();if err!=nil{t.Fatal(err)}
 defer reader.Close();defer writer.Close()
 policy:=&DesktopDarwinSocketPolicy{observation:reader};policy.command.Process=&observedProcess{}
 // Both owners keep their original two-second bounds. Scheduling the
 // independent native cancellation during retirement deterministically
 // exposes the same receive-before-observer ordering without a sleep race.
 parent,cancelParent:=context.WithTimeout(context.Background(),2*time.Second);defer cancelParent()
 native,cancelNative:=context.WithTimeout(context.Background(),2*time.Second);defer cancelNative()
 deadline,_:=native.Deadline()
 native=desktopDarwinObserveRequest(native,DesktopSocketCapture{"session","source","network"},DesktopSocketKernelOwner{ProcessID:41},12,"probe")
 native=context.WithValue(native,desktopDarwinObservationOutputKey{},writer)
 observation,finish:=desktopDarwinObserveReadback(native,"pfctl",desktopDarwinReadbackReporter(native))
 observation.enter(desktopNativeObservationWait,61)
 originalObservationBroker=&DesktopSocketBroker{closeOriginal:func(){
  if line:=desktopDarwinReadbackMessages(reader);line!=""{t.Error("original observation arrived before the modeled native cancellation",line)}
  cancelNative();finish()
 }}
 t.Run("original-probe-failed",func(t *testing.T){
  _=desktopDarwinKernelBroker(t,policy)
  cancelParent()
  if native.Err()!=nil||parent.Err()!=context.Canceled{t.Fatal("independent native owner did not outlive the original probe failure")}
  t.Error("original probe receive timed out")
 })
 if line:=desktopDarwinReadbackMessages(reader);line!=""{t.Error("late original native observation was lost after bounded retirement",line)}
 if after,_:=native.Deadline();after!=deadline||native.Err()!=context.Canceled{t.Fatal("diagnostic changed the native deadline or cancellation")}
}
'''
        (folder/'command.go').write_text(header+command)
        (folder/'pipe.go').write_text(pipe)
        (folder/'late_test.go').write_text(late_regression)
        checkpoint = 'desktopDarwinKernelReadbackTrace(t, policy, "after-broker-drain")'
        if broker.count(checkpoint) != 1:
            raise RuntimeError('Darwin failed cleanup lost its exact late observation checkpoint')
        for label, selected in (('late-original-observation', broker),
                                ('missing-late-observation', broker.replace(checkpoint, '// mutation: late original observation omitted', 1))):
            (folder/'fixture.go').write_text(fixture_header+selected+trace)
            files = [str(folder/name) for name in ('command.go','observer.go','owner.go','pipe.go','fixture.go','late_test.go')]
            result = subprocess.run([compiler,'test','-race','-v','-timeout=15s',*files],
                                    text=True,capture_output=True,timeout=120,
                                    env=dict(os.environ,GOTOOLCHAIN='local'))
            output = result.stdout+result.stderr
            captured = 'owned native readback observations phase=after-broker-drain: Darwin native observation:'
            lost = 'late original native observation was lost after bounded retirement'
            if result.returncode != 1 or 'original probe receive timed out' not in output:
                raise AssertionError(output)
            if label == 'late-original-observation':
                if captured not in output or lost in output or 'guardian=41 request=12 operation=probe command=1 kind=pfctl phase=wait child=61' not in output:
                    raise AssertionError(output)
            elif lost not in output or captured in output:
                raise AssertionError(output)
            if any(invalid in output for invalid in ('panic:','fatal error:','WARNING: DATA RACE','[build failed]','did not join')):
                raise AssertionError(output)
            print('Darwin original command observation: '+label+' verified',flush=True)


if __name__ == '__main__':
    execute(Path(__file__).resolve().parents[1])
