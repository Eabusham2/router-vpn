#!/usr/bin/env python3
"""Execute shipping callLocked with an owned Unix stream and joined peer.

Only Darwin framing/credential lookup, Current, and the peer's PF bookkeeping
are modeled. This is a portable causal channel regression, not native PF proof.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = r'''package probe
import("context";"encoding/json";"errors";"fmt";"net";"os";"os/exec";"time")
type DesktopSocketCapture struct{SessionID string}
type DesktopSocketGrant struct{Sequence uint64}
type desktopDarwinRequest struct{Operation string;Sequence uint64;Capture DesktopSocketCapture;Grant DesktopSocketGrant}
type desktopDarwinReply struct{Sequence uint64;Capture DesktopSocketCapture;Error string}
type DesktopDarwinSocketPolicy struct{sequence uint64;capture DesktopSocketCapture;owner string;channel *net.UnixConn;command *exec.Cmd;current bool;loss string}
func(p *DesktopDarwinSocketPolicy)Current(DesktopSocketCapture,string)bool{return p.current}
func(p *DesktopDarwinSocketPolicy)lose(phase string,_ error){p.current=false;p.loss=phase}
func desktopDarwinSend(c *net.UnixConn,r desktopDarwinRequest,_ *os.File)error{return json.NewEncoder(c).Encode(r)}
func desktopDarwinReceive(c *net.UnixConn,r *desktopDarwinReply,_ uint32,_ int)(*os.File,error){return nil,json.NewDecoder(c).Decode(r)}
'''
TEST = r'''package probe
import("context";"encoding/json";"errors";"io";"net";"os";"os/exec";"path/filepath";"testing";"time")
func TestActualDarwinControlJoinedRejectedOperations(t *testing.T){
 for _,scenario:=range []struct{name,operation string;rejected,mismatch bool}{
  {"grant-rejected","grant",true,false},{"revoke-rejected","revoke",true,false},{"probe-rejected","probe",true,false},
  {"grant-success","grant",false,false},{"grant-mismatch","grant",false,true},{"revoke-mismatch","revoke",false,true},
 }{t.Run(scenario.name,func(t *testing.T){
  // Keep the Unix address below Darwin's native sun_path bound; t.TempDir
  // incorporates this long subtest name and can exceed that bound on macOS.
  directory,err:=os.MkdirTemp("","dcl-");if err!=nil{t.Fatal(err)};defer os.RemoveAll(directory)
  listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:filepath.Join(directory,"control.sock"),Net:"unix"});if err!=nil{t.Fatal(err)};defer listener.Close()
  client,err:=net.DialUnix("unix",nil,listener.Addr().(*net.UnixAddr));if err!=nil{t.Fatal(err)}
  peer,err:=listener.AcceptUnix();if err!=nil{client.Close();t.Fatal(err)}
  observed:=make(chan desktopDarwinRequest,1);result:=make(chan error,1);joined:=make(chan struct{})
  closes:=scenario.mismatch||(scenario.operation=="grant"||scenario.operation=="revoke")&&scenario.rejected
  go func(){defer close(joined);defer peer.Close();_ = peer.SetDeadline(time.Now().Add(2*time.Second))
   var q desktopDarwinRequest;if err:=json.NewDecoder(peer).Decode(&q);err!=nil{result<-err;return};observed<-q
   reply:=desktopDarwinReply{Sequence:q.Sequence,Capture:q.Capture};if scenario.rejected{reply.Error="captured "+q.Operation+" rejected before native completion"};if scenario.mismatch{reply.Sequence++}
   if err:=json.NewEncoder(peer).Encode(reply);err!=nil{result<-err;return}
   var b [1]byte;n,err:=peer.Read(b[:])
   if closes{if n!=0||!errors.Is(err,io.EOF){result<-errors.New("rejected "+scenario.operation+" retained its original peer instead of joined EOF");return}}else{
    if err!=nil||n!=1||b[0]!='k'{result<-errors.New("non-retiring rejection or success lost its original channel");return}
    n,err=peer.Read(b[:]);if n!=0||!errors.Is(err,io.EOF){result<-errors.New("fixture cleanup did not join original peer EOF");return}
   };result<-nil
  }()
  defer func(){client.Close();select{case <-joined:case <-time.After(3*time.Second):t.Error("owned control peer did not join")}}()
  p:=&DesktopDarwinSocketPolicy{sequence:7,capture:DesktopSocketCapture{"original"},channel:client,command:&exec.Cmd{Process:&os.Process{Pid:os.Getpid()}},current:true}
  attempted:=DesktopSocketGrant{Sequence:42};request:=desktopDarwinRequest{Operation:scenario.operation,Capture:p.capture,Grant:attempted}
  ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel()
  _,file,failure:=p.callLocked(ctx,request,nil,true);if file!=nil{file.Close();t.Fatal("unexpected transferred descriptor")}
  var q desktopDarwinRequest
  select{case q=<-observed:case <-ctx.Done():t.Fatal("original control peer did not acknowledge its request",ctx.Err())}
  if q.Sequence!=8||q.Grant!=attempted||p.sequence!=8{t.Fatal("sent request changed its attempted grant sequence")}
  var unsubmitted *desktopSocketGrantNotSubmitted
  if errors.As(failure,&unsubmitted){t.Fatal("sent grant result acquired an unsent rollback marker")}
  if scenario.rejected||scenario.mismatch{if failure==nil||p.current||p.loss!="control-receive-"+scenario.operation{t.Fatal("rejected original request did not record source loss")}}else if failure!=nil||!p.current||p.loss!=""{t.Fatal("successful grant lost its original owner",failure)}
  if !closes{if _,err:=client.Write([]byte{'k'});err!=nil{t.Fatal("non-retiring rejection or success lost its original channel",err)};client.Close()}
  select{case err:=<-result:if err!=nil{t.Fatal(err)};case <-ctx.Done():t.Fatal("original control peer result did not join within its captured context",ctx.Err())}
 })}
}
'''

def sources(root):
    policy = (root/'internal/mobiletor/desktop_socket_darwin_policy.go').read_text()
    start = 'func (p *DesktopDarwinSocketPolicy) callLocked('
    end = '\nfunc desktopDarwinOwner('
    assert policy.count(start) == 1 and policy.count(end) == 1, 'Native control source boundary changed'
    method = policy[policy.index(start):policy.index(end)]
    marker = (root/'internal/mobiletor/desktop_socket_grant_admission.go').read_text()
    assert marker.startswith('package mobiletor\n')
    return HEADER + marker.removeprefix('package mobiletor\n') + method


def execute(root=ROOT, go=None, mutations=True):
    go = go or shutil.which('go')
    if not go:
        raise RuntimeError('Go is required for the actual Darwin control lifetime regression')
    original = sources(root)
    variants = [('baseline', original, None)]
    if mutations:
        close = 'err != nil || reply.Sequence != request.Sequence || reply.Capture != p.capture || (request.Operation == "grant" || request.Operation == "revoke") && reply.Error != ""'
        assert original.count(close) == 1, 'Native grant/revoke rejection lifetime boundary changed'
        variants += [
            ('keep-rejected-grant', original.replace(close, 'err != nil || reply.Sequence != request.Sequence || reply.Capture != p.capture || request.Operation == "revoke" && reply.Error != ""'), 'rejected grant retained its original peer'),
            ('keep-rejected-revoke', original.replace(close, 'err != nil || reply.Sequence != request.Sequence || reply.Capture != p.capture || request.Operation == "grant" && reply.Error != ""'), 'rejected revoke retained its original peer'),
            ('close-non-retiring-error', original.replace(close, 'err != nil || reply.Sequence != request.Sequence || reply.Capture != p.capture || reply.Error != ""'), 'non-retiring rejection or success lost its original channel'),
            ('rollback-sent-result', original.replace('return reply, received, failure', 'return reply, received, desktopSocketUnsubmittedGrant(request.Grant, failure)'), 'sent grant result acquired an unsent rollback marker'),
        ]
    with tempfile.TemporaryDirectory(prefix='darwin-control-lifetime-') as name:
        folder = Path(name); source = folder/'control.go'; test = folder/'control_test.go'; test.write_text(TEST)
        for label, content, witness in variants:
            source.write_text(content)
            result = subprocess.run([go, 'test', '-race', '-v', '-timeout=20s', str(source), str(test)], capture_output=True, text=True, timeout=120, env=dict(os.environ, GOTOOLCHAIN='local'))
            output = result.stdout + result.stderr
            if witness:
                if result.returncode == 0 or witness not in output or re.search(r'panic:|fatal error:|WARNING: DATA RACE|\[build failed\]', output):
                    raise AssertionError(label+': missing clean intended failure\n'+output)
            elif result.returncode != 0 or len(re.findall(r'^--- PASS: TestActualDarwinControlJoinedRejectedOperations ', output, re.M)) != 1 or len(re.findall(r'^    --- PASS: TestActualDarwinControlJoinedRejectedOperations/', output, re.M)) != 6:
                raise AssertionError('Actual original channel lifetime failed\n'+output)
            print('Darwin original control lifetime: '+label+' verified', flush=True)


if __name__ == '__main__':
    execute()
