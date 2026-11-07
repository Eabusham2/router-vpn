#!/usr/bin/env python3
"""Run the shipping heartbeat loop and native deadline admission portably.

Box, physical path, file publication and OS readback are explicit fixtures.
The loop and NativeTun receipt admission are extracted production functions;
this does not establish privileged TUN or kernel acceptance.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2]


FIXTURE = r'''package heartbeat
import ("context";"errors";"os";"sync/atomic";"time")
var routerVPNExternalFailure=errors.New("captured observation failed")
var ErrNetworkReceiptUnavailable=errors.New("unused fixture capability")
type fixtureInbound interface{Type()string;Tag()string}
type fixtureTUN struct{}
func(fixtureTUN)Type()string{return "tun"}
func(fixtureTUN)Tag()string{return "tun-in"}
type fixtureBox struct{native *NativeTun;owner *routerVPNNodeMTU}
func(b *fixtureBox)Inbound()*fixtureBox{return b}
func(*fixtureBox)RouterVPNStrategyDNSProofContext(context.Context)error{panic("heartbeat fixture has no selected DNS request")}
func fixtureInboundsContext(ctx context.Context,b *fixtureBox)([]fixtureInbound,error){return []fixtureInbound{fixtureTUN{}},ctx.Err()}
type fixturePhysical struct{}
func(*fixturePhysical)CurrentContext(ctx context.Context)error{return ctx.Err()}
func routerVPNDesktopPhysicalPathContext(ctx context.Context,b *fixtureBox)(string,error){return "original-path",ctx.Err()}
type routerVPNExternalFiles struct{root *os.Root;stopped atomic.Bool;published int}
func(f *routerVPNExternalFiles)stopRequested(string,string)bool{return f.stopped.Load()}
func(*routerVPNExternalFiles)read(string,int)([]byte,error){return nil,os.ErrNotExist}
func(f *routerVPNExternalFiles)publish(_ string,record routerVPNNodeMTURecord)error{f.published++;f.stopped.Store(true);return nil}
type routerVPNNodeMTURecord struct{Generation uint64;Request,Failure,NetworkReceipt string;Heartbeat int64}
type routerVPNNodeMTUCommand struct{Schema int;Session,Config,Request string;Generation uint64}
func routerVPNMTUStrict([]byte,any)bool{return false}
type routerVPNNodeMTUBox struct{instance *fixtureBox;tag string;physical *fixturePhysical}
type routerVPNNodeMTU struct{record routerVPNNodeMTURecord;native *NativeTun;guard func(context.Context)error;last error}
func newRouterVPNNodeMTUContext(ctx context.Context,b *routerVPNNodeMTUBox,_,_,_ string,guard func(context.Context)error)(*routerVPNNodeMTU,error){
 o:=&routerVPNNodeMTU{native:b.instance.native,guard:guard};b.instance.owner=o;return o,guard(ctx)
}
func(o *routerVPNNodeMTU)currentContext(ctx context.Context)error{return o.guard(ctx)}
func routerVPNConsumeImportedDNS(context.Context,*routerVPNExternalFiles,*routerVPNNodeMTU,*uint64,func(context.Context)error)error{return nil}
func(*routerVPNNodeMTU)expire(time.Time)error{return nil}
func(*routerVPNNodeMTU)command(routerVPNNodeMTUCommand)error{return errors.New("unexpected command")}
func(o *routerVPNNodeMTU)DesktopNetworkReceiptContext(ctx context.Context)(string,error){raw,err:=o.native.RouterVPNDesktopNetworkReceiptContext(ctx);o.last=err;return raw,err}
type NativeTun struct{options struct{FileDescriptor int;NetNs string;EXP_ExternalConfiguration bool};read func(context.Context)(string,error)}
func(t *NativeTun)routervpnObserveNetworkReceiptContext(ctx context.Context)(string,error){return t.read(ctx)}
'''

TESTS = r'''package heartbeat
import("context";"testing";"testing/synctest";"time")
type originalCallerKey struct{}
func TestActualHeartbeatContext(t *testing.T){
 for _,mode:=range []string{"live","shorter-parent","parent-stop","graph-stop","unowned-graph-stop","expired-read"}{t.Run(mode,func(t *testing.T){synctest.Test(t,func(t *testing.T){
  original:=context.WithValue(context.Background(),originalCallerKey{},"original-caller")
  parent,cancelParent:=context.WithCancel(original);defer cancelParent()
  if mode=="shorter-parent"{var stop context.CancelFunc;parent,stop=context.WithTimeout(parent,50*time.Millisecond);defer stop()}
  graph,cancelGraph:=context.WithCancel(context.Background());defer cancelGraph()
  files:=&routerVPNExternalFiles{};var entered context.Context;ready:=false
  native:=&NativeTun{read:func(ctx context.Context)(string,error){
   entered=ctx
   if !ready||ctx.Value(originalCallerKey{})!="original-caller"{t.Fatal("observation lost original caller/readiness")}
   deadline,ok:=ctx.Deadline();if !ok||time.Until(deadline)>2*time.Second{t.Fatal("observation lost two-second caller cap")}
   if mode=="shorter-parent"{prior,_:=parent.Deadline();if !deadline.Equal(prior){t.Fatal("earlier original deadline extended")}}
   switch mode{
   case "parent-stop":cancelParent();<-ctx.Done()
   case "graph-stop":files.stopped.Store(true);cancelGraph();<-ctx.Done()
   case "unowned-graph-stop":cancelGraph();<-ctx.Done()
   case "expired-read":<-ctx.Done();return "late-receipt",nil
   }
   return "original-receipt",ctx.Err()
  }}
  instance:=&fixtureBox{native:native}
  err:=routerVPNRunNodeMTULoop(parent,graph,files,instance,"session","config",nil,func(ctx context.Context)error{return ctx.Err()},func()error{ready=true;return nil})
  if entered==nil{t.Fatal("actual native receipt admission rejected heartbeat",instance.owner.last,err)}
  shouldFail:=mode=="unowned-graph-stop"||mode=="expired-read"
  if (err!=nil)!=shouldFail{t.Fatal("actual loop changed Stop/failure ownership",mode,err)}
  want:=0;if mode=="live"||mode=="shorter-parent"{want=1}
  if files.published!=want{t.Fatal("late or cancelled receipt published",mode,files.published)}
  if entered.Err()==nil{t.Fatal("heartbeat context not released after read")}
  if mode=="live"||mode=="shorter-parent"||mode=="expired-read"{if parent.Err()!=nil||graph.Err()!=nil{t.Fatal("receipt completion/expiry retired original lifetime")}}
 })})}
}
'''


def execute():
    loop = function((ROOT/'mobile/desktop/mtu_node.go.tmpl').read_text(), 'func routerVPNRunNodeMTULoop(')
    # Only native namespace/type aliases change; production control flow stays exact.
    for before, after in [('box.RouterVPNDesktopNodePhysical', 'fixturePhysical'), ('box.Box', 'fixtureBox'),
                          ('adapter.RouterVPNInboundsContext', 'fixtureInboundsContext'), ('adapter.Inbound', 'fixtureInbound')]:
        loop = loop.replace(before, after)
    admission = function((ROOT/'mobile/desktop/sing_tun_network.go.tmpl').read_text(),
                         'func (t *NativeTun) RouterVPNDesktopNetworkReceiptContext(')
    with tempfile.TemporaryDirectory(prefix='node-heartbeat-context-') as temporary:
        folder = Path(temporary)
        language = next(line for line in (ROOT/'go.mod').read_text().splitlines() if line.startswith('go '))
        (folder/'go.mod').write_text('module heartbeat\n\n'+language+'\n')
        (folder/'loop_test.go').write_text(TESTS)
        production = FIXTURE + '\n' + admission + '\n' + loop
        (folder/'loop.go').write_text(production)
        environment = dict(os.environ, GOWORK='off', GOFLAGS='')
        compiler = 'go'
        host_os, host_arch = subprocess.check_output([compiler,'env','GOHOSTOS','GOHOSTARCH'],env=environment,text=True).split()
        race = [] if (host_os,host_arch)==('windows','arm64') else ['-race']
        environment.update(GOOS=host_os,GOARCH=host_arch,CGO_ENABLED='1' if race else '0')
        command = [compiler,'test',*race,'-count=1','-timeout=30s','-v','.']
        subprocess.run(command,cwd=folder,env=environment,check=True,timeout=90)
        needle = 'context.WithTimeout(observe, 2*time.Second)'
        if production.count(needle)!=1:
            raise ValueError('Heartbeat original caller budget seam changed')
        (folder/'loop.go').write_text(production.replace(needle,'context.WithCancel(observe)',1))
        result = subprocess.run(command+['-run','^TestActualHeartbeatContext/live$'],cwd=folder,env=environment,
                                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=90)
        if result.returncode==0 or 'native receipt requires its operation deadline' not in result.stdout or '--- FAIL: TestActualHeartbeatContext/live ' not in result.stdout:
            raise ValueError('Original unbounded caller control missed exact native deadline failure:\n'+result.stdout)
        if any(marker in result.stdout for marker in ('panic:','DATA RACE','build failed','test timed out')):
            raise ValueError('Heartbeat causal control failed for infrastructure instead of deadline admission:\n'+result.stdout)
        print('Original no-deadline caller rejected by actual native receipt admission',flush=True)


if __name__=='__main__':
    execute()
