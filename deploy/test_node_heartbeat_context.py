#!/usr/bin/env python3
"""Run the shipping heartbeat loop and native deadline admission portably.

Box, physical path, file publication and OS readback are explicit fixtures.
The loop, OpenVPN observation and NativeTun receipt admission are extracted
production functions; this does not establish privileged TUN or kernel acceptance.
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
import ("context";"errors";"os";"sync";"sync/atomic";"time")
var routerVPNExternalFailure=errors.New("captured observation failed")
var ErrNetworkReceiptUnavailable=errors.New("unused fixture capability")
type fixtureInbound interface{Type()string;Tag()string}
type fixtureTUN struct{}
func(fixtureTUN)Type()string{return "tun"}
func(fixtureTUN)Tag()string{return "tun-in"}
type fixtureBox struct{native *NativeTun;owner *routerVPNNodeMTU;openVPN *routerVPNImportedOpenVPN}
func(b *fixtureBox)Inbound()*fixtureBox{return b}
func(*fixtureBox)RouterVPNStrategyDNSProofContext(context.Context)error{panic("heartbeat fixture has no selected DNS request")}
func fixtureInboundsContext(ctx context.Context,b *fixtureBox)([]fixtureInbound,error){return []fixtureInbound{fixtureTUN{}},ctx.Err()}
type fixturePhysical struct{}
func(*fixturePhysical)CurrentContext(ctx context.Context)error{return ctx.Err()}
func routerVPNDesktopPhysicalPathContext(ctx context.Context,b *fixtureBox)(string,error){return "original-path",ctx.Err()}
type routerVPNExternalFiles struct{root *os.Root;stopped atomic.Bool;published int;publishHook func(routerVPNNodeMTURecord);consume func(context.Context,*uint64)error}
func(f *routerVPNExternalFiles)stopRequested(string,string)bool{return f.stopped.Load()}
func(*routerVPNExternalFiles)read(name string,_ int)([]byte,error){if name=="sing-box.json"{return []byte(`{}`),nil};return nil,os.ErrNotExist}
func(f *routerVPNExternalFiles)publish(_ string,record routerVPNNodeMTURecord)error{f.published++;if f.publishHook!=nil{f.publishHook(record)}else{f.stopped.Store(true)};return nil}
type routerVPNNodeMTURecord struct{Generation uint64;Request,Failure,NetworkReceipt string;Heartbeat int64;OpenVPN fixtureOpenVPNState}
type routerVPNNodeMTUCommand struct{Schema int;Session,Config,Request string;Generation uint64}
func routerVPNMTUStrict([]byte,any)bool{return false}
type routerVPNNodeMTUBox struct{instance *fixtureBox;tag string;physical *fixturePhysical}
type routerVPNNodeMTU struct{record routerVPNNodeMTURecord;native *NativeTun;guard,guardContext func(context.Context)error;last error;openVPN *routerVPNImportedOpenVPN}
func newRouterVPNNodeMTUContext(ctx context.Context,b *routerVPNNodeMTUBox,_,_,_ string,guard func(context.Context)error)(*routerVPNNodeMTU,error){
 o:=&routerVPNNodeMTU{native:b.instance.native,guard:guard};b.instance.owner=o;return o,guard(ctx)
}
func(o *routerVPNNodeMTU)currentContext(ctx context.Context)error{if o.guardContext!=nil{return o.guardContext(ctx)};return o.guard(ctx)}
type fixtureOpenVPNRemote struct{Remote string;Generation uint64}
type fixtureOpenVPNState struct{Remote fixtureOpenVPNRemote;MTU uint32}
func(s fixtureOpenVPNState)Validate()error{if s.Remote.Remote==""||s.Remote.Generation==0||s.MTU<1280{return routerVPNExternalFailure};return nil}
var errFixtureRemotePending=errors.New("original native endpoint not yet ready")
type routerVPNImportedOpenVPN struct{mu sync.Mutex;tun *routerVPNNodeMTU;read func(context.Context)(fixtureOpenVPNState,error);remote string;minimum uint32;state *fixtureOpenVPNState;retired error;observedAt atomic.Pointer[time.Time]}
func newRouterVPNImportedOpenVPN(ctx context.Context,b *fixtureBox,_ []byte,tun *routerVPNNodeMTU)(*routerVPNImportedOpenVPN,error){if b.openVPN!=nil{b.openVPN.tun=tun};return b.openVPN,ctx.Err()}
func(*routerVPNImportedOpenVPN)pinned(ctx context.Context)error{return ctx.Err()}
func(*routerVPNImportedOpenVPN)pinnedMTU(ctx context.Context)error{return ctx.Err()}
func(*routerVPNImportedOpenVPN)pinnedContext(ctx context.Context,_ bool)error{return ctx.Err()}
func routerVPNConsumeImportedDNS(ctx context.Context,f *routerVPNExternalFiles,_ *routerVPNNodeMTU,generation *uint64,_ func(context.Context)error,_ ...*routerVPNImportedOpenVPN)error{if f.consume!=nil{return f.consume(ctx,generation)};return nil}
func(*routerVPNNodeMTU)expire(time.Time)error{return nil}
func(*routerVPNNodeMTU)command(routerVPNNodeMTUCommand)error{return errors.New("unexpected command")}
func(o *routerVPNNodeMTU)DesktopNetworkReceiptContext(ctx context.Context)(string,error){raw,err:=o.native.RouterVPNDesktopNetworkReceiptContext(ctx);o.last=err;return raw,err}
type NativeTun struct{options struct{FileDescriptor int;NetNs string;EXP_ExternalConfiguration bool};read func(context.Context)(string,error)}
func(t *NativeTun)routervpnObserveNetworkReceiptContext(ctx context.Context)(string,error){return t.read(ctx)}
'''

TESTS = r'''package heartbeat
import("context";"errors";"testing";"testing/synctest";"time")
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

func TestActualOpenVPNHeartbeatFreshness(t *testing.T){
 for _,mode:=range []string{"native-held","observer-held","stale-native","tuple-change","parent-stop","graph-stop","query-expiry"}{t.Run(mode,func(t *testing.T){synctest.Test(t,func(t *testing.T){
  parent,cancelParent:=context.WithCancel(context.WithValue(context.Background(),originalCallerKey{},"original-caller"));defer cancelParent()
  graph,cancelGraph:=context.WithCancel(context.Background());defer cancelGraph()
  state:=fixtureOpenVPNState{Remote:fixtureOpenVPNRemote{Remote:"original-entry",Generation:7},MTU:1500}
  owner:=&routerVPNImportedOpenVPN{remote:"original-entry",minimum:1420}
  files:=&routerVPNExternalFiles{}
  afterFirst,refreshed,queryInProgress,queryConsumed:=false,false,false,false
  postNetworkRead:=false
  misses:=0;var firstHeartbeat int64;var firstObserved *time.Time;var observerReleased chan struct{}
  defer func(){if observerReleased!=nil{<-observerReleased}}()
  owner.read=func(ctx context.Context)(fixtureOpenVPNState,error){
   if ctx.Value(originalCallerKey{})!="original-caller"{t.Fatal("periodic observation lost original caller")}
   afterNetwork:=postNetworkRead;postNetworkRead=false
   if !afterFirst{return state,ctx.Err()}
   deadline,ok:=ctx.Deadline();bound:=250*time.Millisecond;if queryInProgress{bound=300*time.Millisecond};if afterNetwork{bound=2*time.Second};if !ok||time.Until(deadline)>bound{t.Fatal("periodic observation lost bounded refresh admission")}
   switch mode{
   case "native-held":if misses==0{misses++;<-ctx.Done();return fixtureOpenVPNState{},ctx.Err()};refreshed=true
   case "observer-held":refreshed=true
   case "stale-native":misses++;<-ctx.Done();return fixtureOpenVPNState{},ctx.Err()
   case "tuple-change":next:=state;next.Remote.Generation++;return next,nil
   case "parent-stop":cancelParent();<-ctx.Done();return fixtureOpenVPNState{},ctx.Err()
   case "graph-stop":cancelGraph();<-ctx.Done();return fixtureOpenVPNState{},ctx.Err()
   case "query-expiry":
    if queryInProgress{<-ctx.Done();return fixtureOpenVPNState{},ctx.Err()}
    if queryConsumed{if misses==0{misses++;<-ctx.Done();return fixtureOpenVPNState{},ctx.Err()};refreshed=true}
   }
   return state,ctx.Err()
  }
  files.consume=func(ctx context.Context,generation *uint64)error{
   if mode!="query-expiry"||!afterFirst||queryConsumed{return nil}
   queryInProgress=true
   query,stop:=context.WithTimeout(ctx,300*time.Millisecond)
   _,err:=owner.observe(query);stop();queryInProgress=false
   if !errors.Is(err,context.DeadlineExceeded){t.Fatal("query expiry not owned",err)}
   queryConsumed=true;(*generation)++;return nil
  }
  files.publishHook=func(record routerVPNNodeMTURecord){
   if record.OpenVPN!=state{t.Fatal("heartbeat refreshed without a new original-tuple observation")}
   if !afterFirst{
    afterFirst=true;firstHeartbeat=record.Heartbeat;firstObserved=owner.observedAt.Load()
    if firstObserved==nil{t.Fatal("heartbeat has no successful original-tuple observation")}
    if mode=="observer-held"{
     owner.mu.Lock()
     observerReleased=make(chan struct{})
     go func(){defer close(observerReleased);time.Sleep(300*time.Millisecond);if files.published!=1||parent.Err()!=nil||graph.Err()!=nil{t.Error("held observer refreshed evidence or ended healthy lifetime")};owner.mu.Unlock()}()
    }
    return
   }
   if !refreshed||record.Heartbeat<=firstHeartbeat{t.Fatal("heartbeat refreshed without a new original-tuple observation")}
   files.stopped.Store(true)
  }
  native:=&NativeTun{read:func(ctx context.Context)(string,error){postNetworkRead=true;return "original-receipt",ctx.Err()}}
  instance:=&fixtureBox{native:native,openVPN:owner}
  err:=routerVPNRunNodeMTULoop(parent,graph,files,instance,"session","config",nil,func(ctx context.Context)error{return ctx.Err()},func()error{return nil})
  recovering:=mode=="native-held"||mode=="observer-held"||mode=="query-expiry"
  if recovering{
   if err!=nil||files.published!=2||owner.retired!=nil||parent.Err()!=nil||graph.Err()!=nil{t.Fatal("periodic expiry retired healthy child instead of recovering without stale evidence",mode,err,files.published)}
  }else{
   if files.published!=1{t.Fatal("failed original owner refreshed its heartbeat",mode,files.published)}
   if mode=="parent-stop"{if err!=nil{t.Fatal("owned parent cancellation did not join",err)}}else if err==nil{t.Fatal("unproved original owner remained alive",mode)}
  }
  if owner.state==nil||*owner.state!=state{t.Fatal("periodic observation recaptured the packet tuple")}
  if mode=="stale-native"{
   if time.Since(*firstObserved)!=2*time.Second||owner.observedAt.Load()!=firstObserved{t.Fatal("periodic expiry extended the original two-second freshness",time.Since(*firstObserved))}
  }
  if mode=="tuple-change"&&owner.retired==nil{t.Fatal("true generation loss was treated as a busy observation")}
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
    source = (ROOT/'mobile/desktop/node_imported_openvpn_observation.go.tmpl').read_text()
    observations = '\n'.join(function(source, 'func (owner *routerVPNImportedOpenVPN) '+name+'(')
                             for name in ('observe', 'observeMTU', 'observeContext', 'healthy', 'refresh', 'await'))
    observations = observations.replace('nativeopenvpn.PacketObservation', 'fixtureOpenVPNState').replace(
        'nativeopenvpn.ErrRemotePending', 'errFixtureRemotePending').replace('mobilemtu.LockContext', 'LockContext')
    lock = function((ROOT/'internal/mobilemtu/context.go').read_text(), 'func LockContext(')
    with tempfile.TemporaryDirectory(prefix='node-heartbeat-context-') as temporary:
        folder = Path(temporary)
        language = next(line for line in (ROOT/'go.mod').read_text().splitlines() if line.startswith('go '))
        (folder/'go.mod').write_text('module heartbeat\n\n'+language+'\n')
        (folder/'loop_test.go').write_text(TESTS)
        production = FIXTURE + '\n' + lock + '\n' + observations + '\n' + admission + '\n' + loop
        (folder/'loop.go').write_text(production)
        environment = dict(os.environ, GOWORK='off', GOFLAGS='')
        compiler = 'go'
        host_os, host_arch = subprocess.check_output([compiler,'env','GOHOSTOS','GOHOSTARCH'],env=environment,text=True).split()
        race = [] if (host_os,host_arch)==('windows','arm64') else ['-race']
        environment.update(GOOS=host_os,GOARCH=host_arch,CGO_ENABLED='1' if race else '0')
        command = [compiler,'test',*race,'-count=1','-timeout=30s','-v','.']
        subprocess.run(command,cwd=folder,env=environment,check=True,timeout=90)
        needle = 'heartbeatContext, stopHeartbeat := context.WithTimeout(observe, 2*time.Second)'
        if production.count(needle)!=1:
            raise ValueError('Heartbeat original caller budget seam changed')
        (folder/'loop.go').write_text(production.replace(needle,'heartbeatContext, stopHeartbeat := context.WithCancel(observe)',1))
        result = subprocess.run(command+['-run','^TestActualHeartbeatContext/live$'],cwd=folder,env=environment,
                                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=90)
        if result.returncode==0 or 'native receipt requires its operation deadline' not in result.stdout or '--- FAIL: TestActualHeartbeatContext/live ' not in result.stdout:
            raise ValueError('Original unbounded caller control missed exact native deadline failure:\n'+result.stdout)
        if any(marker in result.stdout for marker in ('panic:','DATA RACE','build failed','test timed out')):
            raise ValueError('Heartbeat causal control failed for infrastructure instead of deadline admission:\n'+result.stdout)
        print('Original no-deadline caller rejected by actual native receipt admission',flush=True)
        controls = [
            ('terminal periodic expiry',
             'if observed != nil && time.Since(*observed) < 2*time.Second {\n\t\t\treturn false, nil',
             'if observed != nil && time.Since(*observed) < 2*time.Second {\n\t\t\treturn false, ctx.Err()',
             'native-held|observer-held',
             'periodic expiry retired healthy child instead of recovering without stale evidence'),
            ('stale observation publication', 'if !fresh {', 'if !fresh && false {',
             'native-held', 'heartbeat refreshed without a new original-tuple observation'),
            ('missing post-query observation',
             'if openVPN != nil && dnsGeneration != previousDNSGeneration {',
             'if openVPN != nil && dnsGeneration != previousDNSGeneration && false {',
             'query-expiry', 'periodic expiry retired healthy child instead of recovering without stale evidence'),
            ('extended original freshness',
             'observed.Add(2*time.Second).Before(limit) {',
             'observed.Add(2*time.Second).Before(limit) && false {',
             'stale-native', 'periodic expiry extended the original two-second freshness'),
        ]
        for label, before, after, cases, reason in controls:
            if production.count(before) != 1:
                raise ValueError(label+' causal control seam changed')
            changed = production.replace(before, after, 1)
            if label == 'stale observation publication':
                # The additional post-network read independently blocks stale
                # publication. Remove both protections for this same negative
                # control; neither a missing first read nor a missing second
                # read alone can fabricate a fresh original-tuple receipt.
                terminal = 'next.OpenVPN, err = openVPN.observeMTU(heartbeatContext)'
                if changed.count(terminal) != 1:
                    raise ValueError('Original post-network OpenVPN observation seam changed')
                changed = changed.replace(terminal, 'next.OpenVPN = fixtureOpenVPNState{}', 1)
            (folder/'loop.go').write_text(changed)
            result = subprocess.run(command+['-run','^TestActualOpenVPNHeartbeatFreshness/('+cases+')$'],
                                    cwd=folder,env=environment,stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,text=True,timeout=90)
            if result.returncode == 0 or reason not in result.stdout or '--- FAIL: TestActualOpenVPNHeartbeatFreshness/' not in result.stdout:
                raise ValueError(label+' causal control missed its actual loop failure:\n'+result.stdout)
            if any(marker in result.stdout for marker in ('panic:','DATA RACE','build failed','test timed out')):
                raise ValueError(label+' causal control failed for infrastructure:\n'+result.stdout)
            print('Actual enclosing loop rejected '+label,flush=True)


if __name__=='__main__':
    execute()
