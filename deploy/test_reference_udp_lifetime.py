#!/usr/bin/env python3
"""Execute the actual reference UDP handler/ownership with real loopback packets.

A private short inactivity budget accelerates causal checks; the original native
entry point must still pass exactly30 seconds. This is not encrypted peer proof.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = '''package referenceprobe
import("context";"errors";"io";"net";"net/netip";"sync";"time"
 "github.com/sagernet/sing/common/buf"
 M "github.com/sagernet/sing/common/metadata"
 N "github.com/sagernet/sing/common/network")
'''
TEST = r'''package referenceprobe
import("context";"errors";"fmt";"net";"sync";"sync/atomic";"testing";"time"
 "github.com/sagernet/sing/common/buf"
 M "github.com/sagernet/sing/common/metadata")
var injected = errors.New("original packet boundary refused")
type packets struct {
 *net.UDPConn
 destination M.Socksaddr
 mu sync.Mutex
 peer *net.UDPAddr
 deadlines atomic.Int32
 deadline atomic.Int64
 failDeadline int32
 failWrite bool
}
func(c *packets)ReadPacket(b *buf.Buffer)(M.Socksaddr,error){
 data:=make([]byte,65535);n,p,e:=c.ReadFromUDP(data);if e!=nil{return M.Socksaddr{},e}
 c.mu.Lock();if c.peer!=nil&&c.peer.String()!=p.String(){c.mu.Unlock();return M.Socksaddr{},errors.New("foreign actual sender")};c.peer=p;c.mu.Unlock()
 _,e=b.Write(data[:n]);return c.destination,e
}
func(c *packets)WritePacket(b *buf.Buffer,d M.Socksaddr)error{
 defer b.Release();if c.failWrite{return injected};if d!=c.destination{return errors.New("changed reply destination")}
 c.mu.Lock();p:=c.peer;c.mu.Unlock();if p==nil{return errors.New("no original peer")};_,e:=c.WriteToUDP(b.Bytes(),p);return e
}
// Match the pinned actual gVisor udpNatConn capability, not net.UDPConn's.
func(c *packets)SetDeadline(time.Time)error{return os.ErrInvalid}
func(c *packets)SetWriteDeadline(time.Time)error{return os.ErrInvalid}
func(c *packets)SetReadDeadline(d time.Time)error{c.deadline.Store(d.UnixNano());if n:=c.deadlines.Add(1);c.failDeadline>0&&n>=c.failDeadline{return injected};return c.UDPConn.SetReadDeadline(d)}
type fixture struct{h *desktopReferenceHandler;c *packets;client,backend *net.UDPConn;done chan error;backendDone chan struct{};count atomic.Int32;tupleMu sync.Mutex;tuple string}
func start(t *testing.T,behavior string,deadline int32,write,wrong bool,idle time.Duration)*fixture{
 t.Helper();listen:=func()*net.UDPConn{c,e:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)});if e!=nil{t.Fatal(e)};return c}
 server,backend:=listen(),listen();client,e:=net.DialUDP("udp4",nil,server.LocalAddr().(*net.UDPAddr));if e!=nil{t.Fatal(e)}
 ctx,cancel:=context.WithCancel(context.Background());destination:=M.ParseSocksaddr("192.0.2.19:5519")
 h:=&desktopReferenceHandler{ctx:ctx,cancel:cancel,rules:map[string]desktopReferenceRule{"udp/"+destination.String():{Network:"udp",Target:backend.LocalAddr().String()}},owned:map[io.Closer]bool{}}
 c:=&packets{UDPConn:server,destination:destination,failDeadline:deadline,failWrite:write};if wrong{c.destination=M.ParseSocksaddr("192.0.2.20:5519")}
 f:=&fixture{h:h,c:c,client:client,backend:backend,done:make(chan error,1),backendDone:make(chan struct{})}
 go func(){defer close(f.backendDone);data:=make([]byte,65535);for{n,p,e:=backend.ReadFromUDP(data);if e!=nil{return};f.tupleMu.Lock();if f.tuple!=""&&f.tuple!=p.String(){f.tuple="CHANGED"}else{f.tuple=p.String()};f.tupleMu.Unlock();f.count.Add(1)
  if behavior=="echo"{_,_=backend.WriteToUDP(data[:n],p)}
  if behavior=="push"{for i:=0;i<24;i++{if _,e:=backend.WriteToUDP([]byte("push"),p);e!=nil{return};time.Sleep(50*time.Millisecond)};return}
 }}()
 if idle==30*time.Second{h.NewPacketConnectionEx(ctx,c,M.Socksaddr{},destination,func(e error){f.done<-e})}else{h.newPacketConnectionIdle(ctx,c,M.Socksaddr{},destination,func(e error){f.done<-e},idle)}
 t.Cleanup(func(){f.close(t);_ = client.Close();_ = backend.Close();select{case <-f.backendDone:case <-time.After(2*time.Second):t.Error("backend did not join")}})
 return f
}
func(f *fixture)close(t *testing.T){t.Helper();joined:=make(chan struct{});go func(){f.h.close();close(joined)}();select{case <-joined:case <-time.After(2*time.Second):t.Fatal("original owner Close failed to join")};f.h.mu.Lock();remaining:=len(f.h.owned);closed:=f.h.closed;f.h.mu.Unlock();if remaining!=0||!closed{t.Fatal("original owner retained captured sockets")}}
func(f *fixture)result(t *testing.T)error{t.Helper();select{case e:=<-f.done:return e;case <-time.After(2*time.Second):t.Fatal("original association failed to retire");return nil}}
func TestReferenceUDPActiveOriginalAssociation(t *testing.T){
 for _,mode:=range []string{"echo","send","push"}{t.Run(mode,func(t *testing.T){
  f:=start(t,mode,0,false,false,500*time.Millisecond);begin:=time.Now()
  for i:=0;i<24;i++{if mode!="push"||i==0{if _,e:=f.client.Write([]byte(fmt.Sprint(i)));e!=nil{t.Fatal("active original association expired",e)}}
   if mode!="send"{_ = f.client.SetReadDeadline(time.Now().Add(time.Second));b:=make([]byte,30);if _,e:=f.client.Read(b);e!=nil{t.Fatal("active original association expired",e)}}
   if mode!="push"{time.Sleep(50*time.Millisecond)}
   select{case e:=<-f.done:t.Fatal("active original association expired",e);default:}
  }
  if time.Since(begin)<time.Second{t.Fatal("did not cross original inactivity budget twice")}
  f.tupleMu.Lock();tuple:=f.tuple;f.tupleMu.Unlock();if tuple==""||tuple=="CHANGED"{t.Fatal("active traffic replaced original upstream tuple")}
  if mode=="send"&&f.count.Load()!=24{t.Fatal("outgoing traffic did not retain original association")}
  f.close(t);if f.result(t)==nil{t.Fatal("owner close reported successful live association")}
 })}
}
func TestReferenceUDPIdleAndClose(t *testing.T){
 for _,mode:=range []string{"idle","owner-close"}{t.Run(mode,func(t *testing.T){f:=start(t,"send",0,false,false,200*time.Millisecond);if _,e:=f.client.Write([]byte("start"));e!=nil{t.Fatal(e)}
  if mode=="owner-close"{f.close(t)};e:=f.result(t);if e==nil{t.Fatal("retired association lost failure")};if mode=="idle"{if !errors.Is(e,os.ErrDeadlineExceeded){t.Fatal("idle association did not preserve timeout",e)}};f.close(t)
 })}
}
func TestReferenceUDPRefusesOriginalBoundaryFailures(t *testing.T){
 for _,name:=range []string{"initial-deadline","refresh-deadline","write","destination"}{t.Run(name,func(t *testing.T){deadline:=int32(0);if name=="initial-deadline"{deadline=1};if name=="refresh-deadline"{deadline=2};f:=start(t,"echo",deadline,name=="write",name=="destination",500*time.Millisecond)
  if _,e:=f.client.Write([]byte("original"));e!=nil{t.Fatal(e)};e:=f.result(t)
  if name=="destination"{if e==nil||!strings.Contains(e.Error(),"reference packet destination changed"){t.Fatal("changed destination was not refused",e)};if f.count.Load()!=0{t.Fatal("changed destination reached upstream")}}else if !errors.Is(e,injected){t.Fatal("original boundary error was lost",e)};f.close(t)
 })}
}
func TestReferenceUDPPrivateBudgetCannotWidenDefault(t *testing.T){
 f:=start(t,"echo",0,false,false,30*time.Second);until:=time.Now().Add(time.Second);for f.c.deadline.Load()==0&&time.Now().Before(until){time.Sleep(time.Millisecond)}
 remaining:=time.Until(time.Unix(0,f.c.deadline.Load()));if remaining<29*time.Second||remaining>30*time.Second{t.Fatal("actual exported caller changed original30s inactivity bound",remaining)};f.close(t);if f.result(t)==nil{t.Fatal("default association did not join original close")}
 for _,budget:=range []time.Duration{0,-1,31*time.Second}{f:=start(t,"echo",0,false,false,budget);if e:=f.result(t);e==nil{t.Fatal("private budget widened reference lifetime")};f.close(t)}}
'''.replace('"fmt";', '"fmt";"io";"os";"strings";')


def sources(root):
    text = (root/'mobile/amnezia/desktop_reference_test.go.tmpl').read_text()
    def part(begin, end):
        assert text.count(begin) == text.count(end) == 1, 'actual reference extraction boundary changed'
        return text[text.index(begin):text.index(end)]
    rule = part('type desktopReferenceRule struct {', 'type desktopReferenceConfiguration struct {')
    owner = part('type desktopReferenceHandler struct {', 'func (h *desktopReferenceHandler) NewConnectionEx(')
    udp = part('func (h *desktopReferenceHandler) NewPacketConnectionEx(', '\ntype desktopAWGReference')
    assert re.search(r'h\.newPacketConnectionIdle\(ctx, c, source, destination, done, 30\s*\*\s*time.Second\)', udp), 'original UDP default is not30seconds'
    return HEADER + rule + owner + udp


def execute(root=ROOT, mutations=True):
    go = shutil.which('go')
    if not go:
        raise RuntimeError('Go is required for the actual reference UDP lifetime gate')
    original = sources(root)
    # JudgeFlow/NewDNSPacket are actual unrelated methods; use their real tun
    # types by omitting those two methods, not substituting owner behavior.
    begin = original.index('func (h *desktopReferenceHandler) JudgeFlow(')
    end = original.index('func (h *desktopReferenceHandler) adopt(', begin)
    original = original[:begin] + original[end:]
    original = original.replace(';"net/netip"', '')
    variants = [('baseline', original, None)]
    if mutations:
        anchor = 'deadline := time.Now().Add(idle)'
        assert original.count(anchor) == 1
        absolute = original.replace('var activity sync.Mutex', 'var activity sync.Mutex\n absolute := time.Now().Add(idle)').replace(anchor, 'deadline := absolute')
        destination = 'err == nil && address != destination'
        assert original.count(destination) == 1
        variants += [('absolute-deadline', absolute, 'active original association expired'),
                     ('foreign-destination', original.replace(destination, 'false'), 'changed destination was not refused'),
                     ('unsupported-packet-deadline', original.replace('err := c.SetReadDeadline(deadline)', 'err := c.SetDeadline(deadline)'), 'active original association expired'),
                     ('deadline-error-omitted', original.replace('err := c.SetReadDeadline(deadline)', '_ = c.SetReadDeadline(deadline)\n var err error'), 'original boundary error was lost')]
    with tempfile.TemporaryDirectory(prefix='reference-udp-lifetime-') as name:
        folder = Path(name)
        (folder/'go.mod').write_text('module referenceprobe\n\ngo 1.25.0\nrequire github.com/sagernet/sing v0.9.4\n')
        (folder/'reference_test.go').write_text(TEST)
        env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='', GOMAXPROCS='1')
        for label, source, witness in variants:
            (folder/'reference.go').write_text(source)
            result = subprocess.run([go,'test','-race','-p=1','-mod=mod','-v','-count=1','-timeout=25s','.'],cwd=folder,env=env,text=True,capture_output=True,timeout=120)
            output = result.stdout+result.stderr
            if witness:
                if result.returncode != 1 or witness not in output or re.search(r'panic:|fatal error:|WARNING: DATA RACE|\[build failed\]',output):
                    raise AssertionError(label+': intended actual-handler refusal absent\n'+output)
            elif result.returncode != 0 or len(re.findall(r'^--- PASS: TestReferenceUDP', output, re.M)) != 4:
                raise AssertionError('actual UDP reference failed\n'+output)
            print('Reference UDP lifetime '+label+' verified\n'+output,flush=True)

if __name__ == '__main__':
    execute()
