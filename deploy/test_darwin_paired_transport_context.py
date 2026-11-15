#!/usr/bin/env python3
"""Execute the actual Darwin HTTP/DNS context code with explicit native socket boundaries.

The HTTP transport and DNS byte exchange are real. The socket boundary is a
controlled pipe/held dial; this is not a PF, utun or encrypted-provider verdict.
"""
from pathlib import Path
import os, shutil, subprocess, tempfile
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'cmd/client/desktop_node_measurement_darwin.go'
PROOF=ROOT/'cmd/client/desktop_node_proof_darwin.go'
PRELUDE='''package main
import("context";"errors";"io";"net";"net/http";"net/netip";"strconv";"sync";"time";"syscall";"router-vpn/pairedprobe/dnsmeasure")
type desktopMacOSPairedNodeNativeMeasurement struct { ipv6 bool; reader int; dialFn func(context.Context,string,string)(net.Conn,error); currentFn func(context.Context)error; matchesFn func()bool }
func(m *desktopMacOSPairedNodeNativeMeasurement) Current(ctx context.Context)error{if m.currentFn!=nil{return m.currentFn(ctx)};return ctx.Err()}
func(m *desktopMacOSPairedNodeNativeMeasurement) MatchesOriginal()bool{if m.matchesFn!=nil{return m.matchesFn()};return true}
func(m *desktopMacOSPairedNodeNativeMeasurement) dial(ctx context.Context,n,a string)(net.Conn,error){if m.dialFn!=nil{return m.dialFn(ctx,n,a)};return m.nativeDial(ctx,n,a)}
func bindDesktopImportedMTUKernel(context.Context,string,uintptr,int)error{return nil}
type heldDialer struct{entered,exited chan struct{}}
func(d *heldDialer) DialContext(ctx context.Context,n,a string)(net.Conn,error){close(d.entered);<-ctx.Done();close(d.exited);return nil,ctx.Err()}
'''
TEST='''package main
import("context";"io";"net";"net/http";"testing";"time")
func wait(t *testing.T,c <-chan struct{},message string){t.Helper();select{case <-c:case <-time.After(300*time.Millisecond):t.Fatal(message)}}
func TestOriginalHTTPCallerJoinsDetachedDial(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 d:=&heldDialer{make(chan struct{}),make(chan struct{})}
 m:=&desktopMacOSPairedNodeNativeMeasurement{dialFn:d.DialContext}
 client,err:=m.HTTPClient(ctx,time.Second);if err!=nil{t.Fatal(err)};defer client.CloseIdleConnections()
 request,_:=http.NewRequestWithContext(ctx,"GET","http://192.0.2.1/",nil)
 done:=make(chan struct{});go func(){defer close(done);r,e:=client.Do(request);if r!=nil{r.Body.Close()};if e==nil{t.Error("canceled dial succeeded")}}()
 wait(t,d.entered,"real HTTP transport never dialed");cancel();wait(t,done,"HTTP worker did not join");wait(t,d.exited,"detached dial lost original caller")
}
func TestOriginalDNSCallerClosesHeldRead(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 client,server:=net.Pipe();defer client.Close();defer server.Close()
 entered:=make(chan struct{});closed:=make(chan struct{});done:=make(chan struct{})
 go func(){defer close(closed);query:=make([]byte,4096);if _,err:=server.Read(query);err!=nil{return};close(entered);_,_=io.Copy(io.Discard,server)}()
 m:=&desktopMacOSPairedNodeNativeMeasurement{dialFn:func(c context.Context,n,a string)(net.Conn,error){if n!="udp4"||a!=desktopMacOSPairedDNSInjection{t.Error("DNS changed original transport")};return client,nil}}
 go func(){defer close(done);if _,err:=m.lookup(ctx,"example.com");err==nil{t.Error("held DNS succeeded")}}()
 wait(t,entered,"DNS query never reached captured pipe");cancel();wait(t,done,"DNS read ignored original cancellation");wait(t,closed,"DNS socket not closed and joined")
}
func TestOriginalProofCallerJoinsDetachedDial(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 d:=&heldDialer{make(chan struct{}),make(chan struct{})};transport:=proofTransport(ctx,d);defer transport.CloseIdleConnections()
 client:=&http.Client{Transport:transport};request,_:=http.NewRequestWithContext(ctx,"GET","http://192.0.2.1:80/",nil)
 done:=make(chan struct{});go func(){defer close(done);r,e:=client.Do(request);if r!=nil{r.Body.Close()};if e==nil{t.Error("canceled proof succeeded")}}()
 wait(t,d.entered,"proof transport never dialed");cancel();wait(t,done,"proof HTTP worker retained");wait(t,d.exited,"proof dial lost original caller")
}
'''
def projection(source,proof):
    tail=source[source.index('const desktopMacOSPairedDNSInjection ='):]
    start=proof.index('\ttransport := &http.Transport',proof.index('func (h *desktopMacOSPairedNodeHost) proveReaderLocked'))
    stop=proof.index('\n\tdefer transport.CloseIdleConnections()',start)
    closure='func proofTransport(ctx context.Context,dialer *heldDialer)*http.Transport{seconds:=1;network:="tcp4";remote:=netip.MustParseAddrPort("192.0.2.1:80");\n'+proof[start:stop]+'\nreturn transport}\n'
    begin=source.index("func (m *desktopMacOSPairedNodeNativeMeasurement) currentBeforeHTTPIO(")
    stop=source.index("// This reserved address",begin)
    native=source[begin:stop].replace("NativeMeasurement) dial(","NativeMeasurement) nativeDial(",1)
    return PRELUDE+native+tail+'\n'+closure

def main():
    source,proof=SOURCE.read_text(),PROOF.read_text()
    controls=[('original',source,proof,None),
      ('detached-http',source.replace('call, ok := detached.Value(desktopMacOSPairedNodeRequestContextKey{}).(context.Context)','call, ok := detached, true',1),proof,'detached dial lost original caller'),
      ('held-dns',source.replace('stop := context.AfterFunc(ctx, closeConnection)','stop := func() bool { return false }',1),proof,'DNS read ignored original cancellation'),
      ('detached-proof',source,proof.replace('DialContext: func(_ context.Context, actualNetwork, address string)','DialContext: func(ctx context.Context, actualNetwork, address string)',1),'proof dial lost original caller')]
    with tempfile.TemporaryDirectory(prefix='paired-transport-context-') as directory:
        work=Path(directory);(work/'go.mod').write_text('module router-vpn/pairedprobe\n\ngo 1.25.0\n\nrequire router-vpn v0.0.0\nreplace router-vpn => '+str(ROOT)+'\n');(work/'dnsmeasure').mkdir()
        shutil.copyfile(ROOT/'internal/dnsmeasure/transport_bootstrap.go',work/'dnsmeasure/transport_bootstrap.go')
        wire=(ROOT/'internal/dnsmeasure/wire.go').read_text()
        (work/'dnsmeasure/wire_name.go').write_text('package dnsmeasure\nimport "errors"\n'+wire[wire.index('func wireName('):])
        (work/'probe_test.go').write_text(TEST)
        clock=(ROOT/'cmd/client/measurement_clock.go').read_text().split('// Keep ordinary display precision',1)[0]
        (work/'clock.go').write_text(clock)
        timing=(ROOT/'cmd/client/measurement_http_interval.go').read_text()
        (work/'timing.go').write_text(timing)
        shutil.copyfile(ROOT/'cmd/client/measurement_http_interval_test.go',work/'timing_test.go')
        (work/'timing_transport_test.go').write_text(TIMING_TEST)

        for name,s,p,witness in controls:
            if name!='original' and s==source and p==proof:raise ValueError('Original causal seam vanished: '+name)
            (work/'probe.go').write_text(projection(s,p))
            result=subprocess.run([os.environ.get('GO','go'),'test','-race','-p=1','-count=1','-timeout=10s','-v','.'],cwd=work,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
            print(name+': '+result.stdout,flush=True)
            if witness is None:
                if result.returncode or sum(line.startswith('--- PASS: Test') for line in result.stdout.splitlines())!=9:raise ValueError('Original actual transport controls failed')
            elif result.returncode==0 or witness not in result.stdout or '[build failed]' in result.stdout:raise ValueError('Mutant did not fail at original cancellation assertion: '+name)
        timing_controls=[
          ('omitted-final-current','err = body.owner.Current(body.caller)','err = nil','final native ownership check was omitted'),
          ('omitted-final-clock','_, clockErr := t.checkpointLocked(body.caller)','var clockErr error','post-body-clock'),
          ('guard-time-included','t.excluded += end - begin','t.excluded += 0 * (end - begin)','network interval or full original checks changed'),
          ('post-body-time-included','t.validated = true','t.completed = t.last; t.validated = true','network interval or full original checks changed')]
        (work/'probe.go').write_text(projection(source,proof))
        for name,before,after,witness in timing_controls:
            if timing.count(before)!=1:raise ValueError('Timing causal seam vanished: '+name)
            (work/'timing.go').write_text(timing.replace(before,after,1))
            result=subprocess.run([os.environ.get('GO','go'),'test','-race','-p=1','-count=1','-timeout=10s','-v','-run','Test(ClientHTTPInterval|OriginalMeasuredHTTP)', '.'],cwd=work,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=45)
            print(name+': '+result.stdout,flush=True)
            if result.returncode==0 or witness not in result.stdout or '[build failed]' in result.stdout or 'DATA RACE' in result.stdout:raise ValueError('Timing mutant failed outside its intended assertion: '+name)
    print('Paired transport: 9 actual source roots and 7 causal controls passed; native socket binding and Current explicitly modeled')
TIMING_TEST='''package main
import("context";"crypto/tls";"errors";"io";"net";"strings";"net/http";"net/http/httptest";"sync/atomic";"testing";"time")
func TestOriginalMeasuredHTTP(t *testing.T){
 for _,kind:=range []string{"timed","untimed","final-refusal","final-cancel","owner-replaced","early-close"}{t.Run(kind,func(t *testing.T){
  server:=httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Length","1");w.WriteHeader(200);w.(http.Flusher).Flush();time.Sleep(20*time.Millisecond);_,_=w.Write([]byte("x"))}))
  server.TLS=&tls.Config{GetConfigForClient:func(*tls.ClientHelloInfo)(*tls.Config,error){time.Sleep(15*time.Millisecond);return nil,nil}}
  server.StartTLS();defer server.Close()
  ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
  var checks atomic.Int32;var retired atomic.Bool
  m:=&desktopMacOSPairedNodeNativeMeasurement{matchesFn:func()bool{return !retired.Load()}}
  client,err:=m.HTTPClient(ctx,time.Second);if err!=nil{t.Fatal(err)};defer client.CloseIdleConnections()
  client.Transport.(*desktopMacOSPairedNodeRoundTripper).transport.TLSClientConfig=server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
  m.currentFn=func(context.Context)error{n:=checks.Add(1);time.Sleep(10*time.Millisecond);if n==4{switch kind{case "final-refusal":return errors.New("original Current refused");case "final-cancel":cancel();case "owner-replaced":retired.Store(true)}};return nil}
  request,_:=http.NewRequestWithContext(ctx,"GET",server.URL,nil)
  interval,err:=startClientMeasurementInterval();if err!=nil{t.Fatal(err)}
  if kind!="untimed"{request,interval=captureClientHTTPRequestInterval(request,interval)}
  start:=time.Now();response,err:=client.Do(request);if err!=nil{t.Fatal(err)}
  var body []byte;var readErr error
  if kind!="early-close"{body,readErr=io.ReadAll(response.Body)}
  _=response.Body.Close();elapsed,clockErr:=clientMeasurementMilliseconds(ctx,interval);wall:=float64(time.Since(start))/float64(time.Millisecond)
  if kind=="early-close"{if clockErr==nil||elapsed!=0{t.Fatal("early response close published a sample")};return}
  if checks.Load()!=4{t.Fatalf("final native ownership check was omitted: checks%d",checks.Load())}
  if kind!="timed"&&kind!="untimed"{if readErr==nil||clockErr==nil||elapsed!=0{t.Fatalf("invalid native proof published %v %v %v",elapsed,readErr,clockErr)};return}
  if readErr!=nil||clockErr!=nil||string(body)!="x"{t.Fatalf("real HTTP body failed: %q %v %v",body,readErr,clockErr)}
  if elapsed<30{t.Fatalf("legitimate TLS/body transfer time removed: %v",elapsed)}
  if kind=="timed"&&wall-elapsed<35{t.Fatalf("guard duration remained in network sample: wall%v sample%v",wall,elapsed)}
  if kind=="untimed"&&wall-elapsed>5{t.Fatalf("untimed transport changed existing interval: wall%v sample%v",wall,elapsed)}
 })}
}

func TestOriginalMeasuredDNS(t *testing.T){
 for _,kind:=range []string{"original","guard-during-query"}{t.Run(kind,func(t *testing.T){
  ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
  request,_:=http.NewRequestWithContext(ctx,"GET","http://captured.example/",nil)
  interval,err:=startClientMeasurementInterval();if err!=nil{t.Fatal(err)}
  request,interval=captureClientHTTPRequestInterval(request,interval);ctx=request.Context();timing:=clientHTTPRequestTiming(ctx)
  var checks atomic.Int32
  m:=&desktopMacOSPairedNodeNativeMeasurement{currentFn:func(context.Context)error{checks.Add(1);time.Sleep(10*time.Millisecond);return nil}}
  if err:=timing.claim(m);err!=nil{t.Fatal(err)}
  joined:=make(chan struct{})
  m.dialFn=func(call context.Context,network,address string)(net.Conn,error){
   if network!="udp4"||address!=desktopMacOSPairedDNSInjection{t.Fatal("selected DNS changed original injection destination")}
   if err:=m.currentBeforeHTTPIO(call);err!=nil{return nil,err}
   left,right:=net.Pipe()
   go func(){defer close(joined);defer right.Close();query:=make([]byte,4096);n,e:=right.Read(query);if e!=nil{return};query=query[:n]
    if kind=="guard-during-query"{if timing.currentBeforeIO(call,m)==nil{t.Error("active DNS exchange allowed guard exclusion")}}
    time.Sleep(15*time.Millisecond)
    reply:=append([]byte(nil),query...);reply[2]=0x81;reply[3]=0x80;reply[7]=1
    reply=append(reply,0xc0,0x0c,0,1,0,1,0,0,0,1,0,4,192,0,2,33)
    _,_=right.Write(reply)
   }()
   if err:=m.currentBeforeHTTPIO(call);err!=nil{left.Close();return nil,err};return left,nil
  }
  start:=time.Now();answers,err:=m.lookup(ctx,"captured.example");<-joined
  if kind!="original"{if err==nil{t.Fatal("overlapping DNS timing survived original lookup")};return}
  if err!=nil||len(answers)!=1||answers[0].String()!="192.0.2.33"{t.Fatalf("original DNS byte exchange failed %v %v",answers,err)}
  if err=timing.beginHTTP(m);err!=nil{t.Fatal(err)}
  body,err:=timing.responseBody(ctx,m,io.NopCloser(strings.NewReader("x")));if err!=nil{t.Fatal(err)}
  if _,err=io.ReadAll(body);err!=nil{t.Fatal(err)};body.Close()
  elapsed,err:=clientMeasurementMilliseconds(ctx,interval);wall:=float64(time.Since(start))/float64(time.Millisecond)
  if err!=nil||checks.Load()!=4||elapsed<15||wall-elapsed<35{t.Fatalf("selected DNS transfer or original checks lost: elapsed%v wall%v checks%d err%v",elapsed,wall,checks.Load(),err)}
 })}
}
'''
if __name__=='__main__':main()
