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
import("context";"errors";"io";"net";"net/http";"net/netip";"strconv";"sync";"time";"pairedprobe/dnsmeasure")
type desktopMacOSPairedNodeNativeMeasurement struct { ipv6 bool; dialFn func(context.Context,string,string)(net.Conn,error) }
func(m *desktopMacOSPairedNodeNativeMeasurement) Current(ctx context.Context)error{return ctx.Err()}
func(m *desktopMacOSPairedNodeNativeMeasurement) MatchesOriginal()bool{return true}
func(m *desktopMacOSPairedNodeNativeMeasurement) dial(ctx context.Context,n,a string)(net.Conn,error){return m.dialFn(ctx,n,a)}
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
    return PRELUDE+tail+'\n'+closure

def main():
    source,proof=SOURCE.read_text(),PROOF.read_text()
    controls=[('original',source,proof,None),
      ('detached-http',source.replace('call, ok := detached.Value(desktopMacOSPairedNodeRequestContextKey{}).(context.Context)','call, ok := detached, true',1),proof,'detached dial lost original caller'),
      ('held-dns',source.replace('stop := context.AfterFunc(ctx, closeConnection)','stop := func() bool { return false }',1),proof,'DNS read ignored original cancellation'),
      ('detached-proof',source,proof.replace('DialContext: func(_ context.Context, actualNetwork, address string)','DialContext: func(ctx context.Context, actualNetwork, address string)',1),'proof dial lost original caller')]
    with tempfile.TemporaryDirectory(prefix='paired-transport-context-') as directory:
        work=Path(directory);(work/'go.mod').write_text('module pairedprobe\n\ngo 1.25.0\n');(work/'dnsmeasure').mkdir()
        shutil.copyfile(ROOT/'internal/dnsmeasure/transport_bootstrap.go',work/'dnsmeasure/transport_bootstrap.go')
        wire=(ROOT/'internal/dnsmeasure/wire.go').read_text()
        (work/'dnsmeasure/wire_name.go').write_text('package dnsmeasure\nimport "errors"\n'+wire[wire.index('func wireName('):])
        (work/'probe_test.go').write_text(TEST)
        for name,s,p,witness in controls:
            if name!='original' and s==source and p==proof:raise ValueError('Original causal seam vanished: '+name)
            (work/'probe.go').write_text(projection(s,p))
            result=subprocess.run([os.environ.get('GO','go'),'test','-count=1','-timeout=10s','-v','.'],cwd=work,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
            print(name+': '+result.stdout,flush=True)
            if witness is None:
                if result.returncode or result.stdout.count('--- PASS: Test')!=3:raise ValueError('Original actual transport controls failed')
            elif result.returncode==0 or witness not in result.stdout or '[build failed]' in result.stdout:raise ValueError('Mutant did not fail at original cancellation assertion: '+name)
    print('Paired transport actual context: 3 positive cases and 3 causal controls passed; native socket boundary explicitly modeled')
if __name__=='__main__':main()
