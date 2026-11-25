#!/usr/bin/env python3
"""Exercise shipping reference cleanup and UDP rejection with real local sockets.

These are fixture lifetime controls, not encrypted route or native WFP evidence.
The original hosted native cases and their exact rejection counts remain required.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def function(source, signature):
    start = source.index(signature)
    end = source.index("\n}\n", start) + 3
    return source[start:end]


HEADER = '''package referenceboundary
import("context";"crypto/tls";"errors";"net";"net/http";"sync/atomic";"testing";"time"
 "github.com/sagernet/sing/common/buf"
 M "github.com/sagernet/sing/common/metadata"
 N "github.com/sagernet/sing/common/network")
type desktopNodeLayerServer struct{ rejectedUDP atomic.Int64 }
'''

TEST = r'''package referenceboundary
import("errors";"net";"net/http";"strings";"sync";"testing";"time"
 "github.com/sagernet/sing/common/buf"
 M "github.com/sagernet/sing/common/metadata")

func TestReferenceHTTPShutdownCancelsOwnedHeldRequest(t *testing.T) {
 entered, stopped, clientDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
 t.Run("owned", func(t *testing.T) {
  address:=desktopImportedWGSSHTTP(t,nil,http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
   close(entered);<-r.Context().Done();close(stopped)
  }))
  client:=&http.Client{Timeout:10*time.Second}
  go func(){defer close(clientDone);response,err:=client.Get("http://"+address+"/held");if err==nil{_ =response.Body.Close()}}()
  select{case <-entered:case <-time.After(time.Second):t.Fatal("real held request never entered")}
  select{case <-stopped:t.Fatal("live original handler cancelled before retirement");default:}
 })
 select{case <-stopped:case <-time.After(time.Second):t.Fatal("retired original HTTP handler remained live")}
 select{case <-clientDone:case <-time.After(time.Second):t.Fatal("original HTTP client did not join")}
}

type originalPacket struct {
 *net.UDPConn
 destination M.Socksaddr
 entered chan struct{}
 once sync.Once
}
func(p *originalPacket)ReadPacket(body *buf.Buffer)(M.Socksaddr,error){
 p.once.Do(func(){close(p.entered)})
 data:=make([]byte,65535);n,_,err:=p.ReadFromUDP(data)
 if err!=nil{return M.Socksaddr{},err};_,err=body.Write(data[:n]);return p.destination,err
}
func(p *originalPacket)WritePacket(body *buf.Buffer,_ M.Socksaddr)error{body.Release();return errors.New("a rejected packet must never be forwarded")}
func packet(t *testing.T)(*originalPacket,*net.UDPConn){
 t.Helper();conn,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)});if err!=nil{t.Fatal(err)}
 client,err:=net.DialUDP("udp4",nil,conn.LocalAddr().(*net.UDPAddr));if err!=nil{_ =conn.Close();t.Fatal(err)}
 p:=&originalPacket{UDPConn:conn,destination:M.ParseSocksaddr("192.168.50.133:53"),entered:make(chan struct{})}
 t.Cleanup(func(){_ =client.Close();_ =conn.Close()})
 return p,client
}
func TestReferenceUDPRejectWaitsForOriginalDatagram(t *testing.T){
 for _,reason:=range []string{"layer peer rejected an unowned inner tunnel","layer peer rejected retired original SOCKS association"}{t.Run(reason,func(t *testing.T){
 p,client:=packet(t);owner:=new(desktopNodeLayerServer);done:=make(chan error,1)
 go func(){done<-owner.rejectOriginalUDP(p,p.destination,reason)}()
 select{case <-p.entered:case <-done:t.Fatal("rejection counted before original datagram");case <-time.After(time.Second):t.Fatal("rejection did not start original read")}
 if owner.rejectedUDP.Load()!=0{t.Fatal("rejection counted before original datagram")}
 select{case <-done:t.Fatal("rejection ended before original datagram");default:}
 if _,err:=client.Write([]byte("original first datagram"));err!=nil{t.Fatal(err)}
 select{case err:=<-done:if err==nil||err.Error()!=reason{t.Fatal("original rejection lost",err)}
 case <-time.After(time.Second):t.Fatal("received original datagram did not finish rejection")}
 if owner.rejectedUDP.Load()!=1{t.Fatal("original datagram did not produce exactly one rejection")}
 })}
}
func TestReferenceUDPRejectDoesNotCountForeignDestination(t *testing.T){
 p,client:=packet(t);owner:=new(desktopNodeLayerServer)
 if _,err:=client.Write([]byte("foreign first datagram"));err!=nil{t.Fatal(err)}
 err:=owner.rejectOriginalUDP(p,M.ParseSocksaddr("192.168.50.134:53"),"layer peer rejected an unowned inner tunnel")
 if err==nil||!strings.Contains(err.Error(),"original UDP destination")||owner.rejectedUDP.Load()!=0{t.Fatal("foreign datagram acquired original rejection receipt",err)}
}
func TestReferenceUDPRejectPreservesOriginalReadFailure(t *testing.T){
 p,_:=packet(t);owner:=new(desktopNodeLayerServer);_ =p.Close()
 if err:=owner.rejectOriginalUDP(p,p.destination,"layer peer rejected an unowned inner tunnel");!errors.Is(err,net.ErrClosed)||owner.rejectedUDP.Load()!=0{t.Fatal("failed original read acquired rejection receipt",err)}
}

'''


def execute():
    go = shutil.which("go")
    if not go:
        raise RuntimeError("Go is required for real reference socket boundary checks")
    http_source = (ROOT / "mobile/desktop/node_imported_peer_linux_test.go.tmpl").read_text()
    udp_source = (ROOT / "mobile/desktop/node_layer_peer_test.go.tmpl").read_text()
    http = function(http_source, "func desktopImportedWGSSHTTP(")
    udp = function(udp_source, "func (s *desktopNodeLayerServer) rejectOriginalUDP(")
    caller = function(udp_source, "func (s *desktopNodeLayerServer) NewPacketConnection(")
    for reason in ("layer peer rejected an unowned inner tunnel", "layer peer rejected retired original SOCKS association"):
        if 'return s.rejectOriginalUDP(connection, metadata.Destination, "' + reason + '")' not in caller:
            raise AssertionError("shipping reference no longer consumes the rejected original datagram: " + reason)
    original = HEADER + http + udp
    old_http = http.replace('lifetime, cancelLifetime := context.WithCancel(context.Background())', '')
    old_http = old_http.replace('BaseContext: func(net.Listener) context.Context { return lifetime }, ', '')
    old_http = old_http.replace('cancelLifetime()', '')
    old_udp = '''func (s *desktopNodeLayerServer) rejectOriginalUDP(connection N.PacketConn, destination M.Socksaddr, reason string) error {
 s.rejectedUDP.Add(1)
 return errors.New(reason)
}
'''
    variants = (
        ("original", original, None, "^TestReference"),
        ("held-request-without-owner", HEADER + old_http + udp, "imported reference HTTP did not join", "^TestReferenceHTTP"),
        ("rejection-before-first-packet", HEADER + http + old_udp, "rejection counted before original datagram", "^TestReferenceUDPRejectWaits"),
    )
    with tempfile.TemporaryDirectory(prefix="reference-peer-boundaries-") as name:
        folder = Path(name)
        (folder / "go.mod").write_text("module referenceboundary\n\ngo 1.26.0\n\nrequire github.com/sagernet/sing v0.9.4\n")
        (folder / "boundaries_test.go").write_text(TEST)
        env = dict(os.environ, GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="", GOMAXPROCS="2")
        for label, source, witness, selector in variants:
            # Historical controls omit code that used an otherwise irrelevant
            # import. Retain the same real sockets and extracted function body.
            source += '\nvar _ = context.Canceled\nvar _ = buf.NewPacket\n'
            (folder / "reference.go").write_text(source)
            result = subprocess.run([go, "test", "-race", "-p=1", "-mod=mod", "-count=1", "-v", "-timeout=15s", "-run", selector, "."],
                                    cwd=folder, env=env, text=True, capture_output=True, timeout=120)
            output = result.stdout + result.stderr
            if witness:
                if result.returncode != 1 or witness not in output or re.search(r"panic:|fatal error:|WARNING: DATA RACE|\[build failed\]", output):
                    raise AssertionError(label + ": original scheduling defect was not reproduced\n" + output)
            elif result.returncode != 0 or len(re.findall(r"^--- PASS: TestReference", output, re.M)) != 4:
                raise AssertionError("actual reference boundary failed\n" + output)
            print("Reference peer boundary " + label + ": PASS", flush=True)


if __name__ == "__main__":
    execute()
