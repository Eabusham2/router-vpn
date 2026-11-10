#!/usr/bin/env python3
"""Run the Windows SS forwarding peer method with real pinned SS2022 on Linux.

Only the Windows host/WFP owner is replaced by a small lifecycle holder. The
cached-packet owner and UDP forwarding method are extracted unchanged; real
SS encryption/decryption and loopback UDP forwarding exercise their allocation.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'mobile/desktop/external_box_windows_ss_entry_test.go.tmpl'
GO = r'''
package replycheck
import (
 "bytes"
 "context"
 "encoding/base64"
 "errors"
 "fmt"
 "net"
 "strings"
 "sync"
 "sync/atomic"
 "testing"
 "time"
 "github.com/sagernet/sing-shadowsocks/shadowaead_2022"
 "github.com/sagernet/sing/common/buf"
 B "github.com/sagernet/sing/common/bufio"
 M "github.com/sagernet/sing/common/metadata"
 N "github.com/sagernet/sing/common/network"
)
type desktopWFPSSEntryForward struct {
 ctx context.Context
 target, final string
 rejected, packets atomic.Int32
 mu sync.Mutex
 closing bool
 packetConnections map[N.PacketConn]bool
 workers sync.WaitGroup
}
func(*desktopWFPSSEntryForward)destination()string{return "198.51.100.240:8388"}
// EXTRACTED_METHODS
type handler struct{peer *desktopWFPSSEntryForward;done chan error}
func(*handler)NewConnection(context.Context,net.Conn,M.Metadata)error{return errors.New("unexpected stream")}
func(*handler)NewError(context.Context,error){}
func(h *handler)NewPacketConnection(ctx context.Context,c N.PacketConn,m M.Metadata)(err error){
 defer func(){_ = c.Close();h.done<-err}()
 first:=buf.NewPacket();destination,e:=c.ReadPacket(first);if e!=nil{first.Release();return e}
 cached:=B.NewCachedPacketConn(c,first,destination);first.Release();defer cached.Close()
 return h.peer.NewPacketConnection(ctx,cached,m)
}
type observedWire struct{N.PacketConn;tamper bool;packets atomic.Int32}
func(w *observedWire)WritePacket(b *buf.Buffer,d M.Socksaddr)error{
 w.packets.Add(1)
 if w.tamper{raw:=b.Bytes();raw[len(raw)-1]^=1}
 return w.PacketConn.WritePacket(b,d)
}
func TestActualSS2022EntryForwarding(t *testing.T){
 if buf.UDPBufferSize!=65535{t.Fatal("requires the shipping checksum-verified native packet buffer policy")}
 for _,cipher:=range []string{"2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305"}{
 for _,size:=range []int{0,1,42,4096,65000}{
 t.Run(fmt.Sprintf("%s/%d",cipher,size),func(t *testing.T){runForward(t,cipher,size,false,false)})
 }}
 t.Run("tampered-response",func(t *testing.T){runForward(t,"2022-blake3-aes-256-gcm",42,true,false)})
 t.Run("uncaptured-destination",func(t *testing.T){runForward(t,"2022-blake3-aes-256-gcm",42,false,true)})
}
func runForward(t *testing.T,cipher string,size int,tamper,wrong bool){
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel()
 deadline,_:=ctx.Deadline()
 final,e:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)});if e!=nil{t.Fatal(e)};defer final.Close();_ = final.SetDeadline(deadline)
 payload:=bytes.Repeat([]byte{0x53},size)
 finalDone:=make(chan error,1)
 go func(){raw:=make([]byte,65535);n,from,e:=final.ReadFromUDP(raw);if e==nil&&!bytes.Equal(raw[:n],[]byte("captured final request")){e=errors.New("forwarded request changed")};if e==nil{_,e=final.WriteToUDP(payload,from)};finalDone<-e}()
 listener,e:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)});if e!=nil{t.Fatal(e)};defer listener.Close();_ = listener.SetDeadline(deadline)
 peer:=&desktopWFPSSEntryForward{ctx:ctx,target:final.LocalAddr().String(),final:"shadowsocks",packetConnections:make(map[N.PacketConn]bool)}
 h:=&handler{peer:peer,done:make(chan error,1)}
 keySize:=32;if strings.Contains(cipher,"aes-128"){keySize=16}
 password:=base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7},keySize))
 service,e:=shadowaead_2022.NewServiceWithPassword(cipher,password,60,h,nil);if e!=nil{t.Fatal(e)}
 wire:=&observedWire{PacketConn:B.NewPacketConn(listener),tamper:tamper}
 accepted:=make(chan error,1)
 go func(){b:=buf.NewPacket();source,e:=wire.ReadPacket(b);if e==nil{e=service.NewPacket(ctx,wire,b,M.Metadata{Source:source})};if e!=nil{b.Release()};accepted<-e}()
 socket,e:=net.DialUDP("udp4",nil,listener.LocalAddr().(*net.UDPAddr));if e!=nil{t.Fatal(e)};defer socket.Close();_ = socket.SetDeadline(deadline)
 method,e:=shadowaead_2022.NewWithPassword(cipher,password,nil);if e!=nil{t.Fatal(e)}
 client:=method.DialPacketConn(socket);defer client.Close()
 destination:=M.ParseSocksaddr(peer.destination());if wrong{destination=M.ParseSocksaddr("198.51.100.241:8388")}
 if _,e=client.WriteTo([]byte("captured final request"),destination.UDPAddr());e!=nil{t.Fatal(e)}
 if wrong {
  select{case e=<-h.done:if e==nil||!strings.Contains(e.Error(),"unowned UDP final"){t.Fatal("foreign destination not rejected",e)};case<-ctx.Done():t.Fatal("rejection did not join")}
  if wire.packets.Load()!=0||peer.packets.Load()!=0||peer.rejected.Load()!=1{t.Fatal("foreign owner reached forwarding")}
  _ = final.Close();<-finalDone
  return
 }
 response:=make([]byte,65535);n,from,readError:=client.ReadFrom(response)
 if tamper{if readError==nil||!strings.Contains(readError.Error(),"message authentication failed"){t.Fatal("tampered encrypted response accepted",readError)}}else{
  if readError!=nil{t.Fatal(readError)}
  if !bytes.Equal(response[:n],payload)||from.String()!=destination.String(){t.Fatal("response bytes or original identity changed",n,from)}
 }
 if e=<-finalDone;e!=nil{t.Fatal(e)}
 if e=<-accepted;e!=nil{t.Fatal(e)}
 if wire.packets.Load()!=1||peer.packets.Load()!=1{t.Fatal("real encryption or forwarding bypassed")}
 cancel()
 select{case<-h.done:case<-time.After(time.Second):t.Fatal("cancelled original forwarding owner did not join")}
 peer.mu.Lock();remaining:=len(peer.packetConnections);peer.mu.Unlock();if remaining!=0{t.Fatal("original owner retained packet connection")}
}
'''

def extract():
    text = TEMPLATE.read_text()
    start = text.index('type desktopWFPOwnedInitialPacket struct')
    end = text.index('type desktopWFPSSEntryRetiredPacket struct', start)
    return text[start:end]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    mod = (source/'go.mod').read_text()
    for pin in ('github.com/sagernet/sing-shadowsocks v0.2.8', 'github.com/sagernet/sing v0.9.4'):
        assert pin in mod, pin
    method = extract()
    env = dict(os.environ, GOMAXPROCS='1', GOGC='20', GOMEMLIMIT='768MiB')
    with tempfile.TemporaryDirectory(prefix='ssentryreply_', dir=source) as tmp:
        tmp = Path(tmp)
        test = tmp/'reply_test.go'
        command = ['go', 'test', '-race', '-p=1', '-mod=readonly', '-count=1', '-timeout=60s', '-v', './'+tmp.relative_to(source).as_posix()]
        test.write_text(GO.replace('// EXTRACTED_METHODS', method))
        good = subprocess.run(command, cwd=source, env=env, capture_output=True, text=True, timeout=300)
        print(good.stdout+good.stderr, flush=True)
        good.check_returncode()
        # Reproduce the native Windows panic with the exact old allocation.
        start = method.index('\t\t\t// Keep the UDP payload bound unchanged;')
        end = method.index('\n\t\t\tif e = c.WritePacket(reply,', start)
        old = '\t\t\tbody.Truncate(n)\n\t\t\treply := body'
        mutant = method[:start]+old+method[end:]
        capture = '\tfront, rear := N.CalculateFrontHeadroom(c), N.CalculateRearHeadroom(c)'
        wrong_writer = method.replace(capture, capture.replace('(c)', '(&desktopWFPOwnedInitialPacket{PacketConn: c})'))
        for label, changed in [('original zero-headroom allocation', mutant), ('headroom hidden by ownership wrapper', wrong_writer)]:
            test.write_text(GO.replace('// EXTRACTED_METHODS', changed))
            bad = subprocess.run(command, cwd=source, env=env, capture_output=True, text=True, timeout=300)
            output = bad.stdout+bad.stderr
            assert bad.returncode == 1 and 'panic: buffer overflow:' in output and 'start 0, need 42' in output and 'shadowaead_2022.(*serverPacketWriter).WritePacket' in output, output
            assert 'test timed out' not in output and 'DATA RACE' not in output, output
            print(label+' reproduced the native SS2022 need42 overflow', flush=True)
    print('Actual SS entry forwarding byte identity, authentication, ownership and cancellation passed', flush=True)

if __name__ == '__main__':
    main()
