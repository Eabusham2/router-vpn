#!/usr/bin/env python3
"""Actual pinned SS2022 encrypt/decrypt regression for the extracted desktop DNS reply method."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
TEMPLATE=ROOT/'mobile/desktop/external_box_integration_test.go.tmpl'
GO=r'''
package replycheck
import (
 "bytes"
 "context"
 "encoding/base64"
 "errors"
 "net"
 "sync/atomic"
 "strings"
 "testing"
 "time"
 mDNS "github.com/miekg/dns"
 "github.com/sagernet/sing-shadowsocks/shadowaead_2022"
 "github.com/sagernet/sing/common/buf"
 "github.com/sagernet/sing/common/bufio"
 M "github.com/sagernet/sing/common/metadata"
 N "github.com/sagernet/sing/common/network"
)
const desktopExternalIntegrationDNS="192.168.50.53:5353"
type impossibleLatency struct{}
func(*impossibleLatency)answer(*mDNS.Msg,*mDNS.Msg){panic("unexpected latency branch")}
type desktopExternalIntegrationPeer struct {
 ctx context.Context
 protocol string
 ownedPacket func(context.Context,N.PacketConn,M.Metadata)error
 latency *impossibleLatency
 badDNS bool
 dnsQueries,udpQueries atomic.Int64
}
func desktopExternalIntegrationUDPDNS(string)bool{return false}
// EXTRACTED_METHOD

type handler struct{peer *desktopExternalIntegrationPeer; cached bool;done chan error}
func(h *handler)NewConnection(context.Context,net.Conn,M.Metadata)error{return errors.New("unexpected stream")}
func(h *handler)NewError(context.Context,error){}
func(h *handler)NewPacketConnection(ctx context.Context,c N.PacketConn,m M.Metadata)(err error){
 defer func(){_ = c.Close();h.done<-err}()
 if h.cached {
  first:=buf.NewPacket();destination,e:=c.ReadPacket(first);if e!=nil{first.Release();return e}
  cached:=bufio.NewCachedPacketConn(c,first,destination);first.Release();defer cached.Close();c=cached
 }
 if N.CalculateFrontHeadroom(c)<=0||N.CalculateRearHeadroom(c)!=16{return errors.New("actual SS writer headroom lost through wrapper")}
 return h.peer.NewPacketConnection(ctx,c,m)
}
type observedWire struct{N.PacketConn;tamper bool;packets chan []byte}
func(w *observedWire)WritePacket(b *buf.Buffer,d M.Socksaddr)error{
 raw:=b.Bytes();w.packets<-bytes.Clone(raw)
 if w.tamper{raw[len(raw)-1]^=1}
 return w.PacketConn.WritePacket(b,d)
}
func TestActualSS2022DNSReplyHeadroom(t *testing.T){
 for _,name:=range []string{"direct","cached","tampered-tag"}{t.Run(name,func(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel()
 listener,e:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)});if e!=nil{t.Fatal(e)};defer listener.Close()
 deadline,_:=ctx.Deadline();_ = listener.SetDeadline(deadline)
 peer:=&desktopExternalIntegrationPeer{ctx:ctx,protocol:"shadowsocks"}
 h:=&handler{peer:peer,cached:name!="direct",done:make(chan error,1)}
 password:=base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7},32))
 service,e:=shadowaead_2022.NewServiceWithPassword("2022-blake3-aes-256-gcm",password,60,h,nil);if e!=nil{t.Fatal(e)}
 wire:=&observedWire{PacketConn:bufio.NewPacketConn(listener),tamper:name=="tampered-tag",packets:make(chan []byte,1)}
 accepted:=make(chan error,1)
 go func(){b:=buf.NewPacket();source,e:=wire.ReadPacket(b);if e==nil{e=service.NewPacket(ctx,wire,b,M.Metadata{Source:source})};if e!=nil{b.Release()};accepted<-e}()
 socket,e:=net.DialUDP("udp4",nil,listener.LocalAddr().(*net.UDPAddr));if e!=nil{t.Fatal(e)};defer socket.Close();_ = socket.SetDeadline(deadline)
 method,e:=shadowaead_2022.NewWithPassword("2022-blake3-aes-256-gcm",password,nil);if e!=nil{t.Fatal(e)}
 client:=method.DialPacketConn(socket);defer client.Close()
 question:=new(mDNS.Msg);question.SetQuestion("example.com.",mDNS.TypeA);raw,e:=question.Pack();if e!=nil{t.Fatal(e)}
 destination:=M.ParseSocksaddr(desktopExternalIntegrationDNS)
 if _,e=client.WriteTo(raw,destination.UDPAddr());e!=nil{t.Fatal(e)}
 payload:=make([]byte,4096);n,from,readError:=client.ReadFrom(payload)
 select{case e=<-accepted:if e!=nil{t.Fatal(e)};case<-ctx.Done():t.Fatal("original encrypted request not joined")}
 var encrypted []byte;select{case encrypted=<-wire.packets:case<-ctx.Done():t.Fatal("actual encrypted response absent")}
 if bytes.Contains(encrypted,raw)||len(encrypted)<=len(raw)+16{t.Fatal("response did not traverse actual SS encryption")}
 if name=="tampered-tag"{if readError==nil||!strings.Contains(readError.Error(),"message authentication failed"){t.Fatal("tampered real AEAD response did not fail authentication",readError)}}else{
 if readError!=nil{t.Fatal(readError)};if from.String()!=destination.String(){t.Fatal("decrypted destination changed",from)}
 response:=new(mDNS.Msg);if e=response.Unpack(payload[:n]);e!=nil{t.Fatal(e)}
 if response.Id!=question.Id||len(response.Question)!=1||response.Question[0]!=question.Question[0]||len(response.Answer)!=1{t.Fatal("decrypted DNS identity changed")}
 address,ok:=response.Answer[0].(*mDNS.A);if !ok||!address.A.Equal(net.IPv4(93,184,216,34)){t.Fatal("decrypted DNS answer changed")}
 }
 cancel()
 select{case<-h.done:case<-time.After(time.Second):t.Fatal("original SS response handler failed to join")}
 if peer.dnsQueries.Load()!=1||peer.udpQueries.Load()!=1{t.Fatal("actual fixture method was not the response owner")}
 })}
}
'''

def extract():
    text=TEMPLATE.read_text()
    begin='func (p *desktopExternalIntegrationPeer) NewPacketConnection('
    end='func (*desktopExternalIntegrationPeer) NewError('
    assert text.count(begin)==1 and text.count(end)==1
    return text[text.index(begin):text.index(end)]

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',required=True,type=Path);args=parser.parse_args()
    source=args.source.resolve();mod=(source/'go.mod').read_text()
    for pin in ('github.com/sagernet/sing-shadowsocks v0.2.8','github.com/sagernet/sing v0.9.4','github.com/miekg/dns v1.1.72'):
        assert pin in mod,pin
    method=extract();before=hashlib.sha256(TEMPLATE.read_bytes()).hexdigest()
    env=dict(os.environ,GOMAXPROCS='1',GOGC='20',GOMEMLIMIT='768MiB')
    with tempfile.TemporaryDirectory(prefix='ssreply_',dir=source/'cmd') as tmp:
        tmp=Path(tmp);test=tmp/'reply_test.go';test.write_text(GO.replace('// EXTRACTED_METHOD',method))
        command=['go','test','-race','-p=1','-mod=readonly','-count=1','-timeout=20s','-v','./'+tmp.relative_to(source).as_posix()]
        good=subprocess.run(command,cwd=source,env=env,capture_output=True,text=True,timeout=300)
        print(good.stdout+good.stderr,flush=True);good.check_returncode()
        for case in ('direct','cached','tampered-tag'):
            assert f'--- PASS: TestActualSS2022DNSReplyHeadroom/{case} ' in good.stdout
        start=method.index('\t\t// Follow the actual wrapped writer:')
        finish=method.index('\n\t\tif err := connection.WritePacket',start)
        old='\t\treply := buf.NewSize(2048 + len(raw))\n\t\treply.Resize(2048, 0)\n\t\t_, _ = reply.Write(raw)'
        mutant=method[:start]+old+method[finish:]
        test.write_text(GO.replace('// EXTRACTED_METHOD',mutant))
        bad=subprocess.run(command,cwd=source,env=env,capture_output=True,text=True,timeout=300)
        output=bad.stdout+bad.stderr
        assert bad.returncode==1 and 'panic: buffer overflow:' in output and 'need 16' in output and 'shadowaead_2022.(*serverPacketWriter).WritePacket' in output,output
        assert 'test timed out' not in output and 'DATA RACE' not in output,output
        print(output,flush=True)
        print('Old allocation causal: actual pinned serverPacketWriter overflow requires16 rear bytes',flush=True)
    assert hashlib.sha256(TEMPLATE.read_bytes()).hexdigest()==before
    print('SS DNS fixture source SHA256 '+before,flush=True)
if __name__=='__main__':main()
