#!/usr/bin/env python3
"""Execute shipped PQ setters/bridge with test-only native handles; no VPN starts."""
from pathlib import Path
from unittest import mock
import importlib.util
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('prepare_pq',ROOT/'deploy/prepare-mobile-pq.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)

class Prepare(unittest.TestCase):
    def test_exact_lifecycle_patch_and_drift_rejection(self):
        source=P.START+'\n    return nil\n}\n'+P.CLOSE+'\n'
        with mock.patch.object(P,'WG_SHA',P.blobsha(source.encode())):
            result=P.patch_wireguard(source)
            self.assertEqual(P.patch_wireguard(result),result)
            self.assertIn(P.START_NEW,result);self.assertIn(P.CLOSE_NEW,result)
            for wrong in (source+'drift',result+'drift',source.replace(P.START,P.START_NEW),result.replace('defer w.bindAccess.Unlock()','w.bindAccess.Unlock()',1)):
                with self.assertRaises(ValueError):P.patch_wireguard(wrong)
    def test_registration_and_source_composition_are_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            vendor=Path(tmp)
            registry=vendor/'include/registry.go';registry.parent.mkdir()
            registry.write_text('"github.com/sagernet/sing-box/protocol/routervpnamnezia"\n\troutervpnamnezia.RegisterEndpoint(registry)\n')
            wg=vendor/'protocol/wireguard/endpoint.go';wg.parent.mkdir(parents=True)
            source=P.START+'\n    return nil\n}\n'+P.CLOSE+'\n';wg.write_text(source)
            with mock.patch.object(P,'WG_SHA',P.blobsha(source.encode())),mock.patch.object(P.subprocess,'check_output',return_value=P.CORE+'\n'):
                P.prepare(vendor)
                self.assertEqual((vendor/'protocol/routervpnpq/endpoint.go').read_bytes(),(ROOT/'mobile/pq/endpoint.go.tmpl').read_bytes())
                self.assertEqual((vendor/'experimental/libbox/routervpn_pq_bridge.go').read_bytes(),(ROOT/'mobile/routervpn_pq_bridge.go.tmpl').read_bytes())
                before={str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()}
                P.prepare(vendor)
                self.assertEqual(before,{str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()})
    def test_dependency_inputs_include_bridge_and_runtime(self):
        paths={p.relative_to(ROOT).as_posix() for p in P.inputs()}
        self.assertIn('mobile/routervpn_pq_bridge.go.tmpl',paths)
        self.assertIn('mobile/pq/endpoint.go.tmpl',paths)
        self.assertIn('mobile/pq/wireguard_transport.go.tmpl',paths)
        self.assertNotEqual(P.digest(),'')

BRIDGE_TEST=r'''
package libbox
import("bytes";"errors";"sync";"testing";"github.com/sagernet/sing-box/experimental/libbox/routervpn/mobilepq")
type protocolProbe struct{event *RouterPQEvent;err error;closes int}
func(p *protocolProbe)ProcessEvent(int32,[]byte)(*RouterPQEvent,error){return p.event,p.err}
func(p *protocolProbe)Stop()error{p.closes++;return p.err}
func TestBridgeEventValidationAndKeyErasure(t *testing.T){
 cases:=[]*RouterPQEvent{
 {Key:make([]byte,31)},{Key:bytes.Repeat([]byte{1},33)},
 {Key:bytes.Repeat([]byte{1},32),Expired:true},{Rejected:true,Packet:[]byte{1}},
 {Rejected:true,Key:bytes.Repeat([]byte{1},32)},{Rejected:true,Expired:true},
 {WaitMilliseconds:-1},{WaitMilliseconds:1001},{Packet:make([]byte,65536)},
 }
 for _,event:=range cases{
  key:=event.Key;p:=&routerPQProtocol{protocol:&protocolProbe{event:event}}
  if _,err:=p.Step(0,nil);err==nil{t.Fatal("invalid event accepted")}
  if !bytes.Equal(key,make([]byte,len(key)))||event.Key!=nil{t.Fatal("rejected key retained")}
 }
 p:=&routerPQProtocol{protocol:&protocolProbe{event:&RouterPQEvent{Rejected:true}}}
 if _,err:=p.Step(1,[]byte{1});!errors.Is(err,mobilepq.ErrPacket){t.Fatal("rejection became fatal or success",err)}
 key:=bytes.Repeat([]byte{7},32);packet:=[]byte{2,3};e:=&RouterPQEvent{Key:key,Packet:packet,WaitMilliseconds:1000}
 p=&routerPQProtocol{protocol:&protocolProbe{event:e}}
 actual,err:=p.Step(0,nil);if err!=nil{t.Fatal(err)}
 if actual.Key[0]!=7||actual.Packet[0]!=2||e.Key!=nil||key[0]!=0{t.Fatal("key transfer/copy failed")}
 packet[0]=9;if actual.Packet[0]!=2{t.Fatal("native packet alias escaped")}
}
func TestBridgeFailedEventErasesOutputsAndSuppressesDetails(t *testing.T){
 event:=&RouterPQEvent{Key:bytes.Repeat([]byte{9},32)};key:=event.Key
 p:=&routerPQProtocol{protocol:&protocolProbe{event:event,err:errors.New("secret detail")}}
 if _,err:=p.Step(0,nil);err==nil||err.Error()=="secret detail"{t.Fatal(err)}
 if !bytes.Equal(key,make([]byte,32)){t.Fatal("failed key retained")}
 for _,kind:=range []uint32{3,100,0xffffffff}{if _,err:=p.Step(kind,nil);err==nil{t.Fatal("invalid kind accepted")}}
 if _,err:=p.Step(1,make([]byte,65536));err==nil{t.Fatal("oversize packet accepted")}
}
func TestBridgeCloseJoinsConcurrentCallers(t *testing.T){
 native:=&protocolProbe{err:errors.New("private close detail")};p:=&routerPQProtocol{protocol:native}
 var wg sync.WaitGroup
 for n:=0;n<40;n++{wg.Add(1);go func(){defer wg.Done();if err:=p.Close();err==nil||err.Error()=="private close detail"{t.Error(err)}}()};wg.Wait()
 if native.closes!=1{t.Fatal("native owner closed repeatedly")}
}
'''
SETTER_TEST=r'''
package wireguard
import("encoding/hex";"strings";"testing";"sync";"errors")
type fakeDevice struct{last string; fail bool}
func(d *fakeDevice)IpcSet(s string)error{if d.fail{return errors.New("private key")};d.last=s;return nil}
type peerConfig struct{publicKeyHex,preSharedKeyHex string}
type Endpoint struct{peers []peerConfig;device *fakeDevice}
func TestExactPeerPSKOnly(t *testing.T){
 public,key:=make([]byte,32),make([]byte,32);public[0]=7;key[0]=9
 e:=&Endpoint{peers:[]peerConfig{{publicKeyHex:hex.EncodeToString(public)}}}
 if err:=e.RouterVPNSetPQKey(public,key);err!=nil{t.Fatal(err)}
 if e.peers[0].preSharedKeyHex!=hex.EncodeToString(key){t.Fatal("initial key not installed")}
 d:=&fakeDevice{};e.device=d;key[0]=10
 if err:=e.RouterVPNSetPQKey(public,key);err!=nil{t.Fatal(err)}
 if d.last!="public_key="+hex.EncodeToString(public)+"\nupdate_only=true\npreshared_key="+hex.EncodeToString(key)+"\n"{t.Fatal("rekey changes more than captured peer",d.last)}
 bad:=append([]byte(nil),public...);bad[0]=8
 before:=d.last
 for _,args:=range [][2][]byte{{bad,key},{public,make([]byte,32)},{public,key[:31]},{public[:31],key}}{
  if err:=e.RouterVPNSetPQKey(args[0],args[1]);err==nil{t.Fatal("invalid peer/key accepted")}
 }
 if d.last!=before{t.Fatal("rejected request changed peer")}
 d.fail=true;if err:=e.RouterVPNSetPQKey(public,key);err==nil||strings.Contains(err.Error(),"private key"){t.Fatal("failure hidden/leaked")}
}
var _ sync.Mutex
'''
AWG_TEST=r'''
package routervpnamnezia
import("context";"sync";"encoding/hex";"strings";"testing";"errors")
type fakeDevice struct{last string;fail bool}
func(d *fakeDevice)IpcSet(s string)error{if d.fail{return errors.New("private key")};d.last=s;return nil}
type runtimeConfig struct{PeerPublic [32]byte;UAPI string}
type Endpoint struct{life sync.Mutex;closed bool;ctx context.Context;runtime runtimeConfig;device *fakeDevice}
func TestAWGInitialAndRepeatedPeerUpdates(t *testing.T){
 e:=&Endpoint{ctx:context.Background()};e.runtime.PeerPublic[0]=7
 pub:=e.runtime.PeerPublic[:];key:=make([]byte,32);key[0]=9
 e.runtime.UAPI="private_key=secret\njc=3\nreplace_peers=true\npublic_key="+hex.EncodeToString(pub)+"\npreshared_key=old\nallowed_ip=0.0.0.0/0\n"
 for n:=0;n<100;n++{key[1]=byte(n);if err:=e.RouterVPNSetPQKey(pub,key);err!=nil{t.Fatal(err)}}
 if strings.Count(e.runtime.UAPI,"preshared_key=")!=1||!strings.Contains(e.runtime.UAPI,"jc=3\n")||!strings.Contains(e.runtime.UAPI,"allowed_ip=0.0.0.0/0\n"){t.Fatal("AWG parameters lost/rekey history leaked")}
 d:=&fakeDevice{};e.device=d
 if err:=e.RouterVPNSetPQKey(pub,key);err!=nil{t.Fatal(err)}
 if strings.Contains(d.last,"replace_peers")||strings.Contains(d.last,"allowed_ip")||!strings.Contains(d.last,"update_only=true"){t.Fatal("rekey replaced routing")}
 wrong:=append([]byte(nil),pub...);wrong[0]=8
 if e.RouterVPNSetPQKey(wrong,key)==nil||e.RouterVPNSetPQKey(pub,make([]byte,32))==nil{t.Fatal("wrong peer/empty key accepted")}
 e.closed=true;if e.RouterVPNSetPQKey(pub,key)==nil{t.Fatal("closed peer rekeyed")}
}
'''

class Executable(unittest.TestCase):
    def test_actual_bridge_and_psk_setters(self):
        with tempfile.TemporaryDirectory(prefix='pq-executable-',dir=ROOT/'deploy') as tmp:
            work=Path(tmp)
            # This module uses the actual parent controller/compiler packages.
            bridge=(ROOT/'mobile/routervpn_pq_bridge.go.tmpl').read_text()
            for name in ('mobilepq','mobilemultihop'):
                bridge=bridge.replace('github.com/sagernet/sing-box/experimental/libbox/routervpn/'+name,'router-vpn/internal/'+name)
            # An internal import must remain inside its owning module namespace.
            (work/'go.mod').write_text('module router-vpn/deploy/pq-executable\n\ngo 1.23\n\nrequire router-vpn v0.0.0\nreplace router-vpn => '+str(ROOT)+'\n')
            (work/'bridge.go').write_text(bridge)
            (work/'bridge_test.go').write_text(BRIDGE_TEST.replace('github.com/sagernet/sing-box/experimental/libbox/routervpn/mobilepq','router-vpn/internal/mobilepq'))
            for name,source,test in [('wg','mobile/pq/wireguard_transport.go.tmpl',SETTER_TEST),('awg','mobile/amnezia/pq.go.tmpl',AWG_TEST)]:
                p=work/name;p.mkdir();(p/'setter.go').write_bytes((ROOT/source).read_bytes());(p/'setter_test.go').write_text(test)
            subprocess.run(['go','test','-race','-count=10','-timeout=45s','./...'],cwd=work,check=True,timeout=90)
if __name__=='__main__':unittest.main()
