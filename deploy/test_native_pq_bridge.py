#!/usr/bin/env python3
"""Execute shipped PQ setters/bridge with test-only native handles; no VPN starts."""
from pathlib import Path
from unittest import mock
import importlib.util
import os
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('prepare_pq',ROOT/'deploy/prepare-mobile-pq.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)

class Prepare(unittest.TestCase):
    def test_exact_lifecycle_patch_and_drift_rejection(self):
        source='type Endpoint struct {\n'+P.FIELD+'}\n'+P.START+'\n'+P.CLOSE+'\n'
        with mock.patch.object(P,'WG_SHA',P.blobsha(source.encode())):
            result=P.patch_wireguard(source)
            self.assertEqual(P.patch_wireguard(result),result)
            previous=source.replace(P.START,P.START_OLD,1).replace(P.CLOSE,P.CLOSE_OLD,1)
            self.assertEqual(P.patch_wireguard(previous),result)
            self.assertIn(P.START_NEW,result);self.assertIn(P.CLOSE_NEW,result)
            for wrong in (source+'drift',result+'drift',source.replace(P.START,P.START_NEW),result.replace('defer w.bindAccess.Unlock()','w.bindAccess.Unlock()',1)):
                with self.assertRaises(ValueError):P.patch_wireguard(wrong)
    def test_registration_and_source_composition_are_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            vendor=Path(tmp)
            registry=vendor/'include/registry.go';registry.parent.mkdir()
            registry.write_text('"github.com/sagernet/sing-box/protocol/routervpnamnezia"\n\troutervpnamnezia.RegisterEndpoint(registry)\n')
            wg=vendor/'protocol/wireguard/endpoint.go';wg.parent.mkdir(parents=True)
            source='type Endpoint struct {\n'+P.FIELD+'}\n'+P.START+'\n'+P.CLOSE+'\n';wg.write_text(source)
            with mock.patch.object(P,'WG_SHA',P.blobsha(source.encode())),mock.patch.object(P.subprocess,'check_output',return_value=P.CORE+'\n'):
                P.prepare(vendor)
                self.assertEqual((vendor/'protocol/routervpnpq/endpoint.go').read_bytes(),(ROOT/'mobile/pq/endpoint.go.tmpl').read_bytes())
                self.assertEqual((vendor/'experimental/libbox/routervpn_pq_bridge.go').read_bytes(),(ROOT/'mobile/routervpn_pq_bridge.go.tmpl').read_bytes())
                self.assertEqual((vendor/'experimental/libbox/routervpn_max_resolve_bridge.go').read_bytes(),(ROOT/'mobile/routervpn_max_resolve_bridge.go.tmpl').read_bytes())
                before={str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()}
                P.prepare(vendor)
                self.assertEqual(before,{str(p.relative_to(vendor)):p.read_bytes() for p in vendor.rglob('*') if p.is_file()})
    def test_flow_authorization_uses_its_real_separate_interface(self):
        # In the pinned core FlowOutbound embeds tun.Port, not tun.Handler.
        # Execute the shipping method with that exact separation, so adding
        # JudgeFlow to a permissive test double cannot hide this compiler bug.
        source=(ROOT/'mobile/pq/endpoint.go.tmpl').read_text()
        self.assertIn('judge, ok := base.(flowJudge)',source)
        self.assertIn('native PQ base does not own flow authorization',source)
        self.assertIn('judge: judge',source)
        method=source[source.index('func (e *Endpoint) JudgeFlow('):]
        method=method.replace('tun.FlowVerdict','FlowVerdict').replace('tun.ActionReject','ActionReject')
        with tempfile.TemporaryDirectory(prefix='pq-flow-') as tmp:
            work=Path(tmp)
            (work/'go.mod').write_text('module pqflow\n\ngo 1.23\n')
            (work/'flow.go').write_text('package pqflow\nimport "net/netip"\n'+r'''
const ActionReject=9
type FlowVerdict struct{Action int}
type flowJudge interface{JudgeFlow(uint8,netip.AddrPort,netip.AddrPort,[]byte)FlowVerdict}
type flowOutbound interface{WritePackets([][]byte)error}
type owner struct{ready bool}
func(o *owner)Ready()bool{return o.ready}
type Endpoint struct{owner *owner;flow flowOutbound;judge flowJudge}
'''+method)
            (work/'flow_test.go').write_text(r'''package pqflow
import("net/netip";"testing")
type judge struct{calls int}
func(j *judge)JudgeFlow(uint8,netip.AddrPort,netip.AddrPort,[]byte)FlowVerdict{j.calls++;return FlowVerdict{3}}
func TestCapturedJudgeAndNotReadyRejection(t *testing.T){
 j:=&judge{};e:=&Endpoint{owner:&owner{},judge:j}
 if e.JudgeFlow(17,netip.AddrPort{},netip.AddrPort{},nil).Action!=ActionReject||j.calls!=0{t.Fatal("unready flow authorized")}
 e.owner.ready=true
 if e.JudgeFlow(17,netip.AddrPort{},netip.AddrPort{},nil).Action!=3||j.calls!=1{t.Fatal("captured authorization bypassed")}
}
''')
            subprocess.run(['go','test','-race','./...'],cwd=work,check=True,timeout=30)

    def test_dependency_inputs_include_bridge_and_runtime(self):
        paths={p.relative_to(ROOT).as_posix() for p in P.inputs()}
        self.assertIn('mobile/routervpn_pq_bridge.go.tmpl',paths)
        self.assertIn('mobile/routervpn_max_resolve_bridge.go.tmpl',paths)
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
MAX_BRIDGE_TEST=r'''
package libbox
import("encoding/base64";"encoding/json";"os";"strings";"sync/atomic";"testing")
type maxResolverProbe struct{calls atomic.Int32;closes atomic.Int32;current atomic.Bool}
func(p *maxResolverProbe)OwnerID()string{return "captured-network-17"}
func(p *maxResolverProbe)Current()bool{return p.current.Load()}
func(p *maxResolverProbe)Cancel(){p.closes.Add(1)}
func(p *maxResolverProbe)Lookup(host string)(string,error){
 p.calls.Add(1);raw,_:=json.Marshal(map[string]any{"owner_id":p.OwnerID(),"hostname":host,"addresses":[]string{"192.0.2.71"}});return string(raw),nil
}
func TestMAXNativeBridgeUsesActualCapturedCompilerAndResolver(t *testing.T){
 raw,err:=os.ReadFile(os.Getenv("ROUTERVPN_MAX_PROFILE_FIXTURES"));if err!=nil{t.Fatal(err)}
 var fixtures map[string]struct{Files map[string]string `json:"files"`;Policy map[string]any `json:"policy"`}
 if json.Unmarshal(raw,&fixtures)!=nil||len(fixtures)!=4{t.Fatal("missing actual compiler fixtures")}
 for mode,fixture:=range fixtures{
  endpoint:="captured-max.example";fixture.Policy["endpoint"]=endpoint;fixture.Policy["start_layer"]="aes-256-gcm+xor-whitening"
  name:="middle-sing-box.json";if strings.HasPrefix(mode,"max-tls-"){name="outer-xray.json"}
  source,_:=base64.StdEncoding.DecodeString(fixture.Files[name]);var graph map[string]any
  if json.Unmarshal(source,&graph)!=nil{t.Fatal("invalid actual outer fixture")}
  out:=graph["outbounds"].([]any)[0].(map[string]any)
  if strings.HasPrefix(mode,"max-tls-"){out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"]=endpoint}else{out["server"]=endpoint}
  source,_=json.Marshal(graph);fixture.Files[name]=base64.StdEncoding.EncodeToString(source)
  files,_:=json.Marshal(fixture.Files);metadata,_:=json.Marshal(fixture.Policy)
  digest,err:=RouterCheckMAXProfile(mode,string(files),string(metadata));if err!=nil||len(digest)!=64{t.Fatal("pure native hostname readiness failed",err)}
  if _,err=RouterCompileMAXProfile(mode,string(files),string(metadata));err==nil{t.Fatal("readiness relaxed literal-only runtime")}
  resolver:=&maxResolverProbe{};resolver.current.Store(true)
  request,err:=RouterCreateMAXProfileRequest(mode,string(files),string(metadata),resolver)
  if err!=nil||request.Healthy()||resolver.calls.Load()!=0||request.SourceSHA256()!=digest{t.Fatal("native capture opened DNS or lost source binding",err)}
  result,err:=request.Run();if err!=nil||!request.Healthy()||resolver.calls.Load()!=1{t.Fatal("actual bridge failed",err)}
  var envelope map[string]any;if json.Unmarshal([]byte(result),&envelope)!=nil||envelope["source_sha256"]!=request.SourceSHA256()||envelope["owner_id"]!=resolver.OwnerID()||envelope["hostname"]!=endpoint||envelope["endpoint"]!="192.0.2.71"{t.Fatal("bridge lost exact captured owner")}
  compiled,err:=RouterCompileMAXProfile(mode,envelope["files_json"].(string),envelope["metadata_json"].(string))
  if err!=nil||compiled!=envelope["config_json"]{t.Fatal("bridge bypassed literal-only compiler",err)}
  if _,err=request.Run();err==nil||resolver.calls.Load()!=1{t.Fatal("bridge repeated native request")}
  request.Cancel();if request.Healthy(){t.Fatal("bridge Cancel did not retire exact owner")};request.Close();if resolver.closes.Load()!=1{t.Fatal("bridge Close did not join captured owner")}
  resolver=&maxResolverProbe{};resolver.current.Store(true)
  request,err=RouterCreateMAXProfileRequest(mode,string(files),string(metadata),resolver);if err!=nil{t.Fatal(err)}
  request.Cancel();if result,err=request.Run();result!=""||err==nil||resolver.calls.Load()!=0{t.Fatal("pre-canceled bridge resolved or staged a launch")};request.Close()
 }
 var empty *RouterMAXProfileRequest
 if result,err:=empty.Run();result!=""||err==nil||empty.Healthy()||empty.SourceSHA256()!=""{t.Fatal("nil native request accepted")};empty.Cancel();empty.Close()
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
    def test_blocking_foreign_cancel_negative_control(self):
        source=ROOT/'internal/mobilemultihop/max_request.go'
        original=source.read_text()
        anchor='\t\tgo func() {\n\t\t\tdefer close(r.closed)'
        self.assertEqual(original.count(anchor),1)
        with tempfile.TemporaryDirectory(prefix='max-cancel-control-') as tmp:
            work=Path(tmp)
            mutation=work/'max_request.go'
            mutation.write_text(original.replace(anchor,anchor.replace('go func','func'),1))
            overlay=work/'overlay.json'
            import json
            overlay.write_text(json.dumps({'Replace':{str(source):str(mutation)}}))
            result=subprocess.run(['go','test','-overlay',str(overlay),'-count=1','-run','^TestMAXNativeRequestJoinsLookupAndCancellationBeforeClose$','-timeout=15s','./internal/mobilemultihop'],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=60)
            self.assertNotEqual(result.returncode,0,result.stdout)
            self.assertIn('immediate Cancel blocked on a foreign resolver callback',result.stdout)

    def test_actual_bridge_and_psk_setters(self):
        with tempfile.TemporaryDirectory(prefix='pq-executable-',dir=ROOT/'deploy') as tmp:
            work=Path(tmp)
            # This module uses the actual parent controller/compiler packages.
            bridge=(ROOT/'mobile/routervpn_pq_bridge.go.tmpl').read_text()
            for name in ('mobilepq','mobilemultihop'):
                bridge=bridge.replace('github.com/sagernet/sing-box/experimental/libbox/routervpn/'+name,'router-vpn/internal/'+name)
            # An internal import must remain inside its owning module namespace.
            (work/'go.mod').write_text('module router-vpn/deploy/pq-executable\n\ngo 1.24.13\n\nrequire router-vpn v0.0.0\nreplace router-vpn => '+str(ROOT)+'\n')
            (work/'bridge.go').write_text(bridge)
            (work/'bridge_test.go').write_text(BRIDGE_TEST.replace('github.com/sagernet/sing-box/experimental/libbox/routervpn/mobilepq','router-vpn/internal/mobilepq'))
            max_bridge=(ROOT/'mobile/routervpn_max_resolve_bridge.go.tmpl').read_text().replace('github.com/sagernet/sing-box/experimental/libbox/routervpn/mobilemultihop','router-vpn/internal/mobilemultihop')
            (work/'max_bridge.go').write_text(max_bridge)
            (work/'max_bridge_test.go').write_text(MAX_BRIDGE_TEST)
            environment=dict(os.environ,ROUTERVPN_MAX_PROFILE_FIXTURES=str(work/'max-profiles.json'))
            subprocess.run(['go','test','-count=1','-run','^TestExportMAXMobileProfiles$','./internal/mobilemultihop'],cwd=ROOT,env=environment,check=True,timeout=90)
            for name,source,test in [('wg','mobile/pq/wireguard_transport.go.tmpl',SETTER_TEST),('awg','mobile/amnezia/pq.go.tmpl',AWG_TEST)]:
                p=work/name;p.mkdir();(p/'setter.go').write_bytes((ROOT/source).read_bytes());(p/'setter_test.go').write_text(test)
            subprocess.run(['go','test','-race','-count=10','-timeout=45s','./...'],cwd=work,env=environment,check=True,timeout=90)
if __name__=='__main__':unittest.main()
