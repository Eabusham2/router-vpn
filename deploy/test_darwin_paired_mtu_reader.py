#!/usr/bin/env python3
"""Execute the exact Box confirmation method with the real sealed policy compiler.

Only Box/reader/native observation are explicit models. No PF, utun, physical
source or native handoff acceptance is claimed by this portable causal gate.
"""
from pathlib import Path
from functools import cache
import argparse
import importlib.util
import os
import tempfile

ROOT=Path(__file__).resolve().parents[1]
HEADER=r'''package confirmation
import("context";"errors";"sync";"router-vpn/paired-mtu-fixture/adapter";"router-vpn/internal/mobilemultihop")
type Box struct{identity int}
type modeledNetwork struct{session,source string;refused bool}
func(n *modeledNetwork)MatchesContext(ctx context.Context,session,source string)error{if n==nil||n.refused||n.session!=session||n.source!=source{return errors.New("modeled original source refused")};return ctx.Err()}
type RouterVPNDesktopNodePhysical struct{
 mu sync.Mutex
 instance *Box
 inbound adapter.Inbound
 policy mobilemultihop.DesktopPhysicalPolicy
 detached bool
 interfaceName string
 network *modeledNetwork
 name string
 index,mtu int
 refused bool
 reads int
}
func(o *RouterVPNDesktopNodePhysical)readbackContext(ctx context.Context)(string,int,int,error){o.reads++;if o.refused{return "",0,0,errors.New("modeled original native readback refused")};return o.name,o.index,o.mtu,ctx.Err()}
'''
TEST=r'''package confirmation
import("context";"encoding/base64";"encoding/json";"strings";"testing";"time";"router-vpn/internal/mobilemultihop")
func original(t *testing.T,target string)*mobilemultihop.DesktopNodePolicy{
 t.Helper()
 graph:=map[string]any{"inbounds":[]any{map[string]any{"type":"tun","auto_route":true,"strict_route":true,"mtu":1280}},"outbounds":[]any{map[string]any{"type":"shadowsocks","tag":"proxy","server":"192.0.2.44","server_port":443,"method":"2022-blake3-aes-256-gcm","password":base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s",32)))}},"route":map[string]any{"final":"proxy"}}
 raw,_:=json.Marshal(graph);assets,_:=json.Marshal(map[string]string{"sing-box.json":base64.StdEncoding.EncodeToString(raw)})
 profile,_:=json.Marshal(map[string]any{"id":"captured-darwin-node","node_kind":"router-vpn","node_proof_id":strings.Repeat("a",64),"router_api":"http://10.77.0.1:8787","api_token":"captured-token","endpoint":"192.0.2.44","dns_mode":"home","adguard_ipv4":"192.168.50.133","kill_switch_policy":"always","mtu_policy":"auto","ipv6_mode":"off","home_lan_access":false})
 node,err:=mobilemultihop.NewNodeProfile("shadowsocks",string(assets),string(profile),"","");if err!=nil{t.Fatal(err)}
 policy,err:=mobilemultihop.NewDesktopNodePolicy(node,strings.Repeat("a",32),target);if err!=nil{t.Fatal(err)};return policy
}
func TestActualPairedReaderConfirmation(t *testing.T){
 for _,fault:=range []string{"original","instance","reader","platform","session","config","fixed-alias","detached","readback","source","name","unicode","index","overflow","mtu","cancelled","lock-expiry"}{
  t.Run(fault,func(t *testing.T){
   policy:=original(t,"darwin");meta:=policy.Metadata();box:=&Box{1};reader:=&Box{2}
   owner:=&RouterVPNDesktopNodePhysical{instance:box,inbound:reader,policy:policy,network:&modeledNetwork{session:meta.SessionID,source:meta.SourceSHA256},name:"utun992",index:771,mtu:1400}
   ctx:=t.Context();session,config,name,index,mtu:=meta.SessionID,meta.ConfigSHA256,owner.name,owner.index,owner.mtu
   switch fault{
   case "instance":box=&Box{3}
   case "reader":reader=&Box{3}
   case "platform":owner.policy=original(t,"linux");m:=owner.policy.(*mobilemultihop.DesktopNodePolicy).Metadata();owner.network.source=m.SourceSHA256;config=m.ConfigSHA256
   case "session":session=strings.Repeat("b",32)
   case "config":config=strings.Repeat("b",64)
   case "fixed-alias":owner.interfaceName="utun992"
   case "detached":owner.detached=true
   case "readback":owner.refused=true
   case "source":owner.network.refused=true
   case "name":name="utun993"
   case "unicode":name="utun９９２"
   case "index":index++
   case "overflow":index=int(uint64(1)<<32)
   case "mtu":mtu++
   case "cancelled":var cancel context.CancelFunc;ctx,cancel=context.WithCancel(ctx);cancel()
   case "lock-expiry":var cancel context.CancelFunc;ctx,cancel=context.WithTimeout(ctx,10*time.Millisecond);defer cancel();owner.mu.Lock();defer owner.mu.Unlock()
   }
   err:=owner.ConfirmPairedDarwinMTUReader(ctx,box,reader,session,config,name,index,mtu)
   if (err==nil)!=(fault=="original"){t.Fatal("paired reader causal refusal failed",fault,err)}
   if fault=="original"&&owner.reads!=1{t.Fatal("original native readback omitted")}
  })
 }
}
'''

@cache
def box_gate():
    # Load after the native gate has finished importing its own reader modules.
    spec = importlib.util.spec_from_file_location('darwin_mtu_box_gate', ROOT/'deploy/test_darwin_node_child_tun.py')
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    return gate


def execute_box_variant(work, label, go, environment):
    gate = box_gate()
    return gate.ORDERED_MTU.execute_mtu_variant(gate, work, label, go, environment, owner='box')


def execute(root=ROOT,go='go',environment=None):
    captured=dict(os.environ if environment is None else environment, GOTOOLCHAIN='local')
    raw=(root/'mobile/desktop/node_box_physical.go.tmpl').read_text()
    start=raw.index('func (owner *RouterVPNDesktopNodePhysical) ConfirmPairedDarwinMTUReader(')
    end=raw.index('\nfunc ',start+1)
    method=raw[start:end]
    lock=(root/'mobile/strategy/observation.go.tmpl').read_text()
    lock=lock[:lock.index('func RouterVPNInboundContext(')]+'\ntype Inbound interface{}\n'
    controls={
      'foreign-instance':('owner.instance != instance','false'),
      'foreign-reader':('owner.inbound != next','false'),
      'wrong-platform':('meta.TargetOS != "darwin"','false'),
      'changed-readback':('actualName != name || actualIndex != index || actualMTU != mtu','false'),
    }
    variants=[('original',method)]+[(name,method.replace(before,after,1)) for name,(before,after) in controls.items()]
    for before,_ in controls.values():
        if method.count(before)!=1:raise ValueError('paired reader mutation lost its exact source boundary')
    with tempfile.TemporaryDirectory(prefix='paired-reader-confirmation-') as temp:
        work=Path(temp);(work/'adapter').mkdir()
        (work/'adapter/adapter.go').write_text(lock)
        (work/'go.mod').write_text('module router-vpn/paired-mtu-fixture\n\ngo 1.26.3\nrequire router-vpn v0.0.0\nreplace router-vpn => '+str(root)+'\n')
        (work/'confirmation_test.go').write_text(TEST)
        for label,source in variants:
            # Removing the readback comparison must still compile so only the
            # original executable authority checks determine the verdict.
            if label=='changed-readback':source=source.replace('actualName, actualIndex, actualMTU, err :=','_, _, _, err =',1)
            (work/'confirmation.go').write_text(HEADER+source)
            result=execute_box_variant(work,label,go,captured)
            output=result.stdout
            if label=='original':
                if result.returncode or output.count('--- PASS: TestActualPairedReaderConfirmation/')!=17 or 'DATA RACE' in output:raise AssertionError(output)
            elif result.returncode==0 or 'paired reader causal refusal failed' not in output or any(word in output for word in ('build failed','DATA RACE','panic:')):
                raise AssertionError('causal original-reader control failed: '+label+'\n'+output)
            print('Paired Darwin reader confirmation: '+label+' verified',flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--go',default='go');args=parser.parse_args();execute(go=args.go)
