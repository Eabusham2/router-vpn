#!/usr/bin/env python3
"""Compile the shipping Apple typed restore and explicit Last capture.

Last source framing runs the exact shipping Go bridge constructors and shared
record parser. Actual native-reader/Instance.Close ownership is an explicit
refusing-by-default Libbox boundary; no Apple SDK, TUN or relay proof is claimed.
"""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile
import sys

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
spec=importlib.util.spec_from_file_location('execution_source',ROOT/'deploy/test_ios_node_chain_execution_capture.py')
SOURCE=importlib.util.module_from_spec(spec);spec.loader.exec_module(SOURCE)
# Execute the actual canonical source/Last bridge bodies. Native lifecycle is
# deliberately absent: the shim owns only immutable preparation and Last.
bridge=(ROOT/'mobile/chain_execution/bridge.go.tmpl').read_text()
bridge=bridge[bridge.index('const routerNodeChainExecutionLaunchKind'):bridge.index('func (m *RouterNodeChainExecution) ProgressJSON')]
last=(ROOT/'mobile/chain_execution/last.go.tmpl').read_text()
last=last[last.index('func RouterNodeChainExecutionFromLast'):last.index('// Capture only')]
connect=(ROOT/'mobile/chain_execution/connect.go.tmpl').read_text()
connect_const=connect[connect.index('const routerNodeChainCONNECTExecutionLaunchKind'):connect.index('type routerNodeCONNECTExecutionServerKey')]
connect=connect[connect.index('func NewRouterNodeChainCONNECTExecution('):connect.index('// The typed execution plan creates')]
socks=(ROOT/'mobile/chain_execution/socks.go.tmpl').read_text()
socks_const=socks[socks.index('const routerNodeChainSOCKSExecutionLaunchKind'):socks.index('type routerNodeSOCKSExecutionServerKey')]
socks=socks[socks.index('func NewRouterNodeChainSOCKSExecution('):socks.index('// The typed execution plan creates')]
openvpn=(ROOT/'mobile/chain_execution/openvpn.go.tmpl').read_text()
openvpn_const=openvpn[openvpn.index('const routerNodeChainOpenVPNExecutionLaunchKind'):openvpn.index('type routerNodeOpenVPNExecutionServerKey')]
openvpn=openvpn[openvpn.index('func RouterNodeChainOpenVPNExecutionFromLaunch('):openvpn.index('// The typed execution plan creates')]
GO=SOURCE.GO[:SOURCE.GO.index('type executionEnvelope')]
GO=GO.replace(';libbox "router-vpn/mobile"','')
GO=GO.replace('"fmt"','"fmt";"errors";"net/url";"router-vpn/internal/multihoprelay"',1)
GO=GO.replace(' case "execution-new":',r'''
 case "socks-execution-last":var m *RouterNodeChainExecution;m,err=RouterNodeChainSOCKSExecutionFromLast(r.Source,r.Mode,r.Policy);if err==nil{value,err=executionReceipt(m)}
 case "openvpn-execution-last":var m *RouterNodeChainExecution;m,err=RouterNodeChainOpenVPNExecutionFromLast(r.Source,r.Mode,r.Policy);if err==nil{value,err=executionReceipt(m)}
 case "openvpn-execution-last-record":value,err=executionSavedRecordWithServer(r.Source,r.Mode,r.Policy)
 case "connect-execution-last":var m *RouterNodeChainExecution;m,err=RouterNodeChainCONNECTExecutionFromLast(r.Source,r.Mode,r.Policy);if err==nil{value,err=executionReceipt(m)}
 case "execution-last":var m *RouterNodeChainExecution;m,err=RouterNodeChainExecutionFromLast(r.Source,r.Mode,r.Policy);if err==nil{value,err=executionReceipt(m)}
 case "execution-last-record":value,err=executionSavedRecord(r.Source,r.Mode)
 case "execution-typed-readback":value,err=executionTypedReadback(r.Source)
 case "execution-new":''',1)
GO+=r'''
var errRouterNodeChainExecution=errors.New("execution source")
type RouterNodeChainExecution struct{prep *mobilemultihop.NodeChainExecutionPreparation;last *mobilemultihop.NodeChainExecutionLast}
'''+bridge+last+connect_const+connect+socks_const+socks+openvpn_const+openvpn+r'''
func executionReceipt(m *RouterNodeChainExecution)(string,error){
 launch,err:=m.LaunchInput();if err!=nil{return "",err}
 raw,err:=json.Marshal(map[string]string{"source":m.Source(),"source_sha256":m.SourceSHA256(),"config":m.Config(),"config_sha256":m.ConfigSHA256(),"local_source_sha256":m.LocalSourceSHA256(),"requested":m.RequestedExecution(),"launch":launch});return string(raw),err
}
func connectExecutionNew(input,requested string)(string,error){m,err:=NewRouterNodeChainCONNECTExecution(input,requested);if err!=nil{return "",err};return executionReceipt(m)}
func connectExecutionOpen(input string)(string,error){m,err:=NewRouterNodeChainCONNECTExecutionLaunch(input);if err!=nil{return "",err};return executionReceipt(m)}
func socksExecutionNew(input,requested string)(string,error){m,err:=NewRouterNodeChainSOCKSExecution(input,requested);if err!=nil{return "",err};return executionReceipt(m)}
func socksExecutionOpen(input string)(string,error){m,err:=NewRouterNodeChainSOCKSExecutionLaunch(input);if err!=nil{return "",err};return executionReceipt(m)}
func openVPNExecutionNew(input,requested string)(string,error){m,err:=RouterNodeChainOpenVPNExecutionFromLaunch(input,requested);if err!=nil{return "",err};return executionReceipt(m)}
func openVPNExecutionOpen(input string)(string,error){m,err:=NewRouterNodeChainOpenVPNExecutionLaunch(input);if err!=nil{return "",err};return executionReceipt(m)}
func capturedExecution(input string)(*RouterNodeChainExecution,error){
 var launch routerNodeChainExecutionLaunch;if err:=json.Unmarshal([]byte(input),&launch);err!=nil{return nil,err}
 if launch.Kind==routerNodeChainCONNECTExecutionLaunchKind{return NewRouterNodeChainCONNECTExecutionLaunch(input)}
 if launch.Kind==routerNodeChainSOCKSExecutionLaunchKind{return NewRouterNodeChainSOCKSExecutionLaunch(input)}
 if launch.Kind==routerNodeChainOpenVPNExecutionLaunchKind{return NewRouterNodeChainOpenVPNExecutionLaunch(input)}
 return NewRouterNodeChainExecutionLaunch(input)
}
func executionNew(input,requested string)(string,error){m,err:=RouterNodeChainExecutionFromLaunch(input,requested);if err!=nil{return "",err};return executionReceipt(m)}
func executionOpen(input string)(string,error){m,err:=capturedExecution(input);if err!=nil{return "",err};return executionReceipt(m)}
type savedLast struct{
 Schema int `json:"schema"`;LocalSourceSHA256 string `json:"local_source_sha256"`;LocalInputSHA256 string `json:"local_input_sha256"`
 Setting string `json:"setting"`;Execution string `json:"execution"`;Target string `json:"target"`
 Descriptor multihoprelay.NodeChainDescriptor `json:"descriptor"`;DescriptorSHA256 string `json:"descriptor_sha256"`;DNSPolicySHA256 string `json:"dns_policy_sha256"`
 EntryHost string `json:"entry_host"`;Peer string `json:"peer"`;FirstPort int `json:"first_port"`;LastPort int `json:"last_port"`;Port int `json:"listen_port"`
 DesktopTargetOS string `json:"desktop_target_os,omitempty"`;Digest string `json:"digest"`
}
func digest(raw []byte)string{sum:=sha256.Sum256(raw);return hex.EncodeToString(sum[:])}
func executionSavedRecord(input,selected string)(string,error){
 return executionSavedRecordWithServer(input,selected,"")
}
func executionSavedRecordWithServer(input,selected,serverSource string)(string,error){
 m,err:=capturedExecution(input);if err!=nil{return "",err}
 var source mobilemultihop.NodeChainSource;if err=json.Unmarshal([]byte(m.prep.LocalSource()),&source);err!=nil{return "",err}
 var proof mobilemultihop.NodeChainProof
 if m.prep.RequiresOpenVPNExecutionObserver(){original,e:=m.prep.OriginalOpenVPNSource();if e!=nil{return "",e};proof=original.ProofInventory()[0]}else if m.prep.RequiresSOCKSExecutionObserver(){original,e:=m.prep.OriginalSOCKSSource();if e!=nil{return "",e};_,meta,e:=original.ReadValidated();if e!=nil{return "",e};proof=meta.Proofs[0]}else if m.prep.RequiresCONNECTExecutionObserver(){original,e:=m.prep.OriginalCONNECTSource();if e!=nil{return "",e};_,meta,e:=original.ReadValidated();if e!=nil{return "",e};proof=meta.Proofs[0]}else{chain,e:=mobilemultihop.NewNodeChain(m.prep.LocalSource());if e!=nil{return "",e};proof=chain.ProofInventory()[0]}
 raw,err:=json.Marshal(mobilemultihop.NodeChainServerSource{Schema:source.Schema,EntryID:proof.ProfileID,EntryNodeID:proof.NodeID,EntryMode:proof.Mode,Nodes:source.Nodes[1:],IdentitySources:source.IdentitySources[1:]});if err!=nil{return "",err}
 var policy *mobilemultihop.NodeChainServerPolicy
 if m.prep.RequiresOpenVPNExecutionObserver(){if serverSource==""{return "",fmt.Errorf("independent original OpenVPN Server source required")};policy,err=mobilemultihop.NewNodeChainOpenVPNServerPolicy(serverSource)}else if m.prep.RequiresSOCKSExecutionObserver(){policy,err=mobilemultihop.NewNodeChainSOCKSServerPolicy(string(raw))}else if m.prep.RequiresCONNECTExecutionObserver(){policy,err=mobilemultihop.NewNodeChainCONNECTServerPolicy(string(raw))}else{policy,err=mobilemultihop.NewNodeChainServerPolicy(string(raw))};if err!=nil{return "",err};descriptor:=policy.Descriptor();identity,err:=descriptor.Digest();if err!=nil{return "",err}
 discovery,err:=m.prep.Discovery();if err!=nil{return "",err};api,err:=url.Parse(discovery.API);if err!=nil{return "",err}
 record:=savedLast{Schema:1,LocalSourceSHA256:m.LocalSourceSHA256(),LocalInputSHA256:digest([]byte(m.prep.LocalSource())),Setting:m.RequestedExecution(),Execution:selected,Target:mobilemultihop.Targets[0],Descriptor:descriptor,DescriptorSHA256:identity,DNSPolicySHA256:descriptor.DNSPolicySHA256,EntryHost:api.Hostname(),Peer:"10.80.0.2",FirstPort:27100,LastPort:27107,Port:27104}
 raw,err=json.Marshal(record);if err!=nil{return "",err};record.Digest=digest(append([]byte("routervpn-node-chain-execution-last-v1\x00"),raw...));raw,err=json.Marshal(record);if err!=nil{return "",err}
 if _,err=mobilemultihop.ParseNodeChainExecutionLast(string(raw),m.prep);err!=nil{return "",err};return string(raw),nil
}
// Model only the native typed-readback boundary. No OS value is claimed here:
// the actual typed shared/native projection has separate mandatory gates.
func executionTypedReadback(input string)(string,error){
 m,err:=capturedExecution(input);if err!=nil{return "",err}
 receipt,err:=executionReceipt(m);if err!=nil{return "",err};var fields map[string]string;_ = json.Unmarshal([]byte(receipt),&fields)
 var graph map[string]any;if err=json.Unmarshal([]byte(fields["config"]),&graph);err!=nil{return "",err};inbounds:=graph["inbounds"].([]any);inbounds[0].(map[string]any)["mtu"]=1400
 raw,err:=json.Marshal(graph);if err!=nil{return "",err};fields["config"]=string(raw);fields["config_sha256"]=digest(raw)
 var launch routerNodeChainExecutionLaunch;_ = json.Unmarshal([]byte(fields["launch"]),&launch);launch.ConfigSHA256=fields["config_sha256"];raw,err=json.Marshal(launch);if err!=nil{return "",err};fields["launch"]=string(raw)
 raw,err=json.Marshal(fields);return string(raw),err
}
'''
# All native proof is refused unless this test names and opens the exact
# original plan. The restore factory cannot manufacture a native join.
LIBBOX=SOURCE.LIBBOX+r'''
private final class SavedFault:@unchecked Sendable{static let shared=SavedFault();private let lock=NSLock();private var value="";func set(_ value:String){lock.lock();self.value=value;lock.unlock()};func take()->String{lock.lock();defer{lock.unlock()};let old=value;value="";return old}}
public func LibboxTestSavedFault(_ value:String){SavedFault.shared.set(value)}
'''
LIBBOX=LIBBOX.replace('public final class LibboxRouterNodeChainExecutionRestoreCapture {}',r'''
public final class LibboxRouterNodeChainExecutionRestoreCapture {
 let owner:LibboxRouterNodeChainExecution;var claimed=false
 init(_ owner:LibboxRouterNodeChainExecution){self.owner=owner}
}
''')
LIBBOX=LIBBOX.replace('private var receipt:[String:String];private var closed=false;private var launchError=false',r'''
 private var receipt:[String:String];private var closed=false;private var launchError=false
 private var proved=false,joined=false;private var selected="",saved="";private var restore:LibboxRouterNodeChainExecutionRestoreCapture?
 private var closeFailures=0
 public var restoreFactoryCalls=0
 public func fixtureProve(_ value:String,_ record:String){proved=true;selected=value;saved=record}
 public func fixtureJoin(){joined=true}
 public func fixtureFailClose(){closeFailures=1}
 public func fixtureChoice(_ value:String){selected=value}
 public func fixtureUnprove(){proved=false}
 public var fixtureClosed:Bool{closed}
 public func fixtureSaved()->String{saved}
''')
LIBBOX=LIBBOX.replace('public func healthy()->Bool{false}','public func healthy()->Bool{proved && !closed}')
LIBBOX=LIBBOX.replace('public func execution()->String{""}','public func execution()->String{closed ? "":selected}')
LIBBOX=LIBBOX.replace('public func nativeClosed()->Bool{false}','public func nativeClosed()->Bool{closed && joined}')
LIBBOX=LIBBOX.replace('public func captureRestore()throws->LibboxRouterNodeChainExecutionRestoreCapture?{throw NSError(domain:"SourceOnly",code:1)}',r'''
 public func captureRestore()throws->LibboxRouterNodeChainExecutionRestoreCapture?{guard healthy()else{throw NSError(domain:"UnprovedCapture",code:1)};return LibboxRouterNodeChainExecutionRestoreCapture(self)}
''')
LIBBOX=LIBBOX.replace('public func requireRestore(_ value:LibboxRouterNodeChainExecutionRestoreCapture)throws{throw NSError(domain:"SourceOnly",code:1)}',r'''
 public func requireRestore(_ value:LibboxRouterNodeChainExecutionRestoreCapture)throws{guard restore===value,value.claimed,value.owner.nativeClosed(),!closed else{throw NSError(domain:"WrongReturnedNativeOwner",code:1)}}
 func restored(_ value:LibboxRouterNodeChainExecutionRestoreCapture){restore=value}
''')
LIBBOX=LIBBOX.replace('public func captureLastJSON(_ error:UnsafeMutablePointer<NSError?>?)->String{error?.pointee=NSError(domain:"SourceOnly",code:1);return ""}',r'''
 public func captureLastJSON(_ error:UnsafeMutablePointer<NSError?>?)->String{guard healthy()else{error?.pointee=NSError(domain:"UnprovedLast",code:1);return ""};return saved}
''')
before='public func close()throws{closed=true;ReturnedOwnerFault.shared.close(self)}'
assert LIBBOX.count(before)==1, 'original execution close fixture changed'
LIBBOX=LIBBOX.replace(before,'public func close()throws{if closeFailures>0{closeFailures-=1;throw NSError(domain:"PendingRemoteJoin",code:1)};closed=true;ReturnedOwnerFault.shared.close(self)}',1)
before='public func LibboxNewRouterNodeChainExecutionRestore(_ value:LibboxRouterNodeChainExecutionRestoreCapture,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{error?.pointee=NSError(domain:"SourceOnly",code:1);return nil}'
assert LIBBOX.count(before)==1
LIBBOX=LIBBOX.replace(before,r'''
public func LibboxNewRouterNodeChainExecutionRestore(_ value:LibboxRouterNodeChainExecutionRestoreCapture,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{api(error){
 value.owner.restoreFactoryCalls+=1
 guard value.owner.nativeClosed(),!value.claimed else{throw NSError(domain:"MissingOriginalNativeJoin",code:1)};value.claimed=true
 var failure:NSError?;let launch=value.owner.launchInput(&failure);if let failure{throw failure}
 let fault=SavedFault.shared.take();let next=try executionMake("execution-typed-readback",launch,"")
 if fault != "wrong-restore"{next.restored(value)}
 return next
}}
''')
before='public func LibboxRouterNodeChainExecutionFromLast(_ input:String,_ requested:String,_ record:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{error?.pointee=NSError(domain:"SourceOnly",code:1);return nil}'
assert LIBBOX.count(before)==1
LIBBOX=LIBBOX.replace(before,r'''
public func LibboxRouterNodeChainExecutionFromLast(_ input:String,_ requested:String,_ record:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{api(error){
 let fault=SavedFault.shared.take()
 let raw=try bridge(["Op":"execution-last","Source":input,"Mode":requested,"Policy":record])
 if fault=="drop-last"{return try executionMake("execution-new",input,requested)}
 return try LibboxRouterNodeChainExecution(JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [String:String])
}}
public func LibboxTestSavedLast(_ input:String,_ selected:String)throws->String{try bridge(["Op":"execution-last-record","Source":input,"Mode":selected])}
''')
# Typed Last uses the exact new exported bridge body above, not a generic parser.
before='public func LibboxRouterNodeChainCONNECTExecutionFromLast(_ input:String,_ requested:String,_ record:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{error?.pointee=NSError(domain:"SourceOnly",code:1);return nil}'
assert LIBBOX.count(before)==1
LIBBOX=LIBBOX.replace(before,r'''
public func LibboxRouterNodeChainCONNECTExecutionFromLast(_ input:String,_ requested:String,_ record:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{api(error){
 let fault=SavedFault.shared.take()
 let raw=try bridge(["Op":"connect-execution-last","Source":input,"Mode":requested,"Policy":record])
 if fault=="drop-last"{return try executionMake("connect-execution-new",input,requested)}
 return try LibboxRouterNodeChainExecution(JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [String:String])
}}
public func LibboxTestCONNECTExecutionFixture(_ kind:String)throws->String{try bridge(["Op":"chain-connect-fixture","Mode":kind])}
''')
before='public func LibboxRouterNodeChainSOCKSExecutionFromLast(_ input:String,_ requested:String,_ record:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{error?.pointee=NSError(domain:"SourceOnly",code:1);return nil}'
assert LIBBOX.count(before)==1
LIBBOX=LIBBOX.replace(before,r'''
public func LibboxRouterNodeChainSOCKSExecutionFromLast(_ input:String,_ requested:String,_ record:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{api(error){
 let fault=SavedFault.shared.take()
 let raw=try bridge(["Op":"socks-execution-last","Source":input,"Mode":requested,"Policy":record])
 if fault=="drop-last"{return try executionMake("socks-execution-new",input,requested)}
 return try LibboxRouterNodeChainExecution(JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [String:String])
}}
''')
before='public func LibboxRouterNodeChainOpenVPNExecutionFromLast(_ input:String,_ requested:String,_ record:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{error?.pointee=NSError(domain:"SourceOnly",code:1);return nil}'
assert LIBBOX.count(before)==1
LIBBOX=LIBBOX.replace(before,r'''
public func LibboxRouterNodeChainOpenVPNExecutionFromLast(_ input:String,_ requested:String,_ record:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{api(error){
 let fault=SavedFault.shared.take()
 let raw=try bridge(["Op":"openvpn-execution-last","Source":input,"Mode":requested,"Policy":record])
 if fault=="drop-last"{return try executionMake("openvpn-execution-new",input,requested)}
 return try LibboxRouterNodeChainExecution(JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [String:String])
}}
public func LibboxTestOpenVPNExecutionLast(_ input:String,_ selected:String,_ server:String)throws->String{try bridge(["Op":"openvpn-execution-last-record","Source":input,"Mode":selected,"Policy":server])}
''')
connect_swift=(ROOT/'deploy/test_ios_connect_execution_capture.py').read_text()
connect_fixture=connect_swift[connect_swift.index('func connectFixture('):connect_swift.index('@main struct Tests{')]
SWIFT=SOURCE.SWIFT[:SOURCE.SWIFT.index('@main struct Tests')]+connect_fixture+r'''
func socksFixture(_ mode:String,_ requested:String,_ authenticated:Bool)throws->[Data]{
 let raw=try LibboxTestSOCKSFixture()
 var bundles=try appFixture((JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [Any]).map{try data($0)})
 bundles[2]=try editProfile(bundles[2]){p in p["multihop_execution"]=requested;var nodes=p["multihop_nodes"] as! [[String:Any]];nodes[0]["mode"]=mode;p["multihop_nodes"]=nodes}
 if !authenticated{bundles[1]=try editProfile(bundles[1]){p in var ext=p["external"] as! [String:Any],proxy=ext["socks5"] as! [String:Any];proxy["username"]="";proxy["password"]="";ext["socks5"]=proxy;p["external"]=ext}}
 return bundles
}
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ yes:Bool,_ name:String){guard yes else{fatalError(name)};checks+=1}
 @MainActor static func reject(_ name:String,_ action:()throws->Void){do{try action();fatalError("ACCEPTED "+name)}catch{checks+=1}}
 @MainActor static func main()throws{
  defer{LibboxTestClose()}
  var paths=[[Data]]()
  for count in [2,3,4]{for mixed in [false,true]{paths.append(try fixture(count,"off","auto",mixed))}}
  for first in ["wg","awg2-fast","awg2-strong"]{paths.append(try importedFixture("auto",first,"2022-blake3-aes-256-gcm"))}
  for kind in ["http-connect","https-connect"]{paths.append(try connectFixture(kind,"wg","auto"))}
  for mode in ["wg","awg2-fast","awg2-strong"]{for authenticated in [false,true]{paths.append(try socksFixture(mode,"auto",authenticated))}}
  for bundles in paths{for selected in ["local","server"]{
   let final=try profile(bundles.last!)
   let original=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"auto")
   let saved=try LibboxTestSavedLast(original.launchInput,selected)
   original.plan.fixtureProve(selected,saved)
   check(try original.captureLastRecord()==saved,"actual saved choice changed")
   let last=try IOSNodeChainExecutionCapture.reopenLast(original.launchInput,selectedProfile:final,record:saved)
   let fields=try object(Data(last.launchInput.utf8))
   check(fields["schema"] as? Int==2 && fields["last"] as? String==saved && fields.count==6,"Last lost explicit exact schema2")
   check(last.source==original.source && last.config==original.config && last.ordinaryLaunchInput==original.launchInput,"Last changed original member source")
   check(!last.healthy() && !last.nativeClosed(),"durable Last fabricated native ownership")
   if original.isSOCKS{
    check(last.isSOCKS && fields["kind"] as? String=="routervpn-node-chain-socks-execution-preparation-input","SOCKS Last changed typed family")
    var failure:NSError?
    check(LibboxRouterNodeChainExecutionFromLast(original.local.launchInput,"auto",saved,&failure)==nil && failure != nil,"generic Last borrowed SOCKS source")
    failure=nil;check(LibboxRouterNodeChainCONNECTExecutionFromLast(original.local.launchInput,"auto",saved,&failure)==nil && failure != nil,"CONNECT Last borrowed SOCKS source")
    for changed in [saved+" ",saved.replacingOccurrences(of:"\"listen_port\":27104",with:"\"listen_port\":27105"),"{}"]{
     reject("mutated SOCKS Last record"){_ = try IOSNodeChainExecutionCapture.reopenLast(original.launchInput,selectedProfile:final,record:changed)}
    }
    LibboxTestSavedFault("drop-last")
    reject("native Last schema downgrade"){_ = try IOSNodeChainExecutionCapture.reopenLast(original.launchInput,selectedProfile:final,record:saved)}
   }
   reject("Last ordinary downgrade"){_ = try IOSNodeChainExecutionCapture.reopen(last.launchInput,selectedProfile:final)}
   let replay=try IOSNodeChainExecutionCapture.reopenLastLaunch(last.launchInput,selectedProfile:final)
   check(replay.launchInput==last.launchInput && replay.ordinaryLaunchInput==original.launchInput,"explicit Last replay lost saved source")
   reject("noncanonical Last launch"){_ = try IOSNodeChainExecutionCapture.reopenLastLaunch(last.launchInput+" ",selectedProfile:final)}
   replay.plan.fixtureProve(selected,saved);check(try replay.execution()==selected,"Last concrete proof missing")
   replay.plan.fixtureChoice(selected=="server" ? "local":"server")
   reject("changed selected execution"){_ = try replay.execution()}
   try replay.close();try last.close()
   let restore=try original.captureRestoration()
   reject("restore before shared join"){_ = try restore.makeCapture(ordinaryInput:original.launchInput,selectedProfile:final)}
   original.plan.fixtureFailClose();reject("failed original remote close"){try original.close()}
   reject("restore after failed shared join"){_ = try restore.makeCapture(ordinaryInput:original.launchInput,selectedProfile:final)}
   try original.close()
   reject("restore before native join"){_ = try restore.makeCapture(ordinaryInput:original.launchInput,selectedProfile:final)}
   check(original.plan.restoreFactoryCalls==0,"native factory entered before original Instance.Close")
   original.plan.fixtureJoin()
   var changed=final;changed["api_token"]="replaced-original-token"
   reject("restore changed original selected source"){_ = try restore.makeCapture(ordinaryInput:original.launchInput,selectedProfile:changed)}
   reject("restore changed original launch"){_ = try restore.makeCapture(ordinaryInput:original.launchInput+" ",selectedProfile:final)}
   let next=try restore.makeCapture(ordinaryInput:original.launchInput,selectedProfile:final)
   check(next.config != original.config && next.configSHA256 != original.configSHA256,"typed readback failed to change actual TUN config")
   check(next.source==original.source && next.sourceSHA256==original.sourceSHA256 && next.ordinaryLaunchInput==original.launchInput,"typed readback normalized original source")
   check(next.isSOCKS==original.isSOCKS && next.isCONNECT==original.isCONNECT,"typed readback changed source family")
   let graph=try object(Data(next.config.utf8));check((graph["inbounds"] as! [[String:Any]])[0]["mtu"] as? Int==1400,"typed readback value lost")
   reject("typed restore serialized as ordinary authority"){_ = try IOSNodeChainExecutionCapture.reopen(next.launchInput,selectedProfile:final)}
   next.plan.fixtureProve(selected,saved);check(try next.captureLastRecord()==saved,"typed Last used changed launch as ordinary authority")
   next.plan.fixtureChoice(selected=="server" ? "local":"server")
   reject("changed selected execution"){_ = try next.execution()}
   reject("second restore claim"){_ = try restore.makeCapture(ordinaryInput:original.launchInput,selectedProfile:final)}
   try next.close()
  }}
  for mode in ["wg","awg2-fast","awg2-strong"]{
   let bundles=try socksFixture(mode,"server",true),final=try profile(bundles.last!)
   let original=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"server")
   let saved=try LibboxTestSavedLast(original.launchInput,"server")
   reject("Server-only SOCKS Last cannot select Local"){_ = try LibboxTestSavedLast(original.launchInput,"local")}
   let last=try IOSNodeChainExecutionCapture.reopenLast(original.launchInput,selectedProfile:final,record:saved)
   check(last.isSOCKS && last.requested=="server","Server-only SOCKS Last changed requested policy")
   try last.close();try original.close()
  }
  let bundles=try fixture(3,"off","auto",true),final=try profile(bundles.last!)
  let original=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"auto")
  let saved=try LibboxTestSavedLast(original.launchInput,"server")
  reject("unproved Last capture"){_ = try original.captureLastRecord()}
  reject("unproved restore capture"){_ = try original.captureRestoration()}
  for changed in [saved+" ",saved.replacingOccurrences(of:"\"listen_port\":27104",with:"\"listen_port\":27105"),"{}"]{
   reject("mutated Last record"){_ = try IOSNodeChainExecutionCapture.reopenLast(original.launchInput,selectedProfile:final,record:changed)}
  }
  LibboxTestSavedFault("drop-last")
  reject("native Last schema downgrade"){_ = try IOSNodeChainExecutionCapture.reopenLast(original.launchInput,selectedProfile:final,record:saved)}
  original.plan.fixtureProve("server",saved)
  let restore=try original.captureRestoration();try original.close();original.plan.fixtureJoin()
  LibboxTestSavedFault("wrong-restore")
  reject("wrong returned native restore owner"){_ = try restore.makeCapture(ordinaryInput:original.launchInput,selectedProfile:final)}
  reject("failed claimed restore reused"){_ = try restore.makeCapture(ordinaryInput:original.launchInput,selectedProfile:final)}
  print("PASS Apple typed restore/Last: \(checks) checks")
 }
}
'''

def main(*, binary_cases=None):
    cases = ((),) if binary_cases is None else tuple(tuple(case) for case in binary_cases)
    if not cases:
        raise AssertionError('The original Last/restore runtime inventory is empty')
    with tempfile.TemporaryDirectory(prefix='.ios-execution-last-',dir=ROOT) as gd,tempfile.TemporaryDirectory(prefix='ios-execution-last-') as wd:
        gd,work=Path(gd),Path(wd);(gd/'main.go').write_text(GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(gd/'main.go')],cwd=ROOT,check=True,timeout=180)
        (work/'Libbox.swift').write_text(LIBBOX);(work/'CryptoKit.swift').write_text(SOURCE.CRYPTO);(work/'Tests.swift').write_text(SWIFT)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        suffix='.dylib' if platform.system()=='Darwin' else '.so'
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(work/'Libbox.swift'),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(work/('libLibbox'+suffix))],check=True,timeout=90)
        link=['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        subprocess.run(options+link+['-emit-module','-emit-library','-module-name','CryptoKit',str(work/'CryptoKit.swift'),'-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/('libCryptoKit'+suffix))],check=True,timeout=90)
        command=options+link+['-lCryptoKit',str(APP/'Models.swift'),str(APP/'IOSMultihopStartLayer.swift'),str(APP/'IOSNodeChainCapture.swift'),str(APP/'IOSImportedOpenVPNSource.swift'),str(APP/'IOSNodeChainCONNECTCapture.swift'),str(APP/'IOSNodeChainSOCKSCapture.swift'),str(APP/'IOSNodeChainProviderCapture.swift')]
        source=APP/'IOSNodeChainExecutionCapture.swift';binary=work/'tests';tests=work/'Tests.swift'
        subprocess.run(command+[str(source),str(tests),'-o',str(binary)],check=True,timeout=90)
        for case in cases:
            subprocess.run([str(binary),str(compiler),*map(str,case)],check=True,timeout=180)
        if '--baseline-only' in sys.argv:return
        text=source.read_text()
        controls=(
            ('choice','expectedExecution == nil || value == expectedExecution','true','ACCEPTED changed selected execution',1),
            ('native-join','guard closed, original.nativeClosed() else','guard closed, true else','native factory entered before original Instance.Close',1),
            ('exact-returned-owner','try plan.requireRestore(native)','_ = native','ACCEPTED wrong returned native restore owner',2),
            ('canonical-last','guard result.launchInput == input else','guard true else','ACCEPTED noncanonical Last launch',2),
            ('last-schema','Self.launchFields(launch, lastRecord: lastRecord),','true,','ACCEPTED native Last schema downgrade',1),
        )
        for name,before,after,witness,count in controls:
            assert text.count(before)==count,(name,text.count(before))
            mutant=work/(name+'.swift');mutant.write_text(text.replace(before,after));binary=work/name
            subprocess.run(command+[str(mutant),str(tests),'-o',str(binary)],check=True,timeout=90)
            result=subprocess.run([str(binary),str(compiler),*map(str,cases[0])],capture_output=True,text=True,timeout=180)
            assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,(result.stdout+result.stderr)[-2500:])
            print('Rejected Apple typed restore/Last control:',name,flush=True)

if __name__=='__main__':main()
