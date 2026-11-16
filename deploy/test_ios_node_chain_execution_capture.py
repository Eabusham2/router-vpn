#!/usr/bin/env python3
"""Execute Apple ordered execution capture with the real shared Go compiler.

Native lifecycle methods are refusing boundaries. No system VPN, privileged
traffic, generated Apple framework or signed-device acceptance is claimed.
"""
from pathlib import Path
import importlib.util
import os
import platform
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
spec=importlib.util.spec_from_file_location('apple_local_capture',ROOT/'deploy/test_ios_node_chain_capture.py')
LOCAL=importlib.util.module_from_spec(spec);spec.loader.exec_module(LOCAL)
GO=LOCAL.GO.replace('"router-vpn/internal/mobileperf"','"router-vpn/internal/mobileperf";libbox "router-vpn/mobile"',1)
# The eight-node layered fixture deliberately configures a 4000-byte packet
# ceiling. This is source capacity, never a measured-path/Jumbo success claim.
assert 'MTU=2000\\n' in GO
GO=GO.replace('MTU=2000\\n','MTU=4000\\n')
anchor=' case "chain-fixture":'
assert GO.count(anchor)==1
GO=GO.replace(anchor,r'''
 case "execution-new":value,err=executionNew(r.Source,r.Mode)
 case "execution-open":value,err=executionOpen(r.Source)
 case "connect-execution-new":value,err=connectExecutionNew(r.Source,r.Mode)
 case "connect-execution-open":value,err=connectExecutionOpen(r.Source)
 case "socks-execution-new":value,err=socksExecutionNew(r.Source,r.Mode)
 case "socks-execution-open":value,err=socksExecutionOpen(r.Source)
 case "openvpn-execution-new":value,err=openVPNExecutionNew(r.Source,r.Mode)
 case "openvpn-execution-open":value,err=openVPNExecutionOpen(r.Source)
 case "execution-digest":sum:=sha256.Sum256([]byte(r.Source));value=hex.EncodeToString(sum[:])
'''+anchor,1)+r'''
type executionEnvelope struct{Kind string `json:"kind"`;Schema int `json:"schema"`;Source string `json:"source"`;SourceSHA string `json:"source_sha256"`;ConfigSHA string `json:"config_sha256"`}
func executionPrepared(p *mobilemultihop.NodeChainExecutionPreparation)(string,error){
 kind:="routervpn-node-chain-execution-preparation-input";if p.RequiresCONNECTExecutionObserver(){kind="routervpn-node-chain-connect-execution-preparation-input"};if p.RequiresSOCKSExecutionObserver(){kind="routervpn-node-chain-socks-execution-preparation-input"};if p.RequiresOpenVPNExecutionObserver(){kind="routervpn-node-chain-openvpn-execution-preparation-input"}
 launch,err:=json.Marshal(executionEnvelope{kind,1,p.Source(),p.SourceSHA256(),p.ConfigSHA256()});if err!=nil{return "",err}
 raw,err:=json.Marshal(map[string]string{"source":p.Source(),"source_sha256":p.SourceSHA256(),"config":p.Config(),"config_sha256":p.ConfigSHA256(),"local_source_sha256":p.LocalSourceSHA256(),"requested":p.Execution(),"launch":string(launch)});return string(raw),err
}
func connectExecutionNew(input,requested string)(string,error){
 original,err:=mobilemultihop.NewNodeChainCONNECTSource(input);if err!=nil{return "",err}
 p,err:=mobilemultihop.NewNodeChainCONNECTExecutionPreparation(original,requested);if err!=nil{return "",err};return executionPrepared(p)
}
func connectExecutionOpen(input string)(string,error){
 if err:=libbox.RouterValidatePrivateNodeJSON(input);err!=nil{return "",err}
 var e executionEnvelope;if err:=json.Unmarshal([]byte(input),&e);err!=nil{return "",err}
 canonical,err:=json.Marshal(e);if err!=nil||string(canonical)!=input||e.Kind!="routervpn-node-chain-connect-execution-preparation-input"||e.Schema!=1{return "",fmt.Errorf("noncanonical typed private launch")}
 p,err:=mobilemultihop.ParseNodeChainCONNECTExecutionPreparation(e.Source);if err!=nil{return "",err}
 if p.Source()!=e.Source||p.SourceSHA256()!=e.SourceSHA||p.ConfigSHA256()!=e.ConfigSHA{return "",fmt.Errorf("changed typed execution source")};return executionPrepared(p)
}
func socksExecutionNew(input,requested string)(string,error){
 original,err:=mobilemultihop.NewNodeChainSOCKSSource(input);if err!=nil{return "",err}
 p,err:=mobilemultihop.NewNodeChainSOCKSExecutionPreparation(original,requested);if err!=nil{return "",err};return executionPrepared(p)
}
func socksExecutionOpen(input string)(string,error){
 if err:=libbox.RouterValidatePrivateNodeJSON(input);err!=nil{return "",err}
 var e executionEnvelope;if err:=json.Unmarshal([]byte(input),&e);err!=nil{return "",err}
 canonical,err:=json.Marshal(e);if err!=nil||string(canonical)!=input||e.Kind!="routervpn-node-chain-socks-execution-preparation-input"||e.Schema!=1{return "",fmt.Errorf("noncanonical original SOCKS private launch")}
 p,err:=mobilemultihop.ParseNodeChainSOCKSExecutionPreparation(e.Source);if err!=nil{return "",err}
 if p.Source()!=e.Source||p.SourceSHA256()!=e.SourceSHA||p.ConfigSHA256()!=e.ConfigSHA{return "",fmt.Errorf("changed original SOCKS execution source")};return executionPrepared(p)
}
func openVPNExecutionNew(input,requested string)(string,error){
 original,err:=mobilemultihop.ParseNodeChainLaunchInput(input);if err!=nil{return "",err}
 p,err:=mobilemultihop.NewNodeChainOpenVPNExecutionPreparation(original,requested);if err!=nil{return "",err};return executionPrepared(p)
}
func openVPNExecutionOpen(input string)(string,error){
 if err:=libbox.RouterValidatePrivateNodeJSON(input);err!=nil{return "",err}
 var e executionEnvelope;if err:=json.Unmarshal([]byte(input),&e);err!=nil{return "",err}
 canonical,err:=json.Marshal(e);if err!=nil||string(canonical)!=input||e.Kind!="routervpn-node-chain-openvpn-execution-preparation-input"||e.Schema!=1{return "",fmt.Errorf("noncanonical original OpenVPN private launch")}
 p,err:=mobilemultihop.ParseNodeChainOpenVPNExecutionPreparation(e.Source);if err!=nil{return "",err}
 if p.Source()!=e.Source||p.SourceSHA256()!=e.SourceSHA||p.ConfigSHA256()!=e.ConfigSHA{return "",fmt.Errorf("changed original OpenVPN execution source")};return executionPrepared(p)
}
func executionNew(input,requested string)(string,error){
 if _,err:=mobilemultihop.ParseNodeChainLaunchInput(input);err!=nil{return "",err}
 var local mobilemultihop.NodeChainSource;if err:=json.Unmarshal([]byte(input),&local);err!=nil{return "",err};raw,err:=json.Marshal(local);if err!=nil{return "",err}
 p,err:=mobilemultihop.NewNodeChainExecutionPreparation(string(raw),requested);if err!=nil{return "",err};return executionPrepared(p)
}
func executionOpen(input string)(string,error){
 if err:=libbox.RouterValidatePrivateNodeJSON(input);err!=nil{return "",err}
 var e executionEnvelope;if err:=json.Unmarshal([]byte(input),&e);err!=nil{return "",err}
 canonical,err:=json.Marshal(e);if err!=nil||string(canonical)!=input||e.Kind!="routervpn-node-chain-execution-preparation-input"||e.Schema!=1{return "",fmt.Errorf("noncanonical private launch")}
 if err:=libbox.RouterValidatePrivateNodeJSON(e.Source);err!=nil{return "",err}
 var s mobilemultihop.NodeChainExecutionPreparationSource;if err:=json.Unmarshal([]byte(e.Source),&s);err!=nil{return "",err}
 p,err:=mobilemultihop.NewNodeChainExecutionPreparation(s.LocalSource,s.Execution);if err!=nil{return "",err}
 if s.Schema!=1||p.Source()!=e.Source||p.SourceSHA256()!=e.SourceSHA||p.ConfigSHA256()!=e.ConfigSHA{return "",fmt.Errorf("changed execution source")}
 return executionPrepared(p)
}
'''
LOCAL_LIBBOX=LOCAL.LIBBOX.replace('PQTest','OrdinarySourceTest')
# A generated bridge can return an owned object together with NSError. Retain
# that exact object in the double and count only its own acknowledged close.
local_close=' public func close()throws{}'
local_begin=LOCAL_LIBBOX.index('public final class LibboxRouterNodeChain {')
local_end=LOCAL_LIBBOX.index('private final class NativeLaunchFault',local_begin)
local_body=LOCAL_LIBBOX[local_begin:local_end]
assert local_body.count(local_close)==1
LOCAL_LIBBOX=LOCAL_LIBBOX[:local_begin]+local_body.replace(local_close,' public func close()throws{ReturnedOwnerFault.shared.close(self)}',1)+LOCAL_LIBBOX[local_end:]
local_factory='public func LibboxNewRouterNodeChain(_ source:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChain?{api(error){try make("chain-new",source)}}'
assert LOCAL_LIBBOX.count(local_factory)==1
LOCAL_LIBBOX=LOCAL_LIBBOX.replace(local_factory,'public func LibboxNewRouterNodeChain(_ source:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChain?{returnedOwner("local-new",error){api(error){try make("chain-new",source)}}}',1)
LIBBOX=LOCAL_LIBBOX+r'''
private final class ReturnedOwnerFault: @unchecked Sendable {
 static let shared=ReturnedOwnerFault();private let lock=NSLock();private var operation="";private var returned:AnyObject?;private var closes=0
 func arm(_ value:String){lock.lock();operation=value;returned=nil;closes=0;lock.unlock()}
 func capture(_ name:String,_ value:AnyObject)->Bool{lock.lock();defer{lock.unlock()};guard operation==name else{return false};operation="";returned=value;return true}
 func close(_ value:AnyObject){lock.lock();if let returned,returned===value{closes+=1};lock.unlock()}
 func closed()->Bool{lock.lock();defer{lock.unlock()};return returned != nil && closes==1}
}
public func LibboxTestReturnedOwnerError(_ operation:String){ReturnedOwnerFault.shared.arm(operation)}
public func LibboxTestReturnedOwnerClosed()->Bool{ReturnedOwnerFault.shared.closed()}
private func returnedOwner<T:AnyObject>(_ operation:String,_ error:UnsafeMutablePointer<NSError?>?,_ make:()->T?)->T?{
 let value=make();if let value,ReturnedOwnerFault.shared.capture(operation,value){error?.pointee=NSError(domain:"ReturnedOriginalOwner",code:1)};return value
}

public final class LibboxCommandServer { public var bindAttempts=0; public init(){} }
private final class ExecutionFault: @unchecked Sendable {
 static let shared=ExecutionFault();let lock=NSLock();var value=""
 func set(_ v:String){lock.lock();value=v;lock.unlock()}
 func take()->String{lock.lock();defer{lock.unlock()};let v=value;value="";return v}
}
public func LibboxTestExecutionFault(_ value:String){ExecutionFault.shared.set(value)}
public func LibboxTestDigest(_ data:Data)throws->[UInt8]{
 let raw=try bridge(["Op":"execution-digest","Source":String(decoding:data,as:UTF8.self)])
 return stride(from:0,to:64,by:2).map{offset in let start=raw.index(raw.startIndex,offsetBy:offset);return UInt8(raw[start..<raw.index(start,offsetBy:2)],radix:16)!}
}
public final class LibboxRouterNodeChainExecutionRestoreCapture {}
public final class LibboxRouterNodeChainExecution {
 private var receipt:[String:String];private var closed=false;private var launchError=false
 init(_ receipt:[String:String])throws{
  self.receipt=receipt
  let fault=ExecutionFault.shared.take()
  switch fault{
  case "config":self.receipt["config"]=receipt["config"]!+" "
  case "requested":self.receipt["requested"]="local"
  case "launch-error":launchError=true
  case "local-node","local-schema","local-identity","local-execution","preparation-schema","launch-schema","openvpn-local-launch":
   var source=try JSONSerialization.jsonObject(with:Data(receipt["source"]!.utf8)) as! [String:Any]
   var local=try JSONSerialization.jsonObject(with:Data((source["local_source"] as! String).utf8)) as! [String:Any]
   if fault=="local-node"{var nodes=local["nodes"] as! [String];nodes.swapAt(0,1);local["nodes"]=nodes}
   if fault=="local-schema"{local["schema"]=(local["schema"] as? Int)==1 ? 2:1}
   if fault=="local-identity"{var identities=local["identity_sources"] as! [String];identities[1]=identities[0];local["identity_sources"]=identities}
   if fault=="local-execution"{local["execution"]="server"}
   source["local_source"]=String(decoding:try JSONSerialization.data(withJSONObject:local,options:[.sortedKeys]),as:UTF8.self)
   if fault=="preparation-schema"{source["schema"]=2}
   if fault=="openvpn-local-launch"{source["openvpn_local_launch"]=(source["openvpn_local_launch"] as! String)+" "}
   self.receipt["source"]=String(decoding:try JSONSerialization.data(withJSONObject:source,options:[.sortedKeys]),as:UTF8.self)
   var launch=try JSONSerialization.jsonObject(with:Data(receipt["launch"]!.utf8)) as! [String:Any];launch["source"]=self.receipt["source"]!
   if fault=="launch-schema"{launch["schema"]=2}
   self.receipt["launch"]=String(decoding:try JSONSerialization.data(withJSONObject:launch,options:[.sortedKeys]),as:UTF8.self)
  default:break
  }
 }
 public func source()->String{receipt["source"]!}
 public func config()->String{receipt["config"]!}
 public func sourceSHA256()->String{receipt["source_sha256"]!}
 public func configSHA256()->String{receipt["config_sha256"]!}
 public func localSourceSHA256()->String{receipt["local_source_sha256"]!}
 public func requestedExecution()->String{receipt["requested"]!}
 public func launchInput(_ error:UnsafeMutablePointer<NSError?>?)->String{if launchError{error?.pointee=NSError(domain:"NativeLaunchFault",code:1)};return receipt["launch"]!}
 public func bindNative(_ server:LibboxCommandServer)throws{server.bindAttempts+=1;throw NSError(domain:"SourceOnly",code:1)}
 public func run(_ server:LibboxCommandServer)throws{throw NSError(domain:"SourceOnly",code:1)}
 public func healthy()->Bool{false}
 public func execution()->String{""}
 public func networkChanged(){}
 public func nativeClosed()->Bool{false}
 public func captureRestore()throws->LibboxRouterNodeChainExecutionRestoreCapture?{throw NSError(domain:"SourceOnly",code:1)}
 public func requireRestore(_ value:LibboxRouterNodeChainExecutionRestoreCapture)throws{throw NSError(domain:"SourceOnly",code:1)}
 public func captureLastJSON(_ error:UnsafeMutablePointer<NSError?>?)->String{error?.pointee=NSError(domain:"SourceOnly",code:1);return ""}
 public func retainsServerCleanup(_ server:LibboxCommandServer)->Bool{false}
 public func close()throws{closed=true;ReturnedOwnerFault.shared.close(self)}
}
func executionMake(_ operation:String,_ source:String,_ requested:String)throws->LibboxRouterNodeChainExecution{
 let raw=try bridge(["Op":operation,"Source":source,"Mode":requested]);return try LibboxRouterNodeChainExecution(JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [String:String])
}
public func LibboxRouterNodeChainExecutionFromLaunch(_ input:String,_ execution:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{returnedOwner("execution-new",error){api(error){try executionMake("execution-new",input,execution)}}}
public func LibboxNewRouterNodeChainExecutionLaunch(_ input:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{returnedOwner("execution-open",error){api(error){try executionMake("execution-open",input,"")}}}
public func LibboxNewRouterNodeChainCONNECTExecution(_ input:String,_ execution:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{returnedOwner("execution-new",error){api(error){try executionMake("connect-execution-new",input,execution)}}}
public func LibboxNewRouterNodeChainCONNECTExecutionLaunch(_ input:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{returnedOwner("execution-open",error){api(error){try executionMake("connect-execution-open",input,"")}}}
public func LibboxRouterNodeChainCONNECTExecutionFromLast(_ input:String,_ requested:String,_ record:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{error?.pointee=NSError(domain:"SourceOnly",code:1);return nil}
public func LibboxNewRouterNodeChainSOCKSExecution(_ input:String,_ execution:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{returnedOwner("execution-new",error){api(error){try executionMake("socks-execution-new",input,execution)}}}
public func LibboxNewRouterNodeChainSOCKSExecutionLaunch(_ input:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{returnedOwner("execution-open",error){api(error){try executionMake("socks-execution-open",input,"")}}}
public func LibboxRouterNodeChainSOCKSExecutionFromLast(_ input:String,_ requested:String,_ record:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{error?.pointee=NSError(domain:"SourceOnly",code:1);return nil}
public func LibboxRouterNodeChainOpenVPNExecutionFromLaunch(_ input:String,_ execution:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{returnedOwner("execution-new",error){api(error){try executionMake("openvpn-execution-new",input,execution)}}}
public func LibboxNewRouterNodeChainOpenVPNExecutionLaunch(_ input:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{returnedOwner("execution-open",error){api(error){try executionMake("openvpn-execution-open",input,"")}}}
public func LibboxRouterNodeChainOpenVPNExecutionFromLast(_ input:String,_ requested:String,_ record:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{error?.pointee=NSError(domain:"SourceOnly",code:1);return nil}
public func LibboxNewRouterNodeChainExecutionRestore(_ value:LibboxRouterNodeChainExecutionRestoreCapture,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{error?.pointee=NSError(domain:"SourceOnly",code:1);return nil}
public func LibboxRouterNodeChainExecutionFromLast(_ input:String,_ requested:String,_ record:String,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainExecution?{error?.pointee=NSError(domain:"SourceOnly",code:1);return nil}
'''
CRYPTO='''import Foundation
import Libbox
public enum SHA256 { public static func hash(data:Data)->[UInt8] { try! LibboxTestDigest(data) } }
'''
SWIFT=r'''
import Foundation
import Libbox
func data(_ value:Any)throws->Data{try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
func object(_ value:Data)throws->[String:Any]{try JSONSerialization.jsonObject(with:value) as! [String:Any]}
func profile(_ value:Data)throws->[String:Any]{try (object(value)["routerProfiles"] as! [[String:Any]])[0]}
func edit(_ value:Data,_ change:(inout [String:Any])->Void)throws->Data{var root=try object(value);change(&root);return try data(root)}
func editProfile(_ value:Data,_ change:(inout [String:Any])->Void)throws->Data{var root=try object(value);var p=(root["routerProfiles"] as! [[String:Any]])[0];change(&p);root["routerProfiles"]=[p];return try data(root)}
func fixture(_ count:Int,_ layer:String,_ requested:String,_ awg:Bool)throws->[Data]{let raw=try awg ? LibboxTestAWGFixture(count,layer):LibboxTestFixture(count,layer);var bundles=try (JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [Any]).map{try data($0)};bundles[count-1]=try editProfile(bundles[count-1]){$0["multihop_execution"]=requested};return bundles}
// Supply the app model's required display fields without replacing any saved
// transport, credential or device policy. The shared compiler owns the source.
func appFixture(_ input:[Data])throws->[Data]{
 try input.enumerated().map{position,value in try editProfile(value){p in
  if p["name"]==nil{p["name"]=p["id"]}
  for key in ["adguard_ipv6","socks_host","socks_username","socks_password"]{if p[key]==nil{p[key]=""}}
  if p["socks_port"]==nil{p["socks_port"]=0}
  if position==input.count-1{p["startup_mode"]="manual";p["auto_connect"]=true}
 }}
}
func importedFixture(_ requested:String,_ first:String,_ method:String,_ count:Int=3)throws->[Data]{
 let middlePosition=count-2,finalPosition=count-1
 var bundles=try fixture(count,"off",requested,false),middle=try object(bundles[middlePosition]),custom=try profile(bundles[middlePosition])
 let id="original-execution-middle",keySize=method=="2022-blake3-aes-128-gcm" ? 16:32
 custom["id"]=id;custom["name"]="Original execution middle";custom["node_kind"]="external";custom.removeValue(forKey:"node_proof_id")
 for key in ["router_api","api_token","adguard_ipv6","socks_host","socks_username","socks_password"]{custom[key]=""};custom["socks_port"]=0
 custom["external"]=["protocol":"shadowsocks","expected_public_ip":"203.0.113.76","shadowsocks":["server":"198.51.100.76","port":443,"method":method,"password":Data(repeating:0,count:keySize).base64EncodedString()]]
 middle["selectedRouterID"]=id;middle["routerProfiles"]=[custom];middle["profiles"]=[String:[String:String]]();bundles[middlePosition]=try data(middle)
 bundles[finalPosition]=try editProfile(bundles[finalPosition]){final in var refs=final["multihop_nodes"] as! [[String:Any]];refs[0]["mode"]=first;refs[middlePosition]=["id":id,"mode":"shadowsocks"];final["multihop_nodes"]=refs}
 return bundles
}
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ yes:Bool,_ name:String){guard yes else{fatalError(name)};checks+=1}
 @MainActor static func reject(_ name:String,_ action:()throws->Void){do{try action();fatalError("ACCEPTED "+name)}catch{checks+=1}}
 @MainActor static func main()throws{
  defer{LibboxTestClose()}
  for count in [4,8] {for requested in ["server","auto"] {
   let long=try importedFixture(requested,"wg","2022-blake3-aes-256-gcm",count)
   let capture:IOSNodeChainExecutionCapture
   do{capture=try IOSNodeChainExecutionCapture.compile(bundles:long,requested:requested)}catch{fatalError("imported SS execution was refused: \(error)")}
   check(capture.members.count==count && capture.members[count-2].profile["node_kind"] as? String=="external","complete imported prefix retains penultimate original")
   let replay=try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(long.last!))
   check(replay.source==capture.source && replay.config==capture.config,"long imported source replays complete original policy")
   try replay.close();try capture.close()
  }}
  for count in [2,3,4,8]{for requested in ["server","auto"]{for awg in [false,true]{for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"]{
   let bundles=try fixture(count,layer,requested,awg)
   let capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested)
   check(capture.members.count==count && capture.requested==requested && capture.local.selectionExecution==requested,"captured count/execution changed")
   var expectedProfile=try profile(bundles.last!);expectedProfile.removeValue(forKey:"startup_mode");expectedProfile.removeValue(forKey:"auto_connect")
   check(try data(capture.finalProfile)==data(expectedProfile),"original final execution policy changed beyond startup controls")
   check(capture.strict && !capture.homeLANAccess,"original aggregate protection lost")
   for (position,member) in capture.members.enumerated(){check(try data(member.profile)==data(profile(bundles[position])),"original member profile changed")}
   let graph=try object(Data(capture.config.utf8));let route=graph["route"] as! [String:Any]
   check(route["final"] as? String=="routervpn-chain-application","preparation bypassed native closed gate")
   let reopened=try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(bundles.last!))
   check(reopened.source==capture.source && reopened.config==capture.config,"exact source replay changed")
   check(!capture.healthy() && !capture.nativeClosed(),"source-only preparation claimed readiness or native retirement")
   reject("local entry accepted Server selection"){_ = try IOSNodeChainCapture.compile(bundles:bundles)}
   try reopened.close();try capture.close()
   reject("closed capture remained usable"){try capture.requireCurrent()}
  }}}}
  for requested in ["server","auto"]{for first in ["wg","awg2-fast","awg2-strong"]{for method in ["2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305"]{
   let bundles=try importedFixture(requested,first,method)
   let capture:IOSNodeChainExecutionCapture
   do{capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested)}catch{fatalError("imported SS execution was refused: \(error)")}
   let preparation=try object(Data(capture.source.utf8)),launch=try object(Data(capture.launchInput.utf8)),local=try object(Data((preparation["local_source"] as! String).utf8)),original=try object(Data(capture.local.launchInput.utf8))
   check(preparation["schema"] as? Int==1 && launch["schema"] as? Int==1 && local["schema"] as? Int==2,"imported execution conflated preparation, Local, and saved Last schemas")
   let nodes=local["nodes"] as! [String],identities=local["identity_sources"] as! [String]
   check(nodes.count==3 && identities.count==3 && identities[1].isEmpty && !identities[0].isEmpty && !identities[2].isEmpty,"imported execution invented or omitted paired identity")
   check(nodes==original["nodes"] as? [String] && identities==original["identity_sources"] as? [String],"imported execution substituted original member source")
   let middle=capture.members[1].profile,external=middle["external"] as! [String:Any],ss=external["shadowsocks"] as! [String:Any]
   check(middle["node_kind"] as? String=="external" && middle["node_proof_id"]==nil && (middle["router_api"] as? String ?? "").isEmpty && (middle["api_token"] as? String ?? "").isEmpty,"imported execution manufactured Router authority")
   check(ss["method"] as? String==method && capture.members[0].mode==first && capture.finalProfile["dns_mode"] as? String=="home","imported execution changed captured transport or final DNS")
   let replay=try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(bundles.last!))
   check(replay.source==capture.source && replay.config==capture.config,"imported execution replay changed source or policy")
   check(!capture.healthy() && !capture.nativeClosed(),"source-only imported execution claimed native readiness")
   reject("source-only imported execution fabricated saved proof"){_ = try capture.captureRestoration()}
   try replay.close();try capture.close()
  }}}
  let imported=try importedFixture("server","wg","2022-blake3-aes-256-gcm")
  for fault in ["local-node","local-schema","local-identity","local-execution","preparation-schema","launch-schema"]{
   LibboxTestExecutionFault(fault)
   reject("imported execution "+fault){_ = try IOSNodeChainExecutionCapture.compile(bundles:imported,requested:"server")}
  }
  var tooSmall=try fixture(8,"aes-256-gcm+xor-whitening","server",true)
  for position in tooSmall.indices {
   tooSmall[position]=try edit(tooSmall[position]){root in
    var assets=root["profiles"] as! [String:[String:String]]
    for mode in ["wg","awg2-fast","awg2-strong"] {
     guard var files=assets[mode] else{continue}
     for key in files.keys{if let bytes=Data(base64Encoded:files[key]!),let raw=String(data:bytes,encoding:.utf8){files[key]=Data(raw.replacingOccurrences(of:"MTU=4000\n",with:"MTU=2000\n").utf8).base64EncodedString()}}
     assets[mode]=files
    }
    root["profiles"]=assets
   }
  }
  reject("undersized layered packet source"){_ = try IOSNodeChainExecutionCapture.compile(bundles:tooSmall,requested:"server")}
  let bundles=try fixture(3,"off","server",false)
  for operation in ["local-new","execution-new"]{
   LibboxTestReturnedOwnerError(operation)
   reject("returned native object plus error "+operation){_ = try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"server")}
   check(LibboxTestReturnedOwnerClosed(),"returned original owner was not closed exactly once: "+operation)
  }
  for fault in ["config","requested","launch-error","local-node"]{
   LibboxTestExecutionFault(fault)
   reject("native execution "+fault){_ = try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"server")}
  }
  let capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"server")
  var replaced=try profile(bundles.last!);replaced["api_token"]="another-private-node-token"
  LibboxTestReturnedOwnerError("execution-open")
  reject("returned replay object plus error"){_ = try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:profile(bundles.last!))}
  check(LibboxTestReturnedOwnerClosed(),"returned original owner was not closed exactly once: execution-open")
  reject("changed final control"){_ = try IOSNodeChainExecutionCapture.reopen(capture.launchInput,selectedProfile:replaced)}
  reject("noncanonical launch"){_ = try IOSNodeChainExecutionCapture.reopen(capture.launchInput+" ",selectedProfile:profile(bundles.last!))}
  reject("requested execution normalized"){_ = try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:"auto")}
  try capture.close()
  let cancelledNative=LibboxCommandServer()
  reject("cancelled binding admitted execution"){try capture.bindNative(cancelledNative)}
  check(cancelledNative.bindAttempts==1,"cancelled capture failed to reserve original native cleanup")
  print("PASS Apple execution source: \(checks) checks")
 }
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='.ios-execution-compiler-',dir=ROOT) as gd, tempfile.TemporaryDirectory(prefix='ios-execution-source-') as wd:
        gd,work=Path(gd),Path(wd);(gd/'main.go').write_text(GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(gd/'main.go')],cwd=ROOT,check=True,timeout=180)
        (work/'Libbox.swift').write_text(LIBBOX);(work/'CryptoKit.swift').write_text(CRYPTO);(work/'Tests.swift').write_text(SWIFT)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        suffix='.dylib' if platform.system()=='Darwin' else '.so'
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(work/'Libbox.swift'),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(work/('libLibbox'+suffix))],check=True,timeout=90)
        link=['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        subprocess.run(options+link+['-emit-module','-emit-library','-module-name','CryptoKit',str(work/'CryptoKit.swift'),'-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/('libCryptoKit'+suffix))],check=True,timeout=90)
        command=options+link+['-lCryptoKit',str(APP/'Models.swift'),str(APP/'IOSMultihopStartLayer.swift'),str(APP/'IOSNodeChainCapture.swift'),str(APP/'IOSImportedOpenVPNSource.swift'),str(APP/'IOSNodeChainCONNECTCapture.swift'),str(APP/'IOSNodeChainSOCKSCapture.swift'),str(APP/'IOSNodeChainProviderCapture.swift')]
        source=APP/'IOSNodeChainExecutionCapture.swift';tests=work/'Tests.swift';binary=work/'tests'
        subprocess.run(command+[str(source),str(tests),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary),str(compiler)],check=True,timeout=180)
        text=source.read_text()
        for name,before,after in (
          ('config','configSHA256 == SHA256.hash(data: Data(config.utf8)).map({ String(format: "%02x", $0) }).joined(),','true,'),
          ('requested','plan.requestedExecution() == requested,','true,'),
          ('launch-error','guard failure == nil, let input else {','guard let input else {'),
          ('local-node','nodes == original["nodes"] as? [String], identities == original["identity_sources"] as? [String] else {','!nodes.isEmpty, identities == original["identity_sources"] as? [String] else {'),
          ('imported-schema','(schema == 1 || schema == 2),','schema == 1,'),
          ('local-schema','returned["schema"] as? Int == schema,','true,'),
          ('local-identity','identities == original["identity_sources"] as? [String] else {','!identities.isEmpty else {'),
          ('cleanup-bind-order','func bindNative(_ server: LibboxCommandServer) throws { try plan.bindNative(server); try requireCurrent() }','func bindNative(_ server: LibboxCommandServer) throws { try requireCurrent(); try plan.bindNative(server) }'),
        ):
            assert text.count(before)==1,name
            mutant=work/(name+'.swift');mutant.write_text(text.replace(before,after,1));binary=work/name
            subprocess.run(command+[str(mutant),str(tests),'-o',str(binary)],check=True,timeout=90)
            result=subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
            witness=('cancelled capture failed to reserve original native cleanup' if name=='cleanup-bind-order'
                     else 'imported SS execution was refused' if name=='imported-schema'
                     else 'ACCEPTED imported execution '+name if name in ('local-node','local-schema','local-identity')
                     else 'ACCEPTED native execution '+name)
            assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,(result.stdout+result.stderr)[-1500:])
            print('Rejected Apple execution source control:',name)

        # Each cleanup is independently causal: the native call still returns
        # its original object and NSError; only the required close is removed.
        local_source=APP/'IOSNodeChainCapture.swift'
        for name,owner,reason in (
            ('local-new',local_source,'The selected ordered native graph is unavailable.'),
            ('execution-new',source,'The complete ordered execution could not be prepared.'),
            ('execution-open',source,'The private execution source could not be reproduced.'),
        ):
            original=owner.read_text()
            marker='try? returned?.close()\n'+('            ' if name=='local-new' else '                ')+'throw failure ?? issue("'+reason+'")'
            assert original.count(marker)==1,name
            mutant=work/('returned-'+name+'.swift');mutant.write_text(original.replace(marker,marker.replace('try? returned?.close()','/* controlled original owner close omitted */'),1))
            active_command=[str(mutant) if value==str(local_source) and name=='local-new' else value for value in command]
            execution_source=source if name=='local-new' else mutant
            binary=work/('returned-'+name)
            subprocess.run(active_command+[str(execution_source),str(tests),'-o',str(binary)],check=True,timeout=90)
            result=subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
            witness='returned original owner was not closed exactly once: '+name
            assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,(result.stdout+result.stderr)[-1500:])
            print('Rejected Apple returned-owner cleanup control:',name)

if __name__=='__main__':main()
