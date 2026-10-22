#!/usr/bin/env python3
"""Execute Apple MAX capture, scoped DNS ownership and prestart retirement.

The shipping Swift files are compiled unchanged under Swift 6. Apple Network,
DNS-SD and generated Objective-C handles have deterministic boundary doubles;
each capture/resolution/compile executes the real shared Go implementation.
This gate proves host ownership and configuration, not iOS daemon/device traffic.
"""
from pathlib import Path
import importlib.util
import os
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
TUN = ROOT / 'ios/RouterVPN/PacketTunnel'
spec = importlib.util.spec_from_file_location('max_hostname_compiler', ROOT / 'deploy/test_ios_pq_selection.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
GO = P.GO.replace('import("bytes";', 'import("bytes";"context";', 1)
GO = GO.replace('func handle(r request)', '''type capturedResolver struct{ raw, id string }
func(r *capturedResolver)OwnerID()string{return r.id}
func(r *capturedResolver)Current()bool{return true}
func(r *capturedResolver)Cancel(){}
func(r *capturedResolver)Lookup(string)(string,error){return r.raw,nil}
func handle(r request)''', 1)
GO = GO.replace(' case "compile":', ''' case "max-check":
  var c *mobilemultihop.MAXProfileCapture;c,err=mobilemultihop.CaptureMAXProfile(r.Mode,r.Files,r.Policy);if err==nil{value=c.SourceSHA256()}
 case "max-compile":value,err=mobilemultihop.CompileMAXProfile(r.Mode,r.Files,r.Policy)
 case "max-resolve":
  var answer struct{Owner string `json:"owner_id"`};err=json.Unmarshal([]byte(r.Source),&answer)
  if err==nil{var q *mobilemultihop.MAXResolveRequest;q,err=mobilemultihop.NewMAXResolveRequest(context.Background(),r.Mode,r.Files,r.Policy,&capturedResolver{r.Source,answer.Owner});if err==nil{value,err=q.Run();q.Close()}}
 case "sha256":
  var raw []byte;raw,err=base64.StdEncoding.DecodeString(r.Source);if err==nil{sum:=sha256.Sum256(raw);value=hex.EncodeToString(sum[:])}
 case "compile":''', 1)

NETWORK = r'''
import Foundation
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif
public struct IPv4Address: Equatable, Sendable { public let value:String; public init?(_ value:String){var a=in_addr();guard inet_pton(AF_INET,value,&a)==1 else{return nil};self.value=value} }
public struct IPv6Address: Equatable, Sendable { public let value:String; public init?(_ value:String){var a=in6_addr();guard inet_pton(AF_INET6,value,&a)==1 else{return nil};self.value=value} }
public struct NWInterface: Sendable { public enum InterfaceType: Sendable {case wifi,cellular,wiredEthernet,other};public let name:String;public let index:Int;public let type:InterfaceType }
public struct NWPath: Sendable { public enum Status: Sendable {case satisfied,unsatisfied};public var status:Status = .satisfied;public var availableInterfaces:[NWInterface];public var supportsDNS=true;public let signature:String }
public final class NWPathMonitor: @unchecked Sendable {
 public var pathUpdateHandler:((NWPath)->Void)?
 private let lock=NSLock();private var stopped=false;private var queue:DispatchQueue?
 public init(){}
 public func start(queue:DispatchQueue){lock.lock();self.queue=queue;let live = !stopped;lock.unlock();if live{NetworkTest.shared.add(self)}}
 public func cancel(){lock.lock();stopped=true;lock.unlock();NetworkTest.shared.remove(self)}
 public func deliver(_ path:NWPath){lock.lock();let q=queue;lock.unlock();q?.async{[self] in lock.lock();let live = !stopped;lock.unlock();if live{pathUpdateHandler?(path)}}}
 public func join(){lock.lock();let q=queue;lock.unlock();q?.sync{}}
}
public final class NetworkTest: @unchecked Sendable {
 public static let shared=NetworkTest();private let lock=NSLock();private var monitors:[NWPathMonitor]=[];private var capturedCount=0
 private var path=NWPath(availableInterfaces:[NWInterface(name:"en0",index:7,type:.wifi)],signature:"physical-A")
 public func add(_ monitor:NWPathMonitor){lock.lock();monitors.append(monitor);capturedCount+=1;let p=path;lock.unlock();monitor.deliver(p)}
 public func remove(_ monitor:NWPathMonitor){lock.lock();monitors.removeAll{$0 === monitor};lock.unlock()}
 public func set(index:Int=7,name:String="en0",signature:String="physical-A",valid:Bool=true,dns:Bool=true){lock.lock();path=NWPath(status:valid ? .satisfied:.unsatisfied,availableInterfaces:[NWInterface(name:name,index:index,type:.wifi)],supportsDNS:dns,signature:signature);let p=path,receivers=monitors;lock.unlock();for m in receivers{m.deliver(p)}}
 public func counts()->(Int,Int){lock.lock();defer{lock.unlock()};return(capturedCount,monitors.count)}
 public func join(){lock.lock();let receivers=monitors;lock.unlock();for m in receivers{m.join()}}
}
'''

DNSSD = r'''
import Foundation
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif
public typealias DNSServiceRef=OpaquePointer
public typealias DNSServiceFlags=UInt32
public typealias DNSServiceProtocol=UInt32
public typealias DNSServiceErrorType=Int32
public let kDNSServiceProtocol_IPv4:UInt32=1,kDNSServiceProtocol_IPv6:UInt32=2
public let kDNSServiceFlagsAdd:UInt32=2,kDNSServiceFlagsMoreComing:UInt32=1
public let kDNSServiceErr_NoError:Int32=0
public typealias DNSServiceGetAddrInfoReply=(DNSServiceRef?,UInt32,UInt32,Int32,UnsafePointer<CChar>?,UnsafePointer<sockaddr>?,UInt32,UnsafeMutableRawPointer?)->Void
private final class Record: @unchecked Sendable {
 let ref:DNSServiceRef;let callback:DNSServiceGetAddrInfoReply;let context:UnsafeMutableRawPointer?;let name:String;let index:UInt32
 var queue:DispatchQueue?;var retired=false
 init(_ id:Int,_ cb:@escaping DNSServiceGetAddrInfoReply,_ ctx:UnsafeMutableRawPointer?,_ name:String,_ index:UInt32){ref=OpaquePointer(bitPattern:id)!;callback=cb;context=ctx;self.name=name;self.index=index}
}
public final class DNSSDTest: @unchecked Sendable {
 public static let shared=DNSSDTest();private let lock=NSLock();private var records:[Int:Record]=[:];private var serial=1
 private var address=["192.0.2.71"];private var answerIndex:UInt32=0;private var alias="canonical.example.";private var held=false;private var blockClose=false;private var retiredCount=0;private var queryCount=0
 public let entered=DispatchSemaphore(value:0),closing=DispatchSemaphore(value:0),releaseClose=DispatchSemaphore(value:0)
 private var queries:[String]=[];private var scopes:[UInt32]=[]
 public func configure(addresses:[String]=["192.0.2.71"],index:UInt32=0,name:String="canonical.example.",hold:Bool=false,block:Bool=false){lock.lock();address=addresses;answerIndex=index;alias=name;held=hold;blockClose=block;lock.unlock();while entered.wait(timeout:.now()) == .success{};while closing.wait(timeout:.now()) == .success{}}
 fileprivate func create(_ reference:UnsafeMutablePointer<DNSServiceRef?>,_ index:UInt32,_ name:UnsafePointer<CChar>,_ callback:@escaping DNSServiceGetAddrInfoReply,_ context:UnsafeMutableRawPointer?)->Int32{lock.lock();serial+=1;let r=Record(serial,callback,context,String(cString:name),index);records[serial]=r;queries.append(r.name);scopes.append(index);queryCount+=1;reference.pointee=r.ref;lock.unlock();entered.signal();return 0}
 fileprivate func schedule(_ ref:DNSServiceRef,_ queue:DispatchQueue)->Int32{lock.lock();let r=records[Int(bitPattern:ref)];r?.queue=queue;let wait=held;lock.unlock();guard let r else{return -1};if !wait{emit(r)};return 0}
 public func answer(){lock.lock();let values=Array(records.values);lock.unlock();for r in values{emit(r)}}
 private func emit(_ r:Record){lock.lock();let values=address,index=answerIndex,name=alias,q=r.queue;lock.unlock();q?.async{[self,r] in
   lock.lock();let live = !r.retired;lock.unlock();guard live else{return}
   for (i,value) in values.enumerated(){let flags:UInt32=2 | (i+1<values.count ? 1:0)
    name.withCString{host in
     if value.contains(":"){var a=sockaddr_in6();a.sin6_family=sa_family_t(AF_INET6);_ = inet_pton(AF_INET6,value,&a.sin6_addr);withUnsafePointer(to:&a){p in p.withMemoryRebound(to:sockaddr.self,capacity:1){r.callback(r.ref,flags,index,0,host,$0,60,r.context)}}}
     else{var a=sockaddr_in();a.sin_family=sa_family_t(AF_INET);_ = inet_pton(AF_INET,value,&a.sin_addr);withUnsafePointer(to:&a){p in p.withMemoryRebound(to:sockaddr.self,capacity:1){r.callback(r.ref,flags,index,0,host,$0,60,r.context)}}}
    }
   }
  }}
 fileprivate func retire(_ ref:DNSServiceRef){lock.lock();let r=records[Int(bitPattern:ref)];r?.retired=true;let block=blockClose;lock.unlock();closing.signal();if block{_ = releaseClose.wait(timeout:.now()+8)};lock.lock();records.removeValue(forKey:Int(bitPattern:ref));retiredCount+=1;lock.unlock()}
 public func counts()->(Int,Int,Int){lock.lock();defer{lock.unlock()};return(queryCount,retiredCount,records.count)}
 public func history()->([String],[UInt32]){lock.lock();defer{lock.unlock()};return(queries,scopes)}
}
public func DNSServiceGetAddrInfo(_ ref:UnsafeMutablePointer<DNSServiceRef?>,_ flags:UInt32,_ index:UInt32,_ proto:UInt32,_ name:UnsafePointer<CChar>,_ callback:@escaping DNSServiceGetAddrInfoReply,_ context:UnsafeMutableRawPointer?)->Int32{DNSSDTest.shared.create(ref,index,name,callback,context)}
public func DNSServiceSetDispatchQueue(_ ref:DNSServiceRef,_ queue:DispatchQueue)->Int32{DNSSDTest.shared.schedule(ref,queue)}
public func DNSServiceRefDeallocate(_ ref:DNSServiceRef){DNSSDTest.shared.retire(ref)}
'''

LIBBOX = r'''
import Foundation
public protocol LibboxRouterMAXEndpointResolverProtocol: AnyObject {func ownerID()->String;func current()->Bool;func lookup(_ hostname:String?)throws->String;func cancel()}
public final class NativeMAXTest: @unchecked Sendable {
 public static let shared=NativeMAXTest();private let lock=NSLock();private var handler:((String,String,String,String,String)throws->String)?;private var changes=""
 public func configure(_ value:@escaping (String,String,String,String,String)throws->String){lock.lock();handler=value;lock.unlock()}
 public func mutate(_ value:String){lock.lock();changes=value;lock.unlock()}
 public func call(_ operation:String,_ mode:String,_ files:String,_ metadata:String,_ answer:String="")throws->String{lock.lock();let h=handler;lock.unlock();return try h!(operation,mode,files,metadata,answer)}
 public func change(_ value:String)throws->String{lock.lock();let change=changes;lock.unlock();guard !change.isEmpty else{return value};var body=try JSONSerialization.jsonObject(with:Data(value.utf8)) as! [String:Any]
  switch change{case "digest":body["source_sha256"]=String(repeating:"f",count:64);case "owner":body["owner_id"]="foreign";case "hostname":body["hostname"]="foreign.example";case "schema":body["extra"]=true;case "endpoint":body["endpoint"]="unresolved.example";case "metadata":var meta=try JSONSerialization.jsonObject(with:Data((body["metadata_json"] as! String).utf8)) as! [String:Any];meta["router_api"]="http://10.66.0.1:8787";body["metadata_json"]=String(decoding:try JSONSerialization.data(withJSONObject:meta),as:UTF8.self);default:body["config_json"]="{}"}
  return String(decoding:try JSONSerialization.data(withJSONObject:body),as:UTF8.self)
 }
}
// Deliberately non-Sendable generated-handle stand-in. Its shared Go request
// implementation has separate real race/cancellation tests.
public final class LibboxRouterMAXProfileRequest {
 private let mode:String,files:String,metadata:String,digest:String;private let resolver:any LibboxRouterMAXEndpointResolverProtocol
 private let lock=NSLock();private var stopped=false,used=false,success=false
 public init(_ mode:String,_ files:String,_ metadata:String,_ digest:String,_ resolver:any LibboxRouterMAXEndpointResolverProtocol){self.mode=mode;self.files=files;self.metadata=metadata;self.digest=digest;self.resolver=resolver}
 public func sourceSHA256()->String{digest}
 public func run()throws->String{lock.lock();let valid = !stopped && !used;used=true;lock.unlock();guard valid else{throw NSError(domain:"RetiredNativeMAX",code:1)};let object=try JSONSerialization.jsonObject(with:Data(metadata.utf8)) as! [String:String];let answer=try resolver.lookup(object["endpoint"]!);guard resolver.current() else{throw NSError(domain:"RetiredNativeMAX",code:1)};let result=try NativeMAXTest.shared.call("max-resolve",mode,files,metadata,answer);lock.lock();success = !stopped;lock.unlock();return try NativeMAXTest.shared.change(result)}
 public func healthy()->Bool{lock.lock();let valid = !stopped && success;lock.unlock();return valid && resolver.current()}
 public func cancel(){lock.lock();stopped=true;lock.unlock()}
 public func close(){cancel();resolver.cancel()}
}
public func LibboxRouterCheckMAXProfile(_ mode:String,_ files:String,_ metadata:String,_ error:UnsafeMutablePointer<NSError?>?)->String{do{return try NativeMAXTest.shared.call("max-check",mode,files,metadata)}catch let e as NSError{error?.pointee=e;return ""}}
public func LibboxRouterCompileMAXProfile(_ mode:String,_ files:String,_ metadata:String,_ error:UnsafeMutablePointer<NSError?>?)->String{do{return try NativeMAXTest.shared.call("max-compile",mode,files,metadata)}catch let e as NSError{error?.pointee=e;return ""}}
public func LibboxRouterCreateMAXProfileRequest(_ mode:String,_ files:String,_ metadata:String,_ resolver:any LibboxRouterMAXEndpointResolverProtocol,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterMAXProfileRequest?{do{let digest=try NativeMAXTest.shared.call("max-check",mode,files,metadata);guard resolver.current() else{throw NSError(domain:"RetiredNativeMAX",code:1)};return LibboxRouterMAXProfileRequest(mode,files,metadata,digest,resolver)}catch let e as NSError{error?.pointee=e;return nil}}
'''

SWIFT = P.SWIFT[:P.SWIFT.index('func profile(')] + r'''
import Network
import Libbox
import dnssd
#if canImport(CryptoKit)
import CryptoKit
#else
// CryptoKit is absent on Linux. Use the real Go SHA-256 implementation rather
// than substituting a digest or bypassing the shipping restoration receipt.
enum SHA256 {static func hash(data:Data)->[UInt8]{
 let digest=try! bridge(["Op":"sha256","Source":data.base64EncodedString()])
 return stride(from:0,to:digest.count,by:2).map{offset in
  let start=digest.index(digest.startIndex,offsetBy:offset),end=digest.index(start,offsetBy:2)
  return UInt8(digest[start..<end],radix:16)!
 }
}}
#endif
enum RouterVPNPhysicalPath {static func snapshot(_ path:NWPath)->(name:String,signature:String)?{guard path.status == .satisfied,path.availableInterfaces.count==1,let first=path.availableInterfaces.first,!first.name.hasPrefix("utun"),!first.name.hasPrefix("tun"),!first.name.hasPrefix("lo") else{return nil};return(first.name,path.signature)}}
func checked(_ provider:[String:Any])throws->[String:Any]{var p=provider;p["max_source_sha256"]=try IOSMAXSourceSelection.sourceHashes(provider:p){try bridge(["Op":"max-check","Mode":$0,"Files":$1,"Policy":$2])};return p}
func fixture(_ base:[String:Any],_ mode:String,_ layer:String,_ hostname:String?)throws->[String:Any]{
 var files=base["files"] as! [String:String],policy=base["policy"] as! [String:String]
 if let hostname{let name=mode.hasPrefix("max-tls-") ? "outer-xray.json":"middle-sing-box.json";var root=try object(Data(base64Encoded:files[name]!)!),outs=root["outbounds"] as! [[String:Any]]
  if mode.hasPrefix("max-tls-"){var settings=outs[0]["settings"] as! [String:Any],remotes=settings["vnext"] as! [[String:Any]];remotes[0]["address"]=hostname;settings["vnext"]=remotes;outs[0]["settings"]=settings}
  else{let i=outs.firstIndex{$0["tag"] as? String=="outer"}!;outs[i]["server"]=hostname}
  root["outbounds"]=outs;files[name]=try json(root).base64EncodedString();policy["endpoint"]=hostname
 }
 let p:[String:Any]=["id":"home","node_kind":"router-vpn","node_proof_id":policy["node_id"]!,"endpoint":policy["endpoint"]!,"router_api":policy["router_api"]!,"api_token":"private-test-token","start_layer":layer,"dns_mode":"home","adguard_ipv4":"192.168.50.133","home_lan_access":false,"ipv6_mode":"off"]
 let data=try json(["selectedRouterID":"home","nodeProofId":policy["node_id"]!,"routerProfiles":[p],"profiles":[mode:files]])
 return ["engine":"libbox","bundle":data,"rawProfileID":mode]
}
final class Outcome: @unchecked Sendable {let done=DispatchSemaphore(value:0);private let lock=NSLock();private var value:Error?;private var calls=0;func receive(_ error:Error?){lock.lock();value=error;calls+=1;lock.unlock();done.signal()};func result()->(Int,Bool){lock.lock();defer{lock.unlock()};return(calls,value==nil)}}
func changedBundle(_ provider:[String:Any],_ edit:(inout [String:Any],inout [String:Any])throws->Void)throws->[String:Any]{var p=provider,root=try object(provider["bundle"] as! Data),node=try IOSMAXSourceSelection.profile(root);try edit(&root,&node);root["routerProfiles"]=[node];p["bundle"]=try json(root);return p}
func renamed(_ provider:[String:Any],_ identity:String)throws->[String:Any]{try changedBundle(provider){root,node in root["selectedRouterID"]=identity;node["id"]=identity}}
func capturedRoutes(_ fixtures:[String:Any])throws->[[String:Any]]{
 let entry=try renamed(fixture((fixtures["entry"] as! [String:Any])["max-tls-wg"] as! [String:Any],"max-tls-wg","off","entry.example"),"entry")
 let exit=try renamed(fixture((fixtures["exit"] as! [String:Any])["max-quic-awg"] as! [String:Any],"max-quic-awg","aes-256-gcm","exit.example"),"exit")
 var multi=try changedBundle(exit){_,node in node["multihop_enabled"]=true;node["multihop_entry_id"]="entry";node["multihop_exit_id"]="exit";node["multihop_entry_mode"]="max-tls-wg";node["multihop_exit_mode"]="max-quic-awg"}
 multi["engine"]="multihop-libbox";multi["entryBundle"]=entry["bundle"]
 let tor:[String:Any]=["id":"tor-exit","node_kind":"external","external":["protocol":"tor"],"multihop_enabled":true,"multihop_entry_id":"entry","multihop_entry_mode":"max-tls-wg"]
 let external:[String:Any]=["engine":"external-libbox","bundle":try json(["selectedRouterID":"tor-exit","routerProfiles":[tor],"profiles":[String:String]()]),"tor_entry_bundle":entry["bundle"]!,"tor_entry_mode":"max-tls-wg"]
 return try [checked(entry),checked(multi),checked(external)]
}
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ name:String,_ value:@autoclosure ()throws->Bool)throws{guard try value() else{fatalError(name)};checks+=1}
 @MainActor static func reject(_ name:String,_ action:()throws->Void){do{try action();fatalError("accepted "+name)}catch{checks+=1}}
 @MainActor static func main()throws{
  defer{TestCompiler.shared.close()}
  NativeMAXTest.shared.configure{op,mode,files,metadata,answer in try bridge(["Op":op,"Mode":mode,"Files":files,"Policy":metadata,"Source":answer])}
  let fixtures=try object(Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[2])))
  try check("receipt boundary uses SHA-256",SHA256.hash(data:Data("abc".utf8)).map{String(format:"%02x",$0)}.joined()=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  var count=0
  for mode in IOSNativeMAXProfile.modeIDs.sorted(){for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"]{for address in ["192.0.2.71","2001:db8::71"]{
   NetworkTest.shared.set();DNSSDTest.shared.configure(addresses:[address])
   let input=try checked(fixture(fixtures[mode] as! [String:Any],mode,layer,"Captured-MAX.example.")),before=input["bundle"] as! Data
   let calls=DNSSDTest.shared.counts().0,owner=try RouterVPNMAXPreparation(provider:input)
   try check("readiness makes no query",DNSSDTest.shared.counts().0==calls && owner.requiresResolution)
   let launch=try owner.run(),root=try object(launch["bundle"] as! Data),p=try IOSMAXSourceSelection.profile(root)
   try check("private launch owns exact literal",p["endpoint"] as? String==address && owner.healthy())
   try check("saved source remains exact",input["bundle"] as? Data==before)
   try check("node token and DNS policy unchanged",p["api_token"] as? String=="private-test-token" && p["dns_mode"] as? String=="home" && p["adguard_ipv4"] as? String=="192.168.50.133")
   let history=DNSSDTest.shared.history();try check("one absolute interface-scoped query",DNSSDTest.shared.counts().0==calls+1 && history.0.last=="Captured-MAX.example." && history.1.last==7)
   owner.close();try check("query and callback owner drained",DNSSDTest.shared.counts().2==0 && NetworkTest.shared.counts().1==0 && !owner.healthy())
   reject("single-use launch"){_ = try owner.run()};count+=1
  }}}
  let mode="max-tls-wg",base=fixtures["max-tls-wg"] as! [String:Any]
  let good=try checked(fixture(base,mode,"off","captured.example"))
  for change in ["digest","owner","hostname","schema","endpoint","metadata","config"]{NativeMAXTest.shared.mutate(change);let q=try RouterVPNMAXPreparation(provider:good);reject("bad native envelope "+change){_ = try q.run()};q.close()};NativeMAXTest.shared.mutate("")
  let literal=try fixture(base,mode,"off",nil),before=DNSSDTest.shared.counts().0,literalOwner=try RouterVPNMAXPreparation(provider:literal)
  try check("legacy literal stays synchronous",!literalOwner.requiresResolution && literalOwner.run()["bundle"] as? Data==literal["bundle"] as? Data && DNSSDTest.shared.counts().0==before);literalOwner.close()
  var missing=good;missing.removeValue(forKey:"max_source_sha256");reject("hostname requires app source handoff"){_ = try RouterVPNMAXPreparation(provider:missing)}
  var changed=good;changed["max_source_sha256"]=["bundle/"+mode:String(repeating:"f",count:64)];reject("changed source stamp"){_ = try RouterVPNMAXPreparation(provider:changed)}
  let validationQueries=DNSSDTest.shared.counts().0,validationCaptures=NetworkTest.shared.counts().0
  let broken=try changedBundle(good){root,_ in var profiles=root["profiles"] as! [String:[String:String]],files=profiles[mode]!,middle=try object(Data(base64Encoded:files["middle-sing-box.json"]!)!);var outputs=middle["outbounds"] as! [[String:Any]];outputs[0]["detour"]="foreign-unvalidated-hop";middle["outbounds"]=outputs;files["middle-sing-box.json"]=try json(middle).base64EncodedString();profiles[mode]=files;root["profiles"]=profiles}
  reject("complete inner chain validation before resolver"){_ = try RouterVPNMAXPreparation(provider:broken)}
  try check("invalid complete source creates no path or DNS owner",DNSSDTest.shared.counts().0==validationQueries && NetworkTest.shared.counts().0==validationCaptures)
  let canceled=try RouterVPNMAXPreparation(provider:good);canceled.cancel();let calls=DNSSDTest.shared.counts().0;reject("canceled before first DNS"){_ = try canceled.run()};canceled.close();try check("no DNS after early cancel",calls==DNSSDTest.shared.counts().0)
  for tuple in [(0,"en0",true,true),(7,"utun3",true,true),(7,"en0",false,true),(7,"en0",true,false)]{NetworkTest.shared.set(index:tuple.0,name:tuple.1,valid:tuple.2,dns:tuple.3);let q=try RouterVPNMAXPreparation(provider:good);reject("no unowned physical interface"){_ = try q.run()};q.close()};NetworkTest.shared.set()
  DNSSDTest.shared.configure(index:8);let foreign=try RouterVPNMAXPreparation(provider:good);reject("foreign answer interface"){_ = try foreign.run()};foreign.close()
  DNSSDTest.shared.configure();NetworkTest.shared.set()
  let stale=try RouterVPNMAXPreparation(provider:good);_ = try stale.run();NetworkTest.shared.set(signature:"physical-B");NetworkTest.shared.join();try check("completed answer cannot survive physical path replacement",!stale.healthy());stale.close()
  NetworkTest.shared.set();DNSSDTest.shared.configure(hold:true)
  let pathPending=try RouterVPNMAXPreparation(provider:good),pathResult=Outcome();DispatchQueue.global().async{do{_ = try pathPending.run();pathResult.receive(nil)}catch{pathResult.receive(error)}}
  try check("replacement fixture owns a pending query",DNSSDTest.shared.entered.wait(timeout:.now()+5) == .success)
  NetworkTest.shared.set(index:8,signature:"physical-B");NetworkTest.shared.join()
  try check("path replacement retires pending answer before adoption",pathResult.done.wait(timeout:.now()+5) == .success && !pathResult.result().1 && !pathPending.healthy());pathPending.close()
  NetworkTest.shared.set();DNSSDTest.shared.configure()
  let unstarted=try RouterVPNMAXPreparation(provider:good),unusedResult=Outcome(),unusedDrain=Outcome(),unusedQueries=DNSSDTest.shared.counts().0,unusedCaptures=NetworkTest.shared.counts().0
  let unused=RouterVPNMAXStart(preparation:unstarted){_,error in unusedResult.receive(error)};unused.cancelAndDrain{unusedDrain.receive(nil)}
  try check("Stop before queue admission drains",unusedDrain.done.wait(timeout:.now()+3) == .success && unusedResult.done.wait(timeout:.now()+3) == .success)
  unused.start{_,_,_ in fatalError("retired prestart admitted adoption")}
  try check("retired prestart cannot create resolver or republish",DNSSDTest.shared.counts().0==unusedQueries && NetworkTest.shared.counts().0==unusedCaptures && unusedResult.result().0==1 && !unusedResult.result().1)
  DNSSDTest.shared.configure(hold:true,block:true)
  let pending=try RouterVPNMAXPreparation(provider:good),outcome=Outcome(),drain=Outcome()
  let start=RouterVPNMAXStart(preparation:pending){_,error in outcome.receive(error)}
  start.start{_,_,complete in complete(nil);fatalError("canceled request reached native adoption")}
  try check("actual pending DNS entered",DNSSDTest.shared.entered.wait(timeout:.now()+5) == .success)
  let begin=Date();start.cancelAndDrain{drain.receive(nil)}
  try check("cancel does not wait for DNS deallocation",Date().timeIntervalSince(begin)<0.5)
  try check("DNS deallocation really entered",DNSSDTest.shared.closing.wait(timeout:.now()+2) == .success)
  try check("no early fallback/drain",drain.done.wait(timeout:.now()+0.03) == .timedOut)
  try check("no early OS completion",outcome.done.wait(timeout:.now()+0.03) == .timedOut)
  DNSSDTest.shared.releaseClose.signal()
  try check("stopped completion joins actual cleanup",drain.done.wait(timeout:.now()+5) == .success && outcome.done.wait(timeout:.now()+2) == .success && outcome.result().0==1 && !outcome.result().1)
  try check("no live DNS resources after stop",DNSSDTest.shared.counts().2==0 && NetworkTest.shared.counts().1==0)
  DNSSDTest.shared.configure();NetworkTest.shared.set()
  let success=try RouterVPNMAXPreparation(provider:good),completed=Outcome(),release=DispatchSemaphore(value:0),adopted=DispatchSemaphore(value:0)
  let owned=RouterVPNMAXStart(preparation:success){_,error in completed.receive(error)}
  owned.start{_,_,complete in complete(nil);adopted.signal();_ = release.wait(timeout:.now()+5)}
  try check("proof may finish inside adoption",adopted.wait(timeout:.now()+5) == .success)
  try check("OS success waits prestart retirement",completed.done.wait(timeout:.now()+0.03) == .timedOut)
  owned.cancel();release.signal();try check("cancel overrides early successful proof",completed.done.wait(timeout:.now()+5) == .success && !completed.result().1 && completed.result().0==1)
  checks += try providerPrestartTests(good:good,fixtures:object(Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[3]))))
  checks += try providerExecutionTests(fixtures:object(Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[3]))))
  print("Apple MAX hostname: \(count) real Go launch graphs, \(checks) source/DNS/lifetime checks passed")
 }
}
'''


PRESTART_BOUNDARY = r'''
// Only OS protocol/settings and native traffic/proof are doubled here. The
// provider's prestart, dispatch, generation and Stop method bodies are copied
// verbatim below; actual source validation/private Go compilation stays live.
enum NEProviderStopReason {case userInitiated}
class NEPacketTunnelProvider: @unchecked Sendable {
 var protocolConfiguration:Any?
 func startTunnel(options:[String:NSObject]?=nil,completionHandler:@escaping(Error?)->Void){}
 func stopTunnel(with reason:NEProviderStopReason,completionHandler:@escaping()->Void){}
 func sleep(completionHandler:@escaping()->Void){}
}
final class NETunnelProviderProtocol {var providerConfiguration:[String:Any]?;var includeAllNetworks=true,enforceRoutes=true,excludeLocalNetworks=false}
final class PrestartForwarding {func invalidate(){}}
final class PrestartEngine {let trace:PrestartTrace;init(_ trace:PrestartTrace){self.trace=trace};func stop(){trace.stopped()};func pause(){}}
final class PrestartAdapter {func stop(_ complete:(Error?)->Void){complete(nil)}}
final class PrestartStrategy {let currentEpoch="test-epoch";func stop(){}}
final class PrestartDriver {func drain(_ complete:()->Void){complete()}}
final class PrestartTrace: @unchecked Sendable {
 private let lock=NSLock();private var starts=0,stops=0,dispatches:[String]=[];private var data:Data?;private var proof:((Error?)->Void)?
 private var held=false
 let entered=DispatchSemaphore(value:0),release=DispatchSemaphore(value:0)
 func hold(){lock.lock();held=true;lock.unlock()}
 func started(_ config:[String:Any],complete:@escaping(Error?)->Void)throws{let bytes=try PropertyListSerialization.data(fromPropertyList:config,format:.binary,options:0);lock.lock();starts+=1;dispatches.append(config["engine"] as? String ?? "");data=bytes;proof=complete;let wait=held;lock.unlock();entered.signal();if wait{_ = release.wait(timeout:.now()+8)}}
 func prove(_ error:Error?=nil){lock.lock();let delivery=proof;lock.unlock();delivery?(error)}
 func stopped(){lock.lock();stops+=1;lock.unlock()}
 func counts()->(Int,Int){lock.lock();defer{lock.unlock()};return(starts,stops)}
 func launch()throws->[String:Any]{lock.lock();let bytes=data;lock.unlock();return try PropertyListSerialization.propertyList(from:bytes!,options:[],format:nil) as! [String:Any]}
}
final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
 private static let maxBundleBytes=32*1024*1024
 private var initialMTUHold=""
 private var forwardingChannel:PrestartForwarding?=PrestartForwarding()
 private var libboxEngine:PrestartEngine?,wireGuardAdapter:PrestartAdapter?
 private let strategyOwnerLock=NSLock()
 private var providerStrategy:PrestartStrategy?,strategyDriver:PrestartDriver?
 let trace=PrestartTrace()
 func configure(_ config:[String:Any]){let p=NETunnelProviderProtocol();p.providerConfiguration=config;protocolConfiguration=p}
 func executionState()->(IOSMultihopExecution.Source?,String?){(multihopExecutionSource,restoredMultihopExecution)}
 private func currentProviderStrategy()->PrestartStrategy?{providerStrategy}
 private func retireLibboxSettings(epoch:String){}
 private func clearPathProofGuard(){}
 private func cancelActiveProof(){}
 private func tunnelError(_ code:Int,_ text:String)->NSError{NSError(domain:"ProviderBoundary",code:code,userInfo:[NSLocalizedDescriptionKey:text])}
 private func native(_ provider:[String:Any],_ complete:@escaping(Error?)->Void)throws{libboxEngine=PrestartEngine(trace);try trace.started(provider,complete:complete)}
 private func startWireGuard(provider:[String:Any],root:[String:Any],selectedProfile:[String:Any],completionHandler:@escaping(Error?)->Void)throws{try native(provider,completionHandler)}
 private func startLibbox(provider:[String:Any],root:[String:Any],selectedProfile:[String:Any],strict:Bool,completionHandler:@escaping(Error?)->Void)throws{try native(provider,completionHandler)}
 private func startMultihop(provider:[String:Any],root:[String:Any],selectedProfile:[String:Any],completionHandler:@escaping(Error?)->Void)throws{try native(provider,completionHandler)}
 private func startExternalLibbox(provider:[String:Any],selectedProfile:[String:Any],strict:Bool,completionHandler:@escaping(Error?)->Void)throws{try native(provider,completionHandler)}
 private func beginProviderStrategy(provider:[String:Any],bundleData:Data,root:[String:Any],selectedProfile:[String:Any],strict:Bool,maxSources:[String:String],completionHandler:@escaping(Error?)->Void)throws{throw tunnelError(1,"Strategies execute in their separate actual-driver gate")}
__PRODUCTION__
}

@MainActor func providerPrestartTests(good:[String:Any],fixtures:[String:Any])throws->Int{
 var checks=0
 func check(_ name:String,_ value:@autoclosure ()throws->Bool)throws{guard try value() else{fatalError(name)};checks+=1}
 for engine in ["libbox","external-libbox"]{for selected in ["empty","missing"]{
  var config=good,root=try object(good["bundle"] as! Data),profiles=try object(good["bundle"] as! Data)["profiles"] as! [String:[String:String]]
  profiles["wg"]=["wg.conf":profiles["max-tls-wg"]!["wg.conf"]!];root["profiles"]=profiles
  if engine=="external-libbox" {
   var nodes=root["routerProfiles"] as! [[String:Any]]
   nodes[0]["node_kind"]="external";nodes[0]["start_layer"]="off"
   nodes[0]["external"]=["protocol":"shadowsocks","expected_public_ip":"203.0.113.88","shadowsocks":["server":"198.51.100.8","port":8388,"method":"aes-256-gcm","password":"captured external fixture secret"]]
   root["routerProfiles"]=nodes;config["mode"]="external-shadowsocks"
  }
  if selected=="empty"{root["selectedRouterID"]=""}else{root.removeValue(forKey:"selectedRouterID")}
  config["bundle"]=try json(root);config["rawProfileID"]="wg";config["engine"]=engine;config.removeValue(forKey:"max_source_sha256")
  let queries=DNSSDTest.shared.counts().0,captures=NetworkTest.shared.counts().0
  do{let q=try RouterVPNMAXPreparation(provider:config);try check("no-MAX legacy source keeps its ordinary dispatch",!q.requiresResolution && q.sourceHashes.isEmpty);q.close()}
  catch{fatalError("no-MAX legacy profile was blocked: "+engine+"/"+selected)}
  let p=PacketTunnelProvider(),started=Outcome(),stopped=Outcome();p.configure(config);p.startTunnel{started.receive($0)}
  try check("actual provider preserves its single-profile legacy selector",p.trace.entered.wait(timeout:.now()+3) == .success && p.trace.counts().0==1)
  p.trace.prove();try check("ordinary legacy proof completes without MAX DNS",started.done.wait(timeout:.now()+3) == .success && started.result().1 && DNSSDTest.shared.counts().0==queries && NetworkTest.shared.counts().0==captures)
  p.stopTunnel(with:.userInitiated){stopped.receive(nil)};try check("ordinary legacy owner retires",stopped.done.wait(timeout:.now()+3) == .success && p.trace.counts().1==1)
  config["engine"]="libbox";config["rawProfileID"]="max-tls-wg"
  do{_ = try RouterVPNMAXPreparation(provider:config);fatalError("actual MAX selection relaxed its exact selected identity")}
  catch{checks+=1}
 }}
 let routes=try capturedRoutes(fixtures)
 for input in routes{
  DNSSDTest.shared.configure();NetworkTest.shared.set()
  let p=PacketTunnelProvider(),started=Outcome(),stop=Outcome(),before=DNSSDTest.shared.counts().0
  p.configure(input);p.startTunnel{started.receive($0)}
  try check("actual provider dispatch receives private launch",p.trace.entered.wait(timeout:.now()+5) == .success)
  let launch=try p.trace.launch(),sources=try IOSMAXSourceSelection.sources(provider:launch),original=try IOSMAXSourceSelection.sources(provider:input)
  try check("all selected slots resolved once",sources.count==original.count && sources.allSatisfy{$0.input.endpoint=="192.0.2.71"} && DNSSDTest.shared.counts().0==before+sources.count)
  try check("original slot identities and policy remain saved",original.allSatisfy{$0.input.endpoint.hasSuffix(".example")} && launch["max_source_sha256"] as? [String:String]==input["max_source_sha256"] as? [String:String])
  try check("provider dispatch keeps engine and one native owner",launch["engine"] as? String==input["engine"] as? String && p.trace.counts().0==1)
  try check("actual provider completion still waits native proof",started.done.wait(timeout:.now()+0.03) == .timedOut)
  p.trace.prove()
  try check("proof succeeds once after DNS ownership retirement",started.done.wait(timeout:.now()+5) == .success && started.result().0==1 && started.result().1 && DNSSDTest.shared.counts().2==0 && NetworkTest.shared.counts().1==0)
  p.stopTunnel(with:.userInitiated){stop.receive(nil)}
  try check("actual provider Stop closes its sole native owner",stop.done.wait(timeout:.now()+5) == .success && p.trace.counts().1==1)
  p.trace.prove(NSError(domain:"late-proof",code:1));try check("late proof cannot republish completion",started.result().0==1)
 }
 DNSSDTest.shared.configure(hold:true,block:true);NetworkTest.shared.set()
 let pending=PacketTunnelProvider(),start=Outcome(),stopped=Outcome();pending.configure(good);pending.startTunnel{start.receive($0)}
 try check("actual provider owns pending DNS",DNSSDTest.shared.entered.wait(timeout:.now()+5) == .success)
 let began=Date();pending.stopTunnel(with:.userInitiated){stopped.receive(nil)}
 try check("actual provider Stop is immediately cancellable",Date().timeIntervalSince(began)<0.5)
 try check("actual provider joins DNS deallocation",DNSSDTest.shared.closing.wait(timeout:.now()+3) == .success && stopped.done.wait(timeout:.now()+0.03) == .timedOut && start.done.wait(timeout:.now()+0.03) == .timedOut && pending.trace.counts().0==0)
 let racing=Outcome();pending.startTunnel{racing.receive($0)}
 try check("replacement cannot enter while Stop retains DNS",racing.done.wait(timeout:.now()+3) == .success && !racing.result().1 && pending.trace.counts().0==0)
 DNSSDTest.shared.releaseClose.signal()
 try check("Stop completion proves actual prestart retirement",stopped.done.wait(timeout:.now()+5) == .success && start.done.wait(timeout:.now()+3) == .success && !start.result().1 && start.result().0==1 && DNSSDTest.shared.counts().2==0 && NetworkTest.shared.counts().1==0)
 DNSSDTest.shared.configure();NetworkTest.shared.set()
 let restart=Outcome();pending.startTunnel{restart.receive($0)}
 try check("retired provider may start a fresh captured owner",pending.trace.entered.wait(timeout:.now()+5) == .success && pending.trace.counts().0==1)
 pending.trace.prove();try check("fresh owner proves after retirement",restart.done.wait(timeout:.now()+5) == .success && restart.result().1)
 let restop=Outcome();pending.stopTunnel(with:.userInitiated){restop.receive(nil)};try check("fresh owner cleanup",restop.done.wait(timeout:.now()+3) == .success)
 DNSSDTest.shared.configure();NetworkTest.shared.set()
 let adopting=PacketTunnelProvider(),adoption=Outcome(),adoptionStop=Outcome();adopting.configure(good);adopting.trace.hold();adopting.startTunnel{adoption.receive($0)}
 try check("actual native adoption can be pending",adopting.trace.entered.wait(timeout:.now()+5) == .success)
 adopting.trace.prove();adopting.stopTunnel(with:.userInitiated){adoptionStop.receive(nil)}
 try check("Stop cannot release an admitted native-start worker",adoptionStop.done.wait(timeout:.now()+0.03) == .timedOut && adoption.done.wait(timeout:.now()+0.03) == .timedOut)
 adopting.trace.release.signal()
 try check("Stop joins actual adoption before closing native owner",adoptionStop.done.wait(timeout:.now()+5) == .success && adoption.done.wait(timeout:.now()+3) == .success && !adoption.result().1 && adoption.result().0==1 && adopting.trace.counts().1==1)
 DNSSDTest.shared.configure();NetworkTest.shared.set()
 let sleeping=PacketTunnelProvider(),sleepStart=Outcome(),slept=Outcome();sleeping.configure(good);DNSSDTest.shared.configure(hold:true);sleeping.startTunnel{sleepStart.receive($0)}
 try check("sleep fixture owns DNS",DNSSDTest.shared.entered.wait(timeout:.now()+5) == .success)
 sleeping.sleep{slept.receive(nil)}
 try check("sleep retires pending resolver before completion",slept.done.wait(timeout:.now()+5) == .success && sleepStart.done.wait(timeout:.now()+3) == .success && !sleepStart.result().1 && sleeping.trace.counts().0==0 && NetworkTest.shared.counts().1==0)
 return checks
}

@MainActor func providerExecutionTests(fixtures:[String:Any])throws->Int{
 var checks=0
 func check(_ name:String,_ value:@autoclosure ()throws->Bool)throws{guard try value() else{fatalError(name)};checks+=1}
 let input=try checked(changedBundle(capturedRoutes(fixtures)[1]){_,node in node["multihop_execution"]="auto"})
 let digest:(Data)->String={SHA256.hash(data:$0).map{String(format:"%02x",$0)}.joined()}
 let source=try IOSMultihopExecution.Source(configuration:input,digest:digest),hold=String(repeating:"e",count:32)
 let capture=try IOSMultihopExecution.Capture(source:source,execution:"server",session:UUID().uuidString,request:String(repeating:"a",count:32))
 let receipt=String(decoding:try capture.encoded(),as:UTF8.self) as NSString
 let options:[String:NSObject]=["routervpn_mtu_hold":hold as NSString,IOSMultihopExecution.launchKey:receipt]
 DNSSDTest.shared.configure();NetworkTest.shared.set()
 let p=PacketTunnelProvider(),started=Outcome(),stopped=Outcome();p.configure(input);p.startTunnel(options:options){started.receive($0)}
 try check("actual provider accepts the proved winner before DNS preparation",p.trace.entered.wait(timeout:.now()+5) == .success && p.executionState().0==source && p.executionState().1=="server")
 let launch=try p.trace.launch(),launchedSource=try IOSMultihopExecution.Source(configuration:launch,digest:digest)
 try check("receipt retains original hostname sources across private resolution",launchedSource != source && p.executionState().0==source && source.requested=="auto")
 p.trace.prove();try check("restored startup still needs native proof",started.done.wait(timeout:.now()+5) == .success && started.result().1)
 p.stopTunnel(with:.userInitiated){stopped.receive(nil)};try check("restored native owner retires",stopped.done.wait(timeout:.now()+5) == .success && p.trace.counts().1==1)
 for fault in ["exit-source","entry-source","missing-hold","wrong-engine","malformed-receipt"] {
  var config=input,arguments=options
  switch fault {
  case "exit-source":config=try changedBundle(config){_,node in node["api_token"]="replacement-private-token"}
  case "entry-source":var entry=try object(config["entryBundle"] as! Data);entry["unrelated_saved_field"]="changed";config["entryBundle"]=try json(entry)
  case "missing-hold":arguments.removeValue(forKey:"routervpn_mtu_hold")
  case "wrong-engine":config["engine"]="libbox"
  default:arguments[IOSMultihopExecution.launchKey]="{}" as NSString
  }
  let rejected=PacketTunnelProvider(),result=Outcome(),queries=DNSSDTest.shared.counts().0;rejected.configure(config);rejected.startTunnel(options:arguments){result.receive($0)}
  try check("actual provider rejects invalid restoration before DNS or native start: "+fault,result.done.wait(timeout:.now()+3) == .success && !result.result().1 && rejected.trace.counts().0==0 && DNSSDTest.shared.counts().0==queries)
 }
 return checks
}
'''


def prestart_source():
    source = (TUN / 'PacketTunnelProvider.swift').read_text()
    def section(begin, end):
        return source[source.index(begin):source.index(end, source.index(begin))]
    parts = [
        section('    private var multihopExecutionSource:', '    private var forwardingChannel:'),
        section('    private let maxStartOwnerLock', '    override init()'),
        section('    override func startTunnel(', '    private func startWireGuard('),
        section('    override func stopTunnel(', '    override func wake()'),
        section('    private func selectedRouterProfile(', '    private func wireGuardLikeProfile('),
        section('    private func strictKillSwitchRequested(', '    private func suppliedNodeProof('),
    ]
    return PRESTART_BOUNDARY.replace('__PRODUCTION__', '\n'.join(parts))


def run(command, **kwargs):
    subprocess.run(command, check=True, timeout=kwargs.pop('timeout', 120), **kwargs)


def main():
    with tempfile.TemporaryDirectory(prefix='.ios-max-hostname-go-', dir=ROOT) as source, tempfile.TemporaryDirectory(prefix='ios-max-hostname-') as work:
        source, work = Path(source), Path(work)
        fixtures = work / 'profiles.json'
        multihop = work / 'multihop.json'
        run(['go', 'test', '-count=1', '-run', '^TestExportMAX(Multihop)?MobileProfiles$', './internal/mobilemultihop'], cwd=ROOT,
            env=dict(os.environ, ROUTERVPN_MAX_PROFILE_FIXTURES=str(fixtures), ROUTERVPN_MAX_MULTIHOP_FIXTURES=str(multihop)))
        (source / 'main.go').write_text(GO)
        run(['go', 'build', '-o', str(work / 'compiler'), str(source / 'main.go')], cwd=ROOT)
        modules = {'Network': NETWORK, 'dnssd': DNSSD, 'Libbox': LIBBOX}
        if platform.system() != 'Darwin':
            modules['Darwin'] = '@_exported import Glibc\n'
        libraries = []
        extension = 'dylib' if platform.system() == 'Darwin' else 'so'
        for name, value in modules.items():
            file = work / (name + '.swift'); file.write_text(value)
            run(['swiftc', '-swift-version', '6', '-emit-module', '-emit-library', '-module-name', name,
                 str(file), '-o', str(work / ('lib' + name + '.' + extension))], cwd=work)
            libraries.append('-l' + name)
        tests = work / 'Tests.swift'; tests.write_text(SWIFT + prestart_source())
        run(['swiftc', '-swift-version', '6', '-I', str(work), '-L', str(work), *libraries,
             '-Xlinker', '-rpath', '-Xlinker', str(work), str(APP / 'IOSNativePQProfile.swift'),
              str(APP / 'IOSMultihopStartLayer.swift'), str(APP / 'IOSMultihopExecution.swift'), str(TUN / 'RouterVPNMAXDNSOwner.swift'),
             str(TUN / 'RouterVPNMAXPreparation.swift'), str(tests), '-o', str(work / 'tests')])
        run([str(work / 'tests'), str(work / 'compiler'), str(fixtures), str(multihop)], timeout=150)


if __name__ == '__main__':
    main()
