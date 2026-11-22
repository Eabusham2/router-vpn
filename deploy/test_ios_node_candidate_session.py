#!/usr/bin/env python3
"""Execute the retained Apple session/registry using real publication files.

Libbox's SDK/native object boundary is doubled with signatures checked against
its generated ObjC declarations; native Go worker semantics have separate tests.
"""
from pathlib import Path
import platform
import subprocess
import tempfile
from test_ios_physical_path import LINUX_CRYPTO
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
LIBBOX=r'''
import Foundation
public protocol LibboxRouterNodeChainCandidateCatalogProtocol: AnyObject {func currentInventorySHA256()->String}
public final class LibboxRouterNodeChain {
 public var slot:LibboxRouterNodeChainCandidateMeasurement?
 public init(){}
 public func sourceSHA256()->String{String(repeating:"a",count:64)}
 public func configSHA256()->String{String(repeating:"b",count:64)}

}
public final class LibboxCommandServer {public init(){}}
public final class Fixture: @unchecked Sendable {
 public static let shared=Fixture()
 public var family="ordinary",prepared=0,created=0,starts=0,closed=0,scoped=0,failFactory=false,failClose=false
 public var enter:DispatchSemaphore?,release:DispatchSemaphore?
 public init(){}
 public func reset(){prepared=0;created=0;starts=0;closed=0;scoped=0;failFactory=false;failClose=false;enter=nil;release=nil}
}
public final class LibboxRouterNodeChainCandidateMeasurement {
 private let owner:LibboxRouterNodeChain,catalog:LibboxRouterNodeChainCandidateCatalogProtocol
 private var closed=false,ready=false,attempted=false
 public init(_ owner:LibboxRouterNodeChain,_ catalog:LibboxRouterNodeChainCandidateCatalogProtocol){self.owner=owner;self.catalog=catalog}
 public func prepare()throws{
  guard owner.slot===self,!closed,!attempted else{throw NSError(domain:"ForeignReservation",code:1)}
  attempted=true;Fixture.shared.prepared+=1
  Fixture.shared.enter?.signal();Fixture.shared.release?.wait()
  guard !Fixture.shared.failFactory,!catalog.currentInventorySHA256().isEmpty else{throw NSError(domain:"FailedPreparePendingJoin",code:1)}
  ready=true
 }
 public func metadataPage(_ offset:Int32)->String{""}
 public func metadata()->String{ready ? "metadata" : ""}
 public func captureSHA256()->String{String(repeating:"a",count:64)}
 public func start(_ request:String,candidateID:String)throws{guard owner.slot===self,ready,!closed else{throw NSError(domain:"UnpreparedReservation",code:1)};Fixture.shared.starts+=1}
 public func statusJSON()->String{"status"}
 public func cancel(_ request:String){}
 public func networkChanged(){}
 public func close()throws{
  if closed{return}
  guard owner.slot===self else{throw NSError(domain:"ForeignReservation",code:1)}
  Fixture.shared.closed+=1
  if Fixture.shared.failClose{throw NSError(domain:"NativeJoinPending",code:1)}
  owner.slot=nil;closed=true
 }
}
public func LibboxRouterNodeChainNewCandidateMeasurement(_ plan:LibboxRouterNodeChain,_ server:LibboxCommandServer,_ prefix:Int32,_ inventory:String,_ catalog:LibboxRouterNodeChainCandidateCatalogProtocol,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainCandidateMeasurement?{
 Fixture.shared.created+=1
 guard plan.slot==nil else{error?.pointee=NSError(domain:"ReservationAlreadyOwned",code:1);return nil}
 let handle=LibboxRouterNodeChainCandidateMeasurement(plan,catalog);plan.slot=handle;return handle
}
'''
# Distinct SDK objects retain dispatch observability; these are native-boundary
# doubles, not proof or connected-state receipts.
_TYPED_NATIVE=r'''
public final class LibboxRouterNodeChainFAMILY {
 public var slot:LibboxRouterNodeChainFAMILYCandidateMeasurement?
 public init(){}
}
public final class LibboxRouterNodeChainFAMILYCandidateMeasurement {
 private let owner:LibboxRouterNodeChainFAMILY,catalog:LibboxRouterNodeChainCandidateCatalogProtocol
 private var closed=false,ready=false
 public init(_ owner:LibboxRouterNodeChainFAMILY,_ catalog:LibboxRouterNodeChainCandidateCatalogProtocol){self.owner=owner;self.catalog=catalog}
 public func prepare()throws{
  guard owner.slot===self,!closed else{throw NSError(domain:"ForeignReservation",code:1)}
  Fixture.shared.prepared+=1
  Fixture.shared.enter?.signal();Fixture.shared.release?.wait()
  guard !Fixture.shared.failFactory,!catalog.currentInventorySHA256().isEmpty else{throw NSError(domain:"FailedPreparePendingJoin",code:1)}
  ready=true
 }
 public func metadataPage(_ offset:Int32)->String{""}
 public func metadata()->String{ready ? "metadata" : ""}
 public func start(_ request:String,candidateID:String)throws{guard owner.slot===self,ready,!closed else{throw NSError(domain:"UnpreparedReservation",code:1)};Fixture.shared.starts+=1}
 public func statusJSON()->String{"status"}
 public func cancel(_ request:String){}
 public func networkChanged(){}
 public func close()throws{
  if closed{return}
  guard owner.slot===self else{throw NSError(domain:"ForeignReservation",code:1)}
  Fixture.shared.closed+=1
  if Fixture.shared.failClose{throw NSError(domain:"NativeJoinPending",code:1)}
  owner.slot=nil;closed=true
 }
}
public func LibboxRouterNodeChainFAMILYNewCandidateMeasurement(_ plan:LibboxRouterNodeChainFAMILY,_ server:LibboxCommandServer,_ prefix:Int32,_ inventory:String,_ catalog:LibboxRouterNodeChainCandidateCatalogProtocol,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainFAMILYCandidateMeasurement?{
 Fixture.shared.family="FAMILY";Fixture.shared.created+=1
 guard plan.slot==nil else{error?.pointee=NSError(domain:"ReservationAlreadyOwned",code:1);return nil}
 let handle=LibboxRouterNodeChainFAMILYCandidateMeasurement(plan,catalog);plan.slot=handle;return handle
}
'''
for family in ('SOCKS','CONNECT','Execution'):LIBBOX+=_TYPED_NATIVE.replace('FAMILY',family)
SWIFT=r'''
import Foundation
import Libbox
struct Failed:Error{let text:String}
func check(_ value:Bool,_ text:String)throws{if !value{throw Failed(text:text)}}
func rejects(_ text:String,_ action:()throws->Void)throws{do{try action()}catch{return};throw Failed(text:"ACCEPTED "+text)}
final class Owner:@unchecked Sendable{let lock=NSLock();var alive=true;func current()->Bool{lock.lock();defer{lock.unlock()};return alive};func retire(){lock.lock();alive=false;lock.unlock()}}

struct IOSNodeChainCapture {
 struct Member {let id:String;let mode:String;let profile:[String:Any]}
 let members:[Member]
 init(plan:LibboxRouterNodeChain)throws{members=[Member(id:"entry",mode:"wg",profile:["node_proof_id":"proof"]),Member(id:"final",mode:"shadowsocks",profile:["node_proof_id":"final-proof"])]}
}
struct IOSNodeChainSOCKSCapture {let plan=LibboxRouterNodeChainSOCKS();let members:[IOSNodeChainCapture.Member];init(_ count:Int){members=(0..<count).map{.init(id:"node-\($0)",mode:$0==count-2 ? "socks5" : "wg",profile:["node_proof_id":$0==count-2 ? "" : "proof-\($0)"])}}}
struct IOSNodeChainCONNECTCapture {let plan=LibboxRouterNodeChainCONNECT();let members:[IOSNodeChainCapture.Member];init(_ count:Int){members=(0..<count).map{.init(id:"node-\($0)",mode:$0==count-2 ? "https-connect" : "wg",profile:["node_proof_id":$0==count-2 ? "" : "proof-\($0)"])}}}
final class RouterVPNNodeChainSOCKSHost {let capture:IOSNodeChainSOCKSCapture;init(_ count:Int){capture = .init(count)}}
final class RouterVPNNodeChainCONNECTHost {let capture:IOSNodeChainCONNECTCapture;init(_ count:Int){capture = .init(count)}}
// Explicit selected-execution/native boundary. The real host dispatch and
// retained session/registry below execute unchanged; no encrypted path is modeled.
struct IOSNodeChainExecutionCapture {
 let plan=LibboxRouterNodeChainExecution()
 let members:[IOSNodeChainCapture.Member],requested:String,selected:String
 let sourceSHA256=String(repeating:"c",count:64),configSHA256=String(repeating:"d",count:64)
 var ordinaryLaunchInput:String{String(decoding:try! JSONSerialization.data(withJSONObject:["source_sha256":sourceSHA256,"config_sha256":String(repeating:"e",count:64)]),as:UTF8.self)}
 let kind:String
 var isSOCKS:Bool{kind=="SOCKS"}
 var isCONNECT:Bool{kind=="CONNECT"}
 // SHIPPING_POSITIONS
 // SHIPPING_HEX
 init(_ count:Int,_ requested:String,_ selected:String,_ kind:String){
  self.requested=requested;self.selected=selected;self.kind=kind
  let imports=kind=="Multiple" ? Set([1,count-2]):kind=="Ordinary" ? Set<Int>():Set([count-2])
  let importedMode=["SOCKS":"socks5","CONNECT":"https-connect","OpenVPN":"openvpn"][kind] ?? "shadowsocks"
  members=(0..<count).map { position in
   let imported=imports.contains(position)
   return .init(id:"execution-node-\(position)",mode:position==count-1 ? "shadowsocks":imported ? importedMode : position==0 ? "wg":"awg2-strong",
                profile:["node_kind":imported ? "external":"router-vpn","node_proof_id":imported ? "" : String(repeating:String(position),count:64)])
  }
 }
 func healthy()->Bool{true}
 func execution()throws->String{selected}
}
final class RouterVPNNodeChainExecutionHost {
 let capture:IOSNodeChainExecutionCapture
 init(_ count:Int,_ requested:String,_ selected:String,_ kind:String){capture = .init(count,requested,selected,kind)}
 func observe(_ action:()throws->Void)throws{try action()}
}
enum IOSNodeCandidateOriginalCapture {
 case ordinary(IOSNodeChainCapture),socks(IOSNodeChainSOCKSCapture),connect(IOSNodeChainCONNECTCapture)
 var members:[IOSNodeChainCapture.Member]{switch self{case .ordinary(let v):return v.members;case .socks(let v):return v.members;case .connect(let v):return v.members}}
 var sourceSHA256:String{String(repeating:"a",count:64)}
 var configSHA256:String{String(repeating:"b",count:64)}
}
final class MTU {
 var hasOwner=false,measurementReady=true
 func request(operation:String,request:String,session:String)->Data?{try? JSONSerialization.data(withJSONObject:["ack_id":request,"session_id":UUID().uuidString])}
}
final class Platform{let mtu=MTU()}
final class Engine {
 let ownershipLock=NSLock(),platform=Platform(),settingsEpoch=UUID().uuidString
 var nodeChain:LibboxRouterNodeChain?=LibboxRouterNodeChain(),server:LibboxCommandServer?=LibboxCommandServer(),nodeChainDelivery:NSObject?=NSObject()
 var nodeChainSOCKS:RouterVPNNodeChainSOCKSHost?,nodeChainCONNECT:RouterVPNNodeChainCONNECTHost?
 var nodeChainExecution:RouterVPNNodeChainExecutionHost?
 var nodeCandidatePrefix:NSObject?
 var pendingTypedCandidateCleanup:(session:RouterVPNNodeCandidateSession,server:LibboxCommandServer?)?
 func error(_ text:String)->NSError{NSError(domain:"Cleanup",code:1,userInfo:[NSLocalizedDescriptionKey:text])}
 var nodeCandidate:RouterVPNNodeCandidateSession?,ownershipGeneration=UUID(),starting=false,permanentlyStopped=false
 let publication:IOSCandidateCatalogPublication,registry:RouterVPNNodeCandidateRegistry
 init(_ publication:IOSCandidateCatalogPublication){self.publication=publication;registry=RouterVPNNodeCandidateRegistry(publication:publication)}
 // SHIPPING_CLEANUP
 // SHIPPING_ENGINE
}
@main struct Test{
 static func main()throws{
  let root=URL(fileURLWithPath:CommandLine.arguments[1]);try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true)
  let publication=IOSCandidateCatalogPublication(container:root),records=["all":Data("actual original bytes".utf8)]
  try publication.publish(records)
  func make(_ char:String,_ owner:Owner=Owner(),nativeOwner:RouterVPNNodeCandidateOwner?=nil,nativeServer:LibboxCommandServer?=nil,epoch:String?=nil)throws->RouterVPNNodeCandidateSession{
   let request=char.count==32 ? char : String(repeating:char,count:32),stamp=try publication.current(records:records)
   let inventory=try JSONSerialization.data(withJSONObject:["schema":1,"revision":stamp.revision,"inputs":["exact source"]])
   let source=try publication.capture(request:request,inventory:inventory,expected:stamp)
   return RouterVPNNodeCandidateSession(owner:nativeOwner ?? .ordinary(LibboxRouterNodeChain()),server:nativeServer ?? LibboxCommandServer(),prefix:0,epoch:epoch ?? UUID().uuidString,source:source,publication:publication,current:{owner.current()})
  }
  let f=Fixture.shared,registry=RouterVPNNodeCandidateRegistry(publication:publication)
  let owner=Owner(),session=try make("a",owner)
  try check(registry.retain(session),"register original factory before work")
  try check(try session.open()=="metadata" && f.created==1 && f.prepared==1,"original factory")
  _ = try session.open();try check(f.created==1,"retry open retains same handle")
  let request=String(repeating:"b",count:32)
  _ = try session.start(request:request,candidate:"one");_ = try session.start(request:request,candidate:"one")
  try check(f.starts==1,"duplicate start cannot renew completion")
  try rejects("same request another candidate"){_ = try session.start(request:request,candidate:"two")}
  owner.retire();try check(session.currentInventorySHA256().isEmpty,"retired original owner")
  try rejects("retired status"){_ = try session.status(request:request)}
  f.failClose=true;try check(!registry.close(epoch:session.epoch,request:session.request),"failed join remains retained")
  f.failClose=false;try check(registry.close(epoch:session.epoch,request:session.request),"retry joins original")
  try check(!registry.retain(session),"closed factory cannot revive")
  try check(publication.closed(epoch:session.epoch,request:session.request),"lost IPC recovers only exact joined owner")
  try check(!publication.closed(epoch:UUID().uuidString,request:session.request),"foreign session cannot recover receipt")
  let closes=f.closed;try check(registry.close(epoch:session.epoch,request:session.request) && f.closed==closes,"closed receipt is stable")
  f.reset();let failed=try make("c");try check(registry.retain(failed),"retain failed factory")
  f.failFactory=true;try rejects("failed factory"){_ = try failed.open()}
  try rejects("failed ordinary Prepare cannot restart"){_ = try failed.open()}
  try check(f.prepared==1,"ordinary Prepare is one-shot after failure")
  f.failClose=true;try check(!registry.close(epoch:failed.epoch,request:failed.request) && f.closed==1 && f.scoped==0,"failed ordinary Prepare retains exact handle")
  f.failClose=false;try check(registry.close(epoch:failed.epoch,request:failed.request) && f.closed==2 && f.scoped==0,"failed ordinary Prepare retries exact handle")
  f.reset();let before=try make("d")
  try check(registry.close(epoch:before.epoch,request:before.request),"cancel before open tombstone")
  try check(!registry.retain(before) && f.created==0,"late factory refused")
  f.reset();let late=try make("e");try check(registry.retain(late),"retain late factory")
  let entered=DispatchSemaphore(value:0),release=DispatchSemaphore(value:0),finished=DispatchSemaphore(value:0)
  f.enter=entered;f.release=release
  DispatchQueue.global().async{defer{finished.signal()};_ = try? late.open()}
  try check(entered.wait(timeout:.now()+2) == .success,"real factory entered")
  late.invalidate();try check(late.currentInventorySHA256().isEmpty,"cancel visible without native operation lock")
  let attemptedClose=DispatchSemaphore(value:0)
  DispatchQueue.global().async{_ = registry.close(epoch:late.epoch,request:late.request);attemptedClose.signal()}
  try check(attemptedClose.wait(timeout:.now()+1) == .success,"close cannot queue behind blocked factory")
  try check(!publication.closed(epoch:late.epoch,request:late.request),"blocked factory is not joined")
  release.signal();try check(finished.wait(timeout:.now()+2) == .success,"late factory finishes")
  try check(registry.close(epoch:late.epoch,request:late.request) && f.closed==1,"late returned handle joined")

  f.reset();let sourceChanged=try make("1")
  _ = try sourceChanged.open()
  try publication.publish(records)
  try check(sourceChanged.currentInventorySHA256().isEmpty,"actual catalog publication changes revoke live callback")
  try sourceChanged.close()
  f.reset();let unused=try make("f"),engine=Engine(publication)
  let info=engine.candidateMeasurementRequest(operation:"candidate-info",request:unused.request,session:"",ownerRequest:"",prefix:"",candidate:"")
  try check(info != nil,"shipping engine info")
  func command(_ op:String,_ nonce:String=unused.request,_ candidate:String="",_ prefix:String="",_ epoch:String?=nil)->Data?{
   engine.candidateMeasurementRequest(operation:op,request:nonce,session:epoch ?? engine.settingsEpoch,ownerRequest:unused.request,prefix:prefix,candidate:candidate)
  }
  try check(command("candidate-open",unused.request,"","0") != nil && f.created==1,"shipping engine original factory")
  try check(command("candidate-start",request,"one") != nil && f.starts==1,"shipping engine start")
  try check(command("candidate-close",unused.request,"","",UUID().uuidString)==nil && f.closed==0,"foreign epoch cannot close original")
  engine.ownershipGeneration=UUID()
  try check(command("candidate-status",request)==nil,"shipping engine generation change invalidates callback")
  try check(command("candidate-close") != nil && f.closed==1 && engine.nodeCandidate==nil,"shipping engine closes retained original after generation loss")
  // The same original ordinary plan can host a replacement only after the
  // first session joins. Constructor refusal owns no cleanup authority.
  f.reset();let ordinaryPlan=LibboxRouterNodeChain(),ordinaryServer=LibboxCommandServer()
  let ordinaryOriginal=try make("2",nativeOwner:.ordinary(ordinaryPlan),nativeServer:ordinaryServer)
  _ = try ordinaryOriginal.open()
  let ordinaryRefused=try make("3",nativeOwner:.ordinary(ordinaryPlan),nativeServer:ordinaryServer)
  try rejects("ordinary duplicate reservation"){_ = try ordinaryRefused.open()}
  try ordinaryRefused.close()
  try check(f.closed==0 && f.scoped==0 && f.prepared==1,"ordinary constructor refusal cannot close active reservation")
  _ = try ordinaryOriginal.start(request:request,candidate:"original")
  try check(ordinaryOriginal.matches(owner:.ordinary(ordinaryPlan),server:ordinaryServer),"ordinary original server identity")
  try check(!ordinaryOriginal.matches(owner:.ordinary(LibboxRouterNodeChain()),server:ordinaryServer),"ordinary foreign owner refused")
  try ordinaryOriginal.close()
  let ordinaryReplacement=try make("4",nativeOwner:.ordinary(ordinaryPlan),nativeServer:ordinaryServer)
  _ = try ordinaryReplacement.open();let ordinaryCloses=f.closed
  try ordinaryOriginal.close();try ordinaryRefused.close()
  try check(f.closed==ordinaryCloses && !ordinaryReplacement.currentInventorySHA256().isEmpty,"ordinary stale same-source cleanup cannot close replacement")
  _ = try ordinaryReplacement.start(request:request,candidate:"replacement");try ordinaryReplacement.close()
  // Actual shipping method dispatches complete typed owners; only SDK I/O is doubled.
  let selectedKinds=["Ordinary","Imported","OpenVPN","Multiple","SOCKS","CONNECT"]
  let families=["SOCKS","CONNECT"]+selectedKinds.flatMap{kind in ["Server","Local","Compare"].map{"Execution"+kind+$0}}
  for family in families {for count in (family.contains("Multiple") ? [5,8]:[3,4,8]) {
   let selectedExecution=family.hasPrefix("Execution")
   let kind=selectedKinds.first(where:{family.hasPrefix("Execution"+$0)}) ?? ""
   let allowed:[Int]
   switch kind {
   case "Ordinary": allowed=Array(0..<count-1)
   case "Multiple": allowed=(0..<count-1).filter{$0 != 1 && $0 != count-2}
   case "Imported","OpenVPN": allowed=Array(0..<count-2)
   default: allowed=[0]
   }
   let position=selectedExecution ? allowed.last! : count-3
   let nativeFamily=selectedExecution ? "Execution":family
   f.reset();let input=try make(UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased()),typed=Engine(publication)
   typed.nodeChain=nil;typed.nodeChainDelivery=nil
   let original:RouterVPNNodeCandidateOwner
   if family=="SOCKS"{let host=RouterVPNNodeChainSOCKSHost(count);typed.nodeChainSOCKS=host;original = .socks(host.capture.plan)}
   else if family=="CONNECT"{let host=RouterVPNNodeChainCONNECTHost(count);typed.nodeChainCONNECT=host;original = .connect(host.capture.plan)}
   else{let host=RouterVPNNodeChainExecutionHost(count,family.hasSuffix("Server") ? "server":"auto",family.hasSuffix("Local") ? "local":"server",kind);typed.nodeChainExecution=host;original = .execution(host.capture.plan)}
   func call(_ op:String,_ nonce:String?=nil,_ candidate:String="",_ prefix:String="")->Data?{
    typed.candidateMeasurementRequest(operation:op,request:nonce ?? input.request,session:op=="candidate-info" ? "" : typed.settingsEpoch,ownerRequest:op=="candidate-info" ? "" : input.request,prefix:prefix,candidate:candidate)
   }
   let info=try JSONSerialization.jsonObject(with:call("candidate-info")!) as! [String:Any]
   if family.contains("Multiple"){
    for blocked in [1,count-2,count-1]{try check(call("candidate-open",nil,"",String(blocked))==nil && f.created==0,"selected imported or final appointment acquired a packet stop")}
   }
   try check((info["proofs"] as? [[String:Any]])?.count==count,"complete typed member inventory")
   if selectedExecution {
    try check(info["candidate_positions"] as? [Int] == allowed && info["requested_execution"] as? String == typed.nodeChainExecution!.capture.requested && info["execution"] as? String == typed.nodeChainExecution!.capture.selected,"selected execution information retains original choice")
    try check(info["source_sha256"] as? String == String(repeating:"c",count:64) && info["config_sha256"] as? String == String(repeating:"d",count:64) && info["proposal_config_sha256"] as? String == String(repeating:"e",count:64),"active preparation differs from original proposal without substitution")
    for blocked in 0..<count where !allowed.contains(blocked) {
     try check(call("candidate-open",nil,"",String(blocked))==nil && f.created==0,"selected execution refuses ineligible prefix before reservation")
    }
   }
   try check(call("candidate-open",nil,"",String(position)) != nil && f.family==nativeFamily && f.created==1 && f.prepared==1,"typed original factory dispatch and Prepare")
   let retained=typed.nodeCandidate!,retainedServer=typed.server!
   let copiedSession=RouterVPNNodeCandidateSession(owner:original,server:retainedServer,prefix:Int32(position),epoch:retained.epoch,source:try publication.reopen(request:retained.request),publication:publication,current:{true})
   try check(!typed.registry.close(original:copiedSession) && !retained.currentInventorySHA256().isEmpty,"equal-key copied session cannot retire original")
   try check(call("candidate-start",request,"one") != nil && f.starts==1,"typed start")
   let constructorRefused=try make(UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased(),nativeOwner:original,nativeServer:retainedServer)
   try rejects("duplicate native reservation"){_ = try constructorRefused.open()}
   try constructorRefused.close()
   try check(f.closed==0 && f.scoped==0 && f.prepared==1 && !retained.currentInventorySHA256().isEmpty,"rejected constructor has no authority over active reservation")
   let beforeDuplicate=f.created,other=UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased()
   try check(typed.candidateMeasurementRequest(operation:"candidate-open",request:other,session:typed.settingsEpoch,ownerRequest:other,prefix:String(position),candidate:"")==nil && f.created==beforeDuplicate,"different host key cannot construct against retained native owner")
   let foreign:RouterVPNNodeCandidateOwner = selectedExecution ? .execution(LibboxRouterNodeChainExecution()) : family=="SOCKS" ? .socks(LibboxRouterNodeChainSOCKS()) : .connect(LibboxRouterNodeChainCONNECT())
   try check(!retained.matches(owner:foreign,server:retainedServer),"equal-family replacement owner refused")
   try check(!retained.matches(owner:original,server:LibboxCommandServer()),"foreign command server refused")
   typed.pendingTypedCandidateCleanup=(retained,retainedServer)
   try rejects("foreign cleanup owner"){try typed.closeTypedCandidate(owner:foreign)}
   try check(f.closed==0 && typed.pendingTypedCandidateCleanup != nil && !retained.currentInventorySHA256().isEmpty,"foreign cleanup retains original without retirement")
   f.failClose=true;try rejects("pending native join"){try typed.closeTypedCandidate(owner:original)}
   try check(typed.pendingTypedCandidateCleanup != nil,"failed typed close retains original")
   f.failClose=false;try typed.closeTypedCandidate(owner:original)
   try check(typed.pendingTypedCandidateCleanup==nil && typed.registry.close(original:retained),"typed retry joins exact original")
   let replacement=try make(UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased(),nativeOwner:original,nativeServer:retainedServer)
   _ = try replacement.open()
   let beforeStale=f.closed
   try retained.close();try constructorRefused.close()
   try check(f.closed==beforeStale && !typed.registry.close(original:copiedSession),"stale same-source cleanup cannot close replacement")
   _ = try replacement.start(request:request,candidate:"replacement")
   try replacement.close()

   f.reset();let failedTyped=try make(UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased(),nativeOwner:original,nativeServer:retainedServer)
   let typedRegistry=RouterVPNNodeCandidateRegistry(publication:publication)
   try check(typedRegistry.retain(failedTyped),"typed failed factory retained")
   f.failFactory=true;try rejects("typed failed factory"){_ = try failedTyped.open()}
   try rejects("failed Prepare cannot restart"){_ = try failedTyped.open()}
   try check(f.prepared==1,"Prepare remains one-shot after failure")
   f.failClose=true;try check(!typedRegistry.close(original:failedTyped) && f.family==nativeFamily && f.closed==1 && f.scoped==0,"typed Prepare cleanup retains exact handle")
   f.failClose=false;try check(typedRegistry.close(original:failedTyped) && f.family==nativeFamily && f.closed==2 && f.scoped==0,"typed Prepare cleanup retries exact handle")
   if count==3 {
    f.reset();let lateTyped=try make(UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased(),nativeOwner:original,nativeServer:retainedServer)
    let entered=DispatchSemaphore(value:0),released=DispatchSemaphore(value:0),joined=DispatchSemaphore(value:0)
    f.enter=entered;f.release=released
    DispatchQueue.global().async{defer{joined.signal()};_ = try? lateTyped.open()}
    try check(entered.wait(timeout:.now()+2) == .success,"typed Prepare entered after reservation")
    lateTyped.invalidate()
    try rejects("blocked Prepare retains exact handle"){try lateTyped.close()}
    released.signal();try check(joined.wait(timeout:.now()+2) == .success,"typed Prepare joined after cancellation")
    try lateTyped.close()
    try check(f.closed==1 && f.scoped==0,"late Prepare closes only stored handle")
   }
  }}
  print("Apple candidate session: retained factory/late callback/close/registry controls PASS")
 }
}
'''
def check_generated_sdk_inventory():
 # Execute the actual packaging guard with synthetic header text. This tests
 # omission refusal only; the hosted SDK build must provide its real header.
 import re, textwrap
 source=(ROOT/'ios/RouterVPN/prepare-libbox.sh').read_text()
 guard=textwrap.dedent(source.split('    # CONNECTED_TYPED_CANDIDATE_ABI_BEGIN\n',1)[1].split('    # CONNECTED_TYPED_CANDIDATE_ABI_END',1)[0])
 tokens=[];blocks=[]
 for family in ('','SOCKS','CONNECT'):
  for action in ('NewCandidateMeasurement',):
   name='LibboxRouterNodeChain'+family+action;tokens.append(name);blocks.append('FOUNDATION_EXPORT void '+name+'(void);')
  name='LibboxRouterNodeChain'+family+'CandidateMeasurement';tokens.append('@interface '+name)
  methods=('prepare','metadata','captureSHA256','start','cancel','drain','statusJSON','networkChanged','close')
  blocks.append('@interface '+name+' : NSObject <goSeqRefInterface>\n'+'\n'.join('- (void)'+method+';' for method in methods)+'\n@end')
 header='\n'.join(blocks)
 exec(guard,{'content':header,'re':re})
 for token in tokens:
  try:exec(guard,{'content':header.replace(token,'MissingSymbol'), 're':re})
  except AssertionError:pass
  else:raise AssertionError('generated SDK omission admitted '+token)
 for family in ('','SOCKS','CONNECT'):
  name='LibboxRouterNodeChain'+family+'CandidateMeasurement'
  block=re.search(r'@interface '+name+r' : NSObject .*?\n(.*?)@end',header,re.S).group(0)
  for method in methods:
   changed=header.replace(block,block.replace('- (void)'+method+';','- (void)absent;'))
   try:exec(guard,{'content':changed,'re':re})
   except AssertionError:pass
   else:raise AssertionError('generated SDK method omission admitted '+name+'.'+method)
 try:exec(guard,{'content':header+'\nFOUNDATION_EXPORT void LibboxRouterNodeChainCloseCandidateMeasurement(void);','re':re})
 except AssertionError as error:
  assert 'Unsafe ordinary candidate owner-key cleanup export' in str(error)
 else:raise AssertionError('Generated SDK admitted unsafe ordinary owner-key cleanup')
 print('Connected candidate SDK guard: positive +33 omissions +unsafe-cleanup refusal PASS (synthetic header)')

def main():
 check_generated_sdk_inventory()
 with tempfile.TemporaryDirectory(prefix='ios-candidate-session-')as folder:
  work=Path(folder);stub=work/'Libbox.swift';stub.write_text(LIBBOX);test=work/'Test.swift';engine=(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift').read_text()
  method=engine[engine.index('    func candidateMeasurementRequest('):engine.index('    func hopMeasurementRequest(')]
  method=method.replace('IOSCandidateCatalogPublication.shared','publication').replace('RouterVPNNodeCandidateRegistry.shared','registry')
  cleanup=engine[engine.index('    private func closeTypedCandidate('):engine.index('    private func finishNodeChainSOCKSCleanup(')].replace('private func','func').replace('RouterVPNNodeCandidateRegistry.shared','registry')
  from test_ios_startup_policy import member
  capture=(APP/'IOSNodeChainExecutionCapture.swift').read_text()
  test.write_text(SWIFT.replace(' // SHIPPING_ENGINE',method).replace(' // SHIPPING_CLEANUP',cleanup)
                  .replace(' // SHIPPING_POSITIONS',member(capture,'    var candidatePositions:'))
                  .replace(' // SHIPPING_HEX',member(capture,'    private static func hex(')))
  options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
  library=work/('libLibbox.dylib'if platform.system()=='Darwin'else'libLibbox.so')
  subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(stub),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(library)],check=True,timeout=90)
  if platform.system()!='Darwin':
   crypto=work/'CryptoKit.swift';crypto.write_text(LINUX_CRYPTO)
   subprocess.run(options+['-emit-module','-emit-library','-module-name','CryptoKit',str(crypto),'-lcrypto','-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/'libCryptoKit.so')],check=True,timeout=90)
   options+=['-lCryptoKit']
  options+=['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
  session=ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNNodeCandidateSession.swift'
  subprocess.run(options+[str(APP/'IOSCandidateCatalogPublication.swift'),str(session),str(test),'-o',str(work/'test')],check=True,timeout=90)
  subprocess.run([str(work/'test'),str(work/'container')],check=True,timeout=30)
  code=session.read_text()
  for name,before,after in [
   ('owner', 'available, currentOwner(),', 'available, true,'),
   ('failed-factory', 'if let probe { try probe.close() }', 'if let probe { _ = probe }'),
   ('socks-factory', 'return LibboxRouterNodeChainSOCKSNewCandidateMeasurement(plan, server, prefix, inventory, catalog, failure).map(RouterVPNNodeCandidateHandle.socks)', 'return nil'),
   ('connect-factory', 'return LibboxRouterNodeChainCONNECTNewCandidateMeasurement(plan, server, prefix, inventory, catalog, failure).map(RouterVPNNodeCandidateHandle.connect)', 'return nil'),
   ('typed-owner', 'case (.socks(let a), .socks(let b)): return a === b', 'case (.socks, .socks): return true'),
   ('typed-prepare', 'do { try created.prepare() }', 'do { _ = created }'),
   ('execution-factory', 'return LibboxRouterNodeChainExecutionNewCandidateMeasurement(plan, server, prefix, inventory, catalog, failure).map(RouterVPNNodeCandidateHandle.execution)', 'return nil'),
   ('execution-owner', 'case (.execution(let a), .execution(let b)): return a === b', 'case (.execution, .execution): return true'),
  ]:
   assert code.count(before)==1
   mutant=work/(name+'.swift');mutant.write_text(code.replace(before,after))
   binary=work/name
   subprocess.run(options+[str(APP/'IOSCandidateCatalogPublication.swift'),str(mutant),str(test),'-o',str(binary)],check=True,timeout=90)
   result=subprocess.run([str(binary),str(work/(name+'-container'))],capture_output=True,text=True,timeout=30)
   witness={'owner':'retired original owner','failed-factory':'failed join remains retained','socks-factory':'typed original factory dispatch and Prepare','connect-factory':'typed original factory dispatch and Prepare','typed-owner':'equal-family replacement owner refused','typed-prepare':'original factory','execution-factory':'typed original factory dispatch and Prepare','execution-owner':'equal-family replacement owner refused'}[name]
   if result.returncode==0 or 'Failed' not in result.stderr or witness not in result.stderr:
    raise AssertionError('candidate session causal control missed '+name+': '+result.stdout+result.stderr)
   print('Rejected candidate session control: '+name+': '+witness,flush=True)
  print('Apple candidate session: original two +four typed +two execution causal controls rejected')
if __name__=='__main__':main()
