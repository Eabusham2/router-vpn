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
 public init(){}
 public func sourceSHA256()->String{String(repeating:"a",count:64)}
 public func configSHA256()->String{String(repeating:"b",count:64)}

}
public final class LibboxCommandServer {public init(){}}
public final class Fixture: @unchecked Sendable {
 public static let shared=Fixture()
 public var created=0,starts=0,closed=0,scoped=0,failFactory=false,failClose=false
 public var enter:DispatchSemaphore?,release:DispatchSemaphore?
 public init(){}
 public func reset(){created=0;starts=0;closed=0;scoped=0;failFactory=false;failClose=false;enter=nil;release=nil}
}
public final class LibboxRouterNodeChainCandidateMeasurement {
 public func metadata()->String{"metadata"}
 public func captureSHA256()->String{String(repeating:"a",count:64)}
 public func start(_ request:String,candidateID:String)throws{Fixture.shared.starts+=1}
 public func statusJSON()->String{"status"}
 public func cancel(_ request:String){}
 public func networkChanged(){}
 public func close()throws{Fixture.shared.closed+=1;if Fixture.shared.failClose{throw NSError(domain:"NativeJoinPending",code:1)}}
}
public func LibboxRouterNodeChainNewCandidateMeasurement(_ plan:LibboxRouterNodeChain,_ server:LibboxCommandServer,_ prefix:Int32,_ inventory:String,_ catalog:LibboxRouterNodeChainCandidateCatalogProtocol,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterNodeChainCandidateMeasurement?{
 Fixture.shared.created+=1
 guard !catalog.currentInventorySHA256().isEmpty else{error?.pointee=NSError(domain:"Catalog",code:1);return nil}
 Fixture.shared.enter?.signal();Fixture.shared.release?.wait()
 if Fixture.shared.failFactory{error?.pointee=NSError(domain:"FailedFactoryPendingJoin",code:1);return nil}
 return LibboxRouterNodeChainCandidateMeasurement()
}
public func LibboxRouterNodeChainCloseCandidateMeasurement(_ plan:LibboxRouterNodeChain,_ prefix:Int32,_ inventory:String,_ error:UnsafeMutablePointer<NSError?>?)->Bool{
 Fixture.shared.scoped+=1
 if Fixture.shared.failClose{error?.pointee=NSError(domain:"NativeScopedJoinPending",code:1);return false};return true
}
'''
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
final class MTU {
 var hasOwner=false,measurementReady=true
 func request(operation:String,request:String,session:String)->Data?{try? JSONSerialization.data(withJSONObject:["ack_id":request,"session_id":UUID().uuidString])}
}
final class Platform{let mtu=MTU()}
final class Engine {
 let ownershipLock=NSLock(),platform=Platform(),settingsEpoch=UUID().uuidString
 var nodeChain:LibboxRouterNodeChain?=LibboxRouterNodeChain(),server:LibboxCommandServer?=LibboxCommandServer(),nodeChainDelivery:NSObject?=NSObject()
 var nodeCandidate:RouterVPNNodeCandidateSession?,ownershipGeneration=UUID(),starting=false,permanentlyStopped=false
 let publication:IOSCandidateCatalogPublication,registry:RouterVPNNodeCandidateRegistry
 init(_ publication:IOSCandidateCatalogPublication){self.publication=publication;registry=RouterVPNNodeCandidateRegistry(publication:publication)}
 // SHIPPING_ENGINE
}
@main struct Test{
 static func main()throws{
  let root=URL(fileURLWithPath:CommandLine.arguments[1]);try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true)
  let publication=IOSCandidateCatalogPublication(container:root),records=["all":Data("actual original bytes".utf8)]
  try publication.publish(records)
  func make(_ char:String,_ owner:Owner=Owner())throws->RouterVPNNodeCandidateSession{
   let request=String(repeating:char,count:32),stamp=try publication.current(records:records)
   let inventory=try JSONSerialization.data(withJSONObject:["schema":1,"revision":stamp.revision,"inputs":["exact source"]])
   let source=try publication.capture(request:request,inventory:inventory,expected:stamp)
   return RouterVPNNodeCandidateSession(plan:LibboxRouterNodeChain(),server:LibboxCommandServer(),prefix:0,epoch:UUID().uuidString,source:source,publication:publication,current:{owner.current()})
  }
  let f=Fixture.shared,registry=RouterVPNNodeCandidateRegistry(publication:publication)
  let owner=Owner(),session=try make("a",owner)
  try check(registry.retain(session),"register original factory before work")
  try check(try session.open()=="metadata" && f.created==1,"original factory")
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
  f.failClose=true;try check(!registry.close(epoch:failed.epoch,request:failed.request) && f.scoped==1,"nil handle requires actual scoped join")
  f.failClose=false;try check(registry.close(epoch:failed.epoch,request:failed.request) && f.scoped==2,"failed factory cleanup retries original arguments")
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
  print("Apple candidate session: retained factory/late callback/close/registry controls PASS")
 }
}
'''
def main():
 with tempfile.TemporaryDirectory(prefix='ios-candidate-session-')as folder:
  work=Path(folder);stub=work/'Libbox.swift';stub.write_text(LIBBOX);test=work/'Test.swift';engine=(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift').read_text()
  method=engine[engine.index('    func candidateMeasurementRequest('):engine.index('    func hopMeasurementRequest(')]
  method=method.replace('IOSCandidateCatalogPublication.shared','publication').replace('RouterVPNNodeCandidateRegistry.shared','registry')
  test.write_text(SWIFT.replace(' // SHIPPING_ENGINE',method))
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
   ('failed-factory', 'else if attempted {', 'else if false {'),
  ]:
   assert code.count(before)==1
   mutant=work/(name+'.swift');mutant.write_text(code.replace(before,after))
   binary=work/name
   subprocess.run(options+[str(APP/'IOSCandidateCatalogPublication.swift'),str(mutant),str(test),'-o',str(binary)],check=True,timeout=90)
   result=subprocess.run([str(binary),str(work/(name+'-container'))],capture_output=True,text=True,timeout=30)
   if result.returncode==0 or 'Failed' not in result.stderr:raise AssertionError('candidate session causal control accepted '+name)
  print('Apple candidate session: two causal controls rejected')
if __name__=='__main__':main()
