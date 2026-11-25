#!/usr/bin/env python3
"""Execute the shipping async Apple candidate transaction through a provider double."""
from pathlib import Path
import subprocess
import platform
import tempfile
from test_ios_node_candidate_preparation_flow import mode_boundary
from test_ios_startup_policy import member
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
CONTROLLER_BOUNDARY='import Foundation\nprotocol ObservableObject: AnyObject {}\n@propertyWrapper struct Published<Value> { var wrappedValue: Value; init(wrappedValue: Value) {self.wrappedValue=wrappedValue} }\nfinal class NETunnelProviderSession: @unchecked Sendable {\n func sendProviderMessage(_ data: Data, responseHandler: @escaping (Data?)->Void) throws { responseHandler(nil) }\n}\n@MainActor final class RouterVPNModel {var connected=true;var activeEngine="multihop-libbox"}\n@MainActor enum IOSMTUControl {\n struct Identity {let hopMeasurementRows=IOSMultihopNodeSelection.maximumNodes;let nodeChainSource:Data?=nil;let nodeChainExecutionSource:Data?=nil;let bundleData=Data()}\n struct Binding {let connection:NETunnelProviderSession;let session:String;let identity=Identity()}\n static func capture(_ model:RouterVPNModel)async throws->Binding{Binding(connection:NETunnelProviderSession(),session:UUID().uuidString)}\n static func current(_ value:Binding,model:RouterVPNModel)->Bool{true}\n static func withHold<T>(model:RouterVPNModel,operation:@MainActor ()async throws->T)async throws->T{try await operation()}\n}\nstruct IOSNodeCandidatePrefix:Decodable {let position:Int;let profile_id:String;let node_id:String;let mode:String;var metric:String{"routed-tcp-connect"};var supported:Bool{true}}\n@MainActor struct IOSNodeCandidateCapture {\n struct Row{let id:String;let name:String;let input:String}\n let records:[String:Data]\n let source:IOSCandidateCatalogPublication.Capture,rows:[Row],prefix:IOSNodeCandidatePrefix,chainSource:String,chainConfig:String\n static func make(request:String,prefixPosition:Int,proofs:[IOSNodeCandidatePrefix],chainSource:String,chainConfig:String,selectedResponse:Bool=false)throws->Self{throw NSError(domain:"OriginalStoreBoundary",code:1)}\n func requireCurrent()throws{}\n static func issue()->NSError{NSError(domain:"CandidateCaptureBoundary",code:1)}\n}\n\n@MainActor struct IOSNodeChainCapture {\n class Plan {func close()throws{}}\n let plan=Plan(),sourceSHA256="",configSHA256=""\n static func reopen(_ source:String,selectedProfile:[String:Any])throws->Self{Self()}\n}\n@MainActor struct IOSNodeCandidateProposal {\n let description="",profiles:[String]=[]\n static func compile(original:IOSNodeChainCapture,records:[String:Data],position:Int,candidateID:String,measuredInput:String,retainFinal:Bool=false)throws->Self{Self()}\n}\n@MainActor enum IOSCandidateConnectionProfiles {\n static func save(name:String,profiles:[String],current:()throws->Void)throws->String{try current();return name}\n}\n'
# Only declarations cross this controller typecheck boundary. The separate
# preparation fixture executes the actual owner and its joined teardown.
CONTROLLER_BOUNDARY = CONTROLLER_BOUNDARY.replace(
    '@MainActor final class RouterVPNModel {var connected=true;var activeEngine="multihop-libbox"}',
    '@MainActor final class RouterVPNModel {var connected=true;var activeEngine="multihop-libbox";var tunnelTransitioning=false;let iosSpeedLabOwnership=IOSSpeedLabOwnership();var selectedNodeProfile:Selected?;var iosVisibleOrderedNodePath:[String]?;var bundle:String?;struct Selected{var multihopExecution:String?};func captureIOSNodeChain(_ source:String)throws->IOSNodeChainCapture{throw NSError(domain:"OriginalStoreBoundary",code:1)};func captureIOSCandidateOriginal(_ source:String)throws->IOSNodeCandidateOriginalCapture{throw NSError(domain:"OriginalStoreBoundary",code:1)}}')
CONTROLLER_BOUNDARY = CONTROLLER_BOUNDARY.replace(member(CONTROLLER_BOUNDARY, "struct IOSNodeCandidatePrefix:Decodable"), member((APP/"IOSNodeCandidateOriginalCapture.swift").read_text(), "struct IOSNodeCandidatePrefix:"))
CONTROLLER_BOUNDARY = CONTROLLER_BOUNDARY.replace(' let plan=Plan(),sourceSHA256="",configSHA256=""', ' struct Member {let id:String;let mode:String;let profile:[String:Any]}\n let members:[Member]=[];let plan=Plan(),sourceSHA256="",configSHA256=""')
CONTROLLER_BOUNDARY += r'''
// The actual controller uses the complete original-source union for saved
// prefix proposals and connected typed proposals. These declarations provide
// only the store/native boundary; they grant no execution or cleanup authority.
@MainActor struct IOSNodeCandidateOriginalCapture {
 static func validateExtendedResponseInfo(input:Data,bundle:Data,proofs:[IOSNodeCandidatePrefix],sourceSHA256:String,configSHA256:String)throws{throw NSError(domain:"OriginalStoreBoundary",code:1)}
 let members:[IOSNodeChainCapture.Member]=[]
 let candidatePrefixes:[IOSNodeCandidatePrefix]=[]
 let requiresIndependentPrefix=false,sourceSHA256="",configSHA256=""
 func close()throws{throw NSError(domain:"OriginalStoreBoundary",code:1)}
 static func reopenConnected(_ source:String,selectedProfile:[String:Any],sourceSHA256:String,configSHA256:String)throws->Self{throw NSError(domain:"OriginalStoreBoundary",code:1)}
}
@MainActor extension IOSNodeCandidateProposal {
 static func selectedPositions(input:Data,bundle:Data,proofs:[IOSNodeCandidatePrefix],source:String,config:String,winner:String="")throws->[Int]{throw NSError(domain:"OriginalStoreBoundary",code:1)}
 static func compileConnectedExecution(_ source:String,selectedProfile:[String:Any],sourceSHA256:String,configSHA256:String,records:[String:Data],position:Int,candidateID:String,measuredInput:String,winner:String="",retainFinal:Bool=false)throws->Self{throw NSError(domain:"OriginalStoreBoundary",code:1)}
 static func compile(original:IOSNodeCandidateOriginalCapture,records:[String:Data],position:Int,candidateID:String,measuredInput:String,retainFinal:Bool=false)throws->Self{throw NSError(domain:"OriginalStoreBoundary",code:1)}
}
@MainActor enum IOSRuntimeSelector {static func selectNodeChain(_ capture:IOSNodeChainCapture)throws->Int{throw NSError(domain:"OriginalStoreBoundary",code:1)}}
@MainActor struct IOSNodeCandidatePrefixCapture {
 let sourceSHA256="",configSHA256="",captureSHA256=""
}
@MainActor struct IOSNodeCandidatePrefixBinding {
 let connection=NETunnelProviderSession()
}
@MainActor struct IOSUnavailableSelectedDraft {
 func requireInformation<T>(_ info:T,owner:String,position:Int)throws{throw IOSNodeCandidateResult.issue()}
}
@MainActor final class IOSNodeCandidatePreparation {
 let selectedDraft:IOSUnavailableSelectedDraft?=nil
 static let busy=false;let owner=UUID();let sourceSHA256="",configSHA256="";let prefixes:[IOSNodeCandidatePrefix]=[]
 let prefixCapture:IOSNodeCandidatePrefixCapture?=nil,prefixCandidate:IOSNodeCandidateCapture?=nil
 let prefixBinding:IOSNodeCandidatePrefixBinding?=nil,prefixEpoch=UUID()
 static func reserve(model:RouterVPNModel,prefixPosition:Int?=nil,request:String?=nil,onCancelled:@escaping @MainActor ()->Void)throws->IOSNodeCandidatePreparation{throw IOSNodeCandidateResult.issue()}
 func start()async throws{throw IOSNodeCandidateResult.issue()}
 func requireLive()throws{throw IOSNodeCandidateResult.issue()}
 func originalForProposal()throws->IOSNodeCandidateOriginalCapture{throw IOSNodeCandidateResult.issue()}
 func bind(_ value:IOSNodeCandidateTransaction)throws{throw IOSNodeCandidateResult.issue()}
 func seal(token:UUID,measured:Int64,expires:Int64)throws{throw IOSNodeCandidateResult.issue()}
 func requireSaved(token:UUID)throws{throw IOSNodeCandidateResult.issue()}
 func retire()async{fatalError("typecheck boundary cannot join native ownership")}
 func closeResults(){fatalError("typecheck boundary owns no temporary results")}
 func cancel(){}
}
'''
CONTROLLER_BOUNDARY += mode_boundary()
SWIFT=r'''
import Foundation
struct Failed:Error{let text:String}
func check(_ value:Bool,_ text:String)throws{if !value{throw Failed(text:text)}}
struct IOSNodeCandidatePrefix:Decodable,Equatable{let position:Int;let profile_id:String;let node_id:String;let mode:String;var metric:String{"routed-tcp-connect"};var supported:Bool{["wg","awg2-fast","awg2-strong"].contains(mode)}}
// TRANSACTION
@MainActor final class Provider {
 let epoch=UUID().uuidString,owner=String(repeating:"a",count:32),request=String(repeating:"b",count:32),hash=String(repeating:"c",count:64)
 var pages:[Int:String]=[:]
 var calls:[String]=[],closes=0,recovered=false,foreign=false,cancelOnStatus:(()->Void)?,awaiting=false
 var continuation:CheckedContinuation<Void,Never>?
 func metadata()throws->String{String(decoding:try JSONSerialization.data(withJSONObject:["schema":1,"capture_sha256":hash,"prefix_position":0,"prefix_id":"entry","source_sha256":hash,"config_sha256":hash,"targets":[["id":"target","source_sha256":hash]]]),as:UTF8.self)}
 func send(_ op:String,_ request:String,_ candidate:String,_ prefix:String)async throws->Data{
  calls.append(op)
  var value:[String:Any]=["session_id":foreign ? UUID().uuidString:epoch,"owner_request":owner,"request_id":request]
  if op=="candidate-open"{value["metadata"]=try pages[0] ?? metadata()}
  if op=="candidate-metadata-page"{guard let index=Int(candidate),let raw=pages[index] else{throw Failed(text:"missing page")}; value["metadata"]=raw}
  if op=="candidate-start" || op=="candidate-status"{
   if awaiting{await withCheckedContinuation{continuation=$0}}
   if op=="candidate-status"{cancelOnStatus?()}
   value["status"]=String(decoding:try JSONSerialization.data(withJSONObject:["request_id":request,"complete":op=="candidate-status","drained":op=="candidate-status","stage":"complete","measurement":"routed-tcp-connect","capture_sha256":hash,"prefix_position":0,"prefix_id":"entry"]),as:UTF8.self)
  }
  if op=="candidate-close"{closes+=1;value["closed"]=closes>=3;if closes>=3{recovered=true}}
  return try JSONSerialization.data(withJSONObject:value)
 }
 func transaction()throws->IOSNodeCandidateTransaction{try IOSNodeCandidateTransaction(epoch:epoch,owner:owner,send:{op,request,candidate,prefix,_ in try await self.send(op,request,candidate,prefix)},recovered:{self.recovered},pause:{await Task.yield()})}
}
@MainActor @main struct Tests{
 static func paged(_ count:Int, expectedHash:String) async throws {
  let provider=Provider()
  let ids=(0..<count).map{$0 == count-1 ? "final/<&>\"é\u{2028}\u{2029}" : "node-"+String($0)}
  let rows=ids.map{["id":$0,"source_sha256":provider.hash]}
  var pages=[Int:String]()
  for offset in stride(from:0,to:count,by:64) {
    let body:[String:Any]=["schema":2,"capture_sha256":provider.hash,"source_sha256":provider.hash,"config_sha256":provider.hash,"prefix_id":"entry","prefix_position":0,"target_offset":offset,"targets_sha256":expectedHash,"target_total":count,"targets":Array(rows[offset..<min(count,offset+64)])]
    pages[offset]=String(decoding:try JSONSerialization.data(withJSONObject:body),as:UTF8.self)
  }
  provider.pages=pages
  let transaction=try provider.transaction(), metadata=try await transaction.open(prefix:0,inventoryBytes:4*1024*1024)
  try check(metadata.targets.map(\.id)==ids && provider.calls.filter{$0=="candidate-open"}.count==1,"complete bounded original pages")
  for fault in ["offset","total","digest","source","capture","prefix","duplicate","reorder","missing","oversized","duplicate-key","duplicate-target-key","unknown","cancel"] {
    provider.pages=pages
    let mutated=try provider.transaction()
    if fault=="missing" {provider.pages.removeValue(forKey:64)}
    else if fault=="duplicate-key" {provider.pages[64]=pages[64]!.replacingOccurrences(of:"\"target_offset\":64",with:"\"target_offset\":64,\"target_offset\":64")}
    else if fault=="duplicate-target-key" {provider.pages[64]=pages[64]!.replacingOccurrences(of:"\"id\":\"node-64\"",with:"\"id\":\"unused\",\"id\":\"node-64\"")}
    else if fault=="oversized" {provider.pages[64]=String(repeating:" ",count:12300)+pages[64]!}
    else if fault != "cancel" {
      var frame=try JSONSerialization.jsonObject(with:Data(pages[64]!.utf8)) as! [String:Any]
      switch fault{
       case "unknown":frame["foreign_header"]=1
       case "offset":frame["target_offset"]=0
       case "total":frame["target_total"]=count+1
       case "digest":frame["targets_sha256"]=String(repeating:"d",count:64)
       case "source":frame["source_sha256"]=String(repeating:"d",count:64)
       case "capture":frame["capture_sha256"]=String(repeating:"d",count:64)
       case "prefix":frame["prefix_id"]="other"
       case "duplicate":var part=frame["targets"] as! [[String:String]];part[0]=rows[0];frame["targets"]=part
       case "reorder":var part=frame["targets"] as! [[String:String]];part.swapAt(0,1);frame["targets"]=part
       default:throw Failed(text:"unknown fault")
      }
      provider.pages[64]=String(decoding:try JSONSerialization.data(withJSONObject:frame),as:UTF8.self)
    }
    var observed=0
    do{_ = try await mutated.open(prefix:0,inventoryBytes:4*1024*1024,current:{observed+=1;if fault=="cancel" && observed==3{mutated.cancel()}})}
    catch{continue}
    throw Failed(text:"ACCEPTED paged "+fault)
  }
 }
 static func main()async throws{
  try await paged(479,expectedHash:"d5630d767935f3af132ff21d7c7229b02dada475c0b73b788ab73a267eeb098d")
  try await paged(513,expectedHash:"8aa8fe17757a3c67f6bed00cf07fdac2e3947489091e1558f56605f21be6b9c9")
  let p=Provider(),t=try p.transaction()
  let metadata=try await t.open(prefix:0);try check(metadata.prefix_id=="entry","original metadata")
  var observations=0
  _ = try await t.measure(request:p.request,candidate:"target",current:{observations+=1})
  try check(p.calls.filter{$0=="candidate-start"}.count==1 && observations==4,"single start and both-side observations")
  try await t.observe(request:p.request,metadata:metadata)
  var released=false
  let cleanup=Task{@MainActor in await t.close();released=true}
  await cleanup.value
  try check(released && p.closes==3,"lease remains until exact bounded close joins")
  let foreign=Provider();foreign.foreign=true;let foreignTx=try foreign.transaction()
  do{_ = try await foreignTx.open(prefix:0);throw Failed(text:"ACCEPTED foreign epoch")}catch let error as Failed{throw error}catch{}
  foreign.recovered=true;await foreignTx.close()
  let cancel=Provider(),cancelTx=try cancel.transaction();cancel.cancelOnStatus={cancelTx.cancel()}
  do{_ = try await cancelTx.measure(request:cancel.request,candidate:"target",current:{});throw Failed(text:"ACCEPTED cancelled late completion")}catch let error as Failed{throw error}catch{}
  await cancelTx.close();try check(cancel.closes==3,"cancelled worker still joins")
  let changed=Provider(),changedTx=try changed.transaction();var checks=0
  do{_ = try await changedTx.measure(request:changed.request,candidate:"target",current:{checks+=1;if checks==2{throw Failed(text:"source changed")}});throw Failed(text:"ACCEPTED changed source")}catch let error as Failed{if error.text != "source changed"{throw error}}catch{throw error}
  await changedTx.close();try check(changed.calls.filter{$0=="candidate-start"}.count==1 && changed.closes==3,"changed source cannot adopt or release early")
  let lost=Provider(),lostTx=try lost.transaction();lost.foreign=true
  await lostTx.close();try check(lost.closes==3 && lost.recovered,"lost IPC requires exact durable native join receipt")
  print("Apple candidate transaction: source/epoch/cancellation/adoption/drain controls PASS")
 }
}
'''
def main():
 source=(APP/'IOSNodeCandidates.swift').read_text();transaction=source.split('// CANDIDATE_TRANSACTION_BEGIN',1)[1].split('// CANDIDATE_TRANSACTION_END',1)[0]
 with tempfile.TemporaryDirectory(prefix='ios-candidate-transaction-')as folder:
  work=Path(folder);test=work/'Test.swift';test.write_text(SWIFT.replace('// TRANSACTION',transaction))
  options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
  if platform.system()!='Darwin':
   from test_ios_physical_path import LINUX_CRYPTO
   crypto=work/'CryptoKit.swift';crypto.write_text(LINUX_CRYPTO)
   subprocess.run(options+['-emit-module','-emit-library','-module-name','CryptoKit',str(crypto),'-lcrypto','-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/'libCryptoKit.so')],check=True,timeout=90)
   options+=['-I',str(work),'-L',str(work),'-lCryptoKit','-Xlinker','-rpath','-Xlinker',str(work)]
  command=options+[str(APP/'IOSCandidateCatalogPublication.swift'),str(APP/'IOSNodeCandidateResult.swift')]
  binary=work/'test'
  subprocess.run(command+[str(test),'-o',str(binary)],check=True,timeout=90)
  subprocess.run([str(binary)],check=True,timeout=30)
  before='value.session_id == epoch, value.owner_request == owner,'
  assert transaction.count(before)==1
  test.write_text(SWIFT.replace('// TRANSACTION',transaction.replace(before,'true,')))
  subprocess.run(command+[str(test),'-o',str(binary)],check=True,timeout=90)
  result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
  if result.returncode==0 or 'ACCEPTED foreign epoch' not in result.stderr:raise AssertionError('transaction foreign-epoch causal control did not fail')
  print('Apple candidate transaction: foreign-owner causal control rejected')
  # Typecheck the complete shipping app controller with only OS/store/UI
  # declarations substituted. SwiftUI view syntax is parsed separately below.
  controller=work/'Controller.swift'
  controller.write_text(CONTROLLER_BOUNDARY+source[source.index('private final class IOSCandidateReply:'):source.index('struct IOSNodeCandidatesCard:')])
  subprocess.run(options+['-emit-module','-module-name','CandidateHost',str(controller),str(APP/'IOSSpeedLabOwnership.swift'),str(APP/'IOSCandidateCatalogPublication.swift'),str(APP/'IOSNodeCandidateResult.swift'),'-emit-module-path',str(work/'CandidateHost.swiftmodule')],check=True,timeout=90)
  print('Apple complete candidate controller typecheck PASS (OS/store/UI boundaries substituted)')
 subprocess.run(['swiftc','-frontend','-parse',str(APP/'IOSNodeCandidates.swift'),str(APP/'IOSSpeedLabView.swift')],check=True,timeout=30)
if __name__=='__main__':main()
