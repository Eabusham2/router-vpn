#!/usr/bin/env python3
"""Execute the shipping async Apple candidate transaction through a provider double."""
from pathlib import Path
import subprocess
import platform
import tempfile
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
CONTROLLER_BOUNDARY='import Foundation\nprotocol ObservableObject: AnyObject {}\n@propertyWrapper struct Published<Value> { var wrappedValue: Value; init(wrappedValue: Value) {self.wrappedValue=wrappedValue} }\nfinal class NETunnelProviderSession: @unchecked Sendable {\n func sendProviderMessage(_ data: Data, responseHandler: @escaping (Data?)->Void) throws { responseHandler(nil) }\n}\n@MainActor final class RouterVPNModel {var connected=true;var activeEngine="multihop-libbox"}\n@MainActor enum IOSMTUControl {\n struct Binding {let connection:NETunnelProviderSession;let session:String}\n static func capture(_ model:RouterVPNModel)async throws->Binding{Binding(connection:NETunnelProviderSession(),session:UUID().uuidString)}\n static func current(_ value:Binding,model:RouterVPNModel)->Bool{true}\n static func withHold<T>(model:RouterVPNModel,operation:@MainActor ()async throws->T)async throws->T{try await operation()}\n}\nstruct IOSNodeCandidatePrefix:Decodable {let position:Int;let profile_id:String;let node_id:String;let mode:String;var supported:Bool{true}}\n@MainActor struct IOSNodeCandidateCapture {\n struct Row{let id:String;let name:String;let input:String}\n let source:IOSCandidateCatalogPublication.Capture,rows:[Row],prefix:IOSNodeCandidatePrefix,chainSource:String,chainConfig:String\n static func make(request:String,prefixPosition:Int,proofs:[IOSNodeCandidatePrefix],chainSource:String,chainConfig:String)throws->Self{throw NSError(domain:"OriginalStoreBoundary",code:1)}\n func requireCurrent()throws{}\n}\n'
SWIFT=r'''
import Foundation
struct Failed:Error{let text:String}
func check(_ value:Bool,_ text:String)throws{if !value{throw Failed(text:text)}}
enum IOSCandidateCatalogPublication{
 static func validRequest(_ value:String)->Bool{value.count==32 && value.allSatisfy{$0.isHexDigit}}
 static func isDigest(_ value:String)->Bool{value.count==64 && value.allSatisfy{$0.isHexDigit}}
}
struct IOSNodeCandidatePrefix:Decodable{let position:Int;let profile_id:String;let node_id:String;let mode:String}
// TRANSACTION
@MainActor final class Provider {
 let epoch=UUID().uuidString,owner=String(repeating:"a",count:32),request=String(repeating:"b",count:32),hash=String(repeating:"c",count:64)
 var calls:[String]=[],closes=0,recovered=false,foreign=false,cancelOnStatus:(()->Void)?,awaiting=false
 var continuation:CheckedContinuation<Void,Never>?
 func metadata()throws->String{String(decoding:try JSONSerialization.data(withJSONObject:["schema":1,"capture_sha256":hash,"prefix_position":0,"prefix_id":"entry","source_sha256":hash,"config_sha256":hash,"targets":[["id":"target","source_sha256":hash]]]),as:UTF8.self)}
 func send(_ op:String,_ request:String,_ candidate:String,_ prefix:String)async throws->Data{
  calls.append(op)
  var value:[String:Any]=["session_id":foreign ? UUID().uuidString:epoch,"owner_request":owner,"request_id":request]
  if op=="candidate-open"{value["metadata"]=try metadata()}
  if op=="candidate-start" || op=="candidate-status"{
   if awaiting{await withCheckedContinuation{continuation=$0}}
   if op=="candidate-status"{cancelOnStatus?()}
   value["status"]=String(decoding:try JSONSerialization.data(withJSONObject:["request_id":request,"complete":op=="candidate-status","drained":op=="candidate-status","stage":"complete","measurement":"routed-tcp-connect","capture_sha256":hash,"prefix_position":0,"prefix_id":"entry"]),as:UTF8.self)
  }
  if op=="candidate-close"{closes+=1;value["closed"]=closes>=3;if closes>=3{recovered=true}}
  return try JSONSerialization.data(withJSONObject:value)
 }
 func transaction()throws->IOSNodeCandidateTransaction{try IOSNodeCandidateTransaction(epoch:epoch,owner:owner,send:{op,request,candidate,prefix in try await self.send(op,request,candidate,prefix)},recovered:{self.recovered},pause:{await Task.yield()})}
}
@MainActor @main struct Tests{
 static func main()async throws{
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
  command=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules'),str(APP/'IOSNodeCandidateResult.swift')]
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
  options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
  if platform.system()!='Darwin':
   from test_ios_physical_path import LINUX_CRYPTO
   crypto=work/'CryptoKit.swift';crypto.write_text(LINUX_CRYPTO)
   subprocess.run(options+['-emit-module','-emit-library','-module-name','CryptoKit',str(crypto),'-lcrypto','-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/'libCryptoKit.so')],check=True,timeout=90)
   options+=['-I',str(work),'-L',str(work),'-lCryptoKit']
  subprocess.run(options+['-emit-module','-module-name','CandidateHost',str(controller),str(APP/'IOSCandidateCatalogPublication.swift'),str(APP/'IOSNodeCandidateResult.swift'),'-emit-module-path',str(work/'CandidateHost.swiftmodule')],check=True,timeout=90)
  print('Apple complete candidate controller typecheck PASS (OS/store/UI boundaries substituted)')
 subprocess.run(['swiftc','-frontend','-parse',str(APP/'IOSNodeCandidates.swift'),str(APP/'IOSSpeedLabView.swift')],check=True,timeout=30)
if __name__=='__main__':main()
