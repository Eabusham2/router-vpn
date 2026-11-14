#!/usr/bin/env python3
"""Execute process-owned Apple restore registry and real host observation holds.

Native lifecycle/readback remains an explicit controlled boundary. This gate
establishes IPC/reference ownership, not native SDK/TUN or encrypted traffic.
"""
from pathlib import Path
import importlib.util
import subprocess
import tempfile
import sys
ROOT=Path(__file__).resolve().parents[1]
TUN=ROOT/'ios/RouterVPN/PacketTunnel'
spec=importlib.util.spec_from_file_location('ordered_host',ROOT/'deploy/test_ios_node_chain_execution_host.py')
HOST=importlib.util.module_from_spec(spec);spec.loader.exec_module(HOST)
BOUNDARY=HOST.BOUNDARY
BOUNDARY=BOUNDARY.replace('let plan=LibboxRouterNodeChainExecution(),config="exact-preparation"',r'''
 let plan=LibboxRouterNodeChainExecution(),config="exact-preparation"
 var ordinaryLaunchInput="original-source"
 var finalProfile:[String:Any]=["id":"original-final"]
 let sourceSHA256=String(repeating:"a",count:64),configSHA256=String(repeating:"b",count:64)
 var restoration:Restoration?
 var captureGate:DispatchSemaphore?,captureEntered=DispatchSemaphore(value:0)
 final class Restoration {
  let original:IOSNodeChainExecutionCapture,selected="server";var claimed=false
  var gate:DispatchSemaphore?,entered=DispatchSemaphore(value:0),replacement:IOSNodeChainExecutionCapture?
  init(_ original:IOSNodeChainExecutionCapture){self.original=original}
  func makeCapture(ordinaryInput:String,selectedProfile:[String:Any])throws->IOSNodeChainExecutionCapture{
   guard ordinaryInput==original.ordinaryLaunchInput,NSDictionary(dictionary:selectedProfile).isEqual(to:original.finalProfile),original.nativeClosed(),!claimed else{throw failure("original native/source unavailable")}
   claimed=true;entered.signal();if let gate{_ = gate.wait(timeout:.now()+4)}
   let next=IOSNodeChainExecutionCapture();replacement=next;return next
  }
 }
 func captureRestoration()throws->Restoration{guard healthy()else{throw failure("unproved restore")};captureEntered.signal();if let captureGate{guard captureGate.wait(timeout:.now()+4) == .success else{throw failure("held native capture did not join")}};let next=Restoration(self);restoration=next;return next}
 func captureLastRecord()throws->String{guard healthy()else{throw failure("unproved Last")};return "{\"execution\":\"server\"}"}
''')
BOUNDARY=BOUNDARY.replace('var proofObservationToken:UUID?=UUID(),isChanging=false,optimizerRunning=false','var runAutomatic=true\n var proofObservationToken:UUID?=UUID(),isChanging=false,optimizerRunning=false')
BOUNDARY=BOUNDARY.replace('func activateNodeChainExecution(server:LibboxCommandServer,plan:LibboxRouterNodeChainExecution,onAbort:', 'func activateNodeChainExecution(server:LibboxCommandServer,plan:LibboxRouterNodeChainExecution,runAutomatic:Bool=true,onAbort:')
BOUNDARY=BOUNDARY.replace('Trace.shared.add("mtu-activate");guard','self.runAutomatic=runAutomatic;Trace.shared.add("mtu-activate");guard',1)
provider=(TUN/'PacketTunnelProvider.swift').read_text()
start=provider.index('        if let request = RouterVPNNodeChainExecutionRegistry.Request.parse(messageData) {')
level=0;end=None
for position in range(provider.index('{',start),len(provider)):
    if provider[position]=='{':level+=1
    elif provider[position]=='}':
        level-=1
        if level==0:end=position+1;break
assert end is not None
PROVIDER_BLOCK=provider[start:end]
IPC=r'''
final class RouterVPNLibboxEngine {
 var calls=0,operation="",callback:((Data?)->Void)?
 func orderedExecutionRequest(_ request:RouterVPNNodeChainExecutionRegistry.Request,completion:@escaping(Data?)->Void){calls+=1;operation=request.operation;callback=completion}
}
final class Proof {}
final class PacketTunnelProvider {
 var libboxEngine:RouterVPNLibboxEngine?=RouterVPNLibboxEngine(),proof:Proof?=Proof(),maxStartGeneration=UUID()
 let maxStartOwnerLock=NSLock()
 func currentPathProofGuard()->Proof?{proof}
 func currentMAXGeneration(_ captured:UUID)->Bool{captured==maxStartGeneration}
 func dispatch(_ messageData:Data,completionHandler:@escaping(Data?)->Void){
 // ACTUAL_PROVIDER_IPC
 completionHandler(nil)
 }
}
'''.replace('// ACTUAL_PROVIDER_IPC',PROVIDER_BLOCK)
TESTS=r'''
import Foundation
final class Observation:@unchecked Sendable{var rejected=false;let done=DispatchSemaphore(value:0)}
@main struct Tests {
 static var checks:Int { get{Counter.shared.value} set{Counter.shared.value=newValue} }
 static func check(_ ok:Bool,_ name:String){if !ok{FileHandle.standardError.write(Data(("FAIL "+name+"\n").utf8));exit(1)};checks+=1}
 static func reject(_ name:String,_ action:()throws->Void){do{try action();check(false,"ACCEPTED "+name)}catch{checks+=1}}
 static func request(_ operation:String,_ session:String,_ owner:String,_ token:String="",nonce:String=String(repeating:"c",count:32)) -> RouterVPNNodeChainExecutionRegistry.Request {
  let body=["operation":operation,"request_id":nonce,"session_id":session,"owner_id":owner,"token":token]
  return RouterVPNNodeChainExecutionRegistry.Request.parse(try! JSONSerialization.data(withJSONObject:body))!
 }
 static func observation(_ registry:RouterVPNNodeChainExecutionRegistry)->[String:Any]{
  let ask=request("ordered-execution-owner",sessionForObservation,""),last:[String:Any]=["schema":1,"kind":"routervpn-ordered-execution-last","request_id":ask.request,"session_id":sessionForObservation,"source_sha256":String(repeating:"a",count:64),"preparation_config_sha256":String(repeating:"b",count:64),"last":"{}"]
  return try! decode(registry.observe(JSONSerialization.data(withJSONObject:last,options:[.sortedKeys]),request:ask,epoch:registry.epoch())!)
 }
 static let sessionForObservation=UUID().uuidString
 static func retirement(_ registry:RouterVPNNodeChainExecutionRegistry,_ session:String,_ owner:String,_ capture:String,nonce:String=String(repeating:"e",count:32))->RouterVPNNodeChainExecutionRegistry.Request{
  let scope=observation(registry)
  let body=["operation":"ordered-execution-capture-release","request_id":nonce,"session_id":session,"owner_id":owner,"capture_request_id":capture,"process_id":scope["process_id"] as! String,"registry_generation":scope["registry_generation"] as! String]
  return RouterVPNNodeChainExecutionRegistry.Request.parse(try! JSONSerialization.data(withJSONObject:body))!
 }
 static func request(_ owner:String)->RouterVPNNodeChainExecutionRegistry.Request{request("ordered-execution-capture","",owner)}
 static func decode(_ raw:Data)throws->[String:Any]{try JSONSerialization.jsonObject(with:raw) as! [String:Any]}
 static func start(_ capture:IOSNodeChainExecutionCapture=IOSNodeChainExecutionCapture(),restored:RouterVPNNodeChainExecutionRegistry.Restored?=nil)throws->(RouterVPNNodeChainExecutionHost,LibboxCommandServer,RouterVPNLibboxPlatform){
  Factory.shared.reset();let platform=RouterVPNLibboxPlatform(),host=RouterVPNNodeChainExecutionHost(capture:capture,platform:platform,restored:restored,isCurrent:{true},onFailure:{_ in})
  let server=LibboxCommandServer();try host.bindNative(server);try host.startNative();host.finishConstruction()
  let done=Result();host.run(adoptMeasurement:{_,_ in true},completion:done.finish);check(done.wait() && done.values==[false],"original proof did not run")
  return(host,server,platform)
 }
 static func main()throws{
  let owner=UUID().uuidString,session=UUID().uuidString
  for fault in ["none","engine","proof","generation"] {
   let provider=PacketTunnelProvider(),engine=provider.libboxEngine!,payload=Data("owned-reply".utf8)
   let input=try JSONSerialization.data(withJSONObject:["operation":"ordered-execution-last","request_id":String(repeating:"c",count:32),"session_id":"","owner_id":"","token":""])
   var values:[Data?]=[];provider.dispatch(input){values.append($0)}
   check(engine.calls==1 && values.isEmpty,"provider IPC did not retain exact deferred worker")
   if fault=="engine"{provider.libboxEngine=RouterVPNLibboxEngine()}
   if fault=="proof"{provider.proof=Proof()}
   if fault=="generation"{provider.maxStartGeneration=UUID()}
   engine.callback?(payload)
   check(values.count==1 && values[0]==(fault=="none" ? payload:nil),"provider stale "+fault+" IPC published")
  }
  for changed in [false,true]{
   let provider=PacketTunnelProvider(),engine=provider.libboxEngine!,nonce=String(repeating:"6",count:32)
   let input=try JSONSerialization.data(withJSONObject:["operation":"ordered-execution-owner","request_id":nonce,"session_id":"","owner_id":"","token":""])
   var values:[Data?]=[];provider.dispatch(input){values.append($0)}
   check(engine.calls==1 && engine.operation=="ordered-execution-last" && values.isEmpty,"owner observation bypassed existing proved Last worker")
   if changed{_ = try RouterVPNNodeChainExecutionRegistry.shared.beginStart(temporaryOwner:nil,restoreToken:nil,restoreOwner:nil)}
   let last:[String:Any]=["schema":1,"kind":"routervpn-ordered-execution-last","request_id":nonce,"session_id":session,"source_sha256":String(repeating:"a",count:64),"preparation_config_sha256":String(repeating:"b",count:64),"last":"{}"]
   engine.callback?(try JSONSerialization.data(withJSONObject:last,options:[.sortedKeys]))
   check(values.count==1,"owner observation callback was lost or duplicated")
   if changed{check(values[0]==nil,"provider owner stamp outlived original registry generation")}
   else{let reply=try decode(values[0]!);check(reply.count==9 && reply["kind"] as? String=="routervpn-ordered-execution-owner" && reply["source_sha256"] as? String==last["source_sha256"] as? String,"provider owner stamp replaced original proved source")}
  }
  let good=["operation":"ordered-execution-capture","request_id":String(repeating:"c",count:32),"session_id":"","owner_id":owner,"token":""]
  check(RouterVPNNodeChainExecutionRegistry.Request.parse(try JSONSerialization.data(withJSONObject:good)) != nil,"valid opaque request refused")
  for key in ["operation","request_id","session_id","owner_id","token","extra"]{
   var bad=good;bad[key]="bad";check(RouterVPNNodeChainExecutionRegistry.Request.parse(try JSONSerialization.data(withJSONObject:bad))==nil,"malformed opaque IPC "+key)
  }
  check(RouterVPNNodeChainExecutionRegistry.Request.parse(Data(repeating:32,count:1025))==nil,"unbounded opaque IPC")
  do {
   let registry=RouterVPNNodeChainExecutionRegistry()
   for malformed:Any in [1,NSNull(),["unexpected"]] {
    reject("typed launch option disappeared"){_ = try registry.beginProviderStart(temporaryOwner:nil,restoreValue:malformed,restoreOwnerValue:nil,lastValue:nil,executionSourcePresent:true)}
    reject("typed Last option disappeared"){_ = try registry.beginProviderStart(temporaryOwner:nil,restoreValue:nil,restoreOwnerValue:nil,lastValue:malformed,executionSourcePresent:true)}
   }
   for raw in ["",String(repeating:"x",count:16*1024+1)] {
    reject("unbounded Last option"){_ = try registry.beginProviderStart(temporaryOwner:nil,restoreValue:nil,restoreOwnerValue:nil,lastValue:raw,executionSourcePresent:true)}
   }
   reject("Last used Local or pair source"){_ = try registry.beginProviderStart(temporaryOwner:nil,restoreValue:nil,restoreOwnerValue:nil,lastValue:"{}",executionSourcePresent:false)}
   reject("mixed Last and temporary owner"){_ = try registry.beginProviderStart(temporaryOwner:nil,restoreValue:String(repeating:"c",count:32),restoreOwnerValue:owner,lastValue:"{}",executionSourcePresent:true)}
   let request=try registry.beginProviderStart(temporaryOwner:nil,restoreValue:nil,restoreOwnerValue:nil,lastValue:"{}",executionSourcePresent:true)
   check(request.lastRecord=="{}" && !request.restoring,"explicit Last dispatch lost exact private bytes")
  }
  do {
   let registry=RouterVPNNodeChainExecutionRegistry(),(host,server,platform)=try start()
   let response=try decode(registry.capture(host:host,session:session,request:request(owner),epoch:registry.epoch()))
   let token=response["token"] as! String
   check(response.count==9 && response["execution"] as? String=="server" && response["source_sha256"] as? String==host.capture.sourceSHA256,"restore reply identity changed")
   let verify=request("ordered-execution-verify",session,owner,token)
   _ = try registry.verify(host:host,session:session,request:verify)
   reject("foreign token"){_ = try registry.verify(host:host,session:session,request:request("ordered-execution-verify",session,owner,String(repeating:"d",count:32)))}
   let other=try start();other.2.mtu.proofObservationToken=platform.mtu.proofObservationToken;reject("replacement host borrowed original capsule"){_ = try registry.verify(host:other.0,session:session,request:verify)};try other.0.close()
   let oldEpoch=platform.mtu.proofObservationToken;platform.mtu.proofObservationToken=UUID()
   reject("changed original MTU observation"){_ = try registry.verify(host:host,session:session,request:verify)};platform.mtu.proofObservationToken=oldEpoch
   platform.mtu.optimizerRunning=true
   reject("capture overlapped Auto MTU"){_ = try registry.capture(host:host,session:session,request:request(owner),epoch:registry.epoch())}
   reject("Last overlapped Auto MTU"){_ = try host.lastRecord()};platform.mtu.optimizerRunning=false
   check(try host.lastRecord()=="{\"execution\":\"server\"}","owned Last observation lost")
   let admission=try registry.beginStart(temporaryOwner:nil,restoreToken:token,restoreOwner:owner)
   reject("restore before original close"){_ = try registry.consume(admission,original:host.capture)}
   server.failClose=1;reject("pending native Close"){try host.close()}
   reject("restore borrowed pending Close"){_ = try registry.consume(admission,original:host.capture)}
   try host.close()
   let restored=try registry.consume(admission,original:host.capture)
   reject("claimed registry capsule replay"){_ = try registry.consume(admission,original:host.capture)}
   reject("restored object pointer substitution"){try restored.require(IOSNodeChainExecutionCapture())}
   let fresh=try start(restored.capture,restored:restored);try fresh.0.activateMTU()
   check(!fresh.2.mtu.runAutomatic,"temporary restore reran Auto MTU")
   try fresh.0.close()
  }
  do {
   let registry=RouterVPNNodeChainExecutionRegistry(),(host,_,_)=try start()
   let receipt=try decode(registry.capture(host:host,session:session,request:request(owner),epoch:registry.epoch())),token=receipt["token"] as! String
   _ = try registry.beginStart(temporaryOwner:owner,restoreToken:nil,restoreOwner:nil)
   _ = try registry.verify(host:host,session:session,request:request("ordered-execution-verify",session,owner,token))
   _ = try registry.beginStart(temporaryOwner:UUID().uuidString,restoreToken:nil,restoreOwner:nil)
   reject("unrelated start preserved restore authority"){_ = try registry.beginStart(temporaryOwner:nil,restoreToken:token,restoreOwner:owner)}
   try host.close()
  }
  do {
   let registry=RouterVPNNodeChainExecutionRegistry(),(host,_,_)=try start(),old=registry.epoch()
   _ = try registry.beginStart(temporaryOwner:nil,restoreToken:nil,restoreOwner:nil)
   reject("late original capture after a new start"){_ = try registry.capture(host:host,session:session,request:request(owner),epoch:old)}
   try host.close()
  }
  do {
   let registry=RouterVPNNodeChainExecutionRegistry(),(host,_,_)=try start()
   let first=try decode(registry.capture(host:host,session:session,request:request(owner),epoch:registry.epoch())),old=first["token"] as! String
   let second=try decode(registry.capture(host:host,session:session,request:request(owner),epoch:registry.epoch())),next=second["token"] as! String
   check(old != next,"replacement observation reused token")
   check(registry.release(request("ordered-execution-release",session,owner,old))==nil,"old token released new capture")
   try host.close()
   check(registry.release(request("ordered-execution-release",session,owner,next)) != nil,"exact process capsule could not be released after stop")
   reject("released capsule resumed"){_ = try registry.beginStart(temporaryOwner:nil,restoreToken:next,restoreOwner:owner)}
  }
  do {
   let registry=RouterVPNNodeChainExecutionRegistry(),(host,_,_)=try start()
   let value=try decode(registry.capture(host:host,session:session,request:request(owner),epoch:registry.epoch())),token=value["token"] as! String
   let cleanup=retirement(registry,session,owner,String(repeating:"c",count:32))
   try host.close();let admission=try registry.beginStart(temporaryOwner:nil,restoreToken:token,restoreOwner:owner)
   let capsule=host.capture.restoration!,gate=DispatchSemaphore(value:0);capsule.gate=gate
   let observation=Observation()
   DispatchQueue.global().async{do{_ = try registry.consume(admission,original:host.capture)}catch{observation.rejected=true};observation.done.signal()}
   check(capsule.entered.wait(timeout:.now()+3) == .success,"restore factory did not enter")
   check(registry.releaseCapture(cleanup)==nil,"cleanup retired an actively claiming native capsule")
   _ = try registry.beginStart(temporaryOwner:nil,restoreToken:nil,restoreOwner:nil);gate.signal()
   check(observation.done.wait(timeout:.now()+3) == .success && observation.rejected,"late replacement bypassed new start")
   check((try? capsule.replacement?.requireCurrent())==nil,"late unadopted source owner was dropped")
  }
  // Exact request retirement preserves a marker even before the original
  // native capture worker reaches publication. No time-based eviction occurs.
  let firstNonce=String(repeating:"1",count:32),nextNonce=String(repeating:"2",count:32)
  do {
   let scope=observation(.shared)
   let good=["operation":"ordered-execution-capture-release","request_id":firstNonce,"session_id":session,"owner_id":owner,"capture_request_id":nextNonce,"process_id":scope["process_id"] as! String,"registry_generation":scope["registry_generation"] as! String]
   let parsed=RouterVPNNodeChainExecutionRegistry.Request.parse(try JSONSerialization.data(withJSONObject:good))
   check(parsed?.captureRequest==nextNonce && parsed?.token=="","capture nonce was confused with opaque native token")
   for key in ["operation","request_id","session_id","owner_id","capture_request_id","process_id","registry_generation","token","extra"]{
    var bad=good;bad[key]="bad";check(RouterVPNNodeChainExecutionRegistry.Request.parse(try JSONSerialization.data(withJSONObject:bad))==nil,"malformed capture retirement "+key)
   }
   let provider=PacketTunnelProvider(),engine=provider.libboxEngine!;provider.libboxEngine=nil;provider.proof=nil
   var values:[Data?]=[];provider.dispatch(try JSONSerialization.data(withJSONObject:good)){values.append($0)}
   check(values.count==1 && values[0] != nil && engine.calls==0,"original cleanup borrowed a new live engine")
  }
  do {
   let registry=RouterVPNNodeChainExecutionRegistry(),(host,_,_)=try start()
   let capture=request("ordered-execution-capture",session,owner,nonce:firstNonce)
   let cleanup=retirement(registry,session,owner,firstNonce)
   check(registry.releaseCapture(cleanup) != nil,"unpublished original request could not retire")
   reject("retired capture request published"){_ = try registry.capture(host:host,session:session,request:capture,epoch:registry.epoch())}
   try host.close()
  }
  do {
   let registry=RouterVPNNodeChainExecutionRegistry(),(host,_,_)=try start(),epoch=registry.epoch()
   let gate=DispatchSemaphore(value:0),observation=Observation();host.capture.captureGate=gate
   let capture=request("ordered-execution-capture",session,owner,nonce:firstNonce)
   DispatchQueue.global().async{do{_ = try registry.capture(host:host,session:session,request:capture,epoch:epoch)}catch{observation.rejected=true};observation.done.signal()}
   check(host.capture.captureEntered.wait(timeout:.now()+3) == .success,"first native capture did not enter")
   let cleanup=retirement(registry,session,owner,firstNonce),second=retirement(registry,session,owner,firstNonce,nonce:nextNonce)
   let ack=try decode(registry.releaseCapture(cleanup)!),repeated=try decode(registry.releaseCapture(second)!)
   check(ack.count==9 && ack["capture_request_id"] as? String==firstNonce && ack["released"] as? Bool==true && repeated["request_id"] as? String==nextNonce,"idempotent retirement changed original request identity")
   gate.signal();check(observation.done.wait(timeout:.now()+3) == .success && observation.rejected,"retired in-flight capture published after ACK")
   host.capture.captureGate=nil
   let newOwner=UUID().uuidString,reply=try decode(registry.capture(host:host,session:session,request:request("ordered-execution-capture",session,newOwner,nonce:nextNonce),epoch:registry.epoch()))
   check(registry.releaseCapture(cleanup) != nil,"old duplicate cleanup failed idempotent ACK")
   do{_ = try registry.verify(host:host,session:session,request:request("ordered-execution-verify",session,newOwner,reply["token"] as! String))}catch{check(false,"old retirement deleted replacement capsule")}
   try host.close()
  }
  do {
   let registry=RouterVPNNodeChainExecutionRegistry(),(host,_,_)=try start()
   let original=try decode(registry.capture(host:host,session:session,request:request("ordered-execution-capture",session,owner,nonce:firstNonce),epoch:registry.epoch()))
   let next=try decode(registry.capture(host:host,session:session,request:request("ordered-execution-capture",session,owner,nonce:nextNonce),epoch:registry.epoch()))
   check(registry.releaseCapture(retirement(registry,session,owner,firstNonce)) != nil,"displaced original capture retirement failed")
   do{_ = try registry.verify(host:host,session:session,request:request("ordered-execution-verify",session,owner,next["token"] as! String))}catch{check(false,"old retirement deleted replacement capsule")}
   check(original["token"] as? String != next["token"] as? String,"different capture requests reused native token")
   check(registry.releaseCapture(retirement(registry,session,owner,nextNonce)) != nil,"current original capture retirement failed")
   reject("retired exact capsule remained live"){_ = try registry.verify(host:host,session:session,request:request("ordered-execution-verify",session,owner,next["token"] as! String))}
   try host.close()
  }
  do {
   let registry=RouterVPNNodeChainExecutionRegistry(),(host,_,_)=try start(),epoch=registry.epoch()
   for index in 0..<64{check(registry.releaseCapture(retirement(registry,session,owner,String(format:"%032x",index))) != nil,"retirement capacity refused original bounded inventory")}
   check(registry.releaseCapture(retirement(registry,session,owner,String(repeating:"f",count:32)))==nil,"retirement overflow evicted an in-flight marker")
   reject("earliest retired request was evicted"){_ = try registry.capture(host:host,session:session,request:request("ordered-execution-capture",session,owner,nonce:String(repeating:"0",count:32)),epoch:epoch)}
   _ = try registry.beginStart(temporaryOwner:nil,restoreToken:nil,restoreOwner:nil)
   reject("old generation crossed retirement reset"){_ = try registry.capture(host:host,session:session,request:request("ordered-execution-capture",session,owner,nonce:firstNonce),epoch:epoch)}
   _ = try registry.capture(host:host,session:session,request:request("ordered-execution-capture",session,owner,nonce:String(repeating:"0",count:32)),epoch:registry.epoch())
   try host.close()
  }
  do {
   let registry=RouterVPNNodeChainExecutionRegistry(),other=RouterVPNNodeChainExecutionRegistry(),(host,_,_)=try start()
   let scope=observation(registry),foreign=observation(other),oldEpoch=registry.epoch()
   check(scope["process_id"] as? String != foreign["process_id"] as? String,"separate registry reused process identity")
   let scoped:[String:String]=["operation":"ordered-execution-capture","request_id":firstNonce,"session_id":session,"owner_id":owner,"token":"","process_id":scope["process_id"] as! String,"registry_generation":scope["registry_generation"] as! String]
   let capture=RouterVPNNodeChainExecutionRegistry.Request.parse(try JSONSerialization.data(withJSONObject:scoped))!
   let value=try decode(registry.capture(host:host,session:session,request:capture,epoch:oldEpoch))
   let exact=retirement(registry,session,owner,firstNonce)
   check(other.releaseCapture(exact)==nil,"foreign process acknowledged original capsule absence")
   var future=scoped;future["registry_generation"]="1"
   let futureCapture=RouterVPNNodeChainExecutionRegistry.Request.parse(try JSONSerialization.data(withJSONObject:future))!
   reject("future capture generation"){_ = try registry.capture(host:host,session:session,request:futureCapture,epoch:oldEpoch)}
   var cleanup=["operation":"ordered-execution-capture-release","request_id":nextNonce,"session_id":session,"owner_id":owner,"capture_request_id":firstNonce,"process_id":scope["process_id"] as! String,"registry_generation":"1"]
   check(registry.releaseCapture(RouterVPNNodeChainExecutionRegistry.Request.parse(try JSONSerialization.data(withJSONObject:cleanup))!)==nil,"future generation retirement was acknowledged")
   cleanup["registry_generation"]="00"
   check(RouterVPNNodeChainExecutionRegistry.Request.parse(try JSONSerialization.data(withJSONObject:cleanup))==nil,"noncanonical generation was accepted")
   _ = try registry.beginStart(temporaryOwner:owner,restoreToken:nil,restoreOwner:nil)
   let next=observation(registry)
   check(next["process_id"] as? String==scope["process_id"] as? String && next["registry_generation"] as? String=="1","start failed exact process generation increment")
   let reply:[String:Any]=["schema":1,"kind":"routervpn-ordered-execution-last","request_id":String(repeating:"c",count:32),"session_id":session,"source_sha256":String(repeating:"a",count:64),"preparation_config_sha256":String(repeating:"b",count:64),"last":"{}"]
   check(registry.observe(try JSONSerialization.data(withJSONObject:reply),request:request("ordered-execution-owner",session,""),epoch:oldEpoch)==nil,"stale owner observation survived beginStart")
   check(registry.releaseCapture(exact) != nil,"same process failed old generation exact retirement")
   reject("same process old-generation capsule remained live"){_ = try registry.verify(host:host,session:session,request:request("ordered-execution-verify",session,owner,value["token"] as! String))}
   var current=scoped;current["registry_generation"]="1"
   let currentRequest=RouterVPNNodeChainExecutionRegistry.Request.parse(try JSONSerialization.data(withJSONObject:current))!
   let replacement=try decode(registry.capture(host:host,session:session,request:currentRequest,epoch:registry.epoch()))
   check(registry.releaseCapture(exact) != nil,"old generation idempotent retirement failed")
   do{_ = try registry.verify(host:host,session:session,request:request("ordered-execution-verify",session,owner,replacement["token"] as! String))}catch{check(false,"old generation retired a reused current request nonce")}
   reject("old scoped capture reused new registry generation"){_ = try registry.capture(host:host,session:session,request:capture,epoch:registry.epoch())}
   try host.close()
  }
  print("PASS Apple ordered registry: \(checks) checks")
 }
}
final class Counter:@unchecked Sendable{static let shared=Counter();var value=0}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ios-execution-registry-') as directory:
        work=Path(directory);boundary=work/'Boundary.swift';boundary.write_text(BOUNDARY+IPC);tests=work/'Tests.swift';tests.write_text(TESTS)
        host=work/'Host.swift';host.write_text((TUN/'RouterVPNNodeChainExecutionHost.swift').read_text().replace('import Libbox\n',''))
        registry=TUN/'RouterVPNNodeChainExecutionRegistry.swift'
        command=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules'),str(boundary),str(host)]
        binary=work/'baseline'
        subprocess.run(command+[str(registry),str(tests),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary)],check=True,timeout=30)
        if '--baseline-only' in sys.argv:return
        text=registry.read_text()
        for name,before,after,witness in (
            ('distinct-source','token == nil && owner == nil && last == nil || executionSourcePresent else','true else','ACCEPTED Last used Local or pair source'),
            ('capture-epoch','generation == epoch','true','ACCEPTED late original capture after a new start'),
            ('foreign-start','if entry?.owner != temporaryOwner { entry = nil }','if false { entry = nil }','ACCEPTED unrelated start preserved restore authority'),
            ('host-pointer','original.host === host, original.session == session','true, original.session == session','ACCEPTED replacement host borrowed original capsule'),
            ('late-consume','let current = generation == admission.epoch && entry === captured;','let current = true;','late replacement bypassed new start'),
        ):
            if name == 'capture-epoch':
                start = text.index('    func capture(host:')
                end = text.index('    func verify(host:', start)
                original = text[start:end]
                assert original.count(before) == 3, name
                changed = text[:start] + original.replace(before, after) + text[end:]
            else:
                assert text.count(before) == 1, name
                changed = text.replace(before, after)
            mutant=work/(name+'.swift');mutant.write_text(changed);binary=work/name
            subprocess.run(command+[str(mutant),str(tests),'-o',str(binary)],check=True,timeout=90)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
            assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,(result.stdout+result.stderr)[-2000:])
            print('Rejected ordered registry control:',name,flush=True)
        for name,before,after,witness,count in (
            ('retired-request', '!retiredCaptures.contains(key)', 'true', 'ACCEPTED retired capture request published', 2),
            ('retired-publication', 'guard generation == epoch, !retiredCaptures.contains(key),', 'guard generation == epoch,', 'retired in-flight capture published after ACK', 1),
            ('original-entry-only', 'if matches { entry = nil }', 'entry = nil', 'old retirement deleted replacement capsule', 1),
            ('claiming-owner', 'guard !matches || entry?.claiming == false,', 'guard true,', 'cleanup retired an actively claiming native capsule', 1),
            ('capture-registry-generation', 'let scoped = request.process == nil || request.process == process && request.registryGeneration == generationNumber', 'let scoped = true', 'ACCEPTED future capture generation', 1),
            ('owner-observation-epoch', 'guard generation == epoch else { return nil }', 'guard true else { return nil }', 'provider owner stamp outlived original registry generation', 1),
            ('registry-process', 'guard request.process == process, let requestedGeneration = request.registryGeneration,', 'guard true, let requestedGeneration = request.registryGeneration,', 'foreign process acknowledged original capsule absence', 1),
            ('registry-future', 'requestedGeneration <= generationNumber else { return nil }', 'true else { return nil }', 'future generation retirement was acknowledged', 1),
            ('registry-entry-generation', 'entry?.registryGeneration == requestedGeneration', 'true', 'old generation retired a reused current request nonce', 1),
        ):
            assert text.count(before)==count,name
            mutant=work/(name+'.swift');mutant.write_text(text.replace(before,after));binary=work/name
            subprocess.run(command+[str(mutant),str(tests),'-o',str(binary)],check=True,timeout=90)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
            assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,(result.stdout+result.stderr)[-2000:])
            print('Rejected ordered capture retirement control:',name,flush=True)
        for name,before,after,witness in (
            ('provider-engine','self.libboxEngine === engine,','true,','provider stale engine IPC published'),
            ('provider-generation','self.currentMAXGeneration(generation),','true,','provider stale generation IPC published'),
            ('provider-proof','self.currentPathProofGuard() === proof else','true else','provider stale proof IPC published'),
        ):
            assert IPC.count(before)==1,name
            boundary.write_text(BOUNDARY+IPC.replace(before,after,1));binary=work/name
            subprocess.run(command+[str(registry),str(tests),'-o',str(binary)],check=True,timeout=90)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
            assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,(result.stdout+result.stderr)[-2000:])
            print('Rejected ordered provider IPC control:',name,flush=True)
        boundary.write_text(BOUNDARY+IPC)
        source=host.read_text();before='runAutomatic: restored == nil';assert source.count(before)==1
        host.write_text(source.replace(before,'runAutomatic: true',1));binary=work/'automatic-replay'
        subprocess.run(command+[str(registry),str(tests),'-o',str(binary)],check=True,timeout=90)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
        assert result.returncode!=0 and 'temporary restore reran Auto MTU' in result.stdout+result.stderr
        print('Rejected ordered registry control: automatic-replay',flush=True)

if __name__=='__main__':main()
