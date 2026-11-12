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
 func captureRestoration()throws->Restoration{guard healthy()else{throw failure("unproved restore")};let next=Restoration(self);restoration=next;return next}
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
 var calls=0,callback:((Data?)->Void)?
 func orderedExecutionRequest(_ request:RouterVPNNodeChainExecutionRegistry.Request,completion:@escaping(Data?)->Void){calls+=1;callback=completion}
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
 static func request(_ operation:String,_ session:String,_ owner:String,_ token:String="") -> RouterVPNNodeChainExecutionRegistry.Request {
  let body=["operation":operation,"request_id":String(repeating:"c",count:32),"session_id":session,"owner_id":owner,"token":token]
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
   try host.close();let admission=try registry.beginStart(temporaryOwner:nil,restoreToken:token,restoreOwner:owner)
   let capsule=host.capture.restoration!,gate=DispatchSemaphore(value:0);capsule.gate=gate
   let observation=Observation()
   DispatchQueue.global().async{do{_ = try registry.consume(admission,original:host.capture)}catch{observation.rejected=true};observation.done.signal()}
   check(capsule.entered.wait(timeout:.now()+3) == .success,"restore factory did not enter")
   _ = try registry.beginStart(temporaryOwner:nil,restoreToken:nil,restoreOwner:nil);gate.signal()
   check(observation.done.wait(timeout:.now()+3) == .success && observation.rejected,"late replacement bypassed new start")
   check((try? capsule.replacement?.requireCurrent())==nil,"late unadopted source owner was dropped")
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
            assert text.count(before)==(3 if name=='capture-epoch' else 1),name
            mutant=work/(name+'.swift');mutant.write_text(text.replace(before,after));binary=work/name
            subprocess.run(command+[str(mutant),str(tests),'-o',str(binary)],check=True,timeout=90)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
            assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,(result.stdout+result.stderr)[-2000:])
            print('Rejected ordered registry control:',name,flush=True)
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
