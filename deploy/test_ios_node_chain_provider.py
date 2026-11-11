#!/usr/bin/env python3
"""Execute ordered PacketTunnel startup and joined Stop with explicit native/OS doubles.

The production methods and Stop delivery run unchanged under Swift 6. Shared
compiler, actual encrypted peers, real TUN and Apple SDK gates remain separate.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TUN = ROOT / 'ios/RouterVPN/PacketTunnel'


def member(source, signature):
    begin=source.index(signature);end=source.index('{',begin)+1;depth=1
    while depth:
        if source[end]=='{':depth+=1
        if source[end]=='}':depth-=1
        end+=1
    return source[begin:end]


SWIFT=r'''
import Foundation
enum NEProviderStopReason{case userInitiated}
class NEPacketTunnelProvider {
 var protocolConfiguration:Any?
 func stopTunnel(with reason:NEProviderStopReason,completionHandler:@escaping()->Void){}
}
final class NETunnelProviderProtocol {
 var includeAllNetworks=true,enforceRoutes=true,excludeLocalNetworks=false
}
final class NativePlan {
 var closes=0
 func close()throws{closes+=1}
}
struct IOSNodeChainCapture {
 let plan=NativePlan(),strict=true,homeLANAccess=false
 let finalProfile:[String:Any]=["id":"final-node","node_proof_id":String(repeating:"c",count:64),"api_token":"original-final-token"]
 static func issue(_ message:String)->NSError{NSError(domain:"ChainProviderFixture",code:1,userInfo:[NSLocalizedDescriptionKey:message])}
}
final class CompletionState:@unchecked Sendable {
 private let lock=NSLock();private var errors:[Bool]=[]
 let signal=DispatchSemaphore(value:0)
 func finish(_ error:Error?){lock.lock();errors.append(error != nil);lock.unlock();signal.signal()}
 func done(){finish(nil)}
 var values:[Bool]{lock.lock();defer{lock.unlock()};return errors}
 func wait()->Bool{signal.wait(timeout:.now()+4) == .success}
}
final class EngineState:@unchecked Sendable {
 static let shared=EngineState()
 private let lock=NSLock();private var latest:RouterVPNLibboxEngine?
 var mode="",action:(()->Void)?
 func install(_ engine:RouterVPNLibboxEngine){lock.lock();latest=engine;lock.unlock()}
 var current:RouterVPNLibboxEngine{lock.lock();defer{lock.unlock()};return latest!}
}
final class RouterVPNLibboxEngine {
 private let lock=NSLock();private var owned=false,failures=0,closeCount=0
 private var callback:((Error?)->Void)?
 private(set) var plan:NativePlan?,events:[String]=[]
 let closeEntered=DispatchSemaphore(value:0)
 init(tunnel:PacketTunnelProvider){EngineState.shared.install(self)}
 var ownsNodeChain:Bool{lock.lock();defer{lock.unlock()};return owned}
 var closes:Int{lock.lock();defer{lock.unlock()};return closeCount}
 func prepareMTUHold(_ value:String)throws{events.append("hold:"+value)}
 func start(nodeChain plan:NativePlan,strict:Bool)throws{lock.lock();owned=true;self.plan=plan;lock.unlock();events.append("start")}
 func completeNodeChainExecution(_ completion:@escaping(Error?)->Void){callback=completion;events.append("proof")}
 func resolve(_ error:Error?=nil){let send=callback;callback=nil;send?(error)}
 func activatePerformance()throws{events.append("performance");if EngineState.shared.mode=="performance"{EngineState.shared.action?()}}
 func activateNodeChainMTU()throws{events.append("mtu");if EngineState.shared.mode=="mtu"{EngineState.shared.action?()}}
 func configureFailures(_ value:Int){lock.lock();failures=value;lock.unlock()}
 func stop(){try? stopCheckedForStrategy()}
 func stopCheckedForStrategy()throws{
  lock.lock();closeCount+=1;let reject=failures>0;if reject{failures-=1}else{owned=false};lock.unlock();closeEntered.signal()
  if reject{throw IOSNodeChainCapture.issue("original join still pending")}
 }
}
final class PendingStart{func cancelAndDrain(_ done:()->Void){done()}}
final class Adapter{func stop(_ done:(Error?)->Void){done(nil)}}
final class PacketTunnelProvider:NEPacketTunnelProvider {
 final class NetworkProofGuard{}
 private let maxStartOwnerLock=NSLock(),strategyOwnerLock=NSLock()
 private var maxStartOwner:PendingStart?,maxStartGeneration=UUID(),maxStartDraining=false
 private var nodeChainStop:RouterVPNNodeChainStop?,libboxEngine:RouterVPNLibboxEngine?
 private var providerStrategy:String?,strategyDriver:String?,wireGuardAdapter:Adapter?
 private var initialMTUHold="captured-startup-hold",path:NetworkProofGuard?
 var forwarding=0,afterForward:(()->Void)?
 override init(){super.init();protocolConfiguration=NETunnelProviderProtocol()}
 func armNetworkProofGuard()->NetworkProofGuard{let value=NetworkProofGuard();path=value;return value}
 func currentPathProofGuard()->NetworkProofGuard?{path}
 func clearPathProofGuard(){path=nil}
 func cancelActiveProof(){}
 func currentMAXGeneration(_ value:UUID)->Bool{maxStartOwnerLock.lock();defer{maxStartOwnerLock.unlock()};return maxStartGeneration==value && !maxStartDraining}
 func finishOwnedStop(completion:@escaping()->Void){finishNativeStop(completion:completion)}
 func enableForwarding(profileData:Data,proofID:String,captured:NetworkProofGuard){forwarding+=1;afterForward?()}
 func launch(_ capture:IOSNodeChainCapture,_ completion:@escaping(Error?)->Void)throws{try startNodeChain(capture,generation:maxStartGeneration,completionHandler:completion)}
 func changePath(){path=NetworkProofGuard()}
 func replaceEpoch(){maxStartOwnerLock.lock();maxStartGeneration=UUID();maxStartOwnerLock.unlock()}
 func replaceEngine(_ engine:RouterVPNLibboxEngine){libboxEngine=engine}
 var current:RouterVPNLibboxEngine?{libboxEngine}
 var pending:RouterVPNNodeChainStop?{maxStartOwnerLock.lock();defer{maxStartOwnerLock.unlock()};return nodeChainStop}
 var blocked:Bool{maxStartOwnerLock.lock();defer{maxStartOwnerLock.unlock()};return maxStartDraining || nodeChainStop != nil}
 // SHIPPING_PROVIDER
}
@main struct Tests {
 static func main()throws {
  var checks=0
  func check(_ label:String,_ ok:@autoclosure()->Bool){precondition(ok(),"FAIL "+label);checks+=1}
  for fault in ["none","proof","path","epoch","owner","performance","mtu","forwarding"] {
   EngineState.shared.mode="";EngineState.shared.action=nil
   let provider=PacketTunnelProvider(),capture=IOSNodeChainCapture(),done=CompletionState()
   try provider.launch(capture,done.finish);let engine=EngineState.shared.current
   check("native startup waits for every proof",done.values.isEmpty && engine.plan === capture.plan && engine.events==["hold:captured-startup-hold","start","proof"])
   if fault=="path"{provider.changePath()}
   if fault=="epoch"{provider.replaceEpoch()}
   if fault=="owner"{provider.replaceEngine(RouterVPNLibboxEngine(tunnel:provider))}
   if fault=="performance" || fault=="mtu"{EngineState.shared.mode=fault;EngineState.shared.action={provider.changePath()}}
   if fault=="forwarding"{provider.afterForward={provider.changePath()}}
   engine.resolve(fault=="proof" ? IOSNodeChainCapture.issue("middle-node proof failed"):nil)
   check("startup delivers only current full chain",done.wait() && done.values==[fault != "none"])
   if fault=="none"{check("activation follows proof and owns selected MTU",engine.events==["hold:captured-startup-hold","start","proof","performance","mtu"] && provider.forwarding==1)}
   else if fault != "forwarding"{check("failed or stale chain cannot release control credentials",provider.forwarding==0)}
   if ["proof","path","epoch","owner"].contains(fault){check("failed proof cannot activate native services",!engine.events.contains("performance") && !engine.events.contains("mtu"))}
   if fault=="performance"{check("stale performance phase cannot adopt MTU",!engine.events.contains("mtu"))}
   engine.stop();provider.current?.stop()
  }
  for policy in ["routes","strict","lan"] {
   let provider=PacketTunnelProvider(),capture=IOSNodeChainCapture(),done=CompletionState(),proto=provider.protocolConfiguration as! NETunnelProviderProtocol
   if policy=="routes"{proto.enforceRoutes=false};if policy=="strict"{proto.includeAllNetworks=false};if policy=="lan"{proto.excludeLocalNetworks=true}
   var refused=false;do{try provider.launch(capture,done.finish)}catch{refused=true}
   check("every selected route policy is exact before native start",refused && capture.plan.closes==1 && done.values.isEmpty && provider.current==nil)
  }
  for replace in [false,true] {
   let provider=PacketTunnelProvider(),capture=IOSNodeChainCapture(),start=CompletionState(),first=CompletionState(),second=CompletionState()
   try provider.launch(capture,start.finish);let original=EngineState.shared.current
   original.resolve();check("stop fixture starts proven owner",start.wait() && start.values==[false])
   original.configureFailures(100)
   provider.stopTunnel(with:.userInitiated,completionHandler:first.done)
   check("original stop entered checked retirement",original.closeEntered.wait(timeout:.now()+3) == .success)
   check("unjoined native retirement keeps all Stop callbacks pending",first.values.isEmpty && provider.pending != nil && provider.blocked)
   let pending=provider.pending!
   provider.stopTunnel(with:.userInitiated,completionHandler:second.done)
   check("unjoined native retirement keeps all Stop callbacks pending",first.values.isEmpty && second.values.isEmpty && provider.blocked && provider.current === original)
   var replacement:RouterVPNLibboxEngine?
   if replace{replacement=RouterVPNLibboxEngine(tunnel:provider);provider.replaceEngine(replacement!);provider.replaceEpoch()}
   original.configureFailures(0)
   check("both Stop callbacks wait for joined original owner",first.wait() && second.wait() && first.values==[false] && second.values==[false] && !original.ownsNodeChain)
   if let replacement{check("late native close cannot clear or stop replacement",provider.current === replacement && replacement.closes==0 && provider.blocked)}
   else{check("joined Stop releases original provider admission",provider.current==nil && !provider.blocked)}
   let again=CompletionState(),closed=original.closes
   pending.start(completion:again.done)
   check("completed Stop receipt never reruns native teardown",again.wait() && original.closes==closed)
  }
  // A failure response does not authorize dropping an unfinished native join.
  do {
   let provider=PacketTunnelProvider(),capture=IOSNodeChainCapture(),start=CompletionState(),stopped=CompletionState()
   try provider.launch(capture,start.finish);let engine=EngineState.shared.current
   engine.configureFailures(100);engine.resolve(IOSNodeChainCapture.issue("startup failed"))
   check("failed startup retains unfinished original native owner",start.wait() && start.values==[true] && provider.current === engine && engine.ownsNodeChain)
   provider.stopTunnel(with:.userInitiated,completionHandler:stopped.done)
   check("failed startup Stop remains pending",stopped.values.isEmpty && provider.blocked)
   engine.configureFailures(0)
   check("failed startup Stop joins original retirement",stopped.wait() && provider.current==nil && !provider.blocked)
  }
  print("Apple ordered PacketTunnel: PASS (\(checks) shipping startup/Stop checks; native and OS handles doubled)")
 }
}
'''


def main():
    source=(TUN/'PacketTunnelProvider.swift').read_text()
    signatures=('    private func startNodeChain(', '    override func stopTunnel(', '    private func finishNativeStop(', '    private func beginNodeChainStop(')
    methods='\n'.join(member(source,s) for s in signatures)
    with tempfile.TemporaryDirectory(prefix='ios-node-chain-provider-') as directory:
        work=Path(directory);tests=work/'Tests.swift';tests.write_text(SWIFT.replace(' // SHIPPING_PROVIDER',methods))
        stop=TUN/'RouterVPNNodeChainStop.swift'
        binary=work/'tests'
        command=['swiftc','-j','1','-swift-version','6','-parse-as-library','-module-cache-path',str(work/'modules')]
        subprocess.run(command+[str(stop),str(tests),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary)],check=True,timeout=25)
        for name,before,after,expected in (
            ('provider-epoch','self.libboxEngine === engine, self.currentMAXGeneration(generation)','self.libboxEngine === engine','startup delivers only current full chain'),
            ('pending-proof-owner','if let failure { engine.stop(); completionHandler(failure); return }','if let failure { engine.stop(); self.libboxEngine = nil; completionHandler(failure); return }','failed startup retains unfinished original native owner'),
            ('joined-stop','if let engine = libboxEngine, beginNodeChainStop(engine, completion: completion) { return }','// lost original joined stop','original stop entered checked retirement'),
        ):
            assert before in methods,name
            broken=work/(name+'.swift');broken.write_text(SWIFT.replace(' // SHIPPING_PROVIDER',methods.replace(before,after)))
            executable=work/name
            subprocess.run(command+[str(stop),str(broken),'-o',str(executable)],check=True,timeout=90)
            result=subprocess.run([str(executable)],capture_output=True,text=True,timeout=25)
            # Different callback timing may expose the earlier direct pending
            # assertion before the original entered-retirement assertion.
            accepted=[expected]
            if name=='joined-stop':accepted+=['unjoined native retirement keeps all Stop callbacks pending']
            assert result.returncode != 0 and any('FAIL '+text in result.stdout+result.stderr for text in accepted),name+': missing causal failure '+(result.stdout+result.stderr)[-1400:]
            print('Rejected ordered PacketTunnel defect mutation: '+name)
    branch=source[source.index('            if IOSNodeChainProviderCapture.requested('):source.index('            if try IOSMultihopExecution.requiresCapture(')]
    for marker in ('IOSMultihopExecution.launchKey','IOSMultihopExecution.startupLaunchKey','currentMAXGeneration(generation)','IOSNodeChainProviderCapture.reopen(provider)','startNodeChain(capture, generation: generation','return'):
        assert marker in branch,marker


if __name__=='__main__':main()
