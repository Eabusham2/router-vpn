#!/usr/bin/env python3
"""Run shipping PacketTunnel prefix delivery and joined Stop coordination."""
from pathlib import Path
import subprocess,tempfile
import test_ios_node_chain_provider as P
ROOT=P.ROOT;TUN=P.TUN
BOUNDARY=P.SWIFT[:P.SWIFT.index('@main struct Tests')]
BOUNDARY=BOUNDARY.replace(' func launch(_ capture:IOSNodeChainCapture,_ completion:@escaping(Error?)->Void)throws{try startNodeChain(capture,generation:maxStartGeneration,completionHandler:completion)}',' func launch(_ capture:IOSNodeCandidatePrefixProviderCapture,_ completion:@escaping(Error?)->Void)throws{try startCandidatePrefix(capture,generation:maxStartGeneration,completionHandler:completion)}\n func removeHold(){initialMTUHold=""}')
BOUNDARY=BOUNDARY.replace(' func completeNodeChainExecution(_ completion:', ' func start(candidatePrefix input:IOSNodeCandidatePrefixProviderCapture)throws{try start(nodeChain:input.capture.native,strict:input.capture.strict)}\n func completeCandidatePrefix(_ completion:@escaping(Error?)->Void){completeNodeChainExecution(completion)}\n func completeNodeChainExecution(_ completion:')
BOUNDARY+=r'''
struct IOSNodeCandidatePrefixCapture {
 let native=NativePlan(),strict=true,homeLANAccess=false
 static func issue()->NSError{IOSNodeChainCapture.issue("Original prefix source or native owner changed")}
}
final class IOSNodeCandidatePrefixProviderCapture {
 let capture=IOSNodeCandidatePrefixCapture();var current=true
 func requireCurrent()throws{if !current{throw IOSNodeCandidatePrefixCapture.issue()}}
}
'''
TEST=r'''
@main struct Tests {
 static func main()throws{
  var checks=0
  func check(_ text:String,_ condition:@autoclosure()->Bool){precondition(condition(),"FAIL "+text);checks+=1}
  for fault in ["none","proof","epoch","owner","source"]{
   let provider=PacketTunnelProvider(),capture=IOSNodeCandidatePrefixProviderCapture(),done=CompletionState()
   try provider.launch(capture,done.finish);let engine=EngineState.shared.current
   check("prepared callback waits for original prefix Run",done.values.isEmpty && engine.plan === capture.capture.native && engine.events==["hold:captured-startup-hold","start","proof"])
   if fault=="epoch"{provider.replaceEpoch()};if fault=="owner"{provider.replaceEngine(RouterVPNLibboxEngine(tunnel:provider))};if fault=="source"{capture.current=false}
   engine.resolve(fault=="proof" ? IOSNodeCandidatePrefixCapture.issue():nil)
   check("prefix delivery rejects stale original owner",done.wait() && done.values==[fault != "none"])
   check("prefix never enables forwarding or normal performance/MTU",provider.forwarding==0 && !engine.events.contains("performance") && !engine.events.contains("mtu"))
   engine.stop();provider.current?.stop()
  }
  for fault in ["strict","routes","lan","hold"]{
   let provider=PacketTunnelProvider(),capture=IOSNodeCandidatePrefixProviderCapture(),done=CompletionState(),proto=provider.protocolConfiguration as! NETunnelProviderProtocol
   if fault=="strict"{proto.includeAllNetworks=false};if fault=="routes"{proto.enforceRoutes=false};if fault=="lan"{proto.excludeLocalNetworks=true};if fault=="hold"{provider.removeHold()}
   var refused=false;do{try provider.launch(capture,done.finish)}catch{refused=true}
   check("prefix policy and outer hold required before native Start",refused && provider.current==nil && capture.capture.native.closes==1 && done.values.isEmpty)
  }
  for startupFailure in [false,true]{
   let provider=PacketTunnelProvider(),capture=IOSNodeCandidatePrefixProviderCapture(),start=CompletionState(),stop=CompletionState()
   try provider.launch(capture,start.finish);let engine=EngineState.shared.current
   engine.configureFailures(100)
   engine.resolve(startupFailure ? IOSNodeCandidatePrefixCapture.issue():nil)
   check("original prefix callback delivered",start.wait() && start.values==[startupFailure])
   check("failed prefix startup retains cleanup owner",provider.current === engine && engine.ownsNodeChain)
   provider.stopTunnel(with:.userInitiated,completionHandler:stop.done)
   check("prefix Stop enters original native join",engine.closeEntered.wait(timeout:.now()+3) == .success)
   check("prefix Stop cannot complete before native join",stop.values.isEmpty && provider.blocked && provider.current === engine)
   engine.configureFailures(0)
   check("prefix Stop completes only after original native DOWN",stop.wait() && provider.current==nil && !provider.blocked)
  }
  print("Apple prefix PacketTunnel delivery: \(checks) shipping startup/Stop checks PASS")
 }
}
'''

def main():
    source=(TUN/'PacketTunnelProvider.swift').read_text()
    methods='\n'.join(P.member(source,s) for s in ('    private func startCandidatePrefix(', '    override func stopTunnel(', '    private func finishNativeStop(', '    private func beginNodeChainStop('))
    with tempfile.TemporaryDirectory(prefix='ios-prefix-delivery-') as folder:
        work=Path(folder);fixture=work/'Test.swift';binary=work/'test'
        command=['swiftc','-j','1','-swift-version','6','-parse-as-library','-module-cache-path',str(work/'modules'),str(TUN/'RouterVPNNodeChainStop.swift'),str(fixture),'-o',str(binary)]
        def exercise(code,witness=None):
            fixture.write_text(BOUNDARY.replace(' // SHIPPING_PROVIDER',code)+TEST)
            subprocess.run(command,check=True,timeout=90)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=25)
            if witness:
                assert result.returncode!=0 and witness in result.stdout+result.stderr,(witness,result.stdout+result.stderr[-2500:]);print('Rejected prefix delivery defect: '+witness,flush=True)
            else:assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip(),flush=True)
        exercise(methods)
        for before,after,witness in [
            ('self.libboxEngine === engine, self.currentMAXGeneration(generation)','self.libboxEngine === engine','prefix delivery rejects stale original owner'),
            ('if let failure { engine.stop(); completionHandler(failure); return }','if let failure { engine.stop(); self.libboxEngine = nil; completionHandler(failure); return }','failed prefix startup retains cleanup owner'),
            ('currentMAXGeneration(generation), !initialMTUHold.isEmpty,','currentMAXGeneration(generation), true,','prefix policy and outer hold required before native Start'),
            ('if let engine = libboxEngine, beginNodeChainStop(engine, completion: completion) { return }','// omitted original joined Stop','prefix Stop cannot complete before native join'),
        ]:
            assert methods.count(before)==1,before
            changed=methods.replace(before,after);assert changed!=methods;exercise(changed,witness)
    branch=P.member(source,'            if provider[IOSNodeCandidatePrefixProviderCapture.key] != nil')
    for marker in ('IOSNodeCandidatePrefixProviderCapture.reopen(provider)','startCandidatePrefix(input','restoreKey','restoreOwnerKey','lastKey','IOSMultihopExecution.launchKey','IOSMultihopExecution.startupLaunchKey','!initialMTUHold.isEmpty','return'):
        assert marker in branch,marker
    assert source.index(branch)<source.index('            if IOSNodeChainProviderCapture.requested(')
if __name__=='__main__':main()
