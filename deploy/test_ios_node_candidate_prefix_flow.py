#!/usr/bin/env python3
"""Execute the complete shipping owner/controller prefix-only branch.

NE, native compiler and profile persistence are explicit boundaries; the real
source/native gates run separately. This gate exercises actual 50-sample IPC,
post-DOWN proposal admission and final storage callback before the real SDK gate.
"""
from pathlib import Path
import subprocess
import tempfile
import test_ios_node_candidate_preparation_flow as F
from test_ios_startup_policy import member
APP=F.APP
PREFIX=r'''
@MainActor struct IOSNodeCandidatePrefixCapture {
 let native=IOSNodeChainCapture.Plan(),sourceSHA256=String(repeating:"b",count:64),configSHA256=String(repeating:"b",count:64),captureSHA256=String(repeating:"b",count:64)
 static func compile(original:IOSNodeChainCapture,position:Int,inventory:String)throws->Self{
  guard original.launchInput=="original-complete-local-input",position==0,inventory=="inventory"else{throw CancellationError()};return Self()
 }
}
@MainActor struct IOSNodeCandidatePrefixBinding {
 let connection=NETunnelProviderSession()
 func require(_ model:RouterVPNModel)throws{
  guard !model.connected,!model.tunnelTransitioning,model.activeSessionIdentity==nil,model.iosSpeedLabOwnership.active else{throw CancellationError()}
 }
}
@MainActor extension RouterVPNModel {
 func connectCandidatePrefix(_ capture:IOSNodeCandidatePrefixCapture,bundle:ClientBundle,owner:UUID,epoch:UUID,request:String,current:@escaping @MainActor @Sendable ()throws->Void)async throws->IOSNodeCandidatePrefixBinding{
  try current();try check(IOSSpeedLabContext.owner==owner && IOSMTUMeasurementGate.held,"prefix purpose or outer MTU missing before permission")
  Provider.epoch=epoch.uuidString;iosConnectGeneration=UUID()
  try check(!connected && activeSessionIdentity==nil,"prefix launch entered ordinary Connected")
  try current();return IOSNodeCandidatePrefixBinding()
 }
}
'''
BOUNDARY=F.BOUNDARIES.replace('let request="request"','let request:String;init(request:String="request"){self.request=request}')
BOUNDARY=BOUNDARY.replace('source:IOSCandidateCatalogPublication.Capture(),records:', 'source:IOSCandidateCatalogPublication.Capture(request:request),records:')
BOUNDARY=BOUNDARY.replace('static let epoch=UUID().uuidString,mtu=UUID().uuidString,hash=String(repeating:"a",count:64)','static var epoch=UUID().uuidString;static let mtu=UUID().uuidString,hash=String(repeating:"b",count:64)')
BOUNDARY=BOUNDARY.replace('op=body["operation"]!,request=', 'wire=body["operation"]!,request=')
BOUNDARY=BOUNDARY.replace('  let proofs:[[String:Any]]=', '  guard wire.hasPrefix("prefix-candidate-")else{Provider.wrongScope=true;throw Failure(message:"prefix used ordinary candidate IPC")};let op=String(wire.dropFirst(7))\n  let proofs:[[String:Any]]=')
BOUNDARY=BOUNDARY.replace('static var allowClose=false','static var wrongScope=false;static var samples=50\n static var allowClose=false').replace('"samples":50','"samples":samples')
BOUNDARY=BOUNDARY.replace('static func reset(){','static func reset(){wrongScope=false;')
TEST=F.TEST.replace('probe.start(model:model)','probe.startPrefix(model:model)').replace('view!.start(model:model)','view!.startPrefix(model:model)').replace('Apple complete candidate preparation/controller','Apple independent prefix preparation/controller')
TEST=TEST.replace('Provider.closeCalls>0 || !probe.running','Provider.closeCalls>0 || IOSSpeedLabTunnel.stopEntered || !probe.running')
TEST=TEST.replace('  let labels=ProductLabels(model)','  try check(!model.connected && model.activeSessionIdentity==nil,"prefix comparison advertised ordinary Connected")\n  let labels=ProductLabels(model)')
TEST=TEST.replace(' static func main()async throws{', ''' static func incompleteReceipt()async throws {
  Provider.reset();Provider.samples=49;IOSSpeedLabTunnel.reset();IOSViaEntryNetwork.shared.current=1
  IOSNodeBundleStore.shared.records=["source":Data("original".utf8)]
  let model=RouterVPNModel(),probe=IOSNodeCandidates();await probe.refresh(model:model)
  Provider.allowClose=true;IOSSpeedLabTunnel.allowStop=true;IOSSpeedLabTunnel.allowRestore=true
  probe.startPrefix(model:model);try await until{!probe.running}
  try check(probe.scores.isEmpty && !probe.canSave && IOSConnectionProfileStore.writes==0,"incomplete prefix 50-sample receipt gained Save")
  Provider.samples=50
 }
 static func main()async throws{try await incompleteReceipt();''')

def main():
    boundary=F.fixture_boundary(BOUNDARY,PREFIX)
    boundary=boundary.replace('while !condition(){guard ProcessInfo','while !condition(){guard !Provider.wrongScope else{throw Failure(message:"prefix used ordinary candidate IPC")};guard ProcessInfo')
    source=(APP/'IOSNodeCandidates.swift').read_text()
    controller=source[source.index('private final class IOSCandidateReply:'):source.index('struct IOSNodeCandidatesCard:')]
    owner=(APP/'IOSNodeCandidatePreparation.swift').read_text()
    with tempfile.TemporaryDirectory(prefix='ios-prefix-flow-') as folder:
        work=Path(folder);host=work/'Controller.swift';preparation=work/'Preparation.swift';fixture=work/'Flow.swift';binary=work/'test'
        fixture.write_text(boundary+TEST)
        command=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules'),str(APP/'IOSSpeedLabOwnership.swift'),str(APP/'IOSMTUMeasurementGate.swift'),str(APP/'IOSNodeCandidateResult.swift'),str(host),str(preparation),str(fixture),'-o',str(binary)]
        def exercise(controller_source=controller,owner_source=owner,witness=None):
            host.write_text('import Foundation\n'+controller_source);preparation.write_text(owner_source)
            subprocess.run(command,check=True,timeout=90)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
            if witness:
                assert result.returncode!=0 and witness in result.stdout+result.stderr,(witness,result.stdout+result.stderr)
                print('Rejected independent prefix flow defect: '+witness,flush=True)
            else:
                assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip(),flush=True)
        exercise()
        for path,before,after,witness in [
            ('controller','operation: "prefix-" + op','operation: op','prefix used ordinary candidate IPC'),
            ('owner','if let candidate { await candidate.close() }','if false, let candidate { await candidate.close() }','candidate choices escaped before actual candidate join'),
            ('owner','if retired { return }','if retired { return }; if let hold = outerHold { _ = IOSMTUMeasurementGate.release(hold) }','candidate choices escaped before actual candidate join'),
            ('controller','''                try temporary.requireSaved(token: score.token)
                guard selected == self.proposalGeneration''','''                guard selected == self.proposalGeneration''','late detached invalidation appended future profile'),
            ('controller','task = Task { @MainActor [self, model] in','task = Task { @MainActor [weak self, weak model] in\n            guard let self, let model else { return }','view release abandoned the reserved cleanup task'),
        ]:
            original=controller if path=='controller' else owner;assert original.count(before)==1,before
            mutated=original.replace(before,after);assert mutated!=original
            exercise(controller_source=mutated if path=='controller' else controller,owner_source=mutated if path=='owner' else owner,witness=witness)
if __name__=='__main__':main()
