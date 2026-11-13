#!/usr/bin/env python3
"""Execute the complete shipping candidate controller and preparation owner.

OS VPN completion, source compilation and durable profile storage are explicit
boundaries, covered independently by the mandatory native/compiler/store gates.
This composition verifies that actual IPC receipts cannot reach Save before
both native owners join, and exercises the real final append callback.
"""
from pathlib import Path
import subprocess
import tempfile
import test_ios_node_candidate_preparation as P
from test_ios_startup_policy import member
APP = P.APP
BOUNDARIES = r'''
protocol ObservableObject:AnyObject {}
@propertyWrapper struct Published<Value>{var wrappedValue:Value;init(wrappedValue:Value){self.wrappedValue=wrappedValue}}
@MainActor final class NETunnelProviderSession {
 func sendProviderMessage(_ data:Data,responseHandler:@escaping (Data?)->Void)throws{responseHandler(try Provider.reply(data))}
}
@MainActor enum IOSMTUControl {
 struct Identity {let nodeChainSource:Data?;let bundleData:Data}
 struct Binding {let connection:NETunnelProviderSession;let session:String;let identity:Identity}
 static func capture(_ model:RouterVPNModel)async throws->Binding{
  Binding(connection:NETunnelProviderSession(),session:Provider.mtu,identity:Identity(nodeChainSource:Data("original-complete-local-input".utf8),bundleData:try IOSNodeUsage.canonical(model.bundle)))
 }
 static func current(_ value:Binding,model:RouterVPNModel)->Bool{model.connected}
 static func withHold<T>(model:RouterVPNModel,operation:@MainActor ()async throws->T)async throws->T{
  let lease=IOSMTUMeasurementGate.acquire();defer{_ = IOSMTUMeasurementGate.release(lease)};return try await operation()
 }
}
@MainActor enum IOSCandidateCatalogPublication {
 struct Stamp:Equatable{let generation:Int}
 struct Capture{}
 static let shared=SelfStore()
 nonisolated static func validRequest(_ text:String)->Bool{text.count==32 && text.allSatisfy{$0.isHexDigit}}
 nonisolated static func isDigest(_ text:String)->Bool{text.count==64 && text.allSatisfy{$0.isHexDigit}}
 @MainActor final class SelfStore {
  func closed(epoch:String,request:String)->Bool{Provider.closed && epoch==Provider.epoch}
  func remove(_ capture:Capture)throws{}
  func acknowledgeClosed(epoch:String,request:String)throws{}
 }
}
@MainActor struct IOSNodeCandidateCapture {
 struct Row{let id:String;let name:String;let input:String}
 let source=IOSCandidateCatalogPublication.Capture(),rows=[Row(id:"candidate",name:"Original candidate",input:"measured original")]
 let records:[String:Data],prefix:IOSNodeCandidatePrefix,chainSource:String,chainConfig:String
 static func make(request:String,prefixPosition:Int,proofs:[IOSNodeCandidatePrefix],chainSource:String,chainConfig:String)throws->Self{
  Self(records:IOSNodeBundleStore.shared.records,prefix:proofs[prefixPosition],chainSource:chainSource,chainConfig:chainConfig)
 }
 func requireCurrent()throws{guard records==IOSNodeBundleStore.shared.records else{throw CancellationError()}}
 static func issue()->NSError{NSError(domain:"OriginalSourceBoundary",code:1)}
}
@MainActor struct IOSNodeCandidateProposal {
 let description="Complete original future graph",profiles=["original-first","candidate"]
 static func compile(original:IOSNodeChainCapture,records:[String:Data],position:Int,candidateID:String,measuredInput:String)throws->Self{
  guard !Provider.unsupported else{throw NSError(domain:"ExplicitCompilerBoundary",code:1,userInfo:[NSLocalizedDescriptionKey:"The measured source cannot form a supported future route."])}
  return Self()
 }
}
@MainActor enum IOSConnectionProfileStore {
 struct Record{let name:String}
 static var writes=0;static var beforeFinal:(()->Void)?
 static func appendCandidate(name:String,profiles:[String],current:()throws->Void)throws->Record{
  try current();beforeFinal?();try current();writes+=1;return Record(name:name)
 }
}
// SHIPPING_SAVE_WRAPPER
@MainActor enum Provider {
 static let epoch=UUID().uuidString,mtu=UUID().uuidString,hash=String(repeating:"a",count:64)
 static var allowClose=false,closed=false,closeCalls=0,unsupported=false
 static func reset(){allowClose=false;closed=false;closeCalls=0;unsupported=false;IOSConnectionProfileStore.writes=0;IOSConnectionProfileStore.beforeFinal=nil}
 static func reply(_ data:Data)throws->Data{
  let body=try JSONSerialization.jsonObject(with:data) as! [String:String],op=body["operation"]!,request=body["request_id"]!
  let proofs:[[String:Any]]=[["position":0,"profile_id":"entry","node_id":"original-first","mode":"wg"],["position":1,"profile_id":"final","node_id":"original-final","mode":"shadowsocks"]]
  if op=="candidate-info"{return try json(["request_id":request,"session_id":epoch,"mtu_session_id":mtu,"source_sha256":hash,"config_sha256":hash,"proofs":proofs])}
  var reply:[String:Any]=["request_id":request,"session_id":epoch,"owner_request":body["owner_request"]!]
  if op=="candidate-open"{reply["metadata"]=String(decoding:try json(["schema":1,"capture_sha256":hash,"prefix_position":0,"prefix_id":"entry","source_sha256":hash,"config_sha256":hash,"targets":[["id":"candidate","source_sha256":hash]]]),as:UTF8.self)}
  if op=="candidate-start" || op=="candidate-status"{
   let now=Int64(Date().timeIntervalSince1970*1000)
   let benchmark:[String:Any]=["schema":1,"measurement":"routed-tcp-connect","attempts":50,"failed":0,"trimmed_mean_ms":2.4,"distribution":["samples":50,"min_ms":1.0,"median_ms":2.0,"average_ms":2.5,"p90_ms":3.0,"max_ms":4.0,"jitter_ms":0.5]]
   reply["status"]=String(decoding:try json(["schema":1,"request_id":request,"complete":true,"drained":true,"stage":"complete","measurement":"routed-tcp-connect","capture_sha256":hash,"prefix_position":0,"prefix_id":"entry","candidate_id":"candidate","candidate_source_sha256":hash,"measured_at":now,"expires_at":now+120000,"results":[["node_id":"candidate","role":"candidate","kind":"tcp-connect","ready":true,"benchmark":benchmark]]]),as:UTF8.self)
  }
  if op=="candidate-close"{closeCalls+=1;closed=allowClose;reply["closed"]=closed}
  return try json(reply)
 }
 static func json(_ value:[String:Any])throws->Data{try JSONSerialization.data(withJSONObject:value)}
}
'''
TEST = r'''
@MainActor @main struct Flow {
 static func run(unsupported:Bool=false)async throws {
  Provider.reset();Provider.unsupported=unsupported;IOSSpeedLabTunnel.reset();IOSViaEntryNetwork.shared.current=1
  IOSNodeBundleStore.shared.records=["source":Data("original".utf8)]
  let model=RouterVPNModel(),probe=IOSNodeCandidates()
  await probe.refresh(model:model);try check(probe.prefixes.count==1,"saved complete Local path did not expose original packet prefix")
  probe.start(model:model)
  let labels=ProductLabels(model)
  try check(labels.state()=="Testing" && labels.button()=="Cancel test","temporary purpose presented ordinary Connected or Connect")
  try await until{Provider.closeCalls>0 || !probe.running}
  try check(probe.running && probe.scores.isEmpty && !probe.canPrepare && IOSMTUMeasurementGate.held && !IOSSpeedLabTunnel.stopEntered,"candidate choices escaped before actual candidate join")
  Provider.allowClose=true;try await until{IOSSpeedLabTunnel.stopEntered}
  try check(probe.scores.isEmpty && !probe.canSave && IOSMTUMeasurementGate.held,"candidate choices escaped before original native DOWN")
  IOSSpeedLabTunnel.allowStop=true;try await until{IOSSpeedLabTunnel.restoreEntered}
  try check(!model.connected && probe.scores.isEmpty && IOSMTUMeasurementGate.held,"candidate choices escaped before original idle restore")
  IOSSpeedLabTunnel.allowRestore=true;try await until{probe.canPrepare || !probe.running}
  try check(probe.canPrepare && probe.scores.count==1 && !model.connected && !IOSMTUMeasurementGate.held,"joined original graph did not expose detached results")
  try check(labels.state()=="Disconnected" && labels.button()=="Connect","joined purpose retained Testing or Connected label")
  probe.prepare(probe.scores[0]);try await until{!probe.preparing}
  if unsupported {
   try check(!probe.canSave && probe.profileMessage.contains("cannot form a supported future route") && probe.scores.count==1,"unsupported future route erased honest timing or gained Save")
  } else {
   try check(probe.canSave,"detached original proposal was not prepared")
   probe.save(name:"Explicit future graph");try await until{!probe.preparing}
   try check(IOSConnectionProfileStore.writes==1 && !model.connected,"explicit detached Save failed or started ordinary connection")
   probe.prepare(probe.scores[0]);try await until{!probe.preparing};try check(probe.canSave,"second explicit proposal unavailable")
   IOSConnectionProfileStore.beforeFinal={model.endpoint="changed immediately before append"}
   probe.save(name:"Must not append");try await until{!probe.preparing}
   try check(IOSConnectionProfileStore.writes==1 && probe.profileMessage.hasPrefix("Profile was not saved"),"late detached invalidation appended future profile")
  }
  probe.cancel();try await until{!probe.running}
  try check(IOSNodeCandidatePreparation.retained == nil && !IOSMTUMeasurementGate.held,"closed controller retained temporary purpose")
 }
 static func droppedView()async throws {
  Provider.reset();IOSSpeedLabTunnel.reset();IOSViaEntryNetwork.shared.current=1
  IOSNodeBundleStore.shared.records=["source":Data("original".utf8)]
  let model=RouterVPNModel()
  var view:IOSNodeCandidates?=IOSNodeCandidates()
  await view!.refresh(model:model)
  weak var original=view
  view!.start(model:model)
  view=nil
  try check(original != nil,"view release abandoned the reserved cleanup task")
  model.cancelCandidateTesting()
  Provider.allowClose=true;IOSSpeedLabTunnel.allowStop=true;IOSSpeedLabTunnel.allowRestore=true
  try await until{IOSNodeCandidatePreparation.retained == nil}
  try check(!IOSMTUMeasurementGate.held && !model.iosSpeedLabOwnership.active && !model.connected,"view release abandoned joined temporary cleanup")
  try await until{original == nil}
  try check(original == nil,"completed temporary cleanup retained its controller")
 }
 static func main()async throws{try await run();try await run(unsupported:true);try await droppedView();print("Apple complete candidate preparation/controller: \(checks) detached flow checks PASS")}
}
'''

def main():
    owner_boundaries = P.SWIFT[:P.SWIFT.index('@MainActor @main struct Test')]
    owner_boundaries = owner_boundaries.replace('enum IOSCandidateCatalogPublication {struct Stamp:Equatable {let generation:Int}}', '')
    block = member(owner_boundaries, '@MainActor final class IOSNodeCandidateTransaction')
    owner_boundaries = owner_boundaries.replace(block, '')
    owner_boundaries = owner_boundaries.replace('struct IOSNodeCandidatePrefix:Equatable {let position:Int;let profile_id:String;let node_id:String;let mode:String}', 'struct IOSNodeCandidatePrefix:Decodable,Equatable {let position:Int;let profile_id:String;let node_id:String;let mode:String;var supported:Bool{mode=="wg"}}')
    owner_boundaries = owner_boundaries.replace('sourceSHA256="source",configSHA256="config"', 'sourceSHA256=String(repeating:"a",count:64),configSHA256=String(repeating:"a",count:64)')
    owner_boundaries = owner_boundaries.replace(' let objectWillChange=Change(),iosSpeedLabOwnership=IOSSpeedLabOwnership()', ' var selectedNodeProfile:Profile?{bundle?.routerProfiles.first};var iosVisibleOrderedNodePath:[String]?{["entry","final"]};var activeEngine="multihop-libbox"\n let objectWillChange=Change(),iosSpeedLabOwnership=IOSSpeedLabOwnership()')
    owner_boundaries = owner_boundaries.replace('// SHIPPING_LAST_WRITER', member((APP/'IOSStrategySupport.swift').read_text(), '    func recordIOSLastRuntime('))
    save = member((APP/'IOSConnectionProfilesView.swift').read_text(), '@MainActor enum IOSCandidateConnectionProfiles')
    save = save.replace('[RouterProfile]', '[String]') # Only the source compiler/value boundary is substituted.
    owner_boundaries = owner_boundaries.replace(' var selectedNodeProfile:Profile?', ' struct Status {enum Phase{case blocked};let phase:Phase};var iosStrategyStatus:Status?\n var selectedNodeProfile:Profile?')
    ui = (APP/'IOSUnifiedProductView.swift').read_text()
    labels = '@MainActor final class ProductLabels {let model:RouterVPNModel;init(_ model:RouterVPNModel){self.model=model}\n' + member(ui, '    private var connectionStateTitle:') + '\n' + member(ui, '    private var connectionButtonTitle:') + '\nfunc state()->String{connectionStateTitle};func button()->String{connectionButtonTitle}}'
    boundary = owner_boundaries + BOUNDARIES.replace('// SHIPPING_SAVE_WRAPPER', save) + labels
    source = (APP/'IOSNodeCandidates.swift').read_text()
    controller = source[source.index('private final class IOSCandidateReply:'):source.index('struct IOSNodeCandidatesCard:')]
    with tempfile.TemporaryDirectory(prefix='ios-candidate-flow-') as directory:
        work=Path(directory);fixture=work/'Flow.swift';host=work/'Controller.swift';binary=work/'test'
        fixture.write_text(boundary+TEST);host.write_text('import Foundation\n'+controller)
        command=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules'),str(APP/'IOSSpeedLabOwnership.swift'),str(APP/'IOSMTUMeasurementGate.swift'),str(APP/'IOSNodeCandidatePreparation.swift'),str(APP/'IOSNodeCandidateResult.swift'),str(host),str(fixture),'-o',str(binary)]
        subprocess.run(command,check=True,timeout=90)
        subprocess.run([str(binary)],check=True,timeout=30)
        needle='''                            try temporary.requireSaved(token: score.token)
                            guard selected == self.proposalGeneration'''
        assert controller.count(needle)==1
        host.write_text('import Foundation\n'+controller.replace(needle, '                            guard selected == self.proposalGeneration'))
        subprocess.run(command,check=True,timeout=90,capture_output=True)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
        assert result.returncode!=0 and 'late detached invalidation appended future profile' in result.stderr,result.stdout+result.stderr
        print('Apple complete candidate controller: final detached append authority control rejected')
        host.write_text('import Foundation\n'+controller)
        needle='if model.iosCandidateTesting { return "Testing" }'
        assert boundary.count(needle)==1
        fixture.write_text(boundary.replace(needle, '')+TEST)
        subprocess.run(command,check=True,timeout=90,capture_output=True)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
        assert result.returncode!=0 and 'temporary purpose presented ordinary Connected or Connect' in result.stderr,result.stdout+result.stderr
        print('Apple complete candidate controller: primary Home Testing label control rejected')
        fixture.write_text(boundary+TEST)
        needle='task = Task { @MainActor [self, model] in'
        assert controller.count(needle)==1
        host.write_text('import Foundation\n'+controller.replace(needle,'task = Task { @MainActor [weak self, weak model] in\n            guard let self, let model else { return }'))
        subprocess.run(command,check=True,timeout=90,capture_output=True)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
        assert result.returncode!=0 and 'view release abandoned the reserved cleanup task' in result.stderr,result.stdout+result.stderr
        print('Apple complete candidate controller: view lifetime cleanup control rejected')


if __name__=='__main__':main()
