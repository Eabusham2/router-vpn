#!/usr/bin/env python3
"""Execute the shipping temporary candidate owner, with explicit OS/store boundaries.

Real candidate parsing/50-sample IPC and SDK compilation remain independent
mandatory gates. These controlled native completions prove the app's lease,
source, purpose and post-DOWN Save admission without claiming a device VPN.
"""
from pathlib import Path
import subprocess
import tempfile
from test_ios_startup_policy import member
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
SWIFT = r'''
import Foundation
// Each executable case gets actual Foundation defaults in its own namespace;
// a previous successful ordinary Last write cannot mask the temporary-write control.
@MainActor enum UserDefaults {
 static let standard = Foundation.UserDefaults(suiteName: "RouterVPN.CandidatePreparation.Test." + UUID().uuidString)!
}
struct Failure:Error {let message:String}
@MainActor var checks=0
@MainActor func check(_ yes:Bool,_ text:String)throws{checks+=1;if !yes{throw Failure(message:text)}}
@MainActor func refuses(_ text:String,_ action:()throws->Void)throws{do{try action();throw Failure(message:"ACCEPTED "+text)}catch let error as Failure{throw error}catch{}}
@MainActor func until(_ condition:()->Bool)async throws{let end=ProcessInfo.processInfo.systemUptime+3;while !condition(){guard ProcessInfo.processInfo.systemUptime<end else{throw Failure(message:"owned callback never arrived")};await Task.yield()}}
struct Profile:Codable {var normalizedNodeKind:String{"router-vpn"};var id="final";var multihopNodes:[String]?=["entry","final"];var multihopExecution:String?="local"}
struct ClientBundle:Codable {var selectedRouterID="final";var routerProfiles=[Profile()]}
@MainActor enum IOSNodeUsage {static func canonical<T:Encodable>(_ value:T)throws->Data{let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys];return try encoder.encode(value)}}
@MainActor enum IOSDNSRuntimePolicy {static func selectedProfile(in bundle:ClientBundle)->Profile?{bundle.routerProfiles.first}}
enum IOSCandidateCatalogPublication {struct Stamp:Equatable {let generation:Int}}
@MainActor final class IOSNodeBundleStore {
 static let shared=IOSNodeBundleStore();var records=["source":Data("original".utf8)];var stamp=IOSCandidateCatalogPublication.Stamp(generation:1)
 func candidateSnapshot()throws->(records:[String:Data],stamp:IOSCandidateCatalogPublication.Stamp){(records,stamp)}
}
@MainActor final class IOSViaEntryNetwork {
 static let shared=IOSViaEntryNetwork();var current:UInt64?=1
 func snapshot()async throws->UInt64{guard let current else{throw CancellationError()};return current}
}
struct IOSNodeCandidatePrefix:Equatable {let position:Int;let profile_id:String;let node_id:String;let mode:String}
@MainActor struct IOSNodeChainCapture {
 struct Member {let id:String;let mode:String;let profile:[String:Any]}
 final class Plan {func close()throws{}}
 let plan=Plan();let launchInput="original-complete-local-input",sourceSHA256="source",configSHA256="config"
 let members=[Member(id:"entry",mode:"wg",profile:["node_proof_id":"original-first"]),Member(id:"final",mode:"shadowsocks",profile:["node_proof_id":"original-final"])]
 static func reopen(_ source:String,selectedProfile:[String:Any])throws->Self{guard source=="original-complete-local-input",selectedProfile["id"] as? String=="final" else{throw CancellationError()};return Self()}
}
@MainActor enum IOSRuntimeSelector {static func selectNodeChain(_ capture:IOSNodeChainCapture)throws->Bool{true}}
@MainActor final class IOSNodeCandidateTransaction {
 var entered=false,joined=false
 func close()async{entered=true;while !joined{await Task.yield()}}
}
struct IOSLastRuntime:Codable {let routerID:String;let rawProfileID:String;let logicalModeID:String}
struct Identity {let engine="multihop-libbox";let nodeChainSource:Data?}
@MainActor final class RouterVPNModel {
 struct Change {func send(){}}
 let objectWillChange=Change(),iosSpeedLabOwnership=IOSSpeedLabOwnership()
 var connected=false,tunnelTransitioning=false,iosUserDisconnectInProgress=false
 var bundle:ClientBundle?=ClientBundle(),activeSessionIdentity:Identity?
 var activeRawProfile="shadowsocks";var iosStrategyProfile:Profile?{bundle?.routerProfiles.first}
 // SHIPPING_LAST_WRITER
 var iosConnectGeneration=UUID(),selectedMode="wg",selectedLogicalMode="base-raw",auto=true
 var basePreference="wg",baseFallback=false,homeLANAccess=true,homeLANCIDRs:[String]=[],daita=false,jumbo=false
 var routerName="original",endpoint="192.0.2.1",routerAPI="https://192.0.2.1",apiToken="private-original"
 var socksHost="192.0.2.1",socksPort="1080",socksUsername="",socksPassword="",message=""
 func captureIOSNodeChain(_ bundle:ClientBundle)throws->IOSNodeChainCapture{IOSNodeChainCapture()}
 func refreshTunnelStatus()async{}
 func connectCandidatePreparation(_ capture:IOSNodeChainCapture,bundle:ClientBundle,current:@escaping @MainActor @Sendable ()throws->Void)async throws{
  try current();try check(IOSSpeedLabContext.owner != nil && IOSMTUMeasurementGate.held,"purpose or MTU missing before native launch")
  iosConnectGeneration=UUID();connected=true;activeSessionIdentity=Identity(nodeChainSource:Data(capture.launchInput.utf8));try current()
 }
}
@MainActor final class IOSSpeedLabTunnel {
 static var stopEntered=false,allowStop=false,restoreEntered=false,allowRestore=false
 let identity:Identity?=nil
 static func capture(model:RouterVPNModel,owner:UUID)async throws->IOSSpeedLabTunnel{try model.iosSpeedLabOwnership.require(owner);return IOSSpeedLabTunnel()}
 static func stopTemporary(model:RouterVPNModel,owner:UUID)async throws{
  stopEntered=true;while !allowStop{await Task.yield()};model.connected=false;model.activeSessionIdentity=nil;model.iosConnectGeneration=UUID()
 }
 func restore(model:RouterVPNModel,owner:UUID,reconnect:Bool)async throws{
  try check(!reconnect,"temporary comparison reconnected original idle path");Self.restoreEntered=true;while !Self.allowRestore{await Task.yield()}
 }
 static func reset(){stopEntered=false;allowStop=false;restoreEntered=false;allowRestore=false}
}
@MainActor @main struct Test {
 static func fixture()throws->(RouterVPNModel,IOSNodeCandidatePreparation){
  IOSNodeBundleStore.shared.records=["source":Data("original".utf8)];IOSViaEntryNetwork.shared.current=1;IOSSpeedLabTunnel.reset()
  let model=RouterVPNModel();let preparation=try IOSNodeCandidatePreparation.reserve(model:model,onCancelled:{})
  return(model,preparation)
 }
 static func start(_ value:IOSNodeCandidatePreparation)async throws{try await IOSSpeedLabContext.$owner.withValue(value.owner){try await value.start()}}
 static func drain(_ value:IOSNodeCandidatePreparation)async{IOSSpeedLabTunnel.allowStop=true;IOSSpeedLabTunnel.allowRestore=true;await value.retire();value.closeResults()}
 static func main()async throws{
  let(model,value)=try fixture();try check(IOSNodeCandidatePreparation.busy && model.iosCandidateTesting && IOSMTUMeasurementGate.held,"purpose was not retained before permission")
  try refuses("overlapping temporary owner"){_ = try IOSNodeCandidatePreparation.reserve(model:RouterVPNModel(),onCancelled:{})}
  try await start(value)
  let lastBefore=UserDefaults.standard.data(forKey:"router-vpn.ios.last-runtime-v1")
  model.recordIOSLastRuntime()
  try check(UserDefaults.standard.data(forKey:"router-vpn.ios.last-runtime-v1")==lastBefore,"temporary candidate overwrote Last through UI callback")
  let candidate=IOSNodeCandidateTransaction();try value.bind(candidate)
  let token=UUID(),now=Int64(Date().timeIntervalSince1970*1000);try value.seal(token:token,measured:now,expires:now+120000)
  try refuses("Save before DOWN"){try value.requireSaved(token:token)}
  let inner=IOSMTUMeasurementGate.acquire();try check(!IOSMTUMeasurementGate.release(inner),"nested lease released original outer hold")
  let closing=Task{@MainActor in await value.retire()}
  try await until{candidate.entered || IOSSpeedLabTunnel.stopEntered}
  try check(candidate.entered && !IOSSpeedLabTunnel.stopEntered,"candidate close did not precede native graph stop")
  try check(IOSMTUMeasurementGate.held && IOSNodeCandidatePreparation.busy,"outer MTU lease released before candidate join")
  candidate.joined=true;try await until{IOSSpeedLabTunnel.stopEntered}
  try check(IOSMTUMeasurementGate.held && model.iosSpeedLabOwnership.active,"outer MTU lease released before native DOWN")
  try refuses("Save while native graph drains"){try value.requireSaved(token:token)}
  IOSSpeedLabTunnel.allowStop=true;try await until{IOSSpeedLabTunnel.restoreEntered}
  try check(!model.connected && IOSMTUMeasurementGate.held,"outer MTU lease released before original idle preferences restored")
  try refuses("Save before original idle restore"){try value.requireSaved(token:token)}
  IOSSpeedLabTunnel.allowRestore=true;await closing.value
  try check(value.retired && !model.connected && !IOSMTUMeasurementGate.held && !model.iosCandidateTesting && !model.iosSpeedLabOwnership.active,"joined DOWN did not retire exact purpose and hold")
  try value.requireSaved(token:token);try refuses("foreign result token"){try value.requireSaved(token:UUID())}
  let decision=model.iosConnectGeneration;model.iosConnectGeneration=UUID()
  try refuses("new Home decision"){try value.requireSaved(token:token)};model.iosConnectGeneration=decision
  IOSNodeBundleStore.shared.records["source"]=Data("changed".utf8)
  try refuses("changed saved source"){try value.requireSaved(token:token)}
  IOSNodeBundleStore.shared.records["source"]=Data("original".utf8)
  try refuses("source changed away and back"){try value.requireSaved(token:token)}
  value.closeResults();try check(IOSNodeCandidatePreparation.retained == nil,"closed result authority retained reservation")
  model.connected=true;model.recordIOSLastRuntime()
  let ordinaryLast=try JSONDecoder().decode(IOSLastRuntime.self,from:UserDefaults.standard.data(forKey:"router-vpn.ios.last-runtime-v1")!)
  try check(ordinaryLast.routerID=="final" && ordinaryLast.rawProfileID=="shadowsocks","ordinary connected runtime lost Last publication")
  model.connected=false
  for fault in ["selection","network","cancel","late-source"]{
   let(m,p)=try fixture();try await start(p)
   if fault=="selection"{m.endpoint="new"}else if fault=="network"{IOSViaEntryNetwork.shared.current=2}else if fault=="cancel"{p.cancel()}else{IOSNodeBundleStore.shared.records["source"]=Data("late".utf8)}
   try refuses("changed live "+fault){try p.requireLive()};await drain(p)
   try check(!IOSMTUMeasurementGate.held,"failed comparison leaked or released an unjoined hold")
  }
  let(_,expiry)=try fixture();try await start(expiry);let expiring=UUID(),soon=Int64(Date().timeIntervalSince1970*1000)+50
  try expiry.seal(token:expiring,measured:soon-120000,expires:soon);IOSSpeedLabTunnel.allowStop=true;IOSSpeedLabTunnel.allowRestore=true;await expiry.retire()
  try await until{Int64(Date().timeIntervalSince1970*1000)>=soon};try refuses("expired detached result"){try expiry.requireSaved(token:expiring)};expiry.closeResults()
  print("Apple actual candidate preparation owner: \(checks) purpose, source, MTU, joined DOWN and detached Save checks PASS")
 }
}
'''

# These are explicit, unreachable independent-prefix boundaries for the existing
# complete-saved gate. The prefix composition executes its own real branch.
PREFIX_BOUNDARY = r"""
@MainActor struct IOSNodeCandidatePrefixCapture {
 let native=IOSNodeChainCapture.Plan(),sourceSHA256="prefix-source",configSHA256="prefix-config",captureSHA256="prefix-capture"
 static func compile(original:IOSNodeChainCapture,position:Int,inventory:String)throws->Self{throw Failure(message:"unexpected prefix compiler in complete-saved gate")}
}
@MainActor struct IOSNodeCandidatePrefixBinding {
 let connection=NETunnelProviderSession()
 func require(_ model:RouterVPNModel)throws{throw Failure(message:"unexpected prefix binding in complete-saved gate")}
}
@MainActor extension RouterVPNModel {
 func connectCandidatePrefix(_ capture:IOSNodeCandidatePrefixCapture,bundle:ClientBundle,owner:UUID,epoch:UUID,request:String,current:@escaping @MainActor @Sendable ()throws->Void)async throws->IOSNodeCandidatePrefixBinding{throw Failure(message:"unexpected independent prefix launch in complete-saved gate")}
}
"""
OWNER_PREFIX_BOUNDARY = r"""
@MainActor final class NETunnelProviderSession{}
extension IOSCandidateCatalogPublication {
 struct Capture {struct Inventory{let data=Data("inventory".utf8)};let inventory=Inventory();let request="request"}
 @MainActor static let shared=Store()
 @MainActor final class Store {func remove(_ source:Capture)throws{};func acknowledgeClosed(epoch:String,request:String)throws{}}
}
@MainActor struct IOSNodeCandidateCapture {
 struct Row {let id:String;let name:String;let input:String}
 let source:IOSCandidateCatalogPublication.Capture,records:[String:Data],rows:[Row],prefix:IOSNodeCandidatePrefix,chainSource:String,chainConfig:String
 static func make(request:String,prefixPosition:Int,proofs:[IOSNodeCandidatePrefix],chainSource:String,chainConfig:String)throws->Self{throw Failure(message:"unexpected prefix publication in complete-saved gate")}
 func requireCurrent()throws{throw Failure(message:"unexpected prefix source in complete-saved gate")}
}
"""

def main():
    original = (APP / 'IOSNodeCandidatePreparation.swift').read_text()
    last_writer = member((APP / 'IOSStrategySupport.swift').read_text(), '    func recordIOSLastRuntime(')
    fixture = SWIFT.replace('// SHIPPING_LAST_WRITER', last_writer) + PREFIX_BOUNDARY + OWNER_PREFIX_BOUNDARY
    with tempfile.TemporaryDirectory(prefix='ios-candidate-preparation-') as directory:
        work = Path(directory); source = work / 'Preparation.swift'; test = work / 'Test.swift'
        source.write_text(original); test.write_text(fixture)
        binary = work / 'test'
        command = ['swiftc', '-j', '1', '-swift-version', '6', '-module-cache-path', str(work / 'modules'),
                   str(APP / 'IOSSpeedLabOwnership.swift'), str(APP / 'IOSMTUMeasurementGate.swift'),
                   str(source), str(test), '-o', str(binary)]
        subprocess.run(command, check=True, timeout=90)
        subprocess.run([str(binary)], check=True, timeout=30)
        controls = [
            ('if let candidate { await candidate.close() }', 'if false, let candidate { await candidate.close() }', 'candidate close did not precede native graph stop'),
            ('if retired { return }', 'if retired { return }; if let hold = outerHold { _ = IOSMTUMeasurementGate.release(hold) }', 'outer MTU lease released before candidate join'),
            ('model.iosConnectGeneration == decision,', 'true,', 'ACCEPTED new Home decision'),
            ('now.records == records,', 'true,', 'ACCEPTED changed saved source'),
            ('network == nil || IOSViaEntryNetwork.shared.current == network', 'true', 'ACCEPTED changed live network'),
            ('Int64(Date().timeIntervalSince1970 * 1000) < value.expires,\n              ProcessInfo.processInfo.systemUptime < value.deadline', 'true', 'ACCEPTED expired detached result'),
        ]
        for old,new,witness in controls:
            assert original.count(old) == 1, old
            changed = original.replace(old,new); assert changed != original
            source.write_text(changed)
            subprocess.run(command, check=True, timeout=90, capture_output=True)
            result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30)
            if result.returncode == 0 or witness not in result.stderr:
                raise AssertionError('Candidate preparation causal control missed: '+witness+'\n'+result.stdout+result.stderr)
            print('Apple candidate preparation causal control rejected:', witness)
        source.write_text(original)
        needle = '!iosSpeedLabOwnership.active, connected,'
        assert fixture.count(needle) == 1
        test.write_text(fixture.replace(needle, 'connected,'))
        subprocess.run(command, check=True, timeout=90, capture_output=True)
        result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30)
        assert result.returncode != 0 and 'temporary candidate overwrote Last through UI callback' in result.stderr, result.stdout + result.stderr
        print('Apple candidate preparation causal control rejected: temporary Last writer')


if __name__ == '__main__': main()
