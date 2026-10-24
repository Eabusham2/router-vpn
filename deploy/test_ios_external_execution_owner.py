#!/usr/bin/env python3
"""Run shipping external proof delivery, receipts and checked native teardown.

The generated native request, proof-result validator and OS handles are explicit
boundary doubles. The companion external-policy gate executes the real Swift
builder/validator and Go compiler; shared Go tests exercise routed TLS/leases.
This gate tests cancellation, stale completion, health expiry and teardown order.
"""
from pathlib import Path
import importlib.util
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
ENGINE = ROOT / 'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift'
spec = importlib.util.spec_from_file_location('apple_dns_boundary', ROOT / 'deploy/test_ios_dns_measurement.py')
DNS = importlib.util.module_from_spec(spec); spec.loader.exec_module(DNS)

BOUNDARIES = r'''
import Foundation
#if !canImport(ObjectiveC)
typealias NSErrorPointer = UnsafeMutablePointer<NSError?>?
#endif
enum FixtureFailure {static var error:NSError{NSError(domain:"ExternalOwnerBoundary",code:1)}}
final class Trace: @unchecked Sendable {
 static let shared=Trace();private let lock=NSLock();private var values:[String]=[]
 func add(_ text:String){lock.lock();values.append(text);lock.unlock()}
 func reset(){lock.lock();values=[];lock.unlock()}
 var events:[String]{lock.lock();defer{lock.unlock()};return values}
}
final class ResultBox: @unchecked Sendable {
 let done=DispatchSemaphore(value:0);private let lock=NSLock();private var errors:[Bool]=[]
 func finish(_ error:Error?){lock.lock();errors.append(error != nil);lock.unlock();done.signal()}
 var results:[Bool]{lock.lock();defer{lock.unlock()};return errors}
}
final class CheckCount: @unchecked Sendable {
 private let lock=NSLock();private var total=0
 func add(){lock.lock();total+=1;lock.unlock()}
 var value:Int{lock.lock();defer{lock.unlock()};return total}
}
final class LibboxRouterExternalProofRequest: @unchecked Sendable {
 private let lock=NSLock();private var cancelled=false,succeeded=false,expired=false
 let entered=DispatchSemaphore(value:0),release=DispatchSemaphore(value:0),finished=DispatchSemaphore(value:0)
 var hold=false,lateSuccess=false,failProof=false,failClose=false
 var winner="server",source="",capture="",session=""
 func run(_ failure:NSErrorPointer)->String{
  do{return try runCaptured()}catch{failure?.pointee=error as NSError;return ""}
 }
 private func runCaptured()throws->String{
  defer{finished.signal()};entered.signal();if hold{guard release.wait(timeout:.now()+5) == .success else{throw FixtureFailure.error}}
  lock.lock();let stopped=cancelled;succeeded = !failProof;lock.unlock()
  if failProof || (stopped && !lateSuccess){throw FixtureFailure.error}
  return String(decoding:try JSONSerialization.data(withJSONObject:["session":session,"proved":true]),as:UTF8.self)
 }
 func cancel(){lock.lock();cancelled=true;succeeded=false;lock.unlock();Trace.shared.add("proof-cancel");release.signal()}
 func close()throws{cancel();Trace.shared.add("lease-close");if failClose{throw FixtureFailure.error}}
 func healthy()->Bool{lock.lock();defer{lock.unlock()};return !cancelled && succeeded && !expired}
 func execution()->String{healthy() ? winner:""}
 func progressJSON()->String{"{\"stage\":\"selected\",\"execution\":\""+winner+"\",\"complete\":true}"}
 func expire(){lock.lock();expired=true;lock.unlock()}
}
final class LibboxCommandServer {
 let request=LibboxRouterExternalProofRequest();var closed=false,released=false,failClose=false
 func closeService()throws{closed=true;Trace.shared.add("box-close")}
 func close(){released=true;Trace.shared.add("box-release")}
}
final class LibboxRouterMultihop {func healthy()->Bool{true};func progressJSON()->String{"{}"};func close()throws{}}
final class LibboxRouterHopMeasurement {func close()throws{Trace.shared.add("hop-close")}}
func LibboxRouterExternalCreateProof(_ server:LibboxCommandServer,_ source:String,_ capture:String,_ session:String,_ error:inout NSError?)->LibboxRouterExternalProofRequest? {
 server.request.source=source;server.request.capture=capture;server.request.session=session;return server.request
}
func LibboxRouterExternalCreateHopMeasurement(_ server:LibboxCommandServer,_ request:LibboxRouterExternalProofRequest,_ source:String,_ capture:String,_ session:String,_ error:inout NSError?)->LibboxRouterHopMeasurement? {
 guard request.healthy(),request.source==source,request.capture==capture,request.session==session else{error=FixtureFailure.error;return nil}
 Trace.shared.add("hop-adopt");return LibboxRouterHopMeasurement()
}
func LibboxRouterExternalCreateDNSMeasurement(_ server:LibboxCommandServer,_ request:LibboxRouterExternalProofRequest,_ source:String,_ capture:String,_ session:String,_ error:inout NSError?)->LibboxRouterDNSMeasurement? {
 guard request.healthy(),request.source==source,request.capture==capture,request.session==session else{error=FixtureFailure.error;return nil}
 return LibboxRouterDNSMeasurement(node:"exit",session:session)
}
func LibboxRouterInvalidatePerformance(_ server:LibboxCommandServer){Trace.shared.add("invalidate")}
func LibboxRouterStrategyCloseService(_ server:LibboxCommandServer,_ error:inout NSError?)->Bool {
 Trace.shared.add("box-close");server.closed=true;if server.failClose{error=FixtureFailure.error;return false};return true
}
struct RouterVPNExternalPolicy: Sendable {
 let sourceConfig:String,capture:String,executionRequested:String?
 func validateProof(_ result:String,sessionID:String,began:Date)throws {
  guard let object=try JSONSerialization.jsonObject(with:Data(result.utf8)) as? [String:Any],object["session"] as? String==sessionID,object["proved"] as? Bool==true else{throw FixtureFailure.error}
 }
}
final class MTUBoundary {
 var hasOwner=false
 func stopChecked()throws{Trace.shared.add("mtu-close");hasOwner=false}
 func stop(){hasOwner=false}
 func activateExternal(server:LibboxCommandServer,proof:LibboxRouterExternalProofRequest,source:String,capture:String,failure:@escaping(String)->Void)throws {
  guard proof.healthy(),proof.source==source,proof.capture==capture else{throw FixtureFailure.error};hasOwner=true;Trace.shared.add("mtu-adopt")
 }
}
final class RouterVPNLibboxPlatform {let mtu=MTUBoundary();func reset(){Trace.shared.add("platform-reset")}}
final class PacketTunnelProvider {
 let failure=DispatchSemaphore(value:0)
 func nativeLibboxFailure(_ engine:RouterVPNLibboxEngine,error:Error){Trace.shared.add("expired-owner");failure.signal()}
 func writeLibboxLog(_ message:String){}
}
'''

FIXTURE = r'''
    private final class RetiredHopMeasurements: @unchecked Sendable {func retain(_ probe:LibboxRouterHopMeasurement,session:String){}}
    private final class TorProofDelivery {func cancel(){};func makeHopMeasurement(exitID:String)throws->LibboxRouterHopMeasurement{throw FixtureFailure.error}}
    init(tunnel:PacketTunnelProvider,server:LibboxCommandServer,policy:RouterVPNExternalPolicy){
        self.tunnel=tunnel;self.server=server;self.externalPolicy=policy;self.platform=RouterVPNLibboxPlatform();self.settingsEpoch=UUID().uuidString;self.strategyOwned=false
    }
    private func error(_ text:String)->NSError{NSError(domain:"ExternalOwnerFixture",code:1,userInfo:[NSLocalizedDescriptionKey:text])}
    func fixtureStop()->Error?{stopGeneration(nil)}
    func fixtureRetirementBlocked()->Bool{do{try Self.externalRetirement.requireAvailable();return false}catch{return true}}
    private var previous:ExternalProofDelivery?
    func fixtureReplace(_ replacement:LibboxCommandServer){ownershipLock.lock();previous=externalProofDelivery;externalProofDelivery=nil;server=replacement;ownershipGeneration=UUID();ownershipLock.unlock()}
    func fixtureClosePrevious()throws{try previous?.close()}
}
@main struct Tests {
 static let checks=CheckCount()
 static func check(_ label:String,_ valid:@autoclosure()->Bool){guard valid()else{fatalError("FAIL: "+label)};checks.add()}
 static func reject(_ label:String,_ action:()throws->Void){do{try action();fatalError("ACCEPTED: "+label)}catch{checks.add()}}
 static func json(_ value:Any)throws->String{String(decoding:try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys]),as:UTF8.self)}
 static func capture(_ requested:String="auto",_ entryID:String="entry",_ kind:String="shadowsocks")throws->(IOSMultihopExecution.Source,RouterVPNExternalPolicy){
  var external:[String:Any]=["protocol":kind,"response_probe":["url":"https://198.51.100.8/response"]]
  if ["wireguard","amneziawg"].contains(kind){external["server_peer"]=["public_key":"bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg=","addresses":["10.94.0.3/32","fd94::3/128"],"mtu":1360,"persistent_keepalive_interval":25]}
  let exit:[String:Any]=["id":"exit","node_kind":"external","external":external,"multihop_enabled":true,"multihop_entry_id":entryID,"multihop_exit_id":"exit","multihop_entry_mode":"max-tls-awg","multihop_exit_mode":kind,"multihop_execution":requested]
  let entry:[String:Any]=["id":entryID,"node_kind":"router-vpn"]
  let config:[String:Any]=["engine":"external-libbox","mode":"external-"+kind,"bundle":Data(try json(["selectedRouterID":"exit","routerProfiles":[exit]]).utf8),"external_entry_bundle":Data(try json(["selectedRouterID":entryID,"routerProfiles":[entry]]).utf8),"external_entry_mode":"max-tls-awg"]
  let source=try IOSMultihopExecution.Source(configuration:config){_ in String(repeating:"a",count:64)}
  let policy=RouterVPNExternalPolicy(sourceConfig:"exact compiled graph",capture:try json(["exit_id":"exit","profile":exit,"entry":entry]),executionRequested:requested)
  return(source,policy)
 }
 static func prove(_ engine:RouterVPNLibboxEngine,_ result:ResultBox){engine.proveExternal{result.finish($0)}}
 static func wait(_ event:DispatchSemaphore,_ label:String){check(label,event.wait(timeout:.now()+5) == .success)}
 static func main()throws {
  let request=String(repeating:"d",count:32),sourceAndPolicy=try capture(),source=sourceAndPolicy.0,policy=sourceAndPolicy.1
  for kind in ["shadowsocks","wireguard","amneziawg"] { for winner in ["local","server"] {
   let (source,policy)=try capture("auto","entry",kind)
   Trace.shared.reset();let tunnel=PacketTunnelProvider(),native=LibboxCommandServer(),result=ResultBox()
   native.request.winner=winner
   let engine=RouterVPNLibboxEngine(tunnel:tunnel,server:native,policy:policy)
   check("no proof cannot grant a receipt",engine.multihopExecutionSnapshot(request:request)==nil)
   reject("unproved source cannot bind"){try engine.bindExternalExecutionSource(source)}
   prove(engine,result);wait(result.done,"shared native proof delivered")
   check("proof completes exactly once",result.results==[false])
   reject("receipt requires adopted hop and MTU owners"){try engine.bindExternalExecutionSource(source)}
   try engine.enableExternalHopMeasurement(exitID:"exit")
   reject("hop-only adoption cannot grant restoration"){try engine.bindExternalExecutionSource(source)}
   try engine.activateExternalMTU()
   let other=try capture("auto","other-entry",kind).0
   reject("wrong captured role cannot bind"){try engine.bindExternalExecutionSource(other)}
   try engine.bindExternalExecutionSource(source)
   guard let bytes=engine.multihopExecutionSnapshot(request:request)else{fatalError("missing proved receipt")}
   let receipt=try IOSMultihopExecution.Capture.decode(bytes,source:source,request:request)
   check("receipt carries only actual healthy winner",receipt.execution==winner && receipt.sessionID==engine.settingsEpoch)
   check("same proof supplies measurement and MTU capture",native.request.source==policy.sourceConfig && native.request.capture==policy.capture)
   check("progress is supplied by actual proof owner",engine.multihopProgress() != nil)
   check("invalid IPC request cannot grant receipt",engine.multihopExecutionSnapshot(request:"foreign")==nil)
   reject("source can only bind once"){try engine.bindExternalExecutionSource(source)}
   check("checked stop succeeds",engine.fixtureStop()==nil)
   let events=Trace.shared.events
   check("lease release precedes native Box close",events.firstIndex(of:"lease-close")! < events.firstIndex(of:"box-close")!)
   check("native resources close after lease confirmation",native.closed && native.released && events.contains("platform-reset"))
   check("stopped proof cannot grant stale receipt",engine.multihopExecutionSnapshot(request:request)==nil && engine.multihopProgress()==nil)
   check("old proof cannot recreate hop or MTU owner after stop",result.results==[false])
  }}
  for late in [false,true] {
   Trace.shared.reset();let tunnel=PacketTunnelProvider(),native=LibboxCommandServer(),result=ResultBox()
   native.request.hold=true;native.request.lateSuccess=late
   let engine=RouterVPNLibboxEngine(tunnel:tunnel,server:native,policy:policy)
   prove(engine,result);wait(native.request.entered,"native request entered before cancel")
   check("cancelled native stop checked",engine.fixtureStop()==nil)
   wait(result.done,"cancel delivers failure");wait(native.request.finished,"late run is drained")
   check("cancel consumes callback once",result.results==[true])
   check("late native success cannot produce receipt",engine.multihopExecutionSnapshot(request:request)==nil)
  }
  do {
   let tunnel=PacketTunnelProvider(),old=LibboxCommandServer(),replacement=LibboxCommandServer(),result=ResultBox();old.request.hold=true
   let engine=RouterVPNLibboxEngine(tunnel:tunnel,server:old,policy:policy)
   prove(engine,result);wait(old.request.entered,"captured proof entered")
   engine.fixtureReplace(replacement);old.request.release.signal();wait(result.done,"stale delivery rejected")
   try engine.fixtureClosePrevious()
   check("stale cleanup cannot close replacement runtime",result.results==[true] && !replacement.closed && !replacement.released)
   check("stale source cannot bind to new runtime",engine.multihopExecutionSnapshot(request:request)==nil)
   _=engine.fixtureStop()
  }
  do {
   let tunnel=PacketTunnelProvider(),native=LibboxCommandServer(),result=ResultBox(),engine=RouterVPNLibboxEngine(tunnel:tunnel,server:LibboxCommandServer(),policy:policy)
   _=engine.fixtureStop()
   let current=RouterVPNLibboxEngine(tunnel:tunnel,server:native,policy:policy)
   prove(current,result);wait(result.done,"proved owner before health expiry")
   try current.enableExternalHopMeasurement(exitID:"exit");try current.activateExternalMTU();try current.bindExternalExecutionSource(source)
   native.request.expire()
   check("expired native lease cannot grant receipt",current.multihopExecutionSnapshot(request:request)==nil)
   wait(tunnel.failure,"health timer reports exact expired owner")
   _=current.fixtureStop()
  }
  for failed in ["lease","box"] {
   Trace.shared.reset();let tunnel=PacketTunnelProvider(),native=LibboxCommandServer(),result=ResultBox()
   let engine=RouterVPNLibboxEngine(tunnel:tunnel,server:native,policy:policy)
   prove(engine,result);wait(result.done,"proof before close failure")
   native.request.failClose=failed=="lease";native.failClose=failed=="box"
   check("unconfirmed close reports failure",engine.fixtureStop() != nil)
   check("failed cleanup keeps native retirement owners",engine.fixtureRetirementBlocked() && !native.released && !Trace.shared.events.contains("platform-reset"))
   check("failed stop remains failed on repeat",engine.fixtureStop() != nil)
   let events=Trace.shared.events
   check("checked lease close attempted before Box shutdown even on failure",events.firstIndex(of:"lease-close")! < events.firstIndex(of:"box-close")!)
  }
  print("Apple external execution owner: PASS (\(checks.value) shipping Swift delivery/receipt/teardown checks; native/OS boundaries doubled)")
 }
}
'''


def shipping():
    source = ENGINE.read_text()
    fields = source[source.index('final class RouterVPNLibboxEngine {'):source.index('    init(tunnel:')]
    stop = source[source.index('    func stopCheckedForStrategy()'):source.index('    /// DNS and both node identities')]
    proof = source[source.index('    func proveExternal('):source.index('    private func prepareTorState(')]
    retirement = source[source.index('    private final class NativeRuntimeRetirement:'):source.index('    func proveStrategyDNS(')]
    mtu = source[source.index('    func activateExternalMTU('):source.index('    func activateTorMTU(')]
    # Keep the complete nested delivery; its first method is not a boundary.
    start = source.index('    private final class MTUFailureDelivery:')
    end = source.index('\n    func ', source.index('\n    }', start))
    failure = source[start:end]
    hops = source[source.index('    func enableExternalHopMeasurement('):source.index('    func hopMeasurementRequest(')]
    receipts = source[source.index('    func multihopProgress('):source.index('    func invalidateMultihop(')]
    return fields + stop + proof + retirement + mtu + failure + hops + receipts + FIXTURE


def main():
    with tempfile.TemporaryDirectory(prefix='ios-external-owner-') as directory:
        work = Path(directory); code = work / 'Owner.swift'
        dns_session = (ROOT / 'ios/RouterVPN/PacketTunnel/RouterVPNDNSMeasurementSession.swift').read_text().replace('import Libbox\n', '')
        code.write_text(BOUNDARIES + DNS.NATIVE + DNS.STORAGE + dns_session + (APP / 'IOSMultihopExecution.swift').read_text() + shipping())
        binary = work / 'test'
        subprocess.run(['swiftc', '-swift-version', '6', '-parse-as-library', '-module-cache-path', str(work / 'module-cache'), str(code), '-o', str(binary)], check=True, timeout=90)
        subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == '__main__':
    main()
