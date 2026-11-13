#!/usr/bin/env python3
"""Run the complete shipping prefix launch/binding with an explicit NE boundary."""
from pathlib import Path
import subprocess,tempfile
from test_ios_startup_policy import member
ROOT=Path(__file__).resolve().parents[1];APP=ROOT/'ios/RouterVPN/App'
BOUNDARY=r'''
import Foundation
struct ClientBundle:Codable{let endpoint="198.51.100.1"}
@MainActor final class NETunnelProviderProtocol {
 var providerBundleIdentifier:String?,serverAddress:String?,providerConfiguration:[String:Any]?
 var includeAllNetworks=false,enforceRoutes=false,excludeLocalNetworks=false,excludeAPNs=false,excludeCellularServices=false
}
@MainActor final class NETunnelProviderSession {
 enum Status{case connected,connecting,disconnected,disconnecting,reasserting,invalid}
 var status:Status = .disconnected,connectedDate:Date?
 func startVPNTunnel(options:[String:NSObject]?)throws{
  Fixture.starts+=1;Fixture.launchedWithoutHold=(options?["routervpn_mtu_hold"] as? String)?.isEmpty != false
  status = .connected;connectedDate=Date()
  if Fixture.fault=="after-start"{Fixture.current=false}
 }
}
@MainActor final class NETunnelProviderManager {
 var connection=NETunnelProviderSession(),protocolConfiguration:Any?,localizedDescription:String?
 var isOnDemandEnabled=false,isEnabled=false,onDemandRules:[String]?
 static func loadAllFromPreferences()async throws->[NETunnelProviderManager]{await Task.yield();Fixture.loads+=1;if Fixture.fault=="load-all"{Fixture.current=false};return Fixture.managers}
 func saveToPreferences()async throws{await Task.yield();Fixture.saves+=1;if Fixture.fault=="save"{Fixture.current=false}}
 func loadFromPreferences()async throws{
  await Task.yield();Fixture.readbacks+=1
  guard let p=protocolConfiguration as? NETunnelProviderProtocol else{return}
  switch Fixture.fault {
  case "load":Fixture.current=false
  case "source":p.providerConfiguration?["candidatePrefixSource"]="replacement"
  case "purpose":p.providerConfiguration?["routervpn_speed_lab_owner"]=UUID().uuidString
  case "epoch":p.providerConfiguration?["candidatePrefixEpoch"]=UUID().uuidString
  case "strict":p.includeAllNetworks=false
  case "routes":p.enforceRoutes=false
  case "lan":p.excludeLocalNetworks=true
  case "apns":p.excludeAPNs=true
  case "cellular":p.excludeCellularServices=true
  case "reconnect":isOnDemandEnabled=true
  case "rules":onDemandRules=["Connect"]
  case "disabled":isEnabled=false
  default:break
  }
 }
}
struct IOSNodeCandidatePrefixCapture {
 struct Metadata{let prefixes=[1,2]};let metadata=Metadata(),strict=true,homeLANAccess=false
}
enum IOSNodeCandidatePrefixProviderCapture {
 static let key="candidatePrefixSource",engine="candidate-prefix-libbox"
 static func configuration(capture:IOSNodeCandidatePrefixCapture,bundle:Data,owner:UUID,epoch:UUID,request:String)throws->[String:Any]{["engine":engine,"bundle":bundle,"candidatePrefixSource":"original-prefix","candidateOriginalSource":"complete-save-provenance","routervpn_speed_lab_owner":owner.uuidString,"candidatePrefixEpoch":epoch.uuidString,"candidatePrefixRequest":request]}
}
@MainActor final class RouterVPNModel {
 let iosSpeedLabOwnership=IOSSpeedLabOwnership()
 var iosConnectGeneration=UUID(),connected=false,tunnelTransitioning=false,iosUserDisconnectInProgress=false
 var activeSessionIdentity:String?,activeEngine="none",activeRawProfile="",routerName="Original",message=""
 var userDisconnectInProgress:Bool{iosUserDisconnectInProgress};var iosStrategyStatus:String?
 static func iosStrategyDigest(_ data:Data)->String{"digest"}
 func iosAdoptStrategyStatus(_ status:String,manager:NETunnelProviderManager,bundleData:Data)throws{throw CancellationError()}
 // SHIPPING_REFRESH
}
enum IOSRuntimeSelectionError:Error{case unsupportedMode(String)}
@MainActor enum IOSStrategyWire {
 static func failure(_ value:String)->Error{CancellationError()}
 static func catalog(_ source:[String:Any])throws->String{throw CancellationError()}
 static func status(_ reply:Data,bundleDigest:String,catalog:String)throws->String{throw CancellationError()}
}
@MainActor enum IOSStrategyTransport{static func send(_ session:NETunnelProviderSession,request:[String:String])async throws->Data{throw CancellationError()}}
typealias IOSSessionIdentity=String
extension String {init(connectedAt:Date,engine:String,rawProfile:String,bundleData:Data,configuration:[String:Any])throws{self="ordinary-proved-session"}}
@MainActor enum Fixture {
 static var fault="",current=true,starts=0,saves=0,loads=0,readbacks=0,launchedWithoutHold=false
 static var managers:[NETunnelProviderManager]=[]
 static func reset(_ mode:String){fault=mode;current=true;starts=0;saves=0;loads=0;readbacks=0;launchedWithoutHold=false;managers=[]}
}
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ value:Bool,_ text:String)throws{checks+=1;guard value else{throw NSError(domain:"LaunchCheck",code:1,userInfo:[NSLocalizedDescriptionKey:text])}}
 static func run(_ fault:String)async throws{
  Fixture.reset(fault);let model=RouterVPNModel(),owner=UUID(),epoch=UUID()
  _ = try model.iosSpeedLabOwnership.begin(owner:owner){}
  let hold=IOSMTUMeasurementGate.acquire();defer{_ = IOSMTUMeasurementGate.release(hold);model.iosSpeedLabOwnership.finish(owner)}
  if fault=="missing-hold"{_ = IOSMTUMeasurementGate.release(hold)}
  if ["multiple","busy","initial-reconnect"].contains(fault){
   let manager=NETunnelProviderManager(),proto=NETunnelProviderProtocol();proto.providerBundleIdentifier="com.eabusham.routervpn.PacketTunnel";manager.protocolConfiguration=proto
   if fault=="busy"{manager.connection.status = .connected};if fault=="initial-reconnect"{manager.isOnDemandEnabled=true}
   Fixture.managers=fault=="multiple" ? [manager,manager]:[manager]
  }
  var binding:IOSNodeCandidatePrefixBinding?,failure:Error?
  do{binding=try await IOSSpeedLabContext.$owner.withValue(fault=="wrong-owner" ? UUID():owner){
   try await model.connectCandidatePrefix(IOSNodeCandidatePrefixCapture(),bundle:ClientBundle(),owner:owner,epoch:epoch,request:String(repeating:"a",count:32)){
    guard Fixture.current else{throw CancellationError()}
   }
  }}catch{failure=error}
  if fault=="none"{
   try check(failure==nil && binding != nil && Fixture.starts==1 && !Fixture.launchedWithoutHold,"exact prefix launch failed")
   try check(!model.connected && model.activeSessionIdentity==nil && !model.tunnelTransitioning && model.activeEngine=="candidate-prefix-libbox","prefix launch claimed ordinary connection")
   guard let binding else{throw CancellationError()};try binding.require(model)
   Fixture.managers=[binding.manager]
   await model.refreshTunnelStatus()
   try check(!model.connected && model.activeSessionIdentity==nil && !model.tunnelTransitioning,"prepared prefix status became ordinary Connected")
   for change in ["generation","connected","source","date","apns","owner"]{
    let generation=model.iosConnectGeneration,date=binding.connection.connectedDate
    let proto=binding.manager.protocolConfiguration as! NETunnelProviderProtocol,config=proto.providerConfiguration!
    if change=="generation"{model.iosConnectGeneration=UUID()}else if change=="connected"{model.connected=true}else if change=="source"{proto.providerConfiguration?["candidatePrefixSource"]="foreign"}else if change=="date"{binding.connection.connectedDate=Date.distantPast}else if change=="apns"{proto.excludeAPNs=true}else{model.iosSpeedLabOwnership.finish(owner)}
    var rejected=false;do{try binding.require(model)}catch{rejected=true}
    try check(rejected,"prefix binding accepted changed "+change)
    model.iosConnectGeneration=generation;model.connected=false;proto.providerConfiguration=config;binding.connection.connectedDate=date;proto.excludeAPNs=false
   }
   await model.refreshTunnelStatus()
   try check(!model.connected && model.activeSessionIdentity==nil && model.tunnelTransitioning,"orphaned prefix was not held for explicit cleanup")
   let proto=binding.manager.protocolConfiguration as! NETunnelProviderProtocol
   proto.providerConfiguration?.removeValue(forKey:"candidatePrefixSource");proto.providerConfiguration?["engine"]="multihop-libbox"
   await model.refreshTunnelStatus()
   try check(model.connected && model.activeSessionIdentity != nil,"ordinary session status was disabled by prefix handling")
  }else{
   try check(failure != nil && binding==nil,"stale prefix launch returned binding: "+fault)
   if fault != "after-start"{try check(Fixture.starts==0,"stale prefix source reached native Start: "+fault)}
   try check(!model.connected && model.activeSessionIdentity==nil,"failed prefix launch created ordinary identity")
   if fault=="missing-hold" || fault=="wrong-owner"{try check(Fixture.loads==0 && Fixture.saves==0,"permission work started without immutable purpose and MTU hold")}
  }
 }
 static func main()async{do{for fault in ["none","load-all","save","load","source","purpose","epoch","strict","routes","lan","apns","cellular","reconnect","rules","disabled","multiple","busy","initial-reconnect","missing-hold","wrong-owner","after-start"]{try await run(fault)};print("Apple independent prefix launch: \(checks) actual preference/binding checks PASS")}catch{FileHandle.standardError.write(Data(("FAIL after \(checks): \(error.localizedDescription)\n").utf8));exit(1)}}
}
'''

def main():
    refresh=member((APP/'RouterVPNModel.swift').read_text(),'    func refreshTunnelStatus() async {')
    fixture_source=BOUNDARY.replace(' // SHIPPING_REFRESH',refresh)
    original=(APP/'IOSNodeCandidatePrefixTunnel.swift').read_text().replace('@preconcurrency import NetworkExtension','// Explicit NetworkExtension boundary in this portable fixture.')
    with tempfile.TemporaryDirectory(prefix='ios-prefix-launch-') as folder:
        work=Path(folder);source=work/'Launch.swift';fixture=work/'Test.swift';fixture.write_text(fixture_source);binary=work/'test'
        command=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules'),str(APP/'IOSSpeedLabOwnership.swift'),str(APP/'IOSMTUMeasurementGate.swift'),str(source),str(fixture),'-o',str(binary)]
        def exercise(code,witness=None):
            source.write_text(code);subprocess.run(command,check=True,timeout=90)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
            if witness:
                assert result.returncode!=0 and witness in result.stdout+result.stderr,(witness,result.stdout+result.stderr);print('Rejected prefix launch defect: '+witness,flush=True)
            else:assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip(),flush=True)
        exercise(original)
        for before,after,count,witness in [
            ('try current(); try iosSpeedLabOwnership.require(owner)','try iosSpeedLabOwnership.require(owner)',2,'stale prefix source reached native Start: load-all'),
            ('NSDictionary(dictionary: source).isEqual(to: config)','true',1,'stale prefix source reached native Start: source'),
            ('!actual.excludeAPNs, !actual.excludeCellularServices, manager.isEnabled,','true, !actual.excludeCellularServices, manager.isEnabled,',1,'stale prefix source reached native Start: apns'),
            ('!model.connected, !model.tunnelTransitioning, model.activeSessionIdentity == nil,','true, !model.tunnelTransitioning, model.activeSessionIdentity == nil,',1,'prefix binding accepted changed connected'),
            ('!IOSMTUMeasurementGate.current.isEmpty else','true else',1,'permission work started without immutable purpose and MTU hold'),
        ]:
            assert original.count(before)==count,before
            mutated=original.replace(before,after);assert mutated!=original;exercise(mutated,witness)
        needle='connected = false; activeEngine = IOSNodeCandidatePrefixProviderCapture.engine; activeRawProfile = ""'
        assert fixture_source.count(needle)==1
        fixture.write_text(fixture_source.replace(needle,'activeEngine = IOSNodeCandidatePrefixProviderCapture.engine; activeRawProfile = ""'))
        exercise(original,'prepared prefix status became ordinary Connected')
if __name__=='__main__':main()
