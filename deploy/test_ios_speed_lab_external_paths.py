#!/usr/bin/env python3
"""Execute shipping Speed Lab orchestration for saved external/Tor graphs.

The app connection, persistence, MTU IPC and network transfer boundaries are
deterministic doubles. The runner, models, result types and session identity
are shipping source; this does not substitute for native/device traffic tests.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
FIXTURE = r'''
protocol ObservableObject {}
@propertyWrapper struct Published<T> { var wrappedValue:T }
enum Failure { static var error:NSError {NSError(domain:"SpeedLabFixture",code:1)} }
@MainActor enum Trace {
 static var values:[String]=[], failProof=false, failRestore=false, cancelOnStart=false
 static var measurementHook:(()->Void)?
 static var measurementDrain:(()async->Void)?,restoreHook:(()->Void)?
 static var delayedRetirement=false
 static func reset(){values=[];failProof=false;failRestore=false;cancelOnStart=false;measurementHook=nil;measurementDrain=nil;restoreHook=nil;delayedRetirement=false}
}
@MainActor enum IOSMTUMeasurementGate { static var held=false;static let current="captured-mtu-owner" }
@MainActor enum IOSMTUControl {
 static func withHold<T>(model:RouterVPNModel,operation:@MainActor ()async throws->T)async throws->T {
  Trace.values.append("mtu-hold");IOSMTUMeasurementGate.held=true
  defer{IOSMTUMeasurementGate.held=false;Trace.values.append("mtu-release")}
  return try await operation()
 }
 static func holdCurrent(_ model:RouterVPNModel,request:String)async throws {
  guard IOSMTUMeasurementGate.held,request==IOSMTUMeasurementGate.current else{throw Failure.error}
  Trace.values.append("mtu-drained")
 }
}
@MainActor enum IOSSpeedLabPersistenceJournal {
 static var active=false
 static func begin(owner:UUID?=nil)throws{guard !active else{throw Failure.error};active=true;Trace.values.append("journal-begin")}
 static func reassertOriginalPersistentState()throws{guard active else{throw Failure.error};Trace.values.append("journal-restore")}
 static func finish()throws{active=false;Trace.values.append("journal-finish")}
 static func abandon()throws{active=false;Trace.values.append("journal-abandon")}
}
@MainActor enum IOSSpeedLabEngine {
 static func run(duration:IOSSpeedLabDuration)async throws->IOSSpeedLabMeasurement {
  guard IOSMTUMeasurementGate.held,Trace.values.contains("mtu-drained")else{throw Failure.error}
  Trace.values.append("measure");Trace.measurementHook?();await Trace.measurementDrain?();Trace.values.append("measurement-drained");try Task.checkCancellation()
  let latency=IOSSpeedLabLatencyStats(samples:6,failed:0,minMs:1,medianMs:2,averageMs:2,p90Ms:3,maxMs:3,jitterMs:1)
  let down=IOSSpeedLabDirectionResult(direction:"download",mbps:4,bytes:1_000_000,seconds:2,rounds:1,loadedLatency:latency,bufferbloatMs:0,stoppedStable:false)
  let up=IOSSpeedLabDirectionResult(direction:"upload",mbps:2,bytes:500_000,seconds:2,rounds:1,loadedLatency:latency,bufferbloatMs:0,stoppedStable:false)
  return IOSSpeedLabMeasurement(provider:"Deterministic transfer boundary",duration:duration,idle:latency,download:down,upload:up,startedAt:Date(timeIntervalSince1970:1),finishedAt:Date(timeIntervalSince1970:5))
 }
}
@MainActor final class RouterVPNModel {
 let iosSpeedLabOwnership=IOSSpeedLabOwnership()
 var iosConnectGeneration=UUID(),iosStrategyTaskActive=false,iosUserDisconnectInProgress=false
 var bundle:ClientBundle?,nodes:[String:ClientBundle]=[:],entry=Data("owned-entry-config".utf8)
 var connected=false,tunnelTransitioning=false,auto=true,selectedLogicalMode="original-mode",selectedMode="original-raw",message="original-status"
 var activeEngine="none",activeRawProfile="",activeSessionIdentity:IOSSessionIdentity?
 var failSelection=false,duplicateSelection=false,missingEntry=false
 var selectedNodeProfile:RouterProfile? {
  guard let bundle else{return nil};let matches=bundle.routerProfiles.filter{$0.id==bundle.selectedRouterID};return matches.count==1 ? matches[0]:nil
 }
 var selectedExternalProtocol:String {selectedNodeProfile?.external?.protocolName ?? ""}
 var selectedExternalSupportedOnIOS:Bool {["wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn","tor","tor-bridge"].contains(selectedExternalProtocol)}
 func refreshTunnelStatus()async{}
 func selectNode(_ id:String){guard iosSpeedLabOwnership.admit(.profile)else{return};Trace.values.append("select");if !failSelection{bundle=nodes[id];if duplicateSelection,let p=bundle?.routerProfiles.first{bundle?.routerProfiles.append(p)}}}
 func iosMultihopEntryBundle(for source:ClientBundle)throws->ClientBundle {
  Trace.values.append("validate-entry")
  guard !missingEntry,let selected=selectedNodeProfile,selected.multihopEnabled==true,selected.multihopEntryID=="entry",selected.multihopExitID==selected.id else{throw Failure.error}
  return source
 }
 func connect()async {guard await iosSpeedLabOwnership.admitConnection()else{return};await start(external:false)}
 func connectSelectedExternal()async {guard await iosSpeedLabOwnership.admitConnection()else{return};await start(external:true)}
 func runIOSSmartAuto()async{await connect()}
 func runIOSCustom(layers:[String])async{await connect()}
 private func start(external:Bool)async {
  Trace.values.append(external ? "external-start":"router-start")
  guard !Trace.failProof,let b=bundle,let selected=selectedNodeProfile else{return}
  activeEngine=external ? "external-libbox":(selected.multihopEnabled==true ? "multihop-libbox":"libbox")
  activeRawProfile=external ? "external-"+selectedExternalProtocol:selectedMode
  var config:[String:Any]=[:]
  if selected.multihopEnabled==true {
   if external {let prefix=["tor","tor-bridge"].contains(selectedExternalProtocol) ? "tor_entry":"external_entry";config[prefix+"_bundle"]=entry;config[prefix+"_mode"]=selected.multihopEntryMode!}
   else{config["entryBundle"]=entry}
  }
  activeSessionIdentity=try! IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:activeEngine,rawProfile:activeRawProfile,bundleData:JSONEncoder().encode(b),configuration:config)
  connected=true;Trace.values.append("native-proof")
  if Trace.cancelOnStart{withUnsafeCurrentTask{$0?.cancel()}}
 }
 func disconnect(){guard iosSpeedLabOwnership.admit(.disconnect)else{return};Trace.values.append("disconnect");if !Trace.failRestore{connected=false;tunnelTransitioning=false;activeSessionIdentity=nil}}
 func importBundle(_ bytes:Data)throws{guard iosSpeedLabOwnership.admit(.profile),!connected else{throw Failure.error};bundle=try JSONDecoder().decode(ClientBundle.self,from:bytes);Trace.values.append("restore-model")}
 func restoreIOSSpeedLabBundle(_ bytes:Data?)throws{if let bytes{try importBundle(bytes)}else{bundle=nil}}
}
@MainActor final class IOSSpeedLabTunnel {
 let identity:IOSSessionIdentity?
 init(_ identity:IOSSessionIdentity?){self.identity=identity}
 static func capture(model:RouterVPNModel,owner:UUID)async throws->IOSSpeedLabTunnel {
  try model.iosSpeedLabOwnership.require(owner);Trace.values.append("capture-runtime");return IOSSpeedLabTunnel(model.activeSessionIdentity)
 }
 func stopOriginal(model:RouterVPNModel,owner:UUID)async throws {
  guard identity != nil else{return};try model.iosSpeedLabOwnership.require(owner)
  Trace.values.append("stop-original");model.disconnect();guard !model.connected else{throw Failure.error}
 }
 static func stopTemporary(model:RouterVPNModel,owner:UUID)async throws {
  guard model.iosSpeedLabOwnership.owns(owner)else{throw CancellationError()}
  if Trace.delayedRetirement {Trace.values.append("retirement-pending");throw NSError(domain:"RouterVPN.SpeedLab",code:62)}
  if model.connected || model.tunnelTransitioning {
   Trace.values.append("disconnect");if !Trace.failRestore{model.connected=false;model.tunnelTransitioning=false;model.activeSessionIdentity=nil}
  }
  guard !model.connected,!model.tunnelTransitioning else{throw Failure.error}
 }
 static func retirementPending(_ error:Error)->Bool{let e=error as NSError;return e.domain=="RouterVPN.SpeedLab" && e.code==62}
 func restore(model:RouterVPNModel,owner:UUID,reconnect:Bool)async throws {
  Trace.restoreHook?()
  guard model.iosSpeedLabOwnership.mayRestoreSelection(owner)else{throw CancellationError()}
  if reconnect,let identity {
   try model.iosSpeedLabOwnership.require(owner)
   guard !Trace.failRestore else{throw Failure.error}
   Trace.values.append("restore-proof")
   model.activeEngine=identity.engine;model.activeRawProfile=identity.rawProfile
   model.activeSessionIdentity=try IOSSessionIdentity(connectedAt:identity.connectedAt.addingTimeInterval(1),engine:identity.engine,rawProfile:identity.rawProfile,bundleData:identity.bundleData,entryBundleData:identity.entryBundleData,entryMode:identity.entryMode)
   model.connected=true
  }
 }
}
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ label:String,_ valid:@autoclosure ()->Bool){guard valid()else{FileHandle.standardError.write(Data(("FAIL: "+label+"\n").utf8));exit(1)};checks+=1}
 static func bundle(_ kind:String,_ multihop:Bool=false,_ mode:String="max-quic-awg",_ id:String="test-exit")throws->ClientBundle {
  let external:[String:Any]=["protocol":kind,"expected_public_ip":["tor","tor-bridge"].contains(kind) ? "":"203.0.113.7"]
  let object:[String:Any]=["id":id,"name":"Captured "+kind,"node_kind":kind=="router-vpn" ? "router-vpn":"external","external":external,
   "endpoint":"198.51.100.1","router_api":"","api_token":"fixture-secret","adguard_ipv4":"","adguard_ipv6":"",
   "socks_host":"","socks_port":0,"socks_username":"","socks_password":"",
   "multihop_enabled":multihop,"multihop_entry_id":"entry","multihop_exit_id":id,"multihop_entry_mode":mode]
  var b=ClientBundle.empty;b.selectedRouterID=id;b.routerProfiles=[try JSONDecoder().decode(RouterProfile.self,from:JSONSerialization.data(withJSONObject:object))]
  b.profiles=["original-config":["private.conf":Data("fixture-source".utf8).base64EncodedString()]]
  return try JSONDecoder().decode(ClientBundle.self,from:JSONEncoder().encode(b))
 }
 static func fresh(_ kind:String,_ multihop:Bool,_ mode:String="max-quic-awg")throws->RouterVPNModel {
  Trace.reset();IOSSpeedLabPersistenceJournal.active=false
  let model=RouterVPNModel();model.bundle=try bundle("router-vpn",false,"wg","original");model.nodes["test-exit"]=try bundle(kind,multihop,mode);return model
 }
 static func request(_ multihop:Bool)->IOSSpeedLabRunRequest {
  var r=IOSSpeedLabRunRequest();r.scope = .temporary;r.topology=multihop ? .multihop:.external;r.nodeID="test-exit";return r
 }
 static func restored(_ model:RouterVPNModel){
  check("original entire bundle restored",model.bundle?.selectedRouterID=="original" && model.bundle?.profiles["original-config"]?["private.conf"]==Data("fixture-source".utf8).base64EncodedString())
  check("original mode and status restored",model.selectedLogicalMode=="original-mode" && model.selectedMode=="original-raw" && model.auto && model.message=="original-status")
  check("temporary owner stopped before restore",!model.connected && Trace.values.firstIndex(of:"disconnect")! < Trace.values.firstIndex(of:"restore-model")!)
  check("durable journal and MTU hold released last",!IOSSpeedLabPersistenceJournal.active && !IOSMTUMeasurementGate.held && Trace.values.suffix(2)==["journal-finish","mtu-release"])
 }
 static func captureBytes(_ value:ClientBundle)throws->Data {let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys];return try encoder.encode(value)}
 static func connectedOriginal(_ kind:String,_ execution:String="auto")throws->RouterVPNModel {
  let model=try fresh("tor",true)
  model.bundle=try bundle(kind,kind != "router-vpn","max-tls-awg","original")
  model.bundle!.routerProfiles[0].multihopExecution=execution
  model.bundle!.routerProfiles[0].dnsMode="custom";model.bundle!.routerProfiles[0].mtuPolicy="auto"
  model.activeEngine=kind=="router-vpn" ? "libbox":"external-libbox"
  model.activeRawProfile=kind=="router-vpn" ? "awg2-strong":"external-"+kind
  model.activeSessionIdentity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:model.activeEngine,rawProfile:model.activeRawProfile,bundleData:captureBytes(model.bundle!),entryBundleData:kind=="router-vpn" ? nil:Data("frozen predecessor credential bytes".utf8),entryMode:kind=="router-vpn" ? nil:"max-tls-awg")
  model.connected=true;return model
 }
 static func waitForMeasurement()async {
  for _ in 0..<1000 {if Trace.values.contains("measure"){return};try? await Task.sleep(for:.milliseconds(1))}
  fatalError("measurement did not start")
 }
 static func main()async throws {
  for kind in ["wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn","tor","tor-bridge"] {
   for mode in ["wg","max-quic-awg","reality-xhttp"] {
    let model=try fresh(kind,true,mode),runner=IOSSpeedLabRunner();await runner.run(request(true),model:model)
    check("external saved multihop completes after its native proof",runner.lastResult != nil && runner.lastError.isEmpty && !runner.running)
    check("entry mode is preserved in measured path",runner.lastResult!.path.contains("entry / "+mode) && runner.lastResult!.path.contains("external-"+kind))
    check("external graph uses its own connection owner",Trace.values.contains("external-start") && !Trace.values.contains("router-start") && Trace.values.firstIndex(of:"validate-entry")! < Trace.values.firstIndex(of:"external-start")!)
    check("proof and MTU drain precede bytes",Trace.values.firstIndex(of:"native-proof")! < Trace.values.firstIndex(of:"mtu-drained")! && Trace.values.firstIndex(of:"mtu-drained")! < Trace.values.firstIndex(of:"measure")!)
    restored(model)
   }
   let model=try fresh(kind,false),runner=IOSSpeedLabRunner();await runner.run(request(false),model:model)
   check("direct ordinary or Tor path still works",runner.lastResult?.path.contains("Temporary external direct")==true);restored(model)
   let graph=try fresh(kind,true),wrong=IOSSpeedLabRunner();await wrong.run(request(false),model:graph)
   check("direct topology cannot erase saved multihop",wrong.lastResult==nil && !Trace.values.contains("external-start") && !Trace.values.contains("measure"))
  }
  for failure in ["proof","missing-entry","changed-entry","wrong-selected","duplicate-selected","cancel-after-proof"] {
   let model=try fresh("tor",true),runner=IOSSpeedLabRunner()
   if failure=="proof"{Trace.failProof=true}
   if failure=="missing-entry"{model.missingEntry=true}
   if failure=="wrong-selected"{model.failSelection=true}
   if failure=="duplicate-selected"{model.duplicateSelection=true}
   if failure=="cancel-after-proof"{Trace.cancelOnStart=true}
   if failure=="changed-entry"{Trace.measurementHook={model.activeSessionIdentity=try! IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:"external-libbox",rawProfile:"external-tor",bundleData:Data("same exit".utf8),entryBundleData:Data("replacement entry credentials".utf8),entryMode:"max-quic-awg")}}
   let task=Task{await runner.run(request(true),model:model)};await task.value
   check("failed or stale external graph has no result "+failure,runner.lastResult==nil && !runner.lastError.isEmpty && !runner.running)
   check("failed graph restores selected data "+failure,model.bundle?.selectedRouterID=="original" && !model.connected && !IOSSpeedLabPersistenceJournal.active && !IOSMTUMeasurementGate.held)
   if failure != "changed-entry"{check("unproved graph cannot transfer bytes "+failure,!Trace.values.contains("measure"))}
  }
  for duplicate in [false,true] {
   let model=try fresh("router-vpn",false),runner=IOSSpeedLabRunner();model.failSelection = !duplicate;model.duplicateSelection=duplicate
   var r=request(false);r.topology = .router;await runner.run(r,model:model)
   check("AUTO overrides never mutate a fallback profile",runner.lastResult==nil && !Trace.values.contains("router-start") && model.bundle?.selectedRouterID=="original")
  }
  for kind in ["router-vpn","amneziawg","tor","tor-bridge"] {
   for execution in ["local","server","auto"] {
    let model=try connectedOriginal(kind,execution),runner=IOSSpeedLabRunner()
    let original=model.activeSessionIdentity!,source=try captureBytes(model.bundle!)
    Trace.measurementHook={model.nodes["original"]=try! bundle("hysteria2",false,"wg","original")}
    await runner.run(request(true),model:model)
    check("connected temporary path completes only after restoration",runner.lastResult != nil && runner.lastError.isEmpty && model.connected)
    let restoredSource=try captureBytes(model.bundle!)
    check("original complete data and execution preference restored",restoredSource==source && model.bundle!.routerProfiles[0].multihopExecution==execution)
    check("original selected actual raw mode cannot be reselected",model.activeRawProfile==original.rawProfile && model.activeSessionIdentity?.bundleData==original.bundleData && model.activeSessionIdentity?.entryBundleData==original.entryBundleData)
    check("original gets fresh proof without changing entry mode",model.activeSessionIdentity != original && model.activeSessionIdentity?.entryMode==original.entryMode)
    check("capture precedes MTU quiescence and teardown",Trace.values.firstIndex(of:"capture-runtime")! < Trace.values.firstIndex(of:"mtu-hold")! && Trace.values.firstIndex(of:"mtu-hold")! < Trace.values.firstIndex(of:"stop-original")!)
    check("measurement drains before teardown and original proof",Trace.values.firstIndex(of:"measurement-drained")! < Trace.values.lastIndex(of:"disconnect")! && Trace.values.lastIndex(of:"disconnect")! < Trace.values.firstIndex(of:"restore-proof")! && Trace.values.firstIndex(of:"restore-proof")! < Trace.values.firstIndex(of:"mtu-release")!)
    check("display selection and journal restored",model.selectedLogicalMode=="original-mode" && model.selectedMode=="original-raw" && model.auto && !IOSSpeedLabPersistenceJournal.active && !IOSMTUMeasurementGate.held)
   }
  }
  do {
   let model=try connectedOriginal("tor"),runner=IOSSpeedLabRunner();var r=request(false);r.topology = .systemDirect
   await runner.run(r,model:model)
   check("explicit system direct temporarily pauses and restores Tor",runner.lastResult?.path.contains("system direct")==true && model.connected && model.activeRawProfile=="external-tor" && !Trace.values.contains("external-start"))
  }
  for action in ["cancel","disconnect","new-profile","new-connect"] {
   let model=try connectedOriginal("tor"),runner=IOSSpeedLabRunner(),original=model.activeSessionIdentity!
   var drain:CheckedContinuation<Void,Never>?
   Trace.measurementDrain={await withCheckedContinuation{drain=$0}}
   let task=Task{await runner.run(request(true),model:model)}
   await waitForMeasurement()
   check("owned measurement retains MTU hold before cancellation",runner.running && IOSMTUMeasurementGate.held)
   var userConnection:Task<Void,Never>?
   if action=="cancel"{runner.cancel()}
   else if action=="new-connect" {
    userConnection=IOSSpeedLabContext.$owner.withValue(nil){Task{await model.connectSelectedExternal()}}
    for _ in 0..<3{try? await Task.sleep(for:.milliseconds(1))}
   } else {
    IOSSpeedLabContext.$owner.withValue(nil){
     model.disconnect()
     if action=="new-profile" {model.nodes["replacement"]=try! bundle("shadowsocks",false,"wg","replacement");model.selectNode("replacement")}
    }
   }
   for _ in 0..<3{try? await Task.sleep(for:.milliseconds(1))}
   check("Cancel does not fabricate worker drain "+action,runner.running && IOSMTUMeasurementGate.held && !Trace.values.contains("restore-proof") && !Trace.values.contains("mtu-release"))
   if action=="new-connect"{check("new Home connection waits for old worker",Trace.values.filter{$0=="external-start"}.count==1)}
   drain?.resume();await task.value;await userConnection?.value
   check("cancelled temporary work never publishes a measurement "+action,runner.lastResult==nil && !runner.lastError.isEmpty)
   check("drained transaction releases lease and receipt "+action,!runner.running && !IOSMTUMeasurementGate.held && !IOSSpeedLabPersistenceJournal.active)
   if action=="cancel"{check("Cancel freshly restores original proved source",model.connected && model.activeRawProfile==original.rawProfile && model.activeSessionIdentity?.bundleData==original.bundleData && Trace.values.contains("restore-proof"))}
   if action=="disconnect"{check("explicit Disconnect is never undone",!model.connected && model.bundle?.selectedRouterID=="original" && !Trace.values.contains("restore-proof"))}
   if action=="new-profile"{check("newer profile is never overwritten",model.bundle?.selectedRouterID=="replacement" && !model.connected && Trace.values.contains("journal-abandon") && !Trace.values.contains("restore-proof"))}
   if action=="new-connect"{check("newer connection starts after captured retirement",model.connected && Trace.values.filter{$0=="external-start"}.count==2 && Trace.values.firstIndex(of:"mtu-release")! < Trace.values.lastIndex(of:"external-start")! && !Trace.values.contains("restore-proof"))}
  }
  for disconnect in [false,true] {
   let model=try connectedOriginal("tor"),runner=IOSSpeedLabRunner();Trace.delayedRetirement=true
   let task=Task{await runner.run(request(true),model:model)}
   for _ in 0..<1000 {if Trace.values.contains("retirement-pending"){break};try? await Task.sleep(for:.milliseconds(1))}
   check("unconfirmed native retirement retains transaction",Trace.values.contains("retirement-pending") && runner.running && IOSMTUMeasurementGate.held && IOSSpeedLabPersistenceJournal.active)
   if disconnect {IOSSpeedLabContext.$owner.withValue(nil){model.disconnect()}} else {runner.cancel();Trace.delayedRetirement=false}
   await task.value
   check("native retirement delay cannot publish stale measurement",runner.lastResult==nil && !runner.lastError.isEmpty && !IOSMTUMeasurementGate.held)
   check("native retirement respects final user intent",disconnect ? !model.connected && !Trace.values.contains("restore-proof") : model.connected && Trace.values.contains("restore-proof"))
  }
  do {
   let model=try connectedOriginal("tor"),runner=IOSSpeedLabRunner();Trace.failProof=true
   await runner.run(request(true),model:model)
   check("failed temporary proof restores original without result",runner.lastResult==nil && !Trace.values.contains("measure") && model.connected && model.bundle?.selectedRouterID=="original" && Trace.values.contains("restore-proof"))
  }
  do {
   let model=try connectedOriginal("tor"),runner=IOSSpeedLabRunner();model.bundle!.routerProfiles[0].effectiveMTUMbps = .nan
   await runner.run(request(true),model:model)
   check("unencodable original cannot be treated as absent",runner.lastResult==nil && model.connected && !Trace.values.contains("journal-begin") && !Trace.values.contains("disconnect"))
  }
  print("Apple temporary external/Tor Speed Lab: PASS (\(checks) shipping runner/identity checks; native/network/IPC/storage boundaries substituted)")
 }
}
'''

def main():
    swift = shutil.which('swiftc')
    if not swift:
        raise SystemExit('swiftc is required for real Speed Lab orchestration checks')
    types = (APP / 'IOSSpeedLab.swift').read_text().split('// One shared HTTP policy', 1)[0].replace('import Security', '')
    source = '\n'.join([(APP / 'Models.swift').read_text(), (APP / 'IOSSessionIdentity.swift').read_text(), types,
                        (APP / 'IOSSpeedLabOwnership.swift').read_text(), (APP / 'IOSSpeedLabRunner.swift').read_text(), FIXTURE])
    with tempfile.TemporaryDirectory(prefix='routervpn-external-speed-') as tmp:
        path, binary = Path(tmp) / 'test.swift', Path(tmp) / 'test'
        path.write_text(source)
        subprocess.run([swift, '-swift-version', '6', '-parse-as-library', str(path), '-o', str(binary)], check=True, timeout=120)
        subprocess.run([str(binary)], check=True, timeout=60)
    view = (APP / 'IOSSpeedLabView.swift').read_text()
    assert 'model.allNodeProfiles.filter { $0.multihopEnabled == true }' in view
    assert '$0.normalizedNodeKind == "external" && $0.multihopEnabled != true' in view

if __name__ == '__main__':
    main()
