#!/usr/bin/env python3
"""Execute shipping Apple hop orchestration with deterministic native IPC.

The UI controller, transaction, result types, and app-side MTU lease gate are
shipping source. NetworkExtension handles/native payloads are explicit doubles;
the native service and proof factories have separate encrypted/ownership gates.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
FIXTURE=r'''
protocol ObservableObject {}
@propertyWrapper struct Published<T> {var wrappedValue:T}
@MainActor final class NETunnelProviderSession {
 enum Status {case connected,disconnected}
 var status=Status.connected,connectedDate:Date?=Date(timeIntervalSince1970:10)
 func sendProviderMessage(_ data:Data,responseHandler:@escaping(Data?)->Void)throws{Native.shared.handle(data,responseHandler)}
}
struct SelectedMeasurementSource { let ids: [String], source: String, config: String, requested: String; let privateStreamPositions: Set<Int> = [] }
extension String {
 var hopMeasurementRows:Int { self == "local-maximum" ? 96 : self == "local-long" ? 16 : self == "local-deep" ? 9 : 8 }
 var selectedMeasurementSource:SelectedMeasurementSource? {nil}
 var nodeChainSource:Data? { hasPrefix("local-") ? Data(utf8) : nil }
}
enum IOSNodeChainPresentation {
 struct Point { let id:String,kind:String }
 static func active(_ identity:String)->[Point]? {
  guard ["local-short","local-deep","local-long","local-maximum"].contains(identity) else{return nil}
  let count = identity == "local-short" ? 5 : identity.hopMeasurementRows
  return (0..<count).map { i in
   Point(id:"original-\(i)",kind:i>0 && i<count-1 && i%3==1 ? "external":"router-vpn")
  }
 }
}
@MainActor final class RouterVPNModel {
 var connected=true,activeEngine="external-libbox",activeSessionIdentity:String?="proved-native-selection"
 func refreshTunnelStatus()async{}
}
@MainActor final class Native {
 static let shared=Native()
 let session=UUID().uuidString,mtuSession=UUID().uuidString,connection=NETunnelProviderSession()
 var mode="stable",drained=true,starts=0,cancels=0,statuses=0,releases=0,held=false
 var mtuBusy=false,mtuOperations:[String]=[],mtuRequests:[String]=[]
 var captured:[String:Any]?,pending:((Data?)->Void)?,pendingRequest:[String:Any]?
 var informationHook:(()->Void)?
 func reset(_ mode:String){self.mode=mode;mtuBusy=false;mtuOperations=[];mtuRequests=[];drained=["stable","ordered","oversized"].contains(mode);starts=0;cancels=0;statuses=0;releases=0;held=false;captured=nil;pending=nil;pendingRequest=nil;informationHook=nil;connection.status = .connected;connection.connectedDate=Date(timeIntervalSince1970:10)}
 func body(_ request:[String:Any],complete:Bool,drained:Bool)->Data {
  var rows:[[String:Any]]=[]
  if ["ordered","oversized"].contains(mode), request["operation"] as? String != "hop-measure-cancel" {
   let latency:[String:Any]=["samples":6,"min_ms":1.0,"median_ms":2.0,"average_ms":2.0,"p90_ms":3.0,"max_ms":3.0,"jitter_ms":1.0]
   let transfer:[String:Any]=["bytes":65536,"seconds":0.5,"mbps":1.048576,"loaded_reason":"short transfer"]
   for i in 0..<(mode=="ordered" ? 8:9){rows.append(["node_id":"node-\(i)","role":i==0 ? "entry":i==7 ? "exit":"intermediate","kind":"private-node","label":"Cumulative path through node \(i+1)","ready":true,"idle":latency,"download":transfer,"upload":transfer])}
  }
  var stage = complete ? "complete":"running"
  var failure:String?
  if mode.hasPrefix("local-"), request["operation"] as? String != "hop-measure-cancel" {
   let count = mode == "local-short" ? 5 : mode == "local-long" ? 16 : mode == "local-maximum" ? 96 : 9
   let idle:[String:Any]=["samples":6,"min_ms":1,"median_ms":2,"average_ms":2,"p90_ms":3,"max_ms":3,"jitter_ms":1]
   let speed:[String:Any]=["bytes":8388608,"seconds":1.0,"mbps":67.108864]
   for i in 0..<(complete ? count : 3) {
    let isPublic = i>0 && i<count-1 && i%3==1
    let role = i==0 ? "entry" : i==count-1 ? "exit":"intermediate"
    let label = "Cumulative path through " + (isPublic ? "custom " : "") + "node \(i+1) of \(count)" + (isPublic ? " → Cloudflare edge" : "")
    var row:[String:Any]=["node_id":"original-\(i)","role":role,"kind":isPublic ? "public-path":"private-node","label":label,"ready":true,"idle":idle,"download":speed,"upload":speed]
    if mode=="local-failed-row" && i==2 {
     row["ready"]=false;row["failure"]="Routed identity, byte count, or transfer deadline failed"
     for key in ["idle","download","upload"] { row.removeValue(forKey:key) }
    }
    rows.append(row)
   }
   switch mode {
   case "local-swap": rows[2]["node_id"]="original-3";rows[3]["node_id"]="original-2"
   case "local-kind": rows[2]["kind"]="public-path"
   case "local-role": rows[2]["role"]="exit"
   case "local-label": rows[2]["label"]="Cumulative path through custom node 3 of 9 → Cloudflare edge"
   case "local-short-body": rows[2]["upload"]=["bytes":65536,"seconds":1.0,"mbps":0.524288]
   case "local-short-completion": rows.removeLast()
   case "local-false-completion": stage="running";rows.removeLast()
   case "local-partial-kind": if !complete {rows[2]["kind"]="public-path"}
   case "local-false-unavailable": rows[2]["ready"]=false;rows[2]["failure"]="Routed identity, byte count, or transfer deadline failed"
   case "local-invalidated": stage="invalidated";failure="Session changed or measurement timed out";rows=[]
   default: break
   }
  }
  var status:[String:Any]=["request_id":request["request_id"]!,"session_id":request["session_id"]!,"stage":stage,"complete":complete,"drained":drained,"results":rows]
  if let failure {status["failure"]=failure}
  return try! JSONSerialization.data(withJSONObject:status)
 }
 func handle(_ data:Data,_ reply:@escaping(Data?)->Void) {
  let request=try! JSONSerialization.jsonObject(with:data) as! [String:Any]
  guard request.count==3 && held else {FileHandle.standardError.write(Data("native IPC lost its MTU hold\n".utf8));exit(1)}
  if request["operation"] as? String=="hop-measure-info" {
   guard request["session_id"] as? String=="" else{FileHandle.standardError.write(Data("hop Info incorrectly equated MTU and proof epochs\n".utf8));exit(1)}
   informationHook?()
   reply(try! JSONSerialization.data(withJSONObject:["request_id":request["request_id"]!,"session_id":session,"mtu_session_id":mode=="wrong-info-mtu" ? UUID().uuidString:mtuSession]));return
  }
  guard request["session_id"] as? String==session else{FileHandle.standardError.write(Data("native IPC lost its exact hop proof session\n".utf8));exit(1)}
  captured=request
  switch request["operation"] as? String {
   case "hop-measure-start":
    starts += 1
    if mode=="late" || mode=="changed" {pending=reply;pendingRequest=request;return}
    if mode=="wrong-session" {var wrong=request;wrong["session_id"]=UUID().uuidString;reply(body(wrong,complete:true,drained:true));return}
    if ["local-partial","local-partial-kind"].contains(mode) {reply(body(request,complete:false,drained:false));return}
    reply(body(request,complete:true,drained:drained))
   case "hop-measure-cancel":cancels += 1;reply(body(request,complete:true,drained:drained))
   case "hop-measure-status":statuses += 1;reply(body(request,complete:true,drained:drained))
   default:reply(nil)
  }
 }
 func deliverLate(){let callback=pending;pending=nil;callback?(body(pendingRequest!,complete:true,drained:drained))}
}
@MainActor enum IOSSpeedLabContext {static var startupAdmission:(()->Bool)?=nil}
@MainActor enum IOSMTUControl {
 struct Binding {let connection:NETunnelProviderSession;let connectedDate:Date;let identity:String;let session:String}
 static func capture(_ model:RouterVPNModel)async throws->Binding{
  guard let identity=model.activeSessionIdentity else{throw CancellationError()}
  return Binding(connection:Native.shared.connection,connectedDate:Native.shared.connection.connectedDate!,identity:identity,session:Native.shared.mtuSession)
 }
CURRENT_BINDING
 // Native MTU command replies are doubled; hold admission is shipping code.
 static func failure(_ text:String)->NSError{NSError(domain:"RouterVPN.MTU",code:1,userInfo:[NSLocalizedDescriptionKey:text])}
 static func message(_ binding:Binding,model:RouterVPNModel,operation:String,request:String)async throws->Data{
  guard current(binding,model:model),request==IOSMTUMeasurementGate.current else{throw CancellationError()}
  let native=Native.shared;native.mtuOperations.append(operation);native.mtuRequests.append(request)
  guard operation=="mtu-hold" || operation=="mtu-hold-idle" else{throw CancellationError()}
  // Idle admission must leave a busy Auto-MTU/Retest owner intact.
  if operation=="mtu-hold-idle" && native.mtuBusy{throw CancellationError()}
  if operation=="mtu-hold"{native.mtuBusy=false}
  native.held=true
  return try JSONSerialization.data(withJSONObject:["measurement_hold":true,"measurement_lease":request,"measurement_ready":native.mode != "idle-unready"])
 }
HOLD_CURRENT
 static func releaseCurrent(_ model:RouterVPNModel,request:String)async throws{Native.shared.held=false;Native.shared.releases+=1}
WITH_HOLD
}
'''
TEST=r'''
@main struct Main {
 @MainActor static func main()async throws {
  var checks=0
  func check(_ name:String,_ test:Bool){if !test{FileHandle.standardError.write(Data((name+"\n").utf8));exit(1)};checks+=1}
  func wait(_ condition:()->Bool)async {
   let deadline=ProcessInfo.processInfo.systemUptime+5
   while !condition() && ProcessInfo.processInfo.systemUptime<deadline{try? await Task.sleep(for:.milliseconds(5))}
   check("bounded fixture progress",condition())
  }
  let native=Native.shared
  for mode in ["ordered","oversized"] {
   native.reset(mode);let model=RouterVPNModel(),probe=IOSHopMeasurements();model.activeEngine="multihop-libbox";probe.start(model:model)
   await wait{native.starts==1 && !probe.running}
   if mode=="ordered" {check("complete ordered rows reach UI",probe.text.contains("node 8") && probe.text.components(separatedBy:"Download 1.05 Mbps").count==9)}
   else {check("oversized ordered result is discarded",!probe.text.contains("Mbps") && native.cancels>0)}
   check("ordered native drain releases MTU",native.releases==1 && !IOSMTUMeasurementGate.held)
  }
  for mode in ["local-short","local-deep","local-long","local-partial","local-failed-row","local-invalidated","local-unrecoverable",
               "local-swap","local-kind","local-role","local-label","local-short-body","local-short-completion","local-false-completion","local-partial-kind","local-false-unavailable","local-maximum"] {
   native.reset(mode);native.drained=true
   let model=RouterVPNModel(),probe=IOSHopMeasurements();model.activeEngine="multihop-libbox"
   model.activeSessionIdentity=["local-short","local-long","local-maximum","local-unrecoverable"].contains(mode) ? mode : "local-deep"
   probe.start(model:model)
   if mode=="local-partial" {
    await wait{probe.text.contains("Routed paths: running")}
    check("valid original partial rows appear while owned",probe.text.contains("original-2") && !probe.text.contains("original-3") && probe.running && native.held)
   }
   await wait{!probe.running}
   switch mode {
   case "local-short","local-deep","local-long","local-maximum","local-partial","local-failed-row":
    let count=mode=="local-long" ? 16 : mode=="local-short" ? 5 : mode=="local-maximum" ? 96 : 9
    check("all original Local results reach the UI: "+mode,probe.text.contains("Exit • original-\(count-1)") &&
       probe.text.contains("HTTPS response") && probe.text.contains("Private-node response") &&
       probe.text.components(separatedBy:"Download 67.11 Mbps").count == count+(mode=="local-failed-row" ? 0:1) && native.cancels==0)
    if mode=="local-failed-row" {check("genuine unavailable original retained",probe.text.contains("unavailable — Routed identity, byte count, or transfer deadline failed"))}
   case "local-invalidated":
    check("native scoreless invalidation is readable",probe.text.contains("Session changed or measurement timed out") && !probe.text.contains("Mbps") && native.cancels==0)
   case "local-unrecoverable":
    check("unrecoverable sealed Local path stops before probing",native.starts==0 && probe.text.contains("discarded"))
   default:
    check("foreign Local throughput rejected: "+mode,native.starts==1 && native.cancels>0 && probe.text.contains("discarded") && !probe.text.contains("Mbps"))
   }
   check("owned Local MTU always releases once",native.releases==1 && !IOSMTUMeasurementGate.held)
  }
  for idleOnly in [true,false] {
   native.reset("stable");let model=RouterVPNModel();var ran=false
   try await IOSMTUControl.withHold(model:model,idleOnly:idleOnly){
    check("operation retains the exact native and app MTU lease",native.held && IOSMTUMeasurementGate.held && native.mtuRequests==[IOSMTUMeasurementGate.current]);ran=true
   }
   check("idle-only reservation reaches the matching native operation",native.mtuOperations==[idleOnly ? "mtu-hold-idle":"mtu-hold"])
   check("successful reservation releases both owners",ran && native.releases==1 && !native.held && !IOSMTUMeasurementGate.held)
  }
  for mode in ["stable","idle-unready"] {
   native.reset(mode);native.mtuBusy=mode=="stable";let model=RouterVPNModel();var ran=false,rejected=false
   do{try await IOSMTUControl.withHold(model:model,idleOnly:true){ran=true}}catch{rejected=true}
   check("busy or unready idle reservation never starts work",rejected && !ran && native.mtuOperations==["mtu-hold-idle"] && native.mtuBusy==(mode=="stable"))
   check("refused idle reservation releases its app lease",native.releases==1 && !native.held && !IOSMTUMeasurementGate.held)
  }
  native.reset("stable");native.mtuBusy=true
  do {
   let model=RouterVPNModel(),probe=IOSHopMeasurements();probe.start(model:model);await wait{!probe.running}
   check("manual hop measurement preserves its draining hold policy",native.mtuOperations==["mtu-hold"] && !native.mtuBusy && native.starts==1 && native.releases==1 && !IOSMTUMeasurementGate.held)
  }
  for engine in ["multihop-libbox","external-libbox"] {
   native.reset("stable");let model=RouterVPNModel();model.activeEngine=engine;let probe=IOSHopMeasurements()
   probe.start(model:model);await wait{!probe.running}
   check("supported graph is measured",native.starts==1 && native.releases==1 && !IOSMTUMeasurementGate.held)
   check("native request captures immutable session epoch",native.captured?["session_id"] as? String==native.session)
   check("hop proof UUID remains distinct from MTU lease session",native.session != native.mtuSession)
  }
  for engine in ["libbox","wireguardkit","none"] {
   native.reset("stable");let model=RouterVPNModel();model.activeEngine=engine;let probe=IOSHopMeasurements();probe.start(model:model)
   check("non-owned engine cannot start per-hop work",!probe.running && native.starts==0 && !IOSMTUMeasurementGate.held)
  }
  native.reset("complete-undrained")
  do {
   let model=RouterVPNModel(),probe=IOSHopMeasurements();probe.start(model:model)
   await wait{native.starts==1};try? await Task.sleep(for:.milliseconds(30))
   check("logical completion does not release native work",probe.running && IOSMTUMeasurementGate.held && native.releases==0)
   probe.start(model:model);check("new run cannot overlap undrained request",native.starts==1)
   native.drained=true;await wait{!probe.running}
   check("drain permits exactly one MTU release",native.releases==1 && !IOSMTUMeasurementGate.held)
  }
  for mode in ["late","changed","wrong-session"] {
   native.reset(mode);let model=RouterVPNModel(),probe=IOSHopMeasurements();probe.start(model:model)
   await wait{native.starts==1}
   if mode=="changed" {model.activeSessionIdentity="replacement-node";native.deliverLate()}
   else if mode=="late" {probe.cancel()}
   await wait{native.cancels>0}
   check("cancel or stale reply retains native hold",probe.running && IOSMTUMeasurementGate.held && native.releases==0)
   probe.start(model:model);check("cancel cannot reopen a concurrent run",native.starts==1)
   native.drained=true
   if mode=="late"{native.deliverLate()}
   await wait{!probe.running}
   check("cancel cleanup drains before hold release",native.releases==1 && !IOSMTUMeasurementGate.held)
   check("stale result is discarded",probe.text.contains("discarded") && !probe.text.contains("Mbps"))
  }
  for drift in ["identity","connected","native-status","native-date","wrong-info-mtu"] {
   native.reset(drift);let model=RouterVPNModel(),probe=IOSHopMeasurements()
   native.informationHook={
    switch drift {
     case "identity":model.activeSessionIdentity="new-selection"
     case "connected":model.connected=false
     case "native-status":native.connection.status = .disconnected
     case "native-date":native.connection.connectedDate=Date(timeIntervalSince1970:20)
     default:break
    }
   }
   probe.start(model:model);await wait{!probe.running}
   check("stale info binding rejected before native start: "+drift,native.starts==0 && native.cancels==0 && native.releases==1 && !IOSMTUMeasurementGate.held && probe.text.contains("discarded"))
  }
  print("Apple owned hop transaction: PASS (\(checks) shipping UI/MTU/IPC cancellation checks; native OS handles doubled)")
 }
}
'''

SELECTED_REGISTRY = r'''
import Foundation
final class LibboxRouterHopMeasurement {
 var request="",stage="running",drained=false,rows=[Int](),reads=0
 func start(_ id:String,bytes:Int)throws {precondition(bytes==8388608);request=id}
 func startLatency(_ id:String,exitID:String)throws {request=id}
 func startResponse(_ id:String,exitID:String)throws {request=id}
 func cancel(_ request:String){stage="cancelled";rows=[]}
 func statusJSON()->String{reads+=1;return String(decoding:try! JSONSerialization.data(withJSONObject:["request_id":request,"complete":drained,"drained":drained,"stage":stage,"results":rows]),as:UTF8.self)}
}
SHIPPING_SELECTED_REGISTRY
final class FixtureEngine {
 struct MTU {let hasOwner=false,measurementReady=false}
 struct Platform {let mtu=MTU()}
 struct Plan {
  func extendedLocalStatusLimit()->Int {32000}
  func extendedOriginalStatusLimit()->Int {32000}
 }
 struct Selected {struct Capture {let plan=Plan()};let capture=Capture()}
 static let retiredMeasurements=RetiredHopMeasurements()
 let ownershipLock=NSLock(),platform=Platform(),settingsEpoch=UUID().uuidString
 var hopMeasurement:LibboxRouterHopMeasurement?=LibboxRouterHopMeasurement()
 var hopMeasurementExitID:String?,permanentlyStopped=false,nodeChain:Plan?,nodeChainExecution:Selected?
 var nodeChainSOCKS:Bool?,nodeChainCONNECT:Bool?
 func hopMeasurementInformation(request:String)->Data? {nil}
 SHIPPING_HOP_DISPATCH
}
@main struct SelectedRegistryTest {
 static func main()throws{
  let registry=RetiredHopMeasurements(),probe=LibboxRouterHopMeasurement(),foreign=LibboxRouterHopMeasurement()
  let id=String(repeating:"a",count:32),epoch=UUID().uuidString
  func reply(_ operation:String,_ owner:LibboxRouterHopMeasurement?=nil)throws->[String:Any] {
   guard let raw=registry.reply(operation:operation,request:id,session:epoch,liveProbe:owner),
         let body=try JSONSerialization.jsonObject(with:raw) as? [String:Any] else {fatalError("missing original join acknowledgement")}
   return body
  }
  let started=registry.start(probe,request:id,session:epoch,requiresLiveOwner:true)
  precondition(started != nil)
  foreign.request=id;foreign.rows=[99];registry.retain(foreign,session:epoch,requiresLiveOwner:true)
  let captureReads=foreign.reads
  probe.stage="complete";probe.drained=true;probe.rows=[8,8]
  let first=try reply("hop-measure-status",probe)
  precondition(first["results"] as? [Int]==[8,8],"original selected bytes discarded")
  let reads=probe.reads
  probe.stage="invalidated";probe.rows=[]
  let changed=try reply("hop-measure-status",probe)
  precondition(changed["stage"] as? String=="invalidated" && (changed["results"] as? [Int])==[] && probe.reads==reads+1,"selected replay reused a stale success")
  foreign.request=id;foreign.drained=true;foreign.stage="complete";foreign.rows=[99]
  for owner in [nil,foreign] as [LibboxRouterHopMeasurement?]{
   let retired=try reply("hop-measure-status",owner)
   precondition(retired["drained"] as? Bool==true && retired["stage"] as? String=="invalidated" && retired["results"] as? [Int]==[] && foreign.reads==captureReads,"retired provider replayed successful selected bytes")
  }
  let cancelled=try reply("hop-measure-cancel",probe)
  precondition(cancelled["drained"] as? Bool==true && cancelled["results"] as? [Int]==[])
  // Stop may arrive before the first status read. Only its live exact owner
  // can use a later retry to re-observe original joined results.
  let old=LibboxRouterHopMeasurement(),second=String(repeating:"b",count:32)
  _=registry.start(old,request:second,session:epoch,requiresLiveOwner:true)
  old.drained=true;old.stage="complete";old.rows=[42];registry.retain(old,session:epoch,requiresLiveOwner:true)
  let retiredRaw=registry.reply(operation:"hop-measure-status",request:second,session:epoch)!
  let retired=try JSONSerialization.jsonObject(with:retiredRaw) as! [String:Any]
  precondition(retired["results"] as? [Int]==[] && retired["drained"] as? Bool==true,"unpublished selected result escaped after provider retirement")
  for family in ["local","socks","connect","execution"] {
   let owner=FixtureEngine(), probe=owner.hopMeasurement!, id=String(repeating:"c",count:32)
   switch family {
   case "local": owner.nodeChain = .init()
   case "socks": owner.nodeChainSOCKS = true
   case "connect": owner.nodeChainCONNECT = true
   default: owner.nodeChainExecution = .init()
   }
   func read(_ operation:String)throws->[String:Any] {
    let data=owner.hopMeasurementRequest(operation:operation,request:id,session:owner.settingsEpoch)!
    return try JSONSerialization.jsonObject(with:data) as! [String:Any]
   }
   _=try read("hop-measure-start")
   probe.rows=[42];probe.stage="entry:upload"
   let partial=try read("hop-measure-status")
   precondition(partial["results"] as? [Int]==[42] && partial["drained"] as? Bool==false,"original ordered partial rows discarded")
   probe.rows=[42,84];probe.stage="complete";probe.drained=true
   let joined=try read("hop-measure-status")
   precondition(joined["results"] as? [Int]==[42,84],"original ordered final transfer discarded")
   let count=probe.reads
   probe.stage="invalidated";probe.rows=[]
   let invalid=try read("hop-measure-status")
   precondition(invalid["stage"] as? String=="invalidated" && invalid["results"] as? [Int]==[] && probe.reads==count+1,"stale ordered transfer replayed: "+family)
   owner.hopMeasurement=LibboxRouterHopMeasurement()
   let replaced=try read("hop-measure-status")
   precondition(replaced["stage"] as? String=="invalidated" && replaced["results"] as? [Int]==[] && owner.hopMeasurement!.reads==0,"replacement replayed original ordered transfer: "+family)
   let retired=try JSONSerialization.jsonObject(with:FixtureEngine.retiredMeasurements.reply(operation:"hop-measure-status",request:id,session:owner.settingsEpoch)!) as! [String:Any]
   precondition(retired["drained"] as? Bool==true && retired["results"] as? [Int]==[],"retired ordered transfer leaked through fallback: "+family)
  }
  print("Apple ordered Local and selected throughput registry: original re-observation, scoreless retirement and foreign owner PASS")
 }
}
'''


def selected_registry(work):
    from test_ios_startup_policy import member
    engine = (ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift').read_text()
    original = member(engine, '    private final class RetiredHopMeasurements:').replace('private final class RetiredHopMeasurements:', 'final class RetiredHopMeasurements:', 1)
    dispatch = member(engine, '    func hopMeasurementRequest(')
    shipping = SELECTED_REGISTRY.replace('SHIPPING_SELECTED_REGISTRY', original).replace('SHIPPING_HOP_DISPATCH', dispatch)
    for label, before, after, witness in (
        ('original', None, None, None),
        ('stale replay', 'return data(liveProbe, request: request, session: session) ?? receipt', 'return receipt', 'selected replay reused a stale success'),
        ('foreign retirement', 'save(cleanup, key: id)', 'save(response, key: id)', 'retired provider replayed successful selected bytes'),
        ('ordinary Local cached replay', 'nodeChain != nil || nodeChainSOCKS != nil || nodeChainCONNECT != nil || nodeChainExecution != nil', 'nodeChainExecution != nil', 'stale ordered transfer replayed: local'),
        ('typed Local cached replay', 'nodeChain != nil || nodeChainSOCKS != nil || nodeChainCONNECT != nil || nodeChainExecution != nil', 'nodeChain != nil || nodeChainExecution != nil', 'stale ordered transfer replayed: socks'),
    ):
        if before and shipping.count(before) != 1:
            raise ValueError('selected receipt mutation lost its original source: '+label)
        swift = work/'Selected.swift'; binary = work/'selected'
        swift.write_text(shipping if before is None else shipping.replace(before, after, 1))
        subprocess.run(['swiftc','-swift-version','6','-parse-as-library',str(swift),'-o',str(binary)],check=True,timeout=60)
        result = subprocess.run([str(binary)],capture_output=True,text=True,timeout=25)
        if witness:
            assert result.returncode and witness in result.stderr, label
            print('Rejected ordered receipt mutation: '+label)
        else:
            assert result.returncode == 0, result.stderr
            print(result.stdout.strip())


def main():
    source=(APP/'IOSHopMeasurements.swift').read_text().split('\nstruct IOSHopMeasurementsCard:',1)[0]
    source=source.replace('import SwiftUI','import Foundation').replace('@preconcurrency import NetworkExtension','')
    mtu=(APP/'IOSMTUControl.swift').read_text()
    hold=mtu[mtu.index('    static func withHold<T>'):].rsplit('\n}',1)[0]
    current=mtu[mtu.index('    static func current('):mtu.index('    static func message(')]
    hold_current=mtu[mtu.index('    static func holdCurrent('):mtu.index('    static func releaseCurrent(')]
    fixture=FIXTURE.replace('WITH_HOLD',hold).replace('CURRENT_BINDING',current).replace('HOLD_CURRENT',hold_current)
    gate=(APP/'IOSMTUMeasurementGate.swift').read_text()
    with tempfile.TemporaryDirectory(prefix='routervpn-apple-hop-') as directory:
        work=Path(directory);code=work/'Main.swift';binary=work/'test'
        selected_registry(work)
        code.write_text('import Foundation\n'+gate+fixture+source+TEST)
        subprocess.run(['swiftc','-swift-version','6','-parse-as-library',str(code),'-o',str(binary)],check=True,timeout=60)
        subprocess.run([str(binary)],check=True,timeout=25)
        # Execute the old logical-completion mistake and a wrong-session reply
        # acceptance as negative controls against the same shipping UI harness.
        for name,old,new in [
            ('undrained completion','if result.complete && result.drained { return }','if result.complete { return }'),
            ('foreign session','status.request_id == id, status.session_id == session','status.request_id == id')]:
            assert old in source
            bad=work/'Bad.swift';bad_binary=work/'bad'
            bad.write_text('import Foundation\n'+gate+fixture+source.replace(old,new)+TEST)
            subprocess.run(['swiftc','-swift-version','6','-parse-as-library',str(bad),'-o',str(bad_binary)],check=True,timeout=60)
            result=subprocess.run([str(bad_binary)],capture_output=True,text=True,timeout=25)
            assert result.returncode != 0 and ('logical completion does not release native work' in result.stderr or
                'bounded fixture progress' in result.stderr or
                'native IPC lost its captured session or MTU hold' in result.stderr), name+': ownership regression was accepted or failed for another reason: '+result.stderr[-500:]
        print('Negative controls: undrained completion and foreign-session reply rejected')
        for label, before, after, witness in (
                ('ignored original identity','result.node_id == original.id, result.role == role','result.role == role','local-swap'),
                ('ignored original privacy','result.kind == (original.isPublic ? "public-path" : "private-node"), result.label == label','result.label == label','local-kind'),
                ('unchecked source projection','try status.validateLocalThroughput(path: localPath)','_ = localPath','local-swap')):
            assert source.count(before)==1
            bad=work/'BadSource.swift'; binary=work/'bad-source'
            bad.write_text('import Foundation\n'+gate+fixture+source.replace(before,after,1)+TEST)
            subprocess.run(['swiftc','-swift-version','6','-parse-as-library',str(bad),'-o',str(binary)],check=True,timeout=60)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=25)
            assert result.returncode and 'foreign Local throughput rejected: '+witness in result.stderr, (label,result.stderr)
            print('Original Local throughput causal control rejected: '+label)
        # A successful full-depth fixture necessarily crosses the old 16 KiB IPC cap.
        old = 'let limit = max(16384, 512 + 1536 * rowLimit)'
        assert source.count(old) == 1
        bad=work/'BadBudget.swift'; binary=work/'bad-budget'
        bad.write_text('import Foundation\n'+gate+fixture+source.replace(old,'let limit = 16384',1)+TEST)
        subprocess.run(['swiftc','-swift-version','6','-parse-as-library',str(bad),'-o',str(binary)],check=True,timeout=60)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=25)
        assert result.returncode and 'all original Local results reach the UI: local-maximum' in result.stderr, result.stderr
        print('Full-depth Local throughput causal control rejected: original 16 KiB IPC cap')
        forwarding='request: lease.request, idleOnly: idleOnly'
        assert fixture.count(forwarding)==1
        bad=work/'BadIdle.swift';bad_binary=work/'bad-idle'
        bad.write_text('import Foundation\n'+gate+fixture.replace(forwarding,'request: lease.request, idleOnly: false',1)+source+TEST)
        subprocess.run(['swiftc','-swift-version','6','-parse-as-library',str(bad),'-o',str(bad_binary)],check=True,timeout=60)
        result=subprocess.run([str(bad_binary)],capture_output=True,text=True,timeout=25)
        assert result.returncode != 0 and 'idle-only reservation reaches the matching native operation' in result.stderr, 'idle-only reservation was ignored or failed for another reason: '+result.stderr[-500:]
        print('Negative control: discarded idle-only admission rejected')

if __name__=='__main__':main()
