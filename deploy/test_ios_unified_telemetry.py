#!/usr/bin/env python3
"""Execute shipping iOS telemetry with explicit OS/socket boundaries.

The actual channel, HTTP transfer parser, app transaction, captures, controller,
MTU hold and ownership execute together. Socket callbacks can be held after
cancellation; the fixture rejects an acknowledgement before those callbacks
join. Darwin additionally typechecks the unchanged native adapter with iOS SDK.
"""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

from test_ios_dns_measurement import STORAGE, method

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "ios/RouterVPN/App"
TUNNEL = ROOT / "ios/RouterVPN/PacketTunnel"

BOUNDARIES = r'''
import Foundation
@propertyWrapper struct Published<Value>{var wrappedValue:Value;init(wrappedValue:Value){self.wrappedValue=wrappedValue}}
protocol ObservableObject:AnyObject{}
enum IOSDNSMeasurementStatus {
 static func issue(_ text:String)->NSError{IOSTelemetryProtocol.issue(text)}
}
enum IOSDNSRuntimePolicy {
 static func selectedProfile(in bundle:ClientBundle)->RouterProfile?{
  bundle.routerProfiles.first(where:{$0.id==bundle.selectedRouterID}) ?? bundle.routerProfiles.first
 }
}
enum NEVPNStatus { case connected,disconnected,connecting }
@MainActor class NEVPNConnection {var status:NEVPNStatus = .connected;var connectedDate:Date?=Date(timeIntervalSince1970:1000)}
@MainActor final class NETunnelProviderSession:NEVPNConnection {
 var handler:((Data,((Data?)->Void)?)->Void)?
 func sendProviderMessage(_ data:Data,responseHandler:((Data?)->Void)?=nil)throws{handler?(data,responseHandler)}
}
@MainActor final class NETunnelProviderProtocol {var providerBundleIdentifier:String?="com.eabusham.routervpn.PacketTunnel"}
@MainActor final class NETunnelProviderManager {
 static var all:[NETunnelProviderManager]=[],fail=false
 var protocolConfiguration:AnyObject?=NETunnelProviderProtocol()
 var connection:NEVPNConnection=NETunnelProviderSession()
 static func loadAllFromPreferences()async throws->[NETunnelProviderManager]{
  if fail{throw CancellationError()};return all
 }
}
@MainActor final class IOSViaEntryNetwork {
 static let shared=IOSViaEntryNetwork()
 var current:UInt64?=1,held=false
 private var waiting:CheckedContinuation<UInt64,Error>?
 func snapshot()async throws->UInt64{
  if held{return try await withCheckedThrowingContinuation{waiting=$0}}
  guard let current else{throw CancellationError()};return current
 }
 func release(){held=false;waiting?.resume(returning:current ?? 1);waiting=nil}
}
@MainActor enum IOSViaEntryTCP {
 static var probes=0,held=false,failAt:Int?,cancelled=false,observedOwner=false
 static var checkOwner:(()->Bool)?
 private static var waiting:CheckedContinuation<Double,Error>?
 static func reset(){probes=0;held=false;failAt=nil;cancelled=false;observedOwner=false;checkOwner=nil}
 static func endpointHost(_ text:String)->String{URLComponents(string:"tcp://"+text)?.host ?? text}
 static func probeDirect(host:String,port:UInt16,timeoutMS:Int,network:UInt64)async throws->Double{
  guard IOSViaEntryNetwork.shared.current==network else{throw CancellationError()}
  return try await probe(host:host,port:port,timeoutMS:timeoutMS)
 }
 static func probe(host:String,port:UInt16,timeoutMS:Int)async throws->Double{
  probes+=1;observedOwner = observedOwner || (checkOwner?() ?? false)
  if held {
   return try await withTaskCancellationHandler {
    try await withCheckedThrowingContinuation{waiting=$0}
   } onCancel:{Task{@MainActor in cancelled=true}}
  }
  try Task.checkCancellation()
  if probes==failAt{throw URLError(.timedOut)}
  return Double(probes)+0.125
 }
 static func drain(){held=false;let c=waiting;waiting=nil;if cancelled{c?.resume(throwing:CancellationError())}else{c?.resume(returning:1)}}
}
@MainActor final class IOSNodeBundleStore {
 static let shared=IOSNodeBundleStore()
 var records:[String:Data]=[:]
 func bundleData(containing id:String,current:ClientBundle?)->Data?{
  records.values.first{(try? JSONDecoder().decode(ClientBundle.self,from:$0).routerProfiles.contains(where:{$0.id==id})) == true}
 }
}
@MainActor final class RouterVPNModel {
 var connected=false,tunnelTransitioning=false,iosUserDisconnectInProgress=false,auto=false
 var bundle:ClientBundle?,entry:ClientBundle?,activeSessionIdentity:IOSSessionIdentity?
 var selectedMode="wg",selectedLogicalMode="fast",iosConnectGeneration=UUID()
 let iosSpeedLabOwnership=IOSSpeedLabOwnership()
 var activeEngine:String{activeSessionIdentity?.engine ?? ""}
 var unifiedSelectedProfile:RouterProfile?{bundle.flatMap{IOSDNSRuntimePolicy.selectedProfile(in:$0)}}
 var profileMutationBlocked:Bool{connected || tunnelTransitioning || iosUserDisconnectInProgress}
 var refresh:(()->Void)?
 var commits=0
 func refreshTunnelStatus()async{refresh?()}
 func iosMultihopEntryBundle(for source:ClientBundle)throws->ClientBundle{guard let entry else{throw CancellationError()};return entry}
 func externalRuntimeBundleData(source:ClientBundle,profile:RouterProfile)throws->Data{try JSONEncoder().encode(source)}
 func externalTorEntryData(source:ClientBundle)throws->Data?{try entry.map{try JSONEncoder().encode($0)}}
 // Durable-write correctness is executed against the actual store/model in
 // test_ios_node_store_transactions.py. This boundary observes publication.
 func commitNodeLatency(_ result:IOSLatencyResult,expectedRecord:Data,expectedSelection:Data,owner:UUID)throws{
  try iosSpeedLabOwnership.require(owner)
  guard !profileMutationBlocked,var value=bundle,let index=value.routerProfiles.firstIndex(where:{$0.id==result.id}),
   IOSNodeBundleStore.shared.bundleData(containing:result.id,current:bundle)==expectedRecord,
   try encoded(value)==expectedSelection else{throw CancellationError()}
  value.routerProfiles[index]=try result.applying(to:value.routerProfiles[index])
  bundle=value;IOSNodeBundleStore.shared.records[result.id]=try encoded(value);commits+=1
 }
}
func encoded(_ bundle:ClientBundle)throws->Data{let e=JSONEncoder();e.outputFormatting=[.sortedKeys];return try e.encode(bundle)}
func json(_ value:Any)throws->Data{try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
final class NetworkProofGuard:@unchecked Sendable {weak var owner:TelemetryProvider?}
final class TestPathMonitor {
 var hook:(()->Void)?
 func cancel(){let callback=hook;hook=nil;callback?()}
}
final class TestForwardingChannel {
 func activate(profile:[String:Any],proofID:String){}
 func invalidate(){}
}
enum RouterVPNTelemetryNativeConnection {
 static func factory(_ provider:TelemetryProvider,current:@escaping @Sendable()->Bool)->RouterVPNTelemetryChannel.Factory{
  let wire=provider.wire;return{current() ? wire.factory($0):nil}
 }
}
final class TelemetryProvider:@unchecked Sendable {
 let wire=TestWire(),pathProofOwnerLock=NSLock(),telemetryLock=NSLock()
 var pathProofGuard:NetworkProofGuard?,pathMonitor:TestPathMonitor?
 var telemetryChannel:RouterVPNTelemetryChannel?,telemetryProof:NetworkProofGuard?
 var forwardingChannel:TestForwardingChannel?=TestForwardingChannel()
 func activate(_ data:Data,captured:NetworkProofGuard?=nil){let proof=captured ?? pathProofGuard ?? NetworkProofGuard();proof.owner=self;enableForwarding(profileData:data,proofID:String(repeating:"a",count:64),captured:proof)}
 func release(_ proof:NetworkProofGuard){releasePathProofGuard(proof)}
 func clear(){clearPathProofGuard()}
 func channel()->RouterVPNTelemetryChannel?{currentTelemetryChannel()}
 // SHIPPING_PROVIDER_TELEMETRY
}
'''

SOCKETS = r'''
final class TestSocket:RouterVPNTelemetryConnection,@unchecked Sendable {
 private let lock=NSLock()
 private let parent:TestWire
 private var observer:(@Sendable(RouterVPNTelemetryConnectionState)->Void)?
 private var input=Data(),offset=0,header="",uploaded=0
 private var waiting:(@Sendable(Data?,Error?)->Void)?
 private var cancelRequested=false,retired=false
 let holdRead:Bool,holdCancel:Bool
 init(_ parent:TestWire,read:Bool,cancel:Bool){self.parent=parent;holdRead=read;holdCancel=cancel}
 func observe(_ update:@escaping @Sendable(RouterVPNTelemetryConnectionState)->Void){
  lock.lock();observer=update;lock.unlock();update(.connected)
 }
 func write(_ data:Data,completion:@escaping @Sendable(Error?)->Void){
  lock.lock()
  if header.isEmpty{
   header=String(decoding:data,as:UTF8.self);input=parent.response(header);parent.recordHeader(header)
  }else{uploaded+=data.count;parent.recordUpload(data.count)}
  lock.unlock();completion(nil)
 }
 func read(_ maximum:Int,completion:@escaping @Sendable(Data?,Error?)->Void){
  lock.lock()
  if holdRead && waiting==nil{waiting=completion;lock.unlock();return}
  let end=min(input.count,offset+maximum),data=Data(input[offset..<end]);offset=end
  lock.unlock();completion(data,nil)
 }
 func cancel(){
  lock.lock();cancelRequested=true;let callback=holdCancel ? nil:observer;lock.unlock();callback?(.cancelled)
 }
 func retire(){lock.lock();retired=true;observer=nil;lock.unlock();parent.retiredOne()}
 func releaseRead(){
  lock.lock();let callback=waiting;waiting=nil
  let end=min(input.count,offset+(64<<10)),data=Data(input[offset..<end]);offset=end
  lock.unlock();callback?(data,nil)
 }
 func releaseCancel(){lock.lock();let callback=cancelRequested ? observer:nil;lock.unlock();callback?(.cancelled)}
 func pending()->Bool{lock.lock();defer{lock.unlock()};return waiting != nil}
 func cancellation()->Bool{lock.lock();defer{lock.unlock()};return cancelRequested}
}
final class TestWire:@unchecked Sendable {
 private let lock=NSLock()
 private var sockets:[TestSocket]=[],headers:[String]=[],retired=0,uploaded=0
 var proof=String(repeating:"a",count:64)
 private var badProof=false,holdRead=false,holdCancel=false,malformed:String?
 func configure(bad:Bool=false,read:Bool=false,cancel:Bool=false,malformed:String?=nil){
  lock.lock();badProof=bad;holdRead=read;holdCancel=cancel;self.malformed=malformed;lock.unlock()
 }
 func factory(_ endpoint:RouterVPNForwardingPolicy.Endpoint)->RouterVPNTelemetryConnection?{
  lock.lock();let socket=TestSocket(self,read:holdRead,cancel:holdCancel);sockets.append(socket);lock.unlock();return socket
 }
 func recordHeader(_ value:String){lock.lock();headers.append(value);lock.unlock()}
 func recordUpload(_ count:Int){lock.lock();uploaded+=count;lock.unlock()}
 func retiredOne(){lock.lock();retired+=1;lock.unlock()}
 func snapshot()->([TestSocket],[String],Int,Int){lock.lock();defer{lock.unlock()};return(sockets,headers,retired,uploaded)}
 func response(_ header:String)->Data{
  lock.lock();let bad=badProof,malformed=malformed;lock.unlock()
  if let malformed{return Data(malformed.utf8)}
  let body:Data,kind:String
  if header.hasPrefix("GET /health "){
   body=try! json(["ok":true,"node_id":bad ? String(repeating:"b",count:64):proof,"proof":"router-vpn-private-agent-v1"]);kind="application/json"
  }else if header.hasPrefix("GET /api/benchmark/download?bytes=8388608 "){
   body=Data(repeating:97,count:IOSTelemetryProtocol.bytes);kind="application/octet-stream"
  }else if header.hasPrefix("POST /api/benchmark/upload "){
   body=try! json(["bytes":IOSTelemetryProtocol.bytes,"server_receive_ms":123.5]);kind="application/json"
  }else{return Data("HTTP/1.1 404 No\r\nContent-Length: 0\r\n\r\n".utf8)}
  return Data("HTTP/1.1 200 OK\r\nContent-Length: \(body.count)\r\nContent-Type: \(kind)\r\n\r\n".utf8)+body
 }
}
'''

TESTS = r'''
@MainActor @main struct Tests {
 static var checks=0
 static func fail(_ label:String)->Never{FileHandle.standardError.write(Data(("FAIL: "+label+"\n").utf8));exit(1)}
 static func check(_ label:String,_ value:@autoclosure()throws->Bool)throws{guard try value()else{fail(label)};checks+=1}
 static func rejects(_ label:String,_ work:()throws->Void)throws{do{try work()}catch{checks+=1;return};fail("accepted "+label)}
 static func rejectsAsync(_ label:String,_ work:()async throws->Void)async throws{do{try await work()}catch{checks+=1;return};fail("accepted "+label)}
 static func wait(_ label:String,_ value:()->Bool)async{
  for _ in 0..<7000{if value(){return};try? await Task.sleep(for:.milliseconds(1))};fail("timeout "+label)
 }
 static func profile(_ id:String="node")throws->RouterProfile{
  try JSONDecoder().decode(RouterProfile.self,from:json(["id":id,"name":"Node","node_kind":"router-vpn",
   "node_proof_id":String(repeating:"a",count:64),"endpoint":"198.51.100.5",
   "router_api":"http://10.8.0.1:8787","api_token":"private-node-token-1234567890",
   "adguard_ipv4":"10.8.0.1","adguard_ipv6":"fd08::1","socks_host":"10.8.0.1","socks_port":1080,
   "socks_username":"","socks_password":"","dns_mode":"home","dns_protocol":"udp","ipv6_mode":"on"]))
 }
 static func fixture()throws->RouterVPNModel{
  IOSDNSRetirementReceipts.shared.reset();IOSViaEntryNetwork.shared.current=1;IOSViaEntryTCP.reset()
  NETunnelProviderManager.all=[];NETunnelProviderManager.fail=false
  let model=RouterVPNModel(),p=try profile()
  var bundle=ClientBundle.empty;bundle.routerProfiles=[p];bundle.selectedRouterID=p.id
  bundle.endpoint=p.endpoint;bundle.routerAPI=p.routerAPI;bundle.apiToken=p.apiToken
  bundle.nodeProofID=p.nodeProofID!;bundle.adGuardIPv4=p.adGuardIPv4;bundle.adGuardIPv6=p.adGuardIPv6
  bundle.socks5Host=p.socksHost;bundle.socks5Port=p.socksPort
  model.bundle=bundle;IOSNodeBundleStore.shared.records=[p.id:try encoded(bundle)]
  IOSViaEntryTCP.checkOwner={model.iosSpeedLabOwnership.active}
  return model
 }
 static func channel(_ wire:TestWire,_ profile:RouterProfile)throws->RouterVPNTelemetryChannel{
  try RouterVPNTelemetryChannel(profile:JSONSerialization.jsonObject(with:JSONEncoder().encode(profile)) as! [String:Any],
   proofID:profile.nodeProofID!,factory:{wire.factory($0)})
 }
 static func command(_ operation:String,_ request:String,binding:IOSTelemetryProtocol.Binding?=nil,kind:String="")throws->Data{
  try json(["operation":operation,"request_id":request,"node_id":binding?.nodeID ?? "node",
   "session_id":binding?.providerSession ?? "","native_session_id":binding?.nativeSession ?? "","kind":kind])
 }
 static func reserve(_ channel:RouterVPNTelemetryChannel)throws->IOSTelemetryProtocol.Binding{
  let request=UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased()
  let data=channel.handle(try command("telemetry-info",request))!
  return try IOSTelemetryProtocol.Status.info(data,request:request,node:"node").binding
 }
 static func status(_ channel:RouterVPNTelemetryChannel,_ b:IOSTelemetryProtocol.Binding)throws->IOSTelemetryProtocol.Status?{
  try channel.handle(command("telemetry-status",b.request,binding:b)).map{try IOSTelemetryProtocol.Status.decode($0,binding:b)}
 }
 static func native(_ wire:TestWire)throws->(RouterVPNModel,NETunnelProviderSession,RouterVPNTelemetryChannel){
  let model=try fixture(),provider=try channel(wire,model.unifiedSelectedProfile!)
  model.connected=true
  model.activeSessionIdentity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1000),engine:"libbox",rawProfile:"wg",
   bundleData:encoded(model.bundle!),entryBundleData:nil)
  let manager=NETunnelProviderManager(),session=manager.connection as! NETunnelProviderSession
  let mtuSession=UUID().uuidString
  session.handler={data,reply in
   let object=try! JSONSerialization.jsonObject(with:data) as! [String:Any]
   let operation=object["operation"] as! String
   if operation.hasPrefix("mtu-"){
    reply?(try! json(["session_id":mtuSession,"ack_id":object["request_id"]!,
     "measurement_hold":operation != "mtu-release","measurement_ready":true,"measurement_lease":object["request_id"]!]))
   }else{reply?(provider.handle(data))}
  }
  NETunnelProviderManager.all=[manager]
  return(model,session,provider)
 }
 static func main()async throws {
  let model=try fixture(),telemetry=IOSUnifiedTelemetry()
  let result=try await telemetry.measureOne(model.unifiedSelectedProfile!,model:model,samples:50)
  try check("50 real direct samples reach atomic publisher",model.commits==1 && result.samples==50 && result.failed==0 && model.bundle!.routerProfiles[0].latencySamples==50)
  try check("direct probes own and finish without MTU mutation",IOSViaEntryTCP.observedOwner && !model.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held)
  let saved=model.bundle!.routerProfiles[0]
  IOSViaEntryTCP.reset();IOSViaEntryTCP.failAt=5
  try await rejectsAsync("partial direct benchmark") {_ = try await telemetry.measureOne(saved,model:model)}
  try check("partial result keeps previous durable metrics",model.commits==1 && model.bundle!.routerProfiles[0]==saved)
  IOSViaEntryTCP.reset()
  let light=await telemetry.measureAll([saved],model:model,samples:3)
  try check("light comparison cannot overwrite durable ranking",light.count==1 && model.commits==1 && model.bundle!.routerProfiles[0]==saved)
  try telemetry.requireDirectResultCurrent(model:model)
  IOSViaEntryNetwork.shared.current=2
  try rejects("network changed before fastest adoption"){try telemetry.requireDirectResultCurrent(model:model)}
  telemetry.invalidateResults(model:model)
  try check("stale direct cache cleared",telemetry.latencyByID.isEmpty)

  for drift in ["cancel","network","selection","mode","decision","source"] {
   let model=try fixture(),client=IOSUnifiedTelemetry()
   IOSViaEntryTCP.held=true
   let work=Task {try await client.measureOne(model.unifiedSelectedProfile!,model:model)}
   await wait("held direct probe"){IOSViaEntryTCP.probes>0}
   switch drift {
   case "cancel":client.cancel()
   case "network":IOSViaEntryNetwork.shared.current=2
   case "selection":model.bundle!.routerProfiles[0].name="newer"
   case "mode":model.selectedMode="different"
   case "decision":model.iosConnectGeneration=UUID()
   default:IOSNodeBundleStore.shared.records["node"]=Data("relinked".utf8)
   }
   await wait("direct cancellation \(drift)"){IOSViaEntryTCP.cancelled}
   try check("direct owner retained until real socket callback \(drift)",client.measuring && model.iosSpeedLabOwnership.active && model.commits==0)
   IOSViaEntryTCP.drain()
   try await rejectsAsync("discard direct drift \(drift)") {_ = try await work.value}
   try check("direct drain releases owner \(drift)",!model.iosSpeedLabOwnership.active && !client.measuring && model.commits==0)
  }

  do {
   let wire=TestWire(),(model,_,provider)=try native(wire),client=IOSUnifiedTelemetry()
   let rtt=try await client.measureCurrentRTT(model:model)
   try check("current RTT uses two independent proofs",rtt>0 && wire.snapshot().1.count==2 && wire.snapshot().1.allSatisfy{!$0.contains("Authorization:")})
   try check("every RTT socket retired before result",wire.snapshot().2==2 && !model.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held)
   model.iosConnectGeneration=UUID();client.invalidateResults(model:model)
   try check("new connection decision clears displayed RTT",client.livePathMs==nil)
   provider.close()
  }
  do {
   let wire=TestWire(),(model,_,provider)=try native(wire),client=IOSUnifiedTelemetry()
   let speed=try await client.speedTest(model:model)
   try check("speed uses real bounded download and upload",speed.downloadMbps>0 && speed.uploadMbps>0 && speed.bytes==8388608 && wire.snapshot().3==8388608)
   let headers=wire.snapshot().1
   try check("secrets sent only between verified health proofs",headers.count==4 && !headers[0].contains("Authorization:") && headers[1].contains("GET /api/benchmark/download?bytes=8388608 ") && headers[2].contains("POST /api/benchmark/upload ") && headers[1].contains("Authorization: Bearer private-node-token-1234567890") && !headers[3].contains("Authorization:"))
   try check("native speed joins all four sockets before release",wire.snapshot().2==4 && !model.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held)
   model.bundle!.routerProfiles[0].apiToken="newer";client.invalidateResults(model:model)
   try check("source change clears displayed speed",client.lastSpeedResult==nil)
   provider.close()
  }
  do {
   let wire=TestWire();wire.configure(bad:true)
   let (model,_,provider)=try native(wire),client=IOSUnifiedTelemetry()
   try await rejectsAsync("wrong node proof") {_ = try await client.speedTest(model:model)}
   try check("wrong private node never receives token",wire.snapshot().1.count==1 && !wire.snapshot().1[0].contains("Authorization:"))
   try check("failed proof cannot publish speed",client.lastSpeedResult==nil && !IOSMTUMeasurementGate.held && !model.iosSpeedLabOwnership.active)
   provider.close()
  }
  do {
   let wire=TestWire();wire.configure(read:true)
   let (model,_,provider)=try native(wire),client=IOSUnifiedTelemetry()
   let work=Task{try await client.speedTest(model:model)}
   await wait("speed native read"){wire.snapshot().0.first?.pending()==true}
   client.cancel()
   await wait("native cancelled"){wire.snapshot().0.first?.cancellation()==true}
   try await Task.sleep(for:.milliseconds(300))
   try check("cancel event alone is not read callback drain",client.measuring && model.iosSpeedLabOwnership.active && IOSMTUMeasurementGate.held && wire.snapshot().2==0)
   wire.snapshot().0.first!.releaseRead()
   try await rejectsAsync("cancelled pending native read"){_ = try await work.value}
   try check("late read drain releases speed owner and MTU",!client.measuring && !IOSMTUMeasurementGate.held && !model.iosSpeedLabOwnership.active && wire.snapshot().2==1)
   provider.close()
  }
  do {
   let wire=TestWire();wire.configure(read:true)
   let (model,session,provider)=try native(wire),client=IOSUnifiedTelemetry()
   let work=Task{try await client.speedTest(model:model)}
   await wait("system disconnect read"){wire.snapshot().0.first?.pending()==true}
   model.connected=false;session.status = .disconnected;provider.close()
   session.handler={_,reply in reply?(nil)}
   await wait("cleanup pending after lost IPC"){client.cleanupPending}
   try check("disconnect cannot invent native drain",client.measuring && model.iosSpeedLabOwnership.active && IOSMTUMeasurementGate.held)
   wire.snapshot().0.first!.releaseRead()
   try await rejectsAsync("system disconnect exact receipt"){_ = try await work.value}
   try check("disk cleanup releases without adopting timing",!client.measuring && !IOSMTUMeasurementGate.held && !model.iosSpeedLabOwnership.active && client.lastSpeedResult==nil && IOSDNSRetirementReceipts.shared.count()==1)
  }
  do {
   let wire=TestWire();wire.configure(read:true)
   let (model,session,provider)=try native(wire),client=IOSUnifiedTelemetry()
   let work=Task{try await client.speedTest(model:model)}
   await wait("transient storage read"){wire.snapshot().0.first?.pending()==true}
   IOSDNSRetirementReceipts.shared.configure(writable:false)
   model.connected=false;session.status = .disconnected;provider.close();session.handler={_,reply in reply?(nil)}
   wire.snapshot().0.first!.releaseRead()
   await wait("pending persist"){client.cleanupPending}
   try check("missing persisted acknowledgement retains owner",client.measuring && model.iosSpeedLabOwnership.active && IOSMTUMeasurementGate.held)
   IOSDNSRetirementReceipts.shared.configure(writable:true)
   try await rejectsAsync("retained provider retries storage without IPC"){_ = try await work.value}
   try check("same retired session persists after transient failure",IOSDNSRetirementReceipts.shared.count()==1 && !client.measuring && !IOSMTUMeasurementGate.held)
  }
  do {
   let wire=TestWire(),(model,session,provider)=try native(wire),client=IOSUnifiedTelemetry()
   let previous=session.handler!
   session.handler={data,reply in
    if (try? JSONSerialization.jsonObject(with:data) as? [String:Any])?["operation"] as? String == "telemetry-info"{client.cancel()}
    previous(data,reply)
   }
   try await rejectsAsync("cancel after info before start"){_ = try await client.speedTest(model:model)}
   try check("reserved lost-start nonce gets real no-worker drain",wire.snapshot().0.isEmpty && IOSDNSRetirementReceipts.shared.count()==1 && !model.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held)
   provider.close()
  }
  for drift in ["network","node-source","selection","decision","mode","session","entry"] {
   let wire=TestWire();wire.configure(read:true)
   let (model,session,provider)=try native(wire),client=IOSUnifiedTelemetry()
   if drift=="entry" {
    var entry=model.bundle!;entry.selectedRouterID="entry";entry.routerProfiles[0].id="entry";model.entry=entry
    model.activeSessionIdentity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1000),engine:"multihop-libbox",rawProfile:"wg",
     bundleData:encoded(model.bundle!),entryBundleData:encoded(entry))
   }
   let work=Task{try await client.speedTest(model:model)}
   await wait("drift native read \(drift)"){wire.snapshot().0.first?.pending()==true}
   switch drift {
   case "network":IOSViaEntryNetwork.shared.current=2
   case "node-source":model.bundle!.routerProfiles[0].apiToken="newer"
   case "selection":model.bundle!.selectedRouterID="another"
   case "decision":model.iosConnectGeneration=UUID()
   case "mode":model.auto=true
   case "session":session.connectedDate=Date(timeIntervalSince1970:2000)
   default:model.entry!.routerProfiles[0].apiToken="newer-entry"
   }
   await wait("native drift cancellation \(drift)"){wire.snapshot().0.first?.cancellation()==true}
   try check("drift keeps MTU owner through cleanup \(drift)",model.iosSpeedLabOwnership.active && IOSMTUMeasurementGate.held)
   wire.snapshot().0.first!.releaseRead()
   try await rejectsAsync("stale native measurement \(drift)"){_ = try await work.value}
   try check("drift publishes no stale speed \(drift)",client.lastSpeedResult==nil && !client.measuring && !IOSMTUMeasurementGate.held)
   provider.close()
  }
  do {
   let model=try fixture(),client=IOSUnifiedTelemetry()
   await client.refreshLivePath(model:model)
   try check("background refresh never connects an idle VPN",!model.connected && !model.iosSpeedLabOwnership.active && IOSViaEntryTCP.probes==0)
   let wire=TestWire(),(connected,_,provider)=try native(wire)
   client.showPerformance(true);await client.refreshLivePath(model:connected)
   try check("visible Performance does not race automatic refresh",wire.snapshot().0.isEmpty)
   client.showPerformance(false)
   let lease=IOSMTUMeasurementGate.acquire();await client.refreshLivePath(model:connected)
   try check("read-only refresh never changes another MTU lease",wire.snapshot().0.isEmpty && IOSMTUMeasurementGate.held)
   _ = IOSMTUMeasurementGate.release(lease);provider.close()
  }
  do {
   let wire=TestWire(),(model,_,provider)=try native(wire),client=IOSUnifiedTelemetry()
   let queued=Task{try await client.speedTest(model:model)}
   queued.cancel()
   try await rejectsAsync("queued sheet dismissal"){_ = try await queued.value}
   try check("cancelled queued action never starts native work",wire.snapshot().0.isEmpty && !model.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held)
   IOSViaEntryNetwork.shared.held=true
   let preparing=Task{try await client.speedTest(model:model)}
   await wait("capture started before snapshot"){client.measuring}
   client.cancel();IOSViaEntryNetwork.shared.release()
   try await rejectsAsync("dismissal during initial physical snapshot"){_ = try await preparing.value}
   try check("cancelled preparation cannot acquire a later native owner",wire.snapshot().0.isEmpty && !model.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held)
   IOSDNSRetirementReceipts.shared.configure(available:false)
   try await rejectsAsync("missing shared capability"){_ = try await client.speedTest(model:model)}
   try check("unavailable cleanup store prevents measurement work",wire.snapshot().0.isEmpty && !model.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held)
   IOSDNSRetirementReceipts.shared.reset();provider.close()
  }
  do {
   let wire=TestWire(),channel=try channel(wire,profile()),binding=try reserve(channel)
   let foreign=IOSTelemetryProtocol.Binding(request:binding.request,providerSession:UUID().uuidString,nativeSession:binding.nativeSession,nodeID:binding.nodeID)
   try check("foreign provider epoch cannot start",channel.handle(command("telemetry-start",foreign.request,binding:foreign,kind:"speed"))==nil)
   let foreignNative=IOSTelemetryProtocol.Binding(request:binding.request,providerSession:binding.providerSession,nativeSession:UUID().uuidString,nodeID:binding.nodeID)
   try check("independent native epoch cannot be swapped",channel.handle(command("telemetry-start",foreignNative.request,binding:foreignNative,kind:"speed"))==nil)
   channel.close()
   let cleanup=try status(channel,binding)!
   try check("stopped info reservation has exact durable cleanup",cleanup.complete && cleanup.drained && cleanup.results.isEmpty && IOSTelemetryProtocol.cleanupReceipt(binding) != nil)
   try check("retired channel cannot start reserved nonce",channel.handle(command("telemetry-start",binding.request,binding:binding,kind:"speed"))==nil)
  }
  do {
   IOSDNSRetirementReceipts.shared.reset()
   let provider=TelemetryProvider(),profile=try JSONEncoder().encode(profile())
   provider.activate(profile)
   try check("provider cannot activate telemetry before path proof",provider.telemetryChannel==nil)
   let old=NetworkProofGuard();provider.pathProofGuard=old;provider.pathMonitor=TestPathMonitor();provider.activate(profile)
   let oldChannel=provider.telemetryChannel!,oldBinding=try reserve(oldChannel)
   let next=NetworkProofGuard()
   provider.pathProofGuard=next
   try check("unproved replacement cannot expose old channel",provider.channel()==nil)
   provider.activate(profile,captured:old)
   try check("late old callback cannot activate on a newer proof",provider.telemetryChannel===oldChannel && provider.channel()==nil)
   provider.pathProofGuard=old
   provider.pathMonitor!.hook={provider.pathProofGuard=next;provider.pathMonitor=TestPathMonitor();provider.activate(profile)}
   provider.release(old)
   try check("late old-proof cleanup preserves newly proved channel",provider.telemetryProof===next && provider.telemetryChannel != nil && provider.telemetryChannel !== oldChannel)
   try check("replaced old channel retires its reserved request",try status(oldChannel,oldBinding)?.drained==true && IOSTelemetryProtocol.cleanupReceipt(oldBinding) != nil)
   let nextChannel=provider.telemetryChannel!,nextBinding=try reserve(nextChannel)
   provider.clear()
   try check("current proof clear retires exact current telemetry",provider.telemetryChannel==nil && provider.telemetryProof==nil && status(nextChannel,nextBinding)?.drained==true)
  }
  for wireReply in [
   "HTTP/1.1 302 Redirect\r\nContent-Length: 0\r\nContent-Type: application/json\r\n\r\n",
   "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n{}",
   "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}",
   "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\n\r\n{}",
   "HTTP/1.1 200 OK\r\nContent-Length: 20\r\nContent-Type: application/json\r\n\r\n{}",
   "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/html\r\n\r\n{}"
  ] {
   let wire=TestWire();wire.configure(malformed:wireReply)
   let provider=try channel(wire,profile()),binding=try reserve(provider)
   _ = provider.handle(try command("telemetry-start",binding.request,binding:binding,kind:"speed"))
   await wait("malformed native response drain"){(try? status(provider,binding))?.drained==true}
   let rejected=try status(provider,binding)!
   try check("malformed response never yields timing or authorization",rejected.results.isEmpty && rejected.failure != nil && wire.snapshot().1.allSatisfy{!$0.contains("Authorization:")})
   try check("malformed response still joins socket",wire.snapshot().2==1)
   provider.close()
  }
  do {
   let wire=TestWire(),provider=try channel(wire,profile())
   let first=try reserve(provider)
   for index in 0..<129 {
    let binding=index==0 ? first:try reserve(provider)
    let data=provider.handle(try command("telemetry-cancel",binding.request,binding:binding))!
    let receipt=try IOSTelemetryProtocol.Status.decode(data,binding:binding)
    try check("reserved requests retire without opening sockets",receipt.complete && receipt.drained && receipt.results.isEmpty)
    if index==128 {
     try check("bounded request table rotates both independent epochs",binding.providerSession != first.providerSession && binding.nativeSession != first.nativeSession)
     try check("old epoch cannot cross table rotation",provider.handle(command("telemetry-start",first.request,binding:first,kind:"speed"))==nil)
    }
   }
   try check("reservation cleanup is read only",wire.snapshot().0.isEmpty)
   provider.close()
  }
  print("iOS unified telemetry: PASS (\(checks) shipping Swift checks; native socket and OS boundaries doubled)")
 }
}
'''


def portable(text):
    return text.replace("import Combine\n", "").replace("@preconcurrency import NetworkExtension\n", "")


def native_read_check(swift):
    # This is an explicit API-shape boundary double, not an Apple SDK claim.
    # sdk_check below imports the actual Objective-C header and full adapter.
    source = (TUNNEL / "RouterVPNTelemetryNativeConnection.swift").read_text()
    read = method(source, "    func read(_ maximum: Int,")
    fixture = r'''
import Foundation
final class Socket {
 var requests:[(UInt,UInt)]=[]
 func readMinimumLength(_ minimum:UInt,maximumLength:UInt,
                        completionHandler:@escaping @Sendable(Data?,Error?)->Void){
  requests.append((minimum,maximumLength));completionHandler(Data([7]),nil)
 }
}
final class Adapter {
 let connection=Socket()
 __READ__
}
final class Reply:@unchecked Sendable {
 private let lock=NSLock()
 private var count=0,data:Data?,failed=false
 func record(_ data:Data?,_ error:Error?){
  lock.lock();defer{lock.unlock()};count+=1;self.data=data;failed=error != nil
 }
 func snapshot()->(Int,Data?,Bool){lock.lock();defer{lock.unlock()};return(count,data,failed)}
}
@main struct Test {
 static func main(){
  var checks=0
  func check(_ label:String,_ ok:Bool){precondition(ok,label);checks+=1}
  let adapter=Adapter(),reply=Reply()
  for maximum in [1,64<<10,Int.max] {
   let count=reply.snapshot().0
   adapter.read(maximum){reply.record($0,$1)}
   let response=reply.snapshot(),request=adapter.connection.requests.last!
   check("native read minimum stays one byte",request.0==1)
   check("native read limit retains every signed bit",request.1==UInt(maximum))
   check("valid read delivers exactly one callback",response.0==count+1)
   check("native read preserves data/error",response.1==Data([7]) && !response.2)
  }
  for maximum in [0,-1,Int.min] {
   let count=reply.snapshot().0,reads=adapter.connection.requests.count
   adapter.read(maximum){reply.record($0,$1)}
   let response=reply.snapshot()
   check("invalid signed limit never reaches native socket",adapter.connection.requests.count==reads)
   check("invalid read delivers exactly one callback",response.0==count+1)
   check("invalid read has an explicit error and no bytes",response.1==nil && response.2)
  }
  print("iOS telemetry native read adapter: PASS (\(checks) shipping method checks; UInt API boundary doubled)")
 }
}
'''.replace("__READ__", read)
    with tempfile.TemporaryDirectory(prefix="routervpn-telemetry-read-") as folder:
        work = Path(folder)
        path, binary = work / "Read.swift", work / "read"
        path.write_text(fixture)
        command = [swift, "-swift-version", "6", "-strict-concurrency=complete", "-parse-as-library", str(path), "-o", str(binary)]
        subprocess.run(command, check=True, timeout=90)
        subprocess.run([str(binary)], check=True, timeout=15)
        historical = fixture.replace("maximumLength: length", "maximumLength: maximum", 1)
        assert historical != fixture
        path.write_text(historical)
        rejected = subprocess.run(command, capture_output=True, text=True, timeout=90)
        assert rejected.returncode != 0 and "cannot convert value of type 'Int' to expected argument type 'UInt'" in rejected.stderr, \
            "historical signed native API call was not rejected by the Swift compiler"
        print("iOS telemetry native read adapter: historical Int-to-UInt compile failure reproduced")


def sdk_check(swift):
    if platform.system() != "Darwin":
        print("iOS telemetry real-SDK check: SKIP (required in Darwin native lane)")
        return
    sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="routervpn-telemetry-sdk-") as folder:
        value = (APP / "IOSViaEntryLatency.swift").read_text()
        selected = "import Foundation\n" + value[value.index("struct IOSViaEntryValue:"):value.index("@MainActor\nprivate struct IOSViaEntrySelection")]
        geometry = Path(folder) / "ViaEntryValue.swift"
        geometry.write_text(selected)
        subprocess.run([
            "xcrun", "--sdk", "iphoneos", "swiftc", "-typecheck", "-swift-version", "6",
            "-strict-concurrency=complete", "-target", "arm64-apple-ios17.0", "-sdk", sdk,
            "-module-cache-path", str(Path(folder) / "modules"),
            "-import-objc-header", str(TUNNEL / "RVPNTunnelTCPConnection.h"),
            str(APP / "IOSDNSRetirementReceipts.swift"), str(APP / "IOSTelemetryProtocol.swift"),
            str(TUNNEL / "RouterVPNForwardingPolicy.swift"),
            str(TUNNEL / "RouterVPNTelemetryTransport.swift"),
            str(TUNNEL / "RouterVPNTelemetryChannel.swift"),
            str(TUNNEL / "RouterVPNTelemetryNativeConnection.swift"),
            str(APP / "Models.swift"), str(APP / "IOSViaEntryTCP.swift"), str(geometry),
        ], check=True, timeout=150)
    print("iOS telemetry real-SDK check: PASS (unchanged native through-tunnel adapter and channel)")


def main():
    swift = shutil.which("swiftc")
    if not swift:
        raise SystemExit("swiftc required")
    native_read_check(swift)
    capture = (APP / "IOSDNSMeasurementClient.swift").read_text()
    capture = capture[capture.index("@MainActor struct IOSDNSMeasurementCapture"):capture.index("private final class IOSDNSMeasurementReply")]
    sources = [
        APP / "Models.swift", APP / "IOSSessionIdentity.swift", APP / "IOSSpeedLabOwnership.swift",
        APP / "IOSMTUMeasurementGate.swift", APP / "IOSNodeLatencyStatistics.swift",
        APP / "IOSTelemetryProtocol.swift", APP / "IOSNativeTelemetryTransaction.swift",
        TUNNEL / "RouterVPNForwardingPolicy.swift", TUNNEL / "RouterVPNTelemetryTransport.swift",
        TUNNEL / "RouterVPNTelemetryChannel.swift",
    ]
    text = BOUNDARIES + STORAGE + SOCKETS + capture
    provider = (TUNNEL / "PacketTunnelProvider.swift").read_text()
    lifecycle = "\n".join(method(provider, signature) for signature in [
        "    private func enableForwarding(", "    private func retireTelemetry(",
        "    private func releasePathProofGuard(", "    private func clearPathProofGuard(",
        "    private func currentPathProofGuard(",
        "    private func currentTelemetryChannel(",
    ])
    text = text.replace(" // SHIPPING_PROVIDER_TELEMETRY", lifecycle)
    for path in ["IOSMTUControl.swift", "IOSCurrentTelemetryCapture.swift", "IOSUnifiedTelemetry.swift"]:
        text += portable((APP / path).read_text())
    text += TESTS
    with tempfile.TemporaryDirectory(prefix="routervpn-unified-telemetry-") as folder:
        work = Path(folder)
        fixture = work / "Fixture.swift"
        fixture.write_text(text)
        command = [swift, "-swift-version", "6", "-strict-concurrency=complete", "-module-cache-path", str(work / "modules")]
        subprocess.run(command + [str(p) for p in sources] + [str(fixture), "-o", str(work / "test")], check=True, timeout=150)
        subprocess.run([str(work / "test")], check=True, timeout=180)
        # These controls must fail in the actual asynchronous ownership tests.
        transport = (TUNNEL / "RouterVPNTelemetryTransport.swift").read_text()
        assert "nativeCancelled, pendingIO == 0" in transport
        mutation = work / "TransportWithoutCallbackJoin.swift"
        mutation.write_text(transport.replace("nativeCancelled, pendingIO == 0", "nativeCancelled", 1))
        without_join = [mutation if p.name == "RouterVPNTelemetryTransport.swift" else p for p in sources]
        controls = [
            ("native callback join", without_join, text, "FAIL: cancel event alone is not read callback drain"),
            ("direct network source", sources, text.replace("network == nil || IOSViaEntryNetwork.shared.current == network, let bundle", "let bundle", 1), "FAIL: accepted network changed before fastest adoption"),
        ]
        for label, inputs, mutant, assertion in controls:
            fixture.write_text(mutant)
            subprocess.run(command + [str(p) for p in inputs] + [str(fixture), "-o", str(work / "negative")], check=True, timeout=150)
            result = subprocess.run([str(work / "negative")], capture_output=True, text=True, timeout=180)
            if result.returncode == 0 or assertion not in result.stdout + result.stderr:
                raise AssertionError(f"{label} mutation did not fail at its ownership assertion: {result.stdout} {result.stderr}")
            print(f"iOS telemetry {label} negative control: PASS (missing guard rejected)")
    sdk_check(swift)


if __name__ == "__main__":
    main()
