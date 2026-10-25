#!/usr/bin/env python3
"""Execute the shipping iOS startup admission, external handoff and Settings save.

Models, snapshots, startup selection, external preference/configuration handoff,
and Settings load/save are shipping Swift. NetworkExtension, private-store
publication and native proof completion are declared boundaries. This does not
start a VPN or claim physical device, background or device-boot acceptance.
"""
from pathlib import Path
import argparse
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'


def member(source, signature):
    begin = source.index(signature)
    cursor = source.index('{', begin) + 1
    depth = 1
    while depth:
        if source[cursor] == '{':
            depth += 1
        elif source[cursor] == '}':
            depth -= 1
        cursor += 1
    return source[begin:cursor]


BOUNDARIES = r'''
import Foundation

enum NEVPNStatus { case invalid, disconnected, connecting, connected, reasserting, disconnecting, unknown }
@MainActor class NEVPNConnection {
 var status = NEVPNStatus.disconnected
 var starts = 0,options:[String:NSObject]?
 var connectedDate:Date?
 func startVPNTunnel(options:[String:NSObject]?)throws { starts += 1; self.options=options;status = .connected;connectedDate=Date() }
}
@MainActor final class NETunnelProviderSession:NEVPNConnection { weak var manager:NETunnelProviderManager? }
@MainActor final class NETunnelProviderProtocol {
 var providerBundleIdentifier:String?,serverAddress:String?,providerConfiguration:[String:Any]?
 var includeAllNetworks=false,enforceRoutes=false,excludeLocalNetworks=false,excludeAPNs=false,excludeCellularServices=false
}
@MainActor final class NEOnDemandRuleConnect {}
@MainActor final class NETunnelProviderManager {
 static var instances:[NETunnelProviderManager]=[]
 static var loads=0
 static var hook:((String)async throws->Void)?
 var protocolConfiguration:Any?,localizedDescription:String?,isEnabled=false,isOnDemandEnabled=false
 var onDemandRules:[NEOnDemandRuleConnect]?=[]
 let connection:NEVPNConnection
 init(){let session=NETunnelProviderSession();connection=session;session.manager=self;Self.instances.append(self)}
 static func loadAllFromPreferences()async throws->[NETunnelProviderManager] {
  loads += 1; try await hook?("load-all"); return instances
 }
 func saveToPreferences()async throws { try await Self.hook?("save") }
 func loadFromPreferences()async throws { try await Self.hook?("load") }
 static func reset(){instances=[];loads=0;hook=nil}
 static var starts:Int {instances.reduce(0){$0+$1.connection.starts}}
}
enum IOSRuntimeSelectionError:Error {case unsupportedMode(String)}
enum IOSMAXSourceSelection {
 static func sourceHashes(provider:[String:Any],bridge:(String,String,String)throws->String)throws->[String:String]{[:]}
 static func issue()->NSError{NSError(domain:"NativeMAXBoundary",code:1)}
}
func LibboxRouterCheckMAXProfile(_ mode:String,_ assets:String,_ metadata:String,_ error:inout NSError?)->String?{"native-boundary"}
enum IOSMTUMeasurementGate {static let current=""}
@MainActor enum IOSPrivateJSONStore {
 static var value:Data?,failWrite=false
 static func read(_ filename:String,maximumBytes:Int)throws->Data?{value}
 static func write(_ data:Data,filename:String,maximumBytes:Int)throws {
  if failWrite{throw NSError(domain:"PrivateChoiceStoreBoundary",code:1)}
  guard data.count<=maximumBytes else{throw CancellationError()};value=data
 }
}
@MainActor final class FixturePreferences {
 static let standard=FixturePreferences()
 var values:[String:Data]=[:]
 func data(forKey key:String)->Data?{values[key]}
 func set(_ data:Data,forKey key:String){values[key]=data}
 func removeObject(forKey key:String){values.removeValue(forKey:key)}
}
@MainActor enum IOSMTUControl {
 static var hook:((NETunnelProviderSession,String,Data)async throws->Data)?
 static var winner="server",captures=0
 static func failure(_ text:String)->NSError{NSError(domain:"MTUBoundary",code:1,userInfo:[NSLocalizedDescriptionKey:text])}
 static func capture(_ model:RouterVPNModel)async throws->Int{captures+=1;return captures}
 static func message(_ binding:Int,model:RouterVPNModel,operation:String,request:String)async throws->Data {
  try JSONSerialization.data(withJSONObject:["measurement_hold":true,"measurement_lease":request,"measurement_ready":true])
 }
 // SHIPPING_MTU_HOLD
 static func send(_ connection:NETunnelProviderSession,operation:String,request:String,session:String)async throws->Data {
  guard operation=="speed-lab-execution",session.isEmpty,let config=(connection.manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration else{throw CancellationError()}
  let source=try IOSMultihopExecution.Source(configuration:config,digest:RouterVPNModel.iosStrategyDigest)
  let receipt=try IOSMultihopExecution.Capture(source:source,execution:winner,session:UUID().uuidString,request:request).encoded()
  return try await hook?(connection,request,receipt) ?? receipt
 }
}
enum IOSDNSRuntimePolicy {
 // SELECTED_PROFILE
}
private struct IOSLastRuntime:Codable {let routerID:String,rawProfileID:String,logicalModeID:String}
@MainActor final class RouterVPNModel {
 var bundle:ClientBundle?,entry:ClientBundle?
 var connected=false,tunnelTransitioning=false,iosUserDisconnectInProgress=false
 var profileMutationBlocked:Bool{connected || tunnelTransitioning || iosUserDisconnectInProgress}
 var iosConnectGeneration=UUID(),message="",auto=false,activeRawProfile="",activeEngine="libbox",imports=0,failImport=false
 var routerDispatches:[String]=[]
 var routerHook:(()async->Void)?
 let iosStartupPolicy=IOSStartupPolicy(),iosSpeedLabOwnership=IOSSpeedLabOwnership()
 var iosStrategyProfile:RouterProfile?{selectedNodeProfile}
 static func iosStrategyDigest(_ data:Data)->String {let hash=data.reduce(UInt64(14695981039346656037)){($0 ^ UInt64($1)) &* 1099511628211};return String(repeating:String(format:"%016llx",hash),count:4)}
 func connect()async{await routerHook?();guard await iosSpeedLabOwnership.admitConnection()else{return};routerDispatches.append(auto ? "auto":"manual")}
 func runIOSSmartAuto()async{await routerHook?();guard await iosSpeedLabOwnership.admitConnection()else{return};routerDispatches.append("smart-auto")}
 func connectIOSRawCandidate(_ id:String)async->Bool{
  guard await iosSpeedLabOwnership.admitConnection()else{return false};routerDispatches.append(id)
  iosConnectGeneration=UUID();IOSSpeedLabContext.startupClaimed?(iosConnectGeneration);await routerHook?();return false
 }
 func recordIOSLastRuntime(){}
 func refreshTunnelStatus()async {
  connected=NETunnelProviderManager.instances.contains{$0.connection.status == .connected}
  tunnelTransitioning=false
 }
 func iosMultihopEntryBundle(for source:ClientBundle)throws->ClientBundle {
  guard let profile=IOSDNSRuntimePolicy.selectedProfile(in:source),let entry,
    entry.selectedRouterID==profile.multihopEntryID,profile.multihopExitID==profile.id,
    profile.multihopExitMode==profile.external?.protocolName else{throw CancellationError()}
  return entry
 }
 func importBundle(_ data:Data)throws {
  if failImport{throw NSError(domain:"PrivateStoreBoundary",code:1)}
  bundle=try JSONDecoder().decode(ClientBundle.self,from:data);imports+=1
 }
 // SHIPPING_MODEL
}
@MainActor final class Settings {
 let model:RouterVPNModel
 var loadedProfile:RouterProfile?,homeLANAccess=true,killSwitchPolicy="off",ipv6Mode="on",baseTunnel="auto",baseFallback=false
 var startLayer="off",autoRequireEncrypted=false,autoRequireObfuscation=false,mtuPolicy="auto",manualMTU=""
 var daitaEnabled=false,jumboTUN=false,startupMode="smart-auto",autoConnect=false,status=""
 init(_ model:RouterVPNModel){self.model=model}
 // SHIPPING_SETTINGS
}
'''

TESTS = r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ condition:@autoclosure ()throws->Bool)throws {
  guard try condition()else{throw NSError(domain:"StartupFixture",code:1,userInfo:[NSLocalizedDescriptionKey:name])};checks+=1
 }
 static func encoded(_ value:ClientBundle)throws->Data{let e=JSONEncoder();e.outputFormatting=[.sortedKeys];return try e.encode(value)}
 static func profile(_ kind:String="shadowsocks")->RouterProfile {
  let tor=["tor","tor-bridge"].contains(kind)
  let object:[String:Any]=["id":"exit","name":"Captured exit","node_kind":"external","endpoint":"198.51.100.8",
   "router_api":"","api_token":"private-api-field","adguard_ipv4":"","adguard_ipv6":"","socks_host":"","socks_port":0,"socks_username":"","socks_password":"private-legacy-field",
   "external":["protocol":kind,"expected_public_ip":tor ? "":"203.0.113.8","shadowsocks":["server":"198.51.100.8","port":8388,"method":"2022-blake3-aes-256-gcm","password":"exact external credential"],"openvpn":["config":"captured inline provider profile","username":"owned-user","password":"owned-password"],"response_probe":["url":"https://198.51.100.8/response","server_name":"node.example.test"]],
   "dns_mode":"custom","dns_protocol":"tcp","dns_host":"9.9.9.9","dns_port":5353,"dns_server_name":"","dns_path":"/captured-query",
   "home_lan_access":false,"kill_switch_policy":"off","kill_switch":false,"ipv6_mode":"off","start_layer":"off","mtu_policy":"manual","manual_mtu":1380,
   "startup_mode":"smart-auto","auto_connect":true]
  return try! JSONDecoder().decode(RouterProfile.self,from:JSONSerialization.data(withJSONObject:object))
 }
 static func bundle(_ profile:RouterProfile)->ClientBundle {
  var b=ClientBundle.empty;b.selectedRouterID=profile.id;b.routerProfiles=[profile];b.endpoint=profile.endpoint
  b.profiles=["owned":["private.conf":Data("private node assets".utf8).base64EncodedString()]];return b
 }
 static func model(_ p:RouterProfile)->RouterVPNModel {NETunnelProviderManager.reset();let m=RouterVPNModel();m.bundle=bundle(p);return m}
 static func attachEntry(_ m:RouterVPNModel,execution:String="local") {
  var entry=profile("wireguard");entry.id="entry";entry.nodeKind="router-vpn";entry.routerAPI="http://10.8.0.1:8787";entry.apiToken="independent entry key"
  m.entry=bundle(entry)
  m.bundle!.routerProfiles[0].multihopEnabled=true;m.bundle!.routerProfiles[0].multihopEntryID="entry";m.bundle!.routerProfiles[0].multihopEntryMode="wg"
  m.bundle!.routerProfiles[0].multihopExitID="exit";m.bundle!.routerProfiles[0].multihopExitMode=m.bundle!.routerProfiles[0].external!.protocolName
  m.bundle!.routerProfiles[0].multihopExecution=execution
 }
 static func ordinary()async throws {
  for kind in ["wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn","tor","tor-bridge"] {
   for choice in ["smart-auto","auto","last"] {
    var p=profile(kind);p.startupMode=choice
    let m=model(p),before=try encoded(m.bundle!)
    await m.applyIOSStartupPolicyIfNeeded()
    try check("external startup dispatch "+kind+" "+choice,NETunnelProviderManager.starts==1 && m.routerDispatches.isEmpty && m.connected)
    try check("startup did not rewrite saved policy or private assets",try encoded(m.bundle!)==before && m.imports==0)
    let manager=NETunnelProviderManager.instances[0],proto=manager.protocolConfiguration as! NETunnelProviderProtocol
    let saved=try JSONDecoder().decode(ClientBundle.self,from:proto.providerConfiguration!["bundle"] as! Data)
    try check("exact imported transport and credentials reach PacketTunnel",saved.routerProfiles[0].external==p.external && saved.routerProfiles[0].dnsHost==p.dnsHost && saved.routerProfiles[0].manualMTU==p.manualMTU)
    try check("app launch does not enable on-demand without strict policy",!manager.isOnDemandEnabled && !proto.includeAllNetworks)
    m.connected=false;manager.connection.status = .disconnected;await m.applyIOSStartupPolicyIfNeeded()
    try check("view recreation cannot repeat startup",NETunnelProviderManager.starts==1)
   }
  }
  for kind in ["shadowsocks","openvpn"] {for execution in ["local","server","auto"] {
   let m=model(profile(kind));attachEntry(m,execution:execution)
   let before=try encoded(m.bundle!),entry=try encoded(m.entry!)
   await m.applyIOSStartupPolicyIfNeeded()
   try check("saved execution dispatch "+kind+" "+execution,NETunnelProviderManager.starts==1)
   let config=(NETunnelProviderManager.instances[0].protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
   let saved=try JSONDecoder().decode(ClientBundle.self,from:config["bundle"] as! Data)
   try check("complete entry retained",config["external_entry_bundle"] as? Data==entry && config["external_entry_mode"] as? String=="wg")
   try check("execution and saved policy never substituted",saved.routerProfiles[0].multihopExecution==execution && (try encoded(m.bundle!))==before)
  }}
  for kind in ["tor","tor-bridge"] {
   let m=model(profile(kind));attachEntry(m);await m.applyIOSStartupPolicyIfNeeded()
   let config=(NETunnelProviderManager.instances[0].protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
   try check("Tor startup uses its exact captured predecessor",NETunnelProviderManager.starts==1 && config["tor_entry_bundle"] as? Data == (try encoded(m.entry!)) && config["external_entry_bundle"]==nil)
  }
 }
 static func disabled()async throws {
  for choice in ["smart-auto","auto","last","manual"] {for enabled in [false,true] where !enabled || choice=="manual" {
   var p=profile();p.startupMode=choice;p.autoConnect=enabled;let m=model(p);await m.applyIOSStartupPolicyIfNeeded()
   try check("Off or Manual makes no VPN preference request",NETunnelProviderManager.loads==0 && NETunnelProviderManager.starts==0)
  }}
  var bad=profile();bad.startupMode="invented";let m=model(bad);await m.applyIOSStartupPolicyIfNeeded()
  try check("unknown startup cannot become another choice",NETunnelProviderManager.loads==0 && m.message.contains("invalid"))
  for state in [NEVPNStatus.connected,.connecting,.reasserting,.disconnecting,.unknown] {
   let m=model(profile()),foreign=NETunnelProviderManager(),proto=NETunnelProviderProtocol();proto.providerBundleIdentifier="other.provider";foreign.protocolConfiguration=proto;foreign.connection.status=state
   await m.applyIOSStartupPolicyIfNeeded()
   try check("an active or unverified available manager prevents startup",NETunnelProviderManager.starts==0 && NETunnelProviderManager.loads==1 && foreign.protocolConfiguration as? NETunnelProviderProtocol === proto)
  }
  let failed=model(profile());NETunnelProviderManager.hook={_ in throw NSError(domain:"PreferencesBoundary",code:1)}
  await failed.applyIOSStartupPolicyIfNeeded()
  try check("preference enumeration failure never means no VPN",NETunnelProviderManager.starts==0 && NETunnelProviderManager.loads==1)
  let held=model(profile());let owner=try held.iosSpeedLabOwnership.begin(onSuperseded:{fatalError("startup superseded measurement")})
  await held.applyIOSStartupPolicyIfNeeded()
  try check("startup cannot supersede a temporary test",held.iosSpeedLabOwnership.current(owner) && NETunnelProviderManager.loads==0)
 }
 static func stale()async throws {
  for fault in ["selection","dns","credentials","entry","execution","generation","disconnect","test-owner"] {
   let m=model(profile());attachEntry(m);var changed=false
   NETunnelProviderManager.hook={stage in
    guard stage=="load-all",!changed else{return};changed=true
    switch fault {
    case "selection":m.bundle!.selectedRouterID="replacement"
    case "dns":m.bundle!.routerProfiles[0].dnsHost="1.1.1.1"
    case "credentials":m.bundle!.routerProfiles[0].external!.shadowsocks!.password="replacement key"
    case "entry":m.entry!.routerProfiles[0].apiToken="replacement entry key"
    case "execution":m.bundle!.routerProfiles[0].multihopExecution="server"
    case "generation":m.iosConnectGeneration=UUID()
    case "disconnect":m.iosUserDisconnectInProgress=true
    default:_ = try m.iosSpeedLabOwnership.begin(onSuperseded:{fatalError("startup cancelled replacement test")})
    }
   }
   await m.applyIOSStartupPolicyIfNeeded()
   try check("changed startup capture rejected: "+fault,NETunnelProviderManager.starts==0 && NETunnelProviderManager.loads==1 && m.imports==0)
  }
  let cancelled=model(profile());var release:CheckedContinuation<Void,Never>?
  NETunnelProviderManager.hook={stage in if stage=="load-all" {await withCheckedContinuation{release=$0}}}
  let task=Task{@MainActor in await cancelled.applyIOSStartupPolicyIfNeeded()}
  for _ in 0..<1000 {if release != nil{break};await Task.yield()}
  try check("startup suspension observed",release != nil);task.cancel();release!.resume();await task.value
  try check("cancelled launch cannot resume into a VPN",NETunnelProviderManager.starts==0)
  let refused=model(profile());await refused.connectSelectedExternal(startupAdmission:{false})
  try check("external entry checks startup admission before preparing",NETunnelProviderManager.loads==0 && NETunnelProviderManager.starts==0)
  let raced=model(profile())
  NETunnelProviderManager.hook={stage in
   guard stage=="load" else{return}
   let foreign=NETunnelProviderManager(),proto=NETunnelProviderProtocol();proto.providerBundleIdentifier="new.other.provider"
   foreign.protocolConfiguration=proto;foreign.connection.status = .connected
  }
  await raced.applyIOSStartupPolicyIfNeeded()
  try check("new available VPN during permission is not replaced",NETunnelProviderManager.starts==0)
  for fault in ["generation","entry","source"] {
   let m=model(profile());attachEntry(m)
   NETunnelProviderManager.hook={stage in guard stage=="save" else{return};switch fault {
    case "generation":m.iosConnectGeneration=UUID()
    case "entry":m.entry!.routerProfiles[0].apiToken="changed while permission was pending"
    default:m.bundle!.routerProfiles[0].dnsHost="changed while permission was pending"
   }}
   await m.applyIOSStartupPolicyIfNeeded()
   try check("permission handoff retains captured ownership: "+fault,NETunnelProviderManager.starts==0)
  }
 }
 static func settings()throws {
  for kind in ["wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn","tor","tor-bridge"] {
   let m=model(profile(kind));attachEntry(m);let before=m.bundle!,view=Settings(m);view.load();view.startupMode="last";view.autoConnect=true;view.save()
   var expected=before;expected.routerProfiles[0].startupMode="last";expected.routerProfiles[0].autoConnect=true
   try check("external Settings saves only startup fields: "+kind,m.imports==1 && (try encoded(m.bundle!))==encoded(expected))
   view.startupMode="manual";view.save()
   try check("Manual disables auto-connect without dropping the path",m.imports==2 && m.bundle!.routerProfiles[0].autoConnect==false && m.bundle!.routerProfiles[0].multihopEntryID=="entry")
   view.startupMode="unknown";view.save();try check("invalid editor choice cannot overwrite settings",m.imports==2)
  }
  for fault in ["selection","profile","busy","write"] {
   let m=model(profile()),view=Settings(m);view.load();view.startupMode="last"
   switch fault {
   case "selection":m.bundle!.selectedRouterID="other"
   case "profile":m.bundle!.routerProfiles[0].dnsHost="new choice"
   case "busy":m.tunnelTransitioning=true
   default:m.failImport=true
   }
   let before=try encoded(m.bundle!);view.save()
   try check("editor preserves replacement or failed state: "+fault,m.imports==0 && (try encoded(m.bundle!))==before)
  }
 }
 static func router()async throws {
  for mode in ["auto","smart-auto"] {
   var p=profile();p.nodeKind="router-vpn";p.startupMode=mode;let m=model(p);await m.applyIOSStartupPolicyIfNeeded()
   try check("Router startup retains existing strategy dispatch",m.routerDispatches==[mode] && NETunnelProviderManager.starts==0)
  }
  for mode in ["auto","smart-auto"] {for fault in ["source","entry","generation","test-owner","disconnect"] {
   var p=profile();p.nodeKind="router-vpn";p.startupMode=mode;let m=model(p)
   m.routerHook={switch fault {
    case "source":m.bundle!.routerProfiles[0].dnsHost="replacement saved DNS"
    case "entry":m.bundle!.routerProfiles[0].multihopEnabled=true
    case "generation":m.iosConnectGeneration=UUID()
    case "disconnect":m.iosUserDisconnectInProgress=true
    default:_ = try! m.iosSpeedLabOwnership.begin(onSuperseded:{fatalError("startup cancelled a newly admitted Speed Lab test")})
   }}
   await m.applyIOSStartupPolicyIfNeeded()
   try check("Router startup revalidates at nested admission "+mode+" "+fault,m.routerDispatches.isEmpty)
  }}
  for superseded in [false,true] {
   var p=profile();p.nodeKind="router-vpn";p.startupMode="last";let m=model(p)
   UserDefaults.standard.set(try JSONEncoder().encode(IOSLastRuntime(routerID:p.id,rawProfileID:"wg",logicalModeID:"base-raw")),forKey:"router-vpn.ios.last-runtime-v1")
   if superseded {m.routerHook={m.iosConnectGeneration=UUID()}}
   await m.applyIOSStartupPolicyIfNeeded()
   try check("Last fallback keeps only its own generation "+String(superseded),m.routerDispatches == (superseded ? ["wg"]:["wg","auto"]))
  }
  UserDefaults.standard.removeObject(forKey:"router-vpn.ios.last-runtime-v1")
  let delayed=model(profile()),replacement=NETunnelProviderManager();replacement.connection.status = .connected
  IOSMTUControl.captures=0
  var refused=false
  do {try await IOSSpeedLabContext.$startupAdmission.withValue({!delayed.connected}) {
   try await IOSMTUControl.holdCurrent(delayed,request:String(repeating:"f",count:32))
  }}catch{refused=true}
  try check("startup MTU admission cannot touch newly active owner",refused && IOSMTUControl.captures==0)
  try await IOSMTUControl.holdCurrent(delayed,request:String(repeating:"f",count:32))
  try check("ordinary MTU ownership remains available",IOSMTUControl.captures==1)
 }
 static func lastChoice()async throws {
  IOSPrivateJSONStore.value=nil;IOSMTUControl.hook=nil;IOSMTUControl.winner="server"
  var p=profile();p.startupMode="manual";p.autoConnect=false
  let first=model(p);attachEntry(first,execution:"auto");await first.connectSelectedExternal()
  guard let remembered=IOSPrivateJSONStore.value else{throw NSError(domain:"StartupFixture",code:1,userInfo:[NSLocalizedDescriptionKey:"manual proved Compare records Last choice"])}
  let text=String(decoding:remembered,as:UTF8.self),object=try JSONSerialization.jsonObject(with:remembered) as! [String:Any]
  let records=object["records"] as! [[String:Any]]
  try check("Last record has only hashes and proved choice",records.count==1 && Set(records[0].keys)==Set(["node","bundle","entry","execution"]) && records[0]["execution"] as? String=="server" && !text.contains("credential") && !text.contains("private") && !text.contains("Captured exit") && !text.contains("request_id") && !text.contains("session_id"))
  let saved=first.bundle!,entry=first.entry!
  for mode in ["last","auto","smart-auto"] {
   IOSPrivateJSONStore.value=remembered
   let m=model(p);m.bundle=saved;m.entry=entry;m.bundle!.routerProfiles[0].startupMode=mode;m.bundle!.routerProfiles[0].autoConnect=true
   m.entry!.routerProfiles[0].startupMode="last";m.entry!.routerProfiles[0].autoConnect=true
   m.bundle!.routerProfiles[0].effectiveMTU=1440;m.bundle!.routerProfiles[0].effectiveMTUSource="historical-readback"
   m.entry!.routerProfiles[0].effectiveMTUTestedAt="historical-time";m.entry!.routerProfiles[0].effectiveMTUMbps=42
   await m.applyIOSStartupPolicyIfNeeded()
   let manager=NETunnelProviderManager.instances[0],config=(manager.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
   let source=try IOSMultihopExecution.Source(configuration:config,digest:RouterVPNModel.iosStrategyDigest)
   let option=manager.connection.options?[IOSMultihopExecution.startupLaunchKey]
   let result=try IOSMultihopExecution.restoredStartupExecution(option:option,source:source)
   try check("only Last keeps proved Compare choice "+mode,result == (mode=="last" ? "server":nil) && m.connected && m.bundle!.routerProfiles[0].multihopExecution=="auto")
   try check("startup choice has no Speed Lab restoration or measurement lease",manager.connection.options?[IOSMultihopExecution.launchKey]==nil && manager.connection.options?["routervpn_mtu_hold"]==nil)
  }
  for fault in ["missing","corrupt","dns","key","entry-key","mtu","ipv6","kill-switch","entry-mode"] {
   IOSPrivateJSONStore.value=fault=="missing" ? nil:fault=="corrupt" ? Data("{}".utf8):remembered
   let m=model(p);m.bundle=saved;m.entry=entry;m.bundle!.routerProfiles[0].startupMode="last";m.bundle!.routerProfiles[0].autoConnect=true
   switch fault {
   case "dns":m.bundle!.routerProfiles[0].dnsHost="8.8.8.8"
   case "key":m.bundle!.routerProfiles[0].external!.shadowsocks!.password="new captured private key"
   case "entry-key":m.entry!.routerProfiles[0].apiToken="new captured entry key"
   case "mtu":m.bundle!.routerProfiles[0].manualMTU=1400
   case "ipv6":m.bundle!.routerProfiles[0].ipv6Mode="on"
   case "kill-switch":m.bundle!.routerProfiles[0].killSwitch=true
   case "entry-mode":m.bundle!.routerProfiles[0].multihopEntryMode="awg2-strong"
   default:break
   }
   await m.applyIOSStartupPolicyIfNeeded()
   try check("missing or changed Last evidence uses saved fresh selection "+fault,NETunnelProviderManager.starts==1 && NETunnelProviderManager.instances[0].connection.options?[IOSMultihopExecution.startupLaunchKey]==nil && m.bundle!.routerProfiles[0].multihopExecution=="auto")
  }
  for fault in ["request","health","source","generation","entry","date","disconnect","test-owner","write"] {
   IOSPrivateJSONStore.value=nil;IOSPrivateJSONStore.failWrite=fault=="write"
   let m=model(p);m.bundle=saved;m.entry=entry
   IOSMTUControl.hook={connection,request,receipt in
    switch fault {
    case "generation":m.iosConnectGeneration=UUID()
    case "entry":m.entry!.routerProfiles[0].apiToken="changed while receipt was pending"
    case "date":connection.connectedDate=Date(timeIntervalSince1970:0)
    case "disconnect":connection.status = .disconnected;m.iosUserDisconnectInProgress=true
    case "test-owner":_ = try m.iosSpeedLabOwnership.begin(onSuperseded:{fatalError("receipt superseded test")})
    case "write":break
    default:
     var value=try JSONSerialization.jsonObject(with:receipt) as! [String:Any]
     if fault=="request"{value["request_id"]=String(repeating:"a",count:32)}
     if fault=="health"{value["healthy"]=false}
     if fault=="source"{var source=value["source"] as! [String:Any];source["entry_sha256"]=String(repeating:"0",count:64);value["source"]=source}
     return try JSONSerialization.data(withJSONObject:value)
    }
    return receipt
   }
   await m.connectSelectedExternal()
   try check("Last cannot save stale or unproved provider evidence "+fault,IOSPrivateJSONStore.value==nil)
   if fault=="write"{try check("failed history save cannot destroy proved connection",m.connected && NETunnelProviderManager.instances[0].connection.status == .connected)}
  }
  IOSMTUControl.hook=nil;IOSPrivateJSONStore.failWrite=false;IOSPrivateJSONStore.value=nil
 }
 static func main()async {
  do {try await ordinary();try await disabled();try await stale();try settings();try await router();try await lastChoice();print("iOS cold-launch startup and external Settings: \(checks) executable checks PASS")}
  catch {FileHandle.standardError.write(Data(("FAIL: "+error.localizedDescription+"\n").utf8));exit(1)}
 }
}
'''


def source():
    strategy = (APP / 'IOSStrategySupport.swift').read_text()
    external = (APP / 'RouterVPNModelExternal.swift').read_text()
    settings = (APP / 'IOSProfileSettingsView.swift').read_text()
    dns = (APP / 'IOSDNSRuntimePolicy.swift').read_text()
    snippets = [member(strategy, signature) for signature in (
        'func applyIOSStartupPolicyIfNeeded()', 'private func runIOSRouterStartup(', 'private func iosStartupCapture()',
        'private func iosStartupMatches(_ captured:', 'private func iosStartupMatches(_ intent:')]
    snippets += [member(external, signature) for signature in (
        'var selectedNodeProfile:', 'var selectedNodeIsExternal:', 'var selectedExternalProtocol:',
        'var selectedExternalSupportedOnIOS:', 'func connectSelectedExternal()',
        'func connectSelectedExternal(startupAdmission:',
        'private func rememberIOSExternalExecution(',
        'private func requireExternalPreparation(', 'func externalTorEntryData(',
        'func externalRuntimeBundleData(', 'private func externalStrict(',
        'private func waitExternalConnection(')]
    editor = '\n'.join(member(settings, signature).replace('private func ', 'func ') for signature in (
        'private func selectedProfile()', 'private func load()', 'private func save()'))
    mtu = (APP / 'IOSMTUControl.swift').read_text()
    return (BOUNDARIES.replace('// SHIPPING_MTU_HOLD', member(mtu, 'static func holdCurrent(')).replace('// SELECTED_PROFILE', member(dns, 'static func selectedProfile(')).replace(
        '// SHIPPING_MODEL', '\n'.join(snippets)).replace('// SHIPPING_SETTINGS', editor) + TESTS).replace(
        'UserDefaults.standard', 'FixturePreferences.standard')


def run_fixture(directory, swift, expected=None):
    directory.mkdir()
    fixture = directory / 'Fixture.swift'
    fixture.write_text(swift)
    executable = directory / 'fixture'
    command = ['swiftc', '-swift-version', '6', '-Onone', '-whole-module-optimization', '-parse-as-library', '-module-cache-path', str(directory.parent / 'modules'),
               str(APP / 'Models.swift'), str(APP / 'IOSStartupPolicy.swift'),
               str(APP / 'IOSDevicePolicySettings.swift'),
               str(APP / 'IOSMultihopExecution.swift'), str(APP / 'IOSStartupLastChoice.swift'),
               str(APP / 'IOSSpeedLabOwnership.swift'), str(fixture), '-o', str(executable)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=45)
    if expected is not None:
        if result.returncode != 1 or expected not in result.stderr:
            raise AssertionError('Defect mutation missed its intended failure: ' + result.stdout + result.stderr)
    elif result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    else:
        print(result.stdout.strip(), flush=True)


def test(negative=True, selected_mutations=None):
    model = (APP / 'RouterVPNModel.swift').read_text()
    unified = (APP / 'IOSUnifiedProductView.swift').read_text()
    settings = (APP / 'IOSProfileSettingsView.swift').read_text()
    assert 'let iosStartupPolicy = IOSStartupPolicy()' in model
    assert 'iosConnectGeneration = UUID()' in member(model, 'func disconnect()')
    assert 'await model.applyIOSStartupPolicyIfNeeded()' in unified
    assert 'if externalNode {' in settings and 'Section("Startup")' in settings
    assert 'Section("Live MTU")' in settings and settings.index('Section("Live MTU")') < settings.index('Section("Startup")')
    assert '                }\n                }\n                Section("Live MTU")' in settings
    assert '"startup_mode": "manual"' in (APP / 'IOSExternalNodeBuilderView.swift').read_text()
    assert 'sources:\n      - App' in (APP.parent / 'project.yml').read_text()
    if not shutil.which('swiftc'):
        raise SystemExit('swiftc is required for actual startup admission checks')
    shipping = source()
    with tempfile.TemporaryDirectory(prefix='routervpn-ios-startup-') as temporary:
        root = Path(temporary)
        run_fixture(root / 'shipping', shipping)
        if negative:
            mutations = (
                ('router-only', 'if profile.normalizedNodeKind == "external" {\n            // An imported', 'if profile.normalizedNodeKind == "external" { return }\n        if profile.normalizedNodeKind == "external" {\n            // An imported', 'external startup dispatch'),
                ('stale-source', 'return (try? iosStartupCapture()) == captured', 'return true', 'changed startup capture rejected: dns'),
                ('ignore-off', 'profile.autoConnect == true else { return }', 'true else { return }', 'Off or Manual makes no VPN preference request'),
                ('foreign-vpn', 'managers.allSatisfy({\n                $0.connection.status == .disconnected || $0.connection.status == .invalid\n            })', 'managers.allSatisfy({ _ in true })', 'an active or unverified available manager prevents startup'),
                ('ignore-admission', 'guard startupAdmission() else { return }', '_ = startupAdmission()', 'external entry checks startup admission before preparing'),
                ('hidden-reset', 'bundle.routerProfiles[index] = startup', 'bundle.routerProfiles[index] = startup\n            bundle.routerProfiles[index].dnsHost = ""', 'external Settings saves only startup fields'),
                ('repeat-launch', 'iosStartupPolicy.claim()', 'true', 'view recreation cannot repeat startup'),
                ('ignore-generation', 'return try IOSStartupCapture(bundle: bundle, entry: entry, generation: iosConnectGeneration)', 'return try IOSStartupCapture(bundle: bundle, entry: entry, generation: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!)', 'changed startup capture rejected: generation'),
                ('late-vpn', 'available.allSatisfy({\n                    $0.connection.status == .disconnected || $0.connection.status == .invalid\n                })', 'available.allSatisfy({ _ in true })', 'new available VPN during permission is not replaced'),
                ('router-readmission', 'withValue({ self.iosStartupMatches(intent) })', 'withValue({ true })', 'Router startup revalidates at nested admission auto source'),
                ('last-choice-lost', 'restoreLast: mode == "last"', 'restoreLast: false', 'only Last keeps proved Compare choice last'),
                ('startup-mtu-owner', 'guard startup() else { throw CancellationError() }', '_ = startup()', 'startup MTU admission cannot touch newly active owner'),
            )
            if selected_mutations:
                unknown = set(selected_mutations) - {item[0] for item in mutations}
                if unknown:
                    raise AssertionError('Unknown mutation selection: ' + ', '.join(sorted(unknown)))
            for name, old, new, expected in mutations:
                if selected_mutations and name not in selected_mutations:
                    continue
                if shipping.count(old) != 1:
                    raise AssertionError('Mutation anchor drifted: ' + name)
                run_fixture(root / name, shipping.replace(old, new, 1), expected)
                print('Rejected iOS startup defect mutation: ' + name, flush=True)
    print('iOS startup boundary gate PASS; physical VPN permission and networking remain native/device acceptance', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shipping-only', action='store_true')
    parser.add_argument('--mutation', action='append', help='Run a named negative control after the complete shipping fixture; default runs all controls')
    args = parser.parse_args()
    test(negative=not args.shipping_only, selected_mutations=args.mutation)
