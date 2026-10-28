#!/usr/bin/env python3
"""Execute complete Apple Tor profile transactions with the real native parser.

The visible Add/Load/Update/Delete callbacks, profile store, linked-node store,
model import/save/rollback, multihop readiness, Codable and Tor Go validation
are shipping source. Only durable file/Keychain writes and gomobile marshalling
are deterministic boundaries. No VPN, public Tor circuit or Apple SDK/device
acceptance is claimed by this fixture.
"""
from pathlib import Path
import argparse
import importlib.util
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


T = load('tor_connection_native_bridge', 'deploy/test_ios_tor_profile.py')


def member(source, signature):
    begin = source.index(signature)
    index = source.index('{', begin) + 1
    depth = 1
    while depth:
        if source[index] == '{': depth += 1
        if source[index] == '}': depth -= 1
        index += 1
    return source[begin:index].replace('private func ', 'func ')


SWIFT = r'''
import Foundation
import Network
import Libbox

@MainActor enum UserDefaults {
 static let suite="RouterVPN.TorConnection.Test."+UUID().uuidString
 static let standard=Foundation.UserDefaults(suiteName:suite)!
}
@MainActor enum IOSPrivateJSONStore {
 static var bytes:Data?,failRead=false,failWrite=false,writes=0
 static func read(_ filename:String,maximumBytes:Int)throws->Data? {
  if failRead{throw testError("Private profile read")};return bytes
 }
 static func write(_ data:Data,filename:String,maximumBytes:Int)throws {
  if failWrite{throw testError("Private profile write")}
  guard !data.isEmpty,data.count<=maximumBytes else{throw testError("Private profile size")}
  bytes=data;writes+=1
 }
}
@MainActor final class IOSNodeBundleStore {
 static let shared=IOSNodeBundleStore()
 var records:[String:Data]=[:],storageError:Error?,writes=0,failWrite=false
 private func commitRecords(_ next:[String:Data])throws {
  if failWrite{throw testError("Private node durable write")}
  records=next;writes+=1
 }
 // SHIPPING_NODE_STORE
}
func testError(_ text:String)->NSError{NSError(domain:"TorConnectionProfiles",code:1,userInfo:[NSLocalizedDescriptionKey:text])}
@MainActor final class RouterVPNModel {
 var bundle:ClientBundle?,modes:[VPNMode]=[],logicalModes:[LogicalMode]=[]
 var selectedMode="wg",selectedLogicalMode="base-raw",basePreference="auto",baseFallback=false
 var homeLANAccess=true,homeLANCIDRs:[String]=[]
 var endpoint="",apiToken="",routerAPI="",socksHost="",socksPort="0",socksUsername="",socksPassword="",lanImportHost=""
 var message="",multihopProgressText="",multihopProgressGeneration=UUID()
 var connected=false,tunnelTransitioning=false,userDisconnectInProgress=false
 let iosSpeedLabOwnership=IOSSpeedLabOwnership()
 let bundleKey="router-vpn.bundle",lanImportKey="router-vpn.lan-import-host"
 static let ordinaryExternalHopProtocols=IOSConnectionSafePreferences.ordinaryExternalModes
 var allNodeProfiles:[RouterProfile]{IOSNodeBundleStore.shared.profiles(current:bundle)}
 var selectedNodeProfile:RouterProfile?{bundle.flatMap{IOSDNSRuntimePolicy.selectedProfile(in:$0)}}
 var iosRunnableLogicalModes:[LogicalMode]{bundle.map{IOSRuntimeSelector.runnableModes(in:$0)} ?? []}
 // SHIPPING_BLOCKED
 // SHIPPING_IMPORT
 // SHIPPING_SAVE
 // SHIPPING_APPLY
 // SHIPPING_LEGACY_MODES
 // SHIPPING_GRAPH
 // SHIPPING_RUNTIME
}
@MainActor private final class ProfileActions {
 let model:RouterVPNModel
 var profiles:[IOSConnectionProfileRecord]=[],name="",selectedID:String?,status=""
 init(_ model:RouterVPNModel){self.model=model}
 // SHIPPING_ACTIONS
}

@MainActor @main struct Tests {
 static var checks=0
 static let entryID="rvpn-aaaaaaaaaaaaaaaa"
 static let bridgeLines:[String:[String]]=[
  "tor":[],
  "obfs4":["obfs4 198.51.100.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=Y2VydA iat-mode=0"],
  "meek_lite":["meek_lite 192.0.2.2:2 url=https://bridge.example.test/ front=front.example.test"],
  "snowflake":["snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://broker.example.test/ front=cdn.example.test ice=stun:stun.example.test:3478 utls-imitate=hellorandomizedalpn"],
  "webtunnel":["webtunnel 10.0.0.2:443 89ABCDEF0123456789ABCDEF0123456789ABCDEF url=https://webtunnel.example.test/private ver=0.0.1"],
  "custom":["obfs4 198.51.100.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=Y2VydA iat-mode=0","meek_lite 192.0.2.2:2 url=https://bridge.example.test/ front=front.example.test"]]
 static func check(_ name:String,_ value:@autoclosure ()throws->Bool)throws {
  guard try value()else{throw testError(name)};checks+=1
 }
 static func reject(_ name:String,_ action:()throws->Void)throws {
  do{try action()}catch{checks+=1;return};throw testError("Expected rejection: "+name)
 }
 static func encoded<T:Encodable>(_ value:T)throws->Data{let e=JSONEncoder();e.outputFormatting=[.sortedKeys];return try e.encode(value)}
 static func json(_ value:Any)throws->Data{try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
 static func object(_ value:Data)throws->[String:Any]{try JSONSerialization.jsonObject(with:value) as! [String:Any]}
 static func profile(_ transport:String="tor",id:String="tor-exit")throws->RouterProfile {
  var ext:[String:Any]=["protocol":transport=="tor" ? "tor":"tor-bridge","expected_public_ip":""]
  if transport != "tor"{ext["tor_bridge"]=["transport":transport,"bridges":bridgeLines[transport]!]}
  return try JSONDecoder().decode(RouterProfile.self,from:json([
   "id":id,"name":id,"node_kind":"external","external":ext,"endpoint":"tor",
   "router_api":"","api_token":"","adguard_ipv4":"","adguard_ipv6":"","socks_host":"","socks_port":0,"socks_username":"","socks_password":"",
   "home_lan_access":false,"home_lan_cidrs":["192.168.50.0/24","fd12:3456::/64"],"kill_switch":true,"kill_switch_policy":"always","ipv6_mode":"off",
   "base_tunnel":"auto","base_fallback":false,"start_layer":"off","auto_require_encrypted":true,"auto_require_obfuscation":true,
   "mtu_policy":"fixed","manual_mtu":1380,"daita_enabled":false,"jumbo_tun":false,"startup_mode":"last","auto_connect":true,
   "dns_mode":"custom","dns_protocol":"tcp","dns_host":"9.9.9.9","dns_port":5353,"dns_server_name":"","dns_path":"",
   "effective_mtu":9000,"effective_mtu_source":"historic-only","effective_mtu_path_key":"historic-other-path","effective_mtu_tested_at":"2000-01-01T00:00:00Z"
  ]))
 }
 static func bundle(_ p:RouterProfile)->ClientBundle {
  var b=ClientBundle.empty;b.routerProfiles=[p];b.selectedRouterID=p.id;b.endpoint=p.endpoint
  b.nodeProofID=p.nodeProofID ?? "";b.routerAPI=p.routerAPI;b.apiToken=p.apiToken;b.adGuardIPv4=p.adGuardIPv4;b.adGuardIPv6=p.adGuardIPv6
  b.profiles=["owned":["private.bin":Data("NEVER_COPY_NODE_ASSET".utf8).base64EncodedString()]]
  return b
 }
 static func entry()throws->ClientBundle {
  var p=try profile();p.id=entryID;p.name="Paired home";p.nodeKind="router-vpn";p.external=nil
  p.nodeProofID=String(repeating:"a",count:64);p.endpoint="198.51.100.10";p.routerAPI="http://10.8.0.1:8787";p.apiToken="NEVER_COPY_ENTRY_TOKEN"
  p.adGuardIPv4="192.168.50.133";p.adGuardIPv6="fd12:3456::53";p.dnsMode="home";p.dnsProtocol="udp";p.dnsPort=53
  p.homeLANAccess=true;p.ipv6Mode="on";p.mtuPolicy="auto";p.manualMTU=0;p.homeLANCIDRs=[]
  var b=bundle(p)
  let raw="[Interface]\nPrivateKey = \(Data(repeating:11,count:32).base64EncodedString())\nAddress = 10.8.0.2/32, fd08::2/128\nDNS = 192.168.50.133\n[Peer]\nPublicKey = \(Data(repeating:12,count:32).base64EncodedString())\nEndpoint = 198.51.100.10:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
  b.profiles["wg"]=["wg.conf":Data(raw.utf8).base64EncodedString()]
  return b
 }
 static func graph(_ p:inout RouterProfile,_ execution:String="local"){p.multihopEnabled=true;p.multihopEntryID=entryID;p.multihopEntryMode="wg";p.multihopExitID=p.id;p.multihopExitMode=p.external!.protocolName;p.multihopExecution=execution}
 static func reset(_ p:RouterProfile)throws->RouterVPNModel {
  UserDefaults.standard.removePersistentDomain(forName:UserDefaults.suite)
  IOSPrivateJSONStore.bytes=nil;IOSPrivateJSONStore.failRead=false;IOSPrivateJSONStore.failWrite=false;IOSPrivateJSONStore.writes=0
  let store=IOSNodeBundleStore.shared;store.records=[:];store.storageError=nil;store.failWrite=false;store.writes=0
  try store.save(entry());try store.save(bundle(profile("obfs4",id:"other-tor")))
  let model=RouterVPNModel();try model.importBundle(encoded(bundle(p)))
  // Begin with the durable normalized node, as a reopened app does.
  try model.importBundle(store.bundleData(containing:p.id,current:model.bundle)!)
  UserDefaults.standard.set("custom:unrelated",forKey:iosConnectionModeKey)
  UserDefaults.standard.set(Data("unrelated private preset".utf8),forKey:iosConnectionCustomPresetsKey)
  return model
 }
 static func replaceLinked(_ p:RouterProfile)throws {try IOSNodeBundleStore.shared.save(bundle(p))}
 static func selectOther(_ model:RouterVPNModel)throws{try model.importBundle(encoded(bundle(profile("obfs4",id:"other-tor"))))}
 static func matrix()throws {
  for transport in bridgeLines.keys.sorted(){for dns in ["custom","dot","doh","home"]{for mtu in ["auto","default","fixed","jumbo"]{for execution in ["direct","local","server"]{for cover in [false,true]{
   var p=try profile(transport)
   if dns != "custom"{p.dnsMode=dns;p.dnsProtocol=dns=="dot" ? "tls":dns=="doh" ? "https":"udp";p.dnsHost=dns=="home" ? "192.168.50.133":"9.9.9.9";p.dnsPort=dns=="home" ? 5353:4443;p.dnsServerName="resolver.example.test";p.dnsPath="/saved-query"}
   p.mtuPolicy=mtu=="jumbo" ? "auto":mtu;p.manualMTU=mtu=="fixed" ? 1380:0;p.jumboTUN=mtu=="jumbo"
   p.daitaEnabled=cover;p.daitaRateKbps=cover ? 64:192
   if dns=="home" || execution != "direct"{graph(&p,execution=="server" ? "server":"local")}
   let model=try reset(p),actions=ProfileActions(model),nodeWrites=IOSNodeBundleStore.shared.writes
   let runtime=try JSONDecoder().decode(ClientBundle.self,from:model.externalRuntimeBundleData(source:model.bundle!,profile:model.selectedNodeProfile!))
   try check("linked node and runtime handoff preserve exact cover without Router sink",model.selectedNodeProfile?.daitaEnabled==p.daitaEnabled && model.selectedNodeProfile?.daitaRateKbps==p.daitaRateKbps && runtime.routerProfiles[0].daitaEnabled==p.daitaEnabled && runtime.routerProfiles[0].daitaRateKbps==p.daitaRateKbps && runtime.routerProfiles[0].daitaHost==nil && runtime.routerProfiles[0].daitaPort==nil)
   actions.name="Whole Tor path";actions.add()
   try check("visible Add captures complete Tor preferences",actions.profiles.count==1 && actions.selectedID != nil && actions.status.hasPrefix("Added"))
   let saved=actions.profiles[0],captured=saved.preferences!,originalStore=IOSPrivateJSONStore.bytes!
   try check("Tor snapshot binds dynamic identity",saved.nodeID==p.id && saved.externalProtocol==p.external!.protocolName && saved.externalPublicIP=="" && saved.mode=="external" && saved.customLayers.isEmpty)
   try check("snapshot preserves Tor choices",captured.dnsMode==p.dnsMode && captured.dnsProtocol==p.dnsProtocol && captured.dnsHost==p.dnsHost && captured.dnsPort==p.dnsPort && captured.dnsServerName==p.dnsServerName && captured.dnsPath==p.dnsPath && captured.mtuPolicy==p.mtuPolicy && captured.manualMTU==p.manualMTU && captured.jumboTUN==p.jumboTUN && captured.homeLANCIDRs==p.homeLANCIDRs && captured.killSwitchPolicy==p.killSwitchPolicy && captured.ipv6Mode==p.ipv6Mode && captured.startupMode==p.startupMode && captured.autoConnect==p.autoConnect)
   try check("snapshot preserves Tor execution and exact graph",captured.multihopExecution==(p.multihopExecution ?? "local") && captured.multihopEnabled==(p.multihopEnabled ?? false) && captured.multihopEntryID==p.multihopEntryID && captured.multihopEntryMode==(p.multihopEntryMode ?? "wg") && captured.multihopExitID==p.multihopExitID && captured.multihopExitMode==p.multihopExitMode)
   try check("snapshot preserves complete native cover policy",captured.daitaEnabled==p.daitaEnabled && captured.daitaRateKbps==p.daitaRateKbps)
   let clear=String(decoding:originalStore,as:UTF8.self)
   for secret in ["NEVER_COPY_ENTRY_TOKEN","NEVER_COPY_NODE_ASSET","tor_bridge","cert=","bridge.example.test","webtunnel.example.test","broker.example.test","private_key","effective_mtu"]{try check("profile omits private or historical material "+secret,!clear.contains(secret))}
   try check("Add cannot change node or previous Router selection",IOSNodeBundleStore.shared.writes==nodeWrites && UserDefaults.standard.string(forKey:iosConnectionModeKey)=="custom:unrelated")
   var changed=p;changed.homeLANAccess=true;changed.homeLANCIDRs=["10.0.0.0/8"];changed.ipv6Mode="on";changed.killSwitch=false;changed.killSwitchPolicy="off";changed.mtuPolicy="auto";changed.manualMTU=0;changed.jumboTUN=false;changed.startupMode="manual";changed.autoConnect=false;changed.dnsMode="rescue";changed.dnsHost="1.1.1.1";changed.multihopEnabled=false;changed.multihopExecution=execution=="local" ? "server":"local"
   changed.daitaEnabled = !(p.daitaEnabled ?? false);changed.daitaRateKbps=96
   if let lines=p.external?.torBridge?.bridges{changed.external?.torBridge?.bridges=lines.map{$0.replacingOccurrences(of:"198.51.100.9",with:"198.51.100.10")}}
   try replaceLinked(changed);try selectOther(model)
   let other=IOSNodeBundleStore.shared.records["bundle-other-tor"],entry=IOSNodeBundleStore.shared.records["router-"+String(repeating:"a",count:64)]
   actions.load()
   try check("visible Load restores exact policy",actions.status.hasPrefix("Loaded") && model.selectedNodeProfile?.id==p.id)
   let restored=try IOSConnectionProfileStore.snapshot(model:model,name:"Readback")
   try check("all captured Tor preferences restored",restored.preferences==captured)
   try check("Load restores exact enabled and dormant rates",model.selectedNodeProfile?.daitaEnabled==p.daitaEnabled && model.selectedNodeProfile?.daitaRateKbps==p.daitaRateKbps)
   if p.multihopEnabled==true {
    let restoredEntry=try model.iosMultihopEntryBundle(for:model.bundle!)
    try check("restored execution retains its separate private entry",restoredEntry.selectedRouterID==entryID && restoredEntry.apiToken=="NEVER_COPY_ENTRY_TOKEN" && model.selectedNodeProfile?.multihopExecution==p.multihopExecution)
   }
   try check("Load keeps current node-owned bridge material",model.selectedNodeProfile?.external==changed.external)
   try check("Load never modifies unrelated entry or node",IOSNodeBundleStore.shared.records["bundle-other-tor"]==other && IOSNodeBundleStore.shared.records["router-"+String(repeating:"a",count:64)]==entry)
   try check("historical MTU remains separate from policy",model.selectedNodeProfile?.effectiveMTU==9000 && model.selectedNodeProfile?.manualMTU==captured.manualMTU)
   try check("Load does not connect or claim circuit proof",!model.connected && actions.status.contains("Connect separately to prove"))
   actions.name="Updated Tor path";actions.update()
   try check("visible Update preserves record identity",actions.profiles.count==1 && actions.profiles[0].id==saved.id && actions.profiles[0].name=="Updated Tor path" && actions.profiles[0].preferences==captured)
   let selected=try encoded(model.bundle!),privateRecords=IOSNodeBundleStore.shared.records
   actions.delete()
   try check("visible Delete only removes saved connection",actions.profiles.isEmpty && encoded(model.bundle!)==selected && IOSNodeBundleStore.shared.records==privateRecords)
  }}}}}
 }
 static func legacyAndDefaults()throws {
  for schema in 1...4 {
   let p=try profile("obfs4"),model=try reset(p)
   let legacy=IOSConnectionProfileRecord(id:"legacy",name:"Legacy Tor",nodeID:p.id,nodeKind:"external",mode:"external",customLayers:[],preferences:nil,updatedAt:Date(timeIntervalSince1970:0))
   IOSPrivateJSONStore.bytes=try encoded(IOSConnectionProfileEnvelope(schemaVersion:schema,profiles:[legacy]))
   let before=try encoded(model.bundle!)
   _=try IOSConnectionProfileStore.load(model:model,id:"legacy")
   try check("legacy Tor remains selection-only",encoded(model.bundle!)==before && IOSConnectionProfileStore.all()[0].preferences==nil)
   try check("legacy envelope migrates without invented preferences",try object(IOSPrivateJSONStore.bytes!)["schema_version"] as? Int==5)
   let updated=try IOSConnectionProfileStore.update(model:model,id:"legacy",name:"Captured now")
   try check("explicit Update captures a complete legacy Tor profile",updated.id=="legacy" && updated.preferences != nil && updated.externalPublicIP=="")
  }
  for mode:String? in [nil,"","home"] {
   var p=try profile();p.dnsMode=mode;p.dnsHost=nil;p.dnsProtocol=nil;p.dnsPort=nil;p.homeLANCIDRs=nil
   let model=try reset(p),saved=try IOSConnectionProfileStore.add(model:model,name:"Unresolved Home draft")
   try check("Tor Home draft never silently becomes public DNS",saved.preferences?.dnsMode=="home" && saved.preferences?.dnsHost=="" && saved.preferences?.homeLANCIDRs==[])
   var changed=p;changed.dnsMode="rescue";changed.dnsHost="1.1.1.1";changed.homeLANCIDRs=["10.0.0.0/8"];try replaceLinked(changed)
   _=try IOSConnectionProfileStore.load(model:model,id:saved.id)
   try check("Load restores unresolved Home and default LAN ranges",model.selectedNodeProfile?.dnsMode=="home" && model.selectedNodeProfile?.dnsHost=="" && model.selectedNodeProfile?.homeLANCIDRs==[] && !model.connected)
  }
  for legacy in [false,true] {
   var p=try profile();p.daitaRateKbps=nil
   let model=try reset(p),saved=try IOSConnectionProfileStore.add(model:model,name:"Unset cover")
   try check("new snapshot distinguishes unset rate from legacy omission",saved.preferences?.daitaRateKbps==0)
   if legacy {
    var envelope=try object(IOSPrivateJSONStore.bytes!),rows=envelope["profiles"] as! [[String:Any]],prefs=rows[0]["preferences"] as! [String:Any]
    prefs.removeValue(forKey:"daitaRateKbps");rows[0]["preferences"]=prefs;envelope["profiles"]=rows;IOSPrivateJSONStore.bytes=try JSONSerialization.data(withJSONObject:envelope)
   }
   p.daitaRateKbps=96;try replaceLinked(p)
   _=try IOSConnectionProfileStore.load(model:model,id:saved.id)
   try check("unset restores default while legacy retains unrecorded rate",model.selectedNodeProfile?.daitaRateKbps==(legacy ? 96:0))
  }
 }
 static func nativeRejections()throws {
  for fault in ["fixed-ip","other-owner","bridge-port","bridge-malformed","custom-udp","doh3","resolver-hostname","dns-bootstrap","ipv6","jumbo-fixed","lan-range","start-layer","cover-small","cover-large"] {
   var p=try profile("obfs4")
   switch fault {
   case "fixed-ip":p.external?.expectedPublicIP="203.0.113.8"
   case "other-owner":p.external?.socks5=ExternalSOCKS5Config(host:"198.51.100.8",port:1080,username:nil,password:nil)
   case "bridge-port":p.external?.torBridge?.socksPort=9050
   case "bridge-malformed":p.external?.torBridge?.bridges=["obfs4 malformed"]
   case "custom-udp":p.dnsProtocol="udp"
   case "doh3":p.dnsMode="doh3";p.dnsProtocol="h3"
   case "resolver-hostname":p.dnsHost="unselected.example.test"
   case "dns-bootstrap":p.dnsBootstrap=ExternalDNSBootstrap(server:.init(type:"tcp",server:"9.9.9.9",serverPort:53))
   case "ipv6":p.ipv6Mode="unknown"
   case "jumbo-fixed":p.jumboTUN=true
   case "lan-range":p.homeLANCIDRs=["0.0.0.0/0"]
   case "start-layer":p.startLayer="aes-256-gcm"
   case "cover-small":p.daitaRateKbps=31
   case "cover-large":p.daitaRateKbps=193
   default:break
   }
   let model=try reset(profile("obfs4"));model.bundle=bundle(p)
   let before=try encoded(model.bundle!),nodes=IOSNodeBundleStore.shared.records
   try reject("native snapshot "+fault){_ = try IOSConnectionProfileStore.add(model:model,name:"Invalid native policy")}
   try check("rejected snapshot keeps all state "+fault,IOSPrivateJSONStore.bytes==nil && IOSNodeBundleStore.shared.records==nodes && encoded(model.bundle!)==before)
  }
 }
 static func restoreRejections()throws {
  for fault in ["protocol","fixed-ip","foreign-node","bridge-owner","bridge-port","bridge-malformed","node-read","node-write","profile-read","missing-entry","external-entry","server-missing-entry","server-external-entry","compare","saved-dns","saved-jumbo","connected","transitioning","disconnecting"] {
   var p=try profile("obfs4")
   if ["missing-entry","external-entry","server-missing-entry","server-external-entry","compare"].contains(fault){graph(&p,fault.hasPrefix("server-") ? "server":"local")}
   let model=try reset(p),saved=try IOSConnectionProfileStore.add(model:model,name:"Captured graph")
   var linked=p
   if fault=="protocol"{linked.external?.protocolName="tor";linked.external?.torBridge=nil}
   if fault=="fixed-ip"{linked.external?.expectedPublicIP="203.0.113.8"}
   if fault=="bridge-owner"{linked.external?.socks5=ExternalSOCKS5Config(host:"198.51.100.8",port:1080,username:nil,password:nil)}
   if fault=="bridge-port"{linked.external?.torBridge?.socksPort=9050}
   if fault=="bridge-malformed"{linked.external?.torBridge?.bridges=["obfs4 malformed"]}
   if fault=="foreign-node"{linked.id="foreign-tor"}
   try replaceLinked(linked);try selectOther(model)
   let store=IOSNodeBundleStore.shared
   if fault=="foreign-node"{store.records.removeValue(forKey:"bundle-tor-exit")}
   if fault=="node-read"{store.storageError=testError("Unavailable private nodes")}
   if fault=="node-write"{store.failWrite=true}
   if fault=="profile-read"{IOSPrivateJSONStore.failRead=true}
   if fault=="missing-entry" || fault=="server-missing-entry"{store.records.removeValue(forKey:"router-"+String(repeating:"a",count:64))}
   if ["external-entry","server-external-entry","compare","saved-dns","saved-jumbo"].contains(fault){
    var envelope=try JSONDecoder().decode(IOSConnectionProfileEnvelope.self,from:IOSPrivateJSONStore.bytes!)
    if fault=="external-entry" || fault=="server-external-entry"{envelope.profiles[0].preferences?.multihopEntryID="other-tor";envelope.profiles[0].preferences?.multihopEntryMode="wireguard"}
    if fault=="compare"{envelope.profiles[0].preferences?.multihopExecution="auto"}
    if fault=="saved-dns"{envelope.profiles[0].preferences?.dnsProtocol="udp"}
    if fault=="saved-jumbo"{envelope.profiles[0].preferences?.jumboTUN=true}
    IOSPrivateJSONStore.bytes=try encoded(envelope)
   }
   model.connected=fault=="connected";model.tunnelTransitioning=fault=="transitioning";model.userDisconnectInProgress=fault=="disconnecting"
   let before=try encoded(model.bundle!),nodes=store.records,defaults=UserDefaults.standard.dictionaryRepresentation(),profiles=IOSPrivateJSONStore.bytes
   try reject("restore "+fault){_ = try IOSConnectionProfileStore.load(model:model,id:saved.id)}
   try check("failed restore rolls back exact selected bundle "+fault,encoded(model.bundle!)==before)
   try check("failed restore keeps private stores and mode "+fault,store.records==nodes && IOSPrivateJSONStore.bytes==profiles && NSDictionary(dictionary:UserDefaults.standard.dictionaryRepresentation()).isEqual(to:defaults))
  }
 }
 static func transactionFailures()throws {
  let model=try reset(profile("obfs4")),saved=try IOSConnectionProfileStore.add(model:model,name:"Keep this record")
  for operation in ["add","update","delete"] {
   let before=IOSPrivateJSONStore.bytes!,nodes=IOSNodeBundleStore.shared.records,selection=try encoded(model.bundle!)
   IOSPrivateJSONStore.failWrite=true
   try reject("atomic record write "+operation){
    if operation=="add"{_ = try IOSConnectionProfileStore.add(model:model,name:"Second")}
    if operation=="update"{_ = try IOSConnectionProfileStore.update(model:model,id:saved.id,name:"Changed")}
    if operation=="delete"{try IOSConnectionProfileStore.delete(model:model,id:saved.id)}
   }
   IOSPrivateJSONStore.failWrite=false
   try check("record write failure cannot partially commit "+operation,IOSPrivateJSONStore.bytes==before && IOSNodeBundleStore.shared.records==nodes && encoded(model.bundle!)==selection)
  }
  for state in ["connected","transitioning","disconnecting"] {
   model.connected=state=="connected";model.tunnelTransitioning=state=="transitioning";model.userDisconnectInProgress=state=="disconnecting"
   let before=IOSPrivateJSONStore.bytes
   try reject("busy Add "+state){_ = try IOSConnectionProfileStore.add(model:model,name:"Busy")}
   try reject("busy Update "+state){_ = try IOSConnectionProfileStore.update(model:model,id:saved.id,name:"Busy")}
   try reject("busy Delete "+state){try IOSConnectionProfileStore.delete(model:model,id:saved.id)}
   try check("busy operations retain existing record",IOSPrivateJSONStore.bytes==before)
  }
  model.connected=false;model.tunnelTransitioning=false;model.userDisconnectInProgress=false
  let owner=try model.iosSpeedLabOwnership.begin(onSuperseded:{})
  try selectOther(model)
  let selected=try encoded(model.bundle!),nodes=IOSNodeBundleStore.shared.records,defaults=UserDefaults.standard.dictionaryRepresentation()
  try IOSSpeedLabContext.$owner.withValue(owner){
   try reject("superseded Speed Lab cannot restore Tor"){_ = try IOSConnectionProfileStore.load(model:model,id:saved.id)}
  }
  try check("late Tor restore preserves replacement owner",encoded(model.bundle!)==selected && IOSNodeBundleStore.shared.records==nodes && NSDictionary(dictionary:UserDefaults.standard.dictionaryRepresentation()).isEqual(to:defaults))
  model.iosSpeedLabOwnership.finish(owner)
 }
 static func visiblePolicyAdoption()throws {
  var p=try profile();p.homeLANAccess=nil;p.homeLANCIDRs=nil
  let model=try reset(p),saved=try IOSConnectionProfileStore.add(model:model,name:"Default LAN policy")
  var other=try profile("obfs4",id:"other-tor");other.homeLANCIDRs=["10.0.0.0/8"]
  try replaceLinked(other);try model.importBundle(encoded(bundle(other)))
  _=try IOSConnectionProfileStore.load(model:model,id:saved.id)
  try check("visible model restores default LAN ranges",model.homeLANAccess && model.homeLANCIDRs.isEmpty && model.selectedNodeProfile?.homeLANCIDRs==[])
  for absent in [false,true] {
   var target=try profile();target.homeLANAccess=false;target.homeLANCIDRs=["172.16.0.0/12"]
   try model.importBundle(encoded(bundle(target)))
   let captured=try IOSConnectionProfileStore.update(model:model,id:saved.id,name:"Different LAN ranges")
   other.homeLANAccess=absent ? nil:true;other.homeLANCIDRs=absent ? nil:[]
   try model.importBundle(encoded(bundle(other)))
   let before=try encoded(model.bundle!),lan=model.homeLANAccess,ranges=model.homeLANCIDRs
   IOSNodeBundleStore.shared.failWrite=true
   try reject("visible rollback on node write"){_ = try IOSConnectionProfileStore.load(model:model,id:captured.id)}
   IOSNodeBundleStore.shared.failWrite=false
   try check("failed restore rolls back default visible LAN policy",encoded(model.bundle!)==before && model.homeLANAccess==lan && model.homeLANCIDRs==ranges && lan && ranges.isEmpty)
  }
 }
 static func ordinaryEntry(_ mode:String)throws->ClientBundle {
  var p=try profile();p.id="ordinary-entry";p.name="Ordinary imported entry";p.endpoint="198.51.100.8"
  var ext:[String:Any]=["protocol":mode,"expected_public_ip":"203.0.113.88"]
  let field=mode.replacingOccurrences(of:"-",with:"_")
  switch mode {
  case "wireguard","amneziawg":
   var packet:[String:Any]=["endpoint":"198.51.100.8:51820","private_key":Data(repeating:11,count:32).base64EncodedString(),"peer_public_key":Data(repeating:12,count:32).base64EncodedString(),"preshared_key":Data(repeating:13,count:32).base64EncodedString(),"addresses":["10.91.0.2/32","fd91::2/128"],"allowed_ips":["0.0.0.0/0","::/0"],"dns":[],"mtu":1380]
   if mode=="amneziawg" {packet["parameters"]=["jc":"3","jmin":"40","jmax":"900","s1":"56","s2":"48","s3":"24","s4":"32","h1":"10000000-19999999","h2":"20000000-29999999","h3":"30000000-39999999","h4":"40000000-49999999"]}
   ext[field]=packet
  case "openvpn":ext[field]=["config":"client\ndev tun\nproto udp\nremote 198.51.100.8 1194\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint "+String(repeating:"ab",count:32)+"\n","username":" exact entry user ","password":"NEVER_COPY_ORDINARY_CREDENTIAL"]
  case "socks5","http-connect","https-connect":
   var proxy:[String:Any]=["host":"198.51.100.8","port":8443,"username":" exact entry user ","password":"NEVER_COPY_ORDINARY_CREDENTIAL"]
   if mode=="https-connect" {proxy["tls_server_name"]="entry.example.test"}
   ext[field]=proxy
  case "shadowsocks":ext[field]=["server":"198.51.100.8","port":8388,"method":"aes-256-gcm","password":"NEVER_COPY_ORDINARY_CREDENTIAL"]
  default:ext[field]=["server":"198.51.100.8","port":8443,"tls_server_name":"entry.example.test","password":"NEVER_COPY_ORDINARY_CREDENTIAL"]
  }
  p.external=try JSONDecoder().decode(ExternalNodeConfig.self,from:json(ext))
  p.dnsBootstrap=ExternalDNSBootstrap(server:.init(type:"tcp",server:"9.9.9.9",serverPort:5353))
  p.dnsHost="entry-resolver.example.test"
  return bundle(p)
 }
 static func ordinaryTorProfiles()throws {
  for mode in IOSConnectionSafePreferences.ordinaryExternalModes.sorted() {for kind in ["tor","obfs4"] {
   var p=try profile(kind);graph(&p);p.multihopEntryID="ordinary-entry";p.multihopEntryMode=mode
   let model=try reset(p),lower=try ordinaryEntry(mode);try IOSNodeBundleStore.shared.save(lower)
   let actions=ProfileActions(model);actions.name="Complete ordinary Tor path";actions.add()
   try check("ordinary Tor Add preserves graph with imported entry mode",actions.profiles.count==1 && actions.profiles[0].preferences?.multihopEntryMode==mode && actions.profiles[0].preferences?.multihopEntryID=="ordinary-entry" && actions.profiles[0].preferences?.multihopExecution=="local")
   let saved=actions.profiles[0],preferences=saved.preferences!,stored=IOSPrivateJSONStore.bytes!
   let clear=String(decoding:stored,as:UTF8.self)
   try check("ordinary Tor connection profile keeps only private node references",!clear.contains("NEVER_COPY_ORDINARY_CREDENTIAL") && !clear.contains("private_key") && !clear.contains("entry-resolver.example.test") && !clear.contains("NEVER_COPY_NODE_ASSET"))
   var changed=p;changed.multihopEnabled=false;changed.multihopEntryMode="wg";changed.dnsHost="149.112.112.112";changed.manualMTU=1400
   try replaceLinked(changed);try selectOther(model)
   let nodes=IOSNodeBundleStore.shared.records,entryBytes=IOSNodeBundleStore.shared.bundleData(containing:"ordinary-entry",current:nil)
   let savedEntry=try JSONDecoder().decode(ClientBundle.self,from:entryBytes!)
   actions.load()
   try check("ordinary Tor Load restores exact complete selected policy",actions.status.hasPrefix("Loaded") && model.selectedNodeProfile?.multihopEntryMode==mode && IOSConnectionProfileStore.snapshot(model:model,name:"Readback").preferences==preferences)
   let captured=try model.iosMultihopEntryBundle(for:model.bundle!)
   try check("ordinary Tor Load preserves exact linked entry",captured.routerProfiles==savedEntry.routerProfiles && captured.apiToken.isEmpty && captured.nodeProofID.isEmpty)
   try check("ordinary Tor Load preserves node-owned credentials and DNS bootstrap",captured.routerProfiles[0].external==lower.routerProfiles[0].external && captured.routerProfiles[0].dnsBootstrap==lower.routerProfiles[0].dnsBootstrap)
   try check("ordinary Tor Load leaves predecessor private record untouched",IOSNodeBundleStore.shared.bundleData(containing:"ordinary-entry",current:nil)==entryBytes)
   for fault in ["server","auto","home","missing-entry"] {
    try selectOther(model)
    var envelope=try JSONDecoder().decode(IOSConnectionProfileEnvelope.self,from:stored)
    if fault=="server" || fault=="auto" {envelope.profiles[0].preferences?.multihopExecution=fault}
    if fault=="home" {envelope.profiles[0].preferences?.dnsMode="home"}
    if fault=="missing-entry" {envelope.profiles[0].preferences?.multihopEntryID="unlinked-entry"}
    IOSPrivateJSONStore.bytes=try encoded(envelope)
    let before=try encoded(model.bundle!),privateNodes=IOSNodeBundleStore.shared.records,records=IOSPrivateJSONStore.bytes
    try reject("ordinary Tor profile cannot acquire "+fault){_ = try IOSConnectionProfileStore.load(model:model,id:saved.id)}
    try check("invalid ordinary Tor restore is transactional "+fault,encoded(model.bundle!)==before && IOSNodeBundleStore.shared.records==privateNodes && IOSPrivateJSONStore.bytes==records)
   }
   IOSPrivateJSONStore.bytes=stored;_ = try IOSConnectionProfileStore.load(model:model,id:saved.id)
   actions.name="Updated ordinary Tor";actions.update()
   try check("ordinary Tor Update keeps same private references",actions.status.hasPrefix("Updated") && actions.profiles[0].id==saved.id && actions.profiles[0].preferences==preferences)
   actions.delete()
   try check("ordinary Tor Delete preserves node credentials",actions.profiles.isEmpty && IOSNodeBundleStore.shared.bundleData(containing:"ordinary-entry",current:nil)==entryBytes && nodes.keys.allSatisfy{IOSNodeBundleStore.shared.records[$0] != nil})
  }}
 }
 static func main(){
  defer{RouterVPNTorTestClose();UserDefaults.standard.removePersistentDomain(forName:UserDefaults.suite)}
  do{try matrix();try legacyAndDefaults();try nativeRejections();try restoreRejections();try transactionFailures();try visiblePolicyAdoption();try ordinaryTorProfiles();print("Apple whole Tor connection profiles: PASS (\(checks) shipping callbacks/store/import/native validation checks)")}
  catch{FileHandle.standardError.write(Data((error.localizedDescription+"\n").utf8));exit(1)}
 }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shipping-only', action='store_true')
    args = parser.parse_args()
    swift, go = shutil.which('swiftc'), shutil.which('go')
    if not swift or not go: raise RuntimeError('swiftc and go are required')
    view = (APP / 'IOSConnectionProfilesView.swift').read_text()
    store = view[:view.index('@MainActor\nstruct IOSConnectionProfilesView:')].replace('import SwiftUI\n', '')
    node = (APP / 'IOSNodeBundleStore.swift').read_text()
    model = (APP / 'RouterVPNModel.swift').read_text()
    external = (APP / 'RouterVPNModelExternal.swift').read_text()
    multihop = (APP / 'IOSMultihopView.swift').read_text()
    callbacks = view[view.index('@MainActor\nstruct IOSConnectionProfilesView:'):]
    actions = '\n'.join(member(callbacks, 'private func '+name+'(') for name in ['refresh','add','load','update','delete'])
    for name in ('Add','Load','Update','Delete'):
        assert 'Button("'+name+'"' in callbacks and 'IOSConnectionProfileStore.'+name.lower()+'(' in actions
    source = SWIFT.replace(' // SHIPPING_NODE_STORE', node[node.index('    func link('):node.index('    private func storeDirectory(')])
    source = source.replace(' // SHIPPING_BLOCKED', member(model, 'var profileMutationBlocked:'))
    source = source.replace(' // SHIPPING_IMPORT', member(model, '    func importBundle('))
    source = source.replace(' // SHIPPING_SAVE', member(model, '    func saveRouter('))
    source = source.replace(' // SHIPPING_APPLY', member(model, '    private func apply('))
    source = source.replace(' // SHIPPING_LEGACY_MODES', member(model, '    private func legacyLogicalModes('))
    source = source.replace(' // SHIPPING_GRAPH', '\n'.join(member(multihop, signature) for signature in [
        '    func iosMultihopEntryBundle(', '    private func iosOrdinaryExternalEntryBundle(', '    private func iosMultihopError(']))
    source = source.replace(' // SHIPPING_ACTIONS', actions)
    source = source.replace(' // SHIPPING_RUNTIME', member(external, '    func externalRuntimeBundleData('))
    with tempfile.TemporaryDirectory(prefix='.ios-tor-profiles-go-', dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix='ios-tor-connections-') as temporary:
        work = Path(temporary)
        compiler_source = Path(go_dir) / 'main.go'; compiler_source.write_text(T.GO)
        compiler = work / 'compiler'
        subprocess.run([go,'build','-o',str(compiler),str(compiler_source)],cwd=ROOT,check=True,timeout=120)
        options = [swift,'-swift-version','6','-module-cache-path',str(work/'modules')]
        suffix = '.dylib' if platform.system()=='Darwin' else '.so'
        modules = [('Libbox',T.LIBBOX)] + ([] if platform.system()=='Darwin' else [('Network',T.NETWORK)])
        for name,body in modules:
            path=work/(name+'.swift');path.write_text(body)
            subprocess.run(options+['-emit-module','-emit-library','-module-name',name,str(path),'-emit-module-path',str(work/(name+'.swiftmodule')),'-o',str(work/('lib'+name+suffix))],check=True,timeout=90)
        options+=['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        if platform.system()!='Darwin':options+=['-lNetwork']
        shipping=[APP/name for name in ['Models.swift','IOSExternalExecution.swift','IOSDNSRuntimePolicy.swift','IOSRuntimeSelection.swift','IOSNativeXrayProfile.swift','IOSNativePQProfile.swift','IOSMultihopStartLayer.swift','IOSNodeLatencyStatistics.swift','IOSSpeedLabOwnership.swift']]
        code=work/'Tests.swift';code.write_text(store+'\n'+source)
        binary=work/'tests'
        command=options+['-Onone','-whole-module-optimization',*map(str,shipping),str(code),'-o',str(binary)]
        subprocess.run(command,check=True,timeout=150)
        subprocess.run([str(binary),str(compiler)],check=True,timeout=90)
        if args.shipping_only:return
        for name,before,after,expected in [
            ('snapshot-native-validation','try IOSExternalExecution.validateDeviceDraft(applying(captured, to: selected))','', 'Expected rejection: native snapshot other-owner'),
            ('restore-native-validation','try IOSExternalExecution.validateDeviceDraft(profile)','', 'Expected rejection: restore bridge-owner'),
            ('protocol-identity','selected.protocolName == saved.externalProtocol,\n                      selected.expectedPublicIP == saved.externalPublicIP,\n                      linked.external?.protocolName == saved.externalProtocol,','true,\n                      selected.expectedPublicIP == saved.externalPublicIP,\n                      true,', 'Expected rejection: restore protocol'),
            ('import-rollback','apply(previous ?? ClientBundle.empty)','', 'failed restore rolls back exact selected bundle node-write'),
            ('active-restore','guard !model.profileMutationBlocked else { throw issue("Disconnect or let the active VPN transition finish before loading a connection profile.") }','', 'Expected rejection: restore connected'),
        ]:
            combined=store+'\n'+source
            assert combined.count(before)==1, name
            code.write_text(combined.replace(before,after,1))
            subprocess.run(command,check=True,timeout=150)
            result=subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=90)
            assert result.returncode==1 and expected in result.stderr,name+': '+result.stderr[-2000:]
            print('Rejected Tor connection-profile defect mutation: '+name,flush=True)


if __name__=='__main__':
    main()
