#!/usr/bin/env python3
"""Execute Apple connection-profile persistence with shipping models and store.

Private file storage, node lookup and the final import are deterministic
boundaries. No VPN, credentials, network or device state is opened.
"""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
NETWORK = r'''
import Foundation
import Glibc
public struct IPv4Address {
 public let rawValue: Data
 public init?(_ raw: String) { var v=in_addr();guard inet_pton(AF_INET,raw,&v)==1 else{return nil};rawValue=withUnsafeBytes(of:v){Data($0)} }
}
public struct IPv6Address {
 public let rawValue: Data
 public init?(_ raw: String) { var v=in6_addr();guard inet_pton(AF_INET6,raw,&v)==1 else{return nil};rawValue=withUnsafeBytes(of:v){Data($0)} }
}
'''
BOUNDARIES = r'''
@MainActor enum IOSPrivateJSONStore {
 static var bytes: Data?, failRead=false, failWrite=false, writes=0
 static func read(_ filename:String,maximumBytes:Int)throws->Data? { if failRead{throw TestFailure.error};return bytes }
 static func write(_ data:Data,filename:String,maximumBytes:Int)throws { if failWrite{throw TestFailure.error};guard !data.isEmpty && data.count<=maximumBytes else{throw TestFailure.error};bytes=data;writes+=1 }
}
@MainActor final class IOSNodeBundleStore {
 static let shared=IOSNodeBundleStore()
 var bundles:[String:Data]=[:]
 func bundleData(containing id:String,current:ClientBundle?)->Data? {bundles[id]}
}
enum TestFailure {static var error:NSError {NSError(domain:"ExternalConnectionFixture",code:1)}}
enum IOSExternalExecution {
 // Tor snapshots run the real native parser in test_ios_tor_connection_profiles.
 // This ordinary-exit fixture must never call that path accidentally.
 static func validateDeviceDraft(_ profile:RouterProfile)throws {throw TestFailure.error}
}
@MainActor final class RouterVPNModel {
 var bundle:ClientBundle?, allNodeProfiles:[RouterProfile]=[], profileMutationBlocked=false
 var imports=0, graphChecks=0, failGraph=false, failImport=false
 var selectedNodeProfile:RouterProfile? {bundle.flatMap{IOSDNSRuntimePolicy.selectedProfile(in:$0)}}
 func iosMultihopEntryBundle(for source:ClientBundle)throws->ClientBundle {
  graphChecks+=1
  guard !failGraph,let p=IOSDNSRuntimePolicy.selectedProfile(in:source),p.multihopEnabled==true,
        let id=p.multihopEntryID,id != p.id,p.multihopExitID==p.id,
        let data=IOSNodeBundleStore.shared.bundles[id] else{throw TestFailure.error}
  return try JSONDecoder().decode(ClientBundle.self,from:data)
 }
 func importBundle(_ data:Data)throws {if failImport{throw TestFailure.error};let decoded=try JSONDecoder().decode(ClientBundle.self,from:data);bundle=decoded;imports+=1}
}
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ condition:@autoclosure ()throws->Bool)throws {guard try condition()else{fatalError("FAIL: "+name)};checks+=1}
 static func reject(_ name:String,_ operation:()throws->Void)throws {do{try operation()}catch{checks+=1;return};fatalError("Expected rejection: "+name)}
 static func data(_ value:Any)throws->Data {try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
 static func json(_ value:Data)throws->[String:Any] {try JSONSerialization.jsonObject(with:value) as! [String:Any]}
 static func encoded(_ value:ClientBundle)throws->Data {let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys];return try encoder.encode(value)}
 static func profile(_ kind:String,_ id:String="exit")->RouterProfile {
  var external:[String:Any]=["protocol":kind,"expected_public_ip":"203.0.113.99"]
  switch kind {
  case "amneziawg":external["amneziawg"]=["private_key":"NEVER_COPY_PRIVATE_KEY","peer_public_key":"never-copy-peer","addresses":["10.8.0.2/24"],"endpoint":"198.51.100.1:51820","allowed_ips":["0.0.0.0/0","::/0"],"persistent_keepalive_interval":29,"parameters":["jc":"3","jmin":"40","jmax":"900","s1":"56","s2":"48","s3":"24","s4":"32","h1":"10000000-19999999","h2":"20000000-29999999","h3":"30000000-39999999","h4":"40000000-49999999"]]
  case "wireguard":external["wireguard"]=["private_key":"NEVER_COPY_PRIVATE_KEY","peer_public_key":"never-copy-peer","addresses":["10.8.0.2/24"],"endpoint":"198.51.100.1:51820","allowed_ips":["0.0.0.0/0","::/0"]]
  case "socks5":external["socks5"]=["host":"198.51.100.1","port":1080,"username":"private-user","password":"NEVER_COPY_PASSWORD"]
  case "http-connect","https-connect":external[kind.replacingOccurrences(of:"-",with:"_")]=["host":"198.51.100.1","port":8443,"username":"private-user","password":"NEVER_COPY_PASSWORD","tls_server_name":"exit.example.test"]
  case "shadowsocks":external["shadowsocks"]=["server":"198.51.100.1","port":8388,"method":"aes-256-gcm","password":"NEVER_COPY_PASSWORD"]
  case "hysteria2":external["hysteria2"]=["server":"198.51.100.1","port":443,"password":"NEVER_COPY_PASSWORD","tls_server_name":"exit.example.test"]
  case "openvpn":external["openvpn"]=["config":"NEVER_COPY_OPENVPN_CONFIG","username":"private-user","password":"NEVER_COPY_PASSWORD"]
  default:external["expected_public_ip"]=""
  }
  let object:[String:Any]=["id":id,"name":"Saved external "+kind,"node_kind":"external","external":external,
   "endpoint":"198.51.100.1","router_api":"","api_token":"NEVER_COPY_API_TOKEN","adguard_ipv4":"","adguard_ipv6":"",
   "socks_host":"","socks_port":0,"socks_username":"","socks_password":"NEVER_COPY_SOCKS_SECRET",
   "home_lan_access":false,"kill_switch":true,"kill_switch_policy":"strict","ipv6_mode":"off",
   "base_tunnel":"auto","base_fallback":false,"start_layer":"off","mtu_policy":"fixed","manual_mtu":1380,
   "dns_mode":"custom","dns_protocol":"tcp","dns_host":"9.9.9.9","dns_port":5353,"dns_server_name":"","dns_path":"",
   "startup_mode":"manual","auto_connect":false,"effective_mtu":9000]
  return try! JSONDecoder().decode(RouterProfile.self,from:data(object))
 }
 static func bundle(_ profile:RouterProfile)->ClientBundle {
  var b=ClientBundle.empty;b.routerProfiles=[profile];b.selectedRouterID=profile.id;b.endpoint=profile.endpoint
  b.profiles=["owned-assets":["private.conf":Data("NEVER_COPY_ASSET".utf8).base64EncodedString()]];return b
 }
 static func reset(_ p:RouterProfile)throws->RouterVPNModel {
  IOSPrivateJSONStore.bytes=nil;IOSPrivateJSONStore.failRead=false;IOSPrivateJSONStore.failWrite=false;IOSPrivateJSONStore.writes=0
  IOSNodeBundleStore.shared.bundles=[:]
  UserDefaults.standard.removeObject(forKey:iosConnectionProfilesKey);UserDefaults.standard.set("smart-auto",forKey:iosConnectionModeKey)
  let model=RouterVPNModel();model.bundle=bundle(p);model.allNodeProfiles=[p]
  IOSNodeBundleStore.shared.bundles[p.id]=try JSONEncoder().encode(model.bundle!)
  IOSNodeBundleStore.shared.bundles["entry"]=try JSONEncoder().encode(bundle(profile("wireguard","entry")))
  return model
 }
 static func matrix()throws {
  for kind in IOSConnectionSafePreferences.ordinaryExternalModes.sorted() {for dns in ["custom","home","doh","doh3"] {
   var p=profile(kind)
   if dns != "custom" {p.dnsMode=dns;p.dnsProtocol=dns=="home" ? "tcp":(dns=="doh" ? "https":"h3");p.dnsHost=dns=="home" ? "192.168.50.133":"9.9.9.9";p.dnsPort=dns=="home" ? 5353:4443;p.dnsServerName="resolver.example.test";p.dnsPath="/selected-query"}
   p.multihopEnabled=true;p.multihopEntryID="entry";p.multihopEntryMode="wireguard";p.multihopExitID=p.id;p.multihopExitMode=kind;p.multihopExecution="local"
   let model=try reset(p),source=model.bundle!,saved=try IOSConnectionProfileStore.add(model:model,name:" Whole saved path ")
   try check("new external record stores its public identity",saved.externalProtocol==kind && saved.externalPublicIP==p.external!.expectedPublicIP)
   try check("external record stores selected DNS exactly",saved.preferences?.dnsMode==p.dnsMode && saved.preferences?.dnsProtocol==p.dnsProtocol && saved.preferences?.dnsHost==p.dnsHost && saved.preferences?.dnsPort==p.dnsPort && saved.preferences?.dnsServerName==p.dnsServerName && saved.preferences?.dnsPath==p.dnsPath)
   try check("fixed MTU and protection are preserved",saved.preferences?.mtuPolicy=="fixed" && saved.preferences?.manualMTU==1380 && saved.preferences?.killSwitchPolicy=="strict" && saved.preferences?.ipv6Mode=="off" && saved.preferences?.homeLANAccess==false)
   let record=String(decoding:IOSPrivateJSONStore.bytes!,as:UTF8.self)
   for secret in ["NEVER_COPY_PRIVATE_KEY","NEVER_COPY_PASSWORD","NEVER_COPY_API_TOKEN","NEVER_COPY_SOCKS_SECRET","NEVER_COPY_ASSET","NEVER_COPY_OPENVPN_CONFIG"]{try check("connection record never copies "+secret,!record.contains(secret))}
   try check("saving does not alter active selection",model.imports==0 && model.bundle!.profiles==source.profiles && model.bundle!.routerProfiles==source.routerProfiles)
   var changed=source;changed.routerProfiles[0].dnsMode="rescue";changed.routerProfiles[0].manualMTU=1600;changed.routerProfiles[0].multihopEnabled=false;changed.routerProfiles[0].homeLANAccess=true
   IOSNodeBundleStore.shared.bundles[p.id]=try JSONEncoder().encode(changed)
   model.bundle=bundle(profile("socks5","other"));let before=model.graphChecks
   _=try IOSConnectionProfileStore.load(model:model,id:saved.id)
   let restored=model.selectedNodeProfile!
   try check("load restores exact nonsecret choices",restored.dnsMode==p.dnsMode && restored.dnsProtocol==p.dnsProtocol && restored.dnsHost==p.dnsHost && restored.dnsPort==p.dnsPort && restored.dnsServerName==p.dnsServerName && restored.dnsPath==p.dnsPath && restored.manualMTU==1380 && restored.mtuPolicy=="fixed")
   try check("load validates saved graph before import",model.graphChecks==before+1 && model.imports==1 && restored.multihopEntryID=="entry" && restored.multihopEntryMode=="wireguard" && restored.multihopExitMode==kind)
   try check("load preserves exact imported secrets and owned files",restored.external==p.external && restored.apiToken==p.apiToken && restored.socksPassword==p.socksPassword && model.bundle!.profiles==source.profiles)
   try check("historical MTU never becomes a saved measurement",!record.contains("effective_mtu") && restored.effectiveMTU==9000)
   let updated=try IOSConnectionProfileStore.update(model:model,id:saved.id,name:"Updated path")
   try check("update keeps record identity and exact path",updated.id==saved.id && updated.name=="Updated path" && updated.preferences==saved.preferences)
   try IOSConnectionProfileStore.delete(model:model,id:saved.id)
   try check("delete removes only the saved profile",IOSConnectionProfileStore.all().isEmpty && model.imports==1)
  }}
 }
 static func legacyAndFailures()throws {
  let p=profile("socks5"),model=try reset(p)
  let saved=try IOSConnectionProfileStore.add(model:model,name:"Saved")
  let originalStore=IOSPrivateJSONStore.bytes!,originalBundle=try JSONEncoder().encode(model.bundle!)
  for fault in ["protocol","public-ip","duplicate","kind","graph","missing","import"] {
   let model=RouterVPNModel();model.bundle=bundle(profile("socks5","active"));model.allNodeProfiles=[p]
   IOSPrivateJSONStore.bytes=originalStore;var imported=bundle(p)
   if fault=="protocol" {imported.routerProfiles[0].external!.protocolName="hysteria2"}
   if fault=="public-ip" {imported.routerProfiles[0].external!.expectedPublicIP="203.0.113.100"}
   if fault=="duplicate" {imported.routerProfiles.append(p)}
   if fault=="kind" {imported.routerProfiles[0].nodeKind="router-vpn"}
   if fault=="graph" {
    var envelope=try json(originalStore),records=envelope["profiles"] as! [[String:Any]],prefs=records[0]["preferences"] as! [String:Any]
    prefs["multihopEnabled"]=true;prefs["multihopEntryID"]="entry";prefs["multihopEntryMode"]="wg";prefs["multihopExitID"]="exit";prefs["multihopExitMode"]="socks5";prefs["multihopExecution"]="local";records[0]["preferences"]=prefs;envelope["profiles"]=records;IOSPrivateJSONStore.bytes=try data(envelope);model.failGraph=true
   }
   IOSNodeBundleStore.shared.bundles[p.id]=try JSONEncoder().encode(imported)
   if fault=="missing"{IOSNodeBundleStore.shared.bundles.removeValue(forKey:p.id)}
   if fault=="import"{model.failImport=true}
   let before=try encoded(model.bundle!)
   try reject("load refuses "+fault){_ = try IOSConnectionProfileStore.load(model:model,id:saved.id)}
   try check("failed "+fault+" load never changes active node",model.imports==0 && encoded(model.bundle!)==before)
  }
  IOSNodeBundleStore.shared.bundles[p.id]=originalBundle;IOSPrivateJSONStore.bytes=originalStore
  model.profileMutationBlocked=true
  try reject("busy profile cannot load"){_ = try IOSConnectionProfileStore.load(model:model,id:saved.id)}
  try reject("busy profile cannot update"){_ = try IOSConnectionProfileStore.update(model:model,id:saved.id,name:"Changed")}
  model.profileMutationBlocked=false;IOSPrivateJSONStore.failWrite=true
  try reject("failed store update preserves prior record"){_ = try IOSConnectionProfileStore.update(model:model,id:saved.id,name:"Changed")}
  try check("write failure preserves previous serialized bytes",IOSPrivateJSONStore.bytes==originalStore)
  IOSPrivateJSONStore.failWrite=false;IOSPrivateJSONStore.failRead=true
  try reject("corrupt/inaccessible store cannot become empty"){_ = try IOSConnectionProfileStore.add(model:model,name:"Lost record")}
  IOSPrivateJSONStore.failRead=false
  for kind in ["tor","tor-bridge","openvpn","socks5"] {
   var old=IOSConnectionProfileRecord(id:"legacy",name:"Old external",nodeID:"exit",nodeKind:"external",mode:"external",customLayers:[],preferences:nil,updatedAt:Date(timeIntervalSince1970:0))
   let oldProfile=profile(kind),legacyModel=try reset(oldProfile)
   IOSPrivateJSONStore.bytes=try JSONEncoder().encode(IOSConnectionProfileEnvelope(schemaVersion:4,profiles:[old]))
   let before=legacyModel.bundle!.routerProfiles
   _=try IOSConnectionProfileStore.load(model:legacyModel,id:"legacy")
   try check("legacy external remains selection-only",legacyModel.imports==1 && legacyModel.bundle!.routerProfiles==before)
   old.externalProtocol="socks5"
   IOSPrivateJSONStore.bytes=try JSONEncoder().encode(IOSConnectionProfileEnvelope(schemaVersion:4,profiles:[old]))
   try reject("partial new external identity is not legacy"){_ = try IOSConnectionProfileStore.load(model:legacyModel,id:"legacy")}
  }
 }
 static func conflictingProtectionAndRouterSelection()throws {
  for flag in [false,true] {for policy in ["off","on-connect","always","strict"] {
   var p=profile("socks5");p.killSwitch=flag;p.killSwitchPolicy=policy
   let model=try reset(p),saved=try IOSConnectionProfileStore.add(model:model,name:"Captured protection")
   try check("snapshot preserves independent kill-switch Boolean",saved.preferences?.killSwitch==flag && saved.preferences?.killSwitchPolicy==policy)
   var changed=bundle(p);changed.routerProfiles[0].killSwitch = !flag;changed.routerProfiles[0].killSwitchPolicy="off"
   IOSNodeBundleStore.shared.bundles[p.id]=try JSONEncoder().encode(changed)
   _=try IOSConnectionProfileStore.load(model:model,id:saved.id)
   let restored=model.selectedNodeProfile!
   try check("load preserves both conflicting protection inputs",restored.killSwitch==flag && restored.killSwitchPolicy==policy)
   let expectedStrict=flag || ["always","strict"].contains(policy)
   let restoredStrict=restored.killSwitch==true || ["always","strict"].contains(restored.killSwitchPolicy ?? "")
   try check("saved protection can never weaken native lockdown",expectedStrict==restoredStrict)
  }}
  for mode in ["invalid Router mode", "custom:stale", "custom:invalid:reference"] {
   let model=try reset(profile("socks5"))
   UserDefaults.standard.set(mode,forKey:iosConnectionModeKey)
   UserDefaults.standard.set(try JSONEncoder().encode([IOSConnectionCustomPresetMirror(name:"stale",layers:["invalid Router layer"])]),forKey:iosConnectionCustomPresetsKey)
   let originalPreset=UserDefaults.standard.data(forKey:iosConnectionCustomPresetsKey)
   let saved=try IOSConnectionProfileStore.add(model:model,name:"External is independent")
   try check("external snapshot ignores stale Router mode and CUSTOM preset",saved.mode=="external" && saved.customLayers.isEmpty && saved.preferences != nil)
   try check("saving external policy never rewrites Router selection",UserDefaults.standard.string(forKey:iosConnectionModeKey)==mode && UserDefaults.standard.data(forKey:iosConnectionCustomPresetsKey)==originalPreset)
  }
 }
 static func missingDNSPreservesHome()throws {
  for mode:String? in [nil,"","home"] {
   var p=profile("socks5");p.dnsMode=mode;p.dnsProtocol=nil;p.dnsHost=nil;p.dnsPort=nil
   let direct=try reset(p)
   try reject("missing or blank external DNS cannot silently become Rescue"){_ = try IOSConnectionProfileStore.add(model:direct,name:"Unpaired Home")}
   try check("rejected implicit Home leaves private storage untouched",IOSPrivateJSONStore.writes==0 && direct.imports==0 && direct.selectedNodeProfile?.dnsMode==mode)
   p.multihopEnabled=true;p.multihopEntryID="entry";p.multihopEntryMode="wg";p.multihopExitID=p.id;p.multihopExitMode="socks5";p.multihopExecution="local"
   let model=try reset(p),saved=try IOSConnectionProfileStore.add(model:model,name:"Captured Home")
   try check("implicit Home stays Home in whole connection profile",saved.preferences?.dnsMode=="home" && model.selectedNodeProfile?.dnsMode==mode)
   var changed=bundle(p);changed.routerProfiles[0].dnsMode="rescue";IOSNodeBundleStore.shared.bundles[p.id]=try JSONEncoder().encode(changed)
   _=try IOSConnectionProfileStore.load(model:model,id:saved.id)
   try check("profile restore retains paired Home intent",model.selectedNodeProfile?.dnsMode=="home" && model.selectedNodeProfile?.multihopEntryID=="entry")
  }
 }
 static func hostnameBootstrapPersistence()throws {
  var p=profile("socks5");p.dnsMode="doh";p.dnsProtocol="https";p.dnsHost="resolver.example.test";p.dnsServerName="resolver.example.test";p.dnsPort=443;p.dnsPath="/captured-query"
  var bootstrap=ExternalDNSBootstrap(server:.init(type:"tcp",server:"9.9.9.9",serverPort:5353))
  bootstrap.query.timeout="2.5s";bootstrap.query.strategy="prefer_ipv6";bootstrap.query.disableCache=true;bootstrap.query.disableOptimisticCache=false;bootstrap.query.rewriteTTL=17;bootstrap.query.clientSubnet="2001:db8::/48"
  p.dnsBootstrap=bootstrap
  let model=try reset(p),saved=try IOSConnectionProfileStore.add(model:model,name:"Explicit hostname lookup")
  try check("whole profile retains exact bootstrap server and query",saved.preferences?.dnsBootstrap==bootstrap)
  let all=IOSConnectionProfileStore.all();try check("bootstrap survives private store decode",all.count==1 && all[0].preferences?.dnsBootstrap==bootstrap)
  var changed=bundle(p);changed.routerProfiles[0].dnsBootstrap=nil;IOSNodeBundleStore.shared.bundles[p.id]=try JSONEncoder().encode(changed)
  _=try IOSConnectionProfileStore.load(model:model,id:saved.id)
  try check("whole-profile load restores exact hostname lookup choices",model.selectedNodeProfile?.dnsBootstrap==bootstrap && model.selectedNodeProfile?.dnsHost==p.dnsHost)
 }
 static func externalExecutionPersistence()throws {
  for kind in ["wireguard","amneziawg","shadowsocks","hysteria2","socks5","http-connect","https-connect","openvpn"] { for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] { for execution in ["local","server","auto"] {
   var p=profile(kind)
   if kind=="openvpn" {
    let fixture=try json(Data(contentsOf:URL(fileURLWithPath:ProcessInfo.processInfo.environment["ROUTERVPN_OPENVPN_CLIENT_FIXTURE"]!))),layers=fixture["layers"] as! [String:[String:Any]]
    p.external=try JSONDecoder().decode(ExternalNodeConfig.self,from:data(layers[layer]!["external"]!));p.startLayer=layer
   }
   if ExternalNodeConfig.packetProtocols.contains(kind) { p.external?.serverPeer=try JSONDecoder().decode(ExternalServerPeer.self,from:data(["public_key":"bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg=","addresses":["10.94.0.3/32","fd94::3/128"],"mtu":1360,"persistent_keepalive_interval":25])) }
   if layer != "off" && kind != "openvpn" {
    let raw:[String:Any] = ["mode":layer,"api":"http://10.99.0.1:8787","transport":["type":"shadowsocks","tag":"provisioned-exit-layer","server":"198.51.100.1","server_port":8388,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:77,count:32).base64EncodedString()]]
    p.external?.startLayer=try JSONDecoder().decode(ExternalStartLayer.self,from:data(raw));p.startLayer=layer
   }
   if kind != "openvpn" {p.external?.responseProbe=ExternalResponseProbe(url:"https://198.51.100.1:9443/response",serverName:"paired.example.test")}
   p.multihopEnabled=true;p.multihopEntryID="entry";p.multihopEntryMode="max-tls-awg";p.multihopExitID=p.id;p.multihopExitMode=kind;p.multihopExecution=execution
   let model=try reset(p),saved=try IOSConnectionProfileStore.add(model:model,name:"Saved external execution")
   let record=String(decoding:IOSPrivateJSONStore.bytes!,as:UTF8.self)
   try check("snapshot retains exact Server/Compare choice and native entry",saved.preferences?.multihopExecution==execution && saved.preferences?.multihopEntryMode=="max-tls-awg")
   try check("connection record refers to node transport and response endpoint",!record.contains("paired.example.test") && !record.contains("NEVER_COPY_PASSWORD") && !record.contains("response_probe") && !record.contains("server_peer") && !record.contains("bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg=") && !record.contains(Data(repeating:77,count:32).base64EncodedString()) && !record.contains("10.99.0.1") && saved.preferences?.startLayer==layer)
   if let pairing=p.external?.openVPNPairing {
    try check("complete OpenVPN connection profile stores references without copied pairing or credentials",!record.contains(pairing.privateKey) && !record.contains(pairing.server.pairingPublicKey) && !record.contains("openvpn_pairing") && !record.contains(p.external!.openVPN!.config) && !record.contains(p.external!.openVPN!.password!))
   }
   var current=bundle(p);current.routerProfiles[0].multihopExecution="local";current.routerProfiles[0].external?.shadowsocks?.password="replacement private credential"
   current.routerProfiles[0].external?.responseProbe?.url=kind=="openvpn" ? "https://203.0.113.20/new-response":"https://198.51.100.1:9443/new-response"
   IOSNodeBundleStore.shared.bundles[p.id]=try JSONEncoder().encode(current)
   model.bundle=bundle(profile("socks5","unrelated"));let original=try encoded(model.bundle!)
   model.failGraph=true
   try reject("load requires actual graph validation before restoring execution"){_ = try IOSConnectionProfileStore.load(model:model,id:saved.id)}
   try check("unusable saved execution cannot replace unrelated selection",model.imports==0 && encoded(model.bundle!)==original)
   model.failGraph=false
   _=try IOSConnectionProfileStore.load(model:model,id:saved.id)
   try check("load restores selection while retaining current node credentials",model.selectedNodeProfile?.multihopExecution==execution && model.selectedNodeProfile?.external==current.routerProfiles[0].external && model.imports==1)
   let updated=try IOSConnectionProfileStore.update(model:model,id:saved.id,name:"Updated external execution")
   try check("Update retains saved execution record identity",updated.id==saved.id && updated.preferences?.multihopExecution==execution)
   try IOSConnectionProfileStore.delete(model:model,id:saved.id)
   try check("Delete removes only its connection record",IOSConnectionProfileStore.all().isEmpty && model.selectedNodeProfile?.external==current.routerProfiles[0].external)
   if layer != "off" {
    let again=try IOSConnectionProfileStore.add(model:model,name:"Layer identity");var changed=current
    changed.routerProfiles[0].external?.startLayer?.mode = layer=="aes-256-gcm" ? "aes-256-gcm+xor-whitening" : "aes-256-gcm"
    changed.routerProfiles[0].startLayer=changed.routerProfiles[0].external?.startLayer?.mode
    IOSNodeBundleStore.shared.bundles[p.id]=try JSONEncoder().encode(changed);model.bundle=bundle(profile("socks5","unrelated"));let before=try encoded(model.bundle!),writes=model.imports
    try reject("saved nonsecret choice cannot overwrite changed private layer"){_ = try IOSConnectionProfileStore.load(model:model,id:again.id)}
    try check("rejected layer restore retains current unrelated selection",encoded(model.bundle!)==before && model.imports==writes)
   }
  }}}
  for kind in IOSConnectionSafePreferences.ordinaryExternalModes.sorted() where !ExternalNodeConfig.serverExecutionProtocols.contains(kind) {
   var p=profile(kind);p.multihopEnabled=true;p.multihopEntryID="entry";p.multihopEntryMode="wg";p.multihopExitID=p.id;p.multihopExitMode=kind;p.multihopExecution="auto"
   let model=try reset(p)
   try reject("unsupported external execution cannot be saved as complete "+kind){_ = try IOSConnectionProfileStore.add(model:model,name:"Unowned execution")}
   try check("rejected execution creates no saved record",IOSPrivateJSONStore.writes==0 && model.imports==0)
  }
  for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {for execution in ["local","server","auto"] {
   let variable=layer=="off" ? "ROUTERVPN_OPENVPN_MULTIHOST_CLIENT_FIXTURE":layer=="aes-256-gcm" ? "ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_AES_FIXTURE":"ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_XOR_FIXTURE"
   let mapFixture=try json(Data(contentsOf:URL(fileURLWithPath:ProcessInfo.processInfo.environment[variable]!)))
   var mapped=profile("openvpn");mapped.external=try JSONDecoder().decode(ExternalNodeConfig.self,from:data(mapFixture["external"]!));mapped.startLayer=layer
   mapped.multihopEnabled=true;mapped.multihopEntryID="entry";mapped.multihopEntryMode="max-tls-awg";mapped.multihopExitID=mapped.id;mapped.multihopExitMode="openvpn";mapped.multihopExecution=execution
   let mapModel=try reset(mapped),mappedRecord=try IOSConnectionProfileStore.add(model:mapModel,name:"Private remote map")
   let publicRecord=String(decoding:IOSPrivateJSONStore.bytes!,as:UTF8.self)
   try check("complete connection record stores only node reference, not private maps",!publicRecord.contains("openvpn_start_layers") && !publicRecord.contains("10.93.0.1") && !publicRecord.contains("openvpn_response_probes") && !publicRecord.contains("response_probe") && !publicRecord.contains("server_name"))
   for probe in mapped.external!.openVPNResponseProbes!.values {try check("connection record omits each private probe",!publicRecord.contains(probe.url) && !publicRecord.contains(probe.serverName ?? "NONEXISTENT_NAME"))}
   for provision in mapped.external!.openVPNStartLayers?.values ?? [:].values {try check("complete profile never copies per-remote credentials",!publicRecord.contains(provision.transport.password))}
   var linked=bundle(mapped);linked.routerProfiles[0].external?.openVPNResponseProbes?["203.0.113.21"]?.url="https://203.0.113.21/new-response"
   if layer != "off" {linked.routerProfiles[0].external?.openVPNStartLayers?["203.0.113.21"]?.transport.password=Data(repeating:112,count:32).base64EncodedString()}
   linked.routerProfiles[0].multihopExecution="local"
   IOSNodeBundleStore.shared.bundles[mapped.id]=try JSONEncoder().encode(linked);mapModel.bundle=bundle(profile("socks5","unrelated"))
   _=try IOSConnectionProfileStore.load(model:mapModel,id:mappedRecord.id)
   try check("loading complete profile uses current private node maps and exact choice",mapModel.selectedNodeProfile?.external==linked.routerProfiles[0].external && mapModel.selectedNodeProfile?.startLayer==layer && mapModel.selectedNodeProfile?.multihopExecution==execution && mapModel.selectedNodeProfile?.multihopEntryMode=="max-tls-awg")
   if layer != "off" {
    var changed=linked;let other=layer=="aes-256-gcm" ? "aes-256-gcm+xor-whitening":"aes-256-gcm";changed.routerProfiles[0].startLayer=other
    for host in changed.routerProfiles[0].external!.openVPNStartLayers!.keys {changed.routerProfiles[0].external?.openVPNStartLayers?[host]?.mode=other}
    IOSNodeBundleStore.shared.bundles[mapped.id]=try JSONEncoder().encode(changed);mapModel.bundle=bundle(profile("socks5","unrelated"));let before=try encoded(mapModel.bundle!),writes=mapModel.imports
    try reject("saved selected layer cannot replace a different current private map"){_ = try IOSConnectionProfileStore.load(model:mapModel,id:mappedRecord.id)}
    try check("mismatched layer restore preserves unrelated selected owner",encoded(mapModel.bundle!)==before && mapModel.imports==writes)
   }
  }}
 }
 static func main()throws {
  defer {UserDefaults.standard.removeObject(forKey:iosConnectionProfilesKey);UserDefaults.standard.removeObject(forKey:iosConnectionModeKey);UserDefaults.standard.removeObject(forKey:iosConnectionCustomPresetsKey)}
  try matrix();try legacyAndFailures();try conflictingProtectionAndRouterSelection();try hostnameBootstrapPersistence();try missingDNSPreservesHome();try externalExecutionPersistence()
  print("Apple external whole connection profiles: PASS (\(checks) shipping store/model checks; storage and app boundaries substituted)")
 }
}
'''


def main():
    swift = shutil.which('swiftc')
    if not swift:
        raise RuntimeError('swiftc is required')
    source = (APP / 'IOSConnectionProfilesView.swift').read_text()
    source = source[:source.index('@MainActor\nstruct IOSConnectionProfilesView:')].replace('import SwiftUI\n', '')
    dns = (APP / 'IOSDNSRuntimePolicy.swift').read_text()
    modes = next(line for line in dns.splitlines() if 'static let modeIDs =' in line)
    selected = dns[dns.index('    static func selectedProfile('):dns.index('    static func resolve(')]
    policy = 'enum IOSDNSRuntimePolicy {\n' + modes + '\n' + selected + '}\n'
    with tempfile.TemporaryDirectory(prefix='ios-external-profiles-') as temporary:
        work = Path(temporary)
        options = [swift, '-swift-version', '6', '-module-cache-path', str(work / 'modules')]
        if platform.system() != 'Darwin':
            code = work / 'Network.swift';code.write_text(NETWORK)
            subprocess.run(options + ['-emit-module', '-emit-library', '-module-name', 'Network', str(code), '-emit-module-path', str(work / 'Network.swiftmodule'), '-o', str(work / 'libNetwork.so')], check=True, timeout=60)
            options += ['-I', str(work), '-L', str(work), '-lNetwork', '-Xlinker', '-rpath', '-Xlinker', str(work)]
        code = work / 'Tests.swift';code.write_text(source + '\n' + policy + BOUNDARIES)
        binary = work / 'tests'
        subprocess.run(options + [str(APP / 'Models.swift'), str(code), '-o', str(binary)], check=True, timeout=120)
        subprocess.run([str(binary)], env=dict(os.environ, ROUTERVPN_OPENVPN_CLIENT_FIXTURE=str(ROOT/'deploy/fixtures/external-openvpn-client.json'), ROUTERVPN_OPENVPN_MULTIHOST_CLIENT_FIXTURE=str(ROOT/'deploy/fixtures/external-openvpn-multihost-client.json'), ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_AES_FIXTURE=str(ROOT/'deploy/fixtures/external-openvpn-multihost-layered-aes-client.json'), ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_XOR_FIXTURE=str(ROOT/'deploy/fixtures/external-openvpn-multihost-layered-xor-client.json')), check=True, timeout=30)


if __name__ == '__main__':
    main()
