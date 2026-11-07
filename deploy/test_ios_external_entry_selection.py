#!/usr/bin/env python3
"""Execute Apple graph selection/save with shipping models and capture methods.

The node-store and native-mode readiness boundaries are deterministic doubles;
the separate Swift/Go policy gate validates compiled native configurations.
"""
from pathlib import Path
import importlib.util
import os
import platform
import subprocess
import tempfile
import ios_test_crypto_bridge as crypto

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
spec = importlib.util.spec_from_file_location('external_entry_native_boundary', ROOT / 'deploy/test_ios_tor_profile.py')
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
STUBS = r'''
import Foundation
import CryptoKit
import Libbox
enum IOSRuntimeSelector {
 static let multihopModeIDs:Set<String>=["wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","naive-h2","naive-h3","reality-vision","reality-pq-vision","reality-xhttp","ss-v2ray","split","max","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"]
 static func selectRaw(bundle:ClientBundle,rawProfileID:String)throws->Int {
  guard bundle.profiles[rawProfileID]?.isEmpty==false else{throw NSError(domain:"NativeReadinessBoundary",code:1)};return 1
 }
}
enum IOSNativeMAXProfile {static let modeIDs:Set<String>=[];static func decode(mode:String,encoded:[String:String])throws->Int{1}}
enum IOSNativePQProfile {static let modeIDs:Set<String>=[];static func decode(mode:String,encoded:[String:String])throws->Int{1}}
enum IOSDNSRuntimePolicy {
 // SHIPPING_SELECTED_PROFILE
 static func patch(_ value:ClientBundle)throws->ClientBundle{value}
}
@MainActor final class IOSNodeBundleStore {
 static let shared=IOSNodeBundleStore();var nodes:[String:Data]=[:]
 var failWrite=false
 private var records:[String:Data]{get{nodes}set{nodes=newValue}}
 private func ensureStorageReady()throws{}
 private func canonicalProfileID(_ id:String,current:ClientBundle?)->String{id}
 private func readableRecords(current:ClientBundle?)->[String:Data]{nodes}
 private func store(_ source:ClientBundle,replaceExistingRecord:Bool)throws->Data {
  let data=try JSONEncoder().encode(source);var next=nodes;next[source.selectedRouterID]=data;try commitRecords(next);return data
 }
 private func commitRecords(_ value:[String:Data])throws{if failWrite{throw NSError(domain:"StoreWriteBoundary",code:1)};nodes=value}
 // SHIPPING_METADATA_EDIT
 func bundleData(containing id:String,current:ClientBundle?)->Data? {
  if let current,current.routerProfiles.contains(where:{$0.id==id}){return try? JSONEncoder().encode(current)}
  return nodes[id]
 }
}
@MainActor final class RouterVPNModel {
 var bundle:ClientBundle?,profileMutationBlocked=false,message="",writes=0
 func importBundle(_ data:Data)throws{bundle=try JSONDecoder().decode(ClientBundle.self,from:data);writes+=1}
 func linkNodeBundle(_ data:Data)throws{
  if IOSNodeBundleStore.shared.failWrite {throw NSError(domain:"StoreWriteBoundary",code:1)}
  let incoming=try JSONDecoder().decode(ClientBundle.self,from:data)
  IOSNodeBundleStore.shared.nodes[incoming.selectedRouterID]=data
  try importBundle(data)
 }
}
func encoded(_ value:Any)throws->Data{try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
func encoded(_ value:ClientBundle)throws->Data{let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys];return try encoder.encode(value)}
func profile(_ id:String,_ kind:String,_ protocolName:String="socks5")throws->RouterProfile {
 let value:[String:Any]=["id":id,"name":id,"node_kind":kind,"node_proof_id":kind=="router-vpn" ? String(repeating:"a",count:64):"",
  "endpoint":"198.51.100.8","router_api":kind=="router-vpn" ? "http://10.8.0.1:8787":"","api_token":"private-node-token",
  "adguard_ipv4":"192.168.50.133","adguard_ipv6":"","socks_host":"","socks_port":0,"socks_username":"","socks_password":"",
  "external":["protocol":protocolName,"expected_public_ip":"203.0.113.88","socks5":["host":"198.51.100.8","port":1080,"username":" exact user ","password":" exact secret "]],
  "start_layer":"off","dns_mode":"custom","dns_protocol":"tcp","dns_host":"9.9.9.9","dns_port":5353,"mtu_policy":"fixed","manual_mtu":1380,"home_lan_access":false,"ipv6_mode":"off"]
 return try JSONDecoder().decode(RouterProfile.self,from:encoded(value))
}
func bundle(_ p:RouterProfile)->ClientBundle{var value=ClientBundle.empty;value.selectedRouterID=p.id;value.routerProfiles=[p];value.profiles=["wg":["wg.conf":Data("exact private config".utf8).base64EncodedString()]];return value}
@MainActor @main struct Tests {
 static var checks=0;static var latest="startup"
 static func check(_ name:String,_ result:@autoclosure ()throws->Bool)throws{latest=name;guard try result()else{throw NSError(domain:"ExternalSelection",code:1,userInfo:[NSLocalizedDescriptionKey:name])};checks+=1}
 static func reject(_ name:String,_ operation:()throws->Void)throws{latest=name;do{try operation()}catch{checks+=1;return};throw NSError(domain:"ExternalRejection",code:1,userInfo:[NSLocalizedDescriptionKey:name])}
 static func main() { do { try run() } catch { FileHandle.standardError.write(Data(("FAIL after "+String(checks)+" checks at "+latest+": "+error.localizedDescription+"\n").utf8));exit(1) } }
 static func configured(_ finalBundle:ClientBundle,_ paired:RouterProfile,_ selectedKind:String,_ selectedLayer:String)throws {
  for kind in [selectedKind] {
   var source=try profile("service-connect-entry","external",kind);source.apiToken=""
   let transport=ExternalHTTPConnectConfig(host:"198.51.100.8",port:8443,username:" original user ",password:" original password ",tlsServerName:kind=="https-connect" ? "proxy.example.com":nil)
   if kind=="http-connect" {source.external?.httpConnect=transport}else{source.external?.httpsConnect=transport}
   let original=bundle(source)
   for layer in [selectedLayer] {for dnsMode in ["home","custom"] {for dnsTransport in ["udp","tcp"] {
    var final=finalBundle
    final.routerProfiles[0].startLayer=layer;final.routerProfiles[0].dnsMode=dnsMode;final.routerProfiles[0].dnsProtocol=dnsTransport;final.routerProfiles[0].dnsHost=dnsMode=="home" ? "192.168.50.133":"203.0.113.53";final.routerProfiles[0].dnsPort=5353
    let raw=Data(base64Encoded:final.profiles["shadowsocks"]!["sing-box.json"]!)!,graph=try JSONSerialization.jsonObject(with:raw) as! [String:Any],out=(graph["outbounds"] as! [[String:Any]])[0]
    func hash(_ data:Data)->String{CryptoKit.SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
    let claim:[String:Any]=["schema":1,"node_id":final.routerProfiles[0].nodeProofID!,"configured_image":"ghcr.io/sagernet/sing-box:v1.13.12","uot_version":2,"endpoint":out["server"]!,"port":out["server_port"]!,"method":out["method"]!,"key_sha256":hash(Data((out["password"] as! String).utf8)),"source_sha256":hash(raw)]
    final.profiles["shadowsocks"]!["routervpn-ss-service.json"]=try encoded(claim).base64EncodedString()
    let model=RouterVPNModel();model.bundle=final
    IOSNodeBundleStore.shared.nodes=[source.id:try encoded(original),paired.id:try encoded(final)]
    try model.saveIOSMultihop(enabled:true,entryID:source.id,exitID:paired.id,exitMode:"shadowsocks",execution:"local",entryMode:kind)
    let held=try model.iosMultihopEntryBundle(for:model.bundle!)
    try check("configured CONNECT retains original sources",held.profiles==original.profiles && held.routerProfiles==original.routerProfiles && model.bundle!.profiles==final.profiles)
    try check("configured CONNECT retains selected DNS and layer",model.bundle!.routerProfiles[0].dnsProtocol==dnsTransport && model.bundle!.routerProfiles[0].dnsHost==final.routerProfiles[0].dnsHost && model.bundle!.routerProfiles[0].dnsPort==5353 && model.bundle!.routerProfiles[0].startLayer==layer)
    let configuration:[String:Any]=["engine":"multihop-libbox","mode":"shadowsocks","bundle":try encoded(model.bundle!),"entryBundle":try encoded(original)]
    _ = try IOSMultihopExecution.Source(configuration:configuration,digest:hash)
    var malformedBundle=try JSONSerialization.jsonObject(with:encoded(model.bundle!)) as! [String:Any]
    malformedBundle["profiles"]=["shadowsocks":true]
    var malformedConfiguration=configuration;malformedConfiguration["bundle"]=try encoded(malformedBundle)
    try reject("configured source refuses malformed asset container"){_ = try IOSMultihopExecution.Source(configuration:malformedConfiguration,digest:hash)}
    let firstProfile=try JSONSerialization.jsonObject(with:JSONEncoder().encode(source)) as! [String:Any]
    let lastProfile=try JSONSerialization.jsonObject(with:JSONEncoder().encode(model.bundle!.routerProfiles[0])) as! [String:Any]
    for empty in [false,true] {
     var defaults=lastProfile;defaults["dns_mode"]="home"
     if empty {defaults["dns_protocol"]=""}else{defaults.removeValue(forKey:"dns_protocol")}
     try IOSImportedEntryMultihop.validate(entry:firstProfile,final:defaults,profiles:final.profiles)
     defaults["dns_mode"]="custom"
     try reject("configured custom DNS requires explicit transport"){try IOSImportedEntryMultihop.validate(entry:firstProfile,final:defaults,profiles:final.profiles)}
    }
    var wrongType=lastProfile;wrongType["dns_protocol"]=true
    try reject("configured DNS transport type is strict"){try IOSImportedEntryMultihop.validate(entry:firstProfile,final:wrongType,profiles:final.profiles)}
    for fault in ["missing","foreign","stale","malformed"] {
     var changed=model.bundle!,files=changed.profiles["shadowsocks"]!,badClaim=claim
     if fault=="missing" {files.removeValue(forKey:"routervpn-ss-service.json");changed.routerProfiles[0].dnsProtocol="udp"}
     else {if fault=="foreign" {badClaim["node_id"]=String(repeating:"f",count:64)}else{badClaim["source_sha256"]=String(repeating:"0",count:64)};files["routervpn-ss-service.json"]=(fault=="malformed" ? Data("{".utf8):try encoded(badClaim)).base64EncodedString()}
     changed.profiles["shadowsocks"]=files
     try reject("configured CONNECT refuses missing or invalid authority "+fault){_ = try model.iosMultihopEntryBundle(for:changed)}
     var replaced=configuration;replaced["bundle"]=try encoded(changed)
     try reject("configured CONNECT source capture refuses authority "+fault){_ = try IOSMultihopExecution.Source(configuration:replaced,digest:hash)}
    }
   }}}
  }
  print("PASS configured CONNECT "+selectedKind+" "+selectedLayer+" "+String(checks)+" checks")
 }
 static func selectedDNS(_ finalBundle:ClientBundle,_ paired:RouterProfile,_ kind:String,_ carrier:String)throws {
  var source=try profile("encrypted-connect-entry","external",kind);source.apiToken=""
  let connect=ExternalHTTPConnectConfig(host:"198.51.100.8",port:8443,username:" original user ",password:" original password ",tlsServerName:kind=="https-connect" ? "proxy.example.com":nil)
  if kind=="http-connect" {source.external?.httpConnect=connect}else{source.external?.httpsConnect=connect}
  let original=bundle(source)
  func hash(_ data:Data)->String{CryptoKit.SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
  var cases=0
  for transport in ["tls","https","h3"] {for hostname in [false,true] {
   var final=finalBundle
   var selected=try JSONSerialization.jsonObject(with:JSONEncoder().encode(final.routerProfiles[0])) as! [String:Any]
   selected["start_layer"]=carrier=="plain" ? "off":carrier
   selected["dns_mode"]=hostname ? ["tls":"dot","https":"doh","h3":"doh3"][transport]! : "custom"
   selected["dns_protocol"]=transport;selected["dns_host"]=hostname ? "resolver.example.net":"203.0.113.53";selected["dns_port"]=8853
   selected["dns_server_name"]="resolver.example.net";selected["dns_path"]="/owned-dns-query"
   if hostname {selected["dns_bootstrap"]=["server":["type":carrier=="plain" ? "tcp":"udp","tag":"external-dns-bootstrap","server":"203.0.113.54","server_port":5354,"detour":"proxy"],"query":["server":"external-dns-bootstrap","timeout":"3s","disable_optimistic_cache":true]] as [String:Any]}
   final.routerProfiles[0]=try JSONDecoder().decode(RouterProfile.self,from:encoded(selected))
   if carrier != "plain" {
    let raw=Data(base64Encoded:final.profiles["shadowsocks"]!["sing-box.json"]!)!,graph=try JSONSerialization.jsonObject(with:raw) as! [String:Any],out=(graph["outbounds"] as! [[String:Any]])[0]
    let claim:[String:Any]=["schema":1,"node_id":final.routerProfiles[0].nodeProofID!,"configured_image":"ghcr.io/sagernet/sing-box:v1.13.12","uot_version":2,"endpoint":out["server"]!,"port":out["server_port"]!,"method":out["method"]!,"key_sha256":hash(Data((out["password"] as! String).utf8)),"source_sha256":hash(raw)]
    final.profiles["shadowsocks"]!["routervpn-ss-service.json"]=try encoded(claim).base64EncodedString()
   }
   IOSNodeBundleStore.shared.nodes=[source.id:try encoded(original),paired.id:try encoded(final)]
   let model=RouterVPNModel();model.bundle=final
   if carrier=="plain" && transport=="h3" {try reject("unprovisioned CONNECT refuses selected H3"){try model.saveIOSMultihop(enabled:true,entryID:source.id,exitID:paired.id,exitMode:"shadowsocks",execution:"local",entryMode:kind)};cases+=1;continue}
   try model.saveIOSMultihop(enabled:true,entryID:source.id,exitID:paired.id,exitMode:"shadowsocks",execution:"local",entryMode:kind)
   let held=try model.iosMultihopEntryBundle(for:model.bundle!)
   try check("selected encrypted DNS retains original profiles",held.routerProfiles==original.routerProfiles && model.bundle!.routerProfiles[0].dnsBootstrap==final.routerProfiles[0].dnsBootstrap && model.bundle!.routerProfiles[0].dnsProtocol==transport && model.bundle!.routerProfiles[0].dnsHost==final.routerProfiles[0].dnsHost && model.bundle!.profiles==final.profiles)
   let config:[String:Any]=["engine":"multihop-libbox","mode":"shadowsocks","bundle":try encoded(model.bundle!),"entryBundle":try encoded(original)]
   let captured=try IOSMultihopExecution.Source(configuration:config,digest:hash)
   var changed=model.bundle!;changed.routerProfiles[0].dnsServerName="different.example.net"
   var replaced=config;replaced["bundle"]=try encoded(changed)
   let altered=try IOSMultihopExecution.Source(configuration:replaced,digest:hash)
   try check("selected DNS identity changes source capture",captured != altered)
   cases+=1
  }}
  guard cases==6 else {throw IOSImportedEntryMultihop.issue()}
  print("PASS selected DNS "+kind+" "+carrier+" 6 cases")
 }
 static func reality(_ finalBundle:ClientBundle,_ paired:RouterProfile,_ kind:String="socks5")throws {
  func hash(_ data:Data)->String{CryptoKit.SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
  var first=try profile("reality-"+kind,"external",kind);first.apiToken="";first.dnsMode="home"
  if kind != "socks5"{first.external?.socks5=nil}
  if kind=="shadowsocks"{first.external?.shadowsocks=ExternalShadowsocksConfig(server:"198.51.100.8",port:443,method:"2022-blake3-aes-256-gcm",password:Data(repeating:109,count:32).base64EncodedString())}
  if kind=="hysteria2"{first.external?.hysteria2=ExternalHysteria2Config(server:"198.51.100.8",port:443,password:" exact original Hysteria secret ",tlsServerName:"captured-external.example")}
  let original=bundle(first)
  var final=finalBundle
  final.profiles["reality-vision"]=["sing-box.json":Data("captured wrapper readiness is checked by the separate Swift/Go producer".utf8).base64EncodedString(),"xray.json":Data("complete original private Xray source".utf8).base64EncodedString()]
  let model=RouterVPNModel();model.bundle=final
  IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(final)]
  try check("REALITY picker requires exact captured SOCKS source",model.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains("reality-vision"))
  try check("REALITY picker never infers missing entry",!model.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id).contains("reality-vision"))
  try model.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:"reality-vision",execution:"local",entryMode:kind)
  let captured=try model.iosMultihopEntryBundle(for:model.bundle!)
  try check("REALITY selection keeps complete original entry",captured.routerProfiles==original.routerProfiles && captured.profiles==original.profiles)
  try check("REALITY selection keeps full final assets",model.bundle!.profiles==final.profiles)
  try check("REALITY selection retains final DNS and pairing",model.bundle!.routerProfiles[0].dnsMode==paired.dnsMode && model.bundle!.routerProfiles[0].adGuardIPv4==paired.adGuardIPv4 && model.bundle!.routerProfiles[0].nodeProofID==paired.nodeProofID)
  let configuration:[String:Any]=["engine":"multihop-libbox","mode":"reality-vision","bundle":try encoded(model.bundle!),"entryBundle":try encoded(original)]
  let source=try IOSMultihopExecution.Source(configuration:configuration,digest:hash)
  try check("REALITY capture binds actual roles",source.entryID==first.id && source.exitID==paired.id && source.entryMode==kind && source.exitMode=="reality-vision")
  for asset in ["xray.json","sing-box.json"] {
   var changed=model.bundle!;changed.profiles["reality-vision"]![asset]=Data("replacement original asset".utf8).base64EncodedString()
   var replaced=configuration;replaced["bundle"]=try encoded(changed)
   let next=try IOSMultihopExecution.Source(configuration:replaced,digest:hash)
   try check("REALITY source fingerprint retains asset "+asset,next != source)
  }
  let saved=try encoded(model.bundle!),writes=model.writes
  for kind in ["http-connect","https-connect","openvpn","wireguard","amneziawg"] {
   try check("REALITY unsupported entry remains refused "+kind,!IOSImportedEntryMultihop.supports(entry:kind,final:"reality-vision"))
  }
  for kind in ["shadowsocks","hysteria2"]{try check("REALITY supports captured encrypted proxy "+kind,IOSImportedEntryMultihop.supports(entry:kind,final:"reality-vision"))}
  for mode in ["reality-pq-vision","reality-xhttp","split","max","max-tls-wg"] {
   try check("SOCKS unrelated final remains refused "+mode,!IOSImportedEntryMultihop.supports(entry:kind,final:mode))
  }
  var layerPairs=Set<String>()
  for entryLayer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {for finalLayer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   var first=first;first.startLayer=entryLayer
   if entryLayer != "off" {
    first.external?.startLayer=try JSONDecoder().decode(ExternalStartLayer.self,from:encoded(["mode":entryLayer,"api":"http://10.93.0.1:8787","transport":["type":"shadowsocks","tag":"private-start-layer","server":"198.51.100.8","server_port":8388,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:106,count:32).base64EncodedString()]]))
   }
   let original=bundle(first);var final=final;final.routerProfiles[0].startLayer=finalLayer
   let target=RouterVPNModel();target.bundle=final
   IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(final)]
   try check("REALITY picker retains independently provisioned layers",target.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains("reality-vision"))
   try target.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:"reality-vision",execution:"local",entryMode:kind)
   let captured=try target.iosMultihopEntryBundle(for:target.bundle!)
   try check("REALITY layers preserve both exact original sources",captured.routerProfiles==original.routerProfiles && captured.profiles==original.profiles && target.bundle!.profiles==final.profiles && captured.routerProfiles[0].startLayer==entryLayer && target.bundle!.routerProfiles[0].startLayer==finalLayer)
   try check("REALITY layers keep distinct authentication and paired DNS",captured.routerProfiles[0].external==first.external && captured.apiToken.isEmpty && captured.routerAPI.isEmpty && captured.nodeProofID.isEmpty && target.bundle!.routerProfiles[0].apiToken==paired.apiToken && target.bundle!.routerProfiles[0].dnsMode==paired.dnsMode && target.bundle!.routerProfiles[0].adGuardIPv4==paired.adGuardIPv4)
   let configuration:[String:Any]=["engine":"multihop-libbox","mode":"reality-vision","bundle":try encoded(target.bundle!),"entryBundle":try encoded(original)]
   let source=try IOSMultihopExecution.Source(configuration:configuration,digest:hash)
   try check("REALITY layer receipt binds both captured roles and Local",source.entryID==first.id && source.exitID==paired.id && source.entryMode==kind && source.exitMode=="reality-vision" && source.requested=="local")
   let saved=try encoded(target.bundle!),writes=target.writes
   if entryLayer != "off" {
    var changed=first;changed.external!.startLayer!.transport.password=Data(repeating:107,count:32).base64EncodedString()
    var next=configuration;next["entryBundle"]=try encoded(bundle(changed))
    let replacement=try IOSMultihopExecution.Source(configuration:next,digest:hash)
    try check("REALITY source fingerprint binds independent entry layer key",replacement.entrySHA256 != source.entrySHA256 && replacement.bundleSHA256==source.bundleSHA256)
    var missing=first;missing.external?.startLayer=nil;IOSNodeBundleStore.shared.nodes[first.id]=try encoded(bundle(missing))
    try reject("REALITY selected entry layer requires its own provision"){_ = try target.iosMultihopEntryBundle(for:target.bundle!)}
    try check("REALITY missing entry provision preserves exact saved owner",target.writes==writes && encoded(target.bundle!)==saved)
    IOSNodeBundleStore.shared.nodes[first.id]=try encoded(original)
   }
   if finalLayer != "off" {
    var changed=target.bundle!,graph=try JSONSerialization.jsonObject(with:Data(base64Encoded:changed.profiles["shadowsocks"]!["sing-box.json"]!)!) as! [String:Any]
    var outbounds=graph["outbounds"] as! [[String:Any]];outbounds[0]["password"]=Data(repeating:108,count:32).base64EncodedString();graph["outbounds"]=outbounds
    changed.profiles["shadowsocks"]!["sing-box.json"]=try encoded(graph).base64EncodedString()
    var next=configuration;next["bundle"]=try encoded(changed)
    let replacement=try IOSMultihopExecution.Source(configuration:next,digest:hash)
    try check("REALITY source fingerprint binds independent final layer key",replacement.bundleSHA256 != source.bundleSHA256 && replacement.entrySHA256==source.entrySHA256)
    var missing=final;missing.profiles.removeValue(forKey:"shadowsocks")
    IOSNodeBundleStore.shared.nodes[paired.id]=try encoded(missing)
    let rejected=RouterVPNModel();rejected.bundle=missing
    try reject("REALITY selected final layer requires its own provision"){try rejected.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:"reality-vision",execution:"local",entryMode:kind)}
    try check("REALITY missing final provision preserves exact saved owner",rejected.writes==0 && encoded(rejected.bundle!)==encoded(missing) && target.writes==writes && encoded(target.bundle!)==saved)
   }
   layerPairs.insert(entryLayer+"/"+finalLayer)
  }}
  try check("REALITY captures all nine independent layer selections",layerPairs.count==9)
  for fault in ["missing-entry-aes","missing-entry-xor","missing-final-aes","missing-final-xor","server","auto","missing-assets","changed-entry","entry-type","final-type"] {
   var source=first,other=final,execution="local"
   if fault=="missing-entry-aes"{source.startLayer="aes-256-gcm"}
   if fault=="missing-entry-xor"{source.startLayer="aes-256-gcm+xor-whitening"}
   if fault=="missing-final-aes"{other.routerProfiles[0].startLayer="aes-256-gcm";other.profiles.removeValue(forKey:"shadowsocks")}
   if fault=="missing-final-xor"{other.routerProfiles[0].startLayer="aes-256-gcm+xor-whitening";other.profiles.removeValue(forKey:"shadowsocks")}
   if fault=="server" || fault=="auto"{execution=fault}
   if fault=="missing-assets"{other.profiles.removeValue(forKey:"reality-vision")}
   if fault=="changed-entry"{source.external?.protocolName="openvpn"}
   IOSNodeBundleStore.shared.nodes=[first.id:try encoded(bundle(source)),paired.id:try encoded(other)]
   let target=RouterVPNModel();target.bundle=other
   if fault=="entry-type" || fault=="final-type" {
    var entry=try JSONSerialization.jsonObject(with:JSONEncoder().encode(first)) as! [String:Any]
    var last=try JSONSerialization.jsonObject(with:JSONEncoder().encode(model.bundle!.routerProfiles[0])) as! [String:Any]
    if fault=="entry-type"{entry["start_layer"]=true}else{last["start_layer"]=true}
    try reject("REALITY rejects malformed layer "+fault){try IOSImportedEntryMultihop.validate(entry:entry,final:last,profiles:final.profiles)}
   }else{
    try reject("REALITY selection rejects "+fault){try target.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:"reality-vision",execution:execution,entryMode:kind)}
    try check("REALITY refusal retains original selection "+fault,target.writes==0 && encoded(target.bundle!)==encoded(other))
   }
  }
  try check("REALITY rejected alternatives do not replace saved owner",model.writes==writes && encoded(model.bundle!)==saved)
  print("PASS "+(kind=="socks5" ? "SOCKS":kind)+" REALITY host \(checks) checks")
 }
 static func run()throws {
  defer { RouterVPNTorTestClose() }
  var imported=try profile("imported-first","external","shadowsocks");imported.apiToken="";imported.dnsMode="home"
  imported.external?.shadowsocks=ExternalShadowsocksConfig(server:"203.0.113.20",port:443,method:"2022-blake3-aes-256-gcm",password:Data(repeating:9,count:32).base64EncodedString())
  var paired=try profile("paired-final","router-vpn");paired.external=nil;paired.dnsMode="home"
  var finalBundle=bundle(paired)
  finalBundle.profiles["shadowsocks"]=["sing-box.json":try encoded(["outbounds":[["type":"shadowsocks","tag":"proxy","server":"192.0.2.44","server_port":443,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:8,count:32).base64EncodedString()]]]).base64EncodedString()]
  if CommandLine.arguments.count == 3 && CommandLine.arguments[2] == "socks-reality" {try reality(finalBundle,paired);return}
  if CommandLine.arguments.count == 5 && CommandLine.arguments[2] == "selected-dns" { try selectedDNS(finalBundle,paired,CommandLine.arguments[3],CommandLine.arguments[4]);return }
  if CommandLine.arguments.count == 4 && CommandLine.arguments[2] == "proxy-reality" {guard ["shadowsocks","hysteria2"].contains(CommandLine.arguments[3]) else {throw IOSImportedEntryMultihop.issue()};try reality(finalBundle,paired,CommandLine.arguments[3]);return}
  if CommandLine.arguments.count == 4 { try configured(finalBundle,paired,CommandLine.arguments[2],CommandLine.arguments[3]);return }
  let importedBundle=bundle(imported),mixed=RouterVPNModel();mixed.bundle=finalBundle
  IOSNodeBundleStore.shared.nodes=[imported.id:try encoded(importedBundle),paired.id:try encoded(finalBundle)]
  try mixed.saveIOSMultihop(enabled:true,entryID:imported.id,exitID:paired.id,exitMode:"shadowsocks",execution:"local",entryMode:"shadowsocks")
  let importedCapture=try mixed.iosMultihopEntryBundle(for:mixed.bundle!)
  try check("imported Router captures complete independent entry policy",importedCapture.routerProfiles==importedBundle.routerProfiles && importedCapture.profiles==importedBundle.profiles && importedCapture.apiToken.isEmpty && importedCapture.routerAPI.isEmpty && importedCapture.nodeProofID.isEmpty)
  try check("imported Router retains final paired identity and Home DNS",mixed.bundle?.routerProfiles[0].nodeProofID==paired.nodeProofID && mixed.bundle?.routerProfiles[0].dnsMode=="home" && mixed.bundle?.profiles==finalBundle.profiles)
  let savedMixed=try encoded(mixed.bundle!),mixedWrites=mixed.writes
  for fault in ["server","auto","wrong-mode","private-token","missing-public-proof","legacy-ss"] {
   var changed=imported,execution="local",mode="shadowsocks"
   switch fault {
   case "server","auto":execution=fault
   case "wrong-mode":mode="wg"
   case "private-token":changed.apiToken="invented Router credential"
   case "missing-public-proof":changed.external?.expectedPublicIP=""
   default:changed.external?.shadowsocks?.method="aes-256-gcm"
   }
   IOSNodeBundleStore.shared.nodes[imported.id]=try encoded(bundle(changed))
   try reject("imported Router rejects "+fault){try mixed.saveIOSMultihop(enabled:true,entryID:imported.id,exitID:paired.id,exitMode:"shadowsocks",execution:execution,entryMode:mode)}
   try check("rejected imported selection cannot mutate saved graph",mixed.writes==mixedWrites && encoded(mixed.bundle!)==savedMixed)
  }
  var hysteria=try profile("imported-hysteria","external","hysteria2");hysteria.apiToken="";hysteria.dnsMode="home"
  hysteria.external?.hysteria2=ExternalHysteria2Config(server:"203.0.113.21",port:443,password:" exact HY2 password ",tlsServerName:"entry.example.test")
  let hyBundle=bundle(hysteria),hyModel=RouterVPNModel();hyModel.bundle=finalBundle
  IOSNodeBundleStore.shared.nodes=[hysteria.id:try encoded(hyBundle),paired.id:try encoded(finalBundle)]
  try hyModel.saveIOSMultihop(enabled:true,entryID:hysteria.id,exitID:paired.id,exitMode:"shadowsocks",execution:"local",entryMode:"hysteria2")
  let hyCaptured=try hyModel.iosMultihopEntryBundle(for:hyModel.bundle!)
  try check("HY2 selection retains exact TLS/password/source",hyCaptured.routerProfiles==hyBundle.routerProfiles && hyCaptured.routerProfiles[0].external?.hysteria2==hysteria.external?.hysteria2 && hyModel.bundle?.routerProfiles[0].multihopEntryMode=="hysteria2")
  let savedHY=try encoded(hyModel.bundle!),hyWrites=hyModel.writes
  for fault in ["empty-password","empty-TLS","malformed-TLS","wrong-mode","server","auto","private-token"] {
   var changed=hysteria,execution="local",mode="hysteria2"
   switch fault {
   case "empty-password":changed.external?.hysteria2?.password=""
   case "empty-TLS":changed.external?.hysteria2?.tlsServerName=""
   case "malformed-TLS":changed.external?.hysteria2?.tlsServerName="https://other.example.test"
   case "wrong-mode":mode="shadowsocks"
   case "server","auto":execution=fault
   default:changed.apiToken="invented paired entry credential"
   }
   IOSNodeBundleStore.shared.nodes[hysteria.id]=try encoded(bundle(changed))
   try reject("HY2 selection rejects "+fault){try hyModel.saveIOSMultihop(enabled:true,entryID:hysteria.id,exitID:paired.id,exitMode:"shadowsocks",execution:execution,entryMode:mode)}
   try check("rejected HY2 selection keeps original saved graph",hyModel.writes==hyWrites && encoded(hyModel.bundle!)==savedHY)
  }
  var socks=try profile("imported-socks","external","socks5");socks.apiToken="";socks.dnsMode="home"
  let socksBundle=bundle(socks),socksModel=RouterVPNModel();socksModel.bundle=finalBundle
  IOSNodeBundleStore.shared.nodes=[socks.id:try encoded(socksBundle),paired.id:try encoded(finalBundle)]
  try check("SOCKS picker offers captured SS final",socksModel.iosImportedRouterFinalModes(entryMode:"socks5",exitID:paired.id).contains("shadowsocks"))
  try socksModel.saveIOSMultihop(enabled:true,entryID:socks.id,exitID:paired.id,exitMode:"shadowsocks",execution:"local",entryMode:"socks5")
  let socksCaptured=try socksModel.iosMultihopEntryBundle(for:socksModel.bundle!)
  try check("SOCKS selection retains complete original source and exact authentication",socksCaptured.routerProfiles==socksBundle.routerProfiles && socksCaptured.profiles==socksBundle.profiles && socksCaptured.routerProfiles[0].external?.socks5==socks.external?.socks5 && socksModel.bundle?.routerProfiles[0].multihopEntryMode=="socks5")
  for finalMode in ["shadowsocks","hysteria2","wg","awg2-fast","awg2-strong"] {for entryLayer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {for finalLayer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   var source=socks;source.startLayer=entryLayer
   if entryLayer != "off" {
    source.external?.startLayer=try JSONDecoder().decode(ExternalStartLayer.self,from:encoded(["mode":entryLayer,"api":"http://10.93.0.1:8787","transport":["type":"shadowsocks","tag":"private-start-layer","server":"198.51.100.8","server_port":8388,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:106,count:32).base64EncodedString()]]))
   }
   let original=bundle(source);var final=finalBundle;final.routerProfiles[0].startLayer=finalLayer
   final.profiles["hysteria2"]=["sing-box.json":Data("native readiness is separately exercised by shipping compiler fixture".utf8).base64EncodedString()]
   for mode in ["awg2-fast","awg2-strong"]{final.profiles[mode]=["awg.conf":Data("captured native peer fixture boundary".utf8).base64EncodedString()]}
   let model=RouterVPNModel();model.bundle=final
   IOSNodeBundleStore.shared.nodes=[source.id:try encoded(original),paired.id:try encoded(final)]
   try check("SOCKS picker keeps provisioned final "+finalMode,model.iosImportedRouterFinalModes(entryMode:"socks5",exitID:paired.id).contains(finalMode))
   try model.saveIOSMultihop(enabled:true,entryID:source.id,exitID:paired.id,exitMode:finalMode,execution:"local",entryMode:"socks5")
   let captured=try model.iosMultihopEntryBundle(for:model.bundle!)
   try check("SOCKS layer selection preserves both independent sources",captured.routerProfiles==original.routerProfiles && captured.profiles==original.profiles && model.bundle?.profiles==final.profiles && captured.routerProfiles[0].startLayer==entryLayer && model.bundle?.routerProfiles[0].startLayer==finalLayer)
   try check("SOCKS layers never borrow paired credentials",captured.apiToken.isEmpty && captured.routerAPI.isEmpty && captured.nodeProofID.isEmpty && model.bundle?.routerProfiles[0].apiToken==paired.apiToken && captured.routerProfiles[0].external?.socks5==socks.external?.socks5)
   let before=try encoded(model.bundle!),writes=model.writes
   for execution in ["server","auto"] {
    try reject("SOCKS layers cannot add execution authority "+execution){try model.saveIOSMultihop(enabled:true,entryID:source.id,exitID:paired.id,exitMode:finalMode,execution:execution,entryMode:"socks5")}
    try check("unavailable SOCKS execution leaves exact saved selection",model.writes==writes && encoded(model.bundle!)==before)
   }
   if entryLayer != "off" {
    var missing=source;missing.external?.startLayer=nil;IOSNodeBundleStore.shared.nodes[source.id]=try encoded(bundle(missing))
    try reject("SOCKS selection requires matching provisioned entry layer"){_ = try model.iosMultihopEntryBundle(for:model.bundle!)}
    try check("missing SOCKS provision cannot alter selection",model.writes==writes && encoded(model.bundle!)==before)
   }
  }}}
  for kind in ["http-connect","https-connect"] {
   var source=try profile("connect-entry","external",kind);source.apiToken=""
   let transport=ExternalHTTPConnectConfig(host:"198.51.100.8",port:8443,username:" exact user ",password:" exact secret ",tlsServerName:kind=="https-connect" ? "proxy.example.com":nil)
   if kind=="http-connect" {source.external?.httpConnect=transport}else{source.external?.httpsConnect=transport}
   let original=bundle(source);var final=finalBundle;final.routerProfiles[0].dnsProtocol="tcp";final.routerProfiles[0].dnsHost="192.168.50.133";final.routerProfiles[0].dnsPort=5353
   let model=RouterVPNModel();model.bundle=final
   IOSNodeBundleStore.shared.nodes=[source.id:try encoded(original),paired.id:try encoded(final)]
   try check("CONNECT picker offers SS2022 only",model.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id)==["shadowsocks"])
   try model.saveIOSMultihop(enabled:true,entryID:source.id,exitID:paired.id,exitMode:"shadowsocks",execution:"local",entryMode:kind)
   let held=try model.iosMultihopEntryBundle(for:model.bundle!)
   try check("CONNECT save retains independent credentials and original sources",held.routerProfiles==original.routerProfiles && held.profiles==original.profiles && model.bundle?.profiles==final.profiles)
   try check("CONNECT save retains exact captured Home TCP DNS",model.bundle?.routerProfiles[0].dnsMode=="home" && model.bundle?.routerProfiles[0].dnsProtocol=="tcp" && model.bundle?.routerProfiles[0].dnsHost=="192.168.50.133" && model.bundle?.routerProfiles[0].dnsPort==5353)
   for fault in ["udp","entry-layer","final-layer","server","packet-final"] {
    var first=source,last=final;var execution="local",mode="shadowsocks"
    if fault=="udp" {last.routerProfiles[0].dnsProtocol="udp"}
    else if fault=="entry-layer" {first.startLayer="aes-256-gcm"}
    else if fault=="final-layer" {last.routerProfiles[0].startLayer="aes-256-gcm"}
    else if fault=="server" {execution="server"}else{mode="wg"}
    IOSNodeBundleStore.shared.nodes=[source.id:try encoded(bundle(first)),paired.id:try encoded(last)]
    let refused=RouterVPNModel();refused.bundle=last;let unchanged=try encoded(last)
    try reject("CONNECT selection refuses unsupported captured policy "+fault){try refused.saveIOSMultihop(enabled:true,entryID:source.id,exitID:paired.id,exitMode:mode,execution:execution,entryMode:kind)}
    try check("CONNECT rejected save leaves original stored selection",refused.writes==0 && encoded(refused.bundle!)==unchanged)
   }
  }
  for network in ["tcp","udp"] {
   var ovpn=try profile("imported-openvpn-"+network,"external","openvpn");ovpn.apiToken="";ovpn.dnsMode="home";ovpn.external?.socks5=nil
   ovpn.external?.openVPN=ExternalOpenVPNConfig(config:"client\ndev tun\nproto "+network+"\nremote 198.51.100.8 1194\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint "+String(repeating:"ab",count:32)+"\ntun-mtu 1500\n",username:" exact user ",password:" exact secret ")
  for finalMode in ["shadowsocks","hysteria2","wg","awg2-fast","awg2-strong"] {for entryLayer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {for finalLayer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   var source=ovpn;source.startLayer=entryLayer
   if entryLayer != "off" {
    source.external?.startLayer=try JSONDecoder().decode(ExternalStartLayer.self,from:encoded(["mode":entryLayer,"api":"http://10.93.0.1:8787","transport":["type":"shadowsocks","tag":"private-start-layer","server":"198.51.100.8","server_port":8388,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:106,count:32).base64EncodedString()]]))
   }
   let original=bundle(source);var final=finalBundle;final.routerProfiles[0].startLayer=finalLayer
   final.profiles["hysteria2"]=["sing-box.json":Data("native readiness is separately exercised by shipping compiler fixture".utf8).base64EncodedString()]
   for mode in ["awg2-fast","awg2-strong"]{final.profiles[mode]=["awg.conf":Data("captured native peer fixture boundary".utf8).base64EncodedString()]}
   let model=RouterVPNModel();model.bundle=final
   IOSNodeBundleStore.shared.nodes=[source.id:try encoded(original),paired.id:try encoded(final)]
   try check("OpenVPN picker keeps provisioned final "+finalMode,model.iosImportedRouterFinalModes(entryMode:"openvpn",exitID:paired.id).contains(finalMode))
   try model.saveIOSMultihop(enabled:true,entryID:source.id,exitID:paired.id,exitMode:finalMode,execution:"local",entryMode:"openvpn")
   let captured=try model.iosMultihopEntryBundle(for:model.bundle!)
   try check("OpenVPN layer selection preserves both independent sources",captured.routerProfiles==original.routerProfiles && captured.profiles==original.profiles && model.bundle?.profiles==final.profiles && captured.routerProfiles[0].startLayer==entryLayer && model.bundle?.routerProfiles[0].startLayer==finalLayer)
   try check("OpenVPN layers never borrow paired credentials",captured.apiToken.isEmpty && captured.routerAPI.isEmpty && captured.nodeProofID.isEmpty && model.bundle?.routerProfiles[0].apiToken==paired.apiToken && captured.routerProfiles[0].external?.openVPN==ovpn.external?.openVPN)
   let before=try encoded(model.bundle!),writes=model.writes
   for execution in ["server","auto"] {
    try reject("OpenVPN layers cannot add execution authority "+execution){try model.saveIOSMultihop(enabled:true,entryID:source.id,exitID:paired.id,exitMode:finalMode,execution:execution,entryMode:"openvpn")}
    try check("unavailable OpenVPN execution leaves exact saved selection",model.writes==writes && encoded(model.bundle!)==before)
   }
   if entryLayer != "off" {
    var missing=source;missing.external?.startLayer=nil;IOSNodeBundleStore.shared.nodes[source.id]=try encoded(bundle(missing))
    try reject("OpenVPN selection requires matching provisioned entry layer"){_ = try model.iosMultihopEntryBundle(for:model.bundle!)}
    try check("missing OpenVPN provision cannot alter selection",model.writes==writes && encoded(model.bundle!)==before)
   }
  }}}
  }
  var packetEntries:[RouterProfile]=[]
  for kind in ["wireguard","amneziawg"] {
   var node=try profile("imported-"+kind,"external",kind);node.apiToken="";node.dnsMode="home";node.external?.socks5=nil
   var block:[String:Any]=["private_key":Data(repeating:11,count:32).base64EncodedString(),"peer_public_key":Data(repeating:12,count:32).base64EncodedString(),"preshared_key":Data(repeating:13,count:32).base64EncodedString(),"addresses":["10.91.0.2/32","fd91::2/128"],"endpoint":"198.51.100.8:51820","allowed_ips":["0.0.0.0/0","::/0"],"mtu":1380,"persistent_keepalive_interval":29]
   if kind=="wireguard" {node.external?.wireGuard=try JSONDecoder().decode(ExternalWireGuardConfig.self,from:encoded(block))}
   else {block["parameters"]=["jc":"3","jmin":"40","jmax":"900","s1":"56","s2":"48","s3":"24","s4":"32","h1":"10000000-19999999","h2":"20000000-29999999","h3":"30000000-39999999","h4":"40000000-49999999"];node.external?.amneziaWG=try JSONDecoder().decode(ExternalAmneziaWGConfig.self,from:encoded(block))}
   packetEntries.append(node)
   let original=bundle(node),model=RouterVPNModel();model.bundle=finalBundle
   IOSNodeBundleStore.shared.nodes=[node.id:try encoded(original),paired.id:try encoded(finalBundle)]
   try model.saveIOSMultihop(enabled:true,entryID:node.id,exitID:paired.id,exitMode:"shadowsocks",execution:"local",entryMode:kind)
   let captured=try model.iosMultihopEntryBundle(for:model.bundle!)
   try check("packet entry captures all original keys/PSK/MTU/parameters without pairing credentials",captured.routerProfiles==original.routerProfiles && captured.profiles==original.profiles && captured.routerAPI.isEmpty && captured.apiToken.isEmpty && captured.nodeProofID.isEmpty)
   try check("packet entry retains paired final DNS and raw assets",model.bundle?.profiles==finalBundle.profiles && model.bundle?.routerProfiles[0].dnsMode=="home" && model.bundle?.routerProfiles[0].multihopEntryMode==kind)
   let saved=try encoded(model.bundle!),writes=model.writes
   for fault in ["server","auto","wrong-mode","private-token","missing-key","empty-routes"] {
    var changed=node,execution="local",mode=kind
    switch fault {
    case "server","auto":execution=fault
    case "wrong-mode":mode="wg"
    case "private-token":changed.apiToken="invented paired entry credential"
    case "missing-key":if kind=="wireguard"{changed.external?.wireGuard?.privateKey=""}else{changed.external?.amneziaWG?.privateKey=""}
    default:if kind=="wireguard"{changed.external?.wireGuard?.allowedIPs=[]}else{changed.external?.amneziaWG?.allowedIPs=[]}
    }
    IOSNodeBundleStore.shared.nodes[node.id]=try encoded(bundle(changed))
    try reject("packet selection rejects "+kind+fault){try model.saveIOSMultihop(enabled:true,entryID:node.id,exitID:paired.id,exitMode:"shadowsocks",execution:execution,entryMode:mode)}
    try check("rejected packet selection leaves saved graph untouched",model.writes==writes && encoded(model.bundle!)==saved)
   }
  }
  finalBundle.profiles["hysteria2"]=["sing-box.json":try encoded(["outbounds":[["type":"hysteria2","tag":"proxy","server":"192.0.2.44","server_port":8443,"password":" exact paired final password ","tls":["enabled":true,"server_name":"final.example.test","certificate_path":"final.pem"]]]]).base64EncodedString(),"final.pem":Data("original paired certificate bytes".utf8).base64EncodedString()]
  for originalEntry in [imported,hysteria,socks]+packetEntries {for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   var selectedFinal=finalBundle;selectedFinal.routerProfiles[0].startLayer=layer
   let model=RouterVPNModel();model.bundle=selectedFinal
   IOSNodeBundleStore.shared.nodes=[originalEntry.id:try encoded(bundle(originalEntry)),paired.id:try encoded(selectedFinal)]
   try model.saveIOSMultihop(enabled:true,entryID:originalEntry.id,exitID:paired.id,exitMode:"hysteria2",execution:"local",entryMode:originalEntry.external!.protocolName)
   let captured=try model.iosMultihopEntryBundle(for:model.bundle!)
   try check("HY2 final selection preserves both complete profiles and independent layer",model.bundle?.routerProfiles[0].multihopExitMode=="hysteria2" && model.bundle?.routerProfiles[0].startLayer==layer && model.bundle?.profiles==selectedFinal.profiles && captured.routerProfiles==[originalEntry])
   for fault in ["missing-final-assets","wrong-final-mode","server","auto"] {
    var changed=selectedFinal;var mode="hysteria2",execution="local"
    if fault=="missing-final-assets"{changed.profiles.removeValue(forKey:"hysteria2")}
    else if fault=="wrong-final-mode"{mode="wg-pq"}
    else{execution=fault}
    IOSNodeBundleStore.shared.nodes[paired.id]=try encoded(changed)
    let refused=RouterVPNModel();refused.bundle=changed;let saved=try encoded(changed)
    try reject("HY2 final save rejects "+fault){try refused.saveIOSMultihop(enabled:true,entryID:originalEntry.id,exitID:paired.id,exitMode:mode,execution:execution,entryMode:originalEntry.external!.protocolName)}
    try check("HY2 final failed selection is transactional",refused.writes==0 && encoded(refused.bundle!)==saved)
   }
  }}
  for mode in ["wg","awg2-fast","awg2-strong"] {for originalEntry in [imported,hysteria,socks]+packetEntries {for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   var selectedFinal=finalBundle;selectedFinal.routerProfiles[0].startLayer=layer
   selectedFinal.profiles[mode]=[mode=="wg" ? "wg.conf":"awg.conf":Data(("captured original "+mode+" credentials").utf8).base64EncodedString()]
   let model=RouterVPNModel();model.bundle=selectedFinal
   IOSNodeBundleStore.shared.nodes=[originalEntry.id:try encoded(bundle(originalEntry)),paired.id:try encoded(selectedFinal)]
   try check("actual picker offers captured packet final assets",model.iosImportedRouterFinalModes(entryMode:originalEntry.external!.protocolName,exitID:paired.id).contains(mode))
   try check("actual picker refuses unsupported imported proxy family",!model.iosImportedRouterFinalModes(entryMode:"http-connect",exitID:paired.id).contains(mode))
   try model.saveIOSMultihop(enabled:true,entryID:originalEntry.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:originalEntry.external!.protocolName)
   let captured=try model.iosMultihopEntryBundle(for:model.bundle!)
   try check("packet final save keeps paired raw assets DNS and independent layer",model.bundle?.profiles==selectedFinal.profiles && model.bundle?.routerProfiles[0].dnsMode=="home" && model.bundle?.routerProfiles[0].startLayer==layer && model.bundle?.routerProfiles[0].multihopExitMode==mode && captured.routerProfiles==[originalEntry])
   for fault in ["missing-final-assets","missing-layer-assets","server","auto","unsupported-entry"] {
    if fault=="missing-layer-assets" && layer=="off" {continue}
    var changed=selectedFinal,first=originalEntry,execution="local"
    if fault=="missing-final-assets"{changed.profiles.removeValue(forKey:mode)}
    else if fault=="missing-layer-assets"{changed.profiles.removeValue(forKey:"shadowsocks")}
    else if fault=="unsupported-entry"{first=try profile("unsupported-entry","external","http-connect");first.apiToken=""}
    else{execution=fault}
    let refused=RouterVPNModel();refused.bundle=changed
    IOSNodeBundleStore.shared.nodes=[first.id:try encoded(bundle(first)),paired.id:try encoded(changed)]
    let saved=try encoded(changed)
    if fault=="missing-final-assets" || fault=="missing-layer-assets" || fault=="unsupported-entry" {
     try check("actual picker refuses missing or incompatible packet source",!refused.iosImportedRouterFinalModes(entryMode:first.external!.protocolName,exitID:paired.id).contains(mode))
    }
    try reject("packet final selection rejects "+fault){try refused.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:execution,entryMode:first.external!.protocolName)}
    try check("packet final refusal leaves original selection intact",refused.writes==0 && encoded(refused.bundle!)==saved)
   }
  }}}
  let protocols=["wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn"]
  for entryProtocol in protocols {for exitProtocol in protocols {
   let entry=bundle(try profile("entry","external",entryProtocol)),model=RouterVPNModel()
   var exit=try profile("exit","external",exitProtocol);exit.multihopEnabled=true;exit.multihopEntryID="entry";exit.multihopEntryMode=entryProtocol;exit.multihopExitID="exit";exit.multihopExitMode=exitProtocol;exit.multihopExecution="local"
   let selected=bundle(exit);model.bundle=selected;IOSNodeBundleStore.shared.nodes=["entry":try JSONEncoder().encode(entry),"exit":try JSONEncoder().encode(selected)]
   let captured=try model.iosMultihopEntryBundle(for:selected)
   try check("exact entry profile captured",captured.routerProfiles==entry.routerProfiles && captured.selectedRouterID=="entry" && model.writes==0)
   try check("entry native secrets stay in its linked bundle",captured.routerProfiles[0].external?.socks5?.password==entry.routerProfiles[0].external?.socks5?.password)
   try model.saveIOSMultihop(enabled:true,entryID:"entry",exitID:"exit",exitMode:exitProtocol,execution:"local",entryMode:entryProtocol)
   try check("saved graph restores exact external modes",model.bundle?.routerProfiles[0].multihopEntryMode==entryProtocol && model.bundle?.routerProfiles[0].multihopExitMode==exitProtocol && model.writes==1)
   let before=model.bundle,writes=model.writes
   try reject("foreign protocol rejected before persistence"){try model.saveIOSMultihop(enabled:true,entryID:"entry",exitID:"exit",exitMode:"unregistered",entryMode:entryProtocol)}
   try check("failed save leaves selected bundle intact",model.writes==writes && model.bundle?.routerProfiles==before?.routerProfiles)
  }}
  for mode in protocols {for kind in ["tor","tor-bridge"] {
   var predecessor=try profile("ordinary-tor-entry","external",mode);predecessor.apiToken=""
   var exit=try profile("tor-exit","external",kind);exit.apiToken="";exit.external?.socks5=nil;exit.external?.expectedPublicIP=""
   if kind=="tor-bridge" {exit.external?.torBridge=ExternalTorBridgeConfig(transport:"obfs4",bridges:["obfs4 198.51.100.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=Y2VydA iat-mode=0"])}
   exit.multihopEnabled=true;exit.multihopEntryID=predecessor.id;exit.multihopEntryMode=mode;exit.multihopExitID=exit.id;exit.multihopExitMode=kind;exit.multihopExecution="local"
   let model=RouterVPNModel(),entry=bundle(predecessor),selected=bundle(exit);model.bundle=selected
   IOSNodeBundleStore.shared.nodes=[predecessor.id:try encoded(entry),exit.id:try encoded(selected)]
   let captured=try model.iosMultihopEntryBundle(for:selected)
   try check("ordinary Tor selection captures exact node and complete policy",captured.routerProfiles==entry.routerProfiles && captured.selectedRouterID==predecessor.id && captured.apiToken.isEmpty && captured.routerAPI.isEmpty && captured.nodeProofID.isEmpty)
   try model.saveIOSMultihop(enabled:true,entryID:predecessor.id,exitID:exit.id,exitMode:kind,execution:"local",entryMode:mode)
   try check("ordinary Tor saves exact native entry and Local choice",model.bundle?.routerProfiles[0].multihopEntryMode==mode && model.bundle?.routerProfiles[0].multihopExecution=="local")
   let frozen=try encoded(model.bundle!),writes=model.writes,records=IOSNodeBundleStore.shared.nodes
   for fault in ["server","auto","entry-home","exit-home","private-api","private-token","private-proof","wrong-mode","missing-proof"] {
    var badEntry=predecessor,badExit=exit,requested="local",entryMode=mode
    switch fault {
    case "server","auto":requested=fault
    case "entry-home":badEntry.dnsMode="home"
    case "exit-home":badExit.dnsMode="home"
    case "private-api":badEntry.routerAPI="http://10.8.0.1:8787"
    case "private-token":badEntry.apiToken="unowned private token"
    case "private-proof":badEntry.nodeProofID=String(repeating:"a",count:64)
    case "wrong-mode":entryMode=mode=="socks5" ? "wireguard":"socks5"
    default:badEntry.external?.expectedPublicIP=""
    }
    model.bundle=try JSONDecoder().decode(ClientBundle.self,from:frozen)
    if fault=="exit-home" {model.bundle=bundle(badExit)}
    IOSNodeBundleStore.shared.nodes=[predecessor.id:try encoded(bundle(badEntry)),exit.id:try encoded(bundle(badExit))]
    let selectedBefore=try encoded(model.bundle!)
    try reject("ordinary Tor rejects incompatible captured authority "+fault){try model.saveIOSMultihop(enabled:true,entryID:predecessor.id,exitID:exit.id,exitMode:kind,execution:requested,entryMode:entryMode)}
    try check("failed ordinary Tor save keeps current configuration",model.writes==writes && encoded(model.bundle!)==selectedBefore)
   }
   IOSNodeBundleStore.shared.nodes=records
  }}
  for kind in ["tor","tor-bridge"] {for execution in ["local","server","auto"] {
   let predecessor=try profile("private-tor-entry","router-vpn"),entry=bundle(predecessor)
   var exit=try profile("private-tor-exit","external",kind);exit.apiToken="";exit.external?.socks5=nil;exit.external?.expectedPublicIP=""
   if kind=="tor-bridge"{exit.external?.torBridge=ExternalTorBridgeConfig(transport:"obfs4",bridges:["obfs4 198.51.100.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=Y2VydA iat-mode=0"])}
   let original=bundle(exit),model=RouterVPNModel();model.bundle=original
   let entryBytes=try encoded(entry)
   IOSNodeBundleStore.shared.nodes=[predecessor.id:entryBytes,exit.id:try encoded(original)]
   try model.saveIOSMultihop(enabled:true,entryID:predecessor.id,exitID:exit.id,exitMode:kind,execution:execution,entryMode:"wg")
   let captured=try model.iosMultihopEntryBundle(for:model.bundle!)
   try check("private Tor editor saves exact Local Server or Compare selection",model.bundle?.routerProfiles[0].multihopExecution==execution && model.bundle?.routerProfiles[0].external==exit.external && captured.routerProfiles==entry.routerProfiles && IOSNodeBundleStore.shared.nodes[predecessor.id]==entryBytes)
   let saved=try encoded(model.bundle!),writes=model.writes,records=IOSNodeBundleStore.shared.nodes
   model.profileMutationBlocked=true
   try reject("active private Tor graph cannot be edited"){try model.saveIOSMultihop(enabled:true,entryID:predecessor.id,exitID:exit.id,exitMode:kind,execution:"auto",entryMode:"wg")}
   try check("blocked private Tor save preserves source and node credentials",model.writes==writes && encoded(model.bundle!)==saved && IOSNodeBundleStore.shared.nodes==records)
  }}
  let entry=bundle(try profile("entry","router-vpn")),model=RouterVPNModel()
  var exit=try profile("exit","external");exit.multihopEnabled=true;exit.multihopEntryID="entry";exit.multihopEntryMode="wg";exit.multihopExitID="exit";exit.multihopExitMode="socks5";exit.multihopExecution="local"
  model.bundle=bundle(exit);IOSNodeBundleStore.shared.nodes=["entry":try JSONEncoder().encode(entry)]
  let captured=try model.iosMultihopEntryBundle(for:model.bundle!)
  try check("paired WG carries exact private assets",captured.profiles==entry.profiles && captured.nodeProofID==entry.routerProfiles[0].nodeProofID && captured.apiToken==entry.routerProfiles[0].apiToken)
  for fault in ["duplicate","missing","unpaired","wrong-kind","missing-assets","layer"] {
   var changed=entry
   switch fault {
   case "duplicate":changed.routerProfiles.append(changed.routerProfiles[0])
   case "missing":changed.routerProfiles=[]
   case "unpaired":changed.routerProfiles[0].nodeProofID="invalid"
   case "wrong-kind":changed.routerProfiles[0].nodeKind="unknown"
   case "missing-assets":changed.profiles=[:]
   default:changed.routerProfiles[0].startLayer="aes-256-gcm"
   }
   IOSNodeBundleStore.shared.nodes=["entry":try JSONEncoder().encode(changed)]
   try reject("invalid Router VPN predecessor "+fault){_ = try model.iosMultihopEntryBundle(for:model.bundle!)}
  }
  for mode in IOSRuntimeSelector.multihopModeIDs {
   for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
    var complete=entry;complete.routerProfiles[0].daitaEnabled=true;complete.routerProfiles[0].startLayer=layer
    complete.profiles[mode]=["selected-asset":Data(("exact "+mode+" "+layer).utf8).base64EncodedString()]
    complete.profiles["shadowsocks"]=["sing-box.json":try encoded(["outbounds":[["type":"shadowsocks","tag":"proxy","server":"198.51.100.1","server_port":8388,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:3,count:32).base64EncodedString()]]]).base64EncodedString()]
    var selected=model.bundle!;selected.routerProfiles[0].multihopEntryMode=mode
    IOSNodeBundleStore.shared.nodes=["entry":try JSONEncoder().encode(complete)]
    let result=try model.iosMultihopEntryBundle(for:selected)
    try check("full native mode and layer selection stays captured",result.profiles==complete.profiles && result.routerProfiles[0].startLayer==layer && result.routerProfiles[0].daitaEnabled==true)
   }
  }
  IOSNodeBundleStore.shared.nodes=["entry":try JSONEncoder().encode(entry)]
  for execution in ["server","auto","unknown"]{var changed=model.bundle!;changed.routerProfiles[0].multihopExecution=execution;try reject("unowned external server execution"){_ = try model.iosMultihopEntryBundle(for:changed)}}
  var ss=try profile("paired-ss","external","shadowsocks")
  ss.external?.shadowsocks=ExternalShadowsocksConfig(server:"198.51.100.8",port:8388,method:"aes-256-gcm",password:" exact exit secret ")
  ss.external?.responseProbe=ExternalResponseProbe(url:"https://198.51.100.8:9443/response",serverName:"node.example.test")
  ss.multihopEnabled=true;ss.multihopEntryID="entry";ss.multihopEntryMode="wg";ss.multihopExitID=ss.id;ss.multihopExitMode="shadowsocks"
  for execution in ["local","server","auto"] {
   ss.multihopExecution=execution;let source=bundle(ss);model.bundle=source;IOSNodeBundleStore.shared.nodes=["entry":try JSONEncoder().encode(entry),ss.id:try JSONEncoder().encode(source)]
   let captured=try model.iosMultihopEntryBundle(for:source)
   try check("external execution captures the exact paired entry credentials",captured.profiles==entry.profiles && captured.apiToken==entry.routerProfiles[0].apiToken)
   try model.saveIOSMultihop(enabled:true,entryID:"entry",exitID:ss.id,exitMode:"shadowsocks",execution:execution,entryMode:"wg")
   try check("eligible external save never coerces execution to Local",model.bundle?.routerProfiles[0].multihopExecution==execution && model.bundle?.routerProfiles[0].external==ss.external)
  }
  for invalid in ["host","http","private","query","escaped","sni","missing","external-entry","unpaired"] {
   var bad=ss,predecessor=entry
   switch invalid {
   case "host":bad.external?.responseProbe?.url="https://203.0.113.8/response"
   case "http":bad.external?.responseProbe?.url="http://198.51.100.8/response"
   case "private":bad.external?.shadowsocks?.server="192.168.50.1";bad.external?.responseProbe?.url="https://192.168.50.1/response"
   case "query":bad.external?.responseProbe?.url="https://198.51.100.8/response?secret=unowned"
   case "escaped":bad.external?.responseProbe?.url="https://198.51.100.8/%2fresponse"
   case "sni":bad.external?.responseProbe?.serverName="localhost"
   case "missing":bad.external?.responseProbe=nil
   case "external-entry":predecessor.routerProfiles[0].nodeKind="external"
   default:predecessor.routerProfiles[0].nodeProofID=nil
   }
   model.bundle=bundle(bad);IOSNodeBundleStore.shared.nodes=["entry":try JSONEncoder().encode(predecessor)]
   try reject("external comparison refuses "+invalid){_ = try model.iosMultihopEntryBundle(for:model.bundle!)}
  }
  let edit=RouterVPNModel();ss.multihopExecution="local";ss.latitude=12.5;ss.longitude = -34.5;edit.bundle=bundle(ss)
  IOSNodeBundleStore.shared.nodes=[ss.id:try JSONEncoder().encode(edit.bundle!),"other-node":Data("unrelated private node bytes".utf8)]
  let savedExternal=ss.external!,savedAssets=edit.bundle!.profiles
  let coordinateSource=try encoded(edit.bundle!),coordinateRecords=IOSNodeBundleStore.shared.nodes,coordinateWrites=edit.writes
  for (latitude,longitude) in [("invalid","invalid"),("invalid",""),("","invalid"),("12.5","invalid"),("invalid","-34.5"),("NaN","0"),("0","infinity"),("91","0"),("0","-181"),("12.5","")] {
   try check("invalid coordinate text cannot clear a saved pin "+latitude+"/"+longitude,!edit.updateNodeMetadata(id:ss.id,name:"Unaccepted",location:"Changed",latitudeText:latitude,longitudeText:longitude,expectedExternal:savedExternal,responseProbeURL:"https://198.51.100.8:9443/new-response",responseProbeServerName:"new.example.test"))
   try check("rejected coordinates preserve exact linked records and active bundle",encoded(edit.bundle!)==coordinateSource && IOSNodeBundleStore.shared.nodes==coordinateRecords && edit.writes==coordinateWrites)
  }
  try check("idle editor validates and saves exact response URL",edit.updateNodeMetadata(id:ss.id,name:"Edited",location:"",latitudeText:" 41.8 ",longitudeText:" -87.6 ",expectedExternal:savedExternal,responseProbeURL:"https://198.51.100.8:9443/new-response",responseProbeServerName:"new.example.test"))
  let edited=edit.bundle!.routerProfiles[0]
  try check("valid coordinate text preserves its explicit numeric pair",edited.latitude==41.8 && edited.longitude == -87.6)
  try check("response edit never replaces transport credentials or private assets",edited.external?.shadowsocks==savedExternal.shadowsocks && edit.bundle!.profiles==savedAssets && IOSNodeBundleStore.shared.nodes["other-node"]==Data("unrelated private node bytes".utf8))
  try check("response edit is retained in the private linked node",(try JSONDecoder().decode(ClientBundle.self,from:IOSNodeBundleStore.shared.nodes[ss.id]!)).routerProfiles[0].external?.responseProbe?.url=="https://198.51.100.8:9443/new-response")
  try reject("imported response cannot move to another protocol"){var imported=edit.bundle!;imported.routerProfiles[0].external?.protocolName="wireguard";try IOSExternalExecution.validateImported(imported)}
  try IOSExternalExecution.validateImported(edit.bundle!);checks+=1
  let current=edit.bundle!.routerProfiles[0].external!
  let before=try encoded(edit.bundle!),store=IOSNodeBundleStore.shared.nodes
  try check("invalid response cannot mutate linked node",!edit.updateNodeMetadata(id:ss.id,name:"Invalid",location:"",latitudeText:"",longitudeText:"",expectedExternal:current,responseProbeURL:"https://203.0.113.8/response",responseProbeServerName:"node.example.test"))
  try check("rejected editor retains private nodes and selection",encoded(edit.bundle!)==before && IOSNodeBundleStore.shared.nodes==store)
  try check("stale editor cannot overwrite changed response or credentials",!edit.updateNodeMetadata(id:ss.id,name:"Stale",location:"",latitudeText:"",longitudeText:"",expectedExternal:savedExternal,responseProbeURL:"https://198.51.100.8/response"))
  try check("stale edit leaves newer source intact",encoded(edit.bundle!)==before)
  for execution in ["server","auto"] {
   edit.bundle!.routerProfiles[0].multihopExecution=execution
   IOSNodeBundleStore.shared.nodes[ss.id]=try JSONEncoder().encode(edit.bundle!)
   try check("live graph preference cannot lose its response endpoint",!edit.updateNodeMetadata(id:ss.id,name:"Clear",location:"",latitudeText:"",longitudeText:"",expectedExternal:current))
   try check("rejected clear keeps the saved execution choice",edit.bundle!.routerProfiles[0].multihopExecution==execution && edit.bundle!.routerProfiles[0].external==current)
  }
  edit.bundle!.routerProfiles[0].multihopExecution="local"
  IOSNodeBundleStore.shared.nodes[ss.id]=try JSONEncoder().encode(edit.bundle!)
  IOSNodeBundleStore.shared.failWrite=true
  try check("private write failure is surfaced",!edit.updateNodeMetadata(id:ss.id,name:"Unwritten",location:"",latitudeText:"",longitudeText:"",expectedExternal:current,responseProbeURL:"https://198.51.100.8/final"))
  try check("write failure keeps active credentials and response",edit.bundle!.routerProfiles[0].external==current)
  IOSNodeBundleStore.shared.failWrite=false
  try check("Local can explicitly clear its optional response endpoint",edit.updateNodeMetadata(id:ss.id,name:"Local",location:"",latitudeText:"",longitudeText:"",expectedExternal:current))
  try check("clearing response retains its private SS credentials",edit.bundle!.routerProfiles[0].external?.responseProbe==nil && edit.bundle!.routerProfiles[0].external?.shadowsocks==current.shadowsocks)
  edit.profileMutationBlocked=true
  try check("active session editor is idle-only",!edit.updateNodeMetadata(id:ss.id,name:"Active",location:"",latitudeText:"",longitudeText:"",expectedExternal:edit.bundle!.routerProfiles[0].external))
  model.profileMutationBlocked=true
  try reject("active graph cannot be edited"){try model.saveIOSMultihop(enabled:true,entryID:"entry",exitID:"exit",exitMode:"socks5",entryMode:"wg")}
  for kind in ["wireguard","amneziawg","shadowsocks","hysteria2","socks5","http-connect","https-connect"] { for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   var node=try profile("paired-"+kind,"external",kind)
   switch kind {
   case "wireguard","amneziawg":
    node.external?.socks5=nil
    var block:[String:Any]=["private_key":Data(repeating:11,count:32).base64EncodedString(),"peer_public_key":Data(repeating:12,count:32).base64EncodedString(),"preshared_key":Data(repeating:13,count:32).base64EncodedString(),"addresses":["10.91.0.2/32","fd91::2/128"],"endpoint":"198.51.100.8:51820","allowed_ips":["0.0.0.0/0","::/0"],"mtu":1380,"persistent_keepalive_interval":29]
    if kind=="wireguard" {node.external?.wireGuard=try JSONDecoder().decode(ExternalWireGuardConfig.self,from:encoded(block))}
    else {block["parameters"]=["jc":"3","jmin":"40","jmax":"900","s1":"56","s2":"48","s3":"24","s4":"32","h1":"10000000-19999999","h2":"20000000-29999999","h3":"30000000-39999999","h4":"40000000-49999999"];node.external?.amneziaWG=try JSONDecoder().decode(ExternalAmneziaWGConfig.self,from:encoded(block))}
   case "shadowsocks":node.external?.shadowsocks=ExternalShadowsocksConfig(server:"198.51.100.8",port:8388,method:"aes-256-gcm",password:" exact secret ")
   case "hysteria2":node.external?.hysteria2=ExternalHysteria2Config(server:"198.51.100.8",port:443,password:" exact secret ",tlsServerName:"exit.example.test")
   case "http-connect":node.external?.httpConnect=ExternalHTTPConnectConfig(host:"198.51.100.8",port:8080,username:" exact user ",password:" exact secret ",tlsServerName:nil)
   case "https-connect":node.external?.httpsConnect=ExternalHTTPConnectConfig(host:"198.51.100.8",port:8443,username:" exact user ",password:" exact secret ",tlsServerName:"exit.example.test")
   default:break
   }
   let editor=RouterVPNModel();editor.bundle=bundle(node);IOSNodeBundleStore.shared.nodes=[node.id:try JSONEncoder().encode(editor.bundle!),"entry":try JSONEncoder().encode(entry)]
   let original=node.external!,layerKey=Data(repeating:7,count:32).base64EncodedString()
   try check("every supported native editor retains provisioned response/layer settings "+kind+layer,editor.updateNodeMetadata(id:node.id,name:"Layered",location:"",latitudeText:"",longitudeText:"",expectedExternal:original,responseProbeURL:"https://198.51.100.8:9443/response",responseProbeServerName:"node.example.test",expectedStartLayer:"off",exitStartLayer:layer,exitLayerAPI:layer=="off" ? "":"http://10.99.0.1:8787",exitLayerPort:layer=="off" ? 0:8388,exitLayerKey:layer=="off" ? "":layerKey,serverPeerJSON:ExternalNodeConfig.packetProtocols.contains(kind) ? String(decoding:try encoded(["public_key":"bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg=","addresses":["10.94.0.3/32","fd94::3/128"],"mtu":1380,"persistent_keepalive_interval":25]),as:UTF8.self):nil))
   node=editor.bundle!.routerProfiles[0]
   try check("layer editor preserves exact primary credentials",node.external?.packetConfiguration==original.packetConfiguration && node.external?.shadowsocks==original.shadowsocks && node.external?.hysteria2==original.hysteria2 && node.external?.socks5==original.socks5 && node.external?.httpConnect==original.httpConnect && node.external?.httpsConnect==original.httpsConnect)
   try IOSExternalExecution.validateImported(editor.bundle!);checks+=1
   for execution in ["local","server","auto"] {
    latest="packet execution "+kind+" / "+layer+" / "+execution
    if ExternalNodeConfig.packetProtocols.contains(kind) {
     var trial=editor.bundle!.routerProfiles[0];trial.multihopExecution=execution
     try check("packet descriptor retained before selection "+execution,trial.external?.serverPeer != nil)
     try check("packet auth retained before selection "+execution,trial.external?.authenticatedServerExecution==true)
     try check("packet host retained before selection "+execution,trial.external?.serverExecutionHost=="198.51.100.8")
     try IOSExternalExecution.validate(trial.external!.responseProbe!, host: "198.51.100.8")
     try IOSExternalExecution.validateLayerDraft(trial)
     try check("packet candidate eligible before selection "+execution,IOSExternalExecution.eligible(entry:entry.routerProfiles[0],exit:trial))
    }
    try editor.saveIOSMultihop(enabled:true,entryID:"entry",exitID:node.id,exitMode:kind,execution:execution,entryMode:"wg")
    try check("each protocol and layer retains its exact saved execution",editor.bundle!.routerProfiles[0].multihopExecution==execution && editor.bundle!.routerProfiles[0].external==node.external)
   }
   if ExternalNodeConfig.packetProtocols.contains(kind) {
    try check("packet editor retains public descriptor without replacing local peer",node.external?.serverPeer?.publicKey=="bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg=" && node.external?.packetConfiguration==original.packetConfiguration)
    let saved=try encoded(editor.bundle!),stored=IOSNodeBundleStore.shared.nodes
    try check("Server graph cannot lose separate server peer",!editor.updateNodeMetadata(id:node.id,name:"Clear",location:"",latitudeText:"",longitudeText:"",expectedExternal:node.external,responseProbeURL:"https://198.51.100.8:9443/response",serverPeerJSON:""))
    try check("rejected descriptor removal preserves complete graph and private store",encoded(editor.bundle!)==saved && IOSNodeBundleStore.shared.nodes==stored)
    let malformed="{\"public_key\":\"bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg=\",\"addresses\":[\"10.91.0.2/32\",\"fd94::3/128\"],\"mtu\":1360}"
    try check("editor cannot reuse Local assigned address",!editor.updateNodeMetadata(id:node.id,name:"Borrowed",location:"",latitudeText:"",longitudeText:"",expectedExternal:node.external,responseProbeURL:"https://198.51.100.8:9443/response",serverPeerJSON:malformed))
    try check("failed native descriptor validation preserves old source",encoded(editor.bundle!)==saved && IOSNodeBundleStore.shared.nodes==stored)
    var smaller=try JSONSerialization.jsonObject(with:JSONEncoder().encode(node.external!.serverPeer!)) as! [String:Any];smaller["mtu"]=1280
    try check("fixed MTU cannot exceed the independently provisioned server interface",!editor.updateNodeMetadata(id:node.id,name:"Too small",location:"",latitudeText:"",longitudeText:"",expectedExternal:node.external,responseProbeURL:"https://198.51.100.8:9443/response",serverPeerJSON:String(decoding:try encoded(smaller),as:UTF8.self)))
    try check("invalid server MTU leaves saved execution and private node unchanged",encoded(editor.bundle!)==saved && IOSNodeBundleStore.shared.nodes==stored)
   }
   if layer != "off" {
    var wrong=editor.bundle!;wrong.routerProfiles[0].startLayer="off"
    try reject("an imported layer cannot be silently ignored"){try IOSExternalExecution.validateImported(wrong)}
    let saved=try encoded(editor.bundle!),stored=IOSNodeBundleStore.shared.nodes
    try check("wrong AES key cannot replace a valid private node",!editor.updateNodeMetadata(id:node.id,name:"Invalid",location:"",latitudeText:"",longitudeText:"",expectedExternal:node.external,responseProbeURL:"https://198.51.100.8:9443/response",expectedStartLayer:layer,exitStartLayer:layer,exitLayerAPI:"http://10.99.0.1:8787",exitLayerPort:8388,exitLayerKey:"wrong-key"))
    try check("invalid wrapper edit remains transactional",encoded(editor.bundle!)==saved && IOSNodeBundleStore.shared.nodes==stored)
    for fault in ["extra","null","unknown-transport"] {
     var profile=try JSONSerialization.jsonObject(with:JSONEncoder().encode(node)) as! [String:Any],ext=profile["external"] as! [String:Any],wrapper=ext["start_layer"] as! [String:Any]
     if fault=="null" {ext["start_layer"]=NSNull()} else if fault=="extra" {wrapper["unowned"]=true;ext["start_layer"]=wrapper} else {var transport=wrapper["transport"] as! [String:Any];transport["detour"]="unowned";wrapper["transport"]=transport;ext["start_layer"]=wrapper}
     profile["external"]=ext
     try reject("typed import rejects discarded layer field "+fault){_ = try JSONDecoder().decode(RouterProfile.self,from:encoded(profile))}
    }
   }
   if ExternalNodeConfig.packetProtocols.contains(kind) {
    try editor.saveIOSMultihop(enabled:true,entryID:"entry",exitID:node.id,exitMode:kind,execution:"local",entryMode:"wg")
    let oldExternal=editor.bundle!.routerProfiles[0].external!
    var replacement=oldExternal.serverPeer!;replacement.persistentKeepaliveInterval=30
    try check("Local can update its public server descriptor",editor.updateNodeMetadata(id:node.id,name:"Changed peer",location:"",latitudeText:"",longitudeText:"",expectedExternal:oldExternal,responseProbeURL:"https://198.51.100.8:9443/response",serverPeerJSON:IOSExternalExecution.serverPeerText(replacement)))
    let changed=try encoded(editor.bundle!),stored=IOSNodeBundleStore.shared.nodes
    try check("old editor cannot overwrite a changed packet descriptor",!editor.updateNodeMetadata(id:node.id,name:"Stale",location:"",latitudeText:"",longitudeText:"",expectedExternal:oldExternal,responseProbeURL:"https://198.51.100.8:9443/response",serverPeerJSON:IOSExternalExecution.serverPeerText(oldExternal.serverPeer)))
    try check("stale peer edit leaves the new source unchanged",encoded(editor.bundle!)==changed && IOSNodeBundleStore.shared.nodes==stored)
    let current=editor.bundle!.routerProfiles[0].external!
    try check("Local can explicitly remove the optional server descriptor",editor.updateNodeMetadata(id:node.id,name:"Local",location:"",latitudeText:"",longitudeText:"",expectedExternal:current,responseProbeURL:"https://198.51.100.8:9443/response",serverPeerJSON:""))
    try check("removing server descriptor preserves local peer and Start Layer",editor.bundle!.routerProfiles[0].external?.serverPeer==nil && editor.bundle!.routerProfiles[0].external?.packetConfiguration==current.packetConfiguration && editor.bundle!.routerProfiles[0].external?.startLayer==current.startLayer)
    let local=try encoded(editor.bundle!)
    try reject("packet Server requires its separate descriptor"){try editor.saveIOSMultihop(enabled:true,entryID:"entry",exitID:node.id,exitMode:kind,execution:"server",entryMode:"wg")}
    try check("rejected packet Server keeps the valid Local configuration",encoded(editor.bundle!)==local)
   }
  }}
  var mapped=try profile("mapped-openvpn","external","openvpn")
  mapped.external?.socks5=nil
  mapped.external?.openVPN=ExternalOpenVPNConfig(config:"client\ndev tun\nproto udp\nremote 203.0.113.20 1194\nremote 203.0.113.21 443 tcp\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint "+String(repeating:"ab",count:32)+"\n",username:" exact user ",password:" exact secret ")
  let map:[String:Any]=["203.0.113.20":["url":"https://203.0.113.20/response","server_name":"first.example.test"],"203.0.113.21":["url":"https://203.0.113.21/response","server_name":"second.example.test"]]
  let mapText=String(decoding:try encoded(map),as:UTF8.self),mapEditor=RouterVPNModel(),mapOriginal=mapped.external!
  mapEditor.bundle=bundle(mapped);IOSNodeBundleStore.shared.nodes=[mapped.id:try encoded(mapEditor.bundle!)]
  try check("native editor saves each private OpenVPN response endpoint",mapEditor.updateNodeMetadata(id:mapped.id,name:"Mapped",location:"",latitudeText:"",longitudeText:"",expectedExternal:mapOriginal,openVPNResponseProbesJSON:mapText))
  let mappedExternal=mapEditor.bundle!.routerProfiles[0].external!
  try check("native map edit preserves exact inline source and credentials",mappedExternal.openVPN==mapOriginal.openVPN && mappedExternal.openVPNResponseProbes?.count==2 && mappedExternal.responseProbe==nil)
  let mappedBytes=try encoded(mapEditor.bundle!),mappedRecords=IOSNodeBundleStore.shared.nodes
  for bad in ["null",mapText+" {}",String(mapText.dropLast())+",\"203.0.113.20\":{\"url\":\"https://203.0.113.20/replaced\"}}"] {
   try check("raw ambiguous map cannot overwrite linked node",!mapEditor.updateNodeMetadata(id:mapped.id,name:"Bad",location:"",latitudeText:"",longitudeText:"",expectedExternal:mappedExternal,openVPNResponseProbesJSON:bad))
  }
  try check("single response cannot replace an unremoved remote map",!mapEditor.updateNodeMetadata(id:mapped.id,name:"Conflicting",location:"",latitudeText:"",longitudeText:"",expectedExternal:mappedExternal,responseProbeURL:"https://203.0.113.20/response"))
  try check("stale map editor cannot overwrite newer private state",!mapEditor.updateNodeMetadata(id:mapped.id,name:"Stale",location:"",latitudeText:"",longitudeText:"",expectedExternal:mapOriginal,openVPNResponseProbesJSON:mapText))
  try check("failed edits preserve exact stored and active bundle",encoded(mapEditor.bundle!)==mappedBytes && IOSNodeBundleStore.shared.nodes==mappedRecords)
  let ambiguousRecord=String(decoding:mappedRecords[mapped.id]!,as:UTF8.self).replacingOccurrences(of:"\"openvpn_response_probes\":{",with:"\"openvpn_response_probes\":{\"203.0.113.20\":{\"url\":\"https://203.0.113.20/response\",\"server_name\":\"first.example.test\"},")
  IOSNodeBundleStore.shared.nodes[mapped.id]=Data(ambiguousRecord.utf8)
  try check("stored private bytes reject duplicate remote identities before edit",!mapEditor.updateNodeMetadata(id:mapped.id,name:"Ambiguous record",location:"",latitudeText:"",longitudeText:"",expectedExternal:mappedExternal,openVPNResponseProbesJSON:mapText))
  try check("ambiguous stored record is preserved without normalizing its credentials",IOSNodeBundleStore.shared.nodes[mapped.id]==Data(ambiguousRecord.utf8) && encoded(mapEditor.bundle!)==mappedBytes)
  IOSNodeBundleStore.shared.nodes=mappedRecords
  try check("metadata-only edit retains current private response map",mapEditor.updateNodeMetadata(id:mapped.id,name:"Metadata",location:"",latitudeText:"",longitudeText:"",expectedExternal:mappedExternal))
  try check("metadata-only edit does not drop an optional map",mapEditor.bundle!.routerProfiles[0].external==mappedExternal)
  var serverSelection=mapEditor.bundle!;serverSelection.routerProfiles[0].multihopEnabled=true;serverSelection.routerProfiles[0].multihopExecution="auto";mapEditor.bundle=serverSelection;IOSNodeBundleStore.shared.nodes[mapped.id]=try encoded(serverSelection)
  try check("saved comparison cannot lose every response endpoint",!mapEditor.updateNodeMetadata(id:mapped.id,name:"Clear",location:"",latitudeText:"",longitudeText:"",expectedExternal:mappedExternal,openVPNResponseProbesJSON:""))
  serverSelection.routerProfiles[0].multihopExecution="local";mapEditor.bundle=serverSelection;IOSNodeBundleStore.shared.nodes[mapped.id]=try encoded(serverSelection)
  try check("Local can explicitly remove private response map",mapEditor.updateNodeMetadata(id:mapped.id,name:"Local",location:"",latitudeText:"",longitudeText:"",expectedExternal:mappedExternal,openVPNResponseProbesJSON:""))
  try check("removing map retains original multi-host OpenVPN credentials",mapEditor.bundle!.routerProfiles[0].external?.openVPNResponseProbes==nil && mapEditor.bundle!.routerProfiles[0].external?.openVPN==mapOriginal.openVPN)
  for (fixtureName,mode) in [("AES","aes-256-gcm"),("XOR","aes-256-gcm+xor-whitening")] {
   let fixture=try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:ProcessInfo.processInfo.environment["ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_"+fixtureName+"_FIXTURE"]!))) as! [String:Any],external=try JSONDecoder().decode(ExternalNodeConfig.self,from:encoded(fixture["external"]!)),raw=IOSExternalExecution.openVPNStartLayersText(external.openVPNStartLayers)
   var selected=try profile("layer-map-"+fixtureName,"external","openvpn");selected.external=external;selected.external?.openVPNStartLayers=nil
   let editor=RouterVPNModel(),original=selected.external!;editor.bundle=bundle(selected);IOSNodeBundleStore.shared.nodes=[selected.id:try encoded(editor.bundle!)]
   try check("native editor installs exact private per-remote layers",editor.updateNodeMetadata(id:selected.id,name:"Layers",location:"",latitudeText:"",longitudeText:"",expectedExternal:original,expectedStartLayer:"off",exitStartLayer:mode,openVPNStartLayersJSON:raw))
   let current=editor.bundle!.routerProfiles[0].external!,currentBytes=try encoded(editor.bundle!),currentRecords=IOSNodeBundleStore.shared.nodes
   try check("editor preserves original source and uniform chosen layer",current==external && editor.bundle!.routerProfiles[0].startLayer==mode && current.openVPNStartLayers?["203.0.113.20"]?.api==current.openVPNStartLayers?["203.0.113.21"]?.api && current.openVPNStartLayers?["203.0.113.20"]?.transport.password != current.openVPNStartLayers?["203.0.113.21"]?.transport.password)
   let duplicate=String(raw.trimmingCharacters(in:.whitespacesAndNewlines).dropLast())+",\"203.0.113.20\":"+String(decoding:try JSONEncoder().encode(current.openVPNStartLayers!["203.0.113.20"]!),as:UTF8.self)+"}"
   var missing=current.openVPNStartLayers!;missing.removeValue(forKey:"203.0.113.21")
   var foreign=current.openVPNStartLayers!;foreign["203.0.113.99"]=foreign.removeValue(forKey:"203.0.113.21")
   var disagreement=current.openVPNStartLayers!;disagreement["203.0.113.21"]?.mode=mode=="aes-256-gcm" ? "aes-256-gcm+xor-whitening":"aes-256-gcm"
   for invalid in ["null","{}",raw+" {}",duplicate,IOSExternalExecution.openVPNStartLayersText(missing),IOSExternalExecution.openVPNStartLayersText(foreign),IOSExternalExecution.openVPNStartLayersText(disagreement),raw+String(repeating:" ",count:131073)] {
    try check("raw malformed layer map cannot overwrite saved node",!editor.updateNodeMetadata(id:selected.id,name:"Invalid",location:"",latitudeText:"",longitudeText:"",expectedExternal:current,expectedStartLayer:mode,exitStartLayer:mode,openVPNStartLayersJSON:invalid))
   }
   try check("map cannot borrow singular layer fields",!editor.updateNodeMetadata(id:selected.id,name:"Mixed",location:"",latitudeText:"",longitudeText:"",expectedExternal:current,expectedStartLayer:mode,exitStartLayer:mode,exitLayerAPI:"http://10.93.0.1:8787",openVPNStartLayersJSON:raw))
   try check("Off requires removal of per-remote layers",!editor.updateNodeMetadata(id:selected.id,name:"Wrong Off",location:"",latitudeText:"",longitudeText:"",expectedExternal:current,expectedStartLayer:mode,exitStartLayer:"off",openVPNStartLayersJSON:raw))
   try check("selected encryption requires its complete map",!editor.updateNodeMetadata(id:selected.id,name:"Missing",location:"",latitudeText:"",longitudeText:"",expectedExternal:current,expectedStartLayer:mode,exitStartLayer:mode,openVPNStartLayersJSON:""))
   try check("layered map cannot lose response identities",!editor.updateNodeMetadata(id:selected.id,name:"Missing probes",location:"",latitudeText:"",longitudeText:"",expectedExternal:current,expectedStartLayer:mode,openVPNResponseProbesJSON:""))
   try check("rejected layer edits preserve active and stored bytes",encoded(editor.bundle!)==currentBytes && IOSNodeBundleStore.shared.nodes==currentRecords)
   let ambiguous=String(decoding:currentRecords[selected.id]!,as:UTF8.self).replacingOccurrences(of:"\"openvpn_start_layers\":{",with:"\"openvpn_start_layers\":{\"203.0.113.20\":"+String(decoding:try JSONEncoder().encode(current.openVPNStartLayers!["203.0.113.20"]!),as:UTF8.self)+",")
   IOSNodeBundleStore.shared.nodes[selected.id]=Data(ambiguous.utf8)
   try check("stored layer map duplicate cannot normalize on metadata edit",!editor.updateNodeMetadata(id:selected.id,name:"Ambiguous",location:"",latitudeText:"",longitudeText:"",expectedExternal:current))
   try check("ambiguous private record was not rewritten",IOSNodeBundleStore.shared.nodes[selected.id]==Data(ambiguous.utf8) && encoded(editor.bundle!)==currentBytes)
   IOSNodeBundleStore.shared.nodes=currentRecords
   try check("metadata edit retains exact per-remote map",editor.updateNodeMetadata(id:selected.id,name:"Renamed",location:"",latitudeText:"",longitudeText:"",expectedExternal:current) && editor.bundle!.routerProfiles[0].external==current)
   var replacement=current.openVPNStartLayers!;replacement["203.0.113.21"]?.transport.password=Data(repeating:114,count:32).base64EncodedString()
   try check("current owner may rotate one captured layer key",editor.updateNodeMetadata(id:selected.id,name:"Rotated",location:"",latitudeText:"",longitudeText:"",expectedExternal:current,expectedStartLayer:mode,exitStartLayer:mode,openVPNStartLayersJSON:IOSExternalExecution.openVPNStartLayersText(replacement)))
   let rotated=editor.bundle!.routerProfiles[0].external!,rotatedBytes=try encoded(editor.bundle!),rotatedRecords=IOSNodeBundleStore.shared.nodes
   try check("stale editor cannot replace rotated private keys",!editor.updateNodeMetadata(id:selected.id,name:"Stale",location:"",latitudeText:"",longitudeText:"",expectedExternal:current,expectedStartLayer:mode,exitStartLayer:mode,openVPNStartLayersJSON:raw))
   try check("stale layer rejection preserves new owner",encoded(editor.bundle!)==rotatedBytes && IOSNodeBundleStore.shared.nodes==rotatedRecords)
   IOSNodeBundleStore.shared.failWrite=true
   try check("failed layer-map publication leaves current node usable",!editor.updateNodeMetadata(id:selected.id,name:"Write failure",location:"",latitudeText:"",longitudeText:"",expectedExternal:rotated,expectedStartLayer:mode,exitStartLayer:"off",openVPNStartLayersJSON:""))
   IOSNodeBundleStore.shared.failWrite=false
   try check("write failure preserves all private map references",encoded(editor.bundle!)==rotatedBytes && IOSNodeBundleStore.shared.nodes==rotatedRecords)
   try check("explicit Off clears only layer map",editor.updateNodeMetadata(id:selected.id,name:"Off",location:"",latitudeText:"",longitudeText:"",expectedExternal:rotated,expectedStartLayer:mode,exitStartLayer:"off",openVPNStartLayersJSON:""))
   try check("cleared layer retains original multiremote profile and response proof",editor.bundle!.routerProfiles[0].startLayer=="off" && editor.bundle!.routerProfiles[0].external?.openVPNStartLayers==nil && editor.bundle!.routerProfiles[0].external?.openVPN==rotated.openVPN && editor.bundle!.routerProfiles[0].external?.openVPNResponseProbes==rotated.openVPNResponseProbes && editor.bundle!.routerProfiles[0].external?.openVPNPairing==rotated.openVPNPairing)
  }
  print("Apple external entry selection: PASS (\(checks) shipping Swift checks; storage/native-readiness boundaries doubled)")
 }
}
'''



def validate_imported_picker(view):
    entries = view[view.index('    private var nodes:'):view.index('    private var exitNodes:')]
    if ('["wireguard", "amneziawg", "hysteria2", "socks5", "http-connect", "https-connect", "openvpn"].contains($0.external?.protocolName ?? "")' not in entries
            or 'IOSImportedEntryMultihop.methods.contains' not in entries):
        raise ValueError('Paired finals must expose exact WG/AWG/HY2/SOCKS5, CONNECT and SS2022 imported entries')
    branch = view[view.index('                    if externalEntryProtocol != nil {'):]
    branch = branch[:branch.index('                    } else {')]
    for required in ('Picker("Exit transport", selection: $exitMode)',
                     'if !importedFinalModes.contains(exitMode)',
                     'Text("Choose a supported final for this imported entry").tag(exitMode)',
                     'if importedFinalModes.contains("wg")',
                     'if importedFinalModes.contains("awg2-fast")',
                     'if importedFinalModes.contains("awg2-strong")',
                     'Text("WireGuard").tag("wg")',
                     'Text("AmneziaWG Fast").tag("awg2-fast")',
                     'Text("AmneziaWG Strong").tag("awg2-strong")',
                     'Text("Shadowsocks 2022").tag("shadowsocks")',
                     'Text("Hysteria2").tag("hysteria2")',
                     'if importedFinalModes.contains("reality-vision")',
                     'Text("REALITY Vision").tag("reality-vision")'):
        if required not in branch:
            raise ValueError('Imported final picker must preserve invalid saved values and require an explicit valid choice')
    if 'if ["http-connect", "https-connect"].contains(externalEntryProtocol ?? "") {' not in branch or 'TCP-only' not in branch:
        raise ValueError('CONNECT capability copy must be conditional on the captured CONNECT entry')
    if 'exitMode =' in branch:
        raise ValueError('Imported final picker must not silently rewrite the saved transport')
    requirements = view[view.index('Section("Connection requirements")'):]
    if ('if externalEntryProtocol != nil && torExitProtocol == nil && ordinaryExitProtocol == nil' not in requirements
            or 'one different paired Router VPN final node' not in requirements):
        raise ValueError('Imported entry requirements must describe its one paired final node')


def main():
    view = (APP / 'IOSMultihopView.swift').read_text()
    validate_imported_picker(view)
    capture = view[view.index('@MainActor\nextension RouterVPNModel {'):view.index('struct IOSMultihopView: View')]
    dns = (APP / 'IOSDNSRuntimePolicy.swift').read_text()
    selected = dns[dns.index('    static func selectedProfile('):dns.index('    static func resolve(')]
    store = (APP / 'IOSNodeBundleStore.swift').read_text()
    editing = store[store.index('    func updateMetadata('):store.index('    private func store(')]
    model = (APP / 'RouterVPNModelNodeManagement.swift').read_text()
    model_edit = model[model.index('    @discardableResult'):model.rfind('}')]
    body = STUBS.replace(' // SHIPPING_SELECTED_PROFILE', selected).replace(' // SHIPPING_METADATA_EDIT', editing)
    body += '\n' + capture + '\nextension RouterVPNModel {\n' + model_edit + '\n}\n'
    with tempfile.TemporaryDirectory(prefix='.ios-external-selection-', dir=ROOT) as helper, tempfile.TemporaryDirectory(prefix='ios-external-selection-') as directory:
        work = Path(directory); source = work / 'Test.swift'; source.write_text(body)
        crypto_flags, crypto_env = crypto.prepare(work/'crypto')
        helper = Path(helper) / 'main.go'; helper.write_text(T.GO)
        compiler = work / 'compiler'
        subprocess.run(['go', 'build', '-o', str(compiler), str(helper)], cwd=ROOT, check=True, timeout=180)
        library = work / 'Libbox.swift'; library.write_text(T.LIBBOX)
        suffix = '.dylib' if platform.system() == 'Darwin' else '.so'
        subprocess.run(['swiftc', '-swift-version', '6', '-module-cache-path', str(work/'module-cache'), '-emit-module', '-emit-library', '-module-name', 'Libbox', str(library), '-emit-module-path', str(work/'Libbox.swiftmodule'), '-o', str(work/('libLibbox'+suffix))], check=True, timeout=90)
        subprocess.run(['swiftc', '-swift-version', '6', '-module-cache-path', str(work/'module-cache'), *crypto_flags, '-I', str(work), '-L', str(work), '-lLibbox', '-Xlinker', '-rpath', '-Xlinker', str(work), str(APP / 'IOSMultihopExecution.swift'), str(APP / 'Models.swift'), str(APP / 'IOSExternalExecution.swift'), str(APP / 'IOSMultihopStartLayer.swift'), str(source), '-o', str(work / 'test')], check=True, timeout=90)
        runtime_env = dict(os.environ, **crypto_env, ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_AES_FIXTURE=str(ROOT/'deploy/fixtures/external-openvpn-multihost-layered-aes-client.json'), ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_XOR_FIXTURE=str(ROOT/'deploy/fixtures/external-openvpn-multihost-layered-xor-client.json'))
        baseline = subprocess.run([str(work / 'test'), str(compiler)], env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
        expected_baseline = 'Apple external entry selection: PASS (3231 shipping Swift checks; storage/native-readiness boundaries doubled)\n'
        if baseline.stdout != expected_baseline:
            raise ValueError('Missing or foreign baseline Swift verdict: '+repr(baseline.stdout))
        print(baseline.stdout, end='', flush=True)
        reality = subprocess.run([str(work / 'test'), str(compiler), 'socks-reality'], env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
        if reality.stdout != 'PASS SOCKS REALITY host 112 checks\n':
            raise ValueError('Missing or foreign SOCKS REALITY Swift verdict: '+repr(reality.stdout))
        print(reality.stdout, end='', flush=True)
        for kind in ('shadowsocks', 'hysteria2'):
            proxy = subprocess.run([str(work / 'test'), str(compiler), 'proxy-reality', kind], env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
            if proxy.stdout != f'PASS {kind} REALITY host 112 checks\n':
                raise ValueError('Missing or foreign encrypted REALITY Swift verdict: '+repr(proxy.stdout))
            print(proxy.stdout, end='', flush=True)
        # Each additional configured transport/layer runs with the original
        # process budget; all four DNS selections and refusal controls remain.
        for kind in ('http-connect', 'https-connect'):
            for layer in ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening'):
                result = subprocess.run([str(work / 'test'), str(compiler), kind, layer], env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
                expected = f'PASS configured CONNECT {kind} {layer} 56 checks\n'
                if result.stdout != expected:
                    raise ValueError('Missing or foreign configured CONNECT Swift verdict: '+repr(result.stdout))
                print(result.stdout, end='', flush=True)
        print('Configured CONNECT Swift matrix: PASS (24 combinations, 336 checks across 6 bounded processes)')
        for kind in ('http-connect', 'https-connect'):
            for carrier in ('plain', 'off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening'):
                result = subprocess.run([str(work/'test'), str(compiler), 'selected-dns', kind, carrier], env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
                if result.stdout != f'PASS selected DNS {kind} {carrier} 6 cases\n':
                    raise ValueError('Missing or foreign selected DNS Swift verdict: '+repr(result.stdout))
                print(result.stdout, end='', flush=True)
        print('Selected CONNECT DNS Swift matrix: PASS (44 accepted captures and 4 unavailable-H3 refusals)')


if __name__ == '__main__':
    main()
