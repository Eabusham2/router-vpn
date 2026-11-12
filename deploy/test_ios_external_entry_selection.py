#!/usr/bin/env python3
"""Execute Apple graph selection/save with shipping models and capture methods.

The node-store and native-mode readiness boundaries are deterministic doubles;
the separate Swift/Go policy gate validates compiled native configurations.
"""
from pathlib import Path
import argparse
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
  if ["http-connect","https-connect"].contains(kind){let original=ExternalHTTPConnectConfig(host:"198.51.100.8",port:8443,username:" exact original user ",password:" exact original CONNECT secret ",tlsServerName:kind=="https-connect" ? "captured-connect.example":nil);if kind=="https-connect"{first.external?.httpsConnect=original}else{first.external?.httpConnect=original}}
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
  for kind in ["tor","reality-pq-vision","unknown"] {
   try check("REALITY unsupported entry remains refused "+kind,!IOSImportedEntryMultihop.supports(entry:kind,final:"reality-vision"))
  }
  for kind in ["shadowsocks","hysteria2","http-connect","https-connect","wireguard","amneziawg","openvpn"]{try check("REALITY supports captured original entry "+kind,IOSImportedEntryMultihop.supports(entry:kind,final:"reality-vision"))}
  try check("PQ REALITY supports captured original entry",IOSImportedEntryMultihop.supports(entry:kind,final:"reality-pq-vision"))
  try check("XHTTP supports captured original entry",IOSImportedEntryMultihop.supports(entry:kind,final:"reality-xhttp"))
  for mode in ["split","max","max-tls-wg"] {
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
 static func pqReality(_ path:String,_ mode:String="reality-pq-vision")throws {
  guard ["reality-pq-vision","reality-xhttp"].contains(mode) else {throw IOSImportedEntryMultihop.issue()}
  let source=try JSONDecoder().decode([String].self,from:Data(contentsOf:URL(fileURLWithPath:path)))
  try check("PQ picker uses complete exact source capture",source.count==9 && source[2]==mode)
  let capture=try JSONSerialization.jsonObject(with:Data(source[1].utf8)) as! [String:Any]
  func capturedProfile(_ raw:[String:Any])throws->RouterProfile {
   var value=raw
   for (key,fallback) in ["name":"Captured PQ path","endpoint":"","router_api":"","api_token":"","adguard_ipv4":"","adguard_ipv6":"","socks_host":"","socks_port":0,"socks_username":"","socks_password":""] as [String:Any] where value[key]==nil {value[key]=fallback}
   return try JSONDecoder().decode(RouterProfile.self,from:encoded(value))
  }
  let first=try capturedProfile(capture["profile"] as! [String:Any]),paired=try capturedProfile(JSONSerialization.jsonObject(with:Data(source[4].utf8)) as! [String:Any])
  let assets=try JSONDecoder().decode([String:String].self,from:Data(source[3].utf8))
  var original=ClientBundle.empty;original.selectedRouterID=first.id;original.routerProfiles=[first];original.profiles=[:]
  var final=ClientBundle.empty;final.selectedRouterID=paired.id;final.routerProfiles=[paired];final.profiles=[mode:assets]
  let model=RouterVPNModel();model.bundle=final
  IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(final)]
  try check("PQ picker requires captured entry",model.iosImportedRouterFinalModes(entryMode:"socks5",exitID:paired.id,entryProfile:first).contains(mode))
  try check("PQ picker refuses absent entry",!model.iosImportedRouterFinalModes(entryMode:"socks5",exitID:paired.id).contains(mode))
  try model.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:"socks5")
  let held=try model.iosMultihopEntryBundle(for:model.bundle!)
  try check("PQ save retains both original roles",held.routerProfiles==original.routerProfiles && held.profiles==original.profiles && model.bundle!.profiles==final.profiles && model.bundle!.routerProfiles[0].multihopExitMode==mode)
  func hash(_ data:Data)->String{CryptoKit.SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
  let configuration:[String:Any]=["engine":"multihop-libbox","mode":mode,"bundle":try encoded(model.bundle!),"entryBundle":try encoded(original)]
  let identity=try IOSMultihopExecution.Source(configuration:configuration,digest:hash),receipt=try IOSMultihopExecution.StartupChoice(source:identity,execution:"local").encoded()
  try check("PQ startup binds exact final",identity.exitMode==mode && IOSMultihopExecution.StartupChoice.decode(receipt,source:identity).source==identity)
  let args=["config":source[0],"capture":source[1],"mode":source[2],"files":source[3],"profile":source[4],"start":source[5],"dns":source[6]]
  func compile(_ value:[String:String])throws->String{try RouterVPNTorTestCall(["Op":"imported-router","Config":String(decoding:encoded(value),as:UTF8.self)])}
  let compiled=try compile(args)
  try check("PQ actual compiler retains original graph",try encoded(JSONSerialization.jsonObject(with:Data(compiled.utf8)))==encoded(JSONSerialization.jsonObject(with:Data(source[8].utf8))))
  let faults=mode=="reality-xhttp" ? ["missing-xray","malformed-wrapper","bad-path","ordinary-encryption","pq-label"]:["missing-xray","missing-wrapper","malformed-xray","ordinary-encryption","ordinary-label"]
  for fault in faults {
   var changed=assets,replaced=args
   if fault=="missing-xray"{changed.removeValue(forKey:"xray.json")}
   else if fault=="missing-wrapper"{changed.removeValue(forKey:"sing-box.json")}
   else if fault=="malformed-xray"{changed["xray.json"]=Data("{".utf8).base64EncodedString()}
   else if fault=="malformed-wrapper"{changed["sing-box.json"]=Data("{".utf8).base64EncodedString()}
   else if fault=="pq-label"{replaced["mode"]="reality-pq-vision"}
   else if fault=="bad-path"{
    var raw=try JSONSerialization.jsonObject(with:Data(base64Encoded:assets["xray.json"]!)!) as! [String:Any],rows=raw["outbounds"] as! [[String:Any]],row=rows[0],stream=row["streamSettings"] as! [String:Any],settings=stream["xhttpSettings"] as! [String:Any]
    settings["path"]="unowned-relative-path";stream["xhttpSettings"]=settings;row["streamSettings"]=stream;rows[0]=row;raw["outbounds"]=rows;changed["xray.json"]=try encoded(raw).base64EncodedString()
   }
   else if fault=="ordinary-label"{replaced["mode"]="reality-vision"}
   else {
    var raw=try JSONSerialization.jsonObject(with:Data(base64Encoded:assets["xray.json"]!)!) as! [String:Any],rows=raw["outbounds"] as! [[String:Any]],row=rows[0],settings=row["settings"] as! [String:Any],peers=settings["vnext"] as! [[String:Any]],peer=peers[0],users=peer["users"] as! [[String:Any]]
    users[0]["encryption"]="none";peer["users"]=users;peers[0]=peer;settings["vnext"]=peers;row["settings"]=settings;rows[0]=row;raw["outbounds"]=rows;changed["xray.json"]=try encoded(raw).base64EncodedString()
   }
   replaced["files"]=String(decoding:try encoded(changed),as:UTF8.self)
   try reject("PQ actual compiler refuses "+fault){_ = try compile(replaced)}
   if !["ordinary-label","pq-label"].contains(fault) {
    var replacement=model.bundle!;replacement.profiles[mode]=changed;var config=configuration;config["bundle"]=try encoded(replacement)
    try reject("PQ receipt refuses changed source "+fault){let next=try IOSMultihopExecution.Source(configuration:config,digest:hash);_ = try IOSMultihopExecution.StartupChoice.decode(receipt,source:next)}
   }
  }
  if mode=="reality-xhttp" {
   var rawAssets=assets,rawArgs=args;rawAssets.removeValue(forKey:"sing-box.json");rawArgs["files"]=String(decoding:try encoded(rawAssets),as:UTF8.self)
   func native(_ raw:String)throws->[String:Any]{let graph=try JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [String:Any];return (graph["outbounds"] as! [[String:Any]]).first{$0["tag"] as? String=="routervpn-execution-local"}!}
   try check("XHTTP raw-only assets retain exact native final",try encoded(native(compile(rawArgs)))==encoded(native(compiled)))
   for fault in ["path","mask","key","raw-only"] {
    var changed=assets
    if fault=="raw-only"{changed=rawAssets}
    else {
     var raw=try JSONSerialization.jsonObject(with:Data(base64Encoded:assets["xray.json"]!)!) as! [String:Any],rows=raw["outbounds"] as! [[String:Any]],row=rows[0],stream=row["streamSettings"] as! [String:Any]
     if fault=="path"{var settings=stream["xhttpSettings"] as! [String:Any];settings["path"]="/different-owned-source";stream["xhttpSettings"]=settings}
     else if fault=="mask"{stream.removeValue(forKey:"finalmask")}
     else {var settings=row["settings"] as! [String:Any],peers=settings["vnext"] as! [[String:Any]],peer=peers[0],users=peer["users"] as! [[String:Any]];let key=users[0]["encryption"] as! String;users[0]["encryption"]=String(key.dropLast())+(key.hasSuffix("A") ? "B":"A");peer["users"]=users;peers[0]=peer;settings["vnext"]=peers;row["settings"]=settings}
     row["streamSettings"]=stream;rows[0]=row;raw["outbounds"]=rows;changed["xray.json"]=try encoded(raw).base64EncodedString()
    }
    var replacement=model.bundle!;replacement.profiles[mode]=changed;var config=configuration;config["bundle"]=try encoded(replacement)
    try reject("XHTTP receipt refuses substituted original "+fault){let next=try IOSMultihopExecution.Source(configuration:config,digest:hash);_ = try IOSMultihopExecution.StartupChoice.decode(receipt,source:next)}
   }
  }
  let saved=try encoded(model.bundle!),writes=model.writes
  for execution in ["server","auto"] {
   try reject("PQ picker refuses unowned "+execution){try model.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:execution,entryMode:"socks5")}
   try check("PQ refusal preserves saved owner",model.writes==writes && encoded(model.bundle!)==saved)
  }
  print("PASS "+(mode=="reality-xhttp" ? "XHTTP":"PQ REALITY")+" picker \(checks) checks")
 }
 static func naiveH2(_ path:String)throws {
  func hash(_ data:Data)->String{CryptoKit.SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
  let mode="naive-h2",source=try JSONDecoder().decode([String].self,from:Data(contentsOf:URL(fileURLWithPath:path)))
  try check("Naive H2 picker uses complete original source",source.count==9 && source[2]==mode)
  let capture=try JSONSerialization.jsonObject(with:Data(source[1].utf8)) as! [String:Any],kind=capture["protocol"] as! String
  func capturedProfile(_ raw:[String:Any])throws->RouterProfile {
   var value=raw
   for (key,fallback) in ["name":"Captured H2 path","endpoint":"","router_api":"","api_token":"","adguard_ipv4":"","adguard_ipv6":"","socks_host":"","socks_port":0,"socks_username":"","socks_password":""] as [String:Any] where value[key]==nil {value[key]=fallback}
   return try JSONDecoder().decode(RouterProfile.self,from:encoded(value))
  }
  let first=try capturedProfile(capture["profile"] as! [String:Any]),paired=try capturedProfile(JSONSerialization.jsonObject(with:Data(source[4].utf8)) as! [String:Any]),assets=try JSONDecoder().decode([String:String].self,from:Data(source[3].utf8))
  var original=ClientBundle.empty;original.selectedRouterID=first.id;original.routerProfiles=[first];original.profiles=[:]
  var final=ClientBundle.empty;final.selectedRouterID=paired.id;final.routerProfiles=[paired];final.profiles=[mode:assets]
  let model=RouterVPNModel();model.bundle=final;IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(final)]
  try check("Naive H2 picker offers compatible exact source",model.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains(mode))
  try check("Naive H2 picker requires captured entry",!model.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id).contains(mode))
  try model.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)
  let held=try model.iosMultihopEntryBundle(for:model.bundle!)
  try check("Naive H2 save retains original source roles",held.routerProfiles==original.routerProfiles && held.profiles==original.profiles && model.bundle!.profiles==final.profiles && model.bundle!.routerProfiles[0].dnsProtocol=="tcp")
  let configuration:[String:Any]=["engine":"multihop-libbox","mode":mode,"bundle":try encoded(model.bundle!),"entryBundle":try encoded(original)]
  let owner=try IOSMultihopExecution.Source(configuration:configuration,digest:hash),receipt=try IOSMultihopExecution.StartupChoice(source:owner,execution:"local").encoded()
  try check("Naive H2 startup retains original final choice",owner.exitMode==mode && IOSMultihopExecution.StartupChoice.decode(receipt,source:owner).source==owner)
  let args=["config":source[0],"capture":source[1],"mode":source[2],"files":source[3],"profile":source[4],"start":source[5],"dns":source[6]]
  func compile(_ value:[String:String])throws->String{try RouterVPNTorTestCall(["Op":"imported-router","Config":String(decoding:encoded(value),as:UTF8.self)])}
  try check("Naive H2 actual compiler keeps original graph",try encoded(JSONSerialization.jsonObject(with:Data(compile(args).utf8)))==encoded(JSONSerialization.jsonObject(with:Data(source[8].utf8))))
  for fault in ["h3","numeric-quic","uot-version","missing-user","missing-password","insecure","missing-sni","missing-certificate","malformed-certificate","unused-asset","missing-source","foreign-service"] {
   var changed=assets,raw=try JSONSerialization.jsonObject(with:Data(base64Encoded:assets["sing-box.json"]!)!) as! [String:Any],rows=(try JSONSerialization.jsonObject(with:Data(base64Encoded:assets["sing-box.json"]!)!) as! [String:Any])["outbounds"] as! [[String:Any]]
   let index=rows.firstIndex(where:{$0["tag"] as? String=="proxy"})!;var row=rows[index]
   switch fault {
   case "h3":row["quic"]=true
   case "numeric-quic":row["quic"]=0
   case "uot-version":var uot=row["udp_over_tcp"] as! [String:Any];uot["version"]=1;row["udp_over_tcp"]=uot
   case "missing-user":row.removeValue(forKey:"username")
   case "missing-password":row.removeValue(forKey:"password")
   case "insecure","missing-sni":var tls=row["tls"] as! [String:Any];if fault=="insecure"{tls["insecure"]=true}else{tls.removeValue(forKey:"server_name")};row["tls"]=tls
   case "missing-certificate":var tls=row["tls"] as! [String:Any];tls.removeValue(forKey:"certificate");tls["certificate_path"]="missing.crt";row["tls"]=tls
   case "malformed-certificate":changed[(row["tls"] as! [String:Any])["certificate_path"] as! String]=Data("not a certificate".utf8).base64EncodedString()
   case "unused-asset":changed["unused.crt"]=Data("unused asset".utf8).base64EncodedString()
   case "foreign-service":changed["routervpn-ss-service.json"]=Data("{}".utf8).base64EncodedString()
   default:break
   }
   rows[index]=row;raw["outbounds"]=rows;changed["sing-box.json"]=try encoded(raw).base64EncodedString();if fault=="missing-source"{changed.removeValue(forKey:"sing-box.json")}
   var candidate=final;candidate.profiles[mode]=changed;let rejected=RouterVPNModel();rejected.bundle=candidate
   IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(candidate)]
   try check("Naive H2 picker refuses changed authority "+fault,!rejected.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains(mode))
   try reject("Naive H2 save refuses changed authority "+fault){try rejected.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)}
   var replaced=args;replaced["files"]=String(decoding:try encoded(changed),as:UTF8.self)
   try reject("Naive H2 actual compiler refuses "+fault){_ = try compile(replaced)}
  }
  for transport in ["udp","h3"] {
   var candidate=final;candidate.routerProfiles[0].dnsProtocol=transport
   if transport=="h3" {candidate.routerProfiles[0].dnsServerName="resolver.example.net";candidate.routerProfiles[0].dnsPath="/owned-dns-query"}
   let selection=RouterVPNModel();selection.bundle=candidate
   IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(candidate)]
   var profile=try JSONSerialization.jsonObject(with:Data(source[4].utf8)) as! [String:Any];profile["dns_protocol"]=transport;if transport=="h3" {profile["dns_server_name"]="resolver.example.net";profile["dns_path"]="/owned-dns-query"};var replaced=args;replaced["profile"]=String(decoding:try encoded(profile),as:UTF8.self)
   try check("Naive H2 picker offers final-owned selected DNS "+transport,selection.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains(mode))
   try selection.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)
   try check("Naive H2 save retains selected DNS and original sources",selection.writes==1 && selection.bundle!.routerProfiles[0].dnsProtocol==transport && selection.bundle!.routerProfiles[0].adGuardIPv4==paired.adGuardIPv4 && selection.bundle!.profiles==final.profiles && (try selection.iosMultihopEntryBundle(for:selection.bundle!)).profiles==original.profiles)
   let graph=try JSONSerialization.jsonObject(with:Data(compile(replaced).utf8)) as! [String:Any],resolvers=(graph["dns"] as! [String:Any])["servers"] as! [[String:Any]]
   try check("Naive H2 actual selected DNS is final-owned",resolvers.count==2 && resolvers[0]["type"] as? String==transport && resolvers[0]["server"] as? String==paired.adGuardIPv4 && resolvers[0]["detour"] as? String=="proxy")
   try check("Naive H2 retains the dormant lower resolver owner",resolvers[1]["detour"] as? String=="entry-wg" && resolvers[1]["type"] as? String==transport && resolvers[1]["server"] as? String==paired.adGuardIPv4)
  }
  for transport in ["tcp","tls","https","h3"] {for lower in ["tcp","tcp-custom-exit","udp","h3","missing"] {
   var raw=try JSONSerialization.jsonObject(with:Data(source[4].utf8)) as! [String:Any]
   raw["dns_mode"]="custom";raw["dns_protocol"]=transport;raw["dns_host"]="resolver.example.net";raw["dns_port"]=8853;raw["dns_server_name"]="resolver.example.net";raw["dns_path"]="/owned-dns-query"
   if lower != "missing"{raw["dns_bootstrap"]=["server":["type":lower=="tcp-custom-exit" ? "tcp":lower,"tag":"external-dns-bootstrap","server":"203.0.113.54","server_port":5354,"detour":lower=="tcp-custom-exit" ? "custom-exit":"proxy"],"query":["server":"external-dns-bootstrap","timeout":"3s","disable_optimistic_cache":true]] as [String:Any]}
   if lower=="h3" {var bootstrap=raw["dns_bootstrap"] as! [String:Any],server=bootstrap["server"] as! [String:Any];server["tls"]=["enabled":true,"server_name":"bootstrap.example.net"];server["path"]="/bootstrap-query";bootstrap["server"]=server;raw["dns_bootstrap"]=bootstrap}
   var candidate=final;candidate.routerProfiles=[try capturedProfile(raw)]
   let selection=RouterVPNModel();selection.bundle=candidate;IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(candidate)]
   var selectedArgs=args;selectedArgs["profile"]=String(decoding:try encoded(raw),as:UTF8.self);selectedArgs["dns"]=lower=="missing" ? "":String(decoding:try encoded(raw["dns_bootstrap"]!),as:UTF8.self)
   if lower != "missing"{
    try check("Naive H2 picker offers captured compatible hostname bootstrap",selection.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains(mode))
    try selection.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)
    try check("Naive H2 save retains selected and bootstrap policy",selection.bundle!.routerProfiles[0].dnsBootstrap==candidate.routerProfiles[0].dnsBootstrap && selection.bundle!.routerProfiles[0].dnsHost=="resolver.example.net" && selection.bundle!.routerProfiles[0].dnsProtocol==transport)
    let graph=try JSONSerialization.jsonObject(with:Data(compile(selectedArgs).utf8)) as! [String:Any]
    try check("Naive H2 actual compiler retains four owned resolvers",((graph["dns"] as! [String:Any])["servers"] as! [[String:Any]]).count==4)
   }else{
    try check("Naive H2 picker refuses incompatible hostname bootstrap "+lower,!selection.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains(mode))
    try reject("Naive H2 save refuses incompatible hostname bootstrap "+lower){try selection.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)}
    try reject("Naive H2 actual compiler refuses incompatible hostname bootstrap "+lower){_ = try compile(selectedArgs)}
   }
  }}
  for field in ["username","password","server","server_name"] {
   var changed=assets,raw=try JSONSerialization.jsonObject(with:Data(base64Encoded:assets["sing-box.json"]!)!) as! [String:Any],rows=(try JSONSerialization.jsonObject(with:Data(base64Encoded:assets["sing-box.json"]!)!) as! [String:Any])["outbounds"] as! [[String:Any]]
   let index=rows.firstIndex(where:{$0["tag"] as? String=="proxy"})!;var row=rows[index]
   if field=="server_name"{var tls=row["tls"] as! [String:Any];tls[field]="different.example.net";row["tls"]=tls}else{row[field]=field=="server" ? "203.0.113.99":"different-original"}
   rows[index]=row;raw["outbounds"]=rows;changed["sing-box.json"]=try encoded(raw).base64EncodedString();var replacement=model.bundle!;replacement.profiles[mode]=changed;var config=configuration;config["bundle"]=try encoded(replacement)
   try reject("Naive H2 receipt refuses replacement "+field){let next=try IOSMultihopExecution.Source(configuration:config,digest:hash);_ = try IOSMultihopExecution.StartupChoice.decode(receipt,source:next)}
  }
  IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(model.bundle!)]
  let saved=try encoded(model.bundle!),writes=model.writes
  for execution in ["server","auto"] {
   try reject("Naive H2 picker refuses unowned "+execution){try model.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:execution,entryMode:kind)}
   try check("Naive H2 execution refusal preserves saved source",model.writes==writes && encoded(model.bundle!)==saved)
  }
  for other in ["naive-h3","split","max","max-tls-wg"]{try check("Naive H2 does not admit unrelated final "+other,!IOSImportedEntryMultihop.supports(entry:kind,final:other))}
  print("PASS Naive H2 picker \(checks) checks")
 }
 static func naiveH2LiteralLayers(_ directory:String)throws {
  func hash(_ data:Data)->String{CryptoKit.SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
  func capturedProfile(_ raw:[String:Any])throws->RouterProfile {
   var value=raw
   for (key,fallback) in ["name":"Captured H2 literal path","endpoint":"","router_api":"","api_token":"","adguard_ipv4":"","adguard_ipv6":"","socks_host":"","socks_port":0,"socks_username":"","socks_password":""] as [String:Any] where value[key]==nil {value[key]=fallback}
   return try JSONDecoder().decode(RouterProfile.self,from:encoded(value))
  }
  func compile(_ value:[String:String])throws->[String:Any]{try JSONSerialization.jsonObject(with:Data(RouterVPNTorTestCall(["Op":"imported-router","Config":String(decoding:encoded(value),as:UTF8.self)]).utf8)) as! [String:Any]}
  let mode="naive-h2",layers=["off","aes-256-gcm","aes-256-gcm+xor-whitening"]
  for kind in ["http-connect","https-connect"] {for entryLayer in layers {for finalLayer in layers {
   let path=URL(fileURLWithPath:directory).appendingPathComponent(kind+"--naive-h2--"+entryLayer+"--"+finalLayer+".json"),originalBytes=try Data(contentsOf:path)
   let source=try JSONDecoder().decode([String].self,from:originalBytes)
   try check("literal H2 uses complete independently captured layers",source.count==9 && source[2]==mode && source[5].isEmpty==(finalLayer=="off"))
   let capture=try JSONSerialization.jsonObject(with:Data(source[1].utf8)) as! [String:Any],first=try capturedProfile(capture["profile"] as! [String:Any])
   var raw=try JSONSerialization.jsonObject(with:Data(source[4].utf8)) as! [String:Any]
   // Select the original default Home UDP policy without rewriting its
   // literal resolver, trust, credentials or either independent layer.
   raw.removeValue(forKey:"dns_protocol")
   let paired=try capturedProfile(raw)
   try check("literal H2 retains exact captured CONNECT and layer choices",capture["protocol"] as? String==kind && (first.startLayer ?? "off")==entryLayer && (try IOSMultihopStartLayer.selected(raw))==finalLayer)
   var original=ClientBundle.empty;original.selectedRouterID=first.id;original.routerProfiles=[first];original.profiles=[:]
   var final=ClientBundle.empty;final.selectedRouterID=paired.id;final.routerProfiles=[paired];final.profiles=[mode:try JSONDecoder().decode([String:String].self,from:Data(source[3].utf8))]
   if !source[5].isEmpty {final.profiles["shadowsocks"]=try JSONDecoder().decode([String:String].self,from:Data(source[5].utf8))}
   let model=RouterVPNModel();model.bundle=final
   IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(final)]
   try check("literal H2 picker admits its complete original layer pair "+kind+" "+entryLayer+" "+finalLayer,model.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains(mode))
   try model.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)
   let held=try model.iosMultihopEntryBundle(for:model.bundle!)
   try check("literal H2 save preserves both original layer sources",model.writes==1 && held.routerProfiles==original.routerProfiles && held.profiles==original.profiles && model.bundle!.profiles==final.profiles && model.bundle!.routerProfiles[0].startLayer==paired.startLayer)
   try check("literal H2 save keeps default Home UDP and paired authority",model.bundle!.routerProfiles[0].dnsProtocol==nil && model.bundle!.routerProfiles[0].dnsMode==paired.dnsMode && model.bundle!.routerProfiles[0].adGuardIPv4==paired.adGuardIPv4 && model.bundle!.routerProfiles[0].nodeProofID==paired.nodeProofID && model.bundle!.routerProfiles[0].apiToken==paired.apiToken)
   let configuration:[String:Any]=["engine":"multihop-libbox","mode":mode,"bundle":try encoded(model.bundle!),"entryBundle":try encoded(held)],owner=try IOSMultihopExecution.Source(configuration:configuration,digest:hash)
   let receipt=try IOSMultihopExecution.StartupChoice(source:owner,execution:"local").encoded()
   try check("literal H2 receipt binds its original selected path",owner.entryID==first.id && owner.exitID==paired.id && owner.entryMode==kind && owner.exitMode==mode && (try IOSMultihopExecution.StartupChoice.decode(receipt,source:owner)).source==owner)
   let cold=RouterVPNModel();cold.bundle=try JSONDecoder().decode(ClientBundle.self,from:encoded(model.bundle!))
   let coldEntry=try cold.iosMultihopEntryBundle(for:cold.bundle!),coldConfiguration:[String:Any]=["engine":"multihop-libbox","mode":mode,"bundle":try encoded(cold.bundle!),"entryBundle":try encoded(coldEntry)]
   try check("literal H2 cold save restores both exact source owners",coldEntry.routerProfiles==original.routerProfiles && coldEntry.profiles==original.profiles && (try IOSMultihopExecution.Source(configuration:coldConfiguration,digest:hash))==owner)
   let args=["config":source[0],"capture":source[1],"mode":source[2],"files":source[3],"profile":String(decoding:try encoded(raw),as:UTF8.self),"start":source[5],"dns":source[6]],graph=try compile(args),prior=try JSONSerialization.jsonObject(with:Data(source[8].utf8)) as! [String:Any]
   let resolvers=(graph["dns"] as! [String:Any])["servers"] as! [[String:Any]]
   try check("literal H2 compiler preserves captured encrypted path and route",try encoded(graph["outbounds"]!)==encoded(prior["outbounds"]!) && encoded(graph["route"]!)==encoded(prior["route"]!))
   try check("literal H2 compiler keeps Home UDP final-owned",resolvers.count==2 && resolvers[0]["type"] as? String=="udp" && resolvers[0]["server"] as? String==paired.adGuardIPv4 && resolvers[0]["server_port"] as? Int==53 && resolvers[0]["detour"] as? String=="proxy")
   try check("literal H2 compiler retains dormant lower resolver and layer owner",resolvers[1]["type"] as? String=="udp" && resolvers[1]["server"] as? String==paired.adGuardIPv4 && resolvers[1]["server_port"] as? Int==53 && resolvers[1]["detour"] as? String==(finalLayer=="off" ? "entry-wg":"start-layer-aes"))
   for fault in ["h3","hostname-udp","literal-bootstrap"] {
    var changed=raw
    if fault=="h3"{changed["dns_protocol"]="h3"}
    else if fault=="hostname-udp"{changed["dns_mode"]="custom";changed["dns_host"]="resolver.example.net"}
    else {changed["dns_bootstrap"]=["server":["type":"tcp","tag":"external-dns-bootstrap","server":"203.0.113.54","server_port":5354,"detour":"proxy"],"query":["server":"external-dns-bootstrap","timeout":"3s"]] as [String:Any]}
    var refused=final;refused.routerProfiles=[try capturedProfile(changed)]
    let rejected=RouterVPNModel();rejected.bundle=refused;let before=try encoded(refused)
    IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:before]
    try check("literal H2 picker refuses widened DNS "+fault,!rejected.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains(mode))
    try reject("literal H2 save refuses widened DNS "+fault){try rejected.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)}
    try check("literal H2 rejected DNS does not mutate saved source",rejected.writes==0 && encoded(rejected.bundle!)==before)
    var changedArgs=args;changedArgs["profile"]=String(decoding:try encoded(changed),as:UTF8.self);changedArgs["dns"]=changed["dns_bootstrap"] == nil ? "":String(decoding:try encoded(changed["dns_bootstrap"]!),as:UTF8.self)
    try reject("literal H2 compiler refuses widened DNS "+fault){_ = try compile(changedArgs)}
   }
   if entryLayer != "off" {
    var missing=first;missing.external?.startLayer=nil
    var next=original;next.routerProfiles=[missing]
    IOSNodeBundleStore.shared.nodes=[first.id:try encoded(next),paired.id:try encoded(final)]
    let rejected=RouterVPNModel();rejected.bundle=final
    try check("literal H2 picker requires original entry layer",!rejected.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:missing).contains(mode))
    try reject("literal H2 save requires original entry layer"){try rejected.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)}
    try check("literal H2 missing entry layer preserves saved source",rejected.writes==0 && encoded(rejected.bundle!)==encoded(final))
    var changedCapture=capture,entryRaw=capture["profile"] as! [String:Any],external=entryRaw["external"] as! [String:Any];external.removeValue(forKey:"start_layer");entryRaw["external"]=external;changedCapture["profile"]=entryRaw
    var changedArgs=args;changedArgs["capture"]=String(decoding:try encoded(changedCapture),as:UTF8.self)
    try reject("literal H2 compiler requires original entry layer"){_ = try compile(changedArgs)}
   }
   if finalLayer != "off" {
    var missing=final;missing.profiles.removeValue(forKey:"shadowsocks")
    IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(missing)]
    let rejected=RouterVPNModel();rejected.bundle=missing
    try check("literal H2 picker requires original final layer",!rejected.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains(mode))
    try reject("literal H2 save requires original final layer"){try rejected.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)}
    try check("literal H2 missing final layer preserves saved source",rejected.writes==0 && encoded(rejected.bundle!)==encoded(missing))
    var changedArgs=args;changedArgs["start"]=""
    try reject("literal H2 compiler requires original final layer"){_ = try compile(changedArgs)}
    for fault in ["hostname","missing-peer","mapped-ipv6","scoped-ipv6"] {
     var invalid=final,layer=final.profiles["shadowsocks"]!
     var layerGraph=try JSONSerialization.jsonObject(with:Data(base64Encoded:layer["sing-box.json"]!)!) as! [String:Any],layerRows=layerGraph["outbounds"] as! [[String:Any]]
     let layerIndex=layerRows.firstIndex(where:{$0["type"] as? String=="shadowsocks"})!
     if fault=="missing-peer"{layerRows[layerIndex].removeValue(forKey:"server")}
     else {layerRows[layerIndex]["server"]=fault=="hostname" ? "layer.example.net":fault=="mapped-ipv6" ? "::ffff:192.0.2.44":"2001:db8::44%en0"}
     layerGraph["outbounds"]=layerRows;layer["sing-box.json"]=try encoded(layerGraph).base64EncodedString();invalid.profiles["shadowsocks"]=layer
     let refused=RouterVPNModel();refused.bundle=invalid
     IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(invalid)]
     try check("literal H2 picker refuses final AES "+fault,!refused.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains(mode))
     try reject("literal H2 save refuses final AES "+fault){try refused.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)}
     try check("literal H2 invalid layer refusal preserves captured source",refused.writes==0 && encoded(refused.bundle!)==encoded(invalid))
     changedArgs=args;changedArgs["start"]=String(decoding:try encoded(layer),as:UTF8.self)
     try reject("literal H2 compiler refuses final AES "+fault){_ = try compile(changedArgs)}
     if fault=="hostname" {
      var tcp=invalid,tcpRaw=raw;tcp.routerProfiles[0].dnsProtocol="tcp";tcpRaw["dns_protocol"]="tcp"
      let selection=RouterVPNModel();selection.bundle=tcp
      IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(tcp)]
      try check("H2 TCP picker retains earlier eligibility before native source validation",selection.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains(mode))
      try selection.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)
      try check("H2 hostname layer retains saved TCP policy and original assets",selection.writes==1 && selection.bundle!.routerProfiles[0].dnsProtocol=="tcp" && selection.bundle!.profiles==tcp.profiles)
      changedArgs["profile"]=String(decoding:try encoded(tcpRaw),as:UTF8.self)
      // The picker/native-readiness double does not establish executable
      // source authority: the shared SS compiler already requires a literal.
      try reject("H2 compiler preserves existing hostname layer refusal with TCP DNS"){_ = try compile(changedArgs)}
     }
    }
   }
   try check("literal H2 fixture never modifies its exported source",try Data(contentsOf:path)==originalBytes)
  }}}
  print("PASS Naive H2 literal layered picker \(checks) checks")
 }
 static func naiveH3(_ path:String)throws {
  func hash(_ data:Data)->String{CryptoKit.SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
  let mode="naive-h3",source=try JSONDecoder().decode([String].self,from:Data(contentsOf:URL(fileURLWithPath:path)))
  try check("Naive H3 picker uses complete original source",source.count==9 && source[2]==mode)
  let capture=try JSONSerialization.jsonObject(with:Data(source[1].utf8)) as! [String:Any],kind=capture["protocol"] as! String
  func capturedProfile(_ raw:[String:Any])throws->RouterProfile {
   var value=raw
   for (key,fallback) in ["name":"Captured H3 path","endpoint":"","router_api":"","api_token":"","adguard_ipv4":"","adguard_ipv6":"","socks_host":"","socks_port":0,"socks_username":"","socks_password":""] as [String:Any] where value[key]==nil {value[key]=fallback}
   return try JSONDecoder().decode(RouterProfile.self,from:encoded(value))
  }
  let first=try capturedProfile(capture["profile"] as! [String:Any]),paired=try capturedProfile(JSONSerialization.jsonObject(with:Data(source[4].utf8)) as! [String:Any]),assets=try JSONDecoder().decode([String:String].self,from:Data(source[3].utf8))
  var original=ClientBundle.empty;original.selectedRouterID=first.id;original.routerProfiles=[first];original.profiles=[:]
  var final=ClientBundle.empty;final.selectedRouterID=paired.id;final.routerProfiles=[paired];final.profiles=[mode:assets]
  let model=RouterVPNModel();model.bundle=final;IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(final)]
  try check("Naive H3 picker offers compatible exact source",model.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains(mode))
  try check("Naive H3 picker requires captured entry",!model.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id).contains(mode))
  try model.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)
  let held=try model.iosMultihopEntryBundle(for:model.bundle!)
  try check("Naive H3 save retains original source roles",held.routerProfiles==original.routerProfiles && held.profiles==original.profiles && model.bundle!.profiles==final.profiles && (model.bundle!.routerProfiles[0].dnsProtocol ?? "udp")=="udp")
  let configuration:[String:Any]=["engine":"multihop-libbox","mode":mode,"bundle":try encoded(model.bundle!),"entryBundle":try encoded(original)]
  let owner=try IOSMultihopExecution.Source(configuration:configuration,digest:hash),receipt=try IOSMultihopExecution.StartupChoice(source:owner,execution:"local").encoded()
  try check("Naive H3 startup retains original final choice",owner.exitMode==mode && IOSMultihopExecution.StartupChoice.decode(receipt,source:owner).source==owner)
  let args=["config":source[0],"capture":source[1],"mode":source[2],"files":source[3],"profile":source[4],"start":source[5],"dns":source[6]]
  func compile(_ value:[String:String])throws->String{try RouterVPNTorTestCall(["Op":"imported-router","Config":String(decoding:encoded(value),as:UTF8.self)])}
  try check("Naive H3 actual compiler keeps original graph",try encoded(JSONSerialization.jsonObject(with:Data(compile(args).utf8)))==encoded(JSONSerialization.jsonObject(with:Data(source[8].utf8))))
  for fault in ["h2","numeric-quic","uot-version","missing-user","missing-password","insecure","missing-sni","missing-certificate","malformed-certificate","unused-asset","missing-source","foreign-service"] {
   var changed=assets,raw=try JSONSerialization.jsonObject(with:Data(base64Encoded:assets["sing-box.json"]!)!) as! [String:Any],rows=(try JSONSerialization.jsonObject(with:Data(base64Encoded:assets["sing-box.json"]!)!) as! [String:Any])["outbounds"] as! [[String:Any]]
   let index=rows.firstIndex(where:{$0["tag"] as? String=="proxy"})!;var row=rows[index]
   switch fault {
   case "h2":row["quic"]=false
   case "numeric-quic":row["quic"]=0
   case "uot-version":var uot=row["udp_over_tcp"] as! [String:Any];uot["version"]=1;row["udp_over_tcp"]=uot
   case "missing-user":row.removeValue(forKey:"username")
   case "missing-password":row.removeValue(forKey:"password")
   case "insecure","missing-sni":var tls=row["tls"] as! [String:Any];if fault=="insecure"{tls["insecure"]=true}else{tls.removeValue(forKey:"server_name")};row["tls"]=tls
   case "missing-certificate":var tls=row["tls"] as! [String:Any];tls.removeValue(forKey:"certificate");tls["certificate_path"]="missing.crt";row["tls"]=tls
   case "malformed-certificate":changed[(row["tls"] as! [String:Any])["certificate_path"] as! String]=Data("not a certificate".utf8).base64EncodedString()
   case "unused-asset":changed["unused.crt"]=Data("unused asset".utf8).base64EncodedString()
   case "foreign-service":changed["routervpn-ss-service.json"]=Data("{}".utf8).base64EncodedString()
   default:break
   }
   rows[index]=row;raw["outbounds"]=rows;changed["sing-box.json"]=try encoded(raw).base64EncodedString();if fault=="missing-source"{changed.removeValue(forKey:"sing-box.json")}
   var candidate=final;candidate.profiles[mode]=changed;let rejected=RouterVPNModel();rejected.bundle=candidate
   IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(candidate)]
   try check("Naive H3 picker refuses changed authority "+fault,!rejected.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains(mode))
   try reject("Naive H3 save refuses changed authority "+fault){try rejected.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)}
   var replaced=args;replaced["files"]=String(decoding:try encoded(changed),as:UTF8.self)
   try reject("Naive H3 actual compiler refuses "+fault){_ = try compile(replaced)}
  }
  for transport in ["udp","h3"] {
   var candidate=final;candidate.routerProfiles[0].dnsProtocol=transport
   if transport=="h3"{candidate.routerProfiles[0].dnsServerName="adguard.home.example";candidate.routerProfiles[0].dnsPath="/owned-query";candidate.routerProfiles[0].dnsPort=5443}
   let selected=RouterVPNModel();selected.bundle=candidate
   IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(candidate)]
   try check("Naive H3 picker preserves selected Home "+transport,selected.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains(mode))
   try selected.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)
   try check("Naive H3 save retains selected Home policy",selected.bundle!.routerProfiles[0].dnsProtocol==transport && selected.bundle!.routerProfiles[0].dnsServerName==candidate.routerProfiles[0].dnsServerName && selected.bundle!.routerProfiles[0].dnsPath==candidate.routerProfiles[0].dnsPath && selected.bundle!.routerProfiles[0].dnsPort==candidate.routerProfiles[0].dnsPort)
   var profile=try JSONSerialization.jsonObject(with:Data(source[4].utf8)) as! [String:Any];profile["dns_protocol"]=transport;if transport=="h3"{profile["dns_server_name"]="adguard.home.example";profile["dns_path"]="/owned-query";profile["dns_port"]=5443};var replaced=args;replaced["profile"]=String(decoding:try encoded(profile),as:UTF8.self)
   let graph=try JSONSerialization.jsonObject(with:Data(compile(replaced).utf8)) as! [String:Any],servers=(graph["dns"] as! [String:Any])["servers"] as! [[String:Any]]
   try check("Naive H3 actual compiler preserves both Home DNS lanes",servers.count==2 && servers.allSatisfy{$0["type"] as? String==transport})
  }
  for transport in ["udp","tcp","tls","https","h3"] {for lower in ["tcp","tcp-custom-exit","udp","h3","missing"] {
   var raw=try JSONSerialization.jsonObject(with:Data(source[4].utf8)) as! [String:Any]
   raw["dns_mode"]="custom";raw["dns_protocol"]=transport;raw["dns_host"]="resolver.example.net";raw["dns_port"]=8853;raw["dns_server_name"]="resolver.example.net";raw["dns_path"]="/owned-dns-query"
   if lower != "missing"{raw["dns_bootstrap"]=["server":["type":lower=="tcp-custom-exit" ? "tcp":lower,"tag":"external-dns-bootstrap","server":"203.0.113.54","server_port":5354,"detour":lower=="tcp-custom-exit" ? "custom-exit":"proxy"],"query":["server":"external-dns-bootstrap","timeout":"3s","disable_optimistic_cache":true]] as [String:Any]}
   if lower=="h3"{var bootstrap=raw["dns_bootstrap"] as! [String:Any],server=bootstrap["server"] as! [String:Any];server["tls"]=["enabled":true,"server_name":"bootstrap.example.net"];server["path"]="/bootstrap-dns-query";bootstrap["server"]=server;raw["dns_bootstrap"]=bootstrap}
   var candidate=final;candidate.routerProfiles=[try capturedProfile(raw)]
   let selection=RouterVPNModel();selection.bundle=candidate;IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(candidate)]
   var selectedArgs=args;selectedArgs["profile"]=String(decoding:try encoded(raw),as:UTF8.self);selectedArgs["dns"]=lower=="missing" ? "":String(decoding:try encoded(raw["dns_bootstrap"]!),as:UTF8.self)
   if lower != "missing"{
    try check("Naive H3 picker offers captured compatible hostname bootstrap",selection.iosImportedRouterFinalModes(entryMode:kind,exitID:paired.id,entryProfile:first).contains(mode))
    try selection.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:kind)
    try check("Naive H3 save retains selected and bootstrap policy",selection.bundle!.routerProfiles[0].dnsBootstrap==candidate.routerProfiles[0].dnsBootstrap && selection.bundle!.routerProfiles[0].dnsHost=="resolver.example.net" && selection.bundle!.routerProfiles[0].dnsProtocol==transport)
    let graph=try JSONSerialization.jsonObject(with:Data(compile(selectedArgs).utf8)) as! [String:Any]
    try check("Naive H3 actual compiler retains four owned resolvers",((graph["dns"] as! [String:Any])["servers"] as! [[String:Any]]).count==4)
   }else{
    try reject("Naive H3 actual compiler refuses missing captured hostname bootstrap"){_ = try compile(selectedArgs)}
   }
  }}
  for field in ["username","password","server","server_name"] {
   var changed=assets,raw=try JSONSerialization.jsonObject(with:Data(base64Encoded:assets["sing-box.json"]!)!) as! [String:Any],rows=(try JSONSerialization.jsonObject(with:Data(base64Encoded:assets["sing-box.json"]!)!) as! [String:Any])["outbounds"] as! [[String:Any]]
   let index=rows.firstIndex(where:{$0["tag"] as? String=="proxy"})!;var row=rows[index]
   if field=="server_name"{var tls=row["tls"] as! [String:Any];tls[field]="different.example.net";row["tls"]=tls}else{row[field]=field=="server" ? "203.0.113.99":"different-original"}
   rows[index]=row;raw["outbounds"]=rows;changed["sing-box.json"]=try encoded(raw).base64EncodedString();var replacement=model.bundle!;replacement.profiles[mode]=changed;var config=configuration;config["bundle"]=try encoded(replacement)
   try reject("Naive H3 receipt refuses replacement "+field){let next=try IOSMultihopExecution.Source(configuration:config,digest:hash);_ = try IOSMultihopExecution.StartupChoice.decode(receipt,source:next)}
  }
  guard let lowerDirectory=ProcessInfo.processInfo.environment["ROUTERVPN_IOS_IMPORTED_NAIVE_H2_SOURCES"] else {throw IOSImportedEntryMultihop.issue()}
  for protocolName in ["http-connect","https-connect"] {
   let lowerPath=URL(fileURLWithPath:lowerDirectory).appendingPathComponent(protocolName+"--naive-h2--off--off.json")
   let lowerSource=try JSONDecoder().decode([String].self,from:Data(contentsOf:lowerPath)),lowerCapture=try JSONSerialization.jsonObject(with:Data(lowerSource[1].utf8)) as! [String:Any],forbidden=try capturedProfile(lowerCapture["profile"] as! [String:Any])
   var lowerBundle=ClientBundle.empty;lowerBundle.selectedRouterID=forbidden.id;lowerBundle.routerProfiles=[forbidden];lowerBundle.profiles=[:]
   try check("Naive H3 valid CONNECT capture remains stream-only",lowerCapture["protocol"] as? String==protocolName && !IOSImportedEntryMultihop.supports(entry:protocolName,final:mode))
   for transport in ["udp","tcp","h3"] {
    var candidate=final;candidate.routerProfiles[0].dnsProtocol=transport
    let rejected=RouterVPNModel();rejected.bundle=candidate;let before=try encoded(candidate)
    IOSNodeBundleStore.shared.nodes=[forbidden.id:try encoded(lowerBundle),paired.id:before]
    try check("Naive H3 picker refuses CONNECT despite selected "+transport,!rejected.iosImportedRouterFinalModes(entryMode:protocolName,exitID:paired.id,entryProfile:forbidden).contains(mode))
    try reject("Naive H3 save refuses stream-only CONNECT"){try rejected.saveIOSMultihop(enabled:true,entryID:forbidden.id,exitID:paired.id,exitMode:mode,execution:"local",entryMode:protocolName)}
    try check("Naive H3 CONNECT refusal preserves saved source",rejected.writes==0 && encoded(rejected.bundle!)==before)
    var profile=try JSONSerialization.jsonObject(with:Data(source[4].utf8)) as! [String:Any];profile["dns_protocol"]=transport
    var selectedArgs=args;selectedArgs["config"]=lowerSource[0];selectedArgs["capture"]=lowerSource[1];selectedArgs["profile"]=String(decoding:try encoded(profile),as:UTF8.self)
    try reject("Naive H3 actual compiler refuses valid CONNECT source"){_ = try compile(selectedArgs)}
   }
  }
  IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(model.bundle!)]
  let saved=try encoded(model.bundle!),writes=model.writes
  for execution in ["server","auto"] {
   try reject("Naive H3 picker refuses unowned "+execution){try model.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:mode,execution:execution,entryMode:kind)}
   try check("Naive H3 execution refusal preserves saved source",model.writes==writes && encoded(model.bundle!)==saved)
  }
  for other in ["split","max","max-tls-wg"]{try check("Naive H3 does not admit unrelated final "+other,!IOSImportedEntryMultihop.supports(entry:kind,final:other))}
  print("PASS Naive H3 picker \(checks) checks")
 }
 static func packetReality(_ directory:String,_ kind:String)throws {
  guard ["wireguard","amneziawg","openvpn-tcp","openvpn-udp"].contains(kind) else {throw IOSImportedEntryMultihop.issue()}
  for entryLayer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {for finalLayer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
  let file=URL(fileURLWithPath:directory).appendingPathComponent(kind+"--reality-vision--"+entryLayer+"--"+finalLayer+".json")
  let source=try JSONDecoder().decode([String].self,from:Data(contentsOf:file))
  try check("packet picker uses original independent layer source receipt",source.count==9 && source[2]=="reality-vision" && source[5].isEmpty==(finalLayer=="off"))
  let capture=try JSONSerialization.jsonObject(with:Data(source[1].utf8)) as! [String:Any]
  let mode=kind.hasPrefix("openvpn-") ? "openvpn":kind
  try check("packet picker retains exact imported family",capture["protocol"] as? String==mode)
  // Shared source captures contain transport policy, not display-only defaults.
  // Fill only absent required model fields; keep every original field/asset.
  func capturedProfile(_ raw:[String:Any])throws->RouterProfile {
   var value=raw
   let defaults:[String:Any]=["name":"Captured packet path","endpoint":"","router_api":"","api_token":"","adguard_ipv4":"","adguard_ipv6":"","socks_host":"","socks_port":0,"socks_username":"","socks_password":""]
   for (key,fallback) in defaults where value[key]==nil {value[key]=fallback}
   return try JSONDecoder().decode(RouterProfile.self,from:encoded(value))
  }
  let first=try capturedProfile(capture["profile"] as! [String:Any])
  let paired=try capturedProfile(JSONSerialization.jsonObject(with:Data(source[4].utf8)) as! [String:Any])
  var original=ClientBundle.empty;original.selectedRouterID=first.id;original.routerProfiles=[first];original.profiles=[:]
  var final=ClientBundle.empty;final.selectedRouterID=paired.id;final.routerProfiles=[paired]
  final.profiles=["reality-vision":try JSONDecoder().decode([String:String].self,from:Data(source[3].utf8))]
  if !source[5].isEmpty {final.profiles["shadowsocks"]=try JSONDecoder().decode([String:String].self,from:Data(source[5].utf8))}
  let model=RouterVPNModel();model.bundle=final
  IOSNodeBundleStore.shared.nodes=[first.id:try encoded(original),paired.id:try encoded(final)]
  try check("packet REALITY picker requires original entry",model.iosImportedRouterFinalModes(entryMode:mode,exitID:paired.id,entryProfile:first).contains("reality-vision"))
  try check("packet REALITY picker rejects absent entry",!model.iosImportedRouterFinalModes(entryMode:mode,exitID:paired.id).contains("reality-vision"))
  try model.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:"reality-vision",execution:"local",entryMode:mode)
  let held=try model.iosMultihopEntryBundle(for:model.bundle!)
  try check("packet REALITY save preserves original keys routes MTU and OpenVPN source",held.routerProfiles==original.routerProfiles && held.profiles==original.profiles)
  try check("packet REALITY save preserves paired assets DNS and authority",model.bundle!.profiles==final.profiles && model.bundle!.routerProfiles[0].dnsMode==paired.dnsMode && model.bundle!.routerProfiles[0].adGuardIPv4==paired.adGuardIPv4 && model.bundle!.routerProfiles[0].nodeProofID==paired.nodeProofID && model.bundle!.routerProfiles[0].apiToken==paired.apiToken)
  try check("packet REALITY cannot invent private entry authority",held.apiToken.isEmpty && held.routerAPI.isEmpty && held.nodeProofID.isEmpty)
  func hash(_ data:Data)->String{CryptoKit.SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
  let configuration:[String:Any]=["engine":"multihop-libbox","mode":"reality-vision","bundle":try encoded(model.bundle!),"entryBundle":try encoded(original)]
  let identity=try IOSMultihopExecution.Source(configuration:configuration,digest:hash)
  try check("packet REALITY source binds exact Local roles",identity.entryID==first.id && identity.exitID==paired.id && identity.entryMode==mode && identity.exitMode=="reality-vision" && identity.requested=="local")
  let receipt=try IOSMultihopExecution.StartupChoice(source:identity,execution:"local").encoded()
  try check("packet REALITY startup receipt retains original sources",try IOSMultihopExecution.StartupChoice.decode(receipt,source:identity).source==identity)
  let saved=try encoded(model.bundle!),writes=model.writes,cold=RouterVPNModel()
  cold.bundle=try JSONDecoder().decode(ClientBundle.self,from:saved)
  let coldEntry=try cold.iosMultihopEntryBundle(for:cold.bundle!)
  let coldConfiguration:[String:Any]=["engine":"multihop-libbox","mode":"reality-vision","bundle":try encoded(cold.bundle!),"entryBundle":try encoded(original)]
  try check("packet REALITY cold capture retains saved path",coldEntry.routerProfiles==original.routerProfiles && coldEntry.profiles==original.profiles && IOSMultihopExecution.Source(configuration:coldConfiguration,digest:hash)==identity)
  for role in ["entry","final"] {
   var changed=configuration
   if role=="entry" {
    var next=original
    if mode=="wireguard" {next.routerProfiles[0].external?.wireGuard?.privateKey=Data(repeating:120,count:32).base64EncodedString()}
    else if mode=="amneziawg" {next.routerProfiles[0].external?.amneziaWG?.privateKey=Data(repeating:120,count:32).base64EncodedString()}
    else {next.routerProfiles[0].external?.openVPN?.password="foreign original password"}
    changed["entryBundle"]=try encoded(next)
   }else {
    var next=model.bundle!
    let originalAsset=Data(base64Encoded:next.profiles["reality-vision"]!["xray.json"]!)!
    next.profiles["reality-vision"]!["xray.json"]=(originalAsset+Data("\n".utf8)).base64EncodedString()
    changed["bundle"]=try encoded(next)
   }
   let replaced=try IOSMultihopExecution.Source(configuration:changed,digest:hash)
   try check("packet REALITY fingerprints only replaced role "+role,role=="entry" ? replaced.entrySHA256 != identity.entrySHA256 && replaced.bundleSHA256==identity.bundleSHA256 : replaced.bundleSHA256 != identity.bundleSHA256 && replaced.entrySHA256==identity.entrySHA256)
   try reject("packet REALITY cannot restore replaced original "+role){_ = try IOSMultihopExecution.StartupChoice.decode(receipt,source:replaced)}
  }
  for execution in ["server","auto"] {
   try reject("packet REALITY picker refuses unsupported execution "+execution){try model.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:"reality-vision",execution:execution,entryMode:mode)}
   try check("packet REALITY rejected execution preserves saved owner",model.writes==writes && encoded(model.bundle!)==saved)
  }
  if entryLayer != "off" {
   var missing=first;missing.external?.startLayer=nil
   var next=original;next.routerProfiles=[missing];IOSNodeBundleStore.shared.nodes[first.id]=try encoded(next)
   try reject("packet REALITY captured entry needs its own original layer"){_ = try cold.iosMultihopEntryBundle(for:cold.bundle!)}
   try check("packet REALITY missing entry layer preserves saved owner",model.writes==writes && encoded(model.bundle!)==saved)
   IOSNodeBundleStore.shared.nodes[first.id]=try encoded(original)
  }
  if finalLayer != "off" {
   var missing=final;missing.profiles.removeValue(forKey:"shadowsocks")
   IOSNodeBundleStore.shared.nodes[paired.id]=try encoded(missing)
   let refused=RouterVPNModel();refused.bundle=missing
   try reject("packet REALITY captured final needs its own original layer"){try refused.saveIOSMultihop(enabled:true,entryID:first.id,exitID:paired.id,exitMode:"reality-vision",execution:"local",entryMode:mode)}
   try check("packet REALITY missing final layer preserves saved owner",refused.writes==0 && encoded(refused.bundle!)==encoded(missing) && model.writes==writes && encoded(model.bundle!)==saved)
  }
  }}
  print("PASS packet REALITY picker "+kind+" \(checks) checks")
 }
 static func run()throws {
  defer { RouterVPNTorTestClose() }
  var imported=try profile("imported-first","external","shadowsocks");imported.apiToken="";imported.dnsMode="home"
  imported.external?.shadowsocks=ExternalShadowsocksConfig(server:"203.0.113.20",port:443,method:"2022-blake3-aes-256-gcm",password:Data(repeating:9,count:32).base64EncodedString())
  var paired=try profile("paired-final","router-vpn");paired.external=nil;paired.dnsMode="home"
  var finalBundle=bundle(paired)
  finalBundle.profiles["shadowsocks"]=["sing-box.json":try encoded(["outbounds":[["type":"shadowsocks","tag":"proxy","server":"192.0.2.44","server_port":443,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:8,count:32).base64EncodedString()]]]).base64EncodedString()]
  if CommandLine.arguments.count == 3 && CommandLine.arguments[2] == "socks-reality" {try reality(finalBundle,paired);return}
  if CommandLine.arguments.count == 4 && CommandLine.arguments[2] == "pq-reality" {try pqReality(CommandLine.arguments[3]);return}
  if CommandLine.arguments.count == 4 && CommandLine.arguments[2] == "xhttp-reality" {try pqReality(CommandLine.arguments[3],"reality-xhttp");return}
  if CommandLine.arguments.count == 4 && CommandLine.arguments[2] == "naive-h2" {try naiveH2(CommandLine.arguments[3]);return}
  if CommandLine.arguments.count == 4 && CommandLine.arguments[2] == "naive-h2-literal" {try naiveH2LiteralLayers(CommandLine.arguments[3]);return}
  if CommandLine.arguments.count == 4 && CommandLine.arguments[2] == "naive-h3" {try naiveH3(CommandLine.arguments[3]);return}
  if CommandLine.arguments.count == 5 && CommandLine.arguments[2] == "selected-dns" { try selectedDNS(finalBundle,paired,CommandLine.arguments[3],CommandLine.arguments[4]);return }
  if CommandLine.arguments.count == 5 && CommandLine.arguments[2] == "packet-reality" {try packetReality(CommandLine.arguments[4],CommandLine.arguments[3]);return}
  if CommandLine.arguments.count == 4 && CommandLine.arguments[2] == "proxy-reality" {guard ["shadowsocks","hysteria2"].contains(CommandLine.arguments[3]) else {throw IOSImportedEntryMultihop.issue()};try reality(finalBundle,paired,CommandLine.arguments[3]);return}
  if CommandLine.arguments.count == 4 && CommandLine.arguments[2] == "connect-reality" {guard ["http-connect","https-connect"].contains(CommandLine.arguments[3]) else {throw IOSImportedEntryMultihop.issue()};try reality(finalBundle,paired,CommandLine.arguments[3]);return}
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


def export_naive_h2_sources(work):
    sources = work / 'naive-h2-sources'
    sources.mkdir()
    subprocess.run(['go', 'test', './internal/mobilemultihop', '-run', '^TestImportedNaiveH2IndependentLayers$',
                    '-count=1', '-timeout=30s'], cwd=ROOT, check=True, timeout=45,
                   env=dict(os.environ, ROUTERVPN_IMPORTED_NAIVE_H2_FIXTURES=str(sources)))
    return sources


def verify_naive_h2_literal(work, compiler, runtime_env, sources):
    originals = {}
    for kind in ('http-connect', 'https-connect'):
        for first in ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening'):
            for last in ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening'):
                name = kind+'--naive-h2--'+first+'--'+last+'.json'
                path = sources / name
                if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 1 << 20:
                    raise ValueError('Literal H2 picker requires eighteen complete bounded layer captures')
                originals[name] = path.read_bytes()
    result = subprocess.run([str(work/'test'), str(compiler), 'naive-h2-literal', str(sources)],
                            env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
    if result.stdout != 'PASS Naive H2 literal layered picker 738 checks\n':
        raise ValueError('Missing or foreign literal H2 layered picker verdict: '+repr(result.stdout))
    if any((sources/name).read_bytes() != value for name,value in originals.items()):
        raise ValueError('Literal H2 picker changed its original independent layer captures')
    print(result.stdout, end='', flush=True)


def main(only_naive_h2_literal=False, only_naive_h2_dns=False):
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
        if only_naive_h2_dns:
            sources = export_naive_h2_sources(work)
            original = sources / 'http-connect--naive-h2--off--off.json'
            captured = original.read_bytes()
            result = subprocess.run([str(work/'test'), str(compiler), 'naive-h2', str(original)],
                                    env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
            if result.stdout != 'PASS Naive H2 picker 122 checks\n' or original.read_bytes() != captured:
                raise ValueError('Missing or source-mutating Naive H2 DNS verdict')
            print(result.stdout, end='', flush=True)
            return
        if only_naive_h2_literal:
            verify_naive_h2_literal(work, compiler, runtime_env, export_naive_h2_sources(work))
            return
        baseline = subprocess.run([str(work / 'test'), str(compiler)], env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
        expected_baseline = 'Apple external entry selection: PASS (3231 shipping Swift checks; storage/native-readiness boundaries doubled)\n'
        if baseline.stdout != expected_baseline:
            raise ValueError('Missing or foreign baseline Swift verdict: '+repr(baseline.stdout))
        print(baseline.stdout, end='', flush=True)
        reality = subprocess.run([str(work / 'test'), str(compiler), 'socks-reality'], env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
        if reality.stdout != 'PASS SOCKS REALITY host 115 checks\n':
            raise ValueError('Missing or foreign SOCKS REALITY Swift verdict: '+repr(reality.stdout))
        print(reality.stdout, end='', flush=True)
        pq_sources = work / 'pq-reality-sources'
        pq_sources.mkdir()
        subprocess.run(['go', 'test', './internal/mobilemultihop', '-run', '^TestImportedPQRealityIndependentLayers$',
                        '-count=1', '-timeout=30s'], cwd=ROOT, check=True, timeout=45,
                       env=dict(os.environ, ROUTERVPN_IMPORTED_PQ_XRAY_FIXTURES=str(pq_sources)))
        pq_source = pq_sources / 'socks5--reality-pq-vision--off--off.json'
        original_pq = pq_source.read_bytes()
        pq = subprocess.run([str(work/'test'), str(compiler), 'pq-reality', str(pq_source)],
                            env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
        if pq.stdout != 'PASS PQ REALITY picker 19 checks\n' or pq_source.read_bytes() != original_pq:
            raise ValueError('Missing, foreign, or source-mutating PQ picker verdict: '+repr(pq.stdout))
        print(pq.stdout, end='', flush=True)
        xhttp_sources = work / 'xhttp-sources'
        xhttp_sources.mkdir()
        subprocess.run(['go', 'test', './internal/mobilemultihop', '-run', '^TestImportedXHTTPIndependentLayers$',
                        '-count=1', '-timeout=30s'], cwd=ROOT, check=True, timeout=45,
                       env=dict(os.environ, ROUTERVPN_IMPORTED_XHTTP_XRAY_FIXTURES=str(xhttp_sources)))
        xhttp_source = xhttp_sources / 'socks5--reality-xhttp--off--off.json'
        original_xhttp = xhttp_source.read_bytes()
        xhttp = subprocess.run([str(work/'test'), str(compiler), 'xhttp-reality', str(xhttp_source)],
                               env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
        if xhttp.stdout != 'PASS XHTTP picker 24 checks\n' or xhttp_source.read_bytes() != original_xhttp:
            raise ValueError('Missing, foreign, or source-mutating XHTTP picker verdict: '+repr(xhttp.stdout))
        print(xhttp.stdout, end='', flush=True)
        naive_sources = export_naive_h2_sources(work)
        naive_source = naive_sources / 'http-connect--naive-h2--off--off.json'
        original_naive = naive_source.read_bytes()
        naive = subprocess.run([str(work/'test'), str(compiler), 'naive-h2', str(naive_source)],
                               env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
        if naive.stdout != 'PASS Naive H2 picker 122 checks\n' or naive_source.read_bytes() != original_naive:
            raise ValueError('Missing, foreign, or source-mutating Naive H2 picker verdict: '+repr(naive.stdout))
        print(naive.stdout, end='', flush=True)
        verify_naive_h2_literal(work, compiler, runtime_env, naive_sources)
        naive_h3_sources = work / 'naive-h3-sources'
        naive_h3_sources.mkdir()
        subprocess.run(['go', 'test', './internal/mobilemultihop', '-run', '^TestImportedNaiveH3IndependentLayers$',
                        '-count=1', '-timeout=30s'], cwd=ROOT, check=True, timeout=45,
                       env=dict(os.environ, ROUTERVPN_IMPORTED_NAIVE_H3_FIXTURES=str(naive_h3_sources)))
        naive_h3_source = naive_h3_sources / 'socks5--naive-h3--off--off.json'
        original_naive_h3 = naive_h3_source.read_bytes()
        naive_h3 = subprocess.run([str(work/'test'), str(compiler), 'naive-h3', str(naive_h3_source)],
                               env=dict(runtime_env,ROUTERVPN_IOS_IMPORTED_NAIVE_H2_SOURCES=str(naive_sources)), check=True, timeout=30, text=True, stdout=subprocess.PIPE)
        if naive_h3.stdout != 'PASS Naive H3 picker 150 checks\n' or naive_h3_source.read_bytes() != original_naive_h3:
            raise ValueError('Missing, foreign, or source-mutating Naive H3 picker verdict: '+repr(naive_h3.stdout))
        print(naive_h3.stdout, end='', flush=True)

        for kind in ('shadowsocks', 'hysteria2'):
            proxy = subprocess.run([str(work / 'test'), str(compiler), 'proxy-reality', kind], env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
            if proxy.stdout != f'PASS {kind} REALITY host 115 checks\n':
                raise ValueError('Missing or foreign encrypted REALITY Swift verdict: '+repr(proxy.stdout))
            print(proxy.stdout, end='', flush=True)
        for kind in ('http-connect', 'https-connect'):
            connect = subprocess.run([str(work / 'test'), str(compiler), 'connect-reality', kind], env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
            if connect.stdout != f'PASS {kind} REALITY host 115 checks\n':
                raise ValueError('Missing or foreign CONNECT REALITY Swift verdict: '+repr(connect.stdout))
            print(connect.stdout, end='', flush=True)
        packet_sources = work / 'packet-reality-sources'
        packet_sources.mkdir()
        kinds = ('wireguard', 'amneziawg', 'openvpn-tcp', 'openvpn-udp')
        subprocess.run(['go', 'test', './internal/mobilemultihop', '-run',
                        '^TestImportedPacketRealityVisionIndependentLayers$',
                        '-count=1', '-timeout=30s'], cwd=ROOT, check=True, timeout=45,
                       env=dict(os.environ, ROUTERVPN_IMPORTED_PACKET_XRAY_FIXTURES=str(packet_sources)))
        layers = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
        expected = {kind+'--reality-vision--'+first+'--'+last+'.json' for kind in kinds for first in layers for last in layers}
        if {path.name for path in packet_sources.iterdir()} != expected:
            raise ValueError('Packet REALITY picker requires thirty-six exact original source captures')
        originals = {}
        for name in expected:
            path = packet_sources / name
            if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 1 << 20:
                raise ValueError('Packet REALITY picker source is not a bounded original file')
            originals[name] = path.read_bytes()
        for kind in kinds:
            packet = subprocess.run([str(work/'test'), str(compiler), 'packet-reality', kind, str(packet_sources)],
                                    env=runtime_env, check=True, timeout=30, text=True, stdout=subprocess.PIPE)
            if packet.stdout != f'PASS packet REALITY picker {kind} 186 checks\n':
                raise ValueError('Missing or foreign packet REALITY Swift verdict: '+repr(packet.stdout))
            print(packet.stdout, end='', flush=True)
        if any((packet_sources/name).read_bytes() != value for name,value in originals.items()):
            raise ValueError('Packet REALITY picker changed its original source captures')
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--only-naive-h2-literal', action='store_true', help='Run only the compiler-linked literal H2 layer matrix')
    parser.add_argument("--only-naive-h2-dns", action="store_true", help="Run the compiler-linked selected DNS and original authority cases")
    args = parser.parse_args()
    main(args.only_naive_h2_literal, args.only_naive_h2_dns)
