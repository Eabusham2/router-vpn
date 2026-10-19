#!/usr/bin/env python3
"""Execute Apple Tor creation and complete provider assembly with real Go policy.

The shipping models, external-node creation method, Tor exit builder, WG parser,
device policies and provider's complete pre-start assembly run unchanged. Only
platform data types, storage and gomobile call boundaries are doubled. The Go
compilers execute for every request; these tests do not start a VPN or claim an
Apple SDK build, signed-device traffic, or public Tor circuit verification.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
TUN = ROOT / 'ios/RouterVPN/PacketTunnel'


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load('tor_pq_compiler_fixture', 'deploy/test_ios_pq_selection.py')
W = load('tor_wg_adapter_types', 'deploy/test_ios_wireguard_parser.py')
A = load('tor_native_xray_fixture', 'android/test_android_multihop_graph.py')


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError('Shipping fixture boundary changed: ' + before[:100])
    return source.replace(before, after, 1)


GO = replace_once(P.GO, '"router-vpn/internal/mobileperf"',
    '"router-vpn/internal/mobileperf";"router-vpn/internal/mobiletor";'
    '"router-vpn/internal/applexray";"router-vpn/internal/nativesip003";'
    '"crypto/ecdh";"crypto/mlkem"')
xray_fixture = A.GO_HELPER[A.GO_HELPER.index(' case "test-xray":'):A.GO_HELPER.index(' case "xray-check",')]
GO = replace_once(GO, ' case "compile":value,err=mobilemultihop.CompilePQProfile(r.Mode,r.Files,r.Node)', r'''
 case "tor":value,err=mobiletor.CompileProfile(r.Config,r.Node,r.Source)
 case "predecessor":_,err=mobiletor.NewPredecessorProof(r.Config);value="checked"
 case "hash":sum:=sha256.Sum256([]byte(r.Config));value=base64.StdEncoding.EncodeToString(sum[:])
 case "max":value,err=mobilemultihop.CompileMAXProfile(r.Mode,r.Files,r.Policy)
 case "composite":value,err=mobilemultihop.CompileCompositeProfile(r.Mode,r.Files,r.Policy,r.Source)
 case "composite-base":value,err=mobilemultihop.CompositeMultihopBase(r.Config,r.Mode,r.Node,r.Source)
 case "proxy-entry":value,err=mobilemultihop.CompileProxyEntry(r.Files,r.Mode)
 case "awg":value,err=mobilemultihop.CompileAmneziaProfile(r.Config,r.Node)
 case "xray":var data []byte;data,err=applexray.Compile(r.Mode,[]byte(r.Config),[]byte(r.Files));value=string(data)
 case "xray-start":var data []byte;data,err=applexray.ComposeStartLayer(r.Mode,[]byte(r.Config),[]byte(r.Files),[]byte(r.Source),[]byte(r.Policy));value=string(data)
 case "xray-policy":value,err=mobilemultihop.ApplyNativeXrayDevicePolicy(r.Config,r.Policy)
 case "sip":var data []byte;data,err=nativesip003.Compile([]byte(r.Config),[]byte(r.Files));value=string(data)
 case "sip-start":var data []byte;data,err=nativesip003.ComposeStartLayer([]byte(r.Config),[]byte(r.Files),[]byte(r.Source),[]byte(r.Policy));value=string(data)
''' + xray_fixture + ' case "compile":value,err=mobilemultihop.CompilePQProfile(r.Mode,r.Files,r.Node)')

# A real Swift module makes canImport(Libbox) select every shipping native
# compiler branch. The serialized subprocess implements only the FFI boundary.
LIBBOX = P.SWIFT[:P.SWIFT.index('func compile(_ mode:')]
LIBBOX = replace_once(LIBBOX, 'func bridge(_ request:', 'public func RouterVPNTorTestCall(_ request:')
LIBBOX += r'''
public func RouterVPNTorTestClose() { TestCompiler.shared.close() }
private func result(_ error:inout NSError?,_ request:[String:String])->String {
 do { return try RouterVPNTorTestCall(request) }
 catch let failure { error=failure as NSError; return "" }
}
public func LibboxVersion()->String { "1.14.1" }
public func LibboxRouterCompileTorProfile(_ profile:String,_ session:String,_ predecessor:String,_ error:inout NSError?)->String {
 result(&error,["Op":"tor","Config":profile,"Node":session,"Source":predecessor])
}
public func LibboxRouterCompileMAXProfile(_ mode:String,_ files:String,_ policy:String,_ error:inout NSError?)->String {
 result(&error,["Op":"max","Mode":mode,"Files":files,"Policy":policy])
}
public func LibboxRouterCompileCompositeProfile(_ mode:String,_ files:String,_ policy:String,_ source:String,_ error:inout NSError?)->String {
 result(&error,["Op":"composite","Mode":mode,"Files":files,"Policy":policy,"Source":source])
}
public func LibboxRouterCompositeMultihopBase(_ config:String,_ mode:String,_ node:String,_ layer:String,_ error:inout NSError?)->String {
 result(&error,["Op":"composite-base","Config":config,"Mode":mode,"Node":node,"Source":layer])
}
public func LibboxRouterCompilePQProfile(_ mode:String,_ files:String,_ node:String,_ error:inout NSError?)->String {
 result(&error,["Op":"compile","Mode":mode,"Files":files,"Node":node])
}
public func LibboxRouterCompileAmneziaProfile(_ config:String,_ node:String,_ error:inout NSError?)->String {
 result(&error,["Op":"awg","Config":config,"Node":node])
}
public func LibboxRouterCompileProxyEntry(_ files:String,_ mode:String,_ error:inout NSError?)->String {
 result(&error,["Op":"proxy-entry","Files":files,"Mode":mode])
}
public func LibboxRouterCompileXrayProfile(_ mode:String,_ wrapper:String,_ raw:String,_ error:inout NSError?)->String {
 result(&error,["Op":"xray","Mode":mode,"Config":wrapper,"Files":raw])
}
public func LibboxRouterCompileSIP003Profile(_ wrapper:String,_ raw:String,_ error:inout NSError?)->String {
 result(&error,["Op":"sip","Config":wrapper,"Files":raw])
}
public func LibboxRouterComposeXrayStartLayer(_ mode:String,_ wrapper:String,_ raw:String,_ source:String,_ policy:String,_ error:inout NSError?)->String {
 result(&error,["Op":"xray-start","Mode":mode,"Config":wrapper,"Files":raw,"Source":source,"Policy":policy])
}
public func LibboxRouterComposeSIP003StartLayer(_ wrapper:String,_ raw:String,_ source:String,_ policy:String,_ error:inout NSError?)->String {
 result(&error,["Op":"sip-start","Config":wrapper,"Files":raw,"Source":source,"Policy":policy])
}
public func LibboxRouterComposeNativeBaseStartLayer(_ config:String,_ source:String,_ policy:String,_ error:inout NSError?)->String {
 result(&error,["Op":"start","Config":config,"Source":source,"Policy":policy])
}
public func LibboxRouterApplyNativeXrayDevicePolicy(_ config:String,_ policy:String,_ error:inout NSError?)->String {
 result(&error,["Op":"xray-policy","Config":config,"Policy":policy])
}
public func LibboxRouterApplyMultihopLANPolicy(_ config:String,_ policy:String,_ error:inout NSError?)->String {
 result(&error,["Op":"lan","Config":config,"Policy":policy])
}
public func LibboxRouterApplyPerformancePolicy(_ config:String,_ policy:String,_ error:inout NSError?)->String {
 result(&error,["Op":"performance","Config":config,"Policy":policy])
}
public func LibboxRouterOpenVPNEndpoint(_ config:String,_ user:String,_ password:String,_ tag:String,_ detour:String,_ error:inout NSError?)->String {
 error=NSError(domain:"UnexercisedOpenVPNBoundary",code:1);return ""
}
'''

NETWORK = r'''
import Foundation
import Glibc
public struct IPv4Address {
 public let rawValue:Data
 public init?(_ raw:String) {
  var value=in_addr();guard inet_pton(AF_INET,raw,&value)==1 else{return nil}
  rawValue=withUnsafeBytes(of:value){Data($0)}
 }
}
public struct IPv6Address {
 public let rawValue:Data
 public init?(_ raw:String) {
  var value=in6_addr();guard inet_pton(AF_INET6,raw,&value)==1 else{return nil}
  rawValue=withUnsafeBytes(of:value){Data($0)}
 }
}
'''


def provider_source():
    source = (TUN / 'PacketTunnelProvider.swift').read_text()
    def method(name):
        begin = source.index('    private func ' + name + '(')
        following = re.search(r'(?m)^    private (?:func|struct) ', source[begin + 1:])
        if following is None:
            raise ValueError('Unbounded production method: ' + name)
        return source[begin:begin + 1 + following.start()]
    external = method('startExternalLibbox')
    boundary = '        let engine = RouterVPNLibboxEngine(tunnel: self); libboxEngine = engine'
    if external.count(boundary) != 1:
        raise ValueError('Tor engine boundary changed')
    external = external[:external.index(boundary)]
    external = replace_once(external, 'private func startExternalLibbox(', 'func prepare(')
    external = replace_once(external, ', completionHandler: @escaping (Error?) -> Void) throws {', ') throws -> Prepared {')
    external += '        return Prepared(runtime: runtime, strict: effectiveStrict, predecessor: entryFiles, profile: entryProfile)\n    }\n'
    compilation = source[source.index('    private struct LibboxCompilation {'):source.index('    private func compileLibbox(')]
    domain = re.search(r'(?m)^    private static let nodeProofDomain = .+$', source)
    if domain is None:
        raise ValueError('The production node identity domain is missing')
    support = r'''
@MainActor final class NETunnelProviderProtocol {
 var includeAllNetworks=true,enforceRoutes=true,excludeLocalNetworks=false
}
@MainActor final class ProviderPreparation {
 static let maxProfileBytes=4*1024*1024,maxBundleBytes=32*1024*1024,maxLayeredBytes=12*1024*1024
 // SHIPPING_NODE_PROOF_DOMAIN
 var protocolConfiguration:Any?=NETunnelProviderProtocol()
 struct Prepared {let runtime:RouterVPNExternalExitRuntime;let strict:Bool;let predecessor:[String:Data];let profile:[String:Any]?}
 func tunnelError(_ code:Int,_ message:String)->NSError {NSError(domain:"ShippingTorAssembly",code:code,userInfo:[NSLocalizedDescriptionKey:message])}
 func entry(_ root:[String:Any],_ mode:String)throws->[String:Data] {
  try compileLibbox(provider:["rawProfileID":mode],root:root,selectedProfile:selectedRouterProfile(root)).files
 }
'''
    support = replace_once(support, ' // SHIPPING_NODE_PROOF_DOMAIN', domain.group(0).replace('private static', 'static', 1))
    return support + compilation + ''.join(method(name) for name in (
        'compileLibbox', 'performanceFiles', 'multihopWireGuardEndpoint',
        'nativeAmneziaEndpoint', 'selectedRouterProfile', 'wireGuardLikeProfile',
        'layeredProfile', 'strictKillSwitchRequested', 'suppliedNodeProof',
        'deriveNodeProof', 'selectedProofURL', 'privateLiteralHost')) + external + '}\n'


SWIFT = r'''
import Foundation
import Network
import Libbox
import WireGuardKit
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif
func json(_ value:Any)throws->Data {try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])}
func text(_ value:Any)throws->String {String(decoding:try json(value),as:UTF8.self)}
func object(_ data:Data)throws->[String:Any] {try JSONSerialization.jsonObject(with:data) as! [String:Any]}
func key(_ b:UInt8)->String {Data(repeating:b,count:32).base64EncodedString()}
func bridge(_ request:[String:String])throws->String {try RouterVPNTorTestCall(request)}
// CryptoKit's hash boundary runs the real SHA-256 algorithm in Go. The shipping
// domain, key selection, and exact node-proof comparisons are unchanged.
enum SHA256 {static func hash(data:Data)->[UInt8] {
 let encoded=try! bridge(["Op":"hash","Config":String(decoding:data,as:UTF8.self)])
 return [UInt8](Data(base64Encoded:encoded)!)
}}
@MainActor final class RouterVPNModel {
 var profileMutationBlocked=false,message=""
 var saved:Data?,writes=0
 func linkNodeBundle(_ data:Data)throws {_ = try JSONDecoder().decode(ClientBundle.self,from:data);saved=data;writes+=1}
}
@main struct Tests {
 @MainActor static var checks=0,graphs=0,policyCases=0,sessions=Set<String>()
 static let modes=["wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg","ss-v2ray","split","max","naive-h2","naive-h3"]
 static let kinds=["tor","obfs4","meek_lite","snowflake","webtunnel","custom"]
 static let layers=["off","aes-256-gcm","aes-256-gcm+xor-whitening"]
 static let obfs="obfs4 198.51.100.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=Y2VydA iat-mode=0"
 static let meek="meek_lite 192.0.2.2:2 url=https://bridge.example.test/ front=front.example.test"
 static let snow="snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://broker.example.test/ front=cdn.example.test ice=stun:stun.example.test:3478 utls-imitate=hellorandomizedalpn"
 static let web="webtunnel 10.0.0.2:443 89ABCDEF0123456789ABCDEF0123456789ABCDEF url=https://webtunnel.example.test/private ver=0.0.1"
 @MainActor static func check(_ label:String,_ condition:@autoclosure ()throws->Bool)throws {
  guard try condition() else{throw NSError(domain:"TorProfileCheck",code:1,userInfo:[NSLocalizedDescriptionKey:label])};checks+=1
 }
 @MainActor static func reject(_ label:String,_ action:()throws->Void) {
  do{try action();fatalError("ACCEPTED "+label)}catch{checks+=1}
 }
 static func lines(_ kind:String)->[String] {
  switch kind{case "tor":return [];case "obfs4":return [obfs];case "meek_lite":return [meek];case "snowflake":return [snow];case "webtunnel":return [web];default:return [obfs,meek,snow,web]}
 }
 @MainActor static func create(_ model:RouterVPNModel,_ kind:String,_ supplied:[String]?=nil)throws {
  try model.createIOSExternalNode(protocolName:kind=="tor" ? "tor":"tor-bridge",name:" Tor \(kind) ",server:"must-not-resolve.example.test",port:0,expectedPublicIP:"",username:"",password:"",method:"",secret:"",tlsServerName:"",wgPrivateKey:"",wgPeerPublicKey:"",wgPresharedKey:"",wgAddresses:[],wgAllowedIPs:[],wgDNS:[],wgMTU:nil,torTransport:kind=="tor" ? "custom":kind,torBridges:supplied ?? lines(kind))
 }
 @MainActor static func tor(_ kind:String)throws->[String:Any] {
  let model=RouterVPNModel();try create(model,kind)
  let root=try object(model.saved!),bundle=try JSONDecoder().decode(ClientBundle.self,from:model.saved!)
  var profile=(root["routerProfiles"] as! [[String:Any]])[0]
  let external=profile["external"] as! [String:Any]
  try check("creation saves one selected owned profile",model.writes==1 && bundle.routerProfiles.count==1 && bundle.selectedRouterID==profile["id"] as? String)
  try check("ordinary Tor has zero bridge block",kind != "tor" || external["tor_bridge"]==nil)
  try check("Tor never stores a static exit or raw endpoint",profile["endpoint"] as? String=="tor" && external["expected_public_ip"] as? String=="")
  try check("Tor model preserves bridge input order",kind=="tor" || bundle.routerProfiles[0].external?.torBridge?.bridges==lines(kind))
  profile["mtu_policy"]="fixed";profile["manual_mtu"]=1380;profile["ipv6_mode"]="off";profile["home_lan_access"]=false
  profile["home_lan_cidrs"]=["192.168.50.0/24","fd12:3456::/48"]
  profile["start_layer"]="off";profile["kill_switch_policy"]="strict"
  let dns=kinds.firstIndex(of:kind)! % 3
  profile["dns_mode"]=dns==0 ? "custom":dns==1 ? "dot":"doh"
  profile["dns_protocol"]=dns==0 ? "tcp":dns==1 ? "tls":"https"
  profile["dns_host"]="149.112.112.112";profile["dns_port"]=dns==0 ? 5353:dns==1 ? 8853:8443
  profile["dns_server_name"]="tor-dns.example.test";profile["dns_path"]="/captured-query"
  return profile
 }
 static func tagged(_ graph:[String:Any],_ tag:String)throws->[String:Any] {
  let all=(graph["endpoints"] as? [[String:Any]] ?? [])+(graph["outbounds"] as? [[String:Any]] ?? [])
  let matches=all.filter{$0["tag"] as? String==tag}
  guard matches.count==1 else{throw NSError(domain:"MissingOrAmbiguousGraphOwner",code:1,userInfo:[NSLocalizedDescriptionKey:tag])};return matches[0]
 }
 static func root(_ mode:String,_ layer:String,_ maximum:[String:Any],_ composite:[String:Any])throws->[String:Any] {
  var assets:[String:[String:String]],node:String,host="192.0.2.1",api="http://10.77.0.1:8787"
  if IOSNativeMAXProfile.modeIDs.contains(mode) {
   let f=(maximum["entry"] as! [String:Any])[mode] as! [String:Any],p=f["policy"] as! [String:String]
   assets=[mode:f["files"] as! [String:String]];node=p["node_id"]!;host=p["endpoint"]!;api=p["router_api"]!
  }else if IOSNativeCompositeMultihop.modeIDs.contains(mode) {
   assets=composite["profiles"] as! [String:[String:String]];node=composite["nodeProofId"] as! String
   let p=(composite["routerProfiles"] as! [[String:Any]])[0];host=p["endpoint"] as! String;api=p["router_api"] as! String
  }else {
   let fixture=try object(Data(bridge(["Op":"fixture","Mode":mode=="wg" || mode=="wg-pq" ? "wg-pq":"awg2-pq"]).utf8))
   node=fixture["node"] as! String;assets=[:]
   if ["wg","awg2-fast","awg2-strong"].contains(mode) {
    let f=fixture["files"] as! [String:String],name=mode=="wg" ? "wg.conf":"awg.conf"
    var raw=String(decoding:Data(base64Encoded:f[name]!)!,as:UTF8.self)
    if mode=="awg2-strong"{raw=raw.replacingOccurrences(of:"Jc=3",with:"Jc=8")}
    assets[mode]=[name:Data(raw.utf8).base64EncodedString()]
   }else if IOSNativePQProfile.modeIDs.contains(mode) {assets[mode]=fixture["files"] as? [String:String]}
   var proxy:[String:Any]=["type":"shadowsocks","tag":"proxy","server":host,"server_port":8388,"method":"2022-blake3-aes-256-gcm","password":key(115)]
   let dns:[String:Any]=["servers":[["type":"https","tag":"selected-dns","server":"9.9.9.9","server_port":443,"detour":"proxy","path":"/entry-query","tls":["enabled":true,"server_name":"entry-dns.example.test"]]],"final":"selected-dns"]
   var graph:[String:Any]=["inbounds":[["type":"tun","tag":"tun-in","address":["172.29.94.1/30","fd29:94::1/126"],"mtu":1380,"stack":"system","auto_route":true,"strict_route":true]],"outbounds":[proxy],"dns":dns,"route":["auto_detect_interface":true,"final":"proxy","rules":[["protocol":"dns","action":"hijack-dns"]]]]
   assets["shadowsocks"]=["sing-box.json":try json(graph).base64EncodedString()]
   if mode=="hysteria2" || mode.hasPrefix("naive-") {
    let captured=(composite["profiles"] as! [String:[String:String]])["split"]!
    proxy=["type":mode=="hysteria2" ? "hysteria2":"naive","tag":"proxy","server":host,"server_port":8443,"password":"entry-only-secret","tls":["enabled":true,"server_name":"entry.example.test","certificate_path":"trust.pem"]]
    if mode.hasPrefix("naive-"){proxy["username"]="entry-only-user";proxy["quic"]=mode=="naive-h3";proxy["udp_over_tcp"]=["enabled":true,"version":2]}
    graph["outbounds"]=[proxy];assets[mode]=["sing-box.json":try json(graph).base64EncodedString(),"trust.pem":captured["cert.pem"]!]
   }else if mode.hasPrefix("reality-") {
    graph["outbounds"]=[["type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1090,"version":"5"]]
    let raw=try bridge(["Op":"test-xray","Config":mode,"Policy":host])
    assets[mode]=["sing-box.json":try json(graph).base64EncodedString(),"xray.json":Data(raw.utf8).base64EncodedString()]
   }
  }
  let profile:[String:Any]=["schema_version":4,"id":"entry","name":"Captured entry","node_kind":"router-vpn","node_proof_id":node,"endpoint":host,"router_api":api,"api_token":"entry-private-token","adguard_ipv4":"192.168.50.133","adguard_ipv6":"fd77:77::1","socks_host":"10.77.0.1","socks_port":1080,"socks_username":"","socks_password":"","dns_mode":"doh","dns_host":"9.9.9.9","dns_port":443,"dns_server_name":"entry-dns.example.test","dns_path":"/entry-query","home_lan_access":false,"ipv6_mode":"off","kill_switch_policy":"strict","mtu_policy":"fixed","manual_mtu":1380,"daita_enabled":true,"start_layer":layer,"base_tunnel":"wg","base_fallback":false]
  return ["bundleVersion":4,"profileSchemaVersion":4,"nodeProofId":node,"selectedRouterID":"entry","routerProfiles":[profile],"profiles":assets]
 }
 @MainActor static func verify(_ kind:String,_ mode:String,_ layer:String,_ maximum:[String:Any],_ composite:[String:Any])throws {
  var selected=try tor(kind),provider:[String:Any]=[:],baseline:[String:Data]=[:],entry:[String:Any]?
  let owner=ProviderPreparation()
  if mode != "direct" {
   entry=try root(mode,layer,maximum,composite);baseline=try owner.entry(entry!,mode)
   selected["multihop_enabled"]=true;selected["multihop_entry_id"]="entry";selected["multihop_entry_mode"]=mode
   selected["multihop_exit_id"]=selected["id"];selected["multihop_exit_mode"]=kind=="tor" ? "tor":"tor-bridge";selected["multihop_execution"]="local"
   provider=["tor_entry_bundle":try json(entry!),"tor_entry_mode":mode]
  }
  let before=try json(selected),oldEntry=try entry.map{try json($0)}
  let prepared=try owner.prepare(provider:provider,selectedProfile:selected,strict:true),runtime=prepared.runtime
  let graph=try object(runtime.files["sing-box.json"]!),out=try tagged(graph,"routervpn-tor-exit"),sid=runtime.torSessionID!
  try check("fresh session identity",sessions.insert(sid).inserted && out["session_id"] as? String==sid)
  try check("one TUN and one Tor",(graph["inbounds"] as! [[String:Any]]).count==1 && (graph["outbounds"] as! [[String:Any]]).filter{$0["type"] as? String=="routervpn-tor"}.count==1)
  try check("Tor keeps dynamic exit semantics",runtime.expectedPublicIP.isEmpty && (graph["route"] as! [String:Any])["final"] as? String=="routervpn-tor-exit")
  try check("Tor keeps bridge order and plain emptiness",out["bridges"] as? [String]==lines(kind))
  try check("private proof credentials stay outside Tor outbound",!text(out).contains("entry-private-token") && out["node_proof_id"]==nil && out["router_api"]==nil)
  try check("strict selected route policy",prepared.strict && (graph["inbounds"] as! [[String:Any]])[0]["mtu"] as? Int==1380)
  let dns=graph["dns"] as! [String:Any],servers=dns["servers"] as! [[String:Any]]
  let exitDNS=servers.first{$0["tag"] as? String=="routervpn-tor-dns"}!,bootstrap=servers.first{$0["tag"] as? String=="routervpn-tor-bootstrap"}!
  try check("Tor DNS keeps exact selected transport",exitDNS["type"] as? String==selected["dns_protocol"] as? String && exitDNS["server"] as? String=="149.112.112.112" && exitDNS["server_port"] as? Int==selected["dns_port"] as? Int)
  try check("application DNS traverses Tor",exitDNS["detour"] as? String=="routervpn-tor-exit" && dns["final"] as? String=="routervpn-tor-dns" && dns["independent_cache"] as? Bool==true && dns["rules"]==nil)
  if mode=="direct" {
   try check("direct Tor has no borrowed entry",out["detour"]==nil && bootstrap["detour"]==nil && runtime.torPredecessorProfile==nil)
  }else {
   let previous=try object(baseline["sing-box.json"]!),previousRoute=previous["route"] as! [String:Any],route=graph["route"] as! [String:Any]
   try check("Tor traverses exact complete predecessor",out["detour"] as? String==previousRoute["final"] as? String && bootstrap["detour"] as? String==previousRoute["final"] as? String)
   try check("predecessor bootstrap remains unchanged",text(["value":previousRoute["default_domain_resolver"] ?? NSNull()])==text(["value":route["default_domain_resolver"] ?? NSNull()]))
   for family in ["endpoints","outbounds"] {for row in previous[family] as? [[String:Any]] ?? [] {
    var actual=try tagged(graph,row["tag"] as! String)
    if row["type"] as? String=="naive" {
     let previousDNS=previous["dns"] as! [String:Any],originalServers=previousDNS["servers"] as! [[String:Any]]
     let tag="routervpn-tor-naive-bootstrap-0",query=actual["domain_resolver"] as? [String:Any]
     var expectedQuery:[String:Any]=["server":tag]
     expectedQuery["strategy"]=row["domain_strategy"] ?? previousDNS["strategy"]
     try check("Naive captures its entry DNS query policy",row["domain_resolver"]==nil && query != nil && text(query!)==text(expectedQuery))
     let original=originalServers.first{$0["tag"] as? String==previousDNS["final"] as? String}!
     var expectedBootstrap=original;expectedBootstrap["tag"]=tag;expectedBootstrap["detour"]=row["detour"]
     let captured=servers.filter{$0["tag"] as? String==tag}
     try check("Naive bootstrap keeps exact entry resolver and lower owner",captured.count==1 && text(captured[0])==text(expectedBootstrap))
     let retained=servers.filter{$0["tag"] as? String==original["tag"] as? String}
     try check("Naive bootstrap preserves entry application DNS",retained.count==1 && text(retained[0])==text(original))
     actual.removeValue(forKey:"domain_resolver")
    }
    try check("complete predecessor keys and lanes preserved",json(row)==json(actual))
   }}
   try check("performance owner remains captured",json(previous["services"] ?? [])==json(graph["services"] ?? []))
   for (name,data) in baseline where name != "sing-box.json" {try check("captured auxiliary bytes preserved",runtime.files[name]==data)}
   let native=try tagged(graph,"proxy"),type=native["type"] as! String
   let expected=mode=="wg" ? "wireguard":mode.hasPrefix("awg2-") && mode != "awg2-pq" ? "routervpn-amneziawg":IOSNativePQProfile.modeIDs.contains(mode) || IOSNativeMAXProfile.modeIDs.contains(mode) ? "routervpn-pq":IOSNativeCompositeMultihop.modeIDs.contains(mode) ? "routervpn-composite":mode.hasPrefix("reality-") ? "routervpn-xray":mode.hasPrefix("naive-") ? "naive":mode=="shadowsocks" && layer=="aes-256-gcm+xor-whitening" ? "routervpn-aes-xor":mode
   try check("exact entry family preserved for "+mode,type==expected)
   if type=="routervpn-composite" {
    try check("both composite lanes retained",native["mode"] as? String==mode && tagged(graph,native["tcp"] as! String)["type"] as? String==(mode=="ss-v2ray" ? "shadowsocks":"routervpn-xray") && tagged(graph,native["udp"] as! String)["type"] as? String=="hysteria2")
   }
   if IOSNativeMAXProfile.modeIDs.contains(mode) {
    try check("MAX mandatory chain retained",native["detour"] as? String=="routervpn-max-ss" && tagged(graph,"routervpn-max-ss")["detour"] as? String=="routervpn-max-outer")
   }
   if mode.hasPrefix("naive-"){try check("Naive keeps exact HTTP and packet lane",native["quic"] as? Bool==(mode=="naive-h3") && native["username"] as? String=="entry-only-user" && (native["udp_over_tcp"] as? [String:Any])?["enabled"] as? Bool==true)}
   let proof=try object(Data(runtime.torPredecessorProfile!.utf8))
   try check("private entry proof is separate and exact",proof["id"] as? String=="entry" && proof["node_proof_id"] as? String==entry!["nodeProofId"] as? String && proof["api_token"] as? String=="entry-private-token")
   try check("private proof helper accepts captured origin",bridge(["Op":"predecessor","Config":runtime.torPredecessorProfile!])=="checked")
  }
  try check("source profiles remain immutable",json(selected)==before && entry.map{try! json($0)}==oldEntry)
  if let output=ProcessInfo.processInfo.environment["ROUTERVPN_IOS_TOR_GRAPHS"] {
   let directory=URL(fileURLWithPath:output).appendingPathComponent([mode,layer,kind].joined(separator:"-"))
   try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:false)
   for (name,data) in runtime.files {try data.write(to:directory.appendingPathComponent(name))}
   try json(["mode":mode,"layer":layer,"transport":kind,"session":sid]).write(to:directory.appendingPathComponent("fixture.json"))
  }
  graphs+=1
 }
 @MainActor static func policies(_ maximum:[String:Any],_ composite:[String:Any])throws {
  var failures:[String]=[]
  for mode in ["wg","hysteria2","naive-h3","split","max-tls-wg"] {
   for entryStrict in [false,true] {for exitStrict in [false,true] {
    for entryLAN in [false,true] {for exitLAN in [false,true] {
     for entryIPv6 in [false,true] {for exitIPv6 in [false,true] {
      let label="\(mode)/strict=\(entryStrict),\(exitStrict)/LAN=\(entryLAN),\(exitLAN)/IPv6=\(entryIPv6),\(exitIPv6)"
      do {
       var source=try root(mode,"aes-256-gcm",maximum,composite),entry=(source["routerProfiles"] as! [[String:Any]])[0]
       entry["kill_switch_policy"]=entryStrict ? "strict":"off";entry["home_lan_access"]=entryLAN;entry["home_lan_cidrs"]=["192.168.51.0/24"];entry["ipv6_mode"]=entryIPv6 ? "on":"off";source["routerProfiles"]=[entry]
       var selected=try tor("obfs4")
       selected["kill_switch_policy"]=exitStrict ? "strict":"off";selected["home_lan_access"]=exitLAN;selected["home_lan_cidrs"]=["192.168.50.0/24"];selected["ipv6_mode"]=exitIPv6 ? "on":"off"
       selected["multihop_enabled"]=true;selected["multihop_entry_id"]="entry";selected["multihop_entry_mode"]=mode;selected["multihop_exit_id"]=selected["id"];selected["multihop_exit_mode"]="tor-bridge";selected["multihop_execution"]="local"
       let provider:[String:Any]=["tor_entry_bundle":try json(source),"tor_entry_mode":mode]
       let owner=ProviderPreparation(),flags=owner.protocolConfiguration as! NETunnelProviderProtocol
       flags.includeAllNetworks=entryStrict || exitStrict;flags.enforceRoutes=entryStrict || exitStrict;flags.excludeLocalNetworks=entryLAN && exitLAN
       let prepared=try owner.prepare(provider:provider,selectedProfile:selected,strict:exitStrict)
       let graph=try object(prepared.runtime.files["sing-box.json"]!),rules=(graph["route"] as! [String:Any])["rules"] as! [[String:Any]]
       try check("strict policy belongs to both captured profiles",prepared.strict==(entryStrict || exitStrict))
       let rejected=rules.filter{$0["action"] as? String=="reject"}
       let prefixes=Set(rejected.flatMap{$0["ip_cidr"] as? [String] ?? []})
       try check("entry LAN policy is retained",prefixes.contains("192.168.51.0/24")==(!entryLAN))
       try check("Tor LAN policy is retained",prefixes.contains("192.168.50.0/24")==(!exitLAN))
       let ipv6Blocked=rejected.contains{$0["ip_version"] as? Int==6 || ($0["ip_cidr"] as? [String] ?? []).contains("::/0")}
       try check("neither captured IPv6 restriction is discarded",ipv6Blocked==(!entryIPv6 || !exitIPv6))
       let frozen=try object(Data(prepared.runtime.torPredecessorProfile!.utf8))
       try check("proof retains independent entry preferences",json(frozen)==json(entry))
       policyCases+=1
      }catch {failures.append(label+": "+error.localizedDescription)}
     }}
    }}
   }}
  }
  if !failures.isEmpty {throw NSError(domain:"TorPolicyPairs",code:1,userInfo:[NSLocalizedDescriptionKey:failures.joined(separator:"\n")])}
  try check("complete independent profile-policy combinations",policyCases==320)
 }
 @MainActor static func negatives(_ maximum:[String:Any],_ composite:[String:Any])throws {
  let model=RouterVPNModel();try create(model,"tor");let saved=model.saved,writes=model.writes
  model.profileMutationBlocked=true;reject("active profile mutation"){try create(model,"obfs4")};model.profileMutationBlocked=false
  reject("plain Tor cannot discard bridges"){try create(model,"tor",[obfs])}
  reject("bridge selection needs lines"){try create(model,"obfs4",[])}
  reject("unknown bridge transport"){try create(model,"exec",[obfs])}
  reject("bridge control injection"){try create(model,"obfs4",[obfs+"\nSocksPort 0.0.0.0:9050"])}
  try check("failed creation cannot alter saved source",model.saved==saved && model.writes==writes)
  let basic=try tor("obfs4")
  for (key,value) in [("dns_mode","home"),("dns_mode","fastest"),("dns_mode","doh3"),("dns_protocol","udp"),("dns_host","resolver.example.test"),("dns_host","192.168.50.133"),("start_layer","aes-256-gcm")] {
   var bad=basic;bad[key]=value;if key=="dns_protocol"{bad["dns_mode"]="custom"}
   reject("invalid direct Tor "+key+"="+value){_ = try ProviderPreparation().prepare(provider:[:],selectedProfile:bad,strict:true)}
  }
  for mode in modes {
   let entry=try root(mode,"off",maximum,composite)
   var selected=basic;selected["multihop_enabled"]=true;selected["multihop_entry_id"]="entry";selected["multihop_entry_mode"]=mode;selected["multihop_exit_id"]=selected["id"];selected["multihop_exit_mode"]="tor-bridge";selected["multihop_execution"]="local"
   let provider:[String:Any]=["tor_entry_bundle":try json(entry),"tor_entry_mode":mode]
   reject("missing captured entry "+mode){_ = try ProviderPreparation().prepare(provider:[:],selectedProfile:selected,strict:true)}
   for fault in ["selection","duplicate","identity","assets","layer","foreign-node"] {
    var altered=entry,profiles=altered["routerProfiles"] as! [[String:Any]]
    switch fault {
    case "selection":altered["selectedRouterID"]="missing"
    case "duplicate":profiles.append(profiles[0])
    case "identity":profiles[0]["node_proof_id"]=String(repeating:"f",count:64)
    case "assets":var assets=altered["profiles"] as! [String:[String:String]];assets.removeValue(forKey:mode);altered["profiles"]=assets
    case "layer":profiles[0]["start_layer"]="xor"
    default:profiles[0]["node_kind"]="external"
    }
    altered["routerProfiles"]=profiles;var changed=provider;changed["tor_entry_bundle"]=try json(altered)
    reject("invalid entry "+mode+"/"+fault){_ = try ProviderPreparation().prepare(provider:changed,selectedProfile:selected,strict:true)}
   }
   var mismatch=provider;mismatch["tor_entry_mode"]="foreign"
   reject("captured raw selection changed"){_ = try ProviderPreparation().prepare(provider:mismatch,selectedProfile:selected,strict:true)}
   let owner=ProviderPreparation(),route=owner.protocolConfiguration as! NETunnelProviderProtocol;route.includeAllNetworks=false
   reject("strict OS route ownership"){_ = try owner.prepare(provider:provider,selectedProfile:selected,strict:true)}
   var mtu=selected;mtu["manual_mtu"]=1390
   reject("two fixed sizes for one TUN"){_ = try ProviderPreparation().prepare(provider:provider,selectedProfile:mtu,strict:true)}
  }
 }
 @MainActor static func run()throws {
  defer{RouterVPNTorTestClose()}
  let maximum=try object(Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[2]))),composite=try object(Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[3])))
  try check("every supported Tor predecessor included",Set(modes)==RouterVPNExternalExitBuilder.torEntryModes)
  for kind in kinds {try verify(kind,"direct","off",maximum,composite)}
  var failures:[String]=[]
  for mode in modes {for layer in layers {for kind in kinds {
   do{try verify(kind,mode,layer,maximum,composite)}catch{failures.append("\(mode)/\(layer)/\(kind): \(error.localizedDescription)")}
  }}}
  if !failures.isEmpty{throw NSError(domain:"TorMatrix",code:1,userInfo:[NSLocalizedDescriptionKey:failures.joined(separator:"\n")])}
  try check("complete Tor matrix",graphs==348)
  try policies(maximum,composite)
  try negatives(maximum,composite)
  print("Apple Tor profile creation and complete provider assembly: PASS (\(graphs) transport graphs, \(policyCases) independent profile-policy combinations, \(checks) checks; shipping Swift/real Go; OS and FFI handles doubled)")
 }
 @MainActor static func main() {
  do{try run()}catch{FileHandle.standardError.write(Data(("FAIL Apple Tor: "+error.localizedDescription+"\n").utf8));exit(1)}
 }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    for tool in ('go', 'swiftc'):
        if not shutil.which(tool):
            raise RuntimeError(tool + ' is required')
    if args.output and (not args.output.is_dir() or any(args.output.iterdir()) or args.output.is_symlink()):
        raise ValueError('--output must be an existing empty owned directory')
    with tempfile.TemporaryDirectory(prefix='.ios-tor-go-', dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix='ios-tor-profile-') as temporary:
        go_dir, work = Path(go_dir), Path(temporary)
        (go_dir / 'main.go').write_text(GO)
        compiler = work / 'compiler'
        subprocess.run(['go', 'build', '-o', str(compiler), str(go_dir / 'main.go')], cwd=ROOT, check=True, timeout=120)
        maximum, composite = work / 'max.json', work / 'composite.json'
        subprocess.run(['go', 'test', '-count=1', '-run', '^TestExportMAXMultihopMobileProfiles$', './internal/mobilemultihop'], cwd=ROOT,
            env=dict(os.environ, ROUTERVPN_MAX_MULTIHOP_FIXTURES=str(maximum)), check=True, timeout=120)
        generator = work / 'generator'
        subprocess.run(['go', 'build', '-o', str(generator), './deploy/testfixtures/composite'], cwd=ROOT, check=True, timeout=90)
        with composite.open('wb') as stream:
            subprocess.run([str(generator)], stdout=stream, check=True, timeout=30)
        suffix = '.dylib' if platform.system() == 'Darwin' else '.so'
        for name, body in [('WireGuardKit', W.TYPES), ('Libbox', LIBBOX)] + ([] if platform.system() == 'Darwin' else [('Network', NETWORK)]):
            source = work / (name + '.swift'); source.write_text(body)
            subprocess.run(['swiftc', '-swift-version', '6', '-module-cache-path', str(work / 'module-cache'), '-emit-module', '-emit-library', '-module-name', name,
                str(source), '-emit-module-path', str(work / (name + '.swiftmodule')), '-o', str(work / ('lib' + name + suffix))], check=True, timeout=90)
        creation = (APP / 'IOSExternalNodeBuilderView.swift').read_text()
        creation = creation[creation.index('@MainActor\nextension RouterVPNModel {'):creation.index('struct IOSExternalNodeBuilderView:')]
        # The view declaration's own preceding annotation is outside the model
        # extension. Keep only that complete extension, with no recreated logic.
        creation = creation[:creation.rfind('}') + 1]
        source = work / 'Tests.swift'; source.write_text(SWIFT + '\n' + creation + '\n' + provider_source())
        sources = [APP / name for name in ('Models.swift', 'IOSDNSRuntimePolicy.swift', 'IOSNativeXrayProfile.swift', 'IOSNativePQProfile.swift', 'IOSMultihopStartLayer.swift', 'IOSRuntimeSelection.swift')]
        sources += [TUN / name for name in ('WireGuardQuickConfig.swift', 'RouterVPNMultihopGraph.swift', 'RouterVPNMTUPolicy.swift', 'IOSStartLayer.swift', 'IOSXrayDevicePolicy.swift', 'RouterVPNExternalExit.swift')]
        command = ['swiftc', '-swift-version', '6', '-module-cache-path', str(work / 'module-cache'), '-I', str(work), '-L', str(work), '-lWireGuardKit', '-lLibbox']
        if platform.system() != 'Darwin':
            command += ['-lNetwork']
        command += ['-Xlinker', '-rpath', '-Xlinker', str(work), *map(str, sources), str(source), '-o', str(work / 'tests')]
        subprocess.run(command, check=True, timeout=180)
        environment = dict(os.environ)
        if args.output:
            environment['ROUTERVPN_IOS_TOR_GRAPHS'] = str(args.output.resolve())
        subprocess.run([str(work / 'tests'), str(compiler), str(maximum), str(composite)], env=environment, check=True, timeout=180)
        if args.output:
            inputs = [Path(__file__), APP / 'IOSExternalNodeBuilderView.swift', TUN / 'PacketTunnelProvider.swift', *sources]
            report = {'schema': 1, 'graphs': 348, 'profile_policy_combinations': 320, 'public_tor_traffic': False, 'native_handles': 'boundary doubles',
                'sources': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}}
            (args.output / 'source-evidence.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
