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
EXTRA_EVIDENCE_SOURCES = ()
GRAPH_EVIDENCE = {'schema': 1, 'graphs': 396, 'home_dns_combinations': 285,
    'router_tor_graphs': 348, 'ordinary_tor_graphs': 48,
    'ordinary_external_graphs': 456, 'external_execution_graphs': 912, 'external_exit_layer_graphs': 144,
    'mapped_openvpn_graphs': 171, 'mapped_openvpn_layer_graphs': 342, 'profile_policy_combinations': 320,
    'public_tor_traffic': False, 'native_handles': 'boundary doubles'}
PADDING_EVIDENCE = {'schema': 1, 'execution': 'local', 'padding_enabled': True,
    'graphs': 528, 'private_graphs': 456, 'direct_graphs': 8, 'ordinary_graphs': 64,
    'rates_kbps': [0, 32, 64, 192], 'entry_layers': ['off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening'],
    'public_tor_traffic': False, 'native_handles': 'boundary doubles'}


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
    '"router-vpn/internal/nativeopenvpn";"crypto/ecdh";"crypto/mlkem"')
xray_fixture = A.GO_HELPER[A.GO_HELPER.index(' case "test-xray":'):A.GO_HELPER.index(' case "xray-check",')]
GO = replace_once(GO, ' case "compile":value,err=mobilemultihop.CompilePQProfile(r.Mode,r.Files,r.Node)', r'''
 case "tor":value,err=mobiletor.CompileProfile(r.Config,r.Node,r.Source)
 case "tor-validate":err=mobiletor.ValidateProfile(r.Config);value="checked"
 case "tor-padding-source":value,err=RouterTorPaddingSource(r.Config,r.Policy,r.Node)
 case "canonical-config-sha":var graph map[string]any;err=json.Unmarshal([]byte(r.Config),&graph);if err==nil{var encoded []byte;encoded,err=json.Marshal(graph);if err==nil{sum:=sha256.Sum256(encoded);value=hex.EncodeToString(sum[:])}}
 case "tor-with-predecessor":value,err=mobiletor.CompileProfileWithPredecessor(r.Config,r.Node,r.Source,r.Policy)
 case "tor-with-external-predecessor":value,err=mobiletor.CompileProfileWithExternalPredecessor(r.Config,r.Node,r.Source,r.Policy)
 case "tor-server-with-predecessor":value,err=mobiletor.CompileServerProfileWithPredecessor(r.Config,r.Node,r.Source,r.Policy)
 case "tor-server-mtu-authority":var predecessor *mobiletor.PredecessorProof;predecessor,err=mobiletor.NewPredecessorProof(r.Source);if err==nil{value,err=mobiletor.ServerMTUAuthority(r.Config,r.Policy,r.Node,predecessor)}
 case "tor-mtu-authority":var predecessor *mobiletor.PredecessorProof;if r.Source!=""{predecessor,err=mobiletor.NewPredecessorProof(r.Source)};if err==nil{value,err=mobiletor.MTUAuthorityWithPredecessor(r.Config,r.Policy,r.Node,predecessor)}
 case "external-policy":value,err=mobilemultihop.CompileExternalPolicy(r.Config,r.Policy)
 case "external-validate-transport":err=mobilemultihop.ValidateExternalTransport(r.Config,r.Policy);value="checked"
 case "external-validate-dns":err=mobilemultihop.ValidateExternalDNS(r.Config,r.Policy);value="checked"
 case "external-prepare":value,err=mobilemultihop.PrepareExternalExecutionCapture(r.Config,r.Policy,r.Source)
 case "external-response-probe":err=mobilemultihop.ValidateExternalResponseProbe(r.Node,r.Config);value="checked"
 case "private-node-json":err=nativeopenvpn.ValidatePrivateNodeJSON(r.Config);value="checked"
 case "openvpn-pairing":var p nativeopenvpn.Profile;var pair nativeopenvpn.Pairing;err=json.Unmarshal([]byte(r.Config),&p);if err==nil{err=json.Unmarshal([]byte(r.Policy),&pair)};if err==nil{_,err=nativeopenvpn.ValidatePairing(p,pair)};value="checked"
 case "openvpn-response-probes":err=RouterValidateExternalOpenVPNResponseProbes(r.Config,r.Policy);value="checked"
 case "openvpn-start-layers":err=RouterValidateExternalOpenVPNStartLayers(r.Config,r.Policy,r.Source,r.Mode);value="checked"
 case "openvpn":value,err=nativeopenvpn.CompileEndpoint(r.Config,r.Files,r.Node,r.Mode,r.Source)
 case "predecessor":_,err=mobiletor.NewPredecessorProof(r.Config);value="checked"
 case "predecessor-fingerprint":var proof *mobiletor.PredecessorProof;proof,err=mobiletor.NewPredecessorProof(r.Config);if err==nil{value=proof.Fingerprint()}
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

# Execute the shipping gomobile boundary unchanged, rather than only a second
# call to its underlying parser. Native framework marshalling remains doubled.
_openvpn_binding = (ROOT / 'mobile/routervpn_openvpn.go').read_text()
_response_binding_start = _openvpn_binding.index('func RouterValidateExternalOpenVPNResponseProbes(')
RESPONSE_BINDING = _openvpn_binding[_response_binding_start:_openvpn_binding.index('\n}', _response_binding_start) + 2]
_start_layers_binding_start = _openvpn_binding.index('func RouterValidateExternalOpenVPNStartLayers(')
START_LAYERS_BINDING = _openvpn_binding[_start_layers_binding_start:_openvpn_binding.index('\n}', _start_layers_binding_start) + 2]
GO += '\n' + RESPONSE_BINDING + '\n' + START_LAYERS_BINDING + '\n'
_tor_binding = (ROOT / 'mobile/toroutbound/bridge.go.tmpl').read_text()
_padding_binding_start = _tor_binding.index('func RouterTorPaddingSource(')
PADDING_BINDING = _tor_binding[_padding_binding_start:_tor_binding.index('\n}', _padding_binding_start) + 2]
GO += '\n' + PADDING_BINDING + '\n'

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
public func LibboxRouterValidateTorProfile(_ profile:String,_ error:inout NSError?)->Bool {
 result(&error,["Op":"tor-validate","Config":profile]) == "checked"
}
public func LibboxRouterTorPaddingSource(_ config:String,_ profile:String,_ session:String,_ error:inout NSError?)->String {
 result(&error,["Op":"tor-padding-source","Config":config,"Policy":profile,"Node":session])
}
public func LibboxRouterCompileTorProfileWithPredecessor(_ profile:String,_ session:String,_ predecessor:String,_ predecessorProfile:String,_ error:inout NSError?)->String {
 result(&error,["Op":"tor-with-predecessor","Config":profile,"Node":session,"Source":predecessor,"Policy":predecessorProfile])
}
public func LibboxRouterCompileTorProfileWithExternalPredecessor(_ profile:String,_ session:String,_ predecessor:String,_ predecessorProfile:String,_ error:inout NSError?)->String {
 result(&error,["Op":"tor-with-external-predecessor","Config":profile,"Node":session,"Source":predecessor,"Policy":predecessorProfile])
}
public func LibboxRouterCompileServerTorProfileWithPredecessor(_ profile:String,_ session:String,_ predecessor:String,_ predecessorProfile:String,_ error:inout NSError?)->String {
 result(&error,["Op":"tor-server-with-predecessor","Config":profile,"Node":session,"Source":predecessor,"Policy":predecessorProfile])
}
public func LibboxRouterCompileExternalPolicy(_ config:String,_ capture:String,_ error:inout NSError?)->String {
 result(&error,["Op":"external-policy","Config":config,"Policy":capture])
}
public func LibboxRouterValidateExternalTransport(_ config:String,_ capture:String,_ error:inout NSError?)->Bool {
 result(&error,["Op":"external-validate-transport","Config":config,"Policy":capture]) == "checked"
}
public func LibboxRouterValidateExternalDNS(_ profile:String,_ entry:String,_ error:inout NSError?)->Bool {
 result(&error,["Op":"external-validate-dns","Config":profile,"Policy":entry]) == "checked"
}
public func LibboxRouterPrepareExternalExecutionCapture(_ config:String,_ capture:String,_ restored:String,_ error:inout NSError?)->String {
 result(&error,["Op":"external-prepare","Config":config,"Policy":capture,"Source":restored])
}
public func LibboxRouterValidateExternalResponseProbe(_ host:String,_ probe:String,_ error:inout NSError?)->Bool {
 result(&error,["Op":"external-response-probe","Node":host,"Config":probe]) == "checked"
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
public func LibboxRouterValidateExternalOpenVPNPairing(_ profile:String,_ pairing:String,_ error:inout NSError?)->Bool {
 result(&error,["Op":"openvpn-pairing","Config":profile,"Policy":pairing]) == "checked"
}
public func LibboxRouterValidateExternalOpenVPNResponseProbes(_ profile:String,_ probes:String,_ error:inout NSError?)->Bool {
 result(&error,["Op":"openvpn-response-probes","Config":profile,"Policy":probes]) == "checked"
}
public func LibboxRouterValidateExternalOpenVPNStartLayers(_ profile:String,_ probes:String,_ layers:String,_ mode:String,_ error:inout NSError?)->Bool {
 result(&error,["Op":"openvpn-start-layers","Config":profile,"Policy":probes,"Source":layers,"Mode":mode]) == "checked"
}
public func LibboxRouterValidatePrivateNodeJSON(_ source:String,_ error:inout NSError?)->Bool {
 result(&error,["Op":"private-node-json","Config":source]) == "checked"
}
public func LibboxRouterOpenVPNEndpoint(_ config:String,_ user:String,_ password:String,_ tag:String,_ detour:String,_ error:inout NSError?)->String {
 result(&error,["Op":"openvpn","Config":config,"Files":user,"Node":password,"Mode":tag,"Source":detour])
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
    # Execute the shipping entry/policy preparation unchanged, then the real
    # concrete leaf builder. The separate Compare host gate executes the new
    # public branch and actual callback ownership across sequential engines.
    inputs = source[source.index('    private struct ExternalLibboxInputs {'):source.index('    private func prepareExternalLibbox(')]
    preparation = method('prepareExternalLibbox')
    external = r'''    func assemble(provider: [String: Any], selectedProfile: [String: Any], strict: Bool) throws -> Prepared {
        let prepared = try prepareExternalLibbox(provider: provider, selectedProfile: selectedProfile, strict: strict)
        let runtime = try RouterVPNExternalExitBuilder.build(profile: selectedProfile, predecessorFiles: prepared.files,
            predecessorProfile: prepared.profile, restoredExecution: restoredMultihopExecution)
        guard (runtime.policy?.executionRequested != nil || runtime.torExecution != nil) == (multihopExecutionSource != nil) else {
            throw IOSMultihopExecution.issue()
        }
        return Prepared(runtime: runtime, strict: prepared.strict, predecessor: prepared.files, profile: prepared.profile)
    }
'''
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
 var restoredMultihopExecution:String?,multihopExecutionSource:IOSMultihopExecution.Source?
 struct Prepared {let runtime:RouterVPNExternalExitRuntime;let strict:Bool;let predecessor:[String:Data];let profile:[String:Any]?}
 func tunnelError(_ code:Int,_ message:String)->NSError {NSError(domain:"ShippingTorAssembly",code:code,userInfo:[NSLocalizedDescriptionKey:message])}
 func entry(_ root:[String:Any],_ mode:String)throws->[String:Data] {
  try compileLibbox(provider:["rawProfileID":mode],root:root,selectedProfile:selectedRouterProfile(root)).files
 }
 // startTunnel captures this source before calling the exact assembly method
 // below. Reuse the shipping Source constructor for the isolated pre-start seam.
 func prepare(provider:[String:Any],selectedProfile:[String:Any],strict:Bool)throws->Prepared {
  if provider["tor_entry_bundle"] != nil && multihopExecutionSource == nil {
   var captured=provider
   captured["engine"]="external-libbox"
   let mode=(selectedProfile["external"] as? [String:Any])?["protocol"] as? String ?? ""
   captured["mode"]="external-"+mode
   captured["bundle"]=try JSONSerialization.data(withJSONObject:["selectedRouterID":selectedProfile["id"] ?? "","routerProfiles":[selectedProfile]],options:[.sortedKeys])
   multihopExecutionSource=try IOSMultihopExecution.Source(configuration:captured){SHA256.hash(data:$0).map{String(format:"%02x",$0)}.joined()}
  }
  return try assemble(provider:provider,selectedProfile:selectedProfile,strict:strict)
 }
'''
    support = replace_once(support, ' // SHIPPING_NODE_PROOF_DOMAIN', domain.group(0).replace('private static', 'static', 1))
    return support + compilation + inputs + preparation + ''.join(method(name) for name in (
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
 @MainActor static var checks=0,graphs=0,paddingGraphs=0,homeGraphs=0,policyCases=0,externalGraphs=0,ordinaryTorGraphs=0,executionGraphs=0,externalLayerGraphs=0,mappedOpenVPNGraphs=0,mappedOpenVPNLayerGraphs=0,sessions=Set<String>()
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
  try check("new Tor keeps Home DNS and IPv6 defaults",profile["dns_mode"] as? String=="home" && profile["ipv6_mode"] as? String=="on" && profile["home_lan_access"]==nil)
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
 @MainActor static func verify(_ kind:String,_ mode:String,_ layer:String,_ maximum:[String:Any],_ composite:[String:Any],paddingRate:Int?=nil)throws {
  var selected=try tor(kind),provider:[String:Any]=[:],baseline:[String:Data]=[:],entry:[String:Any]?
  if let paddingRate {selected["daita_enabled"]=true;selected["daita_rate_kbps"]=paddingRate}
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
  try check("Tor MTU retains the exact compiled profile capture",runtime.torProfileJSON==String(decoding:before,as:UTF8.self))
  let authority=try object(Data(bridge(["Op":"tor-mtu-authority","Config":String(decoding:runtime.files["sing-box.json"]!,as:UTF8.self),"Policy":runtime.torProfileJSON!,"Node":sid,"Source":runtime.torPredecessorProfile ?? ""]).utf8))
  try check("native Tor options bind the frozen MTU and DNS policy",authority["source_kind"] as? String=="tor" && authority["id"] as? String==selected["id"] as? String)
  var changedPolicy=selected;changedPolicy["mtu_policy"]="auto"
  reject("Tor factory cannot change frozen policy after native construction"){_ = try bridge(["Op":"tor-mtu-authority","Config":String(decoding:runtime.files["sing-box.json"]!,as:UTF8.self),"Policy":text(changedPolicy),"Node":sid,"Source":runtime.torPredecessorProfile ?? ""])}
  try check("one TUN and one Tor",(graph["inbounds"] as! [[String:Any]]).count==1 && (graph["outbounds"] as! [[String:Any]]).filter{$0["type"] as? String=="routervpn-tor"}.count==1)
  try check("Tor keeps dynamic exit semantics",runtime.expectedPublicIP.isEmpty && (graph["route"] as! [String:Any])["final"] as? String=="routervpn-tor-exit")
  try check("Tor keeps bridge order and plain emptiness",out["bridges"] as? [String]==lines(kind))
  var transport=out
  if paddingRate != nil {transport.removeValue(forKey:"padding_source")}
  try check("private proof credentials stay inside their captured source",!text(transport).contains("entry-private-token") && out["node_proof_id"]==nil && out["router_api"]==nil)
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
   try check("native Tor binds the exact captured entry",out["entry_sha256"] as? String==bridge(["Op":"predecessor-fingerprint","Config":runtime.torPredecessorProfile!]))
  }
  try check("source profiles remain immutable",json(selected)==before && entry.map{try! json($0)}==oldEntry)
  if let paddingRate {
   try paddingCapture(runtime,selected,mode,layer,kind,paddingRate,baseline["sing-box.json"])
  }else if let output=ProcessInfo.processInfo.environment["ROUTERVPN_IOS_TOR_GRAPHS"] {
   let directory=URL(fileURLWithPath:output).appendingPathComponent([mode,layer,kind].joined(separator:"-"))
   try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:false)
   for (name,data) in runtime.files {try data.write(to:directory.appendingPathComponent(name))}
   try json(["mode":mode,"layer":layer,"transport":kind,"session":sid]).write(to:directory.appendingPathComponent("fixture.json"))
  }
  if paddingRate==nil {graphs+=1}
 }
 @MainActor static func paddingCapture(_ runtime:RouterVPNExternalExitRuntime,_ selected:[String:Any],_ mode:String,_ layer:String,_ kind:String,_ rate:Int,_ predecessor:Data?=nil)throws {
  let data=runtime.files["sing-box.json"]!,raw=String(decoding:data,as:UTF8.self),profile=runtime.torProfileJSON!,session=runtime.torSessionID!
  let graph=try object(data),out=try tagged(graph,"routervpn-tor-exit"),source=out["padding_source"] as! [String:Any]
  try check("enabled Local capture keeps exact selected source and rate",source["profile"] as? String==profile && json(object(Data(profile.utf8)))==json(selected) && selected["daita_enabled"] as? Bool==true && selected["daita_rate_kbps"] as? Int==rate && (mode=="direct" ? runtime.torExecution==nil:runtime.torExecution=="local"))
  if mode=="direct" {
   try check("direct padding has no borrowed predecessor",source["predecessor_profile"]==nil && source["predecessor_config"]==nil)
  }else {
   let capturedProfile=source["predecessor_profile"] as? String
   try check("padding retains complete predecessor source "+mode,capturedProfile != nil && source["predecessor_config"] is String && (mode.hasPrefix("external-") ? json(object(Data(capturedProfile!.utf8)))==json(object(Data(runtime.torPredecessorProfile!.utf8))):capturedProfile==runtime.torPredecessorProfile))
   if let predecessor {try check("padding retains exact entry graph bytes",source["predecessor_config"] as? String==String(decoding:predecessor,as:UTF8.self))}
  }
  var failure:NSError?
  let expected=LibboxRouterTorPaddingSource(raw,profile,session,&failure)
  try check("actual padding source API binds the full canonical graph",failure==nil && expected.count==64 && expected==bridge(["Op":"canonical-config-sha","Config":raw]))
  try check("formatting cannot change compiled padding identity",expected==bridge(["Op":"tor-padding-source","Config":text(graph),"Policy":profile,"Node":session]))
  for fault in ["source-profile","source-entry","lost-source","config","selected-policy","selected-session","owner-session","execution","foreign-credential"] {
   var changed=try object(data),rows=changed["outbounds"] as! [[String:Any]],selection=selected,selectedSession=session
   let index=rows.firstIndex{$0["tag"] as? String=="routervpn-tor-exit"}!
   var captured=rows[index]["padding_source"] as! [String:Any]
   switch fault {
   case "source-profile":var value=selected;value["daita_rate_kbps"]=rate==32 ? 64:32;captured["profile"]=try text(value)
   case "source-entry":captured["predecessor_config"]="{}"
   case "lost-source":rows[index].removeValue(forKey:"padding_source")
   case "config":var route=changed["route"] as! [String:Any];route["auto_detect_interface"]=false;changed["route"]=route
   case "selected-policy":selection["daita_enabled"]=false
   case "selected-session":selectedSession="replacement-padding-owner"
   case "owner-session":rows[index]["session_id"]="replacement-padding-owner"
   case "execution":selection["multihop_execution"]="server"
   default:
    if let encoded=captured["predecessor_profile"] as? String {var value=try object(Data(encoded.utf8));value["api_token"]="foreign-private-token";captured["predecessor_profile"]=try text(value)}
    else {captured["predecessor_profile"]="{\"api_token\":\"foreign-private-token\"}"}
   }
   if fault != "lost-source" {rows[index]["padding_source"]=captured};changed["outbounds"]=rows
   reject("padding source API rejects changed capture "+mode+"/"+fault){_ = try bridge(["Op":"tor-padding-source","Config":text(changed),"Policy":text(selection),"Node":selectedSession])}
  }
  if let output=ProcessInfo.processInfo.environment["ROUTERVPN_IOS_LOCAL_PADDING_GRAPHS"] {
   let directory=URL(fileURLWithPath:output).appendingPathComponent([mode,layer,kind,String(rate)].joined(separator:"-"))
   try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:false)
   for (name,data) in runtime.files {try data.write(to:directory.appendingPathComponent(name))}
   try json(["mode":mode,"layer":layer,"transport":kind,"rate_kbps":rate,"session":session,"source_sha256":expected]).write(to:directory.appendingPathComponent("fixture.json"))
  }
  paddingGraphs+=1
 }
 @MainActor static func homeDNS(_ maximum:[String:Any],_ composite:[String:Any])throws {
  for mode in modes {for layer in layers {for transport in ["udp","tcp","tls","https","h3"] {
   var source=try root(mode,layer,maximum,composite),entry=(source["routerProfiles"] as! [[String:Any]])[0]
   entry["ipv6_mode"]="on";entry["home_lan_access"]=false;source["routerProfiles"]=[entry]
   var selected=try tor("obfs4")
   selected["dns_mode"]="home";selected["dns_protocol"]=transport;selected["dns_host"]=transport=="udp" ? "":entry[transport=="tcp" || transport=="https" ? "adguard_ipv6":"adguard_ipv4"]!
   selected["dns_port"]=5453;selected["dns_server_name"]="adguard.home.example";selected["dns_path"]="/selected-home?policy=exact"
   selected["ipv6_mode"]="on";selected["home_lan_access"]=false
   selected["multihop_enabled"]=true;selected["multihop_entry_id"]="entry";selected["multihop_entry_mode"]=mode
   selected["multihop_exit_id"]=selected["id"];selected["multihop_exit_mode"]="tor-bridge";selected["multihop_execution"]="local"
   let frozen=try json(selected),captured=try text(entry),provider:[String:Any]=["tor_entry_bundle":try json(source),"tor_entry_mode":mode]
   let prepared=try ProviderPreparation().prepare(provider:provider,selectedProfile:selected,strict:true),runtime=prepared.runtime
   let graph=try object(runtime.files["sing-box.json"]!),out=try tagged(graph,"routervpn-tor-exit"),dns=graph["dns"] as! [String:Any]
   let servers=dns["servers"] as! [[String:Any]],home=servers.first{$0["tag"] as? String=="routervpn-tor-dns"}!,bootstrap=servers.first{$0["tag"] as? String=="routervpn-tor-bootstrap"}!
   let expectedHost=transport=="udp" ? entry["adguard_ipv4"] as! String:selected["dns_host"] as! String
   try check("Home keeps exact private endpoint and transport",home["type"] as? String==transport && home["server"] as? String==expectedHost && home["server_port"] as? Int==5453)
   try check("Home DNS traverses the exact entry while application traffic stays Tor",home["detour"] as? String==out["detour"] as? String && home["detour"] as? String != "routervpn-tor-exit" && (graph["route"] as! [String:Any])["final"] as? String=="routervpn-tor-exit")
   var expectedBootstrap=home;expectedBootstrap["tag"]="routervpn-tor-bootstrap"
   try check("Tor bootstrap uses the same captured Home policy",json(bootstrap)==json(expectedBootstrap))
   if ["tls","https","h3"].contains(transport) {try check("Home keeps TLS identity",(home["tls"] as? [String:Any])?["server_name"] as? String=="adguard.home.example")}
   if ["https","h3"].contains(transport) {try check("Home keeps exact HTTP path",home["path"] as? String=="/selected-home?policy=exact")}
   try check("Home proof captures all entry fields exactly",runtime.torPredecessorProfile==captured && out["entry_sha256"] as? String==bridge(["Op":"predecessor-fingerprint","Config":captured]))
   try check("Home compilation does not rewrite stored profiles",runtime.torProfileJSON==String(decoding:frozen,as:UTF8.self) && json(selected)==frozen)
   let rules=(graph["route"] as! [String:Any])["rules"] as! [[String:Any]]
   try check("Home DNS does not remove LAN restrictions or add an application bypass",rules.contains{$0["action"] as? String=="reject" && $0["ip_cidr"] != nil} && !rules.contains{$0["action"] as? String=="route" && $0["outbound"] as? String != "routervpn-tor-exit"})
   homeGraphs+=1
  }}}
  try check("Home DNS reaches every entry, Start Layer and selected transport",homeGraphs==285)
  for throughEntry in [false,true] {
   var selected=try tor("tor"),provider:[String:Any]=[:]
   selected["dns_mode"]="rescue"
   if throughEntry {
    selected["multihop_enabled"]=true;selected["multihop_entry_id"]="entry";selected["multihop_entry_mode"]="wg";selected["multihop_exit_id"]=selected["id"];selected["multihop_exit_mode"]="tor";selected["multihop_execution"]="local"
    provider=["tor_entry_bundle":try json(root("wg","off",maximum,composite)),"tor_entry_mode":"wg"]
   }
   let frozen=try text(selected),runtime=try ProviderPreparation().prepare(provider:provider,selectedProfile:selected,strict:true).runtime
   let graph=try object(runtime.files["sing-box.json"]!),servers=(graph["dns"] as! [String:Any])["servers"] as! [[String:Any]],chosen=servers.first{$0["tag"] as? String=="routervpn-tor-dns"}!
   try check("explicit saved Rescue remains Rescue through Tor",chosen["server"] as? String=="1.1.1.1" && chosen["type"] as? String=="https" && chosen["detour"] as? String=="routervpn-tor-exit" && runtime.torProfileJSON==frozen)
  }
  let source=try root("wg","off",maximum,composite),entry=(source["routerProfiles"] as! [[String:Any]])[0],files=try ProviderPreparation().entry(source,"wg")
  var selected=try tor("tor")
  selected["dns_mode"]="home";selected["dns_protocol"]="udp";selected["dns_host"]=""
  selected["multihop_enabled"]=true;selected["multihop_entry_id"]="entry";selected["multihop_entry_mode"]="wg";selected["multihop_exit_id"]=selected["id"];selected["multihop_exit_mode"]="tor";selected["multihop_execution"]="local"
  for fault in ["wrong-entry","missing-api","missing-token","missing-dns","other-resolver","compare","disabled","wrong-exit","missing-mode"] {
   var badEntry=entry,badExit=selected
   switch fault {
   case "wrong-entry":badEntry["id"]="another-entry"
   case "missing-api":badEntry.removeValue(forKey:"router_api")
   case "missing-token":badEntry.removeValue(forKey:"api_token")
   case "missing-dns":badEntry.removeValue(forKey:"adguard_ipv4");badEntry.removeValue(forKey:"adguard_ipv6")
   case "other-resolver":badExit["dns_host"]="192.168.50.134"
   case "compare":badExit["multihop_execution"]="auto"
   case "disabled":badExit["multihop_enabled"]=false
   case "wrong-exit":badExit["multihop_exit_id"]="another-exit"
   default:badExit.removeValue(forKey:"multihop_entry_mode")
   }
   reject("Home host rejects an unowned entry without a DNS fallback "+fault){_ = try RouterVPNExternalExitBuilder.build(profile:badExit,predecessorFiles:files,predecessorProfile:badEntry)}
  }
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
 @MainActor static func jumboCapacity(_ maximum:[String:Any],_ composite:[String:Any])throws {
  for kind in ["tor","obfs4"] {for policy in ["auto","default","fixed"] {
   var selected=try tor(kind);selected["jumbo_tun"]=true;selected["mtu_policy"]=policy;selected["manual_mtu"]=policy=="fixed" ? 9000:0
   let frozen=try text(selected),runtime=try ProviderPreparation().prepare(provider:[:],selectedProfile:selected,strict:true).runtime
   let graph=try object(runtime.files["sing-box.json"]!),tun=(graph["inbounds"] as! [[String:Any]])[0]
   let authority=try object(Data(bridge(["Op":"tor-mtu-authority","Config":String(decoding:runtime.files["sing-box.json"]!,as:UTF8.self),"Policy":runtime.torProfileJSON!,"Node":runtime.torSessionID!]).utf8))
   try check("direct Tor Jumbo uses its single 9000 virtual interface",tun["mtu"] as? Int==9000 && (graph["inbounds"] as! [[String:Any]]).count==1 && tun["stack"] as? String=="system")
   try check("direct Tor Jumbo retains exact saved preference",runtime.torProfileJSON==frozen && authority["mtu_policy"] as? String==policy && authority["jumbo_tun"] as? Bool==true && authority["entry_fixed_mtu"]==nil)
   var conflict=selected;conflict["mtu_policy"]="fixed";conflict["manual_mtu"]=1420
   reject("Tor Jumbo cannot silently normalize conflicting Fixed"){_ = try ProviderPreparation().prepare(provider:[:],selectedProfile:conflict,strict:true)}
  }}
  for mode in ["wg","awg2-fast","shadowsocks","hysteria2","naive-h3","split","max-tls-wg"] {
   for inherited in ["fixed-small","fixed-9000","jumbo"] {for policy in ["auto","default"] {
    var source=try root(mode,"off",maximum,composite),entry=(source["routerProfiles"] as! [[String:Any]])[0]
    let jumbo=inherited=="jumbo",capacity=inherited=="fixed-small" ? 1392:9000
    entry["mtu_policy"]=jumbo ? "default":"fixed";entry["manual_mtu"]=jumbo ? 0:capacity;entry["jumbo_tun"]=jumbo
    source["routerProfiles"]=[entry]
    var selected=try tor("obfs4");selected["mtu_policy"]=policy;selected["manual_mtu"]=0;selected["jumbo_tun"]=false
    selected["multihop_enabled"]=true;selected["multihop_entry_id"]="entry";selected["multihop_entry_mode"]=mode;selected["multihop_exit_id"]=selected["id"];selected["multihop_exit_mode"]="tor-bridge";selected["multihop_execution"]="local"
    let provider:[String:Any]=["tor_entry_bundle":try json(source),"tor_entry_mode":mode]
    if jumbo && ["wg","awg2-fast","max-tls-wg"].contains(mode) {
     reject("packet-bearing entry Jumbo capability stays enforced "+mode){_ = try ProviderPreparation().prepare(provider:provider,selectedProfile:selected,strict:true)}
     continue
    }
    let frozen=try text(selected),frozenEntry=try text(source),baseline=try ProviderPreparation().entry(source,mode)
    let runtime=try ProviderPreparation().prepare(provider:provider,selectedProfile:selected,strict:true).runtime
    let graph=try object(runtime.files["sing-box.json"]!),tun=(graph["inbounds"] as! [[String:Any]])[0]
    let authority=try object(Data(bridge(["Op":"tor-mtu-authority","Config":String(decoding:runtime.files["sing-box.json"]!,as:UTF8.self),"Policy":runtime.torProfileJSON!,"Node":runtime.torSessionID!,"Source":runtime.torPredecessorProfile!]).utf8))
    try check("Apple preserves inherited single TUN capacity "+mode+":"+inherited,tun["mtu"] as? Int==capacity && (graph["inbounds"] as! [[String:Any]]).count==1)
    try check("native authority distinguishes inherited Fixed from Jumbo",authority["mtu_policy"] as? String==policy && authority["jumbo_tun"] as? Bool==jumbo && (authority["entry_fixed_mtu"] as? Int)==(jumbo ? nil:capacity))
    try check("Tor Jumbo does not rewrite saved sources",runtime.torProfileJSON==frozen && text(source)==frozenEntry && runtime.torPredecessorProfile==text(entry))
    let previous=try object(baseline["sing-box.json"]!)
    try check("Tor capacity does not change raw predecessor endpoints",text(["endpoints":graph["endpoints"] ?? NSNull()])==text(["endpoints":previous["endpoints"] ?? NSNull()]))
    var wrong=entry;wrong["manual_mtu"]=capacity==9000 ? 1392:9000;wrong["mtu_policy"]="fixed";wrong["jumbo_tun"]=false
    reject("Tor MTU cannot substitute another captured entry policy"){_ = try bridge(["Op":"tor-mtu-authority","Config":String(decoding:runtime.files["sing-box.json"]!,as:UTF8.self),"Policy":runtime.torProfileJSON!,"Node":runtime.torSessionID!,"Source":text(wrong)])}
    var conflict=selected;conflict["mtu_policy"]="fixed";conflict["manual_mtu"]=capacity==9000 ? 1392:9000
    reject("one TUN rejects conflicting entry and exit capacity "+mode){_ = try ProviderPreparation().prepare(provider:provider,selectedProfile:conflict,strict:true)}
    if capacity != 9000 {
     var oversized=selected;oversized["jumbo_tun"]=true
     reject("Tor Jumbo cannot overwrite a captured smaller Fixed entry"){_ = try ProviderPreparation().prepare(provider:provider,selectedProfile:oversized,strict:true)}
    }
   }}
  }
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
  if ProcessInfo.processInfo.environment["ROUTERVPN_IOS_OPENVPN_PROBES_ONLY"]=="1" {
   try openVPNResponseProbesCreation();try openVPNStartLayersCreation()
   print("Apple OpenVPN remote response map: PASS (\(checks) shipping Swift/real Go checks; storage and FFI boundaries doubled)")
   return
  }
  let maximum=try object(Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[2]))),composite=try object(Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[3])))
  if ProcessInfo.processInfo.environment["ROUTERVPN_IOS_PADDING_ONLY"]=="1" {
   try enabledPadding(maximum,composite)
   print("Apple Local Tor padding: PASS (\(paddingGraphs) separate shipping Swift/Go graphs; \(checks) checks; native handles and OS boundaries doubled)")
   return
  }
  if let output=ProcessInfo.processInfo.environment["ROUTERVPN_IOS_ENTRY_GRAPHS"] {
   for mode in modes {for layer in layers {
    let selected=try root(mode,layer,maximum,composite),files=try ProviderPreparation().entry(selected,mode)
    let directory=URL(fileURLWithPath:output).appendingPathComponent(mode+"-"+layer)
    try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:false)
    for (name,data) in files {try data.write(to:directory.appendingPathComponent(name))}
    try json((selected["routerProfiles"] as! [[String:Any]])[0]).write(to:directory.appendingPathComponent("entry-profile.json"))
    try json(["mode":mode,"layer":layer]).write(to:directory.appendingPathComponent("fixture.json"))
   }}
   if ProcessInfo.processInfo.environment["ROUTERVPN_IOS_ENTRY_ONLY"]=="1" {print("Exported 57 complete shipping Apple entry graphs");return}
  }
  try check("every supported Tor predecessor included",Set(modes)==RouterVPNExternalExitBuilder.torEntryModes)
  for kind in kinds {try verify(kind,"direct","off",maximum,composite)}
  var failures:[String]=[]
  for mode in modes {for layer in layers {for kind in kinds {
   do{try verify(kind,mode,layer,maximum,composite)}catch{failures.append("\(mode)/\(layer)/\(kind): \(error.localizedDescription)")}
  }}}
  if !failures.isEmpty{throw NSError(domain:"TorMatrix",code:1,userInfo:[NSLocalizedDescriptionKey:failures.joined(separator:"\n")])}
  try check("complete Tor matrix",graphs==348)
  try homeDNS(maximum,composite)
  try policies(maximum,composite)
  try jumboCapacity(maximum,composite)
  try negatives(maximum,composite)
  try ordinaryTorPredecessors()
  try enabledPadding(maximum,composite)
  try ordinaryExternalEntry(maximum,composite)
  try importedAmneziaCreation()
  try responseProbeCreation()
  try packetServerPeerCreation()
  try openVPNPairingCreation(maximum,composite)
  try openVPNResponseProbesCreation();try openVPNStartLayersCreation()
  try ordinaryExternalPredecessors(maximum,composite)
  print("Apple Tor profile creation and complete provider assembly: PASS (\(graphs) Tor, \(homeGraphs) Home DNS, \(ordinaryTorGraphs) ordinary-to-Tor, \(paddingGraphs) separate Local padding, \(externalGraphs) ordinary external, \(executionGraphs) external Server/Compare, \(externalLayerGraphs) separate exit-layer graphs, \(mappedOpenVPNGraphs) mapped OpenVPN and \(mappedOpenVPNLayerGraphs) per-remote layered graphs, \(policyCases) independent profile-policy combinations, \(checks) checks; shipping Swift/real Go; OS and FFI handles doubled)")
 }
 @MainActor static func enabledPadding(_ maximum:[String:Any],_ composite:[String:Any])throws {
  for kind in ["tor","obfs4"] {for rate in [0,32,64,192] {
   try verify(kind,"direct","off",maximum,composite,paddingRate:rate)
   for mode in modes {for layer in layers {try verify(kind,mode,layer,maximum,composite,paddingRate:rate)}}
  }}
  try check("complete direct and private enabled padding matrix",paddingGraphs==464)
  try ordinaryTorPredecessors(padding:true)
  try check("complete enabled padding matrix",paddingGraphs==528)
 }
 @MainActor static func main() {
  do{try run()}catch{FileHandle.standardError.write(Data(("FAIL Apple Tor: "+error.localizedDescription+"\n").utf8));exit(1)}
 }
 @MainActor static func ordinaryTorPredecessors(padding:Bool=false)throws {
  let protocols=["wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn"]
  for mode in protocols {
   let model=RouterVPNModel()
   let openVPN="client\ndev tun\nproto udp\nremote 198.51.100.8 1194\nremote 198.51.100.9 443 tcp\nremote-random\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint "+String(repeating:"ab",count:32)+"\n"
   try model.createIOSExternalNode(protocolName:mode,name:"Ordinary Tor predecessor",server:"198.51.100.8",port:51820,expectedPublicIP:"203.0.113.88",username:" exact user ",password:" exact password ",method:"aes-256-gcm",secret:" exact transport secret ",tlsServerName:mode=="http-connect" ? "":"entry.example.test",wgPrivateKey:key(11),wgPeerPublicKey:key(12),wgPresharedKey:key(13),wgAddresses:["10.91.0.2/32","fd91::2/128"],wgAllowedIPs:["0.0.0.0/0","::/0"],wgDNS:[],wgMTU:1380,openVPNConfig:mode=="openvpn" ? openVPN:"",wgKeepalive:29,awgParameters:mode=="amneziawg" ? ["jc":"3","jmin":"40","jmax":"900","s1":"56","s2":"48","s3":"24","s4":"32","h1":"10000000-19999999","h2":"20000000-29999999","h3":"30000000-39999999","h4":"40000000-49999999"]:[:])
   var entry=(try object(model.saved!)["routerProfiles"] as! [[String:Any]])[0]
   entry["dns_mode"]="custom";entry["dns_protocol"]="tcp";entry["dns_host"]="entry-resolver.example.test";entry["dns_port"]=5353
   entry["dns_bootstrap"]=["server":["type":"tcp","tag":"external-dns-bootstrap","server":"9.9.9.9","server_port":5353,"detour":"custom-exit"],"query":["server":"external-dns-bootstrap","strategy":"ipv4_only","timeout":"2300ms","disable_cache":true]]
   entry["mtu_policy"]="fixed";entry["manual_mtu"]=1380;entry["home_lan_access"]=false;entry["ipv6_mode"]="off";entry["kill_switch_policy"]="always"
   let entryRoot:[String:Any]=["selectedRouterID":entry["id"]!,"routerProfiles":[entry],"profiles":[:]]
   let provider:[String:Any]=["tor_entry_bundle":try json(entryRoot),"tor_entry_mode":mode]
   for kind in (padding ? ["tor","obfs4"]:kinds) {for rate in (padding ? [0,32,64,192]:[-1]) {
    var exit=try tor(kind)
    if padding {exit["daita_enabled"]=true;exit["daita_rate_kbps"]=rate}
    exit["multihop_enabled"]=true;exit["multihop_entry_id"]=entry["id"];exit["multihop_entry_mode"]=mode
    exit["multihop_exit_id"]=exit["id"];exit["multihop_exit_mode"]=kind=="tor" ? "tor":"tor-bridge";exit["multihop_execution"]="local"
    let savedExit=try json(exit),savedEntry=try json(entryRoot)
    let owner=ProviderPreparation(),prepared=try owner.prepare(provider:provider,selectedProfile:exit,strict:true),runtime=prepared.runtime
    let graph=try object(runtime.files["sing-box.json"]!),final=try tagged(graph,"routervpn-tor-exit")
    let original=try object(Data((final["external_predecessor_config"] as! String).utf8))
    try check("ordinary Tor provider keeps exact source without private assets",prepared.predecessor.isEmpty && json(prepared.profile!)==json(entry) && Set(runtime.files.keys)==["sing-box.json"])
    try check("ordinary Tor uses the typed captured source compiler",json(object(Data((final["external_predecessor_profile"] as! String).utf8)))==json(entry) && final["external_tor_profile"] as? String==runtime.torProfileJSON && runtime.torExecution=="local")
    try check("ordinary source is raw dual-family transport",original["dns"]==nil && (original["inbounds"] as! [[String:Any]])[0]["address"] as? [String]==["172.29.94.1/30","fd29:94::1/126"] && (original["route"] as! [String:Any])["final"] as? String=="custom-exit")
    try check("Tor final routes through exact ordinary native owner",final["detour"] as? String=="custom-exit" && tagged(graph,"custom-exit")["type"] as? String==tagged(original,"custom-exit")["type"] as? String)
    try check("ordinary proof identity is frozen separately from dynamic Tor",runtime.expectedPublicIP.isEmpty && object(Data(runtime.torPredecessorProfile!.utf8))["node_kind"] as? String=="external" && (object(Data(runtime.torPredecessorProfile!.utf8))["external"] as! [String:Any])["expected_public_ip"] as? String=="203.0.113.88")
    try check("ordinary Tor has exact execution receipt",owner.multihopExecutionSource?.entryID==entry["id"] as? String && owner.multihopExecutionSource?.entryMode==mode && owner.multihopExecutionSource?.requested=="local")
    let tun=(graph["inbounds"] as! [[String:Any]])[0],dns=(graph["dns"] as! [String:Any])["servers"] as! [[String:Any]]
    let rules=(graph["route"] as! [String:Any])["rules"] as! [[String:Any]]
    try check("ordinary Tor preserves one fixed interface and IPv6 policy",tun["mtu"] as? Int==1380 && rules.contains{$0["ip_version"] as? Int==6 && $0["action"] as? String=="reject"} && (graph["dns"] as! [String:Any])["strategy"] as? String=="ipv4_only")
    try check("ordinary Tor retains explicit entry DNS bootstrap",dns.contains{$0["tag"] as? String=="external-dns-bootstrap" && $0["server"] as? String=="9.9.9.9" && $0["server_port"] as? Int==5353 && $0["detour"] as? String=="custom-exit"})
    let selected=dns.first{$0["tag"] as? String=="routervpn-tor-dns"}
    try check("selected Tor resolver is captured through the Tor final",selected?["server"] as? String==exit["dns_host"] as? String && selected?["server_port"] as? Int==exit["dns_port"] as? Int && selected?["detour"] as? String=="routervpn-tor-exit")
    let restored=ProviderPreparation();restored.restoredMultihopExecution="local"
    let rebuilt=try restored.prepare(provider:provider,selectedProfile:exit,strict:true)
    try check("ordinary Tor restoration keeps Local and frozen entry policy",rebuilt.runtime.torExecution=="local" && json(object(Data(rebuilt.runtime.torPredecessorProfile!.utf8)))==json(entry))
    for fault in ["server","auto","exit-home","entry-home","private-proof","private-api","private-token","mode","identity","static-tor","fixed-size","wrong-slot","mixed-slot"] {
     var changedExit=exit,changedEntry=entry,changedProvider=provider
     switch fault {
     case "server","auto":changedExit["multihop_execution"]=fault
     case "exit-home":changedExit["dns_mode"]="home"
     case "entry-home":changedEntry["dns_mode"]="home"
     case "private-proof":changedEntry["node_proof_id"]=String(repeating:"a",count:64)
     case "private-api":changedEntry["router_api"]="http://10.77.0.1:8787"
     case "private-token":changedEntry["api_token"]="foreign private token"
     case "mode":changedProvider["tor_entry_mode"]="foreign"
     case "identity":var imported=changedEntry["external"] as! [String:Any];imported["expected_public_ip"]="";changedEntry["external"]=imported
     case "static-tor":var imported=changedExit["external"] as! [String:Any];imported["expected_public_ip"]="203.0.113.9";changedExit["external"]=imported
     case "fixed-size":changedEntry["manual_mtu"]=1390
     case "wrong-slot":changedProvider.removeValue(forKey:"tor_entry_bundle");changedProvider["external_entry_bundle"]=provider["tor_entry_bundle"]
     default:changedProvider["external_entry_bundle"]=provider["tor_entry_bundle"]
     }
     if changedProvider["tor_entry_bundle"] != nil {changedProvider["tor_entry_bundle"]=try json(["selectedRouterID":changedEntry["id"]!,"routerProfiles":[changedEntry],"profiles":[:]])}
     reject("ordinary Tor cannot substitute authority or source "+mode+"/"+kind+"/"+fault){_ = try ProviderPreparation().prepare(provider:changedProvider,selectedProfile:changedExit,strict:true)}
    }
    try check("ordinary padding retains immutable source credentials and policy",json(exit)==savedExit && json(entryRoot)==savedEntry)
    if padding {
     try paddingCapture(runtime,exit,"external-"+mode,"off",kind,rate,Data((final["external_predecessor_config"] as! String).utf8))
    }else if let output=ProcessInfo.processInfo.environment["ROUTERVPN_IOS_TOR_GRAPHS"] {
     let capturedMode="external-"+mode
     let directory=URL(fileURLWithPath:output).appendingPathComponent([capturedMode,"off",kind].joined(separator:"-"))
     try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:false)
     for (name,data) in runtime.files {try data.write(to:directory.appendingPathComponent(name))}
     try json(["mode":capturedMode,"layer":"off","transport":kind,"session":runtime.torSessionID!]).write(to:directory.appendingPathComponent("fixture.json"))
    }
    if !padding {ordinaryTorGraphs+=1}
   }}
  }
  if !padding {try check("complete ordinary predecessor Tor graph matrix",ordinaryTorGraphs==48)}
 }
 @MainActor static func ordinaryExternalEntry(_ maximum:[String:Any],_ composite:[String:Any])throws {
  let model=RouterVPNModel()
  try model.createIOSExternalNode(protocolName:"socks5",name:"Imported exit",server:"198.51.100.8",port:1080,expectedPublicIP:"203.0.113.88",username:" exact user ",password:" exact secret ",method:"",secret:"",tlsServerName:"",wgPrivateKey:"",wgPeerPublicKey:"",wgPresharedKey:"",wgAddresses:[],wgAllowedIPs:[],wgDNS:[],wgMTU:nil)
  let saved=try object(model.saved!)
  var exit=(saved["routerProfiles"] as! [[String:Any]])[0]
  let credentials=(exit["external"] as! [String:Any])["socks5"] as! [String:Any]
  try check("external creation preserves exact credentials",credentials["username"] as? String==" exact user " && credentials["password"] as? String==" exact secret ")
  exit["multihop_enabled"]=true;exit["multihop_entry_id"]="entry";exit["multihop_entry_mode"]="wg";exit["multihop_exit_id"]=exit["id"];exit["multihop_exit_mode"]="socks5";exit["multihop_execution"]="local"
  exit["dns_mode"]="home";exit["dns_host"]="192.168.50.133";exit["dns_protocol"]="tcp";exit["dns_port"]=5353;exit["mtu_policy"]="fixed";exit["manual_mtu"]=1380
  for entryLAN in [false,true] {for exitLAN in [false,true] {
   var source=try root("wg","off",maximum,composite),profiles=source["routerProfiles"] as! [[String:Any]]
   profiles[0]["daita_enabled"]=false;profiles[0]["home_lan_access"]=entryLAN;profiles[0]["manual_mtu"]=1500
   source["routerProfiles"]=profiles;exit["home_lan_access"]=exitLAN
   let provider:[String:Any]=["external_entry_bundle":try json(source),"external_entry_mode":"wg"]
   let owner=ProviderPreparation(),flags=owner.protocolConfiguration as! NETunnelProviderProtocol;flags.excludeLocalNetworks=entryLAN && exitLAN
   let prepared=try owner.prepare(provider:provider,selectedProfile:exit,strict:true),policy=prepared.runtime.policy!,meta=try object(Data(policy.metadata.utf8))
   try check("provider retains exact private entry identity",meta["entry_node_id"] as? String==profiles[0]["node_proof_id"] as? String && meta["dns_detour"] as? String=="external-entry")
   try check("native policy does not report historical Auto MTU",meta["entry_mtu"] as? Int==1500 && meta["configured_mtu"] as? Int==1380)
   var wrong=provider;wrong["tor_entry_bundle"]=provider["external_entry_bundle"]
   reject("mixed Tor and ordinary entry owners"){_ = try owner.prepare(provider:wrong,selectedProfile:exit,strict:true)}
   wrong=provider;wrong["external_entry_mode"]="hysteria2"
   reject("ordinary provider rejects changed captured mode"){_ = try owner.prepare(provider:wrong,selectedProfile:exit,strict:true)}
   profiles[0]["node_proof_id"]=String(repeating:"f",count:64);source["routerProfiles"]=profiles;wrong=provider;wrong["external_entry_bundle"]=try json(source)
   reject("WireGuard private entry key must match paired identity"){_ = try owner.prepare(provider:wrong,selectedProfile:exit,strict:true)}
  }}
 }
 @MainActor static func importedAmneziaCreation()throws {
  let parameters=["jc":"3","jmin":"40","jmax":"900","s1":"56","s2":"48","s3":"24","s4":"32","h1":"10000000-19999999","h2":"20000000-29999999","h3":"30000000-39999999","h4":"40000000-49999999"]
  let model=RouterVPNModel()
  func save(_ p:[String:String],_ keepalive:Int?=29,_ protocolName:String="amneziawg")throws {
   try model.createIOSExternalNode(protocolName:protocolName,name:"Imported AWG",server:"2001:db8::8",port:51820,expectedPublicIP:"203.0.113.88",username:"",password:"",method:"",secret:"",tlsServerName:"",wgPrivateKey:key(11),wgPeerPublicKey:key(12),wgPresharedKey:key(13),wgAddresses:["10.91.0.2/32","fd91::2/128"],wgAllowedIPs:["0.0.0.0/0","::/0"],wgDNS:["9.9.9.9"],wgMTU:1380,wgKeepalive:keepalive,awgParameters:p)
  }
  try save(parameters)
  let saved=model.saved!,writes=model.writes,bundle=try JSONDecoder().decode(ClientBundle.self,from:saved),external=bundle.routerProfiles[0].external!
  try check("AWG node persists distinct exact parameters",external.protocolName=="amneziawg" && external.wireGuard==nil && external.amneziaWG?.parameters==parameters)
  try check("AWG peer credentials and keepalive round trip",external.amneziaWG?.privateKey==key(11) && external.amneziaWG?.peerPublicKey==key(12) && external.amneziaWG?.presharedKey==key(13) && external.amneziaWG?.persistentKeepaliveInterval==29 && external.amneziaWG?.endpoint=="[2001:db8::8]:51820")
  let encoded=try JSONEncoder().encode(bundle),restored=try JSONDecoder().decode(ClientBundle.self,from:encoded)
  try check("bundle serialization retains complete AWG payload",restored.routerProfiles[0].external==external)
  for p in [[:],parameters.merging(["i1":"foreign"],uniquingKeysWith:{$1}),parameters.merging(["jc":"129"],uniquingKeysWith:{$1}),parameters.merging(["s4":" 32"],uniquingKeysWith:{$1}),parameters.merging(["h2":"10000001"],uniquingKeysWith:{$1})] {
   reject("invalid AWG parameters fail native validation before persistence"){try save(p)}
  }
  reject("invalid keepalive cannot save"){try save(parameters,65536)}
  reject("WG does not discard AWG parameters"){try save(parameters,29,"wireguard")}
  try check("invalid AWG creation keeps the complete old source",model.saved==saved && model.writes==writes)
 }
 @MainActor static func responseProbeCreation()throws {
  let model=RouterVPNModel()
  func save(_ url:String,_ name:String="node.example.test",_ kind:String="shadowsocks",_ layer:String="off")throws {
   try model.createIOSExternalNode(protocolName:kind,name:"Response endpoint",server:"198.51.100.8",port:8388,expectedPublicIP:"203.0.113.88",username:" exact user ",password:" exact secret ",method:"aes-256-gcm",secret:" exact SS secret ",tlsServerName:kind=="http-connect" ? "":"exit.example.test",wgPrivateKey:"",wgPeerPublicKey:"",wgPresharedKey:"",wgAddresses:[],wgAllowedIPs:[],wgDNS:[],wgMTU:nil,responseProbeURL:url,responseProbeServerName:name,exitStartLayer:layer,exitLayerAPI:layer=="off" ? "":"http://10.99.0.1:8787",exitLayerPort:layer=="off" ? 0:8388,exitLayerKey:layer=="off" ? "":key(7))
  }
  try save("https://198.51.100.8:9443/response")
  let saved=model.saved!,decoded=try JSONDecoder().decode(ClientBundle.self,from:saved),external=decoded.routerProfiles[0].external!
  try check("native add keeps the exact HTTPS response contract",external.responseProbe?.url=="https://198.51.100.8:9443/response" && external.responseProbe?.serverName=="node.example.test")
  try check("adding response measurement keeps exact private transport",external.shadowsocks?.password==" exact SS secret " && external.shadowsocks?.server=="198.51.100.8")
  try IOSExternalExecution.validateImported(decoded);checks+=1
  let writes=model.writes
  for url in ["http://198.51.100.8/response","https://203.0.113.8/response","https://198.51.100.8/response?secret=x","https://198.51.100.8/response?","https://user:pass@198.51.100.8/response","https://198.51.100.8/%2fresponse"," https://198.51.100.8/response"] {reject("invalid add response is rejected before saving"){try save(url)}}
  reject("IP-dial route cannot replace TLS server-name validation"){try save("https://198.51.100.8/response","localhost")}
  reject("unsupported protocols cannot silently discard response fields"){try save("https://198.51.100.8/response","","tor")}
  try check("failed creation preserves complete previously saved node",model.saved==saved && model.writes==writes)
  try save("","")
  try check("ordinary Local creation still needs no response endpoint",(try JSONDecoder().decode(ClientBundle.self,from:model.saved!)).routerProfiles[0].external?.responseProbe==nil)
  for kind in ["shadowsocks","hysteria2","socks5","http-connect","https-connect"] {for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   try save("https://198.51.100.8:9443/response","node.example.test",kind,layer)
   let restored=try JSONDecoder().decode(ClientBundle.self,from:model.saved!),profile=restored.routerProfiles[0]
   try check("native creation persists every exact external response and Start Layer",profile.external?.responseProbe?.url=="https://198.51.100.8:9443/response" && profile.startLayer==layer && profile.external?.matchesStartLayer(layer)==true)
   if layer != "off" {try check("typed private layer survives import without changing its key",profile.external?.startLayer?.transport.password==key(7))}
   try IOSExternalExecution.validateImported(restored);checks+=1
  }}
 }
 @MainActor static func packetServerPeerCreation()throws {
  let model=RouterVPNModel(),descriptor:[String:Any]=["public_key":"bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg=","addresses":["10.94.0.3/32","fd94::3/128"],"mtu":1360,"persistent_keepalive_interval":25]
  let peerText=String(decoding:try json(descriptor),as:UTF8.self)
  func save(_ kind:String,_ peer:String,_ layer:String="off",_ endpoint:String="198.51.100.8")throws {
   try model.createIOSExternalNode(protocolName:kind,name:"Independent packet peer",server:endpoint,port:51820,expectedPublicIP:"203.0.113.88",username:"",password:"",method:"",secret:"",tlsServerName:"",wgPrivateKey:key(11),wgPeerPublicKey:key(12),wgPresharedKey:key(13),wgAddresses:["10.91.0.2/32","fd91::2/128"],wgAllowedIPs:["0.0.0.0/0","::/0"],wgDNS:[],wgMTU:1280,wgKeepalive:29,awgParameters:kind=="amneziawg" ? ["jc":"3","jmin":"40","jmax":"900","s1":"56","s2":"48","s3":"24","s4":"32","h1":"10000000-19999999","h2":"20000000-29999999","h3":"30000000-39999999","h4":"40000000-49999999"]:[:],responseProbeURL:"https://"+(endpoint.contains(":") ? "["+endpoint+"]":endpoint)+":9443/response",responseProbeServerName:"node.example.test",exitStartLayer:layer,exitLayerAPI:layer=="off" ? "":"http://10.99.0.1:8787",exitLayerPort:layer=="off" ? 0:8388,exitLayerKey:layer=="off" ? "":key(7),serverPeerJSON:peer)
  }
  for kind in ["wireguard","amneziawg"] { for layer in layers {
   try save(kind,peerText,layer)
   let decoded=try JSONDecoder().decode(ClientBundle.self,from:model.saved!),profile=decoded.routerProfiles[0],external=profile.external!
   try check("packet creation retains independent descriptor and local credentials",external.serverPeer?.publicKey==descriptor["public_key"] as? String && external.packetConfiguration?.privateKey==key(11) && external.packetConfiguration?.presharedKey==key(13) && external.serverPeer?.addresses==["10.94.0.3/32","fd94::3/128"] && external.serverPeer?.mtu==1360 && external.serverPeer?.persistentKeepaliveInterval==25)
   try check("packet execution readiness retains exact response and layer",external.authenticatedServerExecution && external.matchesStartLayer(layer) && external.serverExecutionHost=="198.51.100.8")
   try IOSExternalExecution.validateImported(decoded);checks+=1
  }}
  try save("wireguard",peerText,"off","2001:db8::8")
  try check("packet response owns bracketed IPv6 endpoint",(try JSONDecoder().decode(ClientBundle.self,from:model.saved!)).routerProfiles[0].external?.serverExecutionHost=="2001:db8::8")
  let saved=model.saved,writes=model.writes
  for fault in ["private","preshared","null","null-keepalive","low-mtu","high-keepalive","borrowed-local-address","duplicate-family","wrong-families","noncanonical-address","borrowed-local-key","low-order-key","bad-public-key"] {
   var changed=descriptor
   switch fault {
   case "private":changed["private_key"]=key(88)
   case "preshared":changed["preshared_key"]=key(89)
   case "null":changed["public_key"]=NSNull()
   case "null-keepalive":changed["persistent_keepalive_interval"]=NSNull()
   case "low-mtu":changed["mtu"]=1279
   case "high-keepalive":changed["persistent_keepalive_interval"]=65536
   case "borrowed-local-address":changed["addresses"]=["10.91.0.2/32","fd94::3/128"]
   case "duplicate-family":changed["addresses"]=["10.94.0.3/32","10.94.0.4/32"]
   case "wrong-families":changed["addresses"]=["10.94.0.3/32"]
   case "noncanonical-address":changed["addresses"]=["10.94.0.3/32","FD94::3/128"]
   case "borrowed-local-key":changed["public_key"]="c7LYt2qptTZgAyvI9di+46OuTjs6f9Sa3oH3NHo0qmg="
   case "low-order-key":changed["public_key"]=key(0)
   default:changed["public_key"]="invalid"
   }
   let text=String(decoding:try json(changed),as:UTF8.self)
   reject("packet descriptor rejects "+fault){try save("wireguard",text)}
  }
  reject("packet descriptor rejects explicit null"){try save("wireguard","null")}
  try check("invalid server peer never overwrites a saved private node",model.saved==saved && model.writes==writes)
  try save("wireguard","")
  let local=try JSONDecoder().decode(ClientBundle.self,from:model.saved!).routerProfiles[0]
  try check("Local packet node needs no separate server peer",local.external?.serverPeer==nil && local.external?.authenticatedServerExecution==false)
 }
 @MainActor static func openVPNPairingCreation(_ maximum:[String:Any],_ composite:[String:Any])throws {
  let fixtures=try object(Data(contentsOf:URL(fileURLWithPath:ProcessInfo.processInfo.environment["ROUTERVPN_OPENVPN_CLIENT_FIXTURE"]!)))["layers"] as! [String:[String:Any]]
  let base=fixtures["off"]!["external"] as! [String:Any],original=base["openvpn"] as! [String:Any],pair=base["openvpn_pairing"] as! [String:Any]
  let source=original["config"] as! String,username=original["username"] as! String,password=original["password"] as! String
  let pairingText=String(decoding:try json(pair),as:UTF8.self),model=RouterVPNModel()
  let privateBundle=String(decoding:try json(["routerProfiles":[["id":"private-import","external":base]]]),as:UTF8.self)
  try IOSExternalExecution.validatePrivateNodeJSON(Data(privateBundle.utf8));checks+=1
  for raw in ["null","[]",privateBundle+" {}",String(privateBundle.dropLast())+",\"routerProfiles\":[]}",String(privateBundle.dropLast())+",\"extra\":{\"openvpn_pairing\":{\"private_key\":\"one\",\"private_key\":\"two\"}}}"] {
   reject("raw private import rejects ambiguous nested credentials before JSONDecoder"){try IOSExternalExecution.validatePrivateNodeJSON(Data(raw.utf8))}
  }
  var invalidUTF8=Data((String(privateBundle.dropLast())+",\"extra\":\"").utf8);invalidUTF8.append(255);invalidUTF8.append(Data("\"}".utf8))
  reject("raw private import rejects malformed UTF-8"){try IOSExternalExecution.validatePrivateNodeJSON(invalidUTF8)}
  func save(_ text:String,_ layer:String="off",_ config:String?=nil,_ probe:Bool=true)throws {
   let external=fixtures[layer]!["external"] as! [String:Any],provision=external["start_layer"] as? [String:Any],transport=provision?["transport"] as? [String:Any]
   try model.createIOSExternalNode(protocolName:"openvpn",name:"Independent OpenVPN owner",server:"203.0.113.20",port:1194,expectedPublicIP:external["expected_public_ip"] as! String,username:username,password:password,method:"",secret:"",tlsServerName:"",wgPrivateKey:"",wgPeerPublicKey:"",wgPresharedKey:"",wgAddresses:[],wgAllowedIPs:[],wgDNS:[],wgMTU:1280,openVPNConfig:config ?? source,responseProbeURL:probe ? (base["response_probe"] as! [String:Any])["url"] as! String:"",responseProbeServerName:probe ? "provider.example":"",exitStartLayer:layer,exitLayerAPI:provision?["api"] as? String ?? "",exitLayerPort:transport?["server_port"] as? Int ?? 0,exitLayerKey:transport?["password"] as? String ?? "",openVPNPairingJSON:text)
  }
  let entry=try JSONDecoder().decode(ClientBundle.self,from:json(root("wg","off",maximum,composite))).routerProfiles[0]
  for layer in layers {
   try save(pairingText,layer)
   let imported=try JSONDecoder().decode(ClientBundle.self,from:model.saved!),profile=imported.routerProfiles[0],external=profile.external!
   try IOSExternalExecution.validateImported(imported)
   try check("native OpenVPN form preserves exact source, credentials and pairing",external.openVPN?.config==source && external.openVPN?.username==username && external.openVPN?.password==password && external.openVPNPairing?.privateKey==pair["private_key"] as? String && profile.startLayer==layer)
   try check("independent OpenVPN pair is eligible before authenticated acquisition",IOSExternalExecution.eligible(entry:entry,exit:profile))
   let roundtrip=try JSONDecoder().decode(ClientBundle.self,from:JSONEncoder().encode(imported))
   try check("private saved OpenVPN profile roundtrip retains exact descriptor",json(object(JSONEncoder().encode(roundtrip)))==json(object(JSONEncoder().encode(imported))))
  }
  let saved=model.saved,writes=model.writes
  for raw in ["null",pairingText+" {}",String(pairingText.dropLast())+",\"private_key\":\""+(pair["private_key"] as! String)+"\"}",String(pairingText.dropLast())+",\"unknown\":true}"] {
   reject("OpenVPN editor rejects raw duplicate, unknown, null or trailing JSON"){try save(raw)}
  }
  for fault in ["provider-alias","server-private-key","changed-transport","null-server","missing-key"] {
   var changed=pair,server=changed["server"] as! [String:Any]
   if fault=="provider-alias" {server["provider_identity"]=["username":username]}
   if fault=="server-private-key" {server["private_key"]=key(14)}
   if fault=="changed-transport" {var transport=server["transport"] as! [String:Any];transport["auth"]="SHA512";server["transport"]=transport}
   changed["server"]=server;if fault=="null-server" {changed["server"]=NSNull()}
   if fault=="missing-key" {changed.removeValue(forKey:"private_key")}
   reject("OpenVPN editor rejects invalid captured ownership "+fault){try save(String(decoding:json(changed),as:UTF8.self))}
  }
  try check("invalid OpenVPN editor never overwrites a private saved node",model.saved==saved && model.writes==writes)
  try save("","off",source+"remote 203.0.113.21 443 tcp\n",false)
  let local=try JSONDecoder().decode(ClientBundle.self,from:model.saved!).routerProfiles[0]
  try check("plain Local OpenVPN keeps multi-host remotes without pairing",local.external?.openVPN?.config==source+"remote 203.0.113.21 443 tcp\n" && local.external?.openVPNPairing==nil && !IOSExternalExecution.eligible(entry:entry,exit:local))
 }
 @MainActor static func openVPNResponseProbesCreation()throws {
  let fixtures=try object(Data(contentsOf:URL(fileURLWithPath:ProcessInfo.processInfo.environment["ROUTERVPN_OPENVPN_CLIENT_FIXTURE"]!)))["layers"] as! [String:[String:Any]]
  let original=(fixtures["off"]!["external"] as! [String:Any])["openvpn"] as! [String:Any]
  let source=(original["config"] as! String)+"remote 203.0.113.21 443 tcp\n",username=original["username"] as! String,password=original["password"] as! String
  let probes:[String:Any]=["203.0.113.20":["url":"https://203.0.113.20:9443/response","server_name":"first.example.test"],"203.0.113.21":["url":"https://203.0.113.21:9443/response","server_name":"second.example.test"]]
  let text=String(decoding:try json(probes),as:UTF8.self),model=RouterVPNModel()
  func save(_ value:String,_ legacy:String="",_ layer:String="off")throws {
   try model.createIOSExternalNode(protocolName:"openvpn",name:"Private remote map",server:"203.0.113.20",port:1194,expectedPublicIP:"203.0.113.88",username:username,password:password,method:"",secret:"",tlsServerName:"",wgPrivateKey:"",wgPeerPublicKey:"",wgPresharedKey:"",wgAddresses:[],wgAllowedIPs:[],wgDNS:[],wgMTU:1280,openVPNConfig:source,responseProbeURL:legacy,exitStartLayer:layer,openVPNResponseProbesJSON:value)
  }
  try save(text)
  let imported=try JSONDecoder().decode(ClientBundle.self,from:model.saved!),external=imported.routerProfiles[0].external!
  try IOSExternalExecution.validateImported(imported)
  try check("OpenVPN maker retains exact multi-host source and private response map",external.openVPN?.config==source && external.openVPN?.username==username && external.openVPN?.password==password && external.responseProbe==nil && external.openVPNResponseProbes?.count==2 && external.openVPNResponseProbes?["203.0.113.21"]?.serverName=="second.example.test")
  let roundtrip=try JSONDecoder().decode(ClientBundle.self,from:JSONEncoder().encode(imported))
  try check("OpenVPN private Codable roundtrip preserves every response endpoint",roundtrip.routerProfiles[0].external==external)
  var profile=(try object(model.saved!)["routerProfiles"] as! [[String:Any]])[0]
  profile["dns_mode"]="custom";profile["dns_protocol"]="tcp";profile["dns_host"]="9.9.9.9";profile["dns_port"]=5353;profile["mtu_policy"]="fixed";profile["manual_mtu"]=1280;profile["ipv6_mode"]="on";profile["home_lan_access"]=false
  let runtime=try RouterVPNExternalExitBuilder.build(profile:profile),capture=try object(Data(runtime.policy!.capture.utf8)),metadata=try object(Data(runtime.policy!.metadata.utf8))
  let captured=(capture["profile"] as! [String:Any])["external"] as! [String:Any]
  let expectedOriginal=(profile["external"] as! [String:Any])["openvpn"]!
  try check("PacketTunnel capture preserves private per-remote response identity",json(captured["openvpn_response_probes"]!)==json(probes) && json(captured["openvpn"]!)==json(expectedOriginal))
  try check("public external policy metadata omits map and certificate names",metadata["openvpn_response_probes"]==nil && !runtime.policy!.metadata.contains("first.example.test") && !runtime.policy!.metadata.contains("second.example.test"))
  let saved=model.saved,writes=model.writes
  let duplicate="{\"203.0.113.20\":{\"url\":\"https://203.0.113.20/first\"},\"203.0.113.20\":{\"url\":\"https://203.0.113.20/second\"},\"203.0.113.21\":{\"url\":\"https://203.0.113.21/response\"}}"
  let escapedAlias=duplicate.replacingOccurrences(of:"\"203.0.113.20\":{\"url\":\"https://203.0.113.20/second",with:"\"203.0.113.\\u0032\\u0030\":{\"url\":\"https://203.0.113.20/second")
  for raw in ["null","[]","{}",text+" {}",duplicate,escapedAlias,String(text.dropLast())+",\"203.0.113.22\":{\"url\":\"https://203.0.113.22/extra\"}}",String(repeating:" ",count:40*1024)+text] {
   reject("raw OpenVPN response map rejects ambiguity, wrong shape or bound"){try save(raw)}
  }
  for fault in ["missing-host","extra-field","null-name","wrong-host","http","private-host","uncovered-host"] {
   var changed=probes
   switch fault {
   case "missing-host":changed.removeValue(forKey:"203.0.113.21")
   case "extra-field":changed["203.0.113.20"]=["url":"https://203.0.113.20/response","password":"hidden"]
   case "null-name":changed["203.0.113.20"]=["url":"https://203.0.113.20/response","server_name":NSNull()]
   case "wrong-host":changed["203.0.113.20"]=["url":"https://203.0.113.21/response"]
   case "http":changed["203.0.113.20"]=["url":"http://203.0.113.20/response"]
   case "private-host":changed.removeValue(forKey:"203.0.113.21");changed["192.168.50.1"]=["url":"https://192.168.50.1/response"]
   default:changed.removeValue(forKey:"203.0.113.21");changed["203.0.113.22"]=["url":"https://203.0.113.22/response"]
   }
   reject("OpenVPN response map rejects "+fault){try save(String(decoding:json(changed),as:UTF8.self))}
  }
  reject("single and per-remote response contracts are mutually exclusive"){try save(text,"https://203.0.113.20/response")}
  reject("multi-host map cannot silently borrow the first host's Start Layer"){try save(text,"","aes-256-gcm")}
  var malformed=profile,block=profile["external"] as! [String:Any]
  block["openvpn_response_probes"]=["203.0.113.20":["url":"https://203.0.113.20/response","unknown":true],"203.0.113.21":["url":"https://203.0.113.21/response"]];malformed["external"]=block
  reject("typed import does not erase unknown probe fields before native validation"){_ = try JSONDecoder().decode(RouterProfile.self,from:json(malformed))}
  block["openvpn_response_probes"]=NSNull();malformed["external"]=block
  reject("typed import rejects explicit null map"){_ = try JSONDecoder().decode(RouterProfile.self,from:json(malformed))}
  block["openvpn_response_probes"]=probes;block["response_probe"]=NSNull();malformed["external"]=block
  reject("typed import cannot collapse an explicit null legacy probe beside a remote map"){_ = try JSONDecoder().decode(RouterProfile.self,from:json(malformed))}
  let rawBundle="{\"routerProfiles\":[{\"external\":{\"openvpn_response_probes\":"+duplicate+"}}]}"
  reject("whole private import rejects duplicate response hosts before Codable"){try IOSExternalExecution.validatePrivateNodeJSON(Data(rawBundle.utf8))}
  try check("invalid response maps never overwrite the saved private node",model.saved==saved && model.writes==writes)
  let paired=try object(Data(contentsOf:URL(fileURLWithPath:ProcessInfo.processInfo.environment["ROUTERVPN_OPENVPN_MULTIHOST_CLIENT_FIXTURE"]!)))["external"] as! [String:Any]
  let pairedOriginal=paired["openvpn"] as! [String:Any],pairedMap=paired["openvpn_response_probes"] as! [String:Any],pairedOwner=paired["openvpn_pairing"] as! [String:Any]
  try model.createIOSExternalNode(protocolName:"openvpn",name:"Paired multi-host private map",server:"203.0.113.20",port:1194,expectedPublicIP:paired["expected_public_ip"] as! String,username:pairedOriginal["username"] as! String,password:pairedOriginal["password"] as! String,method:"",secret:"",tlsServerName:"",wgPrivateKey:"",wgPeerPublicKey:"",wgPresharedKey:"",wgAddresses:[],wgAllowedIPs:[],wgDNS:[],wgMTU:1280,openVPNConfig:pairedOriginal["config"] as! String,openVPNPairingJSON:String(decoding:json(pairedOwner),as:UTF8.self),openVPNResponseProbesJSON:String(decoding:json(pairedMap),as:UTF8.self))
  let pairedSaved=(try object(model.saved!)["routerProfiles"] as! [[String:Any]])[0]["external"] as! [String:Any]
  try check("private paired fixture survives maker with exact independent descriptors",json(pairedSaved)==json(paired))
 }
 @MainActor static func openVPNStartLayersCreation()throws {
  for (name,mode) in [("AES","aes-256-gcm"),("XOR","aes-256-gcm+xor-whitening")] {
   let fixture=try object(Data(contentsOf:URL(fileURLWithPath:ProcessInfo.processInfo.environment["ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_"+name+"_FIXTURE"]!))),external=fixture["external"] as! [String:Any],source=external["openvpn"] as! [String:Any],map=external["openvpn_start_layers"] as! [String:[String:Any]]
   let original=try JSONDecoder().decode(ExternalOpenVPNConfig.self,from:json(source)),probes=try JSONDecoder().decode([String:ExternalResponseProbe].self,from:json(external["openvpn_response_probes"]!)),text=String(decoding:try json(map),as:UTF8.self)
   let decoded=try IOSExternalExecution.openVPNStartLayers(text,profile:original,probes:probes,selectedMode:mode)
   try check("raw native binding retains both private layer owners",decoded?.count==2 && decoded?["203.0.113.20"]?.api==decoded?["203.0.113.21"]?.api && decoded?["203.0.113.20"]?.transport.password != decoded?["203.0.113.21"]?.transport.password)
   let duplicate=String(text.dropLast())+",\"203.0.113.20\":"+String(decoding:try json(map["203.0.113.20"]!),as:UTF8.self)+"}"
   for raw in ["null","{}","[]",text+" {}",duplicate,String(repeating:" ",count:128*1024)+text] {
    reject("raw per-remote Start Layers reject ambiguity, malformed shape and size"){_ = try IOSExternalExecution.openVPNStartLayers(raw,profile:original,probes:probes,selectedMode:mode)}
   }
   for fault in ["missing","foreign","wrong-server","mode","unknown","null","off"] {
    var changed=map,record=map["203.0.113.20"]!,transport=record["transport"] as! [String:Any]
    if fault=="missing"{changed.removeValue(forKey:"203.0.113.20")}
    if fault=="foreign"{changed.removeValue(forKey:"203.0.113.20");changed["203.0.113.99"]=record}
    if fault=="wrong-server"{transport["server"]="203.0.113.99";record["transport"]=transport;changed["203.0.113.20"]=record}
    if fault=="mode"{record["mode"]=mode=="aes-256-gcm" ? "aes-256-gcm+xor-whitening":"aes-256-gcm";changed["203.0.113.20"]=record}
    if fault=="unknown"{record["script"]="unowned";changed["203.0.113.20"]=record}
    if fault=="null"{record["api"]=NSNull();changed["203.0.113.20"]=record}
    reject("per-remote layer selection rejects "+fault){_ = try IOSExternalExecution.openVPNStartLayers(String(decoding:json(changed),as:UTF8.self),profile:original,probes:probes,selectedMode:fault=="off" ? "off":mode)}
   }
   let model=RouterVPNModel()
   func save(_ layerText:String,_ api:String="")throws {
    try model.createIOSExternalNode(protocolName:"openvpn",name:"Per-remote layers",server:"203.0.113.20",port:1194,expectedPublicIP:external["expected_public_ip"] as! String,username:original.username ?? "",password:original.password ?? "",method:"",secret:"",tlsServerName:"",wgPrivateKey:"",wgPeerPublicKey:"",wgPresharedKey:"",wgAddresses:[],wgAllowedIPs:[],wgDNS:[],wgMTU:1280,openVPNConfig:original.config,exitStartLayer:mode,exitLayerAPI:api,openVPNPairingJSON:String(decoding:json(external["openvpn_pairing"]!),as:UTF8.self),openVPNResponseProbesJSON:String(decoding:json(external["openvpn_response_probes"]!),as:UTF8.self),openVPNStartLayersJSON:layerText)
   }
   try save(text)
   let saved=model.saved!,writes=model.writes,bundle=try JSONDecoder().decode(ClientBundle.self,from:saved),profile=bundle.routerProfiles[0]
   try check("maker captures every original remote and exact private layer provision",profile.startLayer==mode && profile.external?.openVPNStartLayers==decoded && profile.external?.openVPN==original && profile.external?.startLayer==nil && profile.external?.responseProbe==nil)
   try IOSExternalExecution.validateImported(bundle)
   let providerProfile=try object(JSONEncoder().encode(profile))
   try IOSStartLayer.validateExternal(profile:providerProfile)
   try check("PacketTunnel accepts the exact captured per-remote layer map",true)
   for fault in ["off","missing-probes","singular-layer-null","singular-probe-null","foreign-map","changed-server","changed-mode"] {
    var changed=providerProfile,block=changed["external"] as! [String:Any],layers=block["openvpn_start_layers"] as! [String:[String:Any]]
    if fault=="off"{changed["start_layer"]="off"}
    if fault=="missing-probes"{block.removeValue(forKey:"openvpn_response_probes")}
    if fault=="singular-layer-null"{block["start_layer"]=NSNull()}
    if fault=="singular-probe-null"{block["response_probe"]=NSNull()}
    if fault=="foreign-map"{layers["203.0.113.99"]=layers.removeValue(forKey:"203.0.113.21")}
    if fault=="changed-server"{var remote=layers["203.0.113.21"]!,transport=remote["transport"] as! [String:Any];transport["server"]="203.0.113.20";remote["transport"]=transport;layers["203.0.113.21"]=remote}
    if fault=="changed-mode"{var remote=layers["203.0.113.21"]!;remote["mode"]=mode=="aes-256-gcm" ? "aes-256-gcm+xor-whitening":"aes-256-gcm";layers["203.0.113.21"]=remote}
    block["openvpn_start_layers"]=layers;changed["external"]=block
    reject("PacketTunnel rejects ambiguous or unowned per-remote layer "+fault){try IOSStartLayer.validateExternal(profile:changed)}
   }
   let roundtrip=try JSONDecoder().decode(ClientBundle.self,from:JSONEncoder().encode(bundle))
   try check("private Codable roundtrip preserves layered remote map",roundtrip.routerProfiles[0].external==profile.external)
   reject("per-remote layer maker cannot borrow a singular service address"){try save(text,"http://10.93.0.1:8787")}
   reject("selected multi-host encryption cannot lose its private map"){try save("")}
   try check("invalid layered creation leaves saved node untouched",model.saved==saved && model.writes==writes)
   var invalid=try object(saved),rows=invalid["routerProfiles"] as! [[String:Any]],block=rows[0]["external"] as! [String:Any]
   block["openvpn_start_layers"]=NSNull();rows[0]["external"]=block;invalid["routerProfiles"]=rows
   reject("private imported per-remote layer null is not absence"){_ = try JSONDecoder().decode(ClientBundle.self,from:json(invalid))}
   block["openvpn_start_layers"]=map;block["start_layer"]=NSNull();rows[0]["external"]=block;invalid["routerProfiles"]=rows
   reject("private imported singular-layer null is not absence"){_ = try JSONDecoder().decode(ClientBundle.self,from:json(invalid))}
   let raw="{\"routerProfiles\":[{\"external\":{\"openvpn_start_layers\":"+duplicate+"}}]}"
   reject("raw imported layer map cannot collapse duplicate providers"){try IOSExternalExecution.validatePrivateNodeJSON(Data(raw.utf8))}
  }
 }
 @MainActor static func ordinaryExternalPredecessors(_ maximum:[String:Any],_ composite:[String:Any])throws {
  let pairingFixtures=try object(Data(contentsOf:URL(fileURLWithPath:ProcessInfo.processInfo.environment["ROUTERVPN_OPENVPN_CLIENT_FIXTURE"]!)))["layers"] as! [String:[String:Any]]
  let mappedOpenVPN=try object(Data(contentsOf:URL(fileURLWithPath:ProcessInfo.processInfo.environment["ROUTERVPN_OPENVPN_MULTIHOST_CLIENT_FIXTURE"]!)))["external"] as! [String:Any]
  let mappedAES=try object(Data(contentsOf:URL(fileURLWithPath:ProcessInfo.processInfo.environment["ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_AES_FIXTURE"]!)))["external"] as! [String:Any]
  let mappedXOR=try object(Data(contentsOf:URL(fileURLWithPath:ProcessInfo.processInfo.environment["ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_XOR_FIXTURE"]!)))["external"] as! [String:Any]
  let protocols=["wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn"]
  var failures:[String]=[]
  for mode in modes {for layer in layers {
   var entry=try root(mode,layer,maximum,composite),profiles=entry["routerProfiles"] as! [[String:Any]]
   if ["wg","awg2-fast","awg2-strong","wg-pq","awg2-pq"].contains(mode) || IOSNativeMAXProfile.modeIDs.contains(mode) {
    profiles[0]["manual_mtu"]=1500;entry["routerProfiles"]=profiles
   }
   let profile=profiles[0]
   let owner=ProviderPreparation(),originalFiles=try owner.entry(entry,mode),previous=try object(originalFiles["sing-box.json"]!)
   let oldFinal=(previous["route"] as! [String:Any])["final"] as! String
   let packetEntry=["wireguard","routervpn-amneziawg","routervpn-pq"].contains(try tagged(previous,oldFinal)["type"] as? String ?? "")
   for kind in protocols {
    do {
     let model=RouterVPNModel()
     let exitMTU=["wireguard","amneziawg","openvpn"].contains(kind) && packetEntry ? 1280:1380
     let openVPN="client\ndev tun\nproto udp\nremote 198.51.100.8 1194\nremote 198.51.100.9 443 tcp\nremote-random\nauth-user-pass\nremote-cert-tls server\npeer-fingerprint "+String(repeating:"ab",count:32)+"\n"
     try model.createIOSExternalNode(protocolName:kind,name:"Captured ordinary exit",server:"198.51.100.8",port:kind=="wireguard" ? 51820:8443,expectedPublicIP:"203.0.113.88",username:" exact user ",password:" exact password ",method:"aes-256-gcm",secret:" exact transport secret ",tlsServerName:kind=="http-connect" ? "":"exit.example.test",wgPrivateKey:key(11),wgPeerPublicKey:key(12),wgPresharedKey:key(13),wgAddresses:["10.91.0.2/32","fd91::2/128"],wgAllowedIPs:["0.0.0.0/0","::/0"],wgDNS:[],wgMTU:exitMTU,openVPNConfig:kind=="openvpn" ? openVPN:"",wgKeepalive:29,awgParameters:kind=="amneziawg" ? ["jc":"3","jmin":"40","jmax":"900","s1":"56","s2":"48","s3":"24","s4":"32","h1":"10000000-19999999","h2":"20000000-29999999","h3":"30000000-39999999","h4":"40000000-49999999"]:[:])
     var exit=(try object(model.saved!)["routerProfiles"] as! [[String:Any]])[0]
     try check("every new ordinary protocol retains Home DNS and IPv6 defaults",exit["dns_mode"] as? String=="home" && exit["ipv6_mode"] as? String=="on" && exit["home_lan_access"]==nil)
     reject("new ordinary Home draft is not a runnable direct connection"){_ = try RouterVPNExternalExitBuilder.build(profile:exit)}
     exit["multihop_enabled"]=true;exit["multihop_entry_id"]="entry";exit["multihop_entry_mode"]=mode;exit["multihop_exit_id"]=exit["id"];exit["multihop_exit_mode"]=kind;exit["multihop_execution"]="local"
     exit["dns_mode"]="custom";exit["dns_protocol"]="tcp";exit["dns_host"]="9.9.9.9";exit["dns_port"]=5353;exit["mtu_policy"]="fixed";exit["manual_mtu"]=exitMTU;exit["home_lan_access"]=false;exit["ipv6_mode"]="on"
     let frozen=try json(exit),provider:[String:Any]=["external_entry_bundle":try json(entry),"external_entry_mode":mode]
     if ["wireguard","amneziawg","openvpn"].contains(kind) && packetEntry {
      var oversized=exit;oversized["manual_mtu"]=1500
      reject("nested fixed MTU cannot overwrite or exceed its entry"){_ = try owner.prepare(provider:provider,selectedProfile:oversized,strict:true)}
     }
     let prepared=try owner.prepare(provider:provider,selectedProfile:exit,strict:true),policy=prepared.runtime.policy!
     let capture=try object(Data(policy.capture.utf8)),source=try object(Data(policy.sourceConfig.utf8)),graph=try object(Data(policy.config.utf8)),meta=try object(Data(policy.metadata.utf8))
     try check("complete entry graph captured byte for byte",capture["predecessor_config"] as? String==String(decoding:originalFiles["sing-box.json"]!,as:UTF8.self) && json(capture["entry"]!)==json(profile))
     try check("uncomposed source remains only the selected exit",(source["endpoints"] as! [[String:Any]]).count+(source["outbounds"] as! [[String:Any]]).count==1 && tagged(source,"custom-exit")["detour"]==nil)
     try check("shared native compiler connects final exit to full entry",tagged(graph,"custom-exit")["detour"] as? String=="external-entry" && (graph["inbounds"] as! [[String:Any]]).count==1)
     if kind=="openvpn" {let endpoint=try tagged(graph,"custom-exit");try check("unpaired Local OpenVPN keeps distinct remotes and original credentials",(endpoint["servers"] as? [[String:Any]])?.count==2 && endpoint["username"] as? String==" exact user " && endpoint["password"] as? String==" exact password " && ((capture["profile"] as! [String:Any])["external"] as! [String:Any])["openvpn_pairing"]==nil)}
     try check("exact entry family remains",tagged(graph,"external-entry")["type"] as? String==tagged(previous,oldFinal)["type"] as? String)
     try check("the shared TUN retains the selected fixed MTU",meta["configured_mtu"] as? Int==exitMTU)
     for family in ["endpoints","outbounds"] {
      let before=previous[family] as? [[String:Any]] ?? [],after=(graph[family] as? [[String:Any]] ?? []).filter{($0["tag"] as? String ?? "").hasPrefix("external-entry")}
      try check("all encrypted entry owners retained",before.count==after.count)
      for (original,retained) in zip(before,after) {
       for key in original.keys where !["tag","detour","tcp","udp","domain_resolver"].contains(key) {
        try check("entry cryptography and native configuration unchanged",json(["value":original[key]!])==json(["value":retained[key] ?? NSNull()]))
       }
       for key in ["detour","tcp","udp"] where original[key] != nil {
        guard let tag=retained[key] as? String else{throw NSError(domain:"MissingExternalPredecessorEdge",code:1)}
        _=try tagged(graph,tag);checks+=1
       }
      }
     }
     let oldServices=previous["services"] as? [[String:Any]] ?? [],newServices=graph["services"] as? [[String:Any]] ?? []
     try check("requested padding services retained",oldServices.count==newServices.count && !oldServices.isEmpty)
     for (original,retained) in zip(oldServices,newServices) {for key in original.keys where !["tag","proof_tag","packet_tag"].contains(key) {
      try check("padding identity target and rate stay owned",json(["value":original[key]!])==json(["value":retained[key] ?? NSNull()]))
     }}
     for (name,data) in originalFiles where name != "sing-box.json" {try check("auxiliary private files retain exact bytes",prepared.runtime.files[name]==data)}
     let dns=(graph["dns"] as! [String:Any])["servers"] as! [[String:Any]],selected=dns.first{$0["tag"] as? String=="selected-dns"}!
     try check("DNS selection and IPv6 policy remain captured",selected["type"] as? String=="tcp" && selected["server_port"] as? Int==5353 && selected["detour"] as? String=="custom-exit" && meta["ipv6_mode"] as? String=="off")
     try check("source entry and exit policies stay frozen",json(exit)==frozen && json(capture["entry"]!)==json(profile))
     if ExternalNodeConfig.serverExecutionProtocols.contains(kind) {
      for execution in ["server","auto"] {
       var selected=exit,external=selected["external"] as! [String:Any]
       external["response_probe"]=["url":"https://198.51.100.8:9443/response","server_name":"external.example.test"]
       if kind=="openvpn" {external=pairingFixtures["off"]!["external"] as! [String:Any];selected["endpoint"]="203.0.113.20:1194"}
       if ExternalNodeConfig.packetProtocols.contains(kind) { external["server_peer"]=["public_key":"bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg=","addresses":["10.94.0.3/32","fd94::3/128"],"mtu":max(1360,exitMTU),"persistent_keepalive_interval":25] }
       selected["external"]=external;selected["multihop_execution"]=execution
       var launch=provider;launch["engine"]="external-libbox";launch["mode"]="external-"+kind
       launch["bundle"]=try json(["selectedRouterID":selected["id"]!,"routerProfiles":[selected]])
       owner.multihopExecutionSource=try IOSMultihopExecution.Source(configuration:launch) { SHA256.hash(data:$0).map{String(format:"%02x",$0)}.joined() }
       defer {owner.multihopExecutionSource=nil}
       let built=try owner.prepare(provider:launch,selectedProfile:selected,strict:true).runtime.policy!
       let graph=try object(Data(built.config.utf8)),captured=try object(Data(built.capture.utf8))
       try check("Server/Compare retains entire native entry mode and Start Layer",captured["predecessor_config"] as? String==String(decoding:originalFiles["sing-box.json"]!,as:UTF8.self) && json(captured["entry"]!)==json(profile))
       try check("Server/Compare owns real local transport and selector",tagged(graph,"routervpn-execution-local")["type"] as? String==(kind=="socks5" ? "socks" : kind=="amneziawg" ? "routervpn-amneziawg" : kind=="openvpn" ? "openvpn-client" : ["http-connect","https-connect"].contains(kind) ? "http" : kind) && tagged(graph,"routervpn-execution-local")["detour"] as? String=="external-entry" && tagged(graph,"custom-exit")["type"] as? String=="selector")
       if kind=="openvpn" {let endpoint=try tagged(graph,"routervpn-execution-local"),original=external["openvpn"] as! [String:Any],privateCapture=(captured["profile"] as! [String:Any])["external"] as! [String:Any];try check("OpenVPN comparison preserves Local credentials, remote list and private pairing",(endpoint["servers"] as? [[String:Any]])?.count==2 && endpoint["username"] as? String==original["username"] as? String && endpoint["password"] as? String==original["password"] as? String && json(privateCapture["openvpn_pairing"]!)==json(external["openvpn_pairing"]!) && json(privateCapture["openvpn"]!)==json(original));try check("OpenVPN pairing stays out of public metadata",!built.metadata.contains(original["password"] as! String) && !built.metadata.contains((external["openvpn_pairing"] as! [String:Any])["private_key"] as! String))}
       try check("external execution leaves entry graph cryptography intact",tagged(graph,"external-entry")["type"] as? String==tagged(previous,oldFinal)["type"] as? String && built.executionRequested==execution)
       if let output=ProcessInfo.processInfo.environment["ROUTERVPN_IOS_EXTERNAL_GRAPHS"] {
        let file=URL(fileURLWithPath:output).appendingPathComponent(mode+"-"+layer+"-"+kind+"-"+execution+".json")
        try Data(built.config.utf8).write(to:file,options:.withoutOverwriting)
       }
       executionGraphs+=1
      }
     }
     if kind=="openvpn" {
      for exitLayer in layers { for execution in ["local","server","auto"] {
       let mappedOpenVPN=exitLayer=="off" ? mappedOpenVPN : exitLayer=="aes-256-gcm" ? mappedAES : mappedXOR
       var selected=exit
       selected["external"]=mappedOpenVPN;selected["endpoint"]="203.0.113.20:1194";selected["multihop_execution"]=execution;selected["start_layer"]=exitLayer
       let frozen=try json(selected),entryProfile=try JSONDecoder().decode(RouterProfile.self,from:json(profile)),exitProfile=try JSONDecoder().decode(RouterProfile.self,from:frozen)
       try IOSExternalExecution.require(selection:execution,entry:entryProfile,exit:exitProfile)
       var launch=provider;launch["engine"]="external-libbox";launch["mode"]="external-openvpn"
       launch["bundle"]=try json(["selectedRouterID":selected["id"]!,"routerProfiles":[selected]])
       owner.multihopExecutionSource = execution=="local" ? nil : try IOSMultihopExecution.Source(configuration:launch) { SHA256.hash(data:$0).map{String(format:"%02x",$0)}.joined() }
       defer {owner.multihopExecutionSource=nil}
       let built=try owner.prepare(provider:launch,selectedProfile:selected,strict:true).runtime.policy!
       let graph=try object(Data(built.config.utf8)),captured=try object(Data(built.capture.utf8)),local=try tagged(graph,execution=="local" ? "custom-exit" : "routervpn-execution-local")
       let capturedExternal=(captured["profile"] as! [String:Any])["external"] as! [String:Any],original=mappedOpenVPN["openvpn"] as! [String:Any]
       try check("mapped OpenVPN retains complete entry mode and independent Start Layer",captured["predecessor_config"] as? String==String(decoding:originalFiles["sing-box.json"]!,as:UTF8.self) && json(captured["entry"]!)==json(profile))
       try check("mapped OpenVPN retains both physical remotes and local credentials",local["type"] as? String=="openvpn-client" && (local["servers"] as? [[String:Any]])?.count==2 && local["detour"] as? String==(exitLayer=="off" ? "external-entry":"routervpn-exit-start-layer-map") && local["username"] as? String==original["username"] as? String && local["password"] as? String==original["password"] as? String)
       try check("mapped OpenVPN capture keeps exact private response and pairing contracts",json(capturedExternal)==json(mappedOpenVPN) && json(selected)==frozen)
       let originalEndpoint=try IOSExternalExecution.openVPNEndpoint(exitProfile.external!),originalRemotes=originalEndpoint["servers"] as! [[String:Any]]
       try check("per-remote encryption retains original OpenVPN remote order and identity",json(local["servers"]!)==json(originalRemotes))
       if exitLayer != "off" {
        let mapper=try tagged(graph,"routervpn-exit-start-layer-map"),map=mappedOpenVPN["openvpn_start_layers"] as! [String:[String:Any]],remotes=mapper["remotes"] as! [[String:Any]]
        try check("native per-remote mapper owns exact provisioned layers and captured entry",mapper["type"] as? String=="routervpn-openvpn-layer-map" && mapper["mode"] as? String==exitLayer && mapper["detour"] as? String=="external-entry" && json(mapper["layers"]!)==json(map) && remotes.count==originalRemotes.count)
        for (index,remote) in remotes.enumerated(){let original=originalRemotes[index],network=(original["network"] as! String).hasPrefix("tcp") ? "tcp":"udp";try check("native mapper preserves original host, port and protocol",remote["host"] as? String==original["server"] as? String && remote["port"] as? Int==original["server_port"] as? Int && remote["network"] as? String==network)}
        for value in map.values {try check("per-remote AES keys remain private",!built.metadata.contains((value["transport"] as! [String:Any])["password"] as! String))}
       }
       try check("mapped OpenVPN does not expose private probes or pairing",!built.metadata.contains("openvpn_response_probes") && !built.metadata.contains("provider.example") && !built.metadata.contains(original["password"] as! String) && !built.metadata.contains((mappedOpenVPN["openvpn_pairing"] as! [String:Any])["private_key"] as! String))
       try check("mapped OpenVPN selection reaches native execution owner",execution=="local" ? built.executionRequested==nil : built.executionRequested==execution && tagged(graph,"custom-exit")["type"] as? String=="selector")
       if let output=ProcessInfo.processInfo.environment["ROUTERVPN_IOS_EXTERNAL_GRAPHS"] {
        let file=URL(fileURLWithPath:output).appendingPathComponent(mode+"-"+layer+"-openvpn-mapped-"+(exitLayer=="off" ? "":"exit-"+exitLayer+"-")+execution+".json")
        try Data(built.config.utf8).write(to:file,options:.withoutOverwriting)
       }
       if exitLayer=="off" {mappedOpenVPNGraphs+=1}else{mappedOpenVPNLayerGraphs+=1}
      }}
     }
     if mode=="wg" && ExternalNodeConfig.serverExecutionProtocols.contains(kind) {
      for exitLayer in ["aes-256-gcm","aes-256-gcm+xor-whitening"] { for execution in ["local","server","auto"] {
       var selected=exit,external=selected["external"] as! [String:Any]
       external["response_probe"]=["url":"https://198.51.100.8:9443/response","server_name":"external.example.test"]
       if kind=="openvpn" {external=pairingFixtures["off"]!["external"] as! [String:Any];selected["endpoint"]="203.0.113.20:1194"}
       if ExternalNodeConfig.packetProtocols.contains(kind) { external["server_peer"]=["public_key":"bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg=","addresses":["10.94.0.3/32","fd94::3/128"],"mtu":max(1360,exitMTU),"persistent_keepalive_interval":25] }
       let physicalServer=kind=="openvpn" ? "203.0.113.20" : "198.51.100.8"
       external["start_layer"]=["mode":exitLayer,"api":"http://10.99.0.1:8787","transport":["type":"shadowsocks","tag":"provisioned-exit-layer","server":physicalServer,"server_port":8388,"method":"2022-blake3-aes-256-gcm","password":key(7)]]
       selected["external"]=external;selected["start_layer"]=exitLayer;selected["multihop_execution"]=execution
       let frozen=try json(selected)
       var launch=provider;launch["engine"]="external-libbox";launch["mode"]="external-"+kind
       launch["bundle"]=try json(["selectedRouterID":selected["id"]!,"routerProfiles":[selected]])
       owner.multihopExecutionSource = execution=="local" ? nil : try IOSMultihopExecution.Source(configuration:launch) { SHA256.hash(data:$0).map{String(format:"%02x",$0)}.joined() }
       defer {owner.multihopExecutionSource=nil}
       let built=try owner.prepare(provider:launch,selectedProfile:selected,strict:true).runtime.policy!,graph=try object(Data(built.config.utf8))
       let local=try tagged(graph,execution=="local" ? "custom-exit" : "routervpn-execution-local"),wrapper=try tagged(graph,"routervpn-exit-start-layer")
       let localServer=ExternalNodeConfig.packetProtocols.contains(kind) ? (local["peers"] as? [[String:Any]])?.first?["address"] as? String : kind=="openvpn" ? (local["servers"] as? [[String:Any]])?.first?["server"] as? String : local["server"] as? String
       try check("independent entry and exit layers retain owned routing",localServer=="10.99.0.1" && local["detour"] as? String=="routervpn-exit-start-layer" && wrapper["detour"] as? String=="external-entry")
       try check("the exit layer retains its selected protocol and server",wrapper["type"] as? String==(exitLayer=="aes-256-gcm" ? "shadowsocks" : "routervpn-aes-xor") && wrapper["server"] as? String==physicalServer && json(selected)==frozen)
       if let output=ProcessInfo.processInfo.environment["ROUTERVPN_IOS_EXTERNAL_GRAPHS"] {
        let file=URL(fileURLWithPath:output).appendingPathComponent(mode+"-"+layer+"-"+kind+"-exit-"+exitLayer+"-"+execution+".json")
        try Data(built.config.utf8).write(to:file,options:.withoutOverwriting)
       }
       externalLayerGraphs+=1
      }}
     }
     if let output=ProcessInfo.processInfo.environment["ROUTERVPN_IOS_EXTERNAL_GRAPHS"] {
      let file=URL(fileURLWithPath:output).appendingPathComponent(mode+"-"+layer+"-"+kind+".json")
      try prepared.runtime.files["sing-box.json"]!.write(to:file,options:.withoutOverwriting)
     }
     externalGraphs+=1
    }catch{failures.append(mode+"/"+layer+"/"+kind+": "+error.localizedDescription)}
   }
  }}
  if !failures.isEmpty{throw NSError(domain:"OrdinaryExternalMatrix",code:1,userInfo:[NSLocalizedDescriptionKey:failures.joined(separator:"\n")])}
  try check("every full Router entry mode and layer composes with every ordinary exit",externalGraphs==456)
  try check("every native Router entry and Start Layer has an external execution owner",executionGraphs==912 && externalLayerGraphs==144)
  try check("every Router entry and layer retains mapped OpenVPN Local, Server and Compare",mappedOpenVPNGraphs==171 && mappedOpenVPNLayerGraphs==342)
 }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--padding-output', type=Path)
    parser.add_argument('--padding-only', action='store_true')
    parser.add_argument('--entry-output', type=Path)
    parser.add_argument('--entry-only', action='store_true')
    parser.add_argument('--openvpn-probes-only', action='store_true')
    args = parser.parse_args()
    if args.padding_only and (args.output or args.entry_output or args.entry_only or args.openvpn_probes_only):
        raise ValueError('--padding-only cannot produce unrelated graph evidence')
    if args.padding_output and (args.entry_only or args.openvpn_probes_only or EXTRA_EVIDENCE_SOURCES):
        raise ValueError('--padding-output requires the complete Local padding fixture')
    if args.openvpn_probes_only and (args.output or args.entry_output or args.entry_only or os.environ.get('ROUTERVPN_IOS_EXTERNAL_GRAPHS')):
        raise ValueError('--openvpn-probes-only cannot produce complete graph evidence')
    if args.entry_only and args.output:
        raise ValueError('--entry-only cannot produce complete Tor graph evidence')
    external_output = os.environ.get('ROUTERVPN_IOS_EXTERNAL_GRAPHS')
    if external_output is not None:
        destination = Path(external_output)
        if not external_output or not destination.is_dir() or destination.is_symlink() or any(destination.iterdir()):
            raise ValueError('ROUTERVPN_IOS_EXTERNAL_GRAPHS must name an existing empty owned directory')
        if args.entry_only:
            raise ValueError('--entry-only cannot produce final external graphs')
    for tool in ('go', 'swiftc'):
        if not shutil.which(tool):
            raise RuntimeError(tool + ' is required')
    if args.output and (not args.output.is_dir() or any(args.output.iterdir()) or args.output.is_symlink()):
        raise ValueError('--output must be an existing empty owned directory')
    if args.padding_output and (not args.padding_output.is_dir() or any(args.padding_output.iterdir()) or args.padding_output.is_symlink()):
        raise ValueError('--padding-output must be an existing empty owned directory')
    if args.entry_output and (not args.entry_output.is_dir() or any(args.entry_output.iterdir()) or args.entry_output.is_symlink()):
        raise ValueError('--entry-output must be an existing empty owned directory')
    if args.entry_only and not args.entry_output:
        raise ValueError('--entry-only requires --entry-output')
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
        sources = [APP / name for name in ('Models.swift', 'IOSExternalExecution.swift', 'IOSMultihopExecution.swift', 'IOSDNSRuntimePolicy.swift', 'IOSNativeXrayProfile.swift', 'IOSNativePQProfile.swift', 'IOSMultihopStartLayer.swift', 'IOSRuntimeSelection.swift')]
        sources += [TUN / name for name in ('WireGuardQuickConfig.swift', 'RouterVPNMultihopGraph.swift', 'RouterVPNMTUPolicy.swift', 'IOSStartLayer.swift', 'IOSXrayDevicePolicy.swift', 'RouterVPNExternalExit.swift')]
        command = ['swiftc', '-swift-version', '6', '-module-cache-path', str(work / 'module-cache'), '-I', str(work), '-L', str(work), '-lWireGuardKit', '-lLibbox']
        if platform.system() != 'Darwin':
            command += ['-lNetwork']
        command += ['-Xlinker', '-rpath', '-Xlinker', str(work), *map(str, sources), str(source), '-o', str(work / 'tests')]
        subprocess.run(command, check=True, timeout=180)
        environment = dict(os.environ)
        environment.pop('ROUTERVPN_IOS_OPENVPN_PROBES_ONLY', None)
        environment.pop('ROUTERVPN_IOS_PADDING_ONLY', None)
        environment.pop('ROUTERVPN_IOS_LOCAL_PADDING_GRAPHS', None)
        environment['ROUTERVPN_OPENVPN_CLIENT_FIXTURE'] = str(ROOT / 'deploy/fixtures/external-openvpn-client.json')
        environment['ROUTERVPN_OPENVPN_MULTIHOST_CLIENT_FIXTURE'] = str(ROOT / 'deploy/fixtures/external-openvpn-multihost-client.json')
        environment['ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_AES_FIXTURE'] = str(ROOT / 'deploy/fixtures/external-openvpn-multihost-layered-aes-client.json')
        environment['ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_XOR_FIXTURE'] = str(ROOT / 'deploy/fixtures/external-openvpn-multihost-layered-xor-client.json')
        if args.openvpn_probes_only:
            environment['ROUTERVPN_IOS_OPENVPN_PROBES_ONLY'] = '1'
        if args.output:
            environment['ROUTERVPN_IOS_TOR_GRAPHS'] = str(args.output.resolve())
        if args.padding_output:
            environment['ROUTERVPN_IOS_LOCAL_PADDING_GRAPHS'] = str(args.padding_output.resolve())
        if args.padding_only:
            environment['ROUTERVPN_IOS_PADDING_ONLY'] = '1'
        if args.entry_output:
            environment['ROUTERVPN_IOS_ENTRY_GRAPHS'] = str(args.entry_output.resolve())
        if args.entry_only:
            environment['ROUTERVPN_IOS_ENTRY_ONLY'] = '1'
        # The complete matrix now executes 2,025 external graphs, including 342
        # additional per-remote layer captures and their strict native checks.
        # Only this whole-fixture wall budget grows; native proof, cancellation
        # and bounded-close deadlines remain in their unchanged runtime tests.
        fixture_budget = 180 if args.entry_only or args.openvpn_probes_only else 360
        subprocess.run([str(work / 'tests'), str(compiler), str(maximum), str(composite)], env=environment, check=True, timeout=fixture_budget)
        if args.openvpn_probes_only:
            original = 'return nativeopenvpn.ValidateResponseProbesJSON(profileJSON, probesJSON)'
            if RESPONSE_BINDING.count(original) != 1:
                raise AssertionError('OpenVPN response binding boundary changed')
            broken = RESPONSE_BINDING.replace(original, 'return nil')
            (go_dir / 'main.go').write_text(GO.replace(RESPONSE_BINDING, broken))
            negative = work / 'compiler-without-raw-response-validation'
            subprocess.run(['go', 'build', '-o', str(negative), str(go_dir / 'main.go')], cwd=ROOT, check=True, timeout=120)
            rejected = subprocess.run([str(work / 'tests'), str(negative), str(maximum), str(composite)], env=environment, capture_output=True, text=True, timeout=30)
            if rejected.returncode == 0 or 'raw OpenVPN response map rejects ambiguity' not in rejected.stderr:
                raise AssertionError('Missing raw response-map validation negative control escaped: ' + rejected.stderr[-1500:])
            print('Apple OpenVPN copied-binding negative control: missing raw map validation rejected')
            original_layers = 'return nativeopenvpn.ValidateStartLayers(profileJSON, responseProbesJSON, layersJSON, selectedMode)'
            if START_LAYERS_BINDING.count(original_layers) != 1:
                raise AssertionError('OpenVPN Start Layers binding boundary changed')
            broken_layers = START_LAYERS_BINDING.replace(original_layers, 'return nil')
            (go_dir / 'main.go').write_text(GO.replace(START_LAYERS_BINDING, broken_layers))
            negative_layers = work / 'compiler-without-raw-layer-map-validation'
            subprocess.run(['go', 'build', '-o', str(negative_layers), str(go_dir / 'main.go')], cwd=ROOT, check=True, timeout=120)
            rejected_layers = subprocess.run([str(work / 'tests'), str(negative_layers), str(maximum), str(composite)], env=environment, capture_output=True, text=True, timeout=30)
            if rejected_layers.returncode == 0 or 'raw per-remote Start Layers reject ambiguity' not in rejected_layers.stderr:
                raise AssertionError('Missing raw layer-map validation control escaped: ' + rejected_layers.stderr[-1500:])
            print('Apple OpenVPN copied-binding negative control: missing raw layer-map validation rejected')
        if args.output or args.padding_output:
            inputs = [Path(__file__), *EXTRA_EVIDENCE_SOURCES, ROOT / 'mobile/routervpn_openvpn.go', ROOT / 'mobile/toroutbound/bridge.go.tmpl', APP / 'IOSExternalNodeBuilderView.swift', TUN / 'PacketTunnelProvider.swift', *sources]
        if args.output:
            report = dict(GRAPH_EVIDENCE,
                sources={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs})
            (args.output / 'source-evidence.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        if args.padding_output:
            report = dict(PADDING_EVIDENCE,
                sources={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs})
            (args.padding_output / 'source-evidence.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
