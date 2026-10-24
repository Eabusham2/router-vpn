#!/usr/bin/env python3
"""Execute Apple graph selection/save with shipping models and capture methods.

The node-store and native-mode readiness boundaries are deterministic doubles;
the separate Swift/Go policy gate validates compiled native configurations.
"""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
spec = importlib.util.spec_from_file_location('external_entry_native_boundary', ROOT / 'deploy/test_ios_tor_profile.py')
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
STUBS = r'''
import Foundation
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
 func linkNodeBundle(_ data:Data)throws{try importBundle(data)}
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
 static var checks=0
 static func check(_ name:String,_ result:@autoclosure ()throws->Bool)throws{guard try result()else{throw NSError(domain:"ExternalSelection",code:1,userInfo:[NSLocalizedDescriptionKey:name])};checks+=1}
 static func reject(_ name:String,_ operation:()throws->Void)throws{do{try operation()}catch{checks+=1;return};throw NSError(domain:"ExternalRejection",code:1,userInfo:[NSLocalizedDescriptionKey:name])}
 static func main()throws {
  defer { RouterVPNTorTestClose() }
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
  let edit=RouterVPNModel();ss.multihopExecution="local";edit.bundle=bundle(ss)
  IOSNodeBundleStore.shared.nodes=[ss.id:try JSONEncoder().encode(edit.bundle!),"other-node":Data("unrelated private node bytes".utf8)]
  let savedExternal=ss.external!,savedAssets=edit.bundle!.profiles
  try check("idle editor validates and saves exact response URL",edit.updateNodeMetadata(id:ss.id,name:"Edited",location:"",latitudeText:"",longitudeText:"",expectedExternal:savedExternal,responseProbeURL:"https://198.51.100.8:9443/new-response",responseProbeServerName:"new.example.test"))
  let edited=edit.bundle!.routerProfiles[0]
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
  for kind in ["shadowsocks","hysteria2","socks5","http-connect","https-connect"] { for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   var node=try profile("paired-"+kind,"external",kind)
   switch kind {
   case "shadowsocks":node.external?.shadowsocks=ExternalShadowsocksConfig(server:"198.51.100.8",port:8388,method:"aes-256-gcm",password:" exact secret ")
   case "hysteria2":node.external?.hysteria2=ExternalHysteria2Config(server:"198.51.100.8",port:443,password:" exact secret ",tlsServerName:"exit.example.test")
   case "http-connect":node.external?.httpConnect=ExternalHTTPConnectConfig(host:"198.51.100.8",port:8080,username:" exact user ",password:" exact secret ",tlsServerName:nil)
   case "https-connect":node.external?.httpsConnect=ExternalHTTPConnectConfig(host:"198.51.100.8",port:8443,username:" exact user ",password:" exact secret ",tlsServerName:"exit.example.test")
   default:break
   }
   let editor=RouterVPNModel();editor.bundle=bundle(node);IOSNodeBundleStore.shared.nodes=[node.id:try JSONEncoder().encode(editor.bundle!),"entry":try JSONEncoder().encode(entry)]
   let original=node.external!,layerKey=Data(repeating:7,count:32).base64EncodedString()
   try check("every supported native editor retains provisioned response/layer settings "+kind+layer,editor.updateNodeMetadata(id:node.id,name:"Layered",location:"",latitudeText:"",longitudeText:"",expectedExternal:original,responseProbeURL:"https://198.51.100.8:9443/response",responseProbeServerName:"node.example.test",expectedStartLayer:"off",exitStartLayer:layer,exitLayerAPI:layer=="off" ? "":"http://10.99.0.1:8787",exitLayerPort:layer=="off" ? 0:8388,exitLayerKey:layer=="off" ? "":layerKey))
   node=editor.bundle!.routerProfiles[0]
   try check("layer editor preserves exact primary credentials",node.external?.shadowsocks==original.shadowsocks && node.external?.hysteria2==original.hysteria2 && node.external?.socks5==original.socks5 && node.external?.httpConnect==original.httpConnect && node.external?.httpsConnect==original.httpsConnect)
   try IOSExternalExecution.validateImported(editor.bundle!);checks+=1
   for execution in ["local","server","auto"] {
    try editor.saveIOSMultihop(enabled:true,entryID:"entry",exitID:node.id,exitMode:kind,execution:execution,entryMode:"wg")
    try check("each protocol and layer retains its exact saved execution",editor.bundle!.routerProfiles[0].multihopExecution==execution && editor.bundle!.routerProfiles[0].external==node.external)
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
  }}
  print("Apple external entry selection: PASS (\(checks) shipping Swift checks; storage/native-readiness boundaries doubled)")
 }
}
'''


def main():
    view = (APP / 'IOSMultihopView.swift').read_text()
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
        helper = Path(helper) / 'main.go'; helper.write_text(T.GO)
        compiler = work / 'compiler'
        subprocess.run(['go', 'build', '-o', str(compiler), str(helper)], cwd=ROOT, check=True, timeout=180)
        library = work / 'Libbox.swift'; library.write_text(T.LIBBOX)
        suffix = '.dylib' if platform.system() == 'Darwin' else '.so'
        subprocess.run(['swiftc', '-swift-version', '6', '-module-cache-path', str(work/'module-cache'), '-emit-module', '-emit-library', '-module-name', 'Libbox', str(library), '-emit-module-path', str(work/'Libbox.swiftmodule'), '-o', str(work/('libLibbox'+suffix))], check=True, timeout=90)
        subprocess.run(['swiftc', '-swift-version', '6', '-module-cache-path', str(work/'module-cache'), '-I', str(work), '-L', str(work), '-lLibbox', '-Xlinker', '-rpath', '-Xlinker', str(work), str(APP / 'Models.swift'), str(APP / 'IOSExternalExecution.swift'), str(APP / 'IOSMultihopStartLayer.swift'), str(source), '-o', str(work / 'test')], check=True, timeout=90)
        subprocess.run([str(work / 'test'), str(compiler)], check=True, timeout=30)


if __name__ == '__main__':
    main()
