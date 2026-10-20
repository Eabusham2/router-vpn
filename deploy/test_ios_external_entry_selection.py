#!/usr/bin/env python3
"""Execute Apple graph selection/save with shipping models and capture methods.

The node-store and native-mode readiness boundaries are deterministic doubles;
the separate Swift/Go policy gate validates compiled native configurations.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
STUBS = r'''
import Foundation
enum IOSRuntimeSelector {
 static let multihopModeIDs:Set<String>=["wg","awg2-fast","awg2-strong","shadowsocks","hysteria2"]
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
  let protocols=["wireguard","socks5","http-connect","https-connect","shadowsocks","hysteria2"]
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
  for fault in ["duplicate","missing","unpaired","wrong-kind","missing-assets","padding","layer"] {
   var changed=entry
   switch fault {
   case "duplicate":changed.routerProfiles.append(changed.routerProfiles[0])
   case "missing":changed.routerProfiles=[]
   case "unpaired":changed.routerProfiles[0].nodeProofID="invalid"
   case "wrong-kind":changed.routerProfiles[0].nodeKind="unknown"
   case "missing-assets":changed.profiles=[:]
   case "padding":changed.routerProfiles[0].daitaEnabled=true
   default:changed.routerProfiles[0].startLayer="aes-256-gcm"
   }
   IOSNodeBundleStore.shared.nodes=["entry":try JSONEncoder().encode(changed)]
   try reject("invalid Router VPN predecessor "+fault){_ = try model.iosMultihopEntryBundle(for:model.bundle!)}
  }
  IOSNodeBundleStore.shared.nodes=["entry":try JSONEncoder().encode(entry)]
  for execution in ["server","auto","unknown"]{var changed=model.bundle!;changed.routerProfiles[0].multihopExecution=execution;try reject("unowned external server execution"){_ = try model.iosMultihopEntryBundle(for:changed)}}
  model.profileMutationBlocked=true
  try reject("active graph cannot be edited"){try model.saveIOSMultihop(enabled:true,entryID:"entry",exitID:"exit",exitMode:"socks5",entryMode:"wg")}
  print("Apple external entry selection: PASS (\(checks) shipping Swift checks; storage/native-readiness boundaries doubled)")
 }
}
'''


def main():
    view = (APP / 'IOSMultihopView.swift').read_text()
    capture = view[view.index('@MainActor\nextension RouterVPNModel {'):view.index('struct IOSMultihopView: View')]
    dns = (APP / 'IOSDNSRuntimePolicy.swift').read_text()
    selected = dns[dns.index('    static func selectedProfile('):dns.index('    static func resolve(')]
    body = STUBS.replace(' // SHIPPING_SELECTED_PROFILE', selected) + '\n' + capture
    with tempfile.TemporaryDirectory(prefix='ios-external-selection-') as directory:
        work = Path(directory); source = work / 'Test.swift'; source.write_text(body)
        subprocess.run(['swiftc', '-swift-version', '6', str(APP / 'Models.swift'), str(APP / 'IOSMultihopStartLayer.swift'), str(source), '-o', str(work / 'test')], check=True, timeout=90)
        subprocess.run([str(work / 'test')], check=True, timeout=20)


if __name__ == '__main__':
    main()
