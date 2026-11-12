#!/usr/bin/env python3
"""Execute ordered Apple profile Add/Load and the shipping atomic node store.

Only private durable writes and DNS preparation are doubled. The Codable
models, per-position capture, safe preference snapshot, source checks, Load,
record normalization and transaction commit guards are actual shipping Swift.
This is persistence evidence, not native transport admission.
"""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import tempfile

from test_ios_external_connection_profiles import NETWORK

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'

BOUNDARIES = r'''
@MainActor enum UserDefaults {
 static let suite="RouterVPN.ChainProfiles.Test."+UUID().uuidString
 static let standard=Foundation.UserDefaults(suiteName:suite)!
}
@MainActor enum IOSPrivateJSONStore {
 static var bytes:Data?,writes=0
 static func read(_ filename:String,maximumBytes:Int)throws->Data?{bytes}
 static func write(_ data:Data,filename:String,maximumBytes:Int)throws{guard data.count<=maximumBytes else{throw failure("profile size")};bytes=data;writes+=1}
}
@MainActor final class IOSNodeBundleStore {
 static let shared=IOSNodeBundleStore()
 var records:[String:Data]=[:],storageError:Error?,writes=0,failWrite=false
 private func commitRecords(_ next:[String:Data])throws{if failWrite{throw failure("private durable write")};records=next;writes+=1}
 // SHIPPING_NODE_STORE
}
struct IOSLatencyResult {
 var id:String{fatalError("unrelated measurement path entered")}
 func applying(to profile:RouterProfile,network:UInt64)throws->RouterProfile{throw failure("unrelated measurement path")}
 static func issue(_ text:String)->NSError{failure(text)}
}
enum IOSExternalExecution {
 static func validatePrivateNodeJSON(_ data:Data)throws{_ = try JSONSerialization.jsonObject(with:data)}
 static func validateImported(_ value:ClientBundle)throws{}
 static func validateDeviceDraft(_ profile:RouterProfile)throws{guard IOSImportedShadowsocksSource.eligible(profile)else{throw failure("unexpected external draft")}}
 static func issue()->NSError{failure("external boundary")}
}
@MainActor enum IOSDNSRuntimePolicy {
 static var failID:String?,onPrepare:(()->Void)?
 static func patch(_ value:ClientBundle)throws->ClientBundle{
  onPrepare?()
  if value.selectedRouterID==failID{throw failure("selected DNS preparation")}
  return value
 }
 // SHIPPING_SELECTED_PROFILE
}
func failure(_ text:String)->NSError{NSError(domain:"AppleChainProfiles",code:1,userInfo:[NSLocalizedDescriptionKey:text])}
@MainActor final class RouterVPNModel {
 var bundle:ClientBundle?,profileMutationBlocked=false,imports=0
 let iosSpeedLabOwnership=IOSSpeedLabOwnership()
 let bundleKey="chain-profile-selection"
 var multihopProgressGeneration=UUID(),multihopProgressText=""
 var persistedNodeBundle:ClientBundle?{bundle}
 var allNodeProfiles:[RouterProfile]{IOSNodeBundleStore.shared.profiles(current:bundle)}
 var selectedNodeProfile:RouterProfile?{bundle.flatMap{IOSDNSRuntimePolicy.selectedProfile(in:$0)}}
 func apply(_ value:ClientBundle){bundle=value;imports+=1}
 func importBundle(_ data:Data)throws{let value=try IOSNodeBundleStore.shared.link(data,preserving:bundle,prepare:{$0});apply(value.bundle)}
 func iosMultihopEntryBundle(for source:ClientBundle,capturedEntryData:Data?=nil)throws->ClientBundle{throw failure("ordered chain fell through to pair capture")}
 // SHIPPING_RESTORE
 // SHIPPING_CHAIN_CAPTURE
}

@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ value:@autoclosure ()throws->Bool)throws{guard try value()else{throw failure(name)};checks+=1}
 static func reject(_ name:String,_ body:()throws->Void)throws{do{try body()}catch{checks+=1;return};throw failure("expected rejection: "+name)}
 static func encoded<T:Encodable>(_ value:T)throws->Data{let e=JSONEncoder();e.outputFormatting=[.sortedKeys];return try e.encode(value)}
 static func object(_ data:Data)throws->[String:Any]{try JSONSerialization.jsonObject(with:data) as! [String:Any]}
 static func source(_ position:Int,final:Bool)throws->ClientBundle {
  let proof=String(repeating:String(position+1,radix:16),count:64)
  let profile:[String:Any]=[
   "id":"raw-node-\(position)","name":"Node \(position)","node_kind":"router-vpn","node_proof_id":proof,
   "endpoint":"198.51.100.\(position+10)","router_api":"http://10.\(80+position).0.1:8787","api_token":"PRIVATE-TOKEN-\(position)",
   "adguard_ipv4":"10.\(80+position).0.53","adguard_ipv6":"","socks_host":"","socks_port":0,"socks_username":"","socks_password":"PRIVATE-SOCKS-\(position)",
   "home_lan_access":position%2==0,"kill_switch_policy":position%2==0 ? "always":"on-connect","ipv6_mode":position%2==0 ? "off":"on",
   "start_layer":position%3==0 ? "off":(position%3==1 ? "aes-256-gcm":"aes-256-gcm+xor-whitening"),
   "mtu_policy":"fixed","manual_mtu":1280+position*8,"dns_mode":position%2==0 ? "custom":"dot","dns_protocol":position%2==0 ? "tcp":"tls",
   "dns_host":"9.9.9.9","dns_port":5353+position,"dns_server_name":"resolver-\(position).example","dns_path":"",
   "base_tunnel":position%2==0 ? "wg":"awg","base_fallback":false,"daita_enabled":false,"jumbo_tun":false,
   "startup_mode":"manual","auto_connect":false]
  let p=try JSONDecoder().decode(RouterProfile.self,from:JSONSerialization.data(withJSONObject:profile))
  var value=ClientBundle.empty;value.routerProfiles=[p];value.selectedRouterID=p.id;value.nodeProofID=proof
  value.profiles=[final ? "shadowsocks":"wg":[final ? "sing-box.json":"wg.conf":Data("PRIVATE-ASSET-\(position)".utf8).base64EncodedString()]]
  return value
 }
 static func setup(_ count:Int)throws->(RouterVPNModel,[String]) {
  let store=IOSNodeBundleStore.shared;store.records=[:];store.storageError=nil;store.writes=0;store.failWrite=false
  IOSPrivateJSONStore.bytes=nil;IOSPrivateJSONStore.writes=0;IOSDNSRuntimePolicy.failID=nil;IOSDNSRuntimePolicy.onPrepare=nil
  UserDefaults.standard.removePersistentDomain(forName:UserDefaults.suite)
  UserDefaults.standard.set("smart-auto",forKey:iosConnectionModeKey)
  for i in 0..<count{try store.save(source(i,final:i==count-1))}
  let ids=(0..<count).map{"rvpn-"+String(repeating:String($0+1,radix:16),count:16)}
  var final=try JSONDecoder().decode(ClientBundle.self,from:store.bundleData(containing:ids.last!,current:nil)!)
  final.routerProfiles[0].multihopEnabled=true;final.routerProfiles[0].multihopExecution="local"
  final.routerProfiles[0].multihopNodes=ids.enumerated().map{IOSMultihopNodeSelection(id:$0.element,mode:$0.offset==count-1 ? "shadowsocks":"wg")}
  try store.save(final)
  let model=RouterVPNModel();model.bundle=try JSONDecoder().decode(ClientBundle.self,from:store.bundleData(containing:ids.last!,current:nil)!)
  return(model,ids)
 }
 static func stored(_ id:String)throws->ClientBundle{try JSONDecoder().decode(ClientBundle.self,from:IOSNodeBundleStore.shared.bundleData(containing:id,current:nil)!)}
 static func replaceRaw(_ id:String,_ edit:(inout ClientBundle)->Void)throws {
  let store=IOSNodeBundleStore.shared,data=store.bundleData(containing:id,current:nil)!
  let key=store.records.first(where:{$0.value==data})!.key
  var value=try JSONDecoder().decode(ClientBundle.self,from:data);edit(&value);store.records[key]=try encoded(value)
 }
 static func matrix()throws {
  for count in [3,4,8] {
   let(model,ids)=try setup(count),store=IOSNodeBundleStore.shared
   let original=store.records,selected=try encoded(model.bundle!)
   let saved=try IOSConnectionProfileStore.add(model:model,name:" Complete ordered path ")
   try check("snapshot retains every selected position",saved.preferences?.multihopNodes?.map(\.id)==ids && saved.chainPolicies?.map(\.nodeID)==ids)
   try check("chain snapshot has no borrowed legacy entry",saved.entryPolicy==nil && saved.preferences?.multihopEntryID==nil && saved.preferences?.multihopEntryMode==nil)
   try check("Add leaves live selection and private records unchanged",store.records==original && encoded(model.bundle!)==selected && model.imports==0)
   let text=String(decoding:IOSPrivateJSONStore.bytes!,as:UTF8.self)
   for token in ["PRIVATE-TOKEN","PRIVATE-SOCKS","PRIVATE-ASSET","private_key","api_token"]{try check("saved profile excludes "+token,!text.contains(token))}
   try check("new schema preserves historical decoder boundary",try object(IOSPrivateJSONStore.bytes!)["schema_version"] as? Int==8)
   for id in ids {
    var changed=try stored(id);changed.routerProfiles[0].startLayer="off";changed.routerProfiles[0].dnsProtocol="udp";changed.routerProfiles[0].dnsPort=53
    changed.routerProfiles[0].manualMTU=1500;changed.routerProfiles[0].homeLANAccess=true;changed.routerProfiles[0].ipv6Mode="on"
    changed.routerProfiles[0].multihopEnabled=false;try store.save(changed)
   }
   model.bundle=nil;let before=store.writes
   _=try IOSConnectionProfileStore.load(model:model,id:saved.id)
   let again=try IOSConnectionProfileStore.snapshot(model:model,name:saved.name,id:saved.id)
   try check("Load restores all complete safe preferences",again.preferences==saved.preferences && again.chainPolicies==saved.chainPolicies)
   try check("Load commits every source once",store.writes==before+1 && model.imports==1 && model.bundle?.selectedRouterID==ids.last!)
   for id in ids {
    let restored=try stored(id),prior=try JSONDecoder().decode(ClientBundle.self,from:original.first(where:{(try? JSONDecoder().decode(ClientBundle.self,from:$0.value).selectedRouterID)==id})!.value)
    try check("Load preserves original member secrets and assets",restored.profiles==prior.profiles && restored.routerProfiles[0].apiToken==prior.routerProfiles[0].apiToken && restored.routerProfiles[0].socksPassword==prior.routerProfiles[0].socksPassword)
   }
   try check("model and saved current record agree",UserDefaults.standard.data(forKey:model.bundleKey)==store.bundleData(containing:ids.last!,current:nil))
  }
 }
 static func failures()throws {
  for fault in ["missing-middle","changed-proof","missing-assets","middle-prepare","write","stale-during-prepare","blocked","order","final-policy","pair-capture","missing-capture"] {
   let(model,ids)=try setup(4),store=IOSNodeBundleStore.shared
   let saved=try IOSConnectionProfileStore.add(model:model,name:"Original chain")
   if fault=="missing-middle"{let data=store.bundleData(containing:ids[1],current:nil)!;store.records=store.records.filter{$0.value != data}}
   if fault=="changed-proof"{try replaceRaw(ids[1]){$0.routerProfiles[0].nodeProofID=String(repeating:"f",count:64)}}
   if fault=="missing-assets"{try replaceRaw(ids[1]){$0.profiles=[:]}}
   if fault=="middle-prepare"{IOSDNSRuntimePolicy.failID=ids[1]}
   if fault=="write"{store.failWrite=true}
   if fault=="blocked"{model.profileMutationBlocked=true}
   if ["order","final-policy","pair-capture","missing-capture"].contains(fault) {
    var envelope=try JSONDecoder().decode(IOSConnectionProfileEnvelope.self,from:IOSPrivateJSONStore.bytes!)
    if fault=="order"{envelope.profiles[0].chainPolicies!.swapAt(0,1)}
    if fault=="final-policy"{envelope.profiles[0].chainPolicies![3].preferences.manualMTU=1400}
    if fault=="pair-capture"{envelope.profiles[0].entryPolicy=envelope.profiles[0].chainPolicies![0]}
    if fault=="missing-capture"{envelope.profiles[0].chainPolicies!.remove(at:1)}
    IOSPrivateJSONStore.bytes=try encoded(envelope)
   }
   model.bundle=nil
   let records=store.records,writes=store.writes,imports=model.imports,defaults=UserDefaults.standard.data(forKey:model.bundleKey)
   if fault=="stale-during-prepare" {
    IOSDNSRuntimePolicy.onPrepare={IOSDNSRuntimePolicy.onPrepare=nil;try! replaceRaw(ids[1]){$0.routerProfiles[0].apiToken="NEW-RELINKED-SECRET"}}
   }
   try reject(fault){_ = try IOSConnectionProfileStore.load(model:model,id:saved.id)}
   try check("failed chain Load has no partial write or selection",store.writes==writes && model.imports==imports && model.bundle==nil && UserDefaults.standard.data(forKey:model.bundleKey)==defaults)
   if fault=="stale-during-prepare"{try check("concurrent original source survives refusal",try stored(ids[1]).routerProfiles[0].apiToken=="NEW-RELINKED-SECRET")}
   else{try check("failure preserves every private record",store.records==records)}
  }
 }
 static func normalization()throws {
  let store=IOSNodeBundleStore.shared;store.records=[:];store.failWrite=false;store.storageError=nil;IOSDNSRuntimePolicy.failID=nil;IOSDNSRuntimePolicy.onPrepare=nil
  let first=try source(0,final:false),last=try source(1,final:true)
  var together=last;together.routerProfiles=first.routerProfiles+last.routerProfiles
  together.profiles.merge(first.profiles){left,_ in left}
  together.routerProfiles[1].multihopNodes=[IOSMultihopNodeSelection(id:"raw-node-0",mode:"wg"),IOSMultihopNodeSelection(id:"raw-node-1",mode:"shadowsocks")]
  together.routerProfiles[1].multihopExecution="local";together.routerProfiles[1].multihopEnabled=true
  try store.save(together)
  let value=try JSONDecoder().decode(ClientBundle.self,from:store.records.values.first!)
  let expected=["rvpn-"+String(repeating:"1",count:16),"rvpn-"+String(repeating:"2",count:16)]
  try check("same-record canonicalization preserves ordered references",value.routerProfiles[1].multihopNodes?.map(\.id)==expected && value.selectedRouterID==expected[1])
  var mixed=value;mixed.routerProfiles[1].multihopEntryID=expected[0]
  let before=store.records
  try reject("mixed imported graph"){try store.save(mixed)}
  try check("invalid import cannot replace original record",store.records==before)
 }

 static func importedRoundtrip()throws {
  let(model,ids)=try setup(3),store=IOSNodeBundleStore.shared
  var middle=try stored(ids[1]),profile=middle.routerProfiles[0]
  profile.nodeKind="external";profile.nodeProofID=nil;profile.routerAPI="";profile.apiToken="";profile.startLayer="off";profile.dnsMode="rescue"
  let source:[String:Any] = ["protocol":"shadowsocks","expected_public_ip":"203.0.113.76","shadowsocks":["server":"198.51.100.76","port":443,"method":"2022-blake3-aes-256-gcm","password":Data(repeating:0,count:32).base64EncodedString()]]
  profile.external=try JSONDecoder().decode(ExternalNodeConfig.self,from:JSONSerialization.data(withJSONObject:source))
  middle.routerProfiles=[profile];middle.profiles=[:];try store.save(middle)
  var final=model.bundle!;final.routerProfiles[0].multihopNodes![1].mode="shadowsocks";try store.save(final);model.bundle=try stored(ids.last!)
  let saved=try IOSConnectionProfileStore.add(model:model,name:"Custom middle")
  try check("saved custom middle retains external authority",saved.chainPolicies?[1].nodeKind=="external" && saved.chainPolicies?[1].nodeProofID==nil && saved.chainPolicies?[1].externalProtocol=="shadowsocks")
  try check("saved custom middle excludes original credentials",!String(decoding:IOSPrivateJSONStore.bytes!,as:UTF8.self).contains(Data(repeating:0,count:32).base64EncodedString()))
  _ = try IOSConnectionProfileStore.load(model:model,id:saved.id)
  let captured=try model.iosNodeChainBundles(for:model.bundle!)
  try check("loaded custom middle retains every original position",captured.count==3 && captured[1].routerProfiles[0].normalizedNodeKind=="external" && captured[1].routerProfiles[0].nodeProofID==nil)
  try replaceRaw(ids[1]){$0.routerProfiles[0].external?.expectedPublicIP="203.0.113.77"}
  try reject("replaced custom public identity"){_ = try IOSConnectionProfileStore.load(model:model,id:saved.id)}
 }
 static func main(){do{defer{UserDefaults.standard.removePersistentDomain(forName:UserDefaults.suite)};try matrix();try failures();try normalization();try importedRoundtrip();print("Apple ordered profile persistence: PASS (\(checks) shipping Swift checks)")}
 catch{FileHandle.standardError.write(Data(("FAIL ordered profile persistence: "+error.localizedDescription+"\n").utf8));exit(1)}}
}
'''


def main():
    swift = shutil.which('swiftc')
    if not swift:
        raise SystemExit('swiftc required')
    source = (APP / 'IOSConnectionProfilesView.swift').read_text()
    source = source[:source.index('@MainActor\nstruct IOSConnectionProfilesView:')].replace('import SwiftUI\n', '')
    node = (APP / 'IOSNodeBundleStore.swift').read_text()
    model = (APP / 'RouterVPNModel.swift').read_text()
    multihop = (APP / 'IOSMultihopView.swift').read_text()
    dns = (APP / 'IOSDNSRuntimePolicy.swift').read_text()
    selected = dns[dns.index('    static func selectedProfile('):dns.index('    static func resolve(')]
    modes = next(line for line in dns.splitlines() if 'static let modeIDs =' in line)
    body = BOUNDARIES.replace(' // SHIPPING_NODE_STORE', node[node.index('    func link('):node.index('    private func storeDirectory(')])
    body = body.replace(' // SHIPPING_SELECTED_PROFILE', modes + '\n' + selected)
    body = body.replace(' // SHIPPING_RESTORE', model[model.index('    func restoreConnectionProfile('):model.index('    /// Measurement commits')])
    body = body.replace(' // SHIPPING_CHAIN_CAPTURE', multihop[multihop.index('    func iosNodeChainBundles('):multihop.index('    static let ordinaryExternalHopProtocols')])
    with tempfile.TemporaryDirectory(prefix='ios-node-chain-profiles-') as temporary:
        work = Path(temporary)
        options = [swift, '-j', '1', '-swift-version', '6', '-module-cache-path', str(work / 'modules')]
        if platform.system() != 'Darwin':
            network = work / 'Network.swift'; network.write_text(NETWORK)
            subprocess.run(options + ['-emit-module', '-emit-library', '-module-name', 'Network', str(network), '-emit-module-path', str(work / 'Network.swiftmodule'), '-o', str(work / 'libNetwork.so')], check=True, timeout=60)
            options += ['-I', str(work), '-L', str(work), '-lNetwork', '-Xlinker', '-rpath', '-Xlinker', str(work)]
        code = work / 'Tests.swift'; code.write_text(source + '\n' + body)
        binary = work / 'tests'
        command = options + [str(APP / 'Models.swift'), str(APP / 'IOSHomeDNSPolicy.swift'), str(APP / 'IOSSpeedLabOwnership.swift'), str(code), '-o', str(binary)]
        subprocess.run(command, check=True, timeout=120)
        subprocess.run([str(binary)], check=True, timeout=30)
        actual = code.read_text()
        controls = {
            'old-two-record-limit': ('(1...IOSMultihopNodeSelection.maximumNodes).contains(replacements.count)', '(1...2).contains(replacements.count)'),
            'lost-ordered-selection': ('profile.multihopNodes = prefs.multihopNodes', 'profile.multihopNodes = nil'),
        }
        for label, (before, after) in controls.items():
            if actual.count(before) != 1:
                raise AssertionError('shipping causal control moved: ' + label)
            code.write_text(actual.replace(before, after, 1))
            subprocess.run(command, check=True, timeout=120)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            if result.returncode != 1 or 'FAIL ordered profile persistence:' not in result.stderr:
                raise AssertionError('control did not reject the changed shipping behavior: ' + label + result.stdout + result.stderr)
            print('Apple ordered profile source control rejected: ' + label)


if __name__ == '__main__':
    main()
