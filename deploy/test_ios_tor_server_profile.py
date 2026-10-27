#!/usr/bin/env python3
"""Run shipping Apple Tor Server assembly against the real shared compiler.

This separate matrix preserves the bounded Local/ordinary profile gate. Native
handles and OS entry points are doubled; actual lease/traffic ownership runs in
the native Server gate, and both matrices enter the pinned native parser gate.
"""
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('apple_tor_server_capture', ROOT/'deploy/test_ios_tor_profile.py')
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
T.EXTRA_EVIDENCE_SOURCES = (Path(__file__),)
T.GRAPH_EVIDENCE = {'schema': 1, 'execution': 'server', 'graphs': 342, 'home_dns_combinations': 5,
    'public_tor_traffic': False, 'native_handles': 'boundary doubles'}
start = T.SWIFT.index(' @MainActor static func run()throws {')
end = T.SWIFT.index('\n @MainActor static func ', start + 1)
T.SWIFT = T.SWIFT[:start] + r'''
 @MainActor static func run()throws {
  defer{RouterVPNTorTestClose()}
  let maximum=try object(Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[2]))),composite=try object(Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[3])))
  try check("Server includes every supported private predecessor",Set(modes)==RouterVPNExternalExitBuilder.torEntryModes)
  for mode in modes {for layer in layers {for kind in kinds {try serverVerify(kind,mode,layer,maximum,composite)}}}
  try check("complete Server graph matrix",graphs==342)
  try serverHome(maximum,composite);try serverNegative(maximum,composite)
  print("Apple Tor Server: PASS (\(graphs) shipping Swift/Go graphs; \(checks) checks; native handles and OS boundaries doubled)")
 }
''' + T.SWIFT[end:]
T.SWIFT += r'''
extension Tests {
 @MainActor static func serverSelection(_ kind:String,_ mode:String)throws->[String:Any] {
  var profile=try tor(kind)
  profile["multihop_enabled"]=true;profile["multihop_execution"]="server"
  profile["multihop_entry_id"]="entry";profile["multihop_entry_mode"]=mode
  profile["multihop_exit_id"]=profile["id"];profile["multihop_exit_mode"]=kind=="tor" ? "tor":"tor-bridge"
  return profile
 }
 @MainActor static func serverVerify(_ kind:String,_ mode:String,_ layer:String,_ maximum:[String:Any],_ composite:[String:Any])throws {
  var selected=try serverSelection(kind,mode)
  selected["daita_enabled"]=true;selected["daita_rate_kbps"]=64
  let source=try root(mode,layer,maximum,composite),owner=ProviderPreparation()
  let entry=(source["routerProfiles"] as! [[String:Any]])[0],baseline=try owner.entry(source,mode)
  let provider:[String:Any]=["tor_entry_bundle":try json(source),"tor_entry_mode":mode]
  owner.restoredMultihopExecution="server"
  let selectedBefore=try text(selected),entryBefore=try text(source)
  let prepared=try owner.prepare(provider:provider,selectedProfile:selected,strict:true),runtime=prepared.runtime
  let graph=try object(runtime.files["sing-box.json"]!),out=try tagged(graph,"routervpn-tor-exit"),sid=runtime.torSessionID!
  try check("fresh Server UUID and explicit execution",UUID(uuidString:sid) != nil && sessions.insert(sid).inserted && runtime.torExecution=="server" && owner.multihopExecutionSource?.requested=="server")
  try check("Server keeps exact compiled policy and private entry",runtime.torProfileJSON==selectedBefore && runtime.torPredecessorProfile==text(entry))
  try check("Server final carries only exact source inputs",Set(out.keys)==Set(["type","tag","profile","session_id","entry_config","entry_profile"]) && out["type"] as? String=="routervpn-server-tor" && out["session_id"] as? String==sid && out["profile"] as? String==selectedBefore && out["entry_profile"] as? String==text(entry) && out["entry_config"] as? String==String(decoding:baseline["sing-box.json"]!,as:UTF8.self))
  let cover=try object(Data((out["profile"] as! String).utf8))
  try check("Server native source retains selected cover and nondefault rate",cover["daita_enabled"] as? Bool==true && cover["daita_rate_kbps"] as? Int==64)
  let outputs=graph["outbounds"] as! [[String:Any]],tun=(graph["inbounds"] as! [[String:Any]])
  try check("Server retains exactly one system TUN and one owner",tun.count==1 && tun[0]["type"] as? String=="tun" && tun[0]["mtu"] as? Int==1380 && tun[0]["auto_route"] as? Bool==true && tun[0]["strict_route"] as? Bool==true && outputs.filter{$0["type"] as? String=="routervpn-server-tor"}.count==1 && !outputs.contains{$0["type"] as? String=="routervpn-tor"})
  try check("Server preserves strict protection and dynamic exit",prepared.strict && runtime.expectedPublicIP.isEmpty && (graph["route"] as! [String:Any])["final"] as? String=="routervpn-tor-exit")
  let previous=try object(baseline["sing-box.json"]!),servers=(graph["dns"] as! [String:Any])["servers"] as! [[String:Any]]
  let dns=servers.first{$0["tag"] as? String=="routervpn-tor-dns"}!
  try check("Server sends exact selected DNS through its lease",dns["type"] as? String==selected["dns_protocol"] as? String && dns["server"] as? String=="149.112.112.112" && dns["server_port"] as? Int==selected["dns_port"] as? Int && dns["detour"] as? String=="routervpn-tor-exit")
  try check("Server does not leave client-side Tor bootstrap",!servers.contains{$0["tag"] as? String=="routervpn-tor-bootstrap"})
  for family in ["outbounds","endpoints"] {for row in previous[family] as? [[String:Any]] ?? [] {
   var actual=try tagged(graph,row["tag"] as! String)
   if row["type"] as? String=="naive" {
    try check("Server preserves native Naive entry DNS dependency",(actual["domain_resolver"] as? [String:Any])?["server"] as? String=="routervpn-tor-naive-bootstrap-0" && servers.contains{$0["tag"] as? String=="routervpn-tor-naive-bootstrap-0"})
    actual.removeValue(forKey:"domain_resolver")
   }
   try check("Server retains every entry lane and credential",json(row)==json(actual))
  }}
  try check("Server retains performance and entry Start Layer owners",json(previous["services"] ?? [])==json(graph["services"] ?? []))
  for (name,data) in baseline where name != "sing-box.json" {try check("Server retains auxiliary private source bytes",runtime.files[name]==data)}
  let authority=try object(Data(bridge(["Op":"tor-server-mtu-authority","Config":String(decoding:runtime.files["sing-box.json"]!,as:UTF8.self),"Policy":selectedBefore,"Node":sid,"Source":runtime.torPredecessorProfile!]).utf8))
  try check("Server MTU comes from its exact native source",authority["source_kind"] as? String=="tor" && authority["id"] as? String==selected["id"] as? String)
  var wrong=selected;wrong["manual_mtu"]=1390
  reject("Server MTU cannot use later saved preferences"){_ = try bridge(["Op":"tor-server-mtu-authority","Config":String(decoding:runtime.files["sing-box.json"]!,as:UTF8.self),"Policy":text(wrong),"Node":sid,"Source":runtime.torPredecessorProfile!])}
  try check("Server assembly leaves saved sources immutable",text(selected)==selectedBefore && text(source)==entryBefore)
  if let output=ProcessInfo.processInfo.environment["ROUTERVPN_IOS_TOR_GRAPHS"] {
   let directory=URL(fileURLWithPath:output).appendingPathComponent([mode,layer,kind].joined(separator:"-"))
   try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:false)
   for (name,data) in runtime.files {try data.write(to:directory.appendingPathComponent(name))}
   try json(["mode":mode,"layer":layer,"transport":kind,"session":sid]).write(to:directory.appendingPathComponent("fixture.json"))
  }
  graphs+=1
 }
 @MainActor static func serverHome(_ maximum:[String:Any],_ composite:[String:Any])throws {
  for transport in ["udp","tcp","tls","https","h3"] {
   let source=try root("shadowsocks","off",maximum,composite),entry=(source["routerProfiles"] as! [[String:Any]])[0]
   var selected=try serverSelection("obfs4","shadowsocks")
   selected["dns_mode"]="home";selected["dns_protocol"]=transport;selected["dns_host"]="";selected["dns_port"]=5453
   let before=try text(selected),owner=ProviderPreparation()
   let runtime=try owner.prepare(provider:["tor_entry_bundle":json(source),"tor_entry_mode":"shadowsocks"],selectedProfile:selected,strict:true).runtime
   let graph=try object(runtime.files["sing-box.json"]!),servers=(graph["dns"] as! [String:Any])["servers"] as! [[String:Any]],dns=servers.first{$0["tag"] as? String=="routervpn-tor-dns"}!
   try check("Server Home retains exact private resolver transport and entry",dns["type"] as? String==transport && dns["server"] as? String==entry["adguard_ipv4"] as? String && dns["server_port"] as? Int==5453 && dns["detour"] as? String=="proxy" && runtime.torProfileJSON==before)
   homeGraphs+=1
  }
  try check("Server Home transport matrix",homeGraphs==5)
 }
 @MainActor static func serverNegative(_ maximum:[String:Any],_ composite:[String:Any])throws {
  let source=try root("shadowsocks","off",maximum,composite),entry=(source["routerProfiles"] as! [[String:Any]])[0],selected=try serverSelection("obfs4","shadowsocks")
  let provider:[String:Any]=["tor_entry_bundle":try json(source),"tor_entry_mode":"shadowsocks"]
  for restored in ["local","auto",""] {
   let owner=ProviderPreparation();owner.restoredMultihopExecution=restored
   reject("Server cannot adopt another restored execution"){_ = try owner.prepare(provider:provider,selectedProfile:selected,strict:true)}
  }
  for fault in ["compare","missing-entry","ordinary-entry","wrong-entry-id","entry-proof","wrong-exit-mode","wrong-exit-id","fixed-conflict","padding-local","padding-type","padding-rate-type","padding-rate-small","padding-rate-large"] {
   var changed=selected,changedSource=source,changedEntry=entry,changedProvider=provider
   switch fault {
   case "compare":changed["multihop_execution"]="auto"
   case "missing-entry":changedProvider.removeValue(forKey:"tor_entry_bundle")
   case "ordinary-entry":changedEntry["node_kind"]="external"
   case "wrong-entry-id":changedEntry["id"]="other"
   case "entry-proof":changedEntry["node_proof_id"]=String(repeating:"f",count:64)
   case "wrong-exit-mode":changed["multihop_exit_mode"]="tor"
   case "wrong-exit-id":changed["multihop_exit_id"]="another-exit"
   case "fixed-conflict":changed["manual_mtu"]=1390
   case "padding-local":changed["multihop_execution"]="local";changed["daita_enabled"]=true;changed["daita_rate_kbps"]=64
   case "padding-rate-type":changed["daita_enabled"]=true;changed["daita_rate_kbps"]="64"
   case "padding-rate-small":changed["daita_enabled"]=true;changed["daita_rate_kbps"]=31
   case "padding-rate-large":changed["daita_enabled"]=true;changed["daita_rate_kbps"]=193
   default:changed["daita_enabled"]="false"
   }
   if ["ordinary-entry","wrong-entry-id","entry-proof"].contains(fault) {changedSource["routerProfiles"]=[changedEntry];changedProvider["tor_entry_bundle"]=try json(changedSource)}
   reject("Server rejects "+fault){_ = try ProviderPreparation().prepare(provider:changedProvider,selectedProfile:changed,strict:true)}
  }
  var standalone=selected;standalone["multihop_enabled"]=false
  reject("Server has no ambient standalone fallback"){_ = try RouterVPNExternalExitBuilder.build(profile:standalone)}
  var dormant=selected;dormant["daita_enabled"]=false;dormant["daita_rate_kbps"]=192
  let runtime=try ProviderPreparation().prepare(provider:provider,selectedProfile:dormant,strict:true).runtime
  try check("Server preserves valid dormant padding without enabling it",runtime.torProfileJSON==text(dormant))
 }
}
'''

if __name__ == '__main__':
    T.main()
