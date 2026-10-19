#!/usr/bin/env python3
"""Run captured two-lane multihop through shipping Swift and real Go compilers.

The production provider's complete pre-start assembly and strict-route guard
run against generated private-node assets. OS handles are boundary doubles;
native parser, encrypted packet, Xcode and device gates remain independent.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('apple_composite_max_host', ROOT/'deploy/test_ios_max_multihop.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
P = M.P
support = P.SWIFT[:P.SWIFT.index('@main struct Tests')]
# Keep the exact production strict-route guard inside the executable prefix.
# Only NETunnelProviderProtocol's OS-owned flags are doubled on the host.
strict = M.provider[M.provider.index('        let strict = strictKillSwitchRequested(', M.provider.index('    private func startMultihop(')):]
strict = strict[:strict.index('        let entryURL = try selectedProofURL(')]
support = support.replace('@MainActor final class ProviderPreparation {', '''
@MainActor final class NETunnelProviderProtocol {
 var includeAllNetworks=true, enforceRoutes=true, excludeLocalNetworks=false
}
@MainActor final class ProviderPreparation {
 var protocolConfiguration:Any?=NETunnelProviderProtocol()
'''+M.method('strictKillSwitchRequested', 'suppliedNodeProof'), 1)
support = support.replace('let mtuProfile:Data}', 'let mtuProfile:Data;let strict:Bool}', 1)
returned = '        return Prepared(files: finalFiles, metadata: hopMetadata, entryLayer: entryLayer.source, exitLayer: exitLayer.source, mtuProfile: mtuProfileData)'
assert support.count(returned) == 1
support = support.replace(returned, strict+returned[:-1]+', strict: strict)', 1)

P.SWIFT = support + r'''
func compositeCompile(_ mode:String,_ files:String,_ policy:String,_ start:String)throws->String {
 try bridge(["Op":"composite-compile","Mode":mode,"Files":files,"Policy":policy,"Source":start])
}
func compositeBase(_ config:String,_ mode:String,_ node:String,_ layer:String)throws->String {
 try bridge(["Op":"composite-base","Config":config,"Mode":mode,"Node":node,"Policy":layer])
}
func compositeCompose(_ config:String,_ metadata:String,_ entry:String,_ exit:String)throws->String {
 try bridge(["Op":"composite-compose","Config":config,"Policy":metadata,"Source":text(["Entry":entry,"Exit":exit])])
}
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ label:String,_ condition:@autoclosure ()throws->Bool)throws{guard try condition()else{fatalError("FAIL "+label)};checks+=1}
 @MainActor static func reject(_ label:String,_ action:()throws->Void){do{try action();fatalError("ACCEPTED "+label)}catch{checks+=1}}
 static let modes=["max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg","wg","awg2-fast","shadowsocks","hysteria2","ss-v2ray","split","max"]
 static let layers=[("off","off"),("aes-256-gcm","aes-256-gcm+xor-whitening"),("aes-256-gcm+xor-whitening","aes-256-gcm")]
 struct Hop {
  let mode:String
  var profile:[String:Any]
  let root:[String:Any]
  let files:[String:Data]
  let endpoint:[String:Any]
  let max:IOSNativeMAXMultihop.Capture?
  let composite:IOSNativeCompositeMultihop.Capture?
  let layer:IOSMultihopStartLayer.Capture
  var complete:Bool{max != nil || composite != nil}
 }
 static func at(_ graph:[String:Any],_ tag:String)throws->[String:Any]{
  let values=((graph["endpoints"] as? [[String:Any]] ?? [])+(graph["outbounds"] as? [[String:Any]] ?? [])).filter{$0["tag"] as? String==tag}
  guard values.count==1 else{throw NSError(domain:"TestGraphOwner",code:1)};return values[0]
 }
 @MainActor static func hop(_ fixtures:[String:Any],_ composites:[String:[String:Any]],_ role:String,_ mode:String,_ layer:String,_ fixed:Int)throws->Hop{
  let service=role=="entry" ? "10.77.0.1":"10.88.0.1"
  var root:[String:Any]=[:], p:[String:Any], files:[String:Data], endpoint:[String:Any]
  var max:IOSNativeMAXMultihop.Capture?,composite:IOSNativeCompositeMultihop.Capture?
  if IOSNativeMAXProfile.modeIDs.contains(mode){
   let f=(fixtures[role] as! [String:Any])[mode] as! [String:Any]
   let assets=f["files"] as! [String:String],policy=f["policy"] as! [String:String],node=policy["node_id"]!
   p=profile(node,role=="exit" ? "doh3":"home",layer)
   p["endpoint"]=policy["endpoint"];p["router_api"]=policy["router_api"]
   root=["profiles":[mode:assets],"nodeProofId":node]
   max=try IOSNativeMAXMultihop.capture(mode:mode,encoded:assets,nodeID:node,profile:p,startLayer:layer,compiler:maxCompile,baseCompiler:maxBase)
   files=max!.baseFiles;endpoint=try max!.endpoint()
  }else if IOSNativeCompositeMultihop.modeIDs.contains(mode){
   root=composites[role]!
   let node=root["nodeProofId"] as! String,original=(root["routerProfiles"] as! [[String:Any]])[0]
   p=profile(node,role=="exit" ? "doh3":"home",layer)
   p["endpoint"]=original["endpoint"];p["router_api"]=original["router_api"]
   let before=try text(root)
   composite=try IOSNativeCompositeMultihop.capture(root:root,mode:mode,profile:p,nodeID:node,layer:layer,compiler:compositeCompile,baseCompiler:compositeBase)
   try check("composite capture leaves raw node assets immutable",text(root)==before)
   files=composite!.baseFiles;endpoint=try composite!.outbound()
  }else{
   let f=try object(Data(bridge(["Op":"exit-fixture","Mode":mode]).utf8)),node=f["node"] as! String
   p=profile(node,role=="exit" ? "doh3":"home",layer);p["endpoint"]="198.51.100.2";p["router_api"]="http://\(service):8787"
   let graph=try object(Data((f["config"] as! String).utf8));endpoint=try at(graph,"proxy");files=["sing-box.json":try json(graph)]
   var aes=try object(Data((try object(Data(bridge(["Op":"exit-fixture","Mode":"shadowsocks"]).utf8))["config"] as! String).utf8))
   var outer=(aes["outbounds"] as! [[String:Any]])[0];outer["server"]="198.51.100.2";outer["server_port"]=8388;aes["outbounds"]=[outer]
   root=["profiles":["shadowsocks":["sing-box.json":try json(aes).base64EncodedString()]],"nodeProofId":node]
  }
  p["id"]=role;p["socks_host"]=service;p["manual_mtu"]=fixed;p["api_token"]=role+"-private-token";p["kill_switch_policy"]="strict"
  root["selectedRouterID"]=role;root["routerProfiles"]=[p]
  var construction=p;construction["start_layer"]="off"
  let capture=max != nil || composite != nil ? IOSMultihopStartLayer.Capture(mode:layer,source:nil,graphProfile:construction):
   try IOSMultihopStartLayer.capture(profile:p,profiles:root["profiles"] as! [String:[String:String]])
  if role=="exit"{
   if max != nil{files=try RouterVPNMultihopGraph.pqDNSPolicy(files,profile:p)}
   else if composite != nil{files=try RouterVPNMultihopGraph.compositeDNSPolicy(files,profile:p)}
   else if ["wg","awg2-fast"].contains(mode){files=try RouterVPNMultihopGraph.wireGuardFiles(endpoint:endpoint,profile:p,dnsServers:["192.168.50.133"])}
   else{
    var node=ClientBundle.empty;node.selectedRouterID=role;node.routerProfiles=[try JSONDecoder().decode(RouterProfile.self,from:json(p))]
    node.profiles=[mode:files.mapValues{$0.base64EncodedString()}]
    let patched=try IOSDNSRuntimePolicy.patch(node);files=patched.profiles[mode]!.mapValues{Data(base64Encoded:$0)!}
   }
  }
  return Hop(mode:mode,profile:p,root:root,files:files,endpoint:endpoint,max:max,composite:composite,layer:capture)
 }
 @MainActor static func metadata(_ a:Hop,_ b:Hop,_ execution:String)throws->String{
  var meta:[String:String]=["entry_id":"entry","exit_id":"exit","entry_node_id":a.profile["node_proof_id"] as! String,"exit_node_id":b.profile["node_proof_id"] as! String,
   "entry_api":a.profile["router_api"] as! String,"exit_api":b.profile["router_api"] as! String,"entry_token":"entry-private-token","exit_token":"exit-private-token",
   "entry_tag":RouterVPNMultihopGraph.entryTag,"entry_mode":a.mode,"exit_mode":b.mode,"execution":execution]
  if a.layer.mode != "off"{meta["entry_start_layer"]=a.layer.mode};if b.layer.mode != "off"{meta["exit_start_layer"]=b.layer.mode}
  return try text(meta)
 }
 @MainActor static func construction(_ a:Hop,_ b:Hop)throws->[String:Data]{
  var exit=b.layer.graphProfile;exit["multihop_entry_mode"]=a.max?.baseMode ?? a.mode
  return try RouterVPNMultihopGraph.build(entryEndpoint:a.endpoint,entryProfile:a.layer.graphProfile,exitProfile:exit,exitMode:b.max?.baseMode ?? b.mode,files:b.files)
 }
 @MainActor static func restored(_ a:Hop,_ b:Hop,_ initial:[String:Data],_ meta:String)throws->[String:Data]{
  var files=initial
  if a.max != nil || b.max != nil{files=try IOSNativeMAXMultihop.compose(files:files,metadata:meta,entry:a.max,exit:b.max,compiler:maxCompose)}
  return try IOSNativeCompositeMultihop.compose(files:files,metadata:meta,entry:a.composite,exit:b.composite,compiler:compositeCompose)
 }
 @MainActor static func sourceRoots(_ a:Hop,_ b:Hop,_ execution:String)throws->([String:Any],[String:Any],[String:Any]){
  var exit=b.profile;exit["multihop_enabled"]=true;exit["multihop_entry_id"]="entry";exit["multihop_exit_id"]="exit";exit["multihop_entry_mode"]=a.mode;exit["multihop_exit_mode"]=b.mode;exit["multihop_execution"]=execution
  var root=b.root;root["routerProfiles"]=[exit]
  return (["rawProfileID":b.mode,"entryBundle":try json(a.root)],root,exit)
 }
 @MainActor static func complete(_ graph:[String:Any],_ hop:Hop,_ tag:String,_ side:String)throws{
  guard let capture=hop.composite else{return}
  let prefix="routervpn-"+side+"-composite-",owner=try at(graph,tag),source=try object(Data(capture.source.utf8))
  try check("exact composite network dispatcher",Set(owner.keys)==Set(["type","tag","mode","node_id","tcp","udp"]) && owner["type"] as? String=="routervpn-composite" && owner["mode"] as? String==hop.mode)
  try check("same captured composite node",owner["node_id"] as? String==capture.nodeID)
  try check("independent TCP and UDP lane references",owner["tcp"] as? String==prefix+"tcp" && owner["udp"] as? String==prefix+"udp")
  for network in ["tcp","udp"]{
   var actual=try at(graph,prefix+network),expected=try at(source,"routervpn-composite-"+network)
   try check("actual encryption per lane",actual["type"] as? String==(network=="udp" ? "hysteria2":hop.mode=="ss-v2ray" ? "shadowsocks":"routervpn-xray"))
   let target=capture.startLayer=="off" ? (side=="entry" ? "":RouterVPNMultihopGraph.entryTag):prefix+"start"
   try check("every lane retains its selected outer path",(actual["detour"] as? String ?? "")==target)
   for key in ["tag","detour"]{actual.removeValue(forKey:key);expected.removeValue(forKey:key)}
   try check("lane keys, certificates and obfuscation preserved byte-for-byte",text(actual)==text(expected))
  }
  let udp=try at(graph,prefix+"udp"),tls=udp["tls"] as! [String:Any]
  try check("UDP trust owned inline",tls["certificate_path"]==nil && ((tls["certificate"] as? String)?.isEmpty==false || !(tls["certificate"] as? [String] ?? []).isEmpty))
  if capture.startLayer != "off"{
   var actual=try at(graph,prefix+"start"),expected=try at(source,"routervpn-composite-start")
   try check("authenticated outer layer stays on the predecessor",(actual["detour"] as? String ?? "")==((side=="entry") ? "":RouterVPNMultihopGraph.entryTag))
   for key in ["tag","detour"]{actual.removeValue(forKey:key);expected.removeValue(forKey:key)}
   try check("same-node outer key and whitening preserved",text(actual)==text(expected))
  }
 }
 @MainActor static func main()throws{
  defer{TestCompiler.shared.close()}
  let env=ProcessInfo.processInfo.environment
  let fixtures=try object(Data(contentsOf:URL(fileURLWithPath:env["ROUTERVPN_MAX_MULTIHOP_FIXTURES"]!)))
  let composites=try ["entry":object(Data(contentsOf:URL(fileURLWithPath:env["ROUTERVPN_COMPOSITE_ENTRY"]!))),"exit":object(Data(contentsOf:URL(fileURLWithPath:env["ROUTERVPN_COMPOSITE_EXIT"]!)))]
  var graphs=0,assemblies=0
  for am in modes{for bm in modes where IOSNativeCompositeMultihop.modeIDs.contains(am)||IOSNativeCompositeMultihop.modeIDs.contains(bm){
   for (al,bl) in layers{for execution in ["local","server","auto"]{
    let packet=IOSNativeMAXProfile.modeIDs.contains(am)||["wg","awg2-fast"].contains(am)
    let a=try hop(fixtures,composites,"entry",am,al,packet ? 1500:1280),b=try hop(fixtures,composites,"exit",bm,bl,1280)
    let meta=try metadata(a,b,execution),initial=try construction(a,b),before=try text(try object(initial["sing-box.json"]!))
    let capturedA=try text(a.root),capturedB=try text(b.root),files=try restored(a,b,initial,meta)
    try check("temporary construction immutable",text(try object(initial["sing-box.json"]!))==before)
    try check("only compiled graph staged",files.count==1 && files["sing-box.json"] != nil)
    let ec=try IOSMultihopStartLayer.requiredSource(metadata:meta,source:a.layer.source),xc=try IOSMultihopStartLayer.requiredExitSource(metadata:meta,source:b.layer.source)
    if a.complete{try check("embedded entry AES is not duplicated",ec==nil)};if b.complete{try check("embedded exit AES is not duplicated",xc==nil)}
    let policies=try text(["entry":a.profile,"exit":b.profile])
    var config=try bridge(["Op":"mtu","Config":String(decoding:files["sing-box.json"]!,as:UTF8.self),"Policy":policies])
    config=try bridge(["Op":"lan","Config":config,"Policy":policies]);config=try bridge(["Op":"performance","Config":config,"Policy":policies])
    if a.complete && b.complete{
     let roots=try sourceRoots(a,b,execution),prepared=try ProviderPreparation().prepare(provider:roots.0,root:roots.1,selectedProfile:roots.2)
     if execution=="local"{
      var selected=ClientBundle.empty;selected.selectedRouterID="exit";selected.nodeProofID=b.profile["node_proof_id"] as! String
      selected.routerProfiles=[try JSONDecoder().decode(RouterProfile.self,from:json(roots.2))];selected.profiles=b.root["profiles"] as! [String:[String:String]]
      let choice=try IOSRuntimeSelector.selectMultihop(bundle:selected,rawProfileID:nil)
      try check("Connect preserves complete composite/MAX selection",choice.engine == .multihop && choice.rawProfileID==bm && choice.multihopEntryMode==am && choice.files.isEmpty)
     }
     try check("production provider builds exact complete graph",text(try object(prepared.files["sing-box.json"]!))==text(try object(Data(config.utf8))))
     try check("production provider preserves selected transport metadata",text(try object(Data(prepared.metadata.utf8)))==text(try object(Data(meta.utf8))))
     let policy=try text(["entry":a.profile,"exit":roots.2])
     try check("production MTU profile retains launched ownership",text(try object(prepared.mtuProfile))==text(try object(Data(bridge(["Op":"mtu-profile","Config":config,"Policy":policy]).utf8))))
     try check("production strict route guard and embedded layers",prepared.strict && prepared.entryLayer==nil && prepared.exitLayer==nil)
     assemblies+=1
    }
    let planned=try bridge(["Op":"plan","Config":config,"Policy":meta,"Source":text(["Entry":ec ?? "","Exit":xc ?? ""])])
    let graph=try object(Data(planned.utf8)),inbounds=graph["inbounds"] as! [[String:Any]],tuns=inbounds.filter{$0["type"] as? String=="tun"}
    try check("one strict native TUN",tuns.count==1 && tuns[0]["auto_route"] as? Bool==true && tuns[0]["strict_route"] as? Bool==true && tuns[0]["mtu"] as? Int==1280)
    try complete(graph,a,RouterVPNMultihopGraph.entryTag,"entry");try complete(graph,b,"routervpn-execution-local","exit")
    for (c,tag,prefix,via) in [(a.max,RouterVPNMultihopGraph.entryTag,"routervpn-entry-max-",""),(b.max,"routervpn-execution-local","routervpn-exit-max-",RouterVPNMultihopGraph.entryTag)]{
     guard let c else{continue};let actual=try at(graph,tag),base=(try object(Data(c.source.utf8))["endpoints"] as! [[String:Any]])[0]
     try check("mixed MAX still owns its PQ base",actual["type"] as? String=="routervpn-pq" && actual["mode"] as? String==c.baseMode && actual["node_id"] as? String==c.nodeID)
     for key in ["private_key","pq","amnezia","address","peers"]{try check("mixed MAX keeps captured "+key,text(["value":actual[key] ?? NSNull()])==text(["value":base[key] ?? NSNull()]))}
     try check("mixed MAX ordered encryption",actual["detour"] as? String==prefix+"ss" && at(graph,prefix+"ss")["detour"] as? String==prefix+"outer")
     try check("mixed MAX outermost predecessor",(at(graph,prefix+(c.startLayer=="off" ? "outer":"start"))["detour"] as? String ?? "")==via)
    }
    try check("separate entry proof owner",at(graph,RouterVPNMultihopGraph.entryPrivateTag)["detour"] as? String==RouterVPNMultihopGraph.entryTag)
    try check("independent node identities",a.profile["node_proof_id"] as? String != b.profile["node_proof_id"] as? String)
    let proxy=try at(graph,"proxy"),servers=(graph["dns"] as! [String:Any])["servers"] as! [[String:Any]],rules=(graph["route"] as! [String:Any])["rules"] as! [[String:Any]]
    try check("adaptive execution keeps owned selector",proxy["type"] as? String=="selector" && (proxy["outbounds"] as? [String] ?? []).contains("routervpn-execution-local"))
    try check("AdGuard H3 stays behind exit",servers.allSatisfy{$0["server"] as? String=="192.168.50.133" && $0["detour"] as? String=="proxy"} && servers.last!["type"] as? String=="h3")
    try check("LAN-Off preserved",rules.contains{$0["action"] as? String=="reject" && ($0["ip_cidr"] as? [String] ?? []).contains("192.168.0.0/16")})
    try check("IPv6-Off preserved",rules.contains{$0["action"] as? String=="reject" && $0["ip_version"] as? Int==6})
    try check("padding ownership retained",!(graph["services"] as? [[String:Any]] ?? []).isEmpty)
    try check("source bundles are immutable",text(a.root)==capturedA && text(b.root)==capturedB)
    if let output=env["ROUTERVPN_IOS_COMPOSITE_GRAPHS"]{
     let path=URL(fileURLWithPath:output).appendingPathComponent([am,bm,al,bl,execution].joined(separator:"-")+".json")
     try Data(planned.utf8).write(to:path,options:.withoutOverwriting)
    }
    graphs+=1
   }}
  }}
  try check("complete composite direction/layer/execution matrix",graphs==513)
  try check("actual complete provider assembly matrix",assemblies==297)
  for mode in ["ss-v2ray","split","max"]{
   let a=try hop(fixtures,composites,"entry",mode,"aes-256-gcm",1280),b=try hop(fixtures,composites,"exit",mode,"aes-256-gcm+xor-whitening",1280)
   let meta=try metadata(a,b,"auto"),initial=try construction(a,b)
   for fault in ["node","type","tcp-alias","extra-owner","dns-detour","dns-host"]{
    var g=try object(b.composite!.baseFiles["sing-box.json"]!),outs=g["outbounds"] as! [[String:Any]]
    switch fault{
    case "node":outs[0]["node_id"]=a.profile["node_proof_id"]
    case "type":outs[0]["type"]="routervpn-pq"
    case "tcp-alias":outs[0]["tcp"]=outs[0]["udp"]
    case "extra-owner":outs.append(["type":"direct","tag":"direct"])
    default:var dns=g["dns"] as! [String:Any],servers=dns["servers"] as! [[String:Any]];servers[0][fault=="dns-detour" ? "detour":"server"]=fault=="dns-detour" ? "direct":"unowned.example.test";dns["servers"]=servers;g["dns"]=dns
    };g["outbounds"]=outs
    reject("composite DNS requires captured "+fault){_ = try RouterVPNMultihopGraph.compositeDNSPolicy(["sing-box.json":json(g)],profile:b.profile)}
   }
   for fault in ["empty","owner-key","dns","route","extra-output"]{
    reject("temporary composite base changed "+fault){_ = try IOSNativeCompositeMultihop.capture(root:a.root,mode:mode,profile:a.profile,nodeID:a.composite!.nodeID,layer:a.layer.mode,compiler:compositeCompile){config,m,node,layer in
     if fault=="empty"{return ""};var g=try object(Data(compositeBase(config,m,node,layer).utf8)),outs=g["outbounds"] as! [[String:Any]]
     switch fault{case "owner-key":outs[0]["udp"]=outs[0]["tcp"];case "dns":g["dns"]=["servers":[["type":"local","tag":"system"]]];case "route":g["route"]=["final":"direct"];default:outs.append(["type":"direct","tag":"direct"])}
     g["outbounds"]=outs;return try text(g)
    }}
   }
   reject("missing complete entry source"){_ = try IOSNativeCompositeMultihop.compose(files:initial,metadata:meta,entry:nil,exit:b.composite,compiler:compositeCompose)}
   reject("borrowed node source"){_ = try IOSNativeCompositeMultihop.compose(files:initial,metadata:meta,entry:b.composite,exit:b.composite,compiler:compositeCompose)}
   reject("unrestored construction"){_ = try IOSNativeCompositeMultihop.compose(files:initial,metadata:meta,entry:a.composite,exit:b.composite){config,_,_,_ in config}}
   for fault in ["empty","compiler","tcp-key","udp-key","lane","layer","proof","dns","inbound","metadata"]{
    reject("compiler mutation "+fault){_ = try IOSNativeCompositeMultihop.compose(files:initial,metadata:meta,entry:a.composite,exit:b.composite){config,m,e,x in
     if fault=="compiler"{throw NSError(domain:"InjectedNativeCompiler",code:1)};if fault=="empty"{return ""}
     var g=try object(Data(compositeCompose(config,m,e,x).utf8)),outputs=g["outbounds"] as! [[String:Any]]
     switch fault{
     case "tcp-key","udp-key":let suffix=fault=="tcp-key" ? "tcp":"udp";let i=outputs.firstIndex{$0["tag"] as? String=="routervpn-entry-composite-"+suffix}!;outputs[i]["password"]="different-captured-secret"
     case "lane":let i=outputs.firstIndex{$0["tag"] as? String==RouterVPNMultihopGraph.entryTag}!;outputs[i]["udp"]=outputs[i]["tcp"]
     case "layer":outputs.removeLast()
     case "proof":let i=outputs.firstIndex{$0["tag"] as? String==RouterVPNMultihopGraph.entryPrivateTag}!;outputs[i]["detour"]="direct"
     case "dns":g["dns"]=["servers":[["type":"local","tag":"system"]]]
     case "inbound":var ins=g["inbounds"] as! [[String:Any]];ins.append(ins[0]);g["inbounds"]=ins
     default:g["unrequested_owner"]=true
     };g["outbounds"]=outputs;return try text(g)
    }}
   }
   for fault in ["entry-selection","entry-proof","exit-selection","raw-mode","missing-helper","extra-helper","foreign-aes","layer","duplicate-entry","same-node"]{
    var (provider,root,exit)=try sourceRoots(a,b,"auto"),entry=try object(provider["entryBundle"] as! Data)
    switch fault{
    case "entry-selection":entry["selectedRouterID"]="wrong"
    case "entry-proof":entry["nodeProofId"]=String(repeating:"f",count:64)
    case "exit-selection":root["selectedRouterID"]="wrong"
    case "raw-mode":provider["rawProfileID"]="wg"
    case "duplicate-entry":entry["routerProfiles"]=[a.profile,a.profile]
    case "layer":var p=a.profile;p["start_layer"]="xor";entry["routerProfiles"]=[p]
    case "same-node":exit["node_proof_id"]=a.profile["node_proof_id"];root["nodeProofId"]=a.profile["node_proof_id"]
    default:var profiles=entry["profiles"] as! [String:[String:String]]
     if fault=="missing-helper"{profiles[mode]!.removeValue(forKey:mode=="ss-v2ray" ? "sslocal.json":"xray.json")}
     else if fault=="extra-helper"{profiles[mode]!["run.sh"]=Data("unexpected".utf8).base64EncodedString()}
     else{profiles["shadowsocks"]=(b.root["profiles"] as! [String:[String:String]])["shadowsocks"]}
     entry["profiles"]=profiles
    }
    provider["entryBundle"]=try json(entry)
    let before=try text(entry)
    reject("production rejects "+fault){_ = try ProviderPreparation().prepare(provider:provider,root:root,selectedProfile:exit)}
    try check("rejection retains captured source",text(entry)==before)
   }
   let roots=try sourceRoots(a,b,"auto")
   for flag in ["includeAllNetworks","enforceRoutes","excludeLocalNetworks","missing"]{
    let owner=ProviderPreparation(),proto=NETunnelProviderProtocol();owner.protocolConfiguration=proto
    switch flag{case "includeAllNetworks":proto.includeAllNetworks=false;case "enforceRoutes":proto.enforceRoutes=false;case "excludeLocalNetworks":proto.excludeLocalNetworks=true;default:owner.protocolConfiguration=nil}
    reject("production strict guard "+flag){_ = try owner.prepare(provider:roots.0,root:roots.1,selectedProfile:roots.2)}
   }
   reject("embedded entry layer may not be duplicated"){_ = try IOSMultihopStartLayer.requiredSource(metadata:meta,source:"{}")}
   reject("embedded exit layer may not be duplicated"){_ = try IOSMultihopStartLayer.requiredExitSource(metadata:meta,source:"{}")}
  }
  print("Apple composite multihop: \(graphs) Swift/Go graphs + \(assemblies) production assemblies, \(checks) checks passed (configuration and policy proof; OS handles doubled)")
 }
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ios-composite-multihop-') as tmp:
        folder=Path(tmp); generator=folder/'assets'
        subprocess.run(['go','build','-o',str(generator),'./deploy/testfixtures/composite'],cwd=ROOT,check=True,timeout=90)
        names={'ROUTERVPN_COMPOSITE_ENTRY':[],'ROUTERVPN_COMPOSITE_EXIT':['--exits']}
        old={key:os.environ.get(key) for key in names}
        try:
            for key,args in names.items():
                path=folder/(key+'.json')
                with path.open('wb') as output:subprocess.run([str(generator),*args],stdout=output,check=True,timeout=30)
                os.environ[key]=str(path)
            M.main()
        finally:
            for key,value in old.items():
                if value is None:os.environ.pop(key,None)
                else:os.environ[key]=value


if __name__=='__main__':main()
