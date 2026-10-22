#!/usr/bin/env python3
"""Execute Apple's MAX capture/composition with shipping Swift and real Go policy.

These are host configuration tests, not real VPN/protocol or Xcode tests. The
existing Network.framework literal shim is used only on Linux. Native traffic,
permission/lifecycle testing and signed deployment retain independent gates.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('apple_max_multihop_host', ROOT/'deploy/test_ios_pq_selection.py')
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)
anchor = ' case "compile":value,err=mobilemultihop.CompilePQProfile(r.Mode,r.Files,r.Node)'
assert P.GO.count(anchor) == 1
P.GO = P.GO.replace(anchor, ''' case "max-compile":value,err=mobilemultihop.CompileMAXProfile(r.Mode,r.Files,r.Policy)
 case "composite-compile":value,err=mobilemultihop.CompileCompositeProfile(r.Mode,r.Files,r.Policy,r.Source)
 case "composite-base":value,err=mobilemultihop.CompositeMultihopBase(r.Config,r.Mode,r.Node,r.Policy)
 case "composite-compose":
  var src struct{Entry,Exit string};err=json.Unmarshal([]byte(r.Source),&src)
  if err==nil{value,err=mobilemultihop.ComposeCompositeMultihop(r.Config,r.Policy,src.Entry,src.Exit)}
 case "max-base":value,err=mobilemultihop.MAXMultihopBase(r.Config,r.Mode,r.Node,r.Policy)
 case "max-compose":
  var src struct{Entry,Exit string};err=json.Unmarshal([]byte(r.Source),&src)
  if err==nil{value,err=mobilemultihop.ComposeMAXMultihop(r.Config,r.Policy,src.Entry,src.Exit)}
'''+anchor, 1)
# Compile the exact production pre-start assembly too. Only the unexercised
# ordinary WG/AWG leaf parsers and OS/engine startup below the boundary are
# excluded; selected-profile/proof validation and every MAX compiler call run.
provider = (ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
def method(name, following):
    return provider[provider.index('    private func '+name+'('):provider.index('    private func '+following+'(')]
prepare = method('startMultihop', 'multihopWireGuardEndpoint')
prepare = prepare[:prepare.index('        let strict = strictKillSwitchRequested(')]
prepare = prepare.replace('private func startMultihop(', 'func prepare(', 1)
prepare = prepare.replace(', completionHandler: @escaping (Error?) -> Void) throws {', ') throws -> Prepared {', 1)
prepare += '        return Prepared(files: finalFiles, metadata: hopMetadata, entryLayer: entryLayer.source, exitLayer: exitLayer.source, mtuProfile: mtuProfileData)\n    }\n'
PROVIDER = r''' 
@MainActor final class ProviderPreparation {
 static let maxProfileBytes=4*1024*1024, maxBundleBytes=32*1024*1024, maxLayeredBytes=12*1024*1024
 var restoredMultihopExecution:String?
 struct Prepared {let files:[String:Data];let metadata:String;let entryLayer:String?;let exitLayer:String?;let mtuProfile:Data}
 func tunnelError(_ code:Int,_ message:String)->NSError{NSError(domain:"ProductionPreparationTest",code:code,userInfo:[NSLocalizedDescriptionKey:message])}
 func multihopWireGuardEndpoint(root:[String:Any],expectedProofID:String,name:String)throws->(endpoint:[String:Any],dns:[String]){throw tunnelError(1,"ordinary raw helper has separate native tests")}
 func nativeAmneziaEndpoint(root:[String:Any],expectedProofID:String,mode:String)throws->(endpoint:[String:Any],dns:[String]){throw tunnelError(1,"ordinary AWG helper has separate native tests")}
 func performanceFiles(_ files:[String:Data],entryProfile:[String:Any],exitProfile:[String:Any])throws->[String:Data]{
  var files=files;files["sing-box.json"]=Data(try bridge(["Op":"performance","Config":String(decoding:files["sing-box.json"]!,as:UTF8.self),"Policy":text(["entry":entryProfile,"exit":exitProfile])]).utf8);return files
 }
'''
PROVIDER += method('multihopMAX', 'startMultihop') + prepare
PROVIDER += method('selectedRouterProfile', 'wireGuardLikeProfile') + method('layeredProfile', 'strictKillSwitchRequested') + method('suppliedNodeProof', 'deriveNodeProof') + '}\n'
PROVIDER += r'''
func apiResult(_ error:inout NSError?,_ action:()throws->String)->String?{do{return try action()}catch let caught{error=caught as NSError;return nil}}
func LibboxRouterCompileMAXProfile(_ mode:String,_ files:String,_ policy:String,_ error:inout NSError?)->String?{apiResult(&error){try maxCompile(mode,files,policy)}}
func LibboxRouterMAXMultihopBase(_ config:String,_ mode:String,_ node:String,_ layer:String,_ error:inout NSError?)->String?{apiResult(&error){try maxBase(config,mode,node,layer)}}
func LibboxRouterComposeMAXMultihop(_ config:String,_ meta:String,_ a:String,_ b:String,_ error:inout NSError?)->String?{apiResult(&error){try maxCompose(config,meta,a,b)}}
func LibboxRouterCompileCompositeProfile(_ mode:String,_ files:String,_ policy:String,_ start:String,_ error:inout NSError?)->String?{apiResult(&error){try bridge(["Op":"composite-compile","Mode":mode,"Files":files,"Policy":policy,"Source":start])}}
func LibboxRouterCompositeMultihopBase(_ config:String,_ mode:String,_ node:String,_ layer:String,_ error:inout NSError?)->String?{apiResult(&error){try bridge(["Op":"composite-base","Config":config,"Mode":mode,"Node":node,"Policy":layer])}}
func LibboxRouterComposeCompositeMultihop(_ config:String,_ meta:String,_ a:String,_ b:String,_ error:inout NSError?)->String?{apiResult(&error){try bridge(["Op":"composite-compose","Config":config,"Policy":meta,"Source":text(["Entry":a,"Exit":b])])}}
func LibboxRouterCompilePQProfile(_ mode:String,_ files:String,_ node:String,_ error:inout NSError?)->String?{apiResult(&error){try compile(mode,files,node)}}
func LibboxRouterCompileProxyEntry(_ files:String,_ mode:String,_ error:inout NSError?)->String?{error=NSError(domain:"UnexercisedOrdinaryCompiler",code:1);return nil}
func LibboxRouterCompileXrayExit(_ files:String,_ mode:String,_ error:inout NSError?)->String?{error=NSError(domain:"UnexercisedOrdinaryCompiler",code:1);return nil}
func LibboxRouterApplyMultihopMTUPolicy(_ config:String,_ policy:String,_ error:inout NSError?)->String?{apiResult(&error){try bridge(["Op":"mtu","Config":config,"Policy":policy])}}
func LibboxRouterMultihopMTUProfile(_ config:String,_ policy:String,_ error:inout NSError?)->String?{apiResult(&error){try bridge(["Op":"mtu-profile","Config":config,"Policy":policy])}}
func LibboxRouterApplyMultihopLANPolicy(_ config:String,_ policy:String,_ error:inout NSError?)->String?{apiResult(&error){try bridge(["Op":"lan","Config":config,"Policy":policy])}}
'''

P.SWIFT = P.SWIFT[:P.SWIFT.index('@main struct Tests')] + PROVIDER + r'''
func maxCompile(_ mode:String,_ files:String,_ policy:String)throws->String{try bridge(["Op":"max-compile","Mode":mode,"Files":files,"Policy":policy])}
func maxBase(_ config:String,_ mode:String,_ node:String,_ layer:String)throws->String{try bridge(["Op":"max-base","Config":config,"Mode":mode,"Node":node,"Policy":layer])}
func maxCompose(_ config:String,_ metadata:String,_ entry:String,_ exit:String)throws->String{
 try bridge(["Op":"max-compose","Config":config,"Policy":metadata,"Source":text(["Entry":entry,"Exit":exit])])
}
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ label:String,_ condition:@autoclosure ()throws->Bool)throws{guard try condition()else{fatalError("FAIL "+label)};checks+=1}
 @MainActor static func reject(_ label:String,_ action:()throws->Void){do{try action();fatalError("ACCEPTED "+label)}catch{checks+=1}}
 struct Hop {
  let mode:String
  var profile:[String:Any]
  let originalFiles:[String:Data]
  let endpoint:[String:Any]
  let capture:IOSNativeMAXMultihop.Capture?
  let layer:IOSMultihopStartLayer.Capture
 }
 static func at(_ graph:[String:Any],_ tag:String)throws->[String:Any]{
  let values=((graph["endpoints"] as? [[String:Any]] ?? [])+(graph["outbounds"] as? [[String:Any]] ?? [])).filter{$0["tag"] as? String==tag}
  guard values.count==1 else{throw NSError(domain:"TestGraphOwner",code:1)};return values[0]
 }
 @MainActor static func hop(_ fixtures:[String:Any],_ role:String,_ mode:String,_ layer:String,_ fixed:Int)throws->Hop{
  let service=role=="entry" ? "10.77.0.1":"10.88.0.1"
  if IOSNativeMAXProfile.modeIDs.contains(mode){
   let f=(fixtures[role] as! [String:Any])[mode] as! [String:Any]
   let assets=f["files"] as! [String:String],policy=f["policy"] as! [String:String],node=policy["node_id"]!
   var p=profile(node,role=="exit" ? "doh3":"home",layer)
   p["id"]=role;p["endpoint"]=policy["endpoint"];p["router_api"]=policy["router_api"];p["socks_host"]=service;p["manual_mtu"]=fixed;p["api_token"]=role+"-private-token"
   let before=try text(assets)
   let c=try IOSNativeMAXMultihop.capture(mode:mode,encoded:assets,nodeID:node,profile:p,startLayer:layer,compiler:maxCompile,baseCompiler:maxBase)
   var graphProfile=p;graphProfile["start_layer"]="off"
   let files=role=="exit" ? try RouterVPNMultihopGraph.pqDNSPolicy(c.baseFiles,profile:p):c.baseFiles
   try check("MAX raw assets stay immutable",text(assets)==before)
   return Hop(mode:mode,profile:p,originalFiles:files,endpoint:try c.endpoint(),capture:c,
              layer:IOSMultihopStartLayer.Capture(mode:layer,source:nil,graphProfile:graphProfile))
  }
  let f=try object(Data(bridge(["Op":"exit-fixture","Mode":mode]).utf8)),node=f["node"] as! String
  var p=profile(node,"home",layer);p["id"]=role;p["endpoint"]="198.51.100.2";p["router_api"]="http://\(service):8787";p["socks_host"]=service;p["manual_mtu"]=fixed;p["api_token"]=role+"-private-token"
  let graph=try object(Data((f["config"] as! String).utf8)),endpoint=try at(graph,"proxy")
  var aesGraph=try object(Data((try object(Data(bridge(["Op":"exit-fixture","Mode":"shadowsocks"]).utf8))["config"] as! String).utf8))
  var aes=(aesGraph["outbounds"] as! [[String:Any]])[0];aes["server"]="198.51.100.2";aes["server_port"]=8388;aesGraph["outbounds"]=[aes]
  let assets=["shadowsocks":["sing-box.json":try json(aesGraph).base64EncodedString()]]
  return Hop(mode:mode,profile:p,originalFiles:["sing-box.json":try json(graph)],endpoint:endpoint,capture:nil,
             layer:try IOSMultihopStartLayer.capture(profile:p,profiles:assets))
 }
 @MainActor static func metadata(_ a:Hop,_ b:Hop,_ execution:String)throws->String{
  var meta:[String:String]=["entry_id":"entry","exit_id":"exit","entry_node_id":a.profile["node_proof_id"] as! String,"exit_node_id":b.profile["node_proof_id"] as! String,
    "entry_api":a.profile["router_api"] as! String,"exit_api":b.profile["router_api"] as! String,
    "entry_token":"entry-private-token","exit_token":"exit-private-token","entry_tag":RouterVPNMultihopGraph.entryTag,
    "entry_mode":a.mode,"exit_mode":b.mode,"execution":execution]
  if a.layer.mode != "off"{meta["entry_start_layer"]=a.layer.mode}
  if b.layer.mode != "off"{meta["exit_start_layer"]=b.layer.mode}
  return try text(meta)
 }
 @MainActor static func construction(_ a:Hop,_ b:Hop)throws->[String:Data]{
  var exit=b.layer.graphProfile;exit["multihop_entry_mode"]=a.capture?.baseMode ?? a.mode
  return try RouterVPNMultihopGraph.build(entryEndpoint:a.endpoint,entryProfile:a.layer.graphProfile,exitProfile:exit,
                                        exitMode:b.capture?.baseMode ?? b.mode,files:b.originalFiles)
 }
 @MainActor static func sourceRoots(_ fixtures:[String:Any],_ a:Hop,_ b:Hop,_ execution:String)throws->([String:Any],[String:Any],[String:Any]){
  let ap=(fixtures["entry"] as! [String:Any])[a.mode] as! [String:Any],bp=(fixtures["exit"] as! [String:Any])[b.mode] as! [String:Any]
  var exit=b.profile;exit["multihop_enabled"]=true;exit["multihop_entry_id"]="entry";exit["multihop_exit_id"]="exit";exit["multihop_entry_mode"]=a.mode;exit["multihop_exit_mode"]=b.mode;exit["multihop_execution"]=execution
  let entry:[String:Any]=["selectedRouterID":"entry","nodeProofId":a.capture!.nodeID,"routerProfiles":[a.profile],"profiles":[a.mode:ap["files"]!]]
  let root:[String:Any]=["selectedRouterID":"exit","nodeProofId":b.capture!.nodeID,"routerProfiles":[exit],"profiles":[b.mode:bp["files"]!]]
  return (["rawProfileID":b.mode,"entryBundle":try json(entry)],root,exit)
 }
 @MainActor static func main()throws{
  defer{TestCompiler.shared.close()}
  let fixtures=try object(Data(contentsOf:URL(fileURLWithPath:ProcessInfo.processInfo.environment["ROUTERVPN_MAX_MULTIHOP_FIXTURES"]!)))
  let modes=["max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg","wg","awg2-fast","shadowsocks","hysteria2"]
  let layers=[("off","off"),("aes-256-gcm","off"),("off","aes-256-gcm+xor-whitening"),("aes-256-gcm+xor-whitening","aes-256-gcm")]
  var graphs=0,assemblies=0
  for am in modes{for bm in modes where IOSNativeMAXProfile.modeIDs.contains(am)||IOSNativeMAXProfile.modeIDs.contains(bm){
   for (al,bl) in layers{for execution in ["local","server","auto"]{
    let entryFixed=["shadowsocks","hysteria2"].contains(am) ? 1280:1500
    let a=try hop(fixtures,"entry",am,al,entryFixed),b=try hop(fixtures,"exit",bm,bl,1280)
    let meta=try metadata(a,b,execution),initial=try construction(a,b)
    let before=try text(try object(initial["sing-box.json"]!))
    let restored=try IOSNativeMAXMultihop.compose(files:initial,metadata:meta,entry:a.capture,exit:b.capture,compiler:maxCompose)
    try check("temporary construction stays immutable",text(try object(initial["sing-box.json"]!))==before)
    try check("one compiled file, not executable helper assets",restored.count==1)
    let layerA=try IOSMultihopStartLayer.requiredSource(metadata:meta,source:a.layer.source)
    let layerB=try IOSMultihopStartLayer.requiredExitSource(metadata:meta,source:b.layer.source)
    if a.capture != nil{try check("MAX does not double-wrap entry layer",layerA==nil)}
    if b.capture != nil{try check("MAX does not double-wrap exit layer",layerB==nil)}
    let policies=try text(["entry":a.profile,"exit":b.profile])
    var config=try bridge(["Op":"mtu","Config":String(decoding:restored["sing-box.json"]!,as:UTF8.self),"Policy":policies])
    let mtuProfile=try object(Data(bridge(["Op":"mtu-profile","Config":config,"Policy":policies]).utf8))
    try check("MTU metadata retains fixed preference",mtuProfile["mtu_policy"] as? String=="fixed")
    config=try bridge(["Op":"lan","Config":config,"Policy":policies])
    config=try bridge(["Op":"performance","Config":config,"Policy":policies])
    if let ac=a.capture,let bc=b.capture {
     let roots=try sourceRoots(fixtures,a,b,execution)
     let prepared=try ProviderPreparation().prepare(provider:roots.0,root:roots.1,selectedProfile:roots.2)
     try check("production assembly retains the exact complete graph",text(try object(prepared.files["sing-box.json"]!))==text(try object(Data(config.utf8))))
     try check("production assembly preserves captured metadata",text(try object(Data(prepared.metadata.utf8)))==text(try object(Data(meta.utf8))))
     let launchedPolicy=try text(["entry":a.profile,"exit":roots.2])
     let launchedMTU=try object(Data(bridge(["Op":"mtu-profile","Config":config,"Policy":launchedPolicy]).utf8))
     try check("production MTU metadata preserves the launched profile",text(try object(prepared.mtuProfile))==text(launchedMTU))
     try check("complete MAX layers are not duplicated",prepared.entryLayer==nil && prepared.exitLayer==nil && ac.mode==am && bc.mode==bm)
      if execution=="auto" {for winner in ["local","server"] {
       let owner=ProviderPreparation();owner.restoredMultihopExecution=winner
       let resumed=try owner.prepare(provider:roots.0,root:roots.1,selectedProfile:roots.2)
       var expected=try object(Data(meta.utf8));expected["execution"]=winner
       try check("production restoration retains the proved winner",text(try object(Data(resumed.metadata.utf8)))==text(expected))
       try check("runtime restoration leaves saved Compare policy unchanged",roots.2["multihop_execution"] as? String=="auto")
      }}
     assemblies+=1
    }
    let planned=try bridge(["Op":"plan","Config":config,"Policy":meta,"Source":text(["Entry":layerA ?? "","Exit":layerB ?? ""])])
    let graph=try object(Data(planned.utf8)),ins=graph["inbounds"] as! [[String:Any]]
    try check("one system VPN",ins.filter{$0["type"] as? String=="tun"}.count==1)
    let entry=try at(graph,RouterVPNMultihopGraph.entryTag)
    let exit=try at(graph,"routervpn-execution-local")
    try check("entry proof remains on captured entry",at(graph,RouterVPNMultihopGraph.entryPrivateTag)["detour"] as? String==RouterVPNMultihopGraph.entryTag)
    try check("separate independently paired nodes",a.profile["node_proof_id"] as? String != b.profile["node_proof_id"] as? String)
    for (c,endpoint,prefix,via) in [(a.capture,entry,"routervpn-entry-max-",""),(b.capture,exit,"routervpn-exit-max-",RouterVPNMultihopGraph.entryTag)]{
     guard let c else{continue}
     let original=try object(Data(c.source.utf8)),base=(original["endpoints"] as! [[String:Any]])[0]
     try check("required negotiated-key base",endpoint["type"] as? String=="routervpn-pq" && endpoint["mode"] as? String==c.baseMode && endpoint["node_id"] as? String==c.nodeID)
     for key in ["private_key","pq","amnezia","address","peers"]{try check("exact captured MAX identity "+key,text(["value":endpoint[key] ?? NSNull()])==text(["value":base[key] ?? NSNull()]))}
     try check("base keeps middle encryption",endpoint["detour"] as? String==prefix+"ss")
     try check("middle keeps outer encryption",at(graph,prefix+"ss")["detour"] as? String==prefix+"outer")
     let finalTag=prefix+(c.startLayer=="off" ? "outer":"start")
     try check("outermost path keeps entry ownership",(at(graph,finalTag)["detour"] as? String ?? "")==via)
     if !via.isEmpty{try check("exit does not bypass its entry",at(graph,finalTag)["type"] as? String != "direct")}
    }
    let servers=(graph["dns"] as! [String:Any])["servers"] as! [[String:Any]]
    try check("AdGuard is not substituted",servers.allSatisfy{$0["server"] as? String=="192.168.50.133" && $0["detour"] as? String=="proxy"})
    if b.capture != nil{try check("encrypted exit DNS preserved",servers.last!["type"] as? String=="h3")}
    let rules=(graph["route"] as! [String:Any])["rules"] as! [[String:Any]]
    try check("LAN-Off remains enforced",rules.contains{$0["action"] as? String=="reject" && ($0["ip_cidr"] as? [String] ?? []).contains("192.168.0.0/16")})
    try check("IPv6-Off remains enforced",rules.contains{$0["action"] as? String=="reject" && $0["ip_version"] as? Int==6})
    try check("entry MTU preserved",entry["mtu"] as? Int==entryFixed || a.capture==nil)
    try check("exact exit MTU",exit["mtu"] as? Int==1280 || b.capture==nil)
    graphs+=1
   }}
  }}
  try check("full MAX both-direction graph matrix",graphs==576)
  try check("actual production assembly matrix",assemblies==192)
  let a=try hop(fixtures,"entry","max-tls-wg","aes-256-gcm",1500),b=try hop(fixtures,"exit","max-quic-awg","aes-256-gcm+xor-whitening",1280)
  let meta=try metadata(a,b,"auto"),initial=try construction(a,b)
  reject("missing complete source"){_ = try IOSNativeMAXMultihop.compose(files:initial,metadata:meta,entry:nil,exit:b.capture,compiler:maxCompose)}
  reject("wrong node source"){_ = try IOSNativeMAXMultihop.compose(files:initial,metadata:meta,entry:b.capture,exit:b.capture,compiler:maxCompose)}
  reject("native compiler failed"){_ = try IOSNativeMAXMultihop.compose(files:initial,metadata:meta,entry:a.capture,exit:b.capture){_,_,_,_ in throw NSError(domain:"test",code:1)}}
  reject("unrestored construction"){_ = try IOSNativeMAXMultihop.compose(files:initial,metadata:meta,entry:a.capture,exit:b.capture){config,_,_,_ in config}}
  for fault in ["empty","key","layer","dns","proof","inbound","metadata"]{
   reject("native composition lost "+fault){
    _ = try IOSNativeMAXMultihop.compose(files:initial,metadata:meta,entry:a.capture,exit:b.capture){config,m,ea,ex in
     if fault=="empty"{return ""};var graph=try object(Data(maxCompose(config,m,ea,ex).utf8))
     switch fault{
     case "key":var es=graph["endpoints"] as! [[String:Any]];es[0]["private_key"]=key(4);graph["endpoints"]=es
     case "layer":var outs=graph["outbounds"] as! [[String:Any]];outs.removeLast();graph["outbounds"]=outs
     case "dns":graph["dns"]=["servers":[["type":"local","tag":"system"]]]
     case "proof":var outs=graph["outbounds"] as! [[String:Any]];let i=outs.firstIndex{$0["tag"] as? String==RouterVPNMultihopGraph.entryPrivateTag}!;outs[i]["detour"]="direct";graph["outbounds"]=outs
     case "inbound":var ins=graph["inbounds"] as! [[String:Any]];ins.append(ins[0]);graph["inbounds"]=ins
     default:graph["unrequested_owner"]=true
     };return try text(graph)
    }
   }
  }
  let source=(fixtures["entry"] as! [String:Any])["max-tls-wg"] as! [String:Any]
  let assets=source["files"] as! [String:String]
  for failure in ["empty","keys","route","layer"]{
   reject("temporary base corruption "+failure){
    _ = try IOSNativeMAXMultihop.capture(mode:a.mode,encoded:assets,nodeID:a.capture!.nodeID,profile:a.profile,startLayer:a.layer.mode,compiler:maxCompile){config,mode,node,layer in
     if failure=="empty"{return ""};var graph=try object(Data(maxBase(config,mode,node,layer).utf8))
     if failure=="keys"{var es=graph["endpoints"] as! [[String:Any]];es[0]["private_key"]=key(9);graph["endpoints"]=es}
     else if failure=="route"{graph["route"]=["final":"direct"]}
     else{graph["outbounds"]=[["type":"direct","tag":"bypass"]]}
     return try text(graph)
    }
   }
  }
  reject("MAX duplicated entry layer"){_ = try IOSMultihopStartLayer.requiredSource(metadata:meta,source:"{}")}
  reject("MAX duplicated exit layer"){_ = try IOSMultihopStartLayer.requiredExitSource(metadata:meta,source:"{}")}
  var ordinary=try object(Data(meta.utf8));ordinary["entry_mode"]="wg"
  reject("ordinary entry still needs selected layer"){_ = try IOSMultihopStartLayer.requiredSource(metadata:text(ordinary),source:nil)}
  ordinary=try object(Data(meta.utf8));ordinary["exit_mode"]="wg"
  reject("MAX entry does not waive ordinary exit layer"){_ = try IOSMultihopStartLayer.requiredExitSource(metadata:text(ordinary),source:nil)}
  for fault in ["entry-selection","entry-identity","exit-selection","raw-mode","missing-assets","mode","duplicate-entry"]{
   var (provider,root,exit)=try sourceRoots(fixtures,a,b,"auto")
   var entry=try object(provider["entryBundle"] as! Data)
   switch fault{
   case "entry-selection":entry["selectedRouterID"]="wrong"
   case "entry-identity":entry["nodeProofId"]=String(repeating:"f",count:64)
   case "exit-selection":root["selectedRouterID"]="wrong"
   case "raw-mode":provider["rawProfileID"]="wg"
   case "missing-assets":entry["profiles"]=[String:String]()
   case "mode":exit["multihop_entry_mode"]="max"
   default:entry["routerProfiles"]=[a.profile,a.profile]
   }
   provider["entryBundle"]=try json(entry)
   reject("production prefix rejects "+fault){_ = try ProviderPreparation().prepare(provider:provider,root:root,selectedProfile:exit)}
  }
  print("Apple complete MAX multihop: \(graphs) Swift/Go graphs + \(assemblies) production assemblies, \(checks) checks passed (no physical VPN or native crypto simulated)")
 }
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ios-max-multihop-fixtures-') as tmp:
        fixture = Path(tmp)/'profiles.json'
        subprocess.run(['go','test','-count=1','-run','^TestExportMAXMultihopMobileProfiles$','./internal/mobilemultihop'], cwd=ROOT,
                       env=dict(os.environ, ROUTERVPN_MAX_MULTIHOP_FIXTURES=str(fixture)), check=True, timeout=120)
        before=os.environ.get('ROUTERVPN_MAX_MULTIHOP_FIXTURES');os.environ['ROUTERVPN_MAX_MULTIHOP_FIXTURES']=str(fixture)
        try: P.main()
        finally:
            if before is None: os.environ.pop('ROUTERVPN_MAX_MULTIHOP_FIXTURES',None)
            else: os.environ['ROUTERVPN_MAX_MULTIHOP_FIXTURES']=before

if __name__=='__main__': main()
