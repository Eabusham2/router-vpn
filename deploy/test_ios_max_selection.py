#!/usr/bin/env python3
"""Run complete MAX selection and device policy using shipping Swift and Go.

Network.framework literal parsing uses the Linux test shim. No VPN, physical
traffic, Rust exchange or Apple signing is claimed by these host policy tests.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('apple_max_host',ROOT/'deploy/test_ios_pq_selection.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
a=' case "compile":value,err=mobilemultihop.CompilePQProfile(r.Mode,r.Files,r.Node)'
assert P.GO.count(a)==1
P.GO=P.GO.replace(a,' case "compile-max":value,err=mobilemultihop.CompileMAXProfile(r.Mode,r.Files,r.Policy)\n'+a,1)
P.SWIFT=P.SWIFT[:P.SWIFT.index('@main struct Tests')]+r'''
func compileMAX(_ mode:String,_ files:String,_ policy:String)throws->String {try bridge(["Op":"compile-max","Mode":mode,"Files":files,"Policy":policy])}
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ message:String,_ value:@autoclosure ()throws->Bool)throws{guard try value() else{fatalError(message)};checks+=1}
 @MainActor static func reject(_ message:String,_ action:()throws->Void){do{try action();fatalError("accepted "+message)}catch{checks+=1}}
 @MainActor static func main()throws{
  defer{TestCompiler.shared.close()}
  let path=ProcessInfo.processInfo.environment["ROUTERVPN_MAX_PROFILE_FIXTURES"]!
  let fixtures=try object(Data(contentsOf:URL(fileURLWithPath:path)))
  let first=fixtures["max-tls-wg"] as! [String:Any],firstPolicy=first["policy"] as! [String:String]
  var allProfile=profile(firstPolicy["node_id"]!,"home","off")
  allProfile["endpoint"]=firstPolicy["endpoint"];allProfile["router_api"]=firstPolicy["router_api"]
  var allBundle=try bundle("max-tls-wg",first["files"] as! [String:String],firstPolicy["node_id"]!,allProfile)
  for mode in ["max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"] { allBundle.profiles[mode]=(fixtures[mode] as! [String:Any])["files"] as? [String:String] }
  allBundle.logicalModes=[
   LogicalMode(id:"max-tls",name:"TLS",description:"",baseSelector:true,fallback:true,variants:["wg":"max-tls-wg","awg":"max-tls-awg"]),
   LogicalMode(id:"max-quic",name:"QUIC",description:"",baseSelector:true,fallback:true,variants:["wg":"max-quic-wg","awg":"max-quic-awg"]),
   LogicalMode(id:"all",name:"ALL",description:"",baseSelector:true,fallback:true,variants:["wg":"all","awg":"all"])]
  for (base,fallback,expected) in [
   ("auto",false,["max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"]),
   ("wg",false,["max-tls-wg","max-quic-wg"]),
   ("awg",false,["max-tls-awg","max-quic-awg"]),
   ("wg",true,["max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"]),
   ("awg",true,["max-tls-awg","max-tls-wg","max-quic-awg","max-quic-wg"])] {
    allBundle.routerProfiles[0].baseTunnel=base;allBundle.routerProfiles[0].baseFallback=fallback
    let selections=try IOSRuntimeSelector.candidates(bundle:allBundle,logicalModeID:"all")
    try check("ALL exact complete TLS then QUIC order "+base,selections.map(\.rawProfileID)==expected)
    try check("ALL uses canonical captured MAX membership",selections.allSatisfy{$0.logicalModeID==($0.rawProfileID.hasPrefix("max-tls-") ? "max-tls":"max-quic")})
    try check("ALL appears as executable logical choice",IOSRuntimeSelector.runnableModes(in:allBundle).contains{$0.id=="all"})
  }
  var noMAX=allBundle;noMAX.profiles.removeAll();reject("ALL cannot substitute a weaker mode"){_ = try IOSRuntimeSelector.candidates(bundle:noMAX,logicalModeID:"all")}
  allBundle.routerProfiles[0].baseTunnel="foreign";reject("ALL rejects unknown base"){_ = try IOSRuntimeSelector.candidates(bundle:allBundle,logicalModeID:"all")}
  var graphs=0
  for mode in ["max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg"]{
   let fixture=fixtures[mode] as! [String:Any],assets=fixture["files"] as! [String:String],policy=fixture["policy"] as! [String:String],node=policy["node_id"]!
   let original=try text(assets)
   for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"]{for dns in ["home","custom","dot","doh","doh3","hostname"]{
    var p=profile(node,dns,layer);p["endpoint"]=policy["endpoint"];p["router_api"]=policy["router_api"]
    var b=try bundle(mode,assets,node,p)
    let family=mode.hasPrefix("max-tls-") ? "max-tls":"max-quic"
    b.logicalModes=[LogicalMode(id:family,name:family,description:"",baseSelector:true,fallback:true,variants:[mode.hasSuffix("-awg") ? "awg":"wg":mode])]
    b.routerProfiles[0].baseTunnel=mode.hasSuffix("-awg") ? "awg":"wg"
    let selection=try IOSRuntimeSelector.selectRaw(bundle:b,rawProfileID:mode)
    try check("complete MAX uses existing Libbox PacketTunnel",selection.engine == .libbox && selection.rawProfileID==mode)
    try check("logical base keeps complete MAX chain",IOSRuntimeSelector.select(bundle:b,logicalModeID:family).rawProfileID==mode)
    try check("selection captured immutable generated assets",selection.files==IOSNativeMAXProfile.decode(mode:mode,encoded:assets))
    let compiled=try IOSNativeMAXProfile.compile(mode:mode,encoded:assets,nodeID:node,profile:p,startLayer:layer,compiler:compileMAX)
    let before=try object(compiled["sing-box.json"]!)
    var files=try RouterVPNMultihopGraph.singlePQPolicy(compiled,profile:p)
    files=try RouterVPNMTUPolicy.libbox(files,profile:p)
    let settings=try text(["entry":p,"exit":p])
    let lan=try bridge(["Op":"lan","Config":String(decoding:files["sing-box.json"]!,as:UTF8.self),"Policy":settings])
    let graph=try object(Data(bridge(["Op":"performance","Config":lan,"Policy":settings]).utf8))
    let endpoints=graph["endpoints"] as! [[String:Any]],inbounds=graph["inbounds"] as! [[String:Any]],out=graph["outbounds"] as! [[String:Any]],ep=endpoints[0],pq=ep["pq"] as! [String:Any]
    try check("one TUN and base endpoint",endpoints.count==1 && inbounds.count==1 && files.count==1)
    try check("mandatory independent PQ mode retained",ep["type"] as? String=="routervpn-pq" && ep["mode"] as? String==(mode.hasSuffix("-awg") ? "awg2-pq":"wg-pq"))
    try check("captured node and ordered base detour",ep["node_id"] as? String==node && ep["detour"] as? String=="routervpn-max-ss")
    for (key,asset) in [("secret","rosenpass-client-secret"),("public","rosenpass-client-public"),("peer","rosenpass-server-public")]{try check("captured PQ key "+key,pq[key] as? String==assets[asset])}
    let originalEndpoint=(before["endpoints"] as! [[String:Any]])[0]
    for field in ["private_key","peers","pq"]{try check("key and peer immutable "+field,text([field:ep[field]!])==text([field:originalEndpoint[field]!]))}
    if mode.hasSuffix("-awg"){try check("all AWG parameters unchanged",text(ep["amnezia"]!)==text(originalEndpoint["amnezia"]!))}
    try check("fixed MTU owns both interfaces",ep["mtu"] as? Int==1350 && inbounds[0]["mtu"] as? Int==1350)
    try check("all outer encryption preserved by device policy",text(out)==text(before["outbounds"]!))
    try check("full chain never becomes a direct/proxy shortcut",out.count==(layer=="off" ? 2:3) && out.allSatisfy{$0["type"] as? String != "direct" && $0["server"] as? String != "127.0.0.1"})
    try check("SS2022 middle exists",out[0]["type"] as? String=="shadowsocks" && out[0]["detour"] as? String=="routervpn-max-outer")
    try check("selected TLS/QUIC outer exists",out[1]["type"] as? String==(mode.hasPrefix("max-tls-") ? "routervpn-xray":"hysteria2"))
    let d=graph["dns"] as! [String:Any],servers=d["servers"] as! [[String:Any]],selected=servers.last!
    let transport=dns=="custom" ? "tcp":dns=="dot" ? "tls":dns=="doh3" ? "h3":dns=="doh"||dns=="hostname" ? "https":"udp"
    try check("selected DNS transport",selected["type"] as? String==transport)
    try check("AdGuard not substituted",selected["server"] as? String==(dns=="hostname" ? "resolver.example.test":"192.168.50.133"))
    try check("DNS traverses full MAX path",servers.allSatisfy{$0["detour"] as? String=="proxy"})
    if dns=="custom"{try check("custom DNS port",selected["server_port"] as? Int==5353)}
    let rules=(graph["route"] as! [String:Any])["rules"] as! [[String:Any]]
    try check("IPv6 remains captured and rejected",rules.contains{$0["action"] as? String=="reject" && $0["ip_version"] as? Int==6})
    try check("LAN access disabled",rules.contains{$0["action"] as? String=="reject" && ($0["ip_cidr"] as? [String] ?? []).contains("192.168.0.0/16")})
    try check("padding uses the negotiated base",(graph["services"] as! [[String:Any]])[0]["packet_tag"] as? String=="proxy")
    try check("saved source unchanged",text(assets)==original)
    graphs+=1
   }}
   var p=profile(node,"home","off");p["endpoint"]=policy["endpoint"];p["router_api"]=policy["router_api"]
   let good=try IOSNativeMAXProfile.compile(mode:mode,encoded:assets,nodeID:node,profile:p,startLayer:"off",compiler:compileMAX)
   for name in assets.keys where name != "stack.json" && !name.hasSuffix("-socks.conf"){var bad=assets;bad.removeValue(forKey:name);reject("missing "+name){_ = try IOSNativeMAXProfile.decode(mode:mode,encoded:bad)}}
   for name in ["../escape","run.sh","sing-box.json"]{var bad=assets;bad[name]=Data("unowned".utf8).base64EncodedString();reject("unowned file "+name){_ = try IOSNativeMAXProfile.decode(mode:mode,encoded:bad)}}
   var bad=assets;bad["rosenpass-server-public"]=assets["rosenpass-client-public"];reject("same PQ peer"){_ = try IOSNativeMAXProfile.decode(mode:mode,encoded:bad)}
   for (field,value) in [("node_kind","external"),("node_proof_id",String(repeating:"a",count:64)),("endpoint","192.0.2.99"),("router_api","http://127.0.0.1:8787")]{var changed=p;changed[field]=value;reject("captured node "+field){_ = try IOSNativeMAXProfile.compile(mode:mode,encoded:assets,nodeID:node,profile:changed,startLayer:"off",compiler:compileMAX)}}
   reject("empty compiler"){_ = try IOSNativeMAXProfile.compile(mode:mode,encoded:assets,nodeID:node,profile:p,startLayer:"off"){_,_,_ in ""}}
   for change in ["downgraded-base","missing-middle","wrong-outer","wrong-key","extra-vpn"]{
    var graph=try object(good["sing-box.json"]!),eps=graph["endpoints"] as! [[String:Any]],outs=graph["outbounds"] as! [[String:Any]]
    switch change{case "downgraded-base":eps[0]["type"]="wireguard";case "missing-middle":outs.removeFirst();case "wrong-outer":outs[1]["type"]="direct";case "extra-vpn":graph["inbounds"]=[(graph["inbounds"] as! [[String:Any]])[0],(graph["inbounds"] as! [[String:Any]])[0]];default:var pq=eps[0]["pq"] as! [String:Any];pq["secret"]=key(4);eps[0]["pq"]=pq}
    graph["endpoints"]=eps;graph["outbounds"]=outs;let result=try text(graph)
    reject(change){_ = try IOSNativeMAXProfile.compile(mode:mode,encoded:assets,nodeID:node,profile:p,startLayer:"off"){_,_,_ in result}}
   }
   var b=try bundle(mode,assets,node,p);b.selectedRouterID="missing";reject("missing captured profile"){_ = try IOSRuntimeSelector.selectRaw(bundle:b,rawProfileID:mode)}
   b=try bundle(mode,assets,node,p);b.routerProfiles.append(b.routerProfiles[0]);reject("ambiguous captured profile"){_ = try IOSRuntimeSelector.selectRaw(bundle:b,rawProfileID:mode)}
  }
  try check("all combinations executed",graphs==72)
  print("Apple complete MAX: \(graphs) real compiler graphs, \(checks) checks passed")
 }
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ios-max-fixtures-') as temp:
        fixture=Path(temp)/'profiles.json'
        subprocess.run(['go','test','-count=1','-run','^TestExportMAXMobileProfiles$','./internal/mobilemultihop'],cwd=ROOT,env=dict(os.environ,ROUTERVPN_MAX_PROFILE_FIXTURES=str(fixture)),check=True,timeout=90)
        before=os.environ.get('ROUTERVPN_MAX_PROFILE_FIXTURES');os.environ['ROUTERVPN_MAX_PROFILE_FIXTURES']=str(fixture)
        try:P.main()
        finally:
            if before is None:os.environ.pop('ROUTERVPN_MAX_PROFILE_FIXTURES',None)
            else:os.environ['ROUTERVPN_MAX_PROFILE_FIXTURES']=before
    source=(ROOT/'ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift').read_text()
    start=source[source.index('    private func startLibbox('):source.index('    private struct LibboxCompilation')]
    compiler=source[source.index('    private func compileLibbox('):source.index('    private func performanceFiles(')]
    assert start.index('let compiled = try compileLibbox(')<start.index('let files = compiled.files, provenNodeID = compiled.nodeID')<start.index('engine.start(files: files')<start.index('proveSelectedNode(')
    assert compiler.index('IOSNativeMAXProfile.compile(')<compiler.index('return LibboxCompilation(files: files, nodeID: expectedNodeID')
    assert 'expectedNodeID: provenNodeID' in start
    for token in ('LibboxRouterCompileMAXProfile(', 'RouterVPNMultihopGraph.singlePQPolicy(', 'let completeChain = IOSNativeMAXProfile.modeIDs.contains(rawProfileID) || IOSNativeCompositeMultihop.modeIDs.contains(rawProfileID)', 'let composedFiles = try completeChain ? rawFiles', 'LibboxRouterApplyMultihopLANPolicy(', 'RouterVPNMTUPolicy.libbox('):
        assert token in compiler,token

if __name__=='__main__':main()
