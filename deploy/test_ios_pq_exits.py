#!/usr/bin/env python3
"""Exercise Apple's shipping PQ exits with the actual shared graph compiler.

Network.framework address parsing uses the existing Linux shim. Gomobile calls
run the actual Go compiler over a bounded framed pipe. No protocol negotiation,
operating-system VPN, Xcode build or physical-device traffic is simulated as a
successful result by these policy tests; those have independent native gates.
"""
from pathlib import Path
import importlib.util
import json
import argparse
import hashlib
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('apple_pq_policy', ROOT/'deploy/test_ios_pq_selection.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
old = 'case "exit-fixture":value,err=exitFixture(r.Mode)'
assert P.GO.count(old) == 1
P.GO = P.GO.replace(old, old+'\n case "pq-exit-fixture":value,err=pqExitFixture(r.Mode)', 1)
P.GO += r'''
func pqExitFixture(mode string)(string,error){
 if mode!="wg-pq"&&mode!="awg2-pq"{return "",fmt.Errorf("unsupported PQ fixture mode")}
 key:=func(b byte)string{return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b},32))}
 var src struct{Files map[string][]byte;Node string}
 if err:=json.Unmarshal([]byte(fixture(mode)),&src);err!=nil{return "",err}
 rawName:="wg.conf";oldPeer:=key('b');if mode=="awg2-pq"{rawName="awg.conf";oldPeer=key('d')}
 raw:=string(src.Files[rawName]);for before,after:=range map[string]string{key('a'):key('v'),oldPeer:key('z'),key('c'):key('y'),"10.77.0.2":"10.88.0.2","fd77:77::2":"fd88:88::2","192.0.2.1":"198.51.100.2","MTU=1420":"MTU=1280"}{raw=strings.ReplaceAll(raw,before,after)}
 src.Files[rawName]=[]byte(raw)
 src.Files["rosenpass.env"]=[]byte(strings.ReplaceAll(string(src.Files["rosenpass.env"]),oldPeer,key('z')))
 src.Files["rosenpass-client-secret"]=bytes.Repeat([]byte{4},64)
 src.Files["rosenpass-client-public"]=bytes.Repeat([]byte{5},128)
 src.Files["rosenpass-server-public"]=bytes.Repeat([]byte{6},128)
 hash:=sha256.Sum256([]byte("router-vpn-node-proof-v1\n"+key('z')));src.Node=hex.EncodeToString(hash[:])
 data,err:=json.Marshal(map[string]any{"files":src.Files,"node":src.Node});return string(data),err
}
'''
base = P.SWIFT.index('@main struct Tests {')
P.SWIFT = P.SWIFT[:base] + r'''
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ name:String,_ condition:@autoclosure ()throws->Bool)throws{
  guard try condition()else{fatalError("FAIL "+name)};checks+=1
 }
 @MainActor static func reject(_ name:String,_ action:()throws->Void){do{try action();fatalError("ACCEPTED "+name)}catch{checks+=1}}
 static func endpoint(_ graph:[String:Any],_ tag:String)throws->[String:Any]{
  let selected=((graph["endpoints"] as? [[String:Any]] ?? [])+(graph["outbounds"] as? [[String:Any]] ?? [])).filter{$0["tag"] as? String==tag}
  guard selected.count==1 else{throw NSError(domain:"AmbiguousFixtureEndpoint",code:1)};return selected[0]
 }
 static func aes(_ host:String)throws->[String:[String:String]]{
  let fixture=try object(Data(bridge(["Op":"exit-fixture","Mode":"shadowsocks"]).utf8))
  var graph=try object(Data((fixture["config"] as! String).utf8));var proxy=(graph["outbounds"] as! [[String:Any]])[0]
  proxy["server"]=host;proxy["server_port"]=8388;graph["outbounds"]=[proxy]
  return ["shadowsocks":["sing-box.json":try json(graph).base64EncodedString()]]
 }
 static func entry(_ mode:String)throws->([String:Any],String,String){
  if ["wg-pq","awg2-pq"].contains(mode){
   let fixture=try object(Data(bridge(["Op":"fixture","Mode":mode]).utf8))
   let node=fixture["node"] as! String,assets=fixture["files"] as! [String:String]
   return (try IOSNativePQProfile.entryEndpoint(mode:mode,encoded:assets,nodeID:node,compiler:compile),node,"192.0.2.1")
  }
  if ["reality-vision","reality-pq-vision","reality-xhttp"].contains(mode){
   let path=ProcessInfo.processInfo.environment["ROUTERVPN_PQ_EXIT_XRAY_FIXTURES"]!
   let fixtures=try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:path))) as! [String:[String:Any]]
   let ep=fixtures[mode]!
   let native=try object(Data((ep["config_json"] as! String).utf8)),out=(native["outbounds"] as! [[String:Any]]).first{$0["protocol"] as? String=="vless"}!
   let server=((out["settings"] as! [String:Any])["vnext"] as! [[String:Any]])[0]["address"] as! String
   return (ep,String(repeating:"a",count:64),server)
  }
  let fixture=try object(Data(bridge(["Op":"exit-fixture","Mode":mode]).utf8)),graph=try object(Data((fixture["config"] as! String).utf8))
  return (try endpoint(graph,"proxy"),fixture["node"] as! String,"198.51.100.2")
 }
 @MainActor static func runMatrices()throws{
  let layers=[("off","off"),("aes-256-gcm","off"),("off","aes-256-gcm+xor-whitening"),("aes-256-gcm+xor-whitening","aes-256-gcm")]
  var graphs=0
  for entryMode in ["wg","awg2-fast","awg2-strong","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp","wg-pq","awg2-pq"]{
   let (firstEndpoint,entryNode,entryHost)=try entry(entryMode)
   let packet=["wg","awg2-fast","awg2-strong","wg-pq","awg2-pq"].contains(entryMode)
   for exitMode in ["wg-pq","awg2-pq"]{
    let fixture=try object(Data(bridge(["Op":"pq-exit-fixture","Mode":exitMode]).utf8)),originalAssets=fixture["files"] as! [String:String],exitNode=fixture["node"] as! String
    for execution in ["local","server","auto"]{for pair in layers{for v6 in [false,true]{
     var assets=originalAssets
     let host=v6 ? "2001:db8::88":"198.51.100.2"
     if v6{
      let name=exitMode=="wg-pq" ? "wg.conf":"awg.conf"
      let raw=String(decoding:Data(base64Encoded:assets[name]!)!,as:UTF8.self).replacingOccurrences(of:"198.51.100.2:51820",with:"[2001:db8::88]:51820")
      assets[name]=Data(raw.utf8).base64EncodedString()
     }
     var a=profile(entryNode,"home",pair.0),b=profile(exitNode,"doh3",pair.1)
     a["id"]="entry";a["endpoint"]=entryHost;a["manual_mtu"]=packet ? 1500:1280
     b["id"]="exit";b["endpoint"]=host;b["manual_mtu"]=1280;b["router_api"]=v6 ? "http://[fd88::1]:8787":"http://10.88.0.1:8787";b["socks_host"]=v6 ? "fd88::1":"10.88.0.1"
     b["api_token"]="independent-test-exit-token";b["multihop_entry_mode"]=entryMode;b["multihop_exit_mode"]=exitMode
     let beforeA=try text(a),beforeB=try text(b),beforeEntry=try text(firstEndpoint),beforeAssets=assets
     let raw=try IOSNativePQProfile.compile(mode:exitMode,encoded:assets,nodeID:exitNode,compiler:compile)
     let prepared=try RouterVPNMultihopGraph.pqDNSPolicy(raw,profile:b)
     let entryLayer=try IOSMultihopStartLayer.capture(profile:a,profiles:aes(entryHost)),exitLayer=try IOSMultihopStartLayer.capture(profile:b,profiles:aes(host))
     let built=try RouterVPNMultihopGraph.build(entryEndpoint:firstEndpoint,entryProfile:entryLayer.graphProfile,exitProfile:exitLayer.graphProfile,exitMode:exitMode,files:prepared)
     let policy=try text(["entry":a,"exit":b])
     var sized=try RouterVPNMTUPolicy.multihop(built,entryProfile:a,exitProfile:b)
     let shared=try object(Data(bridge(["Op":"mtu","Config":String(decoding:built["sing-box.json"]!,as:UTF8.self),"Policy":policy]).utf8)),swift=try object(sized["sing-box.json"]!)
     for field in ["endpoints","inbounds"]{try check("same real MTU owners",text(shared[field]!)==text(swift[field]!))}
     for op in ["lan","performance"]{sized["sing-box.json"]=Data(try bridge(["Op":op,"Config":String(decoding:sized["sing-box.json"]!,as:UTF8.self),"Policy":policy]).utf8)}
     let metadata:[String:String]=["entry_id":"entry","exit_id":"exit","entry_node_id":entryNode,"exit_node_id":exitNode,"entry_api":a["router_api"] as! String,"exit_api":b["router_api"] as! String,"entry_token":a["api_token"] as! String,"exit_token":b["api_token"] as! String,"entry_tag":RouterVPNMultihopGraph.entryTag,"entry_mode":entryMode,"exit_mode":exitMode,"execution":execution,"entry_start_layer":entryLayer.source==nil ? "":entryLayer.mode,"exit_start_layer":exitLayer.source==nil ? "":exitLayer.mode]
     let plan=try object(Data(bridge(["Op":"plan","Config":String(decoding:sized["sing-box.json"]!,as:UTF8.self),"Policy":text(metadata),"Source":text(["Entry":entryLayer.source ?? "","Exit":exitLayer.source ?? ""])]).utf8))
     let last=try endpoint(plan,"routervpn-execution-local"),pq=last["pq"] as! [String:Any],peer=(last["peers"] as! [[String:Any]])[0]
     try check("exact exit mode and private proof",last["type"] as? String=="routervpn-pq" && last["mode"] as? String==exitMode && last["node_id"] as? String==exitNode && entryNode != exitNode)
     try check("independent WG credentials",last["private_key"] as? String==key(118) && peer["public_key"] as? String==key(122))
     for (name,file) in [("secret","rosenpass-client-secret"),("public","rosenpass-client-public"),("peer","rosenpass-server-public")]{try check("exact exit KEM bytes",pq[name] as? String==assets[file])}
     let target=pair.1=="off" ? host:(v6 ? "fd88::1":"10.88.0.1"),address=(target.contains(":") ? "[\(target)]:":"\(target):")+"51822"
     try check("both encrypted exchanges follow same outer path",peer["address"] as? String==target && pq["endpoint"] as? String==address)
     try check("no unowned direct exit",last["detour"] as? String==(pair.1=="off" ? RouterVPNMultihopGraph.entryTag:"routervpn-exit-start-layer"))
     try check("PQ graph validated by real runtime compiler",bridge(["Op":"validate","Config":text(last)])=="ok")
     if exitMode=="awg2-pq"{let original=try endpoint(object(raw["sing-box.json"]!),"proxy");try check("eleven original AWG parameters",text(last["amnezia"]!)==text(original["amnezia"]!))}
     try check("one system VPN",(plan["inbounds"] as! [[String:Any]]).filter{$0["type"] as? String=="tun"}.count==1)
     try check("exit MTU belongs to exit",last["mtu"] as? Int==1280)
     try check("entry proof follows entry",endpoint(plan,RouterVPNMultihopGraph.entryPrivateTag)["detour"] as? String==RouterVPNMultihopGraph.entryTag)
     try check("server candidate through captured entry",endpoint(plan,"routervpn-execution-server")["detour"] as? String==RouterVPNMultihopGraph.entryTag)
     let dns=(plan["dns"] as! [String:Any])["servers"] as! [[String:Any]]
     try check("AdGuard and H3 unchanged",dns.last!["server"] as? String=="192.168.50.133" && dns.last!["type"] as? String=="h3" && dns.allSatisfy{$0["detour"] as? String=="proxy"})
     try check("source identities and preferences unchanged",text(a)==beforeA && text(b)==beforeB && text(firstEndpoint)==beforeEntry && assets==beforeAssets)
     try check("no separately executable helper assets",Set(sized.keys)==Set(["sing-box.json"]))
     graphs+=1
    }}}
   }
  }
  try check("complete PQ exit matrix",graphs==480)
  print("Apple PQ exits: \(graphs) real Swift/shared-Go graphs")
 }
 @MainActor static func rejectionAndDNS()throws{
  let (entryEndpoint,entryNode,entryHost)=try entry("wg")
  for mode in ["wg-pq","awg2-pq"]{
   let fixture=try object(Data(bridge(["Op":"pq-exit-fixture","Mode":mode]).utf8)),assets=fixture["files"] as! [String:String],node=fixture["node"] as! String
   var a=profile(entryNode,"home","off"),b=profile(node,"home","off")
   a["id"]="entry";a["endpoint"]=entryHost;a["manual_mtu"]=1500
   b["id"]="exit";b["manual_mtu"]=1280;b["multihop_exit_mode"]=mode;b["multihop_entry_mode"]="wg"
   let raw=try IOSNativePQProfile.compile(mode:mode,encoded:assets,nodeID:node,compiler:compile)
   for dns in ["home","custom","dot","doh","doh3","hostname"]{
    var chosen=profile(node,dns,"off");chosen["id"]="exit";chosen["multihop_exit_mode"]=mode
    let prepared=try RouterVPNMultihopGraph.pqDNSPolicy(raw,profile:chosen)
    let result=try RouterVPNMultihopGraph.build(entryEndpoint:entryEndpoint,entryProfile:a,exitProfile:chosen,exitMode:mode,files:prepared)
    let servers=(try object(result["sing-box.json"]!)["dns"] as! [String:Any])["servers"] as! [[String:Any]]
    let expected=dns=="home" ? "udp":dns=="custom" ? "tcp":dns=="dot" ? "tls":dns=="doh3" ? "h3":"https"
    try check("selected DNS type",servers.last!["type"] as? String==expected)
    try check("selected resolver not substituted",servers.last!["server"] as? String==(dns=="hostname" ? "resolver.example.test":"192.168.50.133"))
    try check("resolver/bootstrap are inside encrypted exit",servers.allSatisfy{$0["detour"] as? String=="proxy"})
    if dns=="custom"{try check("custom port",servers.last!["server_port"] as? Int==5353)}
    if dns=="hostname"{try check("private AdGuard bootstrap",servers.count==2 && servers[0]["server"] as? String=="192.168.50.133")}
   }
   let mutations:[(String,([String:Any])->[String:Any])]=[
    ("complete downgrade",{value in var v=value;v["type"]=mode=="wg-pq" ? "wireguard":"routervpn-amneziawg";for key in ["mode","node_id","pq","listen_port"]{v.removeValue(forKey:key)};if mode=="wg-pq"{v.removeValue(forKey:"amnezia")};return v}),
    ("mode",{value in var v=value;v["mode"]="wg";return v}),
    ("node",{value in var v=value;v["node_id"]=entryNode;return v}),
    ("no handshake",{value in var v=value;v.removeValue(forKey:"pq");return v}),
    ("direct route",{value in var v=value;v["detour"]="direct";return v}),
    ("same KEM key",{value in var v=value;var pq=v["pq"] as! [String:Any];pq["peer"]=pq["public"];v["pq"]=pq;return v}),
    ("reassigned handshake",{value in var v=value;var pq=v["pq"] as! [String:Any];pq["endpoint"]="198.51.100.99:51822";v["pq"]=pq;return v}),
    ("private key encoding",{value in var v=value;v["private_key"]="bad";return v}),
    ("arbitrary option",{value in var v=value;v["bind_interface"]="en0";return v})]
   for (name,change) in mutations{
    var graph=try object(raw["sing-box.json"]!),eps=graph["endpoints"] as! [[String:Any]];eps[0]=change(eps[0]);graph["endpoints"]=eps
    reject(name){_ = try RouterVPNMultihopGraph.build(entryEndpoint:entryEndpoint,entryProfile:a,exitProfile:b,exitMode:mode,files:["sing-box.json":json(graph)])}
   }
   var malformed=assets;malformed.removeValue(forKey:"rosenpass-client-secret")
   reject("missing exit asset"){_ = try IOSNativePQProfile.compile(mode:mode,encoded:malformed,nodeID:node,compiler:compile)}
   // AWG's transport key is separate from the home's canonical WireGuard
   // proof key. Validate the captured compile result here; live proof of both
   // nodes remains mandatory after native startup.
   reject("compiler reassigned captured exit proof"){
    _ = try IOSNativePQProfile.compile(mode:mode,encoded:assets,nodeID:node){_,_,_ in
     var graph=try object(raw["sing-box.json"]!),eps=graph["endpoints"] as! [[String:Any]]
     eps[0]["node_id"]=entryNode;graph["endpoints"]=eps;return try text(graph)
    }
   }
   if mode=="wg-pq"{reject("WG key contradicts canonical node"){_ = try IOSNativePQProfile.compile(mode:mode,encoded:assets,nodeID:entryNode,compiler:compile)}}
   let built=try RouterVPNMultihopGraph.build(entryEndpoint:entryEndpoint,entryProfile:a,exitProfile:b,exitMode:mode,files:raw)
   for rawEntry in [entryEndpoint,try entry("shadowsocks").0]{
    let current=try RouterVPNMultihopGraph.build(entryEndpoint:rawEntry,entryProfile:a,exitProfile:b,exitMode:mode,files:raw)
    var graph=try object(current["sing-box.json"]!),eps=graph["endpoints"] as! [[String:Any]],selected=b
    selected["multihop_exit_mode"]="wg"
    reject("MTU relabel"){_ = try RouterVPNMTUPolicy.multihop(current,entryProfile:a,exitProfile:selected)}
    let index=eps.firstIndex{$0["tag"] as? String=="proxy"}!
    eps[index]=mutations[0].1(eps[index]);graph["endpoints"]=eps
    reject("complete MTU downgrade"){_ = try RouterVPNMTUPolicy.multihop(["sing-box.json":json(graph)],entryProfile:a,exitProfile:b)}
   }
   var short=a,oversized=b;short["manual_mtu"]=1420;oversized["manual_mtu"]=1400
   reject("fixed nested MTU too large"){_ = try RouterVPNMTUPolicy.multihop(built,entryProfile:short,exitProfile:oversized)}
   oversized["mtu_policy"]="auto";oversized.removeValue(forKey:"manual_mtu")
   var imported=try object(built["sing-box.json"]!),eps=imported["endpoints"] as! [[String:Any]]
   let index=eps.firstIndex{$0["tag"] as? String=="proxy"}!;eps[index]["mtu"]=1420;imported["endpoints"]=eps
   let input=["sing-box.json":try json(imported)],bounded=try RouterVPNMTUPolicy.multihop(input,entryProfile:short,exitProfile:oversized)
   let shared=try object(Data(bridge(["Op":"mtu","Config":String(decoding:input["sing-box.json"]!,as:UTF8.self),"Policy":text(["entry":short,"exit":oversized])]).utf8))
   try check("AWG transport padding retained in MTU",text(endpoint(shared,"proxy"))==text(endpoint(object(bounded["sing-box.json"]!),"proxy")))
  }
 }
 @MainActor static func main()throws{
  defer{TestCompiler.shared.close()}
  try runMatrices();try rejectionAndDNS()
  print("Apple PQ exits: PASS (\(checks) executable policy checks; native and physical traffic gates remain separate)")
 }
}
'''

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--xray-fixtures', type=Path, help='Optional input emitted by the unchanged Go 1.24 fixture helper in another compiler workspace')
    parser.add_argument('--fixture-sha256', help='Required checksum for a supplied fixture file')
    args=parser.parse_args()
    if bool(args.xray_fixtures) != bool(args.fixture_sha256):
        parser.error('Supply --xray-fixtures and --fixture-sha256 together')
    with tempfile.TemporaryDirectory(prefix='apple-pq-exit-fixtures-') as tmp:
        fixture = Path(tmp)/'xray-entries.json'
        if args.xray_fixtures:
            data=args.xray_fixtures.read_bytes()
            if len(data)>1024*1024 or hashlib.sha256(data).hexdigest()!=args.fixture_sha256:
                raise RuntimeError('Supplied fixture bytes do not match their captured checksum')
            fixture.write_bytes(data)
        else:
            with fixture.open('w') as out:
                subprocess.run(['go','run','./deploy/testfixtures/xray-entry'],cwd=ROOT,stdout=out,check=True,timeout=90)
        values = json.loads(fixture.read_text())
        assert set(values) == {'reality-vision','reality-pq-vision','reality-xhttp'}
        previous = os.environ.get('ROUTERVPN_PQ_EXIT_XRAY_FIXTURES')
        os.environ['ROUTERVPN_PQ_EXIT_XRAY_FIXTURES'] = str(fixture)
        try:
            P.main()
        finally:
            if previous is None:
                os.environ.pop('ROUTERVPN_PQ_EXIT_XRAY_FIXTURES',None)
            else:
                os.environ['ROUTERVPN_PQ_EXIT_XRAY_FIXTURES'] = previous
    provider=(P.TUN/'PacketTunnelProvider.swift').read_text()
    scoped=provider[provider.index('    private func startMultihop('):provider.index('    private func startLibbox(')]
    assert 'IOSNativePQProfile.compile(mode: exitMode, encoded: assets, nodeID: exitProofID)' in scoped
    assert 'RouterVPNMultihopGraph.pqDNSPolicy(compiled, profile: exitProfile)' in scoped
    assert scoped.index('IOSNativePQProfile.compile(mode: exitMode') < scoped.index('RouterVPNMultihopGraph.build(') < scoped.index('engine.start(')
    assert scoped.index('expectedNodeID: entryProofID') < scoped.index('expectedNodeID: exitProofID') < scoped.index('completionHandler(nil)')
    print('Captured PQ exit is wired into PacketTunnel startup and independent two-node proof.')

if __name__=='__main__':
    main()
